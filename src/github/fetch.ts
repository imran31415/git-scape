/**
 * Repository acquisition — 100% browser-side, no backend.
 *
 * Strategy ladder:
 *  1. GitHub REST API (CORS `*`): repo meta + full recursive tree, then file
 *     contents from raw.githubusercontent.com (public) or the blobs API
 *     (private repos, with a token). Costs only 2 API calls for public repos.
 *  2. jsDelivr's GitHub mirror (CORS `*`): kicks in when the API is
 *     rate-limited and no token is available.
 *  3. Dev-only zip relay (vite middleware) so the pipeline runs inside
 *     sandboxed dev containers. Absent from production builds.
 */
import type { ProgressEvent, RepoMeta } from '../types';
import type { RepoTarget } from './parse';

export interface FetchedFile {
  path: string;
  data?: Uint8Array;
  size?: number;
}

export type RepoPayload =
  | { kind: 'files'; meta: RepoMeta; files: FetchedFile[] }
  | { kind: 'zip'; meta: RepoMeta; zip: ArrayBuffer };

export class RepoFetchError extends Error {
  constructor(
    message: string,
    public readonly hint?: string,
  ) {
    super(message);
  }
}

const API = 'https://api.github.com';
const MAX_FILE_BYTES = 400 * 1024;
const MAX_TOTAL_BYTES = 56 * 1024 * 1024;
const MAX_FILES = 2600;
const CONCURRENCY = 24;

const BINARY_EXT =
  /\.(png|jpe?g|gif|webp|avif|ico|icns|bmp|tiff?|woff2?|ttf|otf|eot|mp[34]|m4[av]|mov|avi|webm|ogg|wav|flac|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|exe|dll|so|dylib|a|o|wasm|bin|dat|db|sqlite3?|parquet|pyc|pyo|min\.map|lockb|node|wgsl\.bin|glb|gltf|fbx|obj|stl|hdr|exr|psd|ai|sketch|fig)$/i;

const VENDORED_DIR =
  /(^|\/)(node_modules|bower_components|vendor|third_party|\.yarn|dist|build|out|target|venv|\.venv|__pycache__|\.terraform|coverage|\.next|\.nuxt|Pods|site-packages)\//;

interface TreeEntry {
  path: string;
  size: number;
}

function ghHeaders(token?: string): HeadersInit {
  const h: Record<string, string> = { Accept: 'application/vnd.github+json' };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

/** Manifests & security-relevant configs always make the cut. */
function isPriorityPath(p: string): boolean {
  const base = p.split('/').pop()!.toLowerCase();
  return (
    [
      'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
      'requirements.txt', 'pyproject.toml', 'go.mod', 'go.sum', 'cargo.toml',
      'gemfile', 'gemfile.lock', 'pom.xml', 'build.gradle', 'build.gradle.kts',
      'composer.json', 'dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
      '.env', '.npmrc', 'makefile', 'security.md', 'license',
    ].includes(base) ||
    base.startsWith('.env.') ||
    base.startsWith('dockerfile.') ||
    p.toLowerCase().includes('.github/workflows/') ||
    /\.(tf|tfvars|pem|key)$/i.test(base)
  );
}

/** Pick which tree entries are worth downloading, under global caps. */
export function selectFiles(entries: TreeEntry[]): { chosen: TreeEntry[]; skipped: number } {
  const candidates = entries.filter(
    (e) => !BINARY_EXT.test(e.path) && !VENDORED_DIR.test(e.path) && e.size <= MAX_FILE_BYTES,
  );
  const score = (e: TreeEntry) => {
    if (isPriorityPath(e.path)) return 0;
    const depth = e.path.split('/').length;
    return depth + Math.min(e.size / MAX_FILE_BYTES, 1);
  };
  candidates.sort((a, b) => score(a) - score(b));

  const chosen: TreeEntry[] = [];
  let total = 0;
  for (const e of candidates) {
    if (chosen.length >= MAX_FILES || total + e.size > MAX_TOTAL_BYTES) break;
    chosen.push(e);
    total += e.size;
  }
  return { chosen, skipped: entries.length - chosen.length };
}

async function downloadPool(
  entries: TreeEntry[],
  urlFor: (e: TreeEntry) => string,
  decode: (resp: Response) => Promise<Uint8Array>,
  headers: HeadersInit,
  onProgress: (done: number, total: number, path: string) => void,
): Promise<FetchedFile[]> {
  const out: FetchedFile[] = [];
  let next = 0;
  let done = 0;
  let failures = 0;

  async function workOne(): Promise<void> {
    while (next < entries.length) {
      const e = entries[next++];
      try {
        let resp = await fetch(urlFor(e), { headers });
        if (resp.status === 429 || resp.status >= 500) {
          await new Promise((r) => setTimeout(r, 800 + Math.random() * 800));
          resp = await fetch(urlFor(e), { headers });
        }
        if (resp.ok) {
          out.push({ path: e.path, data: await decode(resp) });
        } else {
          failures++;
          out.push({ path: e.path, size: e.size });
        }
      } catch {
        failures++;
        out.push({ path: e.path, size: e.size });
      }
      done++;
      if (done % 10 === 0 || done === entries.length) onProgress(done, entries.length, e.path);
    }
  }

  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, entries.length) }, workOne));
  if (failures > entries.length * 0.5 && failures > 20) {
    throw new RepoFetchError(`too many download failures (${failures}/${entries.length})`);
  }
  return out;
}

const plainBytes = async (r: Response) => new Uint8Array(await r.arrayBuffer());

async function blobBytes(r: Response): Promise<Uint8Array> {
  const body = (await r.json()) as { content?: string; encoding?: string };
  if (body.encoding !== 'base64' || body.content == null) return new Uint8Array(0);
  const bin = atob(body.content.replace(/\n/g, ''));
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}

// ---------------------------------------------------------------- strategy 1
async function viaGitHubAPI(
  target: RepoTarget,
  token: string | undefined,
  progress: (e: ProgressEvent) => void,
): Promise<RepoPayload> {
  progress({ stage: 'meta', message: `querying api.github.com/${target.owner}/${target.repo}` });
  const metaResp = await fetch(`${API}/repos/${target.owner}/${target.repo}`, { headers: ghHeaders(token) });
  if (metaResp.status === 404) {
    throw new RepoFetchError(
      'Repository not found.',
      'Check the URL — or, if it is private, supply a GitHub token (it stays in your browser).',
    );
  }
  if (metaResp.status === 403 || metaResp.status === 429) {
    throw new RepoFetchError('rate-limited', 'GitHub API rate limit reached.');
  }
  if (!metaResp.ok) throw new RepoFetchError(`GitHub API error ${metaResp.status}`);
  const metaJson = await metaResp.json();

  const ref = target.ref ?? (metaJson.default_branch as string) ?? 'main';
  const meta: RepoMeta = {
    owner: target.owner,
    repo: target.repo,
    ref,
    description: metaJson.description ?? undefined,
    stars: metaJson.stargazers_count,
    forks: metaJson.forks_count,
    openIssues: metaJson.open_issues_count,
    license: metaJson.license?.spdx_id !== 'NOASSERTION' ? metaJson.license?.spdx_id : metaJson.license?.name,
    pushedAt: metaJson.pushed_at,
    source: 'github-api',
  };

  progress({ stage: 'tree', message: `reading file tree @ ${ref}` });
  const treeResp = await fetch(
    `${API}/repos/${target.owner}/${target.repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`,
    { headers: ghHeaders(token) },
  );
  if (treeResp.status === 403 || treeResp.status === 429) throw new RepoFetchError('rate-limited');
  if (!treeResp.ok) throw new RepoFetchError(`could not read tree (${treeResp.status})`);
  const treeJson = await treeResp.json();
  const blobs: Array<{ path: string; size?: number; sha: string; type: string }> = treeJson.tree ?? [];
  const entries: (TreeEntry & { sha: string })[] = blobs
    .filter((t) => t.type === 'blob')
    .map((t) => ({ path: t.path, size: t.size ?? 0, sha: t.sha }));
  if (entries.length === 0) throw new RepoFetchError('The repository appears to be empty.');

  const { chosen } = selectFiles(entries);
  progress({
    stage: 'download',
    message: `downloading ${chosen.length} files`,
    done: 0,
    total: chosen.length,
  });

  const usePrivateBlobs = Boolean(token) && Boolean(metaJson.private);
  const files = await downloadPool(
    chosen,
    usePrivateBlobs
      ? (e) => `${API}/repos/${target.owner}/${target.repo}/git/blobs/${(e as TreeEntry & { sha: string }).sha}`
      : (e) => `https://raw.githubusercontent.com/${target.owner}/${target.repo}/${encodeURIComponent(ref)}/${e.path.split('/').map(encodeURIComponent).join('/')}`,
    usePrivateBlobs ? blobBytes : plainBytes,
    usePrivateBlobs ? ghHeaders(token) : {},
    (done, total, path) =>
      progress({ stage: 'download', message: path, done, total }),
  );

  // Buildings for everything else (skipped/binary) still appear in the city.
  const chosenSet = new Set(chosen.map((e) => e.path));
  for (const e of entries) {
    if (!chosenSet.has(e.path)) files.push({ path: e.path, size: e.size });
  }
  return { kind: 'files', meta, files };
}

// ---------------------------------------------------------------- strategy 2
interface JsdNode {
  type: 'file' | 'directory';
  name: string;
  size?: number;
  files?: JsdNode[];
}

function flattenJsd(nodes: JsdNode[], prefix: string, out: TreeEntry[]): void {
  for (const n of nodes) {
    const p = prefix ? `${prefix}/${n.name}` : n.name;
    if (n.type === 'directory') flattenJsd(n.files ?? [], p, out);
    else out.push({ path: p, size: n.size ?? 0 });
  }
}

async function viaJsDelivr(
  target: RepoTarget,
  progress: (e: ProgressEvent) => void,
): Promise<RepoPayload> {
  progress({ stage: 'meta', message: 'GitHub API rate-limited — falling back to jsDelivr mirror' });
  const refs = target.ref ? [target.ref] : ['main', 'master'];
  let tree: TreeEntry[] | null = null;
  let ref = refs[0];
  for (const candidate of refs) {
    const r = await fetch(
      `https://data.jsdelivr.com/v1/packages/gh/${target.owner}/${target.repo}@${encodeURIComponent(candidate)}`,
    );
    if (r.ok) {
      const json = (await r.json()) as { files?: JsdNode[] };
      const flat: TreeEntry[] = [];
      flattenJsd(json.files ?? [], '', flat);
      if (flat.length > 0) {
        tree = flat;
        ref = candidate;
        break;
      }
    }
  }
  if (!tree) throw new RepoFetchError('jsDelivr mirror unavailable for this repository');

  const meta: RepoMeta = { owner: target.owner, repo: target.repo, ref, source: 'jsdelivr' };
  const { chosen } = selectFiles(tree);
  progress({ stage: 'download', message: `downloading ${chosen.length} files (jsDelivr)`, done: 0, total: chosen.length });
  const files = await downloadPool(
    chosen,
    (e) => `https://cdn.jsdelivr.net/gh/${target.owner}/${target.repo}@${encodeURIComponent(ref)}/${e.path.split('/').map(encodeURIComponent).join('/')}`,
    plainBytes,
    {},
    (done, total, path) => progress({ stage: 'download', message: path, done, total }),
  );
  const chosenSet = new Set(chosen.map((e) => e.path));
  for (const e of tree) if (!chosenSet.has(e.path)) files.push({ path: e.path, size: e.size });
  return { kind: 'files', meta, files };
}

// ---------------------------------------------------------------- strategy 3
async function viaDevZip(
  target: RepoTarget,
  progress: (e: ProgressEvent) => void,
): Promise<RepoPayload> {
  const ref = target.ref ?? 'HEAD';
  progress({ stage: 'download', message: `dev relay: codeload zipball @ ${ref}` });
  const resp = await fetch(`/__ts_dev/zip/${target.owner}/${target.repo}/${encodeURIComponent(ref)}`);
  if (!resp.ok) throw new RepoFetchError(`dev zip relay failed (${resp.status})`);
  const zip = await resp.arrayBuffer();
  progress({ stage: 'download', message: `zipball ${(zip.byteLength / 1024 / 1024).toFixed(1)} MB` });
  return {
    kind: 'zip',
    meta: { owner: target.owner, repo: target.repo, ref, source: 'dev-zip' },
    zip,
  };
}

/** Fetch a repository using the best available strategy. */
export async function fetchRepo(
  target: RepoTarget,
  token: string | undefined,
  progress: (e: ProgressEvent) => void,
): Promise<RepoPayload> {
  let rateLimited = false;
  try {
    return await viaGitHubAPI(target, token, progress);
  } catch (err) {
    if (err instanceof RepoFetchError && err.message === 'rate-limited') {
      rateLimited = true;
    } else if (err instanceof RepoFetchError && err.hint) {
      throw err; // definitive (404 etc.)
    } else if (!(err instanceof TypeError) && !(err instanceof RepoFetchError)) {
      throw err;
    }
  }

  try {
    return await viaJsDelivr(target, progress);
  } catch {
    /* keep falling */
  }

  if (import.meta.env.DEV) {
    try {
      return await viaDevZip(target, progress);
    } catch {
      /* fall through to the final error */
    }
  }

  throw new RepoFetchError(
    rateLimited
      ? 'GitHub API rate limit reached and the jsDelivr mirror could not serve this repository.'
      : 'Could not reach GitHub from this network.',
    rateLimited
      ? 'Add a GitHub token (Settings → Developer settings → Fine-grained tokens, public repos / read-only). It never leaves your browser.'
      : 'Check connectivity — the app talks directly to api.github.com and raw.githubusercontent.com.',
  );
}
