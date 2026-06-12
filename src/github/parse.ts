export interface RepoTarget {
  owner: string;
  repo: string;
  ref?: string;
}

/**
 * Accepts every common way people paste a repo:
 *   owner/repo
 *   github.com/owner/repo(.git)
 *   https://github.com/owner/repo/tree/branch/sub/dir
 *   git@github.com:owner/repo.git
 *   https://github.com/owner/repo/blob/branch/file.ts
 */
export function parseRepoInput(input: string): RepoTarget | null {
  let s = input.trim();
  if (!s) return null;

  const ssh = s.match(/^git@github\.com:([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/i);
  if (ssh) return { owner: ssh[1], repo: ssh[2] };

  s = s.replace(/^(https?:\/\/)?(www\.)?github\.com\//i, '');
  s = s.replace(/^\/+/, '');

  const m = s.match(/^([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:\/(.*))?$/);
  if (!m) return null;
  const [, owner, repo, rest] = m;
  if (!owner || !repo || owner.includes('..') || repo.includes('..')) return null;

  let ref: string | undefined;
  if (rest) {
    const refMatch = rest.match(/^(?:tree|blob|commits?|releases\/tag)\/([^/]+)/);
    if (refMatch) ref = decodeURIComponent(refMatch[1]);
  }
  return { owner, repo, ref };
}

export function repoSlug(t: RepoTarget): string {
  return `${t.owner}/${t.repo}`;
}
