/**
 * OSV.dev client — real CVE/GHSA data, straight from the browser (the OSV
 * API is CORS-enabled). Degrades gracefully to "unavailable" offline.
 */
import type { Dependency, Severity, VulnerableDependency, VulnInfo } from '../types';

const OSV = 'https://api.osv.dev/v1';
const BATCH_SIZE = 250;
const MAX_DEPS = 900;
const MAX_DETAIL_FETCHES = 80;
const DETAIL_CONCURRENCY = 8;

/** CVSS v3.x base-score calculator (first-principles, spec section 7.1). */
export function cvssBaseScore(vector: string): number | undefined {
  const parts = new Map<string, string>();
  for (const p of vector.split('/')) {
    const [k, v] = p.split(':');
    if (k && v) parts.set(k, v);
  }
  if (!vector.startsWith('CVSS:3') || !parts.has('AV')) return undefined;

  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[parts.get('AV')!];
  const AC = { L: 0.77, H: 0.44 }[parts.get('AC')!];
  const UI = { N: 0.85, R: 0.62 }[parts.get('UI')!];
  const S = parts.get('S');
  const PRmap =
    S === 'C' ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 };
  const PR = PRmap[parts.get('PR') as 'N' | 'L' | 'H'];
  const cia = { H: 0.56, L: 0.22, N: 0 };
  const C = cia[parts.get('C') as 'H' | 'L' | 'N'];
  const I = cia[parts.get('I') as 'H' | 'L' | 'N'];
  const A = cia[parts.get('A') as 'H' | 'L' | 'N'];
  if ([AV, AC, UI, PR, C, I, A].some((x) => x === undefined)) return undefined;

  const iscBase = 1 - (1 - C!) * (1 - I!) * (1 - A!);
  const impact =
    S === 'C'
      ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
      : 6.42 * iscBase;
  const exploitability = 8.22 * AV! * AC! * PR! * UI!;
  if (impact <= 0) return 0;
  const raw = S === 'C' ? Math.min(1.08 * (impact + exploitability), 10) : Math.min(impact + exploitability, 10);
  return Math.ceil(raw * 10) / 10;
}

export function severityFromScore(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

interface OsvVulnDetail {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
}

function resolveSeverity(v: OsvVulnDetail): { severity: Severity; cvss?: number } {
  const dbSev = v.database_specific?.severity?.toLowerCase();
  let cvss: number | undefined;
  for (const s of v.severity ?? []) {
    if (s.type.startsWith('CVSS_V3')) {
      cvss = cvssBaseScore(s.score);
      if (cvss !== undefined) break;
    }
  }
  if (cvss !== undefined) return { severity: severityFromScore(cvss), cvss };
  if (dbSev === 'critical') return { severity: 'critical' };
  if (dbSev === 'high') return { severity: 'high' };
  if (dbSev === 'moderate' || dbSev === 'medium') return { severity: 'medium' };
  if (dbSev === 'low') return { severity: 'low' };
  return { severity: 'high' }; // unknown severity on a known vuln: assume bad
}

export async function queryOsv(
  deps: Dependency[],
  onProgress: (msg: string) => void,
): Promise<{ status: 'ok' | 'unavailable'; vulnerable: VulnerableDependency[] }> {
  const queryable = deps
    .filter((d) => d.version && d.ecosystem)
    .sort((a, b) => Number(a.dev ?? false) - Number(b.dev ?? false))
    .slice(0, MAX_DEPS);
  if (queryable.length === 0) return { status: 'ok', vulnerable: [] };

  // -- phase 1: batched existence query
  const hits = new Map<number, string[]>(); // dep index -> vuln ids
  try {
    for (let i = 0; i < queryable.length; i += BATCH_SIZE) {
      const chunk = queryable.slice(i, i + BATCH_SIZE);
      onProgress(`cross-referencing ${i + chunk.length}/${queryable.length} packages against OSV.dev`);
      const resp = await fetch(`${OSV}/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          queries: chunk.map((d) => ({
            package: { name: d.name, ecosystem: d.ecosystem },
            // OSV stores semver without the v prefix (Go modules carry one)
            version: d.version.replace(/^v/, ''),
          })),
        }),
      });
      if (!resp.ok) throw new Error(`osv ${resp.status}`);
      const json = (await resp.json()) as { results: Array<{ vulns?: Array<{ id: string }> }> };
      json.results.forEach((r, j) => {
        if (r.vulns?.length) hits.set(i + j, r.vulns.map((v) => v.id));
      });
    }
  } catch {
    return { status: 'unavailable', vulnerable: [] };
  }
  if (hits.size === 0) return { status: 'ok', vulnerable: [] };

  // -- phase 2: hydrate details for the most relevant vuln ids
  const wantedIds: string[] = [];
  const seen = new Set<string>();
  for (const ids of hits.values()) {
    for (const id of ids) {
      if (!seen.has(id) && wantedIds.length < MAX_DETAIL_FETCHES) {
        seen.add(id);
        wantedIds.push(id);
      }
    }
  }
  onProgress(`hydrating ${wantedIds.length} advisories`);
  const details = new Map<string, OsvVulnDetail>();
  let cursor = 0;
  await Promise.all(
    Array.from({ length: DETAIL_CONCURRENCY }, async () => {
      while (cursor < wantedIds.length) {
        const id = wantedIds[cursor++];
        try {
          const r = await fetch(`${OSV}/vulns/${id}`);
          if (r.ok) details.set(id, (await r.json()) as OsvVulnDetail);
        } catch {
          /* individual advisory failures are fine */
        }
      }
    }),
  );

  const vulnerable: VulnerableDependency[] = [];
  for (const [depIdx, ids] of hits) {
    const dep = queryable[depIdx];
    const vulns: VulnInfo[] = ids.map((id) => {
      const d = details.get(id);
      const { severity, cvss } = d ? resolveSeverity(d) : { severity: 'high' as Severity, cvss: undefined };
      const alias = d?.aliases?.find((a) => a.startsWith('CVE-'));
      return {
        id,
        aliases: d?.aliases ?? [],
        summary: d?.summary || d?.details?.slice(0, 140) || 'Known vulnerability (see advisory).',
        severity,
        cvss,
        url: `https://osv.dev/vulnerability/${encodeURIComponent(alias ?? id)}`,
      };
    });
    vulns.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));
    const maxSeverity = vulns.reduce<Severity>(
      (acc, v) => (sevRank(v.severity) > sevRank(acc) ? v.severity : acc),
      'low',
    );
    vulnerable.push({ dependency: dep, vulns, maxSeverity });
  }
  vulnerable.sort((a, b) => sevRank(b.maxSeverity) - sevRank(a.maxSeverity));
  return { status: 'ok', vulnerable };
}

function sevRank(s: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s];
}
