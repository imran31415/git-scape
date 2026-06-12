/** End-to-end analysis pipeline: fetch → WASM scan → OSV cross-reference → score. */
import { fetchRepo } from '../github/fetch';
import type { RepoTarget } from '../github/parse';
import { ScanEngine } from '../scanner/bridge';
import { queryOsv } from '../osv/client';
import { computeScore } from './score';
import {
  severityRank,
  type AnalysisResult,
  type Finding,
  type ProgressEvent,
  type VulnerableDependency,
} from '../types';

const engine = new ScanEngine();

export function prewarmEngine(): void {
  engine.prewarm();
}

function dependencyFindings(vulnDeps: VulnerableDependency[], startIndex: number): Finding[] {
  return vulnDeps.map((vd, i) => {
    const d = vd.dependency;
    const top = vd.vulns[0];
    const cveList = vd.vulns
      .slice(0, 4)
      .map((v) => v.aliases.find((a) => a.startsWith('CVE-')) ?? v.id)
      .join(', ');
    return {
      id: `D${String(startIndex + i + 1).padStart(4, '0')}`,
      ruleId: 'osv.vulnerable-dependency',
      title: `${d.name}@${d.version} — ${vd.vulns.length} known ${vd.vulns.length === 1 ? 'vulnerability' : 'vulnerabilities'}`,
      category: 'dependency' as const,
      severity: vd.maxSeverity,
      file: d.file,
      line: 0,
      snippet: `${d.ecosystem}: ${d.name}@${d.version}${d.exact ? '' : ' (declared range, minimum assumed)'}`,
      message:
        `${cveList}. ${top?.summary ?? ''}`.trim() +
        (top?.cvss ? ` (worst CVSS ${top.cvss.toFixed(1)})` : ''),
      recommendation: `Upgrade ${d.name} past the affected ranges — see the linked advisory for fixed versions.`,
      cwe: 'CWE-1395',
      confidence: d.exact ? ('high' as const) : ('medium' as const),
    };
  });
}

export async function analyzeRepo(
  target: RepoTarget,
  token: string | undefined,
  progress: (e: ProgressEvent) => void,
): Promise<AnalysisResult> {
  const payload = await fetchRepo(target, token, progress);

  progress({ stage: 'scan', message: 'booting WASM security engine' });
  const report = await engine.scan(
    payload.kind === 'zip'
      ? { kind: 'zip', zip: payload.zip }
      : { kind: 'files', files: payload.files },
    (done, total, path) =>
      progress({ stage: 'scan', message: path, done, total }),
  );

  progress({ stage: 'osv', message: `cross-referencing ${report.dependencies.length} dependencies` });
  let osvStatus: AnalysisResult['osvStatus'] = 'skipped';
  let vulnerableDeps: VulnerableDependency[] = [];
  if (report.dependencies.length > 0) {
    const osv = await queryOsv(report.dependencies, (message) =>
      progress({ stage: 'osv', message }),
    );
    osvStatus = osv.status === 'ok' ? 'ok' : 'unavailable';
    vulnerableDeps = osv.vulnerable;
  }

  progress({ stage: 'build', message: 'constructing city' });
  const findings = [...report.findings, ...dependencyFindings(vulnerableDeps, report.findings.length)];
  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.file.localeCompare(b.file));

  // Refresh per-file rollups with dependency findings included.
  const byFile = new Map<string, { count: number; max: Finding['severity'] }>();
  for (const f of findings) {
    if (!f.file) continue;
    const cur = byFile.get(f.file);
    if (!cur) byFile.set(f.file, { count: 1, max: f.severity });
    else {
      cur.count++;
      if (severityRank(f.severity) > severityRank(cur.max)) cur.max = f.severity;
    }
  }
  for (const file of report.files) {
    const roll = byFile.get(file.path);
    file.findings = roll?.count ?? 0;
    file.maxSeverity = roll?.max;
  }

  return {
    meta: payload.meta,
    report,
    findings,
    vulnerableDeps,
    osvStatus,
    score: computeScore(findings),
  };
}
