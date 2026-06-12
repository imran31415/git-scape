/** Shared domain types. The engine-side shapes mirror scanner/engine/types.go. */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Category =
  | 'secret'
  | 'injection'
  | 'xss'
  | 'crypto'
  | 'network'
  | 'config'
  | 'cicd'
  | 'dependency'
  | 'hygiene';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function severityRank(s: Severity): number {
  return 5 - SEVERITY_ORDER.indexOf(s);
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  file: string;
  line?: number;
  snippet?: string;
  message: string;
  recommendation?: string;
  cwe?: string;
  confidence: 'high' | 'medium' | 'low';
  /** Under a test/example/docs path: severity pre-downgraded, scored lighter. */
  testContext?: boolean;
}

export interface FileInfo {
  path: string;
  size: number;
  lines: number;
  lang?: string;
  binary?: boolean;
  vendored?: boolean;
  minified?: boolean;
  findings?: number;
  maxSeverity?: Severity;
}

export interface Dependency {
  ecosystem: string;
  name: string;
  version: string;
  file: string;
  dev?: boolean;
  exact: boolean;
}

export interface ScanStats {
  fileCount: number;
  scannedFiles: number;
  skippedBinary: number;
  skippedVendored: number;
  skippedLarge: number;
  totalBytes: number;
  totalLines: number;
  durationMs: number;
  ruleCount: number;
}

/** Raw output of the WASM engine. */
export interface EngineReport {
  files: FileInfo[];
  findings: Finding[];
  dependencies: Dependency[];
  languages: Record<string, number>;
  stats: ScanStats;
}

export interface RepoMeta {
  owner: string;
  repo: string;
  ref: string;
  description?: string;
  stars?: number;
  forks?: number;
  openIssues?: number;
  license?: string;
  pushedAt?: string;
  source: 'github-api' | 'jsdelivr' | 'dev-zip';
}

export interface VulnInfo {
  id: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  cvss?: number;
  url: string;
}

export interface VulnerableDependency {
  dependency: Dependency;
  vulns: VulnInfo[];
  maxSeverity: Severity;
}

export interface ScoreCard {
  value: number; // 0..100
  grade: string; // A+ … F
  threatLevel: string;
  bySeverity: Record<Severity, number>;
  byCategory: Partial<Record<Category, number>>;
}

/** Everything the 3D city + HUD consume. */
export interface AnalysisResult {
  meta: RepoMeta;
  report: EngineReport;
  /** Engine findings + dependency findings merged, sorted by severity. */
  findings: Finding[];
  vulnerableDeps: VulnerableDependency[];
  osvStatus: 'ok' | 'unavailable' | 'skipped';
  score: ScoreCard;
}

export type ProgressStage = 'meta' | 'tree' | 'download' | 'scan' | 'osv' | 'build';

export interface ProgressEvent {
  stage: ProgressStage;
  message: string;
  done?: number;
  total?: number;
}

export const CATEGORY_INFO: Record<Category, { label: string; actor: string; blurb: string }> = {
  secret: {
    label: 'Leaked Secrets',
    actor: 'Credential Phantom',
    blurb: 'Harvests keys and passwords committed to the repo.',
  },
  injection: {
    label: 'Injection',
    actor: 'Injection Wraith',
    blurb: 'Slips hostile commands through unsanitized inputs.',
  },
  xss: {
    label: 'Cross-Site Scripting',
    actor: 'Script Specter',
    blurb: 'Plants scripts that hijack your users’ browsers.',
  },
  crypto: {
    label: 'Weak Crypto',
    actor: 'Cipher Breaker',
    blurb: 'Cracks weak hashes and predictable randomness.',
  },
  network: {
    label: 'Insecure Transport',
    actor: 'Wire Eavesdropper',
    blurb: 'Reads and rewrites unencrypted traffic in transit.',
  },
  config: {
    label: 'Misconfiguration',
    actor: 'Config Goblin',
    blurb: 'Exploits permissive defaults and exposed surfaces.',
  },
  cicd: {
    label: 'CI/CD Risk',
    actor: 'Pipeline Saboteur',
    blurb: 'Poisons builds to ship malicious artifacts.',
  },
  dependency: {
    label: 'Vulnerable Dependencies',
    actor: 'Supply-Chain Parasite',
    blurb: 'Rides known-vulnerable packages into your build.',
  },
  hygiene: {
    label: 'Repo Hygiene',
    actor: 'Entropy Rat',
    blurb: 'Thrives on missing policies and unpatched drift.',
  },
};

export const SEVERITY_COLOR: Record<Severity, number> = {
  critical: 0xff2d55,
  high: 0xff9f0a,
  medium: 0xffd60a,
  low: 0x64d2ff,
  info: 0x98989d,
};

export const SEVERITY_COLOR_CSS: Record<Severity, string> = {
  critical: '#ff2d55',
  high: '#ff9f0a',
  medium: '#ffd60a',
  low: '#64d2ff',
  info: '#98989d',
};
