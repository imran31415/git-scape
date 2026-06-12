/**
 * Full-pipeline integration check, runnable without a browser:
 *   real zipball → WASM engine → TS types → score → city plan.
 * Exercises the exact Go↔TS JSON contract the web app relies on.
 *
 *   npx vite-node scripts/integration.ts -- owner/repo [ref]
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeScore } from '../src/analysis/score';
import { planCity } from '../src/city/layout';
import { parseRepoInput } from '../src/github/parse';
import { severityRank, type EngineReport } from '../src/types';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const slug = process.argv[2] ?? 'expressjs/express';
const ref = process.argv[3] ?? 'HEAD';

const target = parseRepoInput(slug);
if (!target) throw new Error(`unparseable repo: ${slug}`);

// boot the real WASM engine (Node flavor of what scan-worker.js does)
(0, eval)(readFileSync(join(root, 'public/wasm_exec.js'), 'utf8'));
const go = new (globalThis as any).Go();
const { instance } = await WebAssembly.instantiate(
  readFileSync(join(root, 'public/scanner.wasm')),
  go.importObject,
);
const ready = new Promise<void>((res) => ((globalThis as any).__threatscapeReady = res));
go.run(instance);
await ready;

const resp = await fetch(`https://codeload.github.com/${target.owner}/${target.repo}/zip/${ref}`);
if (!resp.ok) throw new Error(`zip ${resp.status}`);
const zip = new Uint8Array(await resp.arrayBuffer());

const raw = (globalThis as any).__threatscape.scanZip(zip) as string;
const report = JSON.parse(raw) as EngineReport & { error?: string };
if (report.error) throw new Error(report.error);

// ---- contract assertions ----
const assert = (cond: unknown, msg: string) => {
  if (!cond) throw new Error(`ASSERT: ${msg}`);
};
assert(Array.isArray(report.files) && report.files.length > 0, 'files[] populated');
assert(Array.isArray(report.findings), 'findings[]');
assert(report.stats.ruleCount > 70, 'rules registered');
for (const f of report.findings.slice(0, 50)) {
  assert(f.id && f.ruleId && f.title && f.severity && f.category, `finding shape: ${JSON.stringify(f)}`);
  assert(severityRank(f.severity) >= 1, `severity valid: ${f.severity}`);
}
const rolled = report.files.filter((f) => (f.findings ?? 0) > 0);
assert(
  report.findings.filter((f) => f.file).length === 0 || rolled.length > 0,
  'file rollups present when findings exist',
);

const score = computeScore(report.findings);
assert(score.value >= 0 && score.value <= 100, 'score in range');

const plan = planCity(report.files);
assert(plan.buildings.length === report.files.filter((f) => !f.path.startsWith('.git/')).length, 'building per file');
assert(plan.size >= 120 && plan.size <= 560, 'city size sane');
for (const b of plan.buildings) {
  assert(Number.isFinite(b.x) && Number.isFinite(b.z) && b.h > 0, `building finite: ${b.file.path}`);
}

console.log(`✓ ${slug}@${ref}`);
console.log(`  files=${report.files.length} findings=${report.findings.length} deps=${report.dependencies.length}`);
console.log(`  score=${score.value} (${score.grade} · ${score.threatLevel})`);
console.log(`  city: ${plan.buildings.length} buildings, ${plan.districts.filter((d) => d.depth === 1).length} districts, side=${plan.size.toFixed(0)}`);
console.log(`  engine: ${report.stats.durationMs}ms, ${report.stats.ruleCount} rules`);
console.log('integration OK');
process.exit(0);
