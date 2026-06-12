#!/usr/bin/env node
// Integration smoke test: runs the compiled scanner.wasm exactly the way the
// browser worker does, against a real GitHub zipball.
//   node scripts/smoke-wasm.mjs [owner/repo] [ref]
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = process.argv[2] ?? 'expressjs/express';
const ref = process.argv[3] ?? 'HEAD';

// Go's JS runtime shim (assigns globalThis.Go).
(0, eval)(readFileSync(join(root, 'public/wasm_exec.js'), 'utf8'));

const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(
  readFileSync(join(root, 'public/scanner.wasm')),
  go.importObject,
);
const ready = new Promise((res) => (globalThis.__threatscapeReady = res));
go.run(instance);
await ready;

console.log(`fetching https://codeload.github.com/${repo}/zip/${ref} …`);
const t0 = performance.now();
const resp = await fetch(`https://codeload.github.com/${repo}/zip/${ref}`);
if (!resp.ok) throw new Error(`zip fetch failed: ${resp.status}`);
const zip = new Uint8Array(await resp.arrayBuffer());
console.log(`zip: ${(zip.length / 1024).toFixed(0)} KiB in ${(performance.now() - t0).toFixed(0)}ms`);

let lastProgress = '';
globalThis.__threatscapeProgress = (done, total, path) => {
  lastProgress = `${done}/${total} ${path}`;
};

const t1 = performance.now();
const raw = globalThis.__threatscape.scanZip(zip);
const wall = performance.now() - t1;
const report = JSON.parse(raw);
if (report.error) throw new Error(`engine error: ${report.error}`);

const bySev = {};
for (const f of report.findings) bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;

console.log(`\n== ${repo}@${ref} ==`);
console.log(`files: ${report.stats.fileCount}  scanned: ${report.stats.scannedFiles}  lines: ${report.stats.totalLines}`);
console.log(`engine: ${report.stats.durationMs}ms (wall ${wall.toFixed(0)}ms)  rules: ${report.stats.ruleCount}`);
console.log(`languages: ${Object.entries(report.languages).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => `${k}:${(v / 1024).toFixed(0)}K`).join('  ')}`);
console.log(`dependencies: ${report.dependencies.length}`);
console.log(`findings: ${report.findings.length}  ${JSON.stringify(bySev)}`);
console.log(`last progress: ${lastProgress}`);
console.log('\ntop findings:');
for (const f of report.findings.slice(0, 12)) {
  console.log(`  [${f.severity.padEnd(8)}] ${f.ruleId.padEnd(28)} ${f.file}:${f.line}  ${f.title}`);
}
process.exit(0);
