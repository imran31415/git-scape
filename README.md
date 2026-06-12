# ThreatScape 🏙️⚠️

**Paste a GitHub URL → watch the repository rise as a 3D cyber-city, with threat actors hovering over the code they'd attack.**

ThreatScape is a fully client-side security visualizer. An in-browser **Go → WebAssembly** engine
scans every file for leaked secrets, injection sinks, weak crypto, and infrastructure
misconfigurations; your dependencies are cross-referenced against **[OSV.dev](https://osv.dev)** for
known CVEs; then the whole repository is rendered as a living night city in **Three.js** —
districts for directories, buildings for files, and animated threat actors locked onto every
vulnerable rooftop.

**There is no backend.** The repo is fetched browser→GitHub directly, the scan runs in a Web
Worker on your machine, and detected secrets are masked before they're ever displayed.

---

## Quick start

```bash
npm install
npm run dev          # → http://localhost:5173
```

Paste something like `juice-shop/juice-shop` (the deliberately vulnerable OWASP app — the city
will be on fire) or any public repo. Add a fine-grained GitHub token in the landing screen for
private repos or extra rate-limit headroom; it's stored in localStorage and sent only to
`api.github.com`.

```bash
npm run build        # static site in dist/ — host anywhere (Pages, S3, nginx…)
npm test             # vitest: layout/scoring/CVSS/parsing + headless 3D world
npm run go:test      # Go engine unit tests
npm run wasm:build   # recompile scanner.wasm (requires Go ≥ 1.24)
npx vite-node scripts/integration.ts owner/repo   # full pipeline against a real repo, no browser needed
```

A prebuilt `public/scanner.wasm` is committed, so the web app works without a Go toolchain.

## How a URL becomes a city

```
 GitHub URL
    │
    ▼
┌─────────────────────────────┐   strategy ladder, all CORS-open from browsers:
│ 1 · acquire                 │   ① api.github.com (meta + recursive tree, 2 calls)
│     fetch tree + contents   │      + raw.githubusercontent.com (contents, pooled ×24)
│                             │   ② jsDelivr mirror (rate-limit fallback)
│                             │   ③ token → blobs API (private repos)
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐   Web Worker → Go/WASM (scanner/)
│ 2 · scan                    │   81 rules: secrets (entropy + placeholder filters,
│     engine.Scan(files)      │   values masked), SAST for 10 languages, Dockerfile/
│                             │   K8s/Actions/Terraform/compose checks, repo hygiene,
│                             │   dependency manifests for 7 ecosystems
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐   api.osv.dev querybatch → advisory hydration →
│ 3 · cross-reference         │   CVSS v3 base scores computed from vectors →
│     OSV.dev (CORS-open)     │   per-dependency findings (graceful offline skip)
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐   squarified treemap (Bruls et al.) → districts/
│ 4 · construct               │   buildings; instanced meshes, emissive windows,
│     Three.js night city     │   severity glow shells, neon curbs, data traffic,
│                             │   radar sweep, bloom; threat actors + beams
└─────────────────────────────┘
```

### Reading the city

| Element | Meaning |
| --- | --- |
| **District** (raised pad + neon curb) | Top-level directory. Curb color = worst finding inside (cyan = clean). |
| **Building** | One file. Footprint ∝ size, height ∝ lines, facade color = language. |
| **Glowing shell** around a building | The file has findings; color = worst severity. |
| **Hovering actor + beam onto a roof** | A cluster of findings (one actor per file × category). Click it. |
| **Actor silhouettes** | 🗝️ Credential Phantom · 💉 Injection Wraith · 👻 Script Specter · 🔓 Cipher Breaker · 📡 Wire Eavesdropper · ⚙️ Config Goblin · 🧨 Pipeline Saboteur · 🪱 Supply-Chain Parasite · 🐀 Entropy Rat |
| **Score dial** | 100 − severity-weighted penalty (geometric diminishing returns), graded A+…F with a threat level from FORTRESS to CRITICAL BREACH. |

**▶ THREAT TOUR** autopilots the camera between the worst findings. Click any building for its
dossier (findings, snippet, CWE, GitHub deep link), filter by severity chips or actor legend,
`O` resets the camera, `📷` exports a PNG.

Calibration reference: `expressjs/express` ≈ 92 (A) · `pallets/flask` ≈ 74 (C) ·
`juice-shop/juice-shop` ≈ 9 (F).

## Architecture notes

- **`scanner/`** — Go module (stdlib only). `engine.Scan` is pure and unit-tested; `cmd/wasm`
  binds it to JS (`__threatscape.scanZip/scanFiles`). Regexes are RE2-safe and executed via
  *windowed matching*: each rule declares literal prefilters, and the regex only runs on small
  windows around prefilter hits — a ~3× speedup that scans juice-shop's 1,258 files in ~2.5 s
  inside WASM.
- **`public/scan-worker.js`** — classic worker hosting the WASM so multi-second scans never drop
  a frame in the viewport (same pattern as Fulcrum's text engine).
- **`src/three/`** — scene engine (ACES tonemapping + UnrealBloom), instanced city builder,
  procedural threat actors. The whole scene-graph layer is testable headlessly (see
  `src/three/world.test.ts`).
- **`vite.config.ts`** — includes a *dev-only* zip relay so the pipeline can run inside sandboxed
  dev containers where only `codeload.github.com` is reachable. Production builds contain no
  trace of it and remain backend-free.

## Honest limitations

This is pattern-based static analysis, not a taint-tracking SAST: a finding means *“this
construct deserves eyes,”* not *“this is exploitable”* — and a clean sweep doesn't mean the code
is safe. Findings under `test/`/`docs/`/`examples/` paths are automatically downgraded one
severity. Range-declared dependency versions (`^1.2.3`) are checked at their declared minimum
unless a lockfile pins them. Files > 400 KB, binaries, vendored/minified bundles and lockfiles
are skipped (caps: 2,600 files / 56 MB per analysis).

## Privacy

Repo contents go browser↔GitHub only. The scan runs locally in WASM. OSV queries contain only
package names + versions. Secret values are masked (`AKIA••••••…`) before they're rendered or
exported. Your GitHub token, if provided, lives in localStorage and is attached only to
`api.github.com` requests.

---

Part of the [Fulcrum](../README.md) family of zero-backend WASM tools, but fully self-contained —
to extract it into its own repository:

```bash
git subtree split --prefix=threatscape -b threatscape-standalone
# push that branch anywhere, or simply copy the threatscape/ directory
```

MIT License.
