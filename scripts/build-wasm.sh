#!/usr/bin/env bash
# Compiles the Go security engine to WebAssembly and stages it (plus the Go
# JS runtime shim) into public/ where the web app loads it from.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "▸ go test"
(cd scanner && go test ./...)

echo "▸ building scanner.wasm"
(cd scanner && GOOS=js GOARCH=wasm go build -ldflags="-s -w" -trimpath -o ../public/scanner.wasm ./cmd/wasm)

WASM_EXEC="$(go env GOROOT)/lib/wasm/wasm_exec.js"
if [ ! -f "$WASM_EXEC" ]; then
  WASM_EXEC="$(go env GOROOT)/misc/wasm/wasm_exec.js" # Go < 1.24 layout
fi
cp "$WASM_EXEC" public/wasm_exec.js

ls -lh public/scanner.wasm public/wasm_exec.js
echo "✓ WASM engine ready"
