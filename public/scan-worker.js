/* ThreatScape scan worker.
 * Hosts the Go/WASM security engine off the main thread so multi-second
 * scans never drop a frame in the 3D viewport. Classic worker (importScripts)
 * so it needs no bundling and resolves wasm_exec.js / scanner.wasm relative
 * to its own URL.
 */
/* global Go */
importScripts('wasm_exec.js');

let enginePromise = null;

function bootEngine() {
  if (!enginePromise) {
    enginePromise = (async () => {
      const go = new Go();
      let instance;
      try {
        const result = await WebAssembly.instantiateStreaming(
          fetch('scanner.wasm'),
          go.importObject,
        );
        instance = result.instance;
      } catch {
        // Server may not send application/wasm; fall back to ArrayBuffer.
        const bytes = await (await fetch('scanner.wasm')).arrayBuffer();
        const result = await WebAssembly.instantiate(bytes, go.importObject);
        instance = result.instance;
      }
      const ready = new Promise((resolve) => {
        self.__threatscapeReady = resolve;
      });
      go.run(instance); // resolves only if Go exits; engine stays resident
      await ready;
      return self.__threatscape;
    })();
  }
  return enginePromise;
}

self.onmessage = async (ev) => {
  const msg = ev.data;
  if (!msg || !msg.id) return;
  try {
    const engine = await bootEngine();
    self.__threatscapeProgress = (done, total, path) => {
      self.postMessage({ id: msg.id, type: 'progress', done, total, path });
    };

    let json;
    if (msg.type === 'scan-zip') {
      json = engine.scanZip(new Uint8Array(msg.zip));
    } else if (msg.type === 'scan-files') {
      json = engine.scanFiles(msg.files);
    } else {
      throw new Error(`unknown message type ${msg.type}`);
    }

    const parsed = JSON.parse(json);
    if (parsed.error) {
      self.postMessage({ id: msg.id, type: 'error', message: parsed.error });
    } else {
      self.postMessage({ id: msg.id, type: 'result', report: parsed });
    }
  } catch (err) {
    self.postMessage({ id: msg.id, type: 'error', message: String(err && err.message || err) });
  }
};

self.postMessage({ type: 'worker-alive' });
bootEngine(); // start fetching + compiling the WASM immediately (prewarm)
