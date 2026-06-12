/** Main-thread handle on the WASM scan worker. */
import type { EngineReport } from '../types';
import type { FetchedFile } from '../github/fetch';

interface WorkerMsg {
  id?: number;
  type: 'worker-alive' | 'progress' | 'result' | 'error';
  done?: number;
  total?: number;
  path?: string;
  report?: EngineReport;
  message?: string;
}

export class ScanEngine {
  private worker: Worker | null = null;
  private nextId = 1;

  private ensureWorker(): Worker {
    if (!this.worker) {
      this.worker = new Worker(new URL(`${import.meta.env.BASE_URL}scan-worker.js`, document.baseURI));
    }
    return this.worker;
  }

  /** Warm the worker + WASM while the user is still typing. */
  prewarm(): void {
    this.ensureWorker();
  }

  scan(
    payload: { kind: 'zip'; zip: ArrayBuffer } | { kind: 'files'; files: FetchedFile[] },
    onProgress: (done: number, total: number, path: string) => void,
  ): Promise<EngineReport> {
    const worker = this.ensureWorker();
    const id = this.nextId++;

    return new Promise<EngineReport>((resolve, reject) => {
      const onMessage = (ev: MessageEvent<WorkerMsg>) => {
        const msg = ev.data;
        if (msg.type === 'worker-alive' || msg.id !== id) return;
        if (msg.type === 'progress') {
          onProgress(msg.done ?? 0, msg.total ?? 0, msg.path ?? '');
        } else if (msg.type === 'result') {
          cleanup();
          // belt-and-braces against nil slices crossing the WASM boundary
          const r = msg.report!;
          r.files ??= [];
          r.findings ??= [];
          r.dependencies ??= [];
          r.languages ??= {};
          resolve(r);
        } else if (msg.type === 'error') {
          cleanup();
          reject(new Error(msg.message ?? 'scan failed'));
        }
      };
      const onError = (e: ErrorEvent) => {
        cleanup();
        reject(new Error(`scan worker crashed: ${e.message}`));
      };
      const cleanup = () => {
        worker.removeEventListener('message', onMessage);
        worker.removeEventListener('error', onError);
      };
      worker.addEventListener('message', onMessage);
      worker.addEventListener('error', onError);

      if (payload.kind === 'zip') {
        worker.postMessage({ id, type: 'scan-zip', zip: payload.zip }, [payload.zip]);
      } else {
        const transfers: ArrayBuffer[] = [];
        for (const f of payload.files) {
          if (f.data && f.data.buffer instanceof ArrayBuffer && f.data.byteLength === f.data.buffer.byteLength) {
            transfers.push(f.data.buffer);
          }
        }
        worker.postMessage({ id, type: 'scan-files', files: payload.files }, transfers);
      }
    });
  }

  dispose(): void {
    this.worker?.terminate();
    this.worker = null;
  }
}
