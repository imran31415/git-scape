import { defineConfig, type Plugin, type ViteDevServer } from 'vite';

/**
 * Dev-only zip relay. The production app never needs it (api.github.com and
 * raw.githubusercontent.com are CORS-open from real browsers), but sandboxed
 * dev containers often only allow codeload.github.com — this middleware lets
 * the full pipeline run there. It does not exist in production builds, which
 * remain 100% backend-free.
 */
function devZipRelay(): Plugin {
  return {
    name: 'threatscape-dev-zip-relay',
    configureServer(server: ViteDevServer) {
      server.middlewares.use('/__ts_dev/zip', (req, res) => {
        const m = (req.url ?? '').match(/^\/?([\w.-]+)\/([\w.-]+)\/(.+)$/);
        if (!m) {
          res.statusCode = 400;
          res.end('expected /__ts_dev/zip/{owner}/{repo}/{ref}');
          return;
        }
        const upstream = `https://codeload.github.com/${m[1]}/${m[2]}/zip/${decodeURIComponent(m[3])}`;
        fetch(upstream)
          .then(async (r) => {
            if (!r.ok) {
              res.statusCode = r.status;
              res.end(`upstream ${r.status}`);
              return;
            }
            res.setHeader('content-type', 'application/zip');
            res.end(Buffer.from(await r.arrayBuffer()));
          })
          .catch((err) => {
            res.statusCode = 502;
            res.end(String(err));
          });
      });
    },
  };
}

export default defineConfig({
  base: './',
  plugins: [devZipRelay()],
  build: {
    target: 'es2022',
    chunkSizeWarningLimit: 1500,
  },
});
