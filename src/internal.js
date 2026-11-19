// Services that listen on the container's loopback only and are never published:
// the default courier partner and an internal operations console.
import http from 'node:http';
import { once } from 'node:events';
import { flagFor } from './config.js';

export async function startInternal(port) {
  const server = http.createServer((req, res) => {
    const host = (req.headers.host ?? '').toLowerCase().replace(/:\d+$/, '');
    if (!['127.0.0.1', 'localhost'].includes(host)) {
      res.statusCode = 421;
      return res.end('{"error":"Host not allowed"}');
    }
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 10000) req.destroy(); });
    req.on('end', () => {
      res.setHeader('content-type', 'application/json');
      if (req.url.startsWith('/courier/quote')) {
        let subtotal = 0;
        try { subtotal = Number(JSON.parse(raw).subtotal) || 0; } catch { /* default */ }
        return res.end(JSON.stringify({ partner: 'Bitebox Fleet', fee: Math.round((2.5 + subtotal * 0.05) * 100) / 100, etaMinutes: 35 }));
      }
      if (req.url.startsWith('/ops')) {
        return res.end(JSON.stringify({
          service: 'ops-console', environment: 'internal',
          message: 'Internal operations console. This should never be reachable from outside the container.',
          flag: flagFor('L5-WEBHOOK-SSRF'),
        }));
      }
      res.statusCode = 404;
      res.end(JSON.stringify({ error: 'Not found' }));
    });
  });
  server.listen(port, '127.0.0.1');
  await once(server, 'listening');
  return server;
}
