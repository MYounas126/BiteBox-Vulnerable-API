// The lab's listener: records every request it receives and can be told what to answer.
//   GET    /_log       every request received, newest first
//   DELETE /_log       clear the log
//   POST   /_respond   {"path": "/x", "status": 200, "location": "...", "body": {...}} sets the reply for a path
//   DELETE /_respond   forget all configured replies
// Control calls must be sent as application/json, which a web page cannot do cross-site
// without a preflight this server never approves. Requests with a non-local Host are refused.
import http from 'node:http';

const PORT = Number(process.env.PORT ?? 8081);
const HOST = process.env.HOST ?? '127.0.0.1';
const ALLOWED = (process.env.ALLOWED_HOSTNAMES ?? '127.0.0.1,localhost,[::1],listener').split(',').map((s) => s.trim());
const log = [];
const replies = new Map();

const json = (res, status, data) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(status === 204 ? undefined : JSON.stringify(data, null, 2));
};

function parseReply(raw) {
  const r = JSON.parse(raw);
  if (typeof r.path !== 'string' || !r.path.startsWith('/') || r.path.startsWith('/_') || r.path.length > 200) throw new Error();
  const status = Number(r.status ?? 200);
  if (!Number.isInteger(status) || status < 200 || status > 599) throw new Error();
  if (r.location !== undefined && (typeof r.location !== 'string' || r.location.length > 500 || /[\r\n]/.test(r.location))) throw new Error();
  return { path: r.path, status, location: r.location, body: typeof r.body === 'string' ? r.body : JSON.stringify(r.body ?? {}) };
}

http.createServer((req, res) => {
  const host = (req.headers.host ?? '').toLowerCase().replace(/:\d+$/, '');
  if (!ALLOWED.includes(host)) return json(res, 421, { error: 'Host not allowed' });
  let raw = '';
  req.on('data', (c) => { raw += c; if (raw.length > 100000) req.destroy(); });
  req.on('end', () => {
    try {
      const path = new URL(req.url, 'http://listener').pathname;
      const control = path === '/_log' || path === '/_respond';
      if (control && req.method !== 'GET' && !String(req.headers['content-type'] ?? '').startsWith('application/json')) {
        return json(res, 415, { error: 'Control requests must use Content-Type: application/json' });
      }
      if (path === '/_log') {
        if (req.method === 'DELETE') { log.length = 0; return json(res, 204); }
        return json(res, 200, log);
      }
      if (path === '/_respond') {
        if (req.method === 'DELETE') { replies.clear(); return json(res, 204); }
        let reply;
        try { reply = parseReply(raw); } catch {
          return json(res, 400, { error: 'Send {"path": "/something", "status": 200, "location": "optional", "body": {}}' });
        }
        replies.set(reply.path, reply);
        return json(res, 200, { configured: reply.path });
      }
      log.unshift({ at: new Date().toISOString(), method: req.method, path: req.url, headers: req.headers, body: raw });
      if (log.length > 500) log.pop();
      const reply = replies.get(path);
      if (!reply) return json(res, 200, { ok: true });
      res.writeHead(reply.status, { 'content-type': 'application/json', ...(reply.location ? { location: reply.location } : {}) });
      res.end(reply.body);
    } catch {
      if (!res.headersSent) json(res, 500, { error: 'Listener error' });
    }
  });
}).listen(PORT, HOST, () => console.log(`Listener on ${HOST}:${PORT}. Log: GET /_log`));
