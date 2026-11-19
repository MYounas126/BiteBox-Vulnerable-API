import { settings, vuln, award } from './config.js';

export function cors(req, res, next) {
  const origin = req.headers.origin;
  if (origin) {
    const allowed = settings.corsOrigins.includes(origin);
    if (vuln('L2-CORS-REFLECT')) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Access-Control-Allow-Credentials', 'true');
      if (!allowed && req.user && req.auth?.via === 'cookie') award(res, 'L2-CORS-REFLECT');
    } else if (allowed) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Access-Control-Allow-Credentials', 'true');
    }
    res.vary('Origin');
    if (req.method === 'OPTIONS') {
      res.set('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE');
      res.set('Access-Control-Allow-Headers', 'Authorization,Content-Type');
      return res.status(204).end();
    }
  }
  next();
}
