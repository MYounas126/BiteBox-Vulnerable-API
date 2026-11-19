// Refuses requests whose Host header is not a local name, which stops DNS-rebinding pages
// in the trainee's browser from talking to the lab as if they were on the same origin.
import { settings } from './config.js';

export function hostCheck(req, res, next) {
  const host = (req.headers.host ?? '').toLowerCase().replace(/:\d+$/, '');
  if (settings.allowedHostnames.includes(host)) return next();
  res.status(421).json({ error: 'Host not allowed' });
}
