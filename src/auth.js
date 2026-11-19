import { db } from './db.js';
import { verifyAccessToken } from './tokens.js';
import { award, vuln } from './config.js';
import { fail } from './errors.js';

export function readCookie(req, name) {
  const header = req.headers.cookie ?? '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

const SAFE = ['GET', 'HEAD', 'OPTIONS'];

// The session cookie is honoured for reads only. Writes need the Authorization header,
// which another page cannot attach, so cookie-based request forgery has nothing to ride on.
export function tokenFrom(req) {
  const h = req.headers.authorization ?? '';
  if (h.startsWith('Bearer ')) return { token: h.slice(7).trim(), via: 'header' };
  if (!SAFE.includes(req.method)) return null;
  const c = readCookie(req, 'bb_session');
  return c ? { token: c, via: 'cookie' } : null;
}

// Sets req.user when a valid token is present. Never rejects on its own.
export function authenticate(req, res, next) {
  const t = tokenFrom(req);
  if (!t) return next();
  const auth = verifyAccessToken(t.token);
  if (!auth) return next();
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(auth.userId);
  if (!user || user.suspended) return next();
  if (auth.forged) award(res, 'L3-WEAK-JWT');
  // With the weak setup the role comes from the token itself, not from the database.
  if (vuln('L3-WEAK-JWT') && auth.role) user.role = auth.role;
  req.user = user;
  req.auth = { ...auth, via: t.via };
  next();
}

export function requireAuth(req, res, next) {
  if (!req.user) fail(401, 'Authentication required');
  next();
}

export const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) fail(401, 'Authentication required');
  if (!roles.includes(req.user.role)) fail(403, 'Forbidden');
  next();
};
