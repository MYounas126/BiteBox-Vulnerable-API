// Access tokens (JWT) and refresh tokens.
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { db } from './db.js';
import { vuln } from './config.js';

// The weak setup a developer copied from a tutorial: the jwt.io example secret and no expiry.
const WEAK_SECRET = 'your-256-bit-secret';
const ISSUER = 'bitebox-api';
const AUDIENCE = 'bitebox-clients';

let keys;
const issued = new Map();   // fingerprint of each token this server signed -> time issued
const revoked = new Map();  // jti revoked at logout -> time it can be forgotten
const KEEP = 24 * 60 * 60 * 1000;

const MAX_ENTRIES = 50000;

// Drops expired entries once the map is large; if it is still full, drops the oldest.
function prune(map, expired) {
  if (map.size < MAX_ENTRIES) return;
  const now = Date.now();
  for (const [k, v] of map) if (expired(v, now)) map.delete(k);
  while (map.size >= MAX_ENTRIES) map.delete(map.keys().next().value);
}

const fingerprint = (t) => crypto.createHash('sha256').update(t).digest('hex');

export function resetTokens() {
  keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  issued.clear();
  revoked.clear();
}

export function issueAccessToken(user) {
  const jti = crypto.randomUUID();
  let token;
  if (vuln('L3-WEAK-JWT')) {
    token = jwt.sign({ sub: String(user.id), role: user.role, name: user.name, jti }, WEAK_SECRET, { algorithm: 'HS256' });
  } else {
    token = jwt.sign({ sub: String(user.id), jti }, keys.privateKey, {
      algorithm: 'RS256', issuer: ISSUER, audience: AUDIENCE, expiresIn: '15m',
    });
  }
  if (vuln('L3-WEAK-JWT')) {
    prune(issued, (t, now) => now - t > KEEP);
    issued.set(fingerprint(token), Date.now());
  }
  return token;
}

const REFRESH_TTL = 7 * 24 * 60 * 60 * 1000;

export function issueRefreshToken(user) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('DELETE FROM refresh_tokens WHERE expires_at < ?').run(Date.now());
  db.prepare('INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .run(fingerprint(token), user.id, Date.now() + REFRESH_TTL);
  return token;
}

// Returns { userId, role?, jti, forged } or null.
export function verifyAccessToken(token) {
  try {
    if (vuln('L3-WEAK-JWT')) {
      const p = jwt.verify(token, WEAK_SECRET);
      return { userId: Number(p.sub), role: p.role, jti: p.jti, forged: !issued.has(fingerprint(token)) };
    }
    const p = jwt.verify(token, keys.publicKey, {
      algorithms: ['RS256'], issuer: ISSUER, audience: AUDIENCE, maxAge: '15m',
    });
    if (revoked.has(p.jti)) return null;
    return { userId: Number(p.sub), jti: p.jti, forged: false };
  } catch {
    return null;
  }
}

// Refresh tokens are stored hashed, expire, and are single use. Presenting a used one
// means it was copied, so every refresh token for that user is revoked.
export function rotateRefreshToken(token) {
  const row = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(fingerprint(String(token ?? '')));
  if (!row) return null;
  if (row.revoked) {
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').run(row.user_id);
    return null;
  }
  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?').run(row.token_hash);
  return row.expires_at > Date.now() ? row.user_id : null;
}

export function logout(auth, userId) {
  if (!vuln('L3-WEAK-JWT') && auth?.jti) {
    prune(revoked, (until, now) => now > until);
    revoked.set(auth.jti, Date.now() + 16 * 60 * 1000);
  }
  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').run(userId);
}
