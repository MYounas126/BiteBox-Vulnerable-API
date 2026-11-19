import express from 'express';
import { db, hashPassword, checkPassword, publicUser } from '../db.js';
import { issueAccessToken, issueRefreshToken, rotateRefreshToken, logout } from '../tokens.js';
import { requireAuth } from '../auth.js';
import { vuln, award } from '../config.js';
import { fail } from '../errors.js';
import { body, str, EMAIL, PHONE } from '../validate.js';
import { requestOtp, verifyOtp } from '../otp.js';
import { registry } from '../registry.js';

// Failed logins are counted per account and address, per address, and per account,
// so one attacker cannot lock a victim out and many addresses cannot share one budget.
const WINDOW = 15 * 60 * 1000;
const LIMITS = { pair: 5, ip: 20, account: 50 };
const failures = new Map(); // key -> timestamps
const DUMMY_HASH = hashPassword('only-used-to-keep-timing-even');

const MAX_KEYS = 50000;

function recentFailures(key) {
  const now = Date.now();
  return (failures.get(key) ?? []).filter((t) => now - t < WINDOW);
}

// Returns false when the table is full of live entries; the caller then refuses the login
// rather than forgetting anyone's failures.
function recordFailure(key) {
  if (!failures.has(key) && failures.size >= MAX_KEYS) {
    for (const [k, list] of failures) if (!list.some((t) => Date.now() - t < WINDOW)) failures.delete(k);
    if (failures.size >= MAX_KEYS) return false;
  }
  failures.set(key, [...recentFailures(key), Date.now()]);
  return true;
}

function session(res, user, status = 200) {
  const accessToken = issueAccessToken(user);
  const refreshToken = issueRefreshToken(user);
  res.append('Set-Cookie', `bb_session=${accessToken}; Path=/; HttpOnly; SameSite=Lax`);
  res.status(status).json({ user: publicUser(user), accessToken, refreshToken });
}

export function authRoutes() {
  failures.clear();
  const router = express.Router();
  const r = registry(router, '/api/v2/auth', 'Auth');

  r.post('/register', {
    summary: 'Create a customer or merchant account', auth: 'none',
    body: { name: 'Test Customer', email: 'trainee1@lab.test', password: 'Passw0rd!lab', phone: '+920000001001', accountType: 'customer' },
  }, (req, res) => {
    const b = body(req);
    const name = str(b.name, 'name', { max: 80 });
    const email = str(b.email, 'email', { max: 120, pattern: EMAIL }).toLowerCase();
    const password = str(b.password, 'password', { min: 8, max: 128 });
    const phone = str(b.phone, 'phone', { optional: true, pattern: PHONE });
    const type = b.accountType ?? 'customer';
    if (!['customer', 'merchant'].includes(type)) fail(400, 'accountType must be customer or merchant');
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) fail(409, 'Email already registered');
    const uid = db.prepare('INSERT INTO users (name, email, phone, password_hash, role, wallet_balance) VALUES (?, ?, ?, ?, ?, ?)')
      .run(name, email, phone ?? null, hashPassword(password), type, type === 'customer' ? 50 : 0).lastInsertRowid;
    if (type === 'merchant') {
      const rid = db.prepare('INSERT INTO restaurants (owner_id, name, cuisine, city) VALUES (?, ?, ?, ?)')
        .run(uid, `${name}'s Kitchen`, 'Pakistani', 'Karachi').lastInsertRowid;
      const add = db.prepare('INSERT INTO menu_items (restaurant_id, name, price) VALUES (?, ?, ?)');
      add.run(rid, 'House Biryani', 12);
      add.run(rid, 'Raita', 2);
    }
    session(res, db.prepare('SELECT * FROM users WHERE id = ?').get(uid), 201);
  });

  r.post('/login', {
    summary: 'Log in with email and password', auth: 'none',
    body: { email: 'trainee1@lab.test', password: 'Passw0rd!lab' },
  }, (req, res) => {
    const b = body(req);
    const email = str(b.email, 'email', { max: 120 }).toLowerCase();
    const password = str(b.password, 'password', { max: 128 });
    const limited = !vuln('L3-NO-ATTEMPT-LIMIT');
    const keys = { pair: `p:${email}|${req.ip}`, ip: `i:${req.ip}`, account: `a:${email}` };
    if (limited && Object.entries(keys).some(([k, key]) => recentFailures(key).length >= LIMITS[k])) {
      fail(429, 'Too many failed logins. Try again later.');
    }
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    const good = checkPassword(password, user?.password_hash ?? DUMMY_HASH) && !!user;
    if (!good) {
      if (limited && !Object.values(keys).every(recordFailure)) fail(429, 'Too many failed logins. Try again later.');
      fail(401, 'Invalid email or password');
    }
    if (user.suspended) fail(403, 'Account suspended');
    failures.delete(keys.pair);
    session(res, user);
  });

  r.post('/otp/request', {
    summary: 'Send a one-time login code by SMS', auth: 'none', body: { email: 'trainee1@lab.test' },
  }, async (req, res) => {
    await requestOtp(str(body(req).email, 'email', { max: 120 }).toLowerCase(), req.ip);
    res.json({ sent: true, message: 'If the account exists, a code has been sent.' });
  });

  r.post('/otp/verify', {
    summary: 'Log in with a one-time code', auth: 'none', body: { email: 'trainee1@lab.test', code: '0000' },
  }, (req, res) => {
    const b = body(req);
    const result = verifyOtp(str(b.email, 'email', { max: 120 }).toLowerCase(), str(b.code, 'code', { min: 4, max: 6 }), req.ip);
    for (const id of result.awards) award(res, id);
    if (!result.ok) fail(result.status, result.error);
    session(res, result.user);
  });

  r.post('/refresh', {
    summary: 'Swap a refresh token for a new pair', auth: 'none', body: { refreshToken: '{{refreshToken}}' },
  }, (req, res) => {
    const userId = rotateRefreshToken(body(req).refreshToken);
    const user = userId && db.prepare('SELECT * FROM users WHERE id = ? AND suspended = 0').get(userId);
    if (!user) fail(401, 'Invalid refresh token');
    session(res, user);
  });

  r.post('/logout', { summary: 'End the session' }, requireAuth, (req, res) => {
    logout(req.auth, req.user.id);
    res.append('Set-Cookie', 'bb_session=; Path=/; HttpOnly; Max-Age=0');
    res.status(204).end();
  });

  return router;
}
