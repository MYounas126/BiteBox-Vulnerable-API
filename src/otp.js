// One-time login codes. Shared by the REST endpoint and the GraphQL mutation.
import crypto from 'node:crypto';
import { db } from './db.js';
import { settings, vuln } from './config.js';

const MAX_ATTEMPTS = 5;             // wrong guesses allowed on one code
const ADDRESS_BUDGET = 10;          // wrong guesses per account from one address per hour
const ACCOUNT_BUDGET = 30;          // wrong guesses per account from all addresses per hour
const REQUEST_LIMIT = 3;            // codes sent per account per address per 15 minutes
const HOUR = 60 * 60 * 1000;
const QUARTER = 15 * 60 * 1000;

const failures = new Map();         // userId -> timestamps of wrong guesses
const requests = new Map();         // userId -> timestamps of code requests

export function resetOtp() {
  failures.clear();
  requests.clear();
}

const MAX_KEYS = 50000;

function recent(map, key, windowMs) {
  const now = Date.now();
  return (map.get(key) ?? []).filter((t) => now - t < windowMs);
}

// Never evicts live entries: when the table is full of them, the caller refuses instead.
function record(map, key, windowMs) {
  if (!map.has(key) && map.size >= MAX_KEYS) {
    for (const [k, list] of map) if (!list.some((t) => Date.now() - t < windowMs)) map.delete(k);
    if (map.size >= MAX_KEYS) return false;
  }
  map.set(key, [...recent(map, key, windowMs), Date.now()]);
  return true;
}

function sendSms(user, code) {
  // The "SMS gateway" is the lab's listener container. Read codes at http://127.0.0.1:8081/_log
  fetch(`${settings.listenerUrl}/sms`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ to: user.phone, email: user.email, message: `Your Bitebox login code is ${code}` }),
  }).catch(() => {});
}

export async function requestOtp(email, ip = '') {
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND suspended = 0').get(String(email ?? ''));
  if (!user) return;
  const open = vuln('L3-NO-ATTEMPT-LIMIT');
  if (open) {
    db.prepare('UPDATE otps SET used = 1 WHERE user_id = ?').run(user.id);
  } else {
    const key = `${user.id}|${ip}`;
    if (recent(requests, key, QUARTER).length >= REQUEST_LIMIT) return;
    if (!record(requests, key, QUARTER)) return;
    // Resend a live code instead of minting a new one, so asking again never resets the attempt count.
    const live = db.prepare('SELECT * FROM otps WHERE user_id = ? AND used = 0 AND expires_at > ? ORDER BY id DESC LIMIT 1')
      .get(user.id, Date.now());
    if (live) return sendSms(user, live.code);
  }
  const digits = open ? 4 : 6;
  const code = String(crypto.randomInt(0, 10 ** digits)).padStart(digits, '0');
  db.prepare('INSERT INTO otps (user_id, code, expires_at) VALUES (?, ?, ?)').run(user.id, code, Date.now() + 10 * 60 * 1000);
  sendSms(user, code);
}

// Returns { ok, status, error, user, awards }
export function verifyOtp(email, code, ip = '') {
  const awards = [];
  const open = vuln('L3-NO-ATTEMPT-LIMIT');
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND suspended = 0').get(String(email ?? ''));
  const otp = user && db.prepare('SELECT * FROM otps WHERE user_id = ? AND used = 0 AND expires_at > ? ORDER BY id DESC LIMIT 1')
    .get(user.id, Date.now());
  if (!otp) return { ok: false, status: 400, error: 'No active code. Request a new one.', awards };
  if (!open) {
    if (recent(failures, `${user.id}|${ip}`, HOUR).length >= ADDRESS_BUDGET || recent(failures, user.id, HOUR).length >= ACCOUNT_BUDGET) {
      return { ok: false, status: 429, error: 'Too many attempts. Try again later.', awards };
    }
    if (otp.attempts >= MAX_ATTEMPTS) {
      db.prepare('UPDATE otps SET used = 1 WHERE id = ?').run(otp.id);
      return { ok: false, status: 429, error: 'Too many attempts. Request a new code.', awards };
    }
  }
  if (String(code ?? '') !== otp.code) {
    db.prepare('UPDATE otps SET attempts = attempts + 1 WHERE id = ?').run(otp.id);
    if (!open && !(record(failures, `${user.id}|${ip}`, HOUR) && record(failures, user.id, HOUR))) return { ok: false, status: 429, error: 'Too many attempts. Try again later.', awards };
    return { ok: false, status: 401, error: 'Incorrect code', awards };
  }
  db.prepare('UPDATE otps SET used = 1 WHERE id = ?').run(otp.id);
  if (open && otp.attempts >= 20) awards.push('L3-NO-ATTEMPT-LIMIT');
  return { ok: true, status: 200, user, awards };
}
