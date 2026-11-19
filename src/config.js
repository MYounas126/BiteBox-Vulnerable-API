// Lab settings and the weakness switchboard.
// A weakness is live only when the lab runs at its level (or level 6) and SECURE is off.
import crypto from 'node:crypto';

const list = (v, d) => (v ?? d).split(',').map((s) => s.trim()).filter(Boolean);

export const settings = {
  level: Number(process.env.LAB_LEVEL ?? 1),
  secure: /^(1|true|yes|on)$/i.test(process.env.SECURE ?? ''),
  port: Number(process.env.PORT ?? 8080),
  host: process.env.HOST ?? '127.0.0.1',
  internalPort: Number(process.env.INTERNAL_PORT ?? 9100),
  flagSeed: process.env.FLAG_SEED ?? 'local-practice',
  listenerUrl: process.env.LISTENER_URL ?? 'http://listener:8081',
  corsOrigins: list(process.env.CORS_ORIGINS, 'http://localhost:3000'),
  webhookAllowedHosts: list(process.env.WEBHOOK_ALLOWED_HOSTS, 'listener'),
  courierAllowedUrls: list(process.env.COURIER_ALLOWED_URLS, 'http://listener:8081/courier'),
  extraLabPorts: [], // tests only: ports of stand-in partners on loopback
  allowedHostnames: list(process.env.ALLOWED_HOSTNAMES, '127.0.0.1,localhost,[::1]'),
};

export function configure(overrides = {}) {
  Object.assign(settings, overrides);
  if (!Number.isInteger(settings.level) || settings.level < 1 || settings.level > 6) {
    throw new Error(`LAB_LEVEL must be 1 to 6, got ${settings.level}`);
  }
}

export const WEAKNESSES = {
  'L2-ZOMBIE-V1':        { level: 2, top10: 'API9',  title: 'Old API version still answering' },
  'L2-SHADOW-DEBUG':     { level: 2, top10: 'API9',  title: 'Undocumented debug endpoint' },
  'L2-CORS-REFLECT':     { level: 2, top10: 'API8',  title: 'Any origin trusted with credentials' },
  'L2-VERBOSE-ERRORS':   { level: 2, top10: 'API8',  title: 'Stack traces in error responses' },
  'L3-WEAK-JWT':         { level: 3, top10: 'API2',  title: 'Weak token signing and verification' },
  'L3-NO-ATTEMPT-LIMIT': { level: 3, top10: 'API2',  title: 'Login code with no attempt limit' },
  'L4-BOLA-ORDER':       { level: 4, top10: 'API1',  title: 'Any order readable by any user' },
  'L4-MASS-ASSIGN':      { level: 4, top10: 'API3',  title: 'Profile update accepts protected fields' },
  'L4-BFLA-ADMIN-USERS': { level: 4, top10: 'API5',  title: 'Admin user list open to every role' },
  'L5-COUPON-RACE':      { level: 5, top10: 'API6',  title: 'Single-use coupon redeemable in parallel' },
  'L5-WEBHOOK-SSRF':     { level: 5, top10: 'API7',  title: 'Webhook test reaches internal services' },
  'L5-NO-PAGE-LIMIT':    { level: 5, top10: 'API4',  title: 'List endpoint with no maximum page size' },
  'L5-COURIER-TRUST':    { level: 5, top10: 'API10', title: 'Partner courier response used unchecked' },
  'L6-GQL-ADMIN-FIELD':  { level: 6, top10: 'API5',  title: 'GraphQL admin query open to every role' },
  'L6-GQL-DEPTH':        { level: 6, top10: 'API4',  title: 'GraphQL query depth not limited' },
  'L6-GQL-ALIAS-BATCH':  { level: 6, top10: 'API4',  title: 'GraphQL aliases batch many attempts in one request' },
};

export function vuln(id) {
  const w = WEAKNESSES[id];
  if (!w) throw new Error(`Unknown weakness ${id}`);
  return !settings.secure && (settings.level === 6 || settings.level === w.level);
}

export function flagFor(id, seed = settings.flagSeed) {
  const mac = crypto.createHmac('sha256', seed).update(id).digest('hex').slice(0, 12);
  return `BB{${id}_${mac}}`;
}

// Flags travel in a response header so they never change the shape of the API.
export function award(res, id) {
  if (vuln(id)) res.append('X-Lab-Flag', flagFor(id));
}
