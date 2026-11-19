// Shared test helpers: start the lab in-process on free ports and talk to it.
import http from 'node:http';
import { once } from 'node:events';
import { startLab } from '../src/server.js';
import { settings } from '../src/config.js';

export async function lab(level, secure, extra = {}) {
  const sms = await smsCatcher();
  const l = await startLab({
    level, secure, port: 0, internalPort: 0, host: '127.0.0.1', flagSeed: 'test-seed', listenerUrl: sms.url, ...extra,
  });
  const flags = [];
  const call = async (method, path, { body, token, headers = {}, raw } = {}) => {
    const r = await fetch(l.url + path, {
      method,
      headers: { ...(body !== undefined || raw ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
      body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined),
    });
    const text = await r.text();
    let json; try { json = JSON.parse(text); } catch { json = undefined; }
    const flag = r.headers.get('x-lab-flag');
    if (flag) flags.push(flag);
    return { status: r.status, json, text, flag, headers: r.headers };
  };
  let n = 0;
  const register = async (accountType = 'customer') => {
    n += 1;
    const email = `user${n}.${accountType}@lab.test`;
    const r = await call('POST', '/api/v2/auth/register', {
      body: { name: `Lab ${accountType} ${n}`, email, password: 'Passw0rd!lab', phone: `+92000000${1000 + n}`, accountType },
    });
    if (r.status !== 201) throw new Error(`register failed: ${r.text}`);
    return { ...r.json, email };
  };
  return { ...l, call, register, flags, sms, close: () => { l.close(); sms.close(); } };
}

// Stands in for the listener container: records SMS messages the lab sends.
export async function smsCatcher() {
  const messages = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => { try { messages.push(JSON.parse(raw)); } catch { /* ignore */ } res.end('ok'); });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    messages,
    async codeFor(email) {
      for (let i = 0; i < 50; i++) {
        const m = [...messages].reverse().find((x) => x.email === email);
        if (m) return m.message.match(/\d{4,6}/)[0];
        await new Promise((r) => setTimeout(r, 20));
      }
      throw new Error('no SMS received');
    },
    close: () => server.close(),
  };
}

// Sends a request with a chosen Host header, which fetch() does not allow.
export function withHost(url, host) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    http.get({ host: u.hostname, port: u.port, path: u.pathname, headers: { host } }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    }).on('error', reject);
  });
}

// A stand-in partner that answers every request with a fixed JSON body.
export async function fakePartner(reply) {
  const server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(reply)); });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  settings.extraLabPorts.push(server.address().port);
  return { url: `http://127.0.0.1:${server.address().port}/quote`, close: () => server.close() };
}

export async function placeOrder(t, token, restaurantId = 1, menuItemId = 1, qty = 2) {
  const r = await t.call('POST', '/api/v2/orders', { token, body: { restaurantId, items: [{ menuItemId, qty }] } });
  if (r.status !== 201) throw new Error(`order failed: ${r.text}`);
  return r.json;
}

export const ALIASED_OTP = (email, n) => `mutation { ${Array.from({ length: n }, (_, i) =>
  `a${i}: verifyOtp(email: "${email}", code: "${String(i).padStart(4, '0')}") { ok }`).join(' ')} }`;

export const DEEP_QUERY = '{ restaurant(id: 1) { menu { restaurant { menu { restaurant { menu { restaurant { menu { restaurant { name } } } } } } } } } }';
