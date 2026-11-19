// Requests the server makes on a merchant's behalf: webhook tests and courier quotes.
//
// Containment applies in every mode, vulnerable or secure: the server only ever connects to
// its own loopback and to the listener container. The planted weaknesses live inside that
// boundary, so nothing a trainee does can reach their laptop, their network or the internet.
import http from 'node:http';
import dns from 'node:dns/promises';
import net from 'node:net';
import { settings } from './config.js';
import { fail } from './errors.js';

const MAX_REDIRECTS = 3;
const MAX_BODY = 64 * 1024;

export function internalBase() {
  return `http://127.0.0.1:${settings.internalPort}`;
}

function isLoopback(ip) {
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return isLoopback(v.slice(7));
  if (net.isIPv6(v)) return v === '::1';
  return v.split('.')[0] === '127';
}

async function addressesOf(hostname) {
  const h = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(h)) return [h];
  try { return (await dns.lookup(h, { all: true })).map((a) => a.address); } catch { return []; }
}

const portOf = (u) => Number(u.port || (u.protocol === 'https:' ? 443 : 80));

// Returns the single address to connect to, or null when the destination is outside the lab.
// Inside the lab means the internal services' port on loopback, or the listener's own address
// and port. Matching the port as well keeps other services on a trainee's laptop out of reach
// when the API runs outside Docker.
async function labAddress(u) {
  const addrs = await addressesOf(u.hostname);
  if (!addrs.length) return null;
  const port = portOf(u);
  const lu = new URL(settings.listenerUrl);
  const listener = await addressesOf(lu.hostname);
  const loopbackPorts = [settings.internalPort, ...settings.extraLabPorts];
  if (listener.some(isLoopback)) loopbackPorts.push(portOf(lu));
  const inside = (a) => (isLoopback(a) && loopbackPorts.includes(port)) || (listener.includes(a) && port === portOf(lu));
  return addrs.every(inside) ? addrs[0] : null;
}

// The filter the first developer wrote: block the obvious spellings of "this machine".
export function naiveCheck(raw) {
  let u;
  try { u = new URL(raw); } catch { fail(400, 'Invalid URL'); }
  if (/localhost|127\.0\.0\.1/i.test(String(raw))) fail(400, 'Internal addresses are not allowed');
  return u;
}

// The fix: http only, exact host allow-list, and the address must resolve inside the lab.
export async function strictCheck(raw, allowedHosts) {
  let u;
  try { u = new URL(raw); } catch { fail(400, 'Invalid URL'); }
  if (u.protocol !== 'http:') fail(400, 'Only http is allowed in the lab');
  if (u.username || u.password) fail(400, 'Credentials in URLs are not allowed');
  if (!allowedHosts.includes(u.hostname)) fail(400, 'Host is not on the allow-list');
  if (!(await labAddress(u))) fail(400, 'Host does not resolve to an approved address');
  return u;
}

// Connects to the already-checked address, so a second DNS answer cannot change the target.
function post(u, address, payload) {
  return new Promise((resolve) => {
    const data = JSON.stringify(payload);
    const req = http.request({
      host: address,
      port: u.port || 80,
      path: `${u.pathname}${u.search}`,
      method: 'POST',
      timeout: 4000,
      headers: {
        host: u.host,
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(data),
        'user-agent': 'Bitebox-Webhooks/1.0',
      },
    }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { if (text.length < MAX_BODY) text += c; });
      res.on('end', () => resolve({ status: res.statusCode, text, location: res.headers.location }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => resolve({ status: 0, text: '', error: e.message === 'timeout' ? 'timeout' : 'connection failed' }));
    req.end(data);
  });
}

export async function send(url, payload, { followRedirects }) {
  let u;
  try { u = new URL(url); } catch { return { status: 0, text: '', error: 'invalid URL' }; }
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (u.protocol !== 'http:') return { status: 0, text: '', error: 'only http is used inside the lab' };
    const address = await labAddress(u);
    if (!address) return { status: 0, text: '', error: 'destination is outside the lab' };
    const r = await post(u, address, payload);
    if (!(followRedirects && r.location && [301, 302, 303, 307, 308].includes(r.status))) return r;
    try { u = new URL(r.location, u); } catch { return { status: 0, text: '', error: 'bad redirect' }; }
  }
  return { status: 0, text: '', error: 'too many redirects' };
}

// Courier partners are approved by exact URL, never by prefix.
export function approvedCourier(raw) {
  if (raw === 'internal') return true;
  let u;
  try { u = new URL(raw); } catch { return false; }
  return settings.courierAllowedUrls.some((a) => { try { return new URL(a).href === u.href; } catch { return false; } });
}
