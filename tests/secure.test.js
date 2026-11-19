// Secure mode at level 6: every weakness must be closed and no flag may ever appear.
// These are the regression tests a fixed codebase has to pass.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import { settings } from '../src/config.js';
import { lab, placeOrder, fakePartner, withHost, ALIASED_OTP, DEEP_QUERY } from './helpers.js';

let t;
before(async () => { t = await lab(6, true, { courierAllowedUrls: [] }); });
after(() => {
  assert.deepEqual(t.flags, [], 'secure mode must never return a flag');
  t.close();
});

test('API9: old version and debug endpoint are gone', async () => {
  assert.equal((await t.call('GET', '/api/v1/orders/1')).status, 404);
  assert.equal((await t.call('GET', '/api/v2/debug/config')).status, 404);
});

test('API8: untrusted origins are not reflected', async () => {
  const r = await t.call('GET', '/api/v2/health', { headers: { origin: 'https://evil.example' } });
  assert.equal(r.headers.get('access-control-allow-origin'), null);
});

test('API8: errors do not leak internals', async () => {
  const r = await t.call('POST', '/api/v2/auth/login', { raw: '{"email": ' });
  assert.equal(r.status, 400);
  assert.equal(r.json.stack, undefined);
  assert.equal(r.headers.get('x-powered-by'), null);
});

test('API2: a token signed with a guessable secret is refused', async () => {
  const forged = jwt.sign({ sub: '1', role: 'admin', jti: 'x' }, 'your-256-bit-secret', { algorithm: 'HS256' });
  assert.equal((await t.call('GET', '/api/v2/users/me', { token: forged })).status, 401);
});

test('API2: logout revokes the access token', async () => {
  const u = await t.register();
  assert.equal((await t.call('POST', '/api/v2/auth/logout', { token: u.accessToken })).status, 204);
  assert.equal((await t.call('GET', '/api/v2/users/me', { token: u.accessToken })).status, 401);
});

test('API2: a refresh token works once, and reusing it revokes the newer one too', async () => {
  const u = await t.register();
  const first = await t.call('POST', '/api/v2/auth/refresh', { body: { refreshToken: u.refreshToken } });
  assert.equal(first.status, 200);
  assert.equal((await t.call('POST', '/api/v2/auth/refresh', { body: { refreshToken: u.refreshToken } })).status, 401);
  assert.equal((await t.call('POST', '/api/v2/auth/refresh', { body: { refreshToken: first.json.refreshToken } })).status, 401);
});

test('API2: asking for a code again resends it without resetting the attempt count', async () => {
  const u = await t.register();
  await t.call('POST', '/api/v2/auth/otp/request', { body: { email: u.email } });
  const code = await t.sms.codeFor(u.email);
  const wrong = code === '000000' ? '000001' : '000000';
  for (let i = 0; i < 3; i++) await t.call('POST', '/api/v2/auth/otp/verify', { body: { email: u.email, code: wrong } });
  await t.call('POST', '/api/v2/auth/otp/request', { body: { email: u.email } });
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(await t.sms.codeFor(u.email), code);
  for (let i = 0; i < 2; i++) await t.call('POST', '/api/v2/auth/otp/verify', { body: { email: u.email, code: wrong } });
  assert.equal((await t.call('POST', '/api/v2/auth/otp/verify', { body: { email: u.email, code } })).status, 429);
});

test('API2: new codes do not buy more guesses than the account budget', async () => {
  const u = await t.register();
  for (let round = 0; round < 2; round++) {
    await t.call('POST', '/api/v2/auth/otp/request', { body: { email: u.email } });
    const c = await t.sms.codeFor(u.email);
    const wrong = c === '000000' ? '000001' : '000000';
    for (let i = 0; i < 5; i++) await t.call('POST', '/api/v2/auth/otp/verify', { body: { email: u.email, code: wrong } });
    await t.call('POST', '/api/v2/auth/otp/verify', { body: { email: u.email, code: wrong } });
    t.sms.messages.length = 0;
  }
  await t.call('POST', '/api/v2/auth/otp/request', { body: { email: u.email } });
  const code = await t.sms.codeFor(u.email);
  assert.equal((await t.call('POST', '/api/v2/auth/otp/verify', { body: { email: u.email, code } })).status, 429);
});

test('Requests with a foreign Host header are refused', async () => {
  assert.equal(await withHost(`${t.url}/api/v2/health`, 'attacker.example'), 421);
  assert.equal(await withHost(`${t.url}/api/v2/health`, 'localhost:8000'), 200);
});

test('Orders only move forward, merchants do not see customer email, one review each', async () => {
  const m = await t.register('merchant');
  const c = await t.register();
  const restId = (await t.call('GET', '/api/v2/merchant/restaurant', { token: m.accessToken })).json.id;
  const menu = (await t.call('GET', `/api/v2/restaurants/${restId}/menu`)).json;
  const order = await placeOrder(t, c.accessToken, restId, menu[0].id, 1);
  assert.equal((await t.call('POST', `/api/v2/orders/${order.id}/pay`, { token: c.accessToken })).status, 409);
  await t.call('GET', `/api/v2/orders/${order.id}/delivery-quote`, { token: c.accessToken });
  assert.equal((await t.call('POST', `/api/v2/orders/${order.id}/pay`, { token: c.accessToken })).status, 200);
  const step = (status) => t.call('POST', `/api/v2/merchant/orders/${order.id}/status`, { token: m.accessToken, body: { status } });
  const delivered = await step('delivered');
  assert.equal(delivered.status, 200);
  assert.equal(delivered.json.customer.email, undefined);
  const viaOrders = await t.call('GET', `/api/v2/orders/${order.id}`, { token: m.accessToken });
  assert.equal(viaOrders.status, 200);
  assert.equal(viaOrders.json.customer.email, undefined);
  assert.equal((await step('preparing')).status, 409);
  const review = () => t.call('POST', `/api/v2/restaurants/${restId}/reviews`, { token: c.accessToken, body: { rating: 4, comment: 'Fine' } });
  assert.equal((await review()).status, 201);
  assert.equal((await review()).status, 409);
});

test('API2: a login code dies after five wrong guesses', async () => {
  const u = await t.register();
  await t.call('POST', '/api/v2/auth/otp/request', { body: { email: u.email } });
  const code = await t.sms.codeFor(u.email);
  assert.equal(code.length, 6);
  const wrong = code === '000000' ? '000001' : '000000';
  for (let i = 0; i < 5; i++) assert.equal((await t.call('POST', '/api/v2/auth/otp/verify', { body: { email: u.email, code: wrong } })).status, 401);
  assert.equal((await t.call('POST', '/api/v2/auth/otp/verify', { body: { email: u.email, code } })).status, 429);
});

test('API2: password login locks after five failures', async () => {
  const u = await t.register();
  for (let i = 0; i < 5; i++) await t.call('POST', '/api/v2/auth/login', { body: { email: u.email, password: 'wrong-password' } });
  assert.equal((await t.call('POST', '/api/v2/auth/login', { body: { email: u.email, password: 'Passw0rd!lab' } })).status, 429);
});

test('API1: another customer cannot read my order', async () => {
  const a = await t.register();
  const b = await t.register();
  const order = await placeOrder(t, a.accessToken);
  assert.equal((await t.call('GET', `/api/v2/orders/${order.id}`, { token: a.accessToken })).status, 200);
  assert.equal((await t.call('GET', `/api/v2/orders/${order.id}`, { token: b.accessToken })).status, 404);
});

test('API3: protected profile fields cannot be set', async () => {
  const u = await t.register();
  for (const body of [{ role: 'admin' }, { walletBalance: 9999 }, { email: 'x@lab.test' }]) {
    assert.equal((await t.call('PATCH', '/api/v2/users/me', { token: u.accessToken, body })).status, 400);
  }
  const me = await t.call('GET', '/api/v2/users/me', { token: u.accessToken });
  assert.equal(me.json.role, 'customer');
  assert.equal((await t.call('PATCH', '/api/v2/users/me', { token: u.accessToken, body: { name: 'Renamed' } })).json.name, 'Renamed');
});

test('API5: only admins list users', async () => {
  const c = await t.register();
  const m = await t.register('merchant');
  assert.equal((await t.call('GET', '/api/v2/admin/users', { token: c.accessToken })).status, 403);
  assert.equal((await t.call('GET', '/api/v2/admin/users', { token: m.accessToken })).status, 403);
});

test('API6: parallel coupon requests redeem once', async () => {
  const u = await t.register();
  const order = await placeOrder(t, u.accessToken);
  const results = await Promise.all(Array.from({ length: 6 }, () =>
    t.call('POST', `/api/v2/orders/${order.id}/apply-coupon`, { token: u.accessToken, body: { code: 'WELCOME10' } })));
  assert.equal(results.filter((r) => r.status === 200).length, 1);
  const after = await t.call('GET', `/api/v2/orders/${order.id}`, { token: u.accessToken });
  assert.equal(after.json.discount, Math.round(order.subtotal * 10) / 100);
});

test('API7: webhooks cannot point inside the server', async () => {
  const m = await t.register('merchant');
  for (const url of ['http://127.1:9100/ops', 'http://localhost/', 'http://169.254.169.254/', 'file:///etc/passwd', 'http://example.test/']) {
    assert.equal((await t.call('PUT', '/api/v2/merchant/webhook', { token: m.accessToken, body: { url } })).status, 400, url);
  }
});

test('API4: page size is capped', async () => {
  assert.equal((await t.call('GET', '/api/v2/restaurants?limit=1000')).status, 400);
  assert.equal((await t.call('GET', '/api/v2/restaurants?limit=50')).json.items.length, 50);
});

test('API10: unapproved courier partners are refused and quotes are validated', async () => {
  const m = await t.register('merchant');
  assert.equal((await t.call('PUT', '/api/v2/merchant/courier', { token: m.accessToken, body: { url: 'http://partner.example/quote' } })).status, 400);
  const c = await t.register();
  const restId = (await t.call('GET', '/api/v2/merchant/restaurant', { token: m.accessToken })).json.id;
  const menu = (await t.call('GET', `/api/v2/restaurants/${restId}/menu`)).json;
  const order = await placeOrder(t, c.accessToken, restId, menu[0].id, 1);
  const q = await t.call('GET', `/api/v2/orders/${order.id}/delivery-quote`, { token: c.accessToken });
  assert.equal(q.status, 200);
  assert.ok(q.json.deliveryFee > 0);
});

test('API10: a negative fee from an approved partner is rejected', async () => {
  const partner = await fakePartner({ fee: -40, etaMinutes: 5 });
  try {
    settings.courierAllowedUrls = [partner.url];
    const m = await t.register('merchant');
    assert.equal((await t.call('PUT', '/api/v2/merchant/courier', { token: m.accessToken, body: { url: partner.url } })).status, 200);
    const c = await t.register();
    const restId = (await t.call('GET', '/api/v2/merchant/restaurant', { token: m.accessToken })).json.id;
    const menu = (await t.call('GET', `/api/v2/restaurants/${restId}/menu`)).json;
    const order = await placeOrder(t, c.accessToken, restId, menu[0].id, 1);
    assert.equal((await t.call('GET', `/api/v2/orders/${order.id}/delivery-quote`, { token: c.accessToken })).status, 502);
  } finally {
    partner.close();
  }
});

test('GraphQL: introspection off, admin query guarded, depth and aliases limited', async () => {
  const c = await t.register();
  const intro = await t.call('POST', '/graphql', { body: { query: '{ __schema { queryType { name } } }' } });
  assert.equal(intro.status, 400);
  const stats = await t.call('POST', '/graphql', { token: c.accessToken, body: { query: '{ adminStats { users } }' } });
  assert.equal(stats.json.data.adminStats, null);
  assert.match(stats.json.errors[0].message, /Forbidden/);
  assert.equal((await t.call('POST', '/graphql', { body: { query: DEEP_QUERY } })).status, 400);
  assert.equal((await t.call('POST', '/graphql', { body: { query: ALIASED_OTP(c.email, 10) } })).status, 400);
});

test('Happy path: order, coupon, quote, pay', async () => {
  const u = await t.register();
  const order = await placeOrder(t, u.accessToken, 1, 1, 1);
  assert.equal((await t.call('POST', `/api/v2/orders/${order.id}/apply-coupon`, { token: u.accessToken, body: { code: 'FEAST20' } })).status, 200);
  const q = await t.call('GET', `/api/v2/orders/${order.id}/delivery-quote`, { token: u.accessToken });
  assert.equal(q.status, 200);
  const paid = await t.call('POST', `/api/v2/orders/${order.id}/pay`, { token: u.accessToken });
  assert.equal(paid.json.status, 'paid');
  const wallet = await t.call('GET', '/api/v2/wallet', { token: u.accessToken });
  assert.equal(wallet.json.balance, Math.round((50 - q.json.total) * 100) / 100);
});

test('GraphQL: nested fragment spreads are measured quickly', async () => {
  // Each fragment spreads the next one twice: without caching, measuring depth doubles at every level.
  const n = 24;
  const frags = Array.from({ length: n }, (_, i) => (i === n - 1
    ? `fragment F${i} on Restaurant { name }`
    : `fragment F${i} on Restaurant { ...F${i + 1} ...F${i + 1} }`)).join(' ');
  const started = Date.now();
  const r = await t.call('POST', '/graphql', { body: { query: `{ restaurant(id: 1) { ...F0 } } ${frags}` } });
  assert.ok(Date.now() - started < 1000, `took ${Date.now() - started} ms`);
  assert.equal(r.status, 200);
});

test('The session cookie does not authorise writes', async () => {
  const u = await t.register();
  const order = await placeOrder(t, u.accessToken);
  const cookie = `bb_session=${u.accessToken}`;
  assert.equal((await t.call('GET', '/api/v2/users/me', { headers: { cookie } })).status, 200);
  assert.equal((await t.call('POST', `/api/v2/orders/${order.id}/cancel`, { headers: { cookie } })).status, 401);
});

test('GraphQL nested lists are capped and menus have a size limit', async () => {
  const m = await t.register('merchant');
  let last;
  for (let i = 0; i < 100; i++) last = await t.call('POST', '/api/v2/merchant/menu', { token: m.accessToken, body: { name: `Item ${i}`, price: 1 } });
  assert.equal(last.status, 409);
  const restId = (await t.call('GET', '/api/v2/merchant/restaurant', { token: m.accessToken })).json.id;
  const r = await t.call('POST', '/graphql', { body: { query: `{ restaurant(id: ${restId}) { menu { restaurant { menu { name } } } } }` } });
  assert.equal(r.json.data.restaurant.menu.length, 50);
  assert.equal(r.json.data.restaurant.menu[0].restaurant.menu.length, 50);
});
