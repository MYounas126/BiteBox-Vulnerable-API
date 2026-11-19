// Even in vulnerable mode the API must never connect outside the lab: only its own
// loopback and the listener. This protects the trainee's laptop and network.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { lab, placeOrder, withHost } from './helpers.js';
import http from 'node:http';
import { once } from 'node:events';

let t;
before(async () => { t = await lab(5, false); });
after(() => t.close());

const outside = ['http://192.0.2.10/hook', 'http://169.254.169.254/latest/', 'http://10.0.0.1/', 'http://host.docker.internal:8080/'];

test('webhook tests cannot leave the lab', async () => {
  const m = await t.register('merchant');
  for (const url of outside) {
    assert.equal((await t.call('PUT', '/api/v2/merchant/webhook', { token: m.accessToken, body: { url } })).status, 200);
    const r = await t.call('POST', '/api/v2/merchant/webhook/test', { token: m.accessToken });
    assert.equal(r.json.status, 0, url);
    assert.match(r.json.error, /outside the lab/, url);
  }
});

test('courier quotes cannot leave the lab', async () => {
  const m = await t.register('merchant');
  const c = await t.register();
  const restId = (await t.call('GET', '/api/v2/merchant/restaurant', { token: m.accessToken })).json.id;
  const menu = (await t.call('GET', `/api/v2/restaurants/${restId}/menu`)).json;
  for (const url of outside) {
    await t.call('PUT', '/api/v2/merchant/courier', { token: m.accessToken, body: { url } });
    const order = await placeOrder(t, c.accessToken, restId, menu[0].id, 1);
    assert.equal((await t.call('GET', `/api/v2/orders/${order.id}/delivery-quote`, { token: c.accessToken })).status, 502, url);
  }
});

test('other services on loopback are out of reach, and the internal service checks Host', async () => {
  const other = http.createServer((req, res) => res.end('private'));
  other.listen(0, '127.0.0.1');
  await once(other, 'listening');
  try {
    const m = await t.register('merchant');
    const url = `http://127.1:${other.address().port}/`;
    await t.call('PUT', '/api/v2/merchant/webhook', { token: m.accessToken, body: { url } });
    const r = await t.call('POST', '/api/v2/merchant/webhook/test', { token: m.accessToken });
    assert.match(r.json.error, /outside the lab/);
    assert.equal(await withHost(`http://127.0.0.1:${t.internalPort}/ops`, 'rebind.example'), 421);
  } finally {
    other.close();
  }
});
