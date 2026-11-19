import express from 'express';
import { db } from '../db.js';
import { requireRole } from '../auth.js';
import { settings, vuln } from '../config.js';
import { fail } from '../errors.js';
import { body, str, int, money, id } from '../validate.js';
import { naiveCheck, strictCheck, send, approvedCourier } from '../outbound.js';
import { orderView } from './orders.js';
import { registry } from '../registry.js';

// Orders only move forward through these steps.
const FLOW = ['paid', 'preparing', 'out_for_delivery', 'delivered'];
const STATUSES = FLOW.slice(1);

export function merchantRoutes() {
  const router = express.Router();
  const r = registry(router, '/api/v2/merchant', 'Merchant');
  router.use(requireRole('merchant'));

  const own = (req) => db.prepare('SELECT * FROM restaurants WHERE owner_id = ? ORDER BY id LIMIT 1').get(req.user.id)
    ?? fail(404, 'You have no restaurant');
  const view = (x) => ({
    id: x.id, name: x.name, cuisine: x.cuisine, city: x.city, rating: x.rating, webhookUrl: x.webhook_url, courierUrl: x.courier_url,
  });
  const ownItem = (req) => {
    const rest = own(req);
    return db.prepare('SELECT * FROM menu_items WHERE id = ? AND restaurant_id = ?').get(id(req, 'itemId'), rest.id)
      ?? fail(404, 'Menu item not found');
  };

  r.get('/restaurant', { summary: 'Your restaurant' }, (req, res) => res.json(view(own(req))));

  r.patch('/restaurant', {
    summary: 'Update your restaurant details', body: { name: 'Lab Kitchen', cuisine: 'Thai', city: 'Lahore' },
  }, (req, res) => {
    const rest = own(req);
    const b = body(req);
    const next = {
      name: str(b.name, 'name', { optional: true, max: 80 }) ?? rest.name,
      cuisine: str(b.cuisine, 'cuisine', { optional: true, max: 40 }) ?? rest.cuisine,
      city: str(b.city, 'city', { optional: true, max: 60 }) ?? rest.city,
    };
    db.prepare('UPDATE restaurants SET name = ?, cuisine = ?, city = ? WHERE id = ?').run(next.name, next.cuisine, next.city, rest.id);
    res.json(view({ ...rest, ...next }));
  });

  r.post('/menu', { summary: 'Add a menu item', body: { name: 'Chai', price: 2.5 } }, (req, res) => {
    const rest = own(req);
    const b = body(req);
    const name = str(b.name, 'name', { max: 80 });
    const price = money(b.price, 'price', { min: 0.5, max: 500 });
    if (db.prepare('SELECT COUNT(*) AS n FROM menu_items WHERE restaurant_id = ?').get(rest.id).n >= 100) fail(409, 'A menu can hold at most 100 items');
    const iid = db.prepare('INSERT INTO menu_items (restaurant_id, name, price) VALUES (?, ?, ?)').run(rest.id, name, price).lastInsertRowid;
    res.status(201).json({ id: iid, name, price, available: true });
  });

  r.patch('/menu/:itemId', {
    summary: 'Change a menu item', body: { price: 3, available: false },
  }, (req, res) => {
    const item = ownItem(req);
    const b = body(req);
    const name = str(b.name, 'name', { optional: true, max: 80 }) ?? item.name;
    const price = b.price === undefined ? item.price : money(b.price, 'price', { min: 0.5, max: 500 });
    const available = b.available === undefined ? item.available : (b.available ? 1 : 0);
    db.prepare('UPDATE menu_items SET name = ?, price = ?, available = ? WHERE id = ?').run(name, price, available, item.id);
    res.json({ id: item.id, name, price, available: !!available });
  });

  r.delete('/menu/:itemId', { summary: 'Remove a menu item' }, (req, res) => {
    db.prepare('UPDATE menu_items SET available = 0 WHERE id = ?').run(ownItem(req).id);
    res.status(204).end();
  });

  r.get('/orders', { summary: 'Orders placed at your restaurant' }, (req, res) => {
    const rest = own(req);
    res.json(db.prepare('SELECT * FROM orders WHERE restaurant_id = ? ORDER BY id DESC').all(rest.id).map((o) => orderView(o, { forMerchant: true })));
  });

  r.post('/orders/:id/status', {
    summary: 'Move an order along', body: { status: 'preparing' },
  }, (req, res) => {
    const rest = own(req);
    const o = db.prepare('SELECT * FROM orders WHERE id = ? AND restaurant_id = ?').get(id(req), rest.id) ?? fail(404, 'Order not found');
    const status = body(req).status;
    if (!STATUSES.includes(status)) fail(400, `status must be one of ${STATUSES.join(', ')}`);
    if (!FLOW.includes(o.status)) fail(409, 'Order has not been paid');
    if (FLOW.indexOf(status) <= FLOW.indexOf(o.status)) fail(409, `Order is already ${o.status}`);
    db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, o.id);
    res.json(orderView({ ...o, status }, { forMerchant: true }));
  });

  r.put('/webhook', {
    summary: 'Set the URL that receives your order events', body: { url: 'http://listener:8081/hooks/my-kitchen' },
  }, async (req, res) => {
    const rest = own(req);
    const raw = str(body(req).url, 'url', { max: 300 });
    if (vuln('L5-WEBHOOK-SSRF')) naiveCheck(raw);
    else await strictCheck(raw, settings.webhookAllowedHosts);
    db.prepare('UPDATE restaurants SET webhook_url = ? WHERE id = ?').run(raw, rest.id);
    res.json(view({ ...rest, webhook_url: raw }));
  });

  r.post('/webhook/test', { summary: 'Send a test event to your webhook' }, async (req, res) => {
    const rest = own(req);
    if (!rest.webhook_url) fail(400, 'Set a webhook URL first');
    const event = { event: 'webhook.test', restaurantId: rest.id, sentAt: new Date().toISOString() };
    if (vuln('L5-WEBHOOK-SSRF')) {
      naiveCheck(rest.webhook_url);
      const reply = await send(rest.webhook_url, event, { followRedirects: true });
      // Echoing the reply back is what turns a blind request into a readable one.
      return res.json({ deliveredTo: rest.webhook_url, status: reply.status, error: reply.error, responseBody: reply.text.slice(0, 4000) });
    }
    await strictCheck(rest.webhook_url, settings.webhookAllowedHosts);
    const reply = await send(rest.webhook_url, event, { followRedirects: false });
    res.json({ deliveredTo: rest.webhook_url, status: reply.status, delivered: reply.status >= 200 && reply.status < 300 });
  });

  r.put('/courier', {
    summary: 'Choose the courier partner that quotes your deliveries', body: { url: 'internal' },
  }, (req, res) => {
    const rest = own(req);
    const raw = str(body(req).url, 'url', { max: 300 });
    if (raw !== 'internal') {
      try { new URL(raw); } catch { fail(400, 'url must be "internal" or a full URL'); }
      if (!vuln('L5-COURIER-TRUST') && !approvedCourier(raw)) fail(400, 'Courier partner is not approved');
    }
    db.prepare('UPDATE restaurants SET courier_url = ? WHERE id = ?').run(raw, rest.id);
    res.json(view({ ...rest, courier_url: raw }));
  });

  return router;
}
