import express from 'express';
import { db } from '../db.js';
import { requireAuth } from '../auth.js';
import { vuln, award } from '../config.js';
import { fail } from '../errors.js';
import { body, str, int, id } from '../validate.js';
import { internalBase, send, approvedCourier } from '../outbound.js';
import { registry } from '../registry.js';

const round = (n) => Math.round(n * 100) / 100;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function orderView(o, { forMerchant = false } = {}) {
  const rest = db.prepare('SELECT id, name FROM restaurants WHERE id = ?').get(o.restaurant_id);
  const cust = db.prepare(forMerchant ? 'SELECT id, name, phone FROM users WHERE id = ?' : 'SELECT id, name, email, phone FROM users WHERE id = ?')
    .get(o.customer_id);
  const items = db.prepare(`SELECT oi.menu_item_id AS menuItemId, m.name, oi.qty, oi.unit_price AS unitPrice
    FROM order_items oi JOIN menu_items m ON m.id = oi.menu_item_id WHERE oi.order_id = ?`).all(o.id);
  return {
    id: o.id, status: o.status, restaurant: rest, customer: cust, items,
    subtotal: o.subtotal, discount: o.discount, deliveryFee: o.delivery_fee,
    total: round(o.subtotal - o.discount + o.delivery_fee), couponCode: o.coupon_code, createdAt: o.created_at,
  };
}

export function canSeeOrder(order, user) {
  if (user.role === 'admin' || order.customer_id === user.id) return true;
  return !!db.prepare('SELECT 1 FROM restaurants WHERE id = ? AND owner_id = ?').get(order.restaurant_id, user.id);
}

// Stands in for a call to the pricing service, which takes a moment.
const pricingCheck = () => sleep(250);

export function orderRoutes() {
  const router = express.Router();
  const r = registry(router, '/api/v2/orders', 'Orders');
  router.use(requireAuth);

  const mine = (req) => {
    const o = db.prepare('SELECT * FROM orders WHERE id = ?').get(id(req));
    if (!o || o.customer_id !== req.user.id) fail(404, 'Order not found');
    return o;
  };

  r.post('/', {
    summary: 'Place an order', body: { restaurantId: 1, items: [{ menuItemId: 1, qty: 2 }], addressId: null },
  }, (req, res) => {
    const b = body(req);
    const restaurantId = int(b.restaurantId, 'restaurantId');
    if (!Array.isArray(b.items) || !b.items.length || b.items.length > 20) fail(400, 'items must be a list of 1 to 20 entries');
    const rest = db.prepare('SELECT * FROM restaurants WHERE id = ? AND approved = 1').get(restaurantId) ?? fail(404, 'Restaurant not found');
    const lines = b.items.map((it, i) => {
      const menuItemId = int(it?.menuItemId, `items[${i}].menuItemId`);
      const qty = int(it?.qty, `items[${i}].qty`, { max: 20 });
      const m = db.prepare('SELECT * FROM menu_items WHERE id = ? AND restaurant_id = ? AND available = 1').get(menuItemId, rest.id);
      if (!m) fail(400, `Menu item ${menuItemId} is not available at this restaurant`);
      return { m, qty };
    });
    const addressId = b.addressId == null ? null : int(b.addressId, 'addressId');
    if (addressId && !db.prepare('SELECT 1 FROM addresses WHERE id = ? AND user_id = ?').get(addressId, req.user.id)) {
      fail(400, 'Unknown address');
    }
    const subtotal = round(lines.reduce((s, l) => s + l.m.price * l.qty, 0));
    const oid = db.prepare('INSERT INTO orders (customer_id, restaurant_id, address_id, subtotal) VALUES (?, ?, ?, ?)')
      .run(req.user.id, rest.id, addressId, subtotal).lastInsertRowid;
    const addLine = db.prepare('INSERT INTO order_items (order_id, menu_item_id, qty, unit_price) VALUES (?, ?, ?, ?)');
    for (const l of lines) addLine.run(oid, l.m.id, l.qty, l.m.price);
    res.status(201).json(orderView(db.prepare('SELECT * FROM orders WHERE id = ?').get(oid)));
  });

  r.get('/', { summary: 'Your orders' }, (req, res) => {
    res.json(db.prepare('SELECT * FROM orders WHERE customer_id = ? ORDER BY id DESC').all(req.user.id).map(orderView));
  });

  r.get('/:id', { summary: 'One of your orders' }, (req, res) => {
    const o = db.prepare('SELECT * FROM orders WHERE id = ?').get(id(req));
    if (!o) fail(404, 'Order not found');
    if (!canSeeOrder(o, req.user)) {
      if (!vuln('L4-BOLA-ORDER')) fail(404, 'Order not found');
      award(res, 'L4-BOLA-ORDER');
      return res.json(orderView(o));
    }
    const asMerchant = req.user.role !== 'admin' && o.customer_id !== req.user.id;
    res.json(orderView(o, { forMerchant: asMerchant }));
  });

  r.post('/:id/cancel', { summary: 'Cancel a pending order' }, (req, res) => {
    const o = mine(req);
    if (o.status !== 'pending') fail(409, 'Only pending orders can be cancelled');
    db.prepare("UPDATE orders SET status = 'cancelled' WHERE id = ?").run(o.id);
    res.json(orderView({ ...o, status: 'cancelled' }));
  });

  r.post('/:id/apply-coupon', {
    summary: 'Apply a coupon to a pending order (each coupon once per customer)', body: { code: 'WELCOME10' },
  }, async (req, res) => {
    const o = mine(req);
    if (o.status !== 'pending') fail(409, 'Coupons apply to pending orders only');
    const code = str(body(req).code, 'code', { max: 30 }).toUpperCase();
    const coupon = db.prepare('SELECT * FROM coupons WHERE code = ? AND active = 1').get(code) ?? fail(404, 'Unknown coupon');
    const discount = round((o.subtotal * coupon.percent) / 100);

    if (vuln('L5-COUPON-RACE')) {
      // Check, then wait for pricing, then write: two requests can both pass the check.
      const used = db.prepare('SELECT COUNT(*) AS n FROM redemptions WHERE user_id = ? AND code = ?').get(req.user.id, code).n;
      if (used) fail(409, 'You have already used this coupon');
      await pricingCheck();
      db.prepare('INSERT INTO redemptions (user_id, code, order_id) VALUES (?, ?, ?)').run(req.user.id, code, o.id);
      db.prepare('UPDATE orders SET discount = discount + ?, coupon_code = ? WHERE id = ?').run(discount, code, o.id);
      const n = db.prepare('SELECT COUNT(*) AS n FROM redemptions WHERE user_id = ? AND code = ?').get(req.user.id, code).n;
      if (n > 1) award(res, 'L5-COUPON-RACE');
    } else {
      // Claim the coupon in one atomic statement before doing anything slow.
      const claimed = db.prepare(`INSERT INTO redemptions (user_id, code, order_id)
        SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM redemptions WHERE user_id = ? AND code = ?)`)
        .run(req.user.id, code, o.id, req.user.id, code);
      if (claimed.changes !== 1) fail(409, 'You have already used this coupon');
      await pricingCheck();
      db.prepare('UPDATE orders SET discount = ?, coupon_code = ? WHERE id = ?').run(discount, code, o.id);
    }
    res.json(orderView(db.prepare('SELECT * FROM orders WHERE id = ?').get(o.id)));
  });

  r.get('/:id/delivery-quote', { summary: "Get a delivery fee from the restaurant's courier partner" }, async (req, res) => {
    const o = mine(req);
    if (o.status !== 'pending') fail(409, 'Quotes are for pending orders only');
    const rest = db.prepare('SELECT * FROM restaurants WHERE id = ?').get(o.restaurant_id);
    const url = rest.courier_url === 'internal' ? `${internalBase()}/courier/quote` : rest.courier_url;
    const trusting = vuln('L5-COURIER-TRUST');
    if (!trusting && !approvedCourier(rest.courier_url)) fail(502, 'Courier partner is not approved');
    const reply = await send(url, { orderId: o.id, subtotal: o.subtotal, city: rest.city }, { followRedirects: trusting });
    if (reply.status !== 200) fail(502, 'Courier partner did not answer');
    let quote;
    try { quote = JSON.parse(reply.text); } catch { fail(502, 'Courier partner sent an unreadable quote'); }
    let fee = Number(quote?.fee);
    let eta = Number(quote?.etaMinutes);
    if (trusting) {
      if (fee < 0) award(res, 'L5-COURIER-TRUST');
    } else if (!Number.isFinite(fee) || fee < 0 || fee > 100 || !Number.isInteger(eta) || eta < 1 || eta > 240) {
      fail(502, 'Courier partner sent an invalid quote');
    }
    fee = round(fee || 0);
    eta = eta || null;
    db.prepare("UPDATE orders SET delivery_fee = ?, quoted = 1 WHERE id = ? AND status = 'pending'").run(fee, o.id);
    res.json({ orderId: o.id, deliveryFee: fee, etaMinutes: eta, total: round(o.subtotal - o.discount + fee) });
  });

  r.post('/:id/pay', { summary: 'Pay for an order from your wallet' }, (req, res) => {
    const o = mine(req);
    if (o.status !== 'pending') fail(409, 'Order is not awaiting payment');
    if (!o.quoted) fail(409, 'Get a delivery quote before paying');
    const total = round(o.subtotal - o.discount + o.delivery_fee);
    const wallet = db.prepare('SELECT wallet_balance FROM users WHERE id = ?').get(req.user.id).wallet_balance;
    if (wallet < total) fail(402, 'Not enough wallet balance');
    db.prepare('UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?').run(total, req.user.id);
    db.prepare('INSERT INTO wallet_tx (user_id, amount, reason) VALUES (?, ?, ?)').run(req.user.id, -total, `Order ${o.id}`);
    db.prepare("UPDATE orders SET status = 'paid' WHERE id = ?").run(o.id);
    res.json(orderView({ ...o, status: 'paid' }));
  });

  return router;
}
