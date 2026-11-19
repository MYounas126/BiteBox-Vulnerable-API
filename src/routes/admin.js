import express from 'express';
import { db, publicUser } from '../db.js';
import { requireAuth, requireRole } from '../auth.js';
import { vuln, award } from '../config.js';
import { fail } from '../errors.js';
import { body, str, int, id } from '../validate.js';
import { registry } from '../registry.js';

export function stats() {
  const one = (sql) => Object.values(db.prepare(sql).get())[0];
  return {
    users: one('SELECT COUNT(*) FROM users'),
    orders: one('SELECT COUNT(*) FROM orders'),
    revenue: one("SELECT ROUND(COALESCE(SUM(subtotal - discount + delivery_fee), 0), 2) FROM orders WHERE status IN ('paid','delivered')"),
    restaurants: one('SELECT COUNT(*) FROM restaurants'),
  };
}

export function adminRoutes() {
  const router = express.Router();
  const r = registry(router, '/api/v2/admin', 'Admin');
  const admin = requireRole('admin');

  // The original version of this route only checked that the caller was logged in.
  const userListGuard = (req, res, next) => {
    if (!vuln('L4-BFLA-ADMIN-USERS')) return admin(req, res, next);
    requireAuth(req, res, () => {
      if (req.user.role !== 'admin') award(res, 'L4-BFLA-ADMIN-USERS');
      next();
    });
  };

  r.get('/users', { summary: 'All users (admin)', auth: ['admin'] }, userListGuard, (req, res) => {
    res.json(db.prepare('SELECT * FROM users ORDER BY id').all().map((u) => ({ ...publicUser(u), suspended: !!u.suspended })));
  });

  r.post('/users/:id/suspend', { summary: 'Suspend a user (admin)', auth: ['admin'] }, admin, (req, res) => {
    const out = db.prepare("UPDATE users SET suspended = 1 WHERE id = ? AND role != 'admin'").run(id(req));
    if (!out.changes) fail(404, 'User not found');
    res.json({ id: Number(req.params.id), suspended: true });
  });

  r.get('/stats', { summary: 'Platform numbers (admin)', auth: ['admin'] }, admin, (req, res) => res.json(stats()));

  r.post('/coupons', {
    summary: 'Create a coupon (admin)', auth: ['admin'], body: { code: 'LAB15', percent: 15 },
  }, admin, (req, res) => {
    const b = body(req);
    const code = str(b.code, 'code', { min: 3, max: 30, pattern: /^[A-Z0-9]+$/ });
    const percent = int(b.percent, 'percent', { min: 1, max: 50 });
    if (db.prepare('SELECT 1 FROM coupons WHERE code = ?').get(code)) fail(409, 'Coupon exists');
    db.prepare('INSERT INTO coupons (code, percent) VALUES (?, ?)').run(code, percent);
    res.status(201).json({ code, percent, active: true });
  });

  return router;
}
