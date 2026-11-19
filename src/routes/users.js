import express from 'express';
import { db, publicUser } from '../db.js';
import { requireAuth } from '../auth.js';
import { vuln, award } from '../config.js';
import { fail } from '../errors.js';
import { body, str, id, PHONE, EMAIL } from '../validate.js';
import { registry } from '../registry.js';

// Request field -> column. Only name and phone are meant to be editable by the user.
const FIELDS = {
  name: { column: 'name', check: (v) => str(v, 'name', { max: 80 }) },
  phone: { column: 'phone', check: (v) => str(v, 'phone', { pattern: PHONE }) },
  email: { column: 'email', check: (v) => str(v, 'email', { pattern: EMAIL }) },
  role: { column: 'role', check: (v) => v },
  walletBalance: { column: 'wallet_balance', check: (v) => Number(v) },
  suspended: { column: 'suspended', check: (v) => (v ? 1 : 0) },
};
const EDITABLE = ['name', 'phone'];

export function userRoutes() {
  const router = express.Router();
  const r = registry(router, '/api/v2/users', 'Users');
  router.use(requireAuth);

  r.get('/me', { summary: 'Your profile' }, (req, res) => {
    res.json(publicUser(req.user));
  });

  r.patch('/me', { summary: 'Update your name or phone', body: { name: 'New Name', phone: '+920000001002' } }, (req, res) => {
    const b = body(req);
    const open = vuln('L4-MASS-ASSIGN');
    const sets = [];
    const values = [];
    for (const [key, value] of Object.entries(b)) {
      const field = FIELDS[key];
      if (!field) { if (!open) fail(400, `Unknown field ${key}`); continue; }
      if (!open && !EDITABLE.includes(key)) fail(400, `${key} cannot be changed`);
      sets.push(`${field.column} = ?`);
      values.push(field.check(value));
      if (!EDITABLE.includes(key)) award(res, 'L4-MASS-ASSIGN');
    }
    if (!sets.length) fail(400, 'Nothing to update');
    db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...values, req.user.id);
    res.json(publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)));
  });

  r.get('/me/addresses', { summary: 'Your saved addresses' }, (req, res) => {
    res.json(db.prepare('SELECT id, label, line1, city FROM addresses WHERE user_id = ?').all(req.user.id));
  });

  r.post('/me/addresses', {
    summary: 'Save an address', body: { label: 'Office', line1: '1 Lab Road', city: 'Karachi' },
  }, (req, res) => {
    const b = body(req);
    const row = [str(b.label, 'label', { max: 40 }), str(b.line1, 'line1', { max: 120 }), str(b.city, 'city', { max: 60 })];
    const aid = db.prepare('INSERT INTO addresses (user_id, label, line1, city) VALUES (?, ?, ?, ?)').run(req.user.id, ...row).lastInsertRowid;
    res.status(201).json({ id: aid, label: row[0], line1: row[1], city: row[2] });
  });

  r.delete('/me/addresses/:id', { summary: 'Delete one of your addresses' }, (req, res) => {
    const out = db.prepare('DELETE FROM addresses WHERE id = ? AND user_id = ?').run(id(req), req.user.id);
    if (!out.changes) fail(404, 'Address not found');
    res.status(204).end();
  });

  return router;
}
