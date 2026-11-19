import express from 'express';
import { db } from '../db.js';
import { requireAuth } from '../auth.js';
import { vuln, award } from '../config.js';
import { fail } from '../errors.js';
import { body, str, int, id } from '../validate.js';
import { registry } from '../registry.js';

const MAX_PAGE = 50;
const restaurantView = (r) => ({ id: r.id, name: r.name, cuisine: r.cuisine, city: r.city, rating: r.rating });

export function restaurantRoutes() {
  const router = express.Router();
  const r = registry(router, '/api/v2/restaurants', 'Restaurants');

  r.get('/', {
    summary: 'Browse restaurants', auth: 'none', query: { city: 'Karachi', cuisine: 'Thai', limit: '20', offset: '0' },
  }, (req, res) => {
    const q = req.query;
    const limit = vuln('L5-NO-PAGE-LIMIT')
      ? int(q.limit ?? 20, 'limit', { min: 1 })
      : int(q.limit ?? 20, 'limit', { min: 1, max: MAX_PAGE });
    const offset = int(q.offset ?? 0, 'offset', { min: 0 });
    const where = ['approved = 1'];
    const args = [];
    if (q.city) { where.push('city = ?'); args.push(String(q.city)); }
    if (q.cuisine) { where.push('cuisine = ?'); args.push(String(q.cuisine)); }
    const rows = db.prepare(`SELECT * FROM restaurants WHERE ${where.join(' AND ')} ORDER BY id LIMIT ? OFFSET ?`)
      .all(...args, limit, offset);
    if (rows.length > 500) award(res, 'L5-NO-PAGE-LIMIT');
    res.json({ items: rows.map(restaurantView), limit, offset });
  });

  const load = (req) => db.prepare('SELECT * FROM restaurants WHERE id = ? AND approved = 1').get(id(req)) ?? fail(404, 'Restaurant not found');

  r.get('/:id', { summary: 'One restaurant', auth: 'none' }, (req, res) => {
    res.json(restaurantView(load(req)));
  });

  r.get('/:id/menu', { summary: 'A restaurant menu', auth: 'none' }, (req, res) => {
    const rest = load(req);
    res.json(db.prepare('SELECT id, name, price, available FROM menu_items WHERE restaurant_id = ?').all(rest.id)
      .map((i) => ({ ...i, available: !!i.available })));
  });

  r.get('/:id/reviews', { summary: 'Reviews for a restaurant', auth: 'none' }, (req, res) => {
    const rest = load(req);
    res.json(db.prepare(`SELECT v.id, v.rating, v.comment, v.created_at AS createdAt, u.name AS author
      FROM reviews v JOIN users u ON u.id = v.user_id WHERE v.restaurant_id = ? ORDER BY v.id DESC`).all(rest.id));
  });

  r.post('/:id/reviews', {
    summary: 'Review a restaurant you ordered from', body: { rating: 5, comment: 'Great food' },
  }, requireAuth, (req, res) => {
    const rest = load(req);
    const b = body(req);
    const rating = int(b.rating, 'rating', { min: 1, max: 5 });
    const comment = str(b.comment, 'comment', { max: 500 });
    const ordered = db.prepare("SELECT 1 FROM orders WHERE customer_id = ? AND restaurant_id = ? AND status IN ('paid','delivered')")
      .get(req.user.id, rest.id);
    if (!ordered) fail(403, 'You can only review restaurants you have ordered from');
    if (db.prepare('SELECT 1 FROM reviews WHERE restaurant_id = ? AND user_id = ?').get(rest.id, req.user.id)) {
      fail(409, 'You have already reviewed this restaurant');
    }
    const vid = db.prepare('INSERT INTO reviews (restaurant_id, user_id, rating, comment) VALUES (?, ?, ?, ?)')
      .run(rest.id, req.user.id, rating, comment).lastInsertRowid;
    res.status(201).json({ id: vid, rating, comment });
  });

  return router;
}
