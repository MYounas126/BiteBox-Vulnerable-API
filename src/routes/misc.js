import express from 'express';
import { db } from '../db.js';
import { requireAuth } from '../auth.js';
import { registry } from '../registry.js';

export function miscRoutes() {
  const router = express.Router();
  const r = registry(router, '/api/v2', 'Account');

  r.get('/health', { summary: 'Service health', auth: 'none' }, (req, res) => {
    res.json({ status: 'ok', service: 'bitebox-api', version: '2.4.1' });
  });

  r.get('/wallet', { summary: 'Your wallet balance' }, requireAuth, (req, res) => {
    res.json({ balance: db.prepare('SELECT wallet_balance FROM users WHERE id = ?').get(req.user.id).wallet_balance, currency: 'USD' });
  });

  r.get('/wallet/transactions', { summary: 'Your wallet history' }, requireAuth, (req, res) => {
    res.json(db.prepare('SELECT id, amount, reason, created_at AS createdAt FROM wallet_tx WHERE user_id = ? ORDER BY id DESC')
      .all(req.user.id));
  });

  r.get('/coupons', { summary: 'Coupons you can use', auth: 'none' }, (req, res) => {
    res.json(db.prepare('SELECT code, percent FROM coupons WHERE active = 1').all()
      .map((c) => ({ ...c, rule: 'Once per customer' })));
  });

  return router;
}
