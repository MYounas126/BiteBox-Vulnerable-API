// Things that should not be here. Neither route is in the OpenAPI spec.
import express from 'express';
import { db } from '../db.js';
import { settings, vuln, award } from '../config.js';
import { fail } from '../errors.js';
import { id } from '../validate.js';
import { internalBase } from '../outbound.js';
import { orderView } from './orders.js';
import { registry } from '../registry.js';

export function legacyV1Routes() {
  const router = express.Router();
  const r = registry(router, '/api/v1', 'Legacy');

  // Version 1 order lookup from before accounts had tokens. Left running for an old partner app.
  r.get('/orders/:id', { summary: 'Order lookup (v1)', auth: 'none', documented: false }, (req, res, next) => {
    if (!vuln('L2-ZOMBIE-V1')) return next();
    const o = db.prepare('SELECT * FROM orders WHERE id = ?').get(id(req)) ?? fail(404, 'Order not found');
    award(res, 'L2-ZOMBIE-V1');
    res.json({ apiVersion: 1, order: orderView(o) });
  });
  return router;
}

export function debugRoutes() {
  const router = express.Router();
  const r = registry(router, '/api/v2', 'Debug');

  r.get('/debug/config', { summary: 'Runtime configuration', auth: 'none', documented: false }, (req, res, next) => {
    if (!vuln('L2-SHADOW-DEBUG')) return next();
    award(res, 'L2-SHADOW-DEBUG');
    res.json({
      environment: 'staging',
      version: '2.4.1',
      database: { engine: 'sqlite', file: ':memory:' },
      cors: { allowedOrigins: settings.corsOrigins },
      services: {
        smsGateway: `${settings.listenerUrl}/sms`,
        courierDefault: `${internalBase()}/courier/quote`,
        opsConsole: `${internalBase()}/ops`,
      },
      uptimeSeconds: Math.round(process.uptime()),
    });
  });
  return router;
}
