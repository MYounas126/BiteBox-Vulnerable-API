import express from 'express';
import { initDb } from './db.js';
import { resetTokens } from './tokens.js';
import { resetOtp } from './otp.js';
import { settings, vuln } from './config.js';
import { authenticate } from './auth.js';
import { cors } from './cors.js';
import { hostCheck } from './hostcheck.js';
import { notFound, errorHandler } from './errors.js';
import { resetRegistry } from './registry.js';
import { openApi } from './spec.js';
import { authRoutes } from './routes/auth.js';
import { userRoutes } from './routes/users.js';
import { restaurantRoutes } from './routes/restaurants.js';
import { orderRoutes } from './routes/orders.js';
import { merchantRoutes } from './routes/merchant.js';
import { adminRoutes } from './routes/admin.js';
import { miscRoutes } from './routes/misc.js';
import { legacyV1Routes, debugRoutes } from './routes/legacy.js';
import { graphqlRoutes } from './graphql.js';

export function buildApp() {
  resetRegistry();
  initDb();
  resetTokens();
  resetOtp();

  const app = express();
  if (!vuln('L2-VERBOSE-ERRORS')) app.disable('x-powered-by');
  app.set('etag', false);
  app.use(hostCheck);
  app.use(express.json({ limit: '100kb' }));
  app.use(authenticate);
  app.use(cors);

  app.use('/api/v2/auth', authRoutes());
  app.use('/api/v2/users', userRoutes());
  app.use('/api/v2/restaurants', restaurantRoutes());
  app.use('/api/v2/orders', orderRoutes());
  app.use('/api/v2/merchant', merchantRoutes());
  app.use('/api/v2/admin', adminRoutes());
  app.use('/api/v2', debugRoutes());
  app.use('/api/v2', miscRoutes());
  app.use('/api/v1', legacyV1Routes());
  if (settings.level === 6) app.use(graphqlRoutes());

  app.get('/api/v2/openapi.json', (req, res) => res.json(openApi()));
  app.use(notFound);
  app.use(errorHandler);
  return app;
}
