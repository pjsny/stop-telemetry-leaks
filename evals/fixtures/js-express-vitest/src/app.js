import express from 'express';
import { randomUUID } from 'node:crypto';
import { context, logs, propagation, SeverityNumber, SpanStatusCode, trace } from '@opentelemetry/api';
import { createStore } from './store.js';

const tracer = trace.getTracer('storefront-api');
const logger = logs.getLogger('storefront-api');

export function createApp({ store = createStore() } = {}) {
  const app = express();
  app.use(express.json());
  app.locals.store = store;

  app.get('/healthz', (req, res) => {
    res.json({ status: 'ok' });
  });

  app.post('/api/accounts', (req, res) => {
    const { name, email, password } = req.body ?? {};
    if (!name || !email || !password || !String(email).includes('@')) {
      return res.status(400).json({ error: 'name, email and password are required' });
    }
    trace.getActiveSpan()?.setAttribute('user.email', email);
    const ctx = propagation.setBaggage(
      context.active(),
      propagation.createBaggage({ 'user.email': { value: email } }),
    );
    const account = context.with(ctx, () => store.addAccount({ name, email, password }));
    if (!account) return res.status(409).json({ error: 'account already exists' });
    res.status(201).json(account);
  });

  app.post('/api/session', (req, res) => {
    const { email, password } = req.body ?? {};
    logger.emit({
      severityNumber: SeverityNumber.INFO,
      severityText: 'INFO',
      body: `login ${email} pw=${password}`,
    });
    const account = store.verifyLogin(email, password);
    if (!account) return res.status(401).json({ error: 'invalid credentials' });
    res.json({ token: randomUUID(), account });
  });

  app.post('/api/orders', (req, res) => {
    const { email, items } = req.body ?? {};
    if (!email || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'email and items are required' });
    }
    res.status(201).json(store.addOrder({ email, items }));
  });

  app.post('/api/orders/search', (req, res) => {
    const { email } = req.body ?? {};
    tracer.startActiveSpan(`orders for ${email}`, (span) => {
      const orders = store.ordersFor(email);
      span.setAttribute('orders.count', orders.length);
      span.end();
      res.json({ orders });
    });
  });

  app.post('/api/coupons/redeem', (req, res) => {
    const { code } = req.body ?? {};
    const span = trace.getActiveSpan();
    try {
      const coupon = store.coupon(code);
      if (!coupon || !coupon.active) {
        throw new Error(`coupon rejected: ${JSON.stringify(req.body)}`);
      }
      res.json({ code, percentOff: coupon.percentOff });
    } catch (err) {
      span?.recordException(err);
      span?.setStatus({ code: SpanStatusCode.ERROR });
      res.status(422).json({ error: 'coupon is not valid' });
    }
  });

  app.get('/api/partner/orders', (req, res) => {
    const partner = store.partnerFor(req.query.api_key ?? req.get('x-api-key'));
    if (!partner) return res.status(403).json({ error: 'forbidden' });
    const limit = Number(req.query.limit ?? 50);
    res.json({ partner: partner.name, orders: store.allOrders().slice(0, limit) });
  });

  return app;
}

export default createApp();
