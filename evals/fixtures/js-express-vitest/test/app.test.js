import { beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { createStore } from '../src/store.js';

let app;
let store;

beforeEach(() => {
  store = createStore();
  store.addPartner('Northwind', 'nw-test-key');
  app = createApp({ store });
});

describe('health', () => {
  it('reports ok', async () => {
    const res = await request(app).get('/healthz');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });
});

describe('accounts and sessions', () => {
  it('creates an account and logs in', async () => {
    const created = await request(app)
      .post('/api/accounts')
      .send({ name: 'Ada Lovelace', email: 'ada@example.com', password: 'analytical-engine' });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ id: 1, email: 'ada@example.com' });

    const session = await request(app)
      .post('/api/session')
      .send({ email: 'ada@example.com', password: 'analytical-engine' });
    expect(session.status).toBe(200);
    expect(session.body.account.name).toBe('Ada Lovelace');
    expect(session.body.token).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('rejects duplicate accounts', async () => {
    const body = { name: 'Ada', email: 'ada@example.com', password: 'x1' };
    await request(app).post('/api/accounts').send(body);
    const res = await request(app).post('/api/accounts').send(body);
    expect(res.status).toBe(409);
  });

  it('rejects a wrong password', async () => {
    await request(app)
      .post('/api/accounts')
      .send({ name: 'Ada', email: 'ada@example.com', password: 'right' });
    const res = await request(app)
      .post('/api/session')
      .send({ email: 'ada@example.com', password: 'wrong' });
    expect(res.status).toBe(401);
  });
});

describe('orders', () => {
  it('creates and finds orders by email', async () => {
    const created = await request(app)
      .post('/api/orders')
      .send({ email: 'grace@example.com', items: [{ sku: 'MUG-01', quantity: 2, priceCents: 1200 }] });
    expect(created.status).toBe(201);
    expect(created.body.totalCents).toBe(2400);

    const found = await request(app).post('/api/orders/search').send({ email: 'grace@example.com' });
    expect(found.body.orders).toHaveLength(1);
  });

  it('validates order input', async () => {
    const res = await request(app).post('/api/orders').send({ email: 'grace@example.com', items: [] });
    expect(res.status).toBe(400);
  });
});

describe('coupons', () => {
  it('redeems an active coupon', async () => {
    const res = await request(app).post('/api/coupons/redeem').send({ code: 'WELCOME10' });
    expect(res.body).toEqual({ code: 'WELCOME10', percentOff: 10 });
  });

  it('rejects an expired coupon', async () => {
    const res = await request(app).post('/api/coupons/redeem').send({ code: 'SPRING25' });
    expect(res.status).toBe(422);
  });
});

describe('partner api', () => {
  it('lists orders for a known partner key', async () => {
    await request(app)
      .post('/api/orders')
      .send({ email: 'grace@example.com', items: [{ sku: 'TEE-02', quantity: 1, priceCents: 2500 }] });
    const res = await request(app).get('/api/partner/orders').query({ api_key: 'nw-test-key' });
    expect(res.status).toBe(200);
    expect(res.body.partner).toBe('Northwind');
    expect(res.body.orders).toHaveLength(1);
  });

  it('accepts the key as a header', async () => {
    const res = await request(app).get('/api/partner/orders').set('x-api-key', 'nw-test-key');
    expect(res.status).toBe(200);
  });

  it('rejects an unknown key', async () => {
    const res = await request(app).get('/api/partner/orders').query({ api_key: 'nope' });
    expect(res.status).toBe(403);
  });
});
