'use strict';

const http = require('node:http');
const { buildApp } = require('../src/app');

let creditServer;
let creditUrl;
let app;

beforeAll(async () => {
  creditServer = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname !== '/v1/score' || url.searchParams.get('access_token') !== 'test-credit-token') {
      res.writeHead(401).end();
      return;
    }
    const customer = Number(url.searchParams.get('customer'));
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ score: customer === 1 ? 712 : 590 }));
  });
  await new Promise((resolve) => creditServer.listen(0, '127.0.0.1', resolve));
  creditUrl = `http://127.0.0.1:${creditServer.address().port}`;
});

afterAll(async () => {
  await new Promise((resolve) => creditServer.close(resolve));
});

beforeEach(() => {
  app = buildApp({ config: { creditServiceUrl: creditUrl, creditApiToken: 'test-credit-token' } });
});

afterEach(async () => {
  await app.close();
});

async function createCustomer(overrides = {}) {
  return app.inject({
    method: 'POST',
    url: '/customers',
    payload: { name: 'Maria Garcia', phone: '+14155550123', ssn: '219-09-9999', ...overrides },
  });
}

test('health check', async () => {
  const res = await app.inject({ method: 'GET', url: '/healthz' });
  expect(res.json()).toEqual({ status: 'ok' });
});

test('creates a customer without exposing the ssn', async () => {
  const res = await createCustomer();
  expect(res.statusCode).toBe(201);
  expect(res.json()).toEqual({ id: 1, name: 'Maria Garcia', phone: '+14155550123', tier: 'standard' });
});

test('rejects malformed phone numbers', async () => {
  const res = await createCustomer({ phone: '555-0123' });
  expect(res.statusCode).toBe(400);
});

test('rejects duplicate customers', async () => {
  await createCustomer();
  const res = await createCustomer({ name: 'M. Garcia' });
  expect(res.statusCode).toBe(409);
});

test('fetches a customer by id', async () => {
  await createCustomer();
  const res = await app.inject({ method: 'GET', url: '/customers/1' });
  expect(res.json().name).toBe('Maria Garcia');
});

test('verifies a customer by ssn', async () => {
  await createCustomer();
  const res = await app.inject({ method: 'POST', url: '/customers/verify', payload: { ssn: '219-09-9999' } });
  expect(res.json()).toMatchObject({ verified: true, customer: { id: 1 } });
});

test('verification fails for unknown ssn', async () => {
  const res = await app.inject({ method: 'POST', url: '/customers/verify', payload: { ssn: '219-09-9998' } });
  expect(res.statusCode).toBe(404);
});

test('approves good credit', async () => {
  await createCustomer();
  const res = await app.inject({ method: 'GET', url: '/customers/1/credit' });
  expect(res.json()).toEqual({ customerId: 1, score: 712, approved: true });
});

test('declines low credit', async () => {
  await createCustomer();
  await createCustomer({ name: 'Lee Chen', phone: '+442071838750', ssn: '219-09-9991' });
  const res = await app.inject({ method: 'GET', url: '/customers/2/credit' });
  expect(res.json()).toEqual({ customerId: 2, score: 590, approved: false });
});

test('reports credit service failures', async () => {
  await app.close();
  app = buildApp({ config: { creditServiceUrl: creditUrl, creditApiToken: 'wrong' } });
  await createCustomer();
  const res = await app.inject({ method: 'GET', url: '/customers/1/credit' });
  expect(res.statusCode).toBe(502);
});
