'use strict';

// Canary requests through every route of the accounts service (copied in by evals/score.py).
// Requests go over a real socket (app.listen) as well as app.inject: inject bypasses http.Server,
// so the http instrumentation creates no server span (and captures no headers) for it.

const http = require('node:http');
const { buildApp } = require('../src/app');

const SEED = process.env.OTEL_PII_CANARY_SEED;
const TOKEN = `otelcanary_${SEED}`;
const EMAIL = `canary+${SEED}@example.invalid`;
const NAME = `Canary Person ${SEED}`;
// The routes validate E.164 phones and NNN-NN-NNNN SSNs, so these cannot carry the canary token.
const PHONE = '+15555550100';
const SSN = '219-09-9999';
const HEADERS = { authorization: `Bearer ${TOKEN}`, cookie: `session=${TOKEN}`, 'x-api-key': TOKEN };

let creditServer;
let app;
let base;

beforeAll(async () => {
  creditServer = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ score: 700 }));
  });
  await new Promise((resolve) => creditServer.listen(0, '127.0.0.1', resolve));
  app = buildApp({
    config: { creditServiceUrl: `http://127.0.0.1:${creditServer.address().port}`, creditApiToken: TOKEN },
  });
  await app.listen({ port: 0, host: '127.0.0.1' });
  base = `http://127.0.0.1:${app.server.address().port}`;
});

afterAll(async () => {
  await app.close();
  await new Promise((resolve) => creditServer.close(resolve));
});

function send(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = http.request(`${base}${path}`, {
      method,
      headers: { ...HEADERS, ...(payload ? { 'content-type': 'application/json' } : {}) },
    }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

test('otel pii canary requests', async () => {
  const q = `?api_key=${TOKEN}`;
  const customer = { name: NAME, phone: PHONE, ssn: SSN, email: EMAIL };
  await send('GET', `/healthz${q}`);
  await send('POST', `/customers${q}`, customer);
  await send('GET', `/customers/1${q}`);
  await send('POST', `/customers/verify${q}`, { ssn: SSN });
  await send('GET', `/customers/1/credit${q}`);
  // Invalid input: drives the validation error path with canary values.
  await send('POST', `/customers${q}`, { name: NAME, phone: TOKEN, ssn: EMAIL });

  await app.inject({ method: 'POST', url: `/customers${q}`, headers: HEADERS, payload: { ...customer, ssn: '219-09-9998' } });
  await app.inject({ method: 'POST', url: `/customers/verify${q}`, headers: HEADERS, payload: { ssn: SSN } });
  await app.inject({ method: 'GET', url: `/customers/1/credit${q}`, headers: HEADERS });
});
