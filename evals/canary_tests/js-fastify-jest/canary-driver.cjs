'use strict';

// Fallback driver (copied in by evals/score.py): jest runs app code in its own vm global, so the
// app's @opentelemetry/api cannot see the preloaded SDK. This script loads the app in the real Node
// global, serves it on 127.0.0.1, and sends the canary requests over node:http.
// Run: canary_run.py --lang node --bootstrap ./instrumentation.js -- node canary-driver.cjs

const http = require('node:http');
const { buildApp } = require('./src/app');

const SEED = process.env.OTEL_PII_CANARY_SEED;
const TOKEN = `otelcanary_${SEED}`;
const EMAIL = `canary+${SEED}@example.invalid`;
const NAME = `Canary Person ${SEED}`;
// The routes validate E.164 phones and NNN-NN-NNNN SSNs, so these cannot carry the canary token.
const PHONE = '+15555550100';
const SSN = '219-09-9999';
const HEADERS = { authorization: `Bearer ${TOKEN}`, cookie: `session=${TOKEN}`, 'x-api-key': TOKEN };

function send(base, method, path, body) {
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

async function main() {
  if (!SEED) throw new Error('OTEL_PII_CANARY_SEED is not set');
  const creditServer = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ score: 700 }));
  });
  await new Promise((resolve) => creditServer.listen(0, '127.0.0.1', resolve));
  const app = buildApp({
    config: { creditServiceUrl: `http://127.0.0.1:${creditServer.address().port}`, creditApiToken: TOKEN },
  });
  await app.listen({ port: 0, host: '127.0.0.1' });
  const base = `http://127.0.0.1:${app.server.address().port}`;
  const q = `?api_key=${TOKEN}`;
  try {
    await send(base, 'GET', `/healthz${q}`);
    await send(base, 'POST', `/customers${q}`, { name: NAME, phone: PHONE, ssn: SSN, email: EMAIL });
    await send(base, 'GET', `/customers/1${q}`);
    await send(base, 'POST', `/customers/verify${q}`, { ssn: SSN });
    await send(base, 'GET', `/customers/1/credit${q}`);
    // Invalid input: drives the validation error path with canary values.
    await send(base, 'POST', `/customers${q}`, { name: NAME, phone: TOKEN, ssn: EMAIL });
  } finally {
    await app.close();
    await new Promise((resolve) => creditServer.close(resolve));
  }
}

// No process.exit(): the event loop drains, so the flush preload runs on beforeExit.
main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
