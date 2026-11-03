// Canary requests through every route of the storefront API (copied in by evals/score.py).
import { describe, it } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { createStore } from '../src/store.js';

const SEED = process.env.OTEL_PII_CANARY_SEED;
const TOKEN = `otelcanary_${SEED}`;
const EMAIL = `canary+${SEED}@example.invalid`;
const CARD = '4111111111111111';
const NAME = `Canary Person ${SEED}`;

const withCanaryHeaders = (req) =>
  req.set('authorization', `Bearer ${TOKEN}`).set('cookie', `session=${TOKEN}`).set('x-api-key', TOKEN);

describe('otel pii canary', () => {
  it('sends canary values through every route', async () => {
    const store = createStore();
    store.addPartner('Canary Partner', TOKEN);
    const app = createApp({ store });
    const q = `?api_key=${TOKEN}`;

    await withCanaryHeaders(request(app).get(`/healthz${q}`));
    await withCanaryHeaders(request(app).post(`/api/accounts${q}`)).send({ name: NAME, email: EMAIL, password: TOKEN });
    await withCanaryHeaders(request(app).post(`/api/session${q}`)).send({ email: EMAIL, password: TOKEN });
    await withCanaryHeaders(request(app).post(`/api/orders${q}`)).send({
      email: EMAIL,
      card: CARD,
      items: [{ sku: 'MUG-01', quantity: 1, priceCents: 1200 }],
    });
    await withCanaryHeaders(request(app).post(`/api/orders/search${q}`)).send({ email: EMAIL });
    // Unknown coupon: drives the exception path with canary input in the request body.
    await withCanaryHeaders(request(app).post(`/api/coupons/redeem${q}`)).send({ code: TOKEN, email: EMAIL, card: CARD });
    await withCanaryHeaders(request(app).get(`/api/partner/orders${q}&limit=5`));
  });
});
