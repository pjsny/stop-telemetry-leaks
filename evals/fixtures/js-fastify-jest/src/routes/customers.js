'use strict';

const { trace } = require('@opentelemetry/api');

const PHONE = /^\+[1-9]\d{7,14}$/;
const SSN = /^\d{3}-\d{2}-\d{4}$/;

const customerBody = {
  type: 'object',
  required: ['name', 'phone', 'ssn'],
  properties: {
    name: { type: 'string', minLength: 1 },
    phone: { type: 'string', pattern: PHONE.source },
    ssn: { type: 'string', pattern: SSN.source },
  },
};

const verifyBody = {
  type: 'object',
  required: ['ssn'],
  properties: { ssn: { type: 'string', pattern: SSN.source } },
};

function publicCustomer(row) {
  return { id: row.id, name: row.name, phone: row.phone, tier: row.tier };
}

async function customerRoutes(app) {
  app.post('/', { schema: { body: customerBody } }, async (request, reply) => {
    const { name, phone, ssn } = request.body;
    trace.getActiveSpan()?.setAttribute('customer.phone', phone);
    const existing = app.db.get('SELECT id FROM customers WHERE ssn = ?', [ssn]);
    if (existing) {
      return reply.code(409).send({ error: 'customer already exists' });
    }
    const result = app.db.insert('INSERT INTO customers (name, phone, ssn) VALUES (?, ?, ?)', [
      name,
      phone,
      ssn,
    ]);
    const row = app.db.get('SELECT * FROM customers WHERE id = ?', [result.lastInsertRowid]);
    return reply.code(201).send(publicCustomer(row));
  });

  app.get('/:id', async (request, reply) => {
    const row = app.db.get('SELECT * FROM customers WHERE id = ?', [Number(request.params.id)]);
    if (!row) return reply.code(404).send({ error: 'not found' });
    return publicCustomer(row);
  });

  app.post('/verify', { schema: { body: verifyBody } }, async (request, reply) => {
    const { ssn } = request.body;
    const row = app.db.get(`SELECT * FROM customers WHERE ssn = '${ssn}'`);
    if (!row) return reply.code(404).send({ verified: false });
    return { verified: true, customer: publicCustomer(row) };
  });

  app.get('/:id/credit', async (request, reply) => {
    const row = app.db.get('SELECT * FROM customers WHERE id = ?', [Number(request.params.id)]);
    if (!row) return reply.code(404).send({ error: 'not found' });
    try {
      const { score } = await app.credit.score(row.id);
      return { customerId: row.id, score, approved: score >= 640 };
    } catch (err) {
      request.log.warn({ err }, 'credit check failed');
      return reply.code(502).send({ error: 'credit service unavailable' });
    }
  });
}

module.exports = customerRoutes;
