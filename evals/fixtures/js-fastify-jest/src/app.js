'use strict';

const Fastify = require('fastify');
const { openDatabase } = require('./db');
const { createCreditClient } = require('./credit');
const customerRoutes = require('./routes/customers');

function buildApp({ config = {}, logger = false } = {}) {
  const app = Fastify({ logger });
  const db = openDatabase(config.databaseFile);
  const credit = createCreditClient({
    baseUrl: config.creditServiceUrl || process.env.CREDIT_SERVICE_URL || 'http://localhost:7070',
    apiToken: config.creditApiToken || process.env.CREDIT_API_TOKEN || '',
  });

  app.decorate('db', db);
  app.decorate('credit', credit);
  app.addHook('onClose', async () => db.close());

  app.get('/healthz', async () => ({ status: 'ok' }));
  app.register(customerRoutes, { prefix: '/customers' });

  return app;
}

module.exports = { buildApp };
