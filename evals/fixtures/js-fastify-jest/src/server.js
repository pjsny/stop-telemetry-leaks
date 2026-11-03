'use strict';

const { buildApp } = require('./app');

const app = buildApp({
  logger: true,
  config: { databaseFile: process.env.DATABASE_FILE || 'accounts.db' },
});

app.listen({ host: '0.0.0.0', port: Number(process.env.PORT || 8080) }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
