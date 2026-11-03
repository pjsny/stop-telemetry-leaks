'use strict';

const { DatabaseSync } = require('node:sqlite');
const { trace, SpanKind, SpanStatusCode } = require('@opentelemetry/api');

const tracer = trace.getTracer('accounts-service.db');

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    ssn TEXT NOT NULL UNIQUE,
    tier TEXT NOT NULL DEFAULT 'standard'
  );
`;

function openDatabase(filename = ':memory:') {
  const db = new DatabaseSync(filename);
  db.exec(SCHEMA);

  function run(operation, sql, params, fn) {
    return tracer.startActiveSpan(`${operation} customers`, { kind: SpanKind.CLIENT }, (span) => {
      span.setAttribute('db.system.name', 'sqlite');
      span.setAttribute('db.operation.name', operation);
      span.setAttribute('db.query.text', sql);
      try {
        return fn(db.prepare(sql), params);
      } catch (err) {
        span.recordException(err);
        span.setStatus({ code: SpanStatusCode.ERROR });
        throw err;
      } finally {
        span.end();
      }
    });
  }

  return {
    all: (sql, params = []) => run('SELECT', sql, params, (stmt, p) => stmt.all(...p)),
    get: (sql, params = []) => run('SELECT', sql, params, (stmt, p) => stmt.get(...p)),
    insert: (sql, params = []) => run('INSERT', sql, params, (stmt, p) => stmt.run(...p)),
    close: () => db.close(),
  };
}

module.exports = { openDatabase };
