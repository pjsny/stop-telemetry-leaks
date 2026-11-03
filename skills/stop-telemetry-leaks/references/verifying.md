# Verifying leaks and fixes (optional)

Only run this when the user asked for verification in preflight. It adds a lot of time, so the default is static only.

Both options send fake secrets through the app, capture the telemetry it would export, and search it for those values, before and after the fixes. The skill ships no tooling: you write everything in the target repo and delete it afterwards. Static-only surfaces (baggage, metrics, committed exporter config, session replay) can't be verified this way; report them from the code.

| Option | How | Good for | Misses |
|---|---|---|---|
| Mock exporter (section 2) | A temporary test swaps the innermost exporter for an in-memory one | Repos with a test runner; no Docker | Instrumentation that only loads in the real start command (jest, vitest module runners) |
| Mock collector (section 3) | Run the real start command with OTLP pointed at a local Collector, send HTTP | Anything that starts locally; closest to production | Exporters with a hardcoded vendor URL in code |

## 1. Fake values

Generate a seed once (`python3 -c "import secrets; print(secrets.token_hex(4))"`) and reuse it for the before and after runs. Send these values, never real ones:

| Kind | Value | Where to send it |
|---|---|---|
| Token | `otelcanary_<seed>` | `Authorization: Bearer otelcanary_<seed>`, `Cookie: session=otelcanary_<seed>`, `X-Api-Key: otelcanary_<seed>`, `?api_key=otelcanary_<seed>` / `?token=...`, password and token fields in bodies |
| Email | `canary+<seed>@example.invalid` | Email fields, lookups, path segments that take an email |
| Card | `4111111111111111` | Card fields. Also send a variant that fails validation (`4111111111111112`) to reach the error path |
| Name | `Canary Person <seed>` | Name fields |

When validation needs other fields (phone, SSN), use obviously fake values in the format the schema accepts. Search for each fake value as a plain substring: `otelcanary_<seed>` finds every token wherever it was sent.

## 2. Option: mock exporter

Name every file `*otel_pii_canary*` so cleanup is one glob. The test:

1. Unsets every `OTEL_EXPORTER_OTLP_*` variable for the run. Never point the run at a real exporter endpoint or vendor.
2. Builds the app's telemetry **the way production does** (the same bootstrap module, processors and wrappers), replacing only the innermost exporter with an in-memory one. Replace the exporter class where the bootstrap imports it, so a redacting wrapper around it stays in the path. Don't build a fresh `TracerProvider` in the test: that skips the code you're checking.
3. Sends the fake values through every route: headers, query strings, bodies, and at least one error path.
4. Force-flushes the tracer and logger providers (batch processors hold records until then).
5. Serializes every finished span and log record: span name, attributes, event names and attributes, status description, log body, log attributes, resource attributes.
6. Prints each fake value it finds, with the surface and span name, and fails if it found any.

Run it on its own (it sets global providers), before any fix and again after, with the same seed. The work is done when the after run reports no fake value. A value that survives the redactor (for example a token inside an exception message) needs a source fix.

### Python (pytest)

Verified on a copy of a FastAPI app whose `app/telemetry.py` builds `TracerProvider`/`LoggerProvider` with `BatchSpanProcessor(OTLPSpanExporter())`. Adapt the module path, exporter class names and requests:

```python
# Temporary leak check. Delete after use.
import json
import os
import secrets

from fastapi.testclient import TestClient
from opentelemetry import _logs, trace
from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

SEED = os.environ.get("OTEL_CANARY_SEED") or secrets.token_hex(4)
TOKEN = f"otelcanary_{SEED}"
FAKES = {
    "bearer": TOKEN,
    "email": f"canary+{SEED}@example.invalid",
    "card": "4111111111111111",
    "bad_card": "4111111111111112",  # fails validation: reaches the error path
    "name": f"Canary Person {SEED}",
}
SPANS, LOGS = InMemorySpanExporter(), InMemoryLogRecordExporter()


def _records():
    for s in SPANS.get_finished_spans():
        yield "span.name", s.name, s.name
        yield "span.status", s.name, s.status.description or ""
        yield "span.attribute", s.name, dict(s.attributes or {})
        for e in s.events:
            yield f"span.event:{e.name}", s.name, dict(e.attributes or {})
        yield "resource", s.name, dict(s.resource.attributes)
    for r in LOGS.get_finished_logs():
        yield "log.body", "log", r.log_record.body
        yield "log.attribute", "log", dict(r.log_record.attributes or {})
        yield "resource", "log", dict(r.resource.attributes)


def test_otel_pii_canary(monkeypatch, tmp_path):
    for key in list(os.environ):
        if key.startswith("OTEL_EXPORTER_OTLP_"):
            monkeypatch.delenv(key)  # never reach a real backend
    # Swap only the innermost exporter; any redacting wrapper stays in the path.
    import app.telemetry as telemetry

    monkeypatch.setattr(telemetry, "OTLPSpanExporter", lambda *a, **k: SPANS)
    monkeypatch.setattr(telemetry, "OTLPLogExporter", lambda *a, **k: LOGS)

    from app.main import add_user, create_app

    app = create_app(str(tmp_path / "canary.db"))
    telemetry.setup_telemetry(app)
    add_user(app.state.db, "canary", TOKEN)
    headers = {"Authorization": f"Bearer {TOKEN}", "Cookie": f"session={TOKEN}", "X-Api-Key": TOKEN}
    with TestClient(app, raise_server_exceptions=False) as c:
        c.post(f"/auth/login?api_key={TOKEN}", json={"username": "canary", "password": TOKEN}, headers=headers)
        r = c.post("/customers", json={"name": FAKES["name"], "email": FAKES["email"]}, headers=headers)
        c.post("/customers/lookup", json={"email": FAKES["email"]}, headers=headers)
        c.get(f"/customers/{r.json().get('id', 1)}?token={TOKEN}", headers=headers)
        c.post("/payments", json={"customer_id": 1, "amount_cents": 100, "card": FAKES["card"]}, headers=headers)
        c.post("/payments", json={"customer_id": 1, "amount_cents": 100, "card": FAKES["bad_card"]}, headers=headers)
    trace.get_tracer_provider().force_flush()
    _logs.get_logger_provider().force_flush()

    hits = []
    for surface, where, payload in _records():
        text = json.dumps(payload, default=str)
        for kind, value in FAKES.items():
            if value in text:
                hits.append(f"{kind:8} {surface:22} {where}: {text[:160]}")
    print(f"\nseed={SEED} spans={len(SPANS.get_finished_spans())} logs={len(LOGS.get_finished_logs())}")
    print("\n".join(sorted(set(hits))) or "no fake values found")
    assert not hits, f"{len(set(hits))} leaks"
```

```sh
OTEL_CANARY_SEED=<seed> python -m pytest -s -p no:cacheprovider tests/test_otel_pii_canary.py
```

On the unfixed app this reported the token in `http.request.header.authorization`/`cookie` on every server span, in the log body (`login canary password=otelcanary_...`), the email in a span name and in `db.statement`, and the invalid card in the `exception` event. With the redactor from [fix-python.md](fix-python.md) wrapped around the OTLP exporter, the same seed reported nothing.

For the zero-code route (`opentelemetry-instrument`), keep `OTEL_TRACES_EXPORTER=none` / `OTEL_LOGS_EXPORTER=none` as production does and patch the exporter classes inside the module that attaches the redacting exporters (see [fix-python.md](fix-python.md#zero-code-bootstrap-opentelemetry-instrument)).

### Node (vitest)

Verified on a copy of an ESM Express app whose `instrumentation.mjs` starts `NodeSDK` with `OTLPTraceExporter` and a `BatchLogRecordProcessor({ exporter: new OTLPLogExporter() })`. `vi.mock` swaps the exporter packages; the test then imports the real bootstrap before the app:

```js
// Temporary leak check. Delete after use.
import { randomBytes } from 'node:crypto';
import { afterAll, expect, it, vi } from 'vitest';

const { spans, logs } = await vi.hoisted(async () => {
  const { InMemorySpanExporter } = await import('@opentelemetry/sdk-trace');
  const { InMemoryLogRecordExporter } = await import('@opentelemetry/sdk-logs');
  for (const k of Object.keys(process.env)) if (k.startsWith('OTEL_EXPORTER_OTLP_')) delete process.env[k];
  return { spans: new InMemorySpanExporter(), logs: new InMemoryLogRecordExporter() };
});
// Swap only the innermost exporter; any redacting wrapper in instrumentation.mjs stays in the path.
vi.mock('@opentelemetry/exporter-trace-otlp-http', () => ({ OTLPTraceExporter: function () { return spans; } }));
vi.mock('@opentelemetry/exporter-logs-otlp-http', () => ({ OTLPLogExporter: function () { return logs; } }));

const SEED = process.env.OTEL_CANARY_SEED ?? randomBytes(4).toString('hex');
const TOKEN = `otelcanary_${SEED}`;
const FAKES = {
  bearer: TOKEN,
  email: `canary+${SEED}@example.invalid`,
  card: '4111111111111111',
  name: `Canary Person ${SEED}`,
};

it('otel pii canary', async () => {
  await import('../instrumentation.mjs'); // production bootstrap, loaded before the app
  const { trace, logs: logsApi } = await import('@opentelemetry/api');
  const { default: request } = await import('supertest');
  const { createApp } = await import('../src/app.js');
  const { createStore } = await import('../src/store.js');
  const app = createApp({ store: createStore() });
  const h = { Authorization: `Bearer ${TOKEN}`, Cookie: `session=${TOKEN}`, 'X-Api-Key': TOKEN };

  await request(app).post('/api/accounts').set(h).send({ name: FAKES.name, email: FAKES.email, password: TOKEN });
  await request(app).post('/api/session').set(h).send({ email: FAKES.email, password: TOKEN });
  await request(app).post('/api/orders').set(h).send({ email: FAKES.email, card: FAKES.card, items: [{ sku: 'A', quantity: 1, priceCents: 1 }] });
  await request(app).post('/api/orders/search').set(h).send({ email: FAKES.email });
  await request(app).post(`/api/coupons/redeem?token=${TOKEN}`).set(h).send({ code: TOKEN, email: FAKES.email }); // error path
  await request(app).get(`/api/partner/orders?api_key=${TOKEN}`).set(h);

  const tp = trace.getTracerProvider();
  await (tp.getDelegate?.() ?? tp).forceFlush();
  await logsApi.getLoggerProvider().forceFlush?.();

  const records = [
    ...spans.getFinishedSpans().flatMap((s) => [
      ['span.name', s.name, s.name],
      ['span.status', s.name, s.status.message ?? ''],
      ['span.attribute', s.name, s.attributes],
      ...s.events.map((e) => [`span.event:${e.name}`, s.name, e.attributes ?? {}]),
      ['resource', s.name, s.resource.attributes],
    ]),
    ...logs.getFinishedLogRecords().flatMap((r) => [
      ['log.body', 'log', r.body],
      ['log.attribute', 'log', r.attributes],
      ['resource', 'log', r.resource.attributes],
    ]),
  ];
  const hits = new Set();
  for (const [surface, where, payload] of records) {
    const text = JSON.stringify(payload) ?? '';
    for (const [kind, value] of Object.entries(FAKES)) {
      if (text.includes(value)) hits.add(`${kind.padEnd(7)} ${surface.padEnd(22)} ${where}: ${text.slice(0, 160)}`);
    }
  }
  console.log(`seed=${SEED} spans=${spans.getFinishedSpans().length} logs=${logs.getFinishedLogRecords().length}`);
  console.log([...hits].sort().join('\n') || 'no fake values found');
  expect([...hits]).toEqual([]);
});

afterAll(() => vi.restoreAllMocks());
```

```sh
OTEL_CANARY_SEED=<seed> npx vitest run test/otel_pii_canary.test.js --silent=false
```

On the unfixed app this reported the token in captured headers and `url.full`, the log body, an email span name, and the request body inside an exception message. After wrapping both exporters with the redactor from [fix-js.md](fix-js.md), only the exception message still held the token (free text the value rules can't recognise). After the source fix (`new Error('coupon rejected')`) it reported nothing, and the app's own tests still passed.

Vitest loads app code through its own module runner, so `@opentelemetry/instrumentation-express` spans may be missing: expect HTTP server spans named `POST`/`GET` without the route. The leaks above still show up on the HTTP spans. Routes that only appear on Express spans need the driver below.

### Node (jest, node:test, or anything else): a driver script

Jest runs app code in its own global and module registry, so the bootstrap's instrumentation doesn't see the app's modules. Don't fight it: write a plain Node driver that loads the bootstrap the way `node --require ./instrumentation.js` does, starts the app on `127.0.0.1:0`, and sends real HTTP. This works for any runner, including `node:test`. CommonJS example, verified on a copy of a Fastify app whose `instrumentation.js` starts `NodeSDK` with `OTLPTraceExporter`:

```js
// Temporary leak check. Delete after use. Run: node otel_pii_canary_driver.cjs
'use strict';
const crypto = require('node:crypto');
const Module = require('node:module');
const { InMemorySpanExporter } = require('@opentelemetry/sdk-trace');

for (const k of Object.keys(process.env)) if (k.startsWith('OTEL_EXPORTER_OTLP_')) delete process.env[k];
const spans = new InMemorySpanExporter();
// Replace the OTLP exporter module before the bootstrap requires it; wrappers stay in the path.
const stub = (name, exports) => {
  const file = require.resolve(name);
  const m = new Module(file);
  m.filename = file; m.loaded = true; m.exports = exports;
  require.cache[file] = m;
};
stub('@opentelemetry/exporter-trace-otlp-http', { OTLPTraceExporter: function () { return spans; } });

require('./instrumentation.js'); // production bootstrap, same as `node --require ./instrumentation.js`
const { trace } = require('@opentelemetry/api');
const { buildApp } = require('./src/app.js');

const SEED = process.env.OTEL_CANARY_SEED || crypto.randomBytes(4).toString('hex');
const TOKEN = `otelcanary_${SEED}`;
const FAKES = { bearer: TOKEN, email: `canary+${SEED}@example.invalid`, card: '4111111111111111', name: `Canary Person ${SEED}` };

(async () => {
  const app = buildApp({ config: { databaseFile: ':memory:' } });
  const base = await app.listen({ host: '127.0.0.1', port: 0 });
  const headers = { authorization: `Bearer ${TOKEN}`, cookie: `session=${TOKEN}`, 'x-api-key': TOKEN, 'content-type': 'application/json' };
  const send = (method, path, body) => fetch(base + path, { method, headers, body: body && JSON.stringify(body) }).catch(() => {});
  await send('POST', `/customers?api_key=${TOKEN}`, { name: FAKES.name, phone: '+15550100123', ssn: '123-45-6789', email: FAKES.email });
  await send('GET', `/customers/1?token=${TOKEN}`);
  await send('POST', '/customers/verify', { ssn: 'not-an-ssn', card: FAKES.card }); // error path
  await app.close();
  const tp = trace.getTracerProvider();
  await (tp.getDelegate?.() ?? tp).forceFlush();

  const hits = new Set();
  for (const s of spans.getFinishedSpans()) {
    const parts = [['span.name', s.name], ['span.status', s.status.message ?? ''], ['span.attribute', s.attributes],
      ...s.events.map((e) => [`span.event:${e.name}`, e.attributes ?? {}]), ['resource', s.resource.attributes]];
    for (const [surface, payload] of parts) {
      const text = JSON.stringify(payload) ?? '';
      for (const [kind, value] of Object.entries(FAKES)) if (text.includes(value)) hits.add(`${kind.padEnd(7)} ${surface.padEnd(22)} ${s.name}: ${text.slice(0, 160)}`);
    }
  }
  console.log(`seed=${SEED} spans=${spans.getFinishedSpans().length}`);
  console.log([...hits].sort().join('\n') || 'no fake values found');
  process.exit(hits.size ? 1 : 0);
})();
```

```sh
OTEL_CANARY_SEED=<seed> node otel_pii_canary_driver.cjs
```

It stubs the exporter module in `require.cache` before requiring the bootstrap, which is the same as `node --require ./instrumentation.js`. On the unfixed app it reported the token in captured `cookie` headers on the server spans. For an ESM app with `node:test`, replace the exporter packages with `mock.module()` and run `node --experimental-test-module-mocks --test otel_pii_canary.test.mjs` (Node 24). Call `mock.module('@opentelemetry/exporter-trace-otlp-http', { exports: { OTLPTraceExporter: function () { return spans; } } })` at the top of the test file, then `await import('./instrumentation.mjs')` and the app inside the test, listen on `127.0.0.1:0` and send requests with `fetch`. On the Express app above this captured the HTTP and Express spans (`POST /api/orders/search`, `request handler - /api/orders/search`). If the app also exports logs, stub the log exporter package the same way and serialize `getFinishedLogRecords()`.

## 3. Option: mock collector

Run the app with its production start command and point OTLP at a throwaway Collector on localhost that writes everything to a file. Verified on the Express fixture (`node --import ./instrumentation.mjs server.js`, OTLP/HTTP) and the FastAPI fixture (`uvicorn app.asgi:app`, OTLP/gRPC) with `otel/opentelemetry-collector-contrib` 0.164.0.

1. Write `otel_pii_canary_collector.yaml` in a temp directory:

   ```yaml
   receivers:
     otlp:
       protocols:
         grpc: { endpoint: 0.0.0.0:4317 }
         http: { endpoint: 0.0.0.0:4318 }
   exporters:
     file:
       path: /out/telemetry.jsonl
   service:
     pipelines:
       traces: { receivers: [otlp], exporters: [file] }
       logs: { receivers: [otlp], exporters: [file] }
       metrics: { receivers: [otlp], exporters: [file] }
   ```

2. Start it, bound to localhost only (the `out` directory must be writable by the container user):

   ```sh
   docker run -d --rm --name otel-pii-canary-collector \
     -p 127.0.0.1:4317:4317 -p 127.0.0.1:4318:4318 \
     -v "$TMP/otel_pii_canary_collector.yaml:/etc/otelcol-contrib/config.yaml:ro" \
     -v "$TMP/out:/out" otel/opentelemetry-collector-contrib:latest
   ```

   Without Docker, `otelcol-contrib --config otel_pii_canary_collector.yaml` works the same (change `/out/` to a local path).

3. Start the app with its production command and this environment:
   - unset `OTEL_EXPORTER_OTLP_HEADERS` and every signal-specific `OTEL_EXPORTER_OTLP_{TRACES,LOGS,METRICS}_{ENDPOINT,HEADERS}` (they win over the generic endpoint);
   - `OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318` for `http/protobuf` exporters, `http://127.0.0.1:4317` for gRPC;
   - `OTEL_BSP_SCHEDULE_DELAY=500` and `OTEL_BLRP_SCHEDULE_DELAY=500`, so batches export while the app runs. Python apps without a shutdown hook drop the last batch when killed;
   - a temporary database path and a free port.

   Before starting, check the bootstrap for an exporter `url`/`endpoint` passed in code and for a `.env` loader that overrides the environment. Either one can send the run to the real vendor. If you can't redirect it, don't run it: mark the runtime surfaces `unverified`.
4. Send the fake values through every route with `curl` or `fetch`, including at least one error path.
5. Wait a second, stop the app with SIGTERM (Node SDKs flush on shutdown), then search the output: `grep -c -F 'otelcanary_<seed>' out/telemetry.jsonl`, once per fake value. Each line is one OTLP JSON export request. To name the surface, walk `resourceSpans[].scopeSpans[].spans[]` (`name`, `attributes[]`, `events[].attributes[]`) and `resourceLogs[].scopeLogs[].logRecords[].body`.
6. Empty the output file, apply the fixes, restart the app, and repeat with the same seed.

On the unfixed Express fixture this found the token in `http.request.header.authorization`, `cookie`, `x-api-key`, `url.query`, the log body and the exception event, and the email in `user.email`. On the FastAPI fixture it also found `db.statement`, `http.url`, and the email in a span name (`lookup canary+…`).

## 4. Clean up

Delete every temporary file when you're done (`git status --porcelain` lists them; they all match `*otel_pii_canary*`), any `.db` or output files the run created, and stop the Collector (`docker stop otel-pii-canary-collector`). Don't commit them. Report the option used, the seed, the before and after hit lists, and the commands you ran.
