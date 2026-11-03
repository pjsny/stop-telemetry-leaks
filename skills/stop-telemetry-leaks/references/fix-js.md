# Fixing JavaScript / TypeScript telemetry

Checked against `@opentelemetry/sdk-node` and `instrumentation-http` 0.300.0 and `sdk-trace`/`sdk-logs`/`sdk-metrics` 3.0.0, on Node 24.15. The redactor below was run with Node 24 type stripping against `sdk-trace` 3 and `sdk-logs` 3 (`InMemorySpanExporter` / `InMemoryLogRecordExporter` as the inner exporter), and its output was serialized with `@opentelemetry/otlp-transformer`.

## 1. Add a redacting exporter wrapper

Write this file into the app's source tree (`redactor.ts` for an ESM package, `redactor.mts` for CommonJS) and adapt it. It imports only `node:crypto` and needs no SDK imports: its structural types match `ReadableSpan`/`SpanExporter`/`LogRecordExporter` in SDK 2.x (`sdk-trace-base`) and 3.x (`sdk-trace`). It uses only erasable TS syntax (no parameter properties, enums or namespaces), so Node can strip the types. It copies each span and log record into a plain object with redacted attributes, event attributes, span name, status message and log body. A record it can't copy is dropped, never exported raw.

```ts
// Redacting exporter wrappers. Imports only node:crypto; types are structural.
import { createHmac } from 'node:crypto';

type Attrs = Record<string, unknown>;
type Callback = (result: { code: number; error?: Error }) => void;
// Fields the wrapper reads or rewrites; the rest pass through untouched (`unknown`).
interface SpanLike {
  name: string; attributes: Attrs; events: { name: string; attributes?: Attrs }[];
  status: { code: number; message?: string }; spanContext(): unknown; [field: string]: unknown;
}
interface LogLike { body?: unknown; attributes: Attrs; [field: string]: unknown }
interface Exporter<T> { export(items: T[], cb: Callback): void; shutdown(): Promise<void>; forceFlush?(): Promise<void> }

const MASK = '[REDACTED]';
// Keys whose whole value is masked. Extend from the patterns table in surfaces.md.
const CREDENTIAL_KEY = /(?:^|[._-])(?:proxy-authorization|authorization|set-cookie|cookie|x-api-key|api[_-]?key|access_token|refresh_token|client_secret|token|secret|passw(?:or)?d|session[_-]?(?:id|token))(?:$|[._-])/i;
// [regex (must be global), action] applied to the matching part of every string value.
const VALUE_RULES: [RegExp, 'mask' | 'hmac'][] = [
  [/\b[Bb]earer[ \t]+[A-Za-z0-9._~+/-]{8,}=*/g, 'mask'],
  [/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, 'mask'],
  [/(?:^|[?&;])(?:api_key|apikey|token|access_token|password|secret)=[^&#\s]+/gi, 'mask'],
  [/(?:\b|_)(?:password|passwd|secret|token|pwd|pw)["']?[ \t]*[=:][ \t]*["']?[^\s"'&,;]{4,}/gi, 'mask'],
  [/\b(?:\d[ -]?){12,18}\d\b/g, 'mask'], // add a Luhn check to cut false positives
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, 'hmac'],
];

export function piiHmac(value: string): string {
  const key = process.env.OTEL_PII_HMAC_KEY;
  if (!key) return MASK; // fail closed
  return 'hmac:' + createHmac('sha256', key).update(value, 'utf8').digest('hex').slice(0, 16);
}

export function redactText(text: string): string {
  for (const [re, action] of VALUE_RULES) text = text.replace(re, (m) => (action === 'hmac' ? piiHmac(m) : MASK));
  return text;
}

function redactValue(value: unknown): unknown {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (value && typeof value === 'object' && !ArrayBuffer.isView(value)) return redactAttributes(value as Attrs);
  return value;
}

function redactAttributes(attrs: Attrs | undefined): Attrs {
  const out: Attrs = {};
  for (const [k, v] of Object.entries(attrs ?? {})) out[k] = CREDENTIAL_KEY.test(k) ? MASK : redactValue(v);
  return out;
}

// Copy every ReadableSpan field by name: SDK spans expose several of them as getters,
// which `{ ...span }` would skip.
function redactSpan(s: SpanLike): SpanLike {
  return {
    name: redactText(s.name), kind: s.kind, spanContext: () => s.spanContext(), parentSpanContext: s.parentSpanContext,
    startTime: s.startTime, endTime: s.endTime, duration: s.duration, ended: s.ended,
    status: s.status.message === undefined ? s.status : { ...s.status, message: redactText(s.status.message) },
    attributes: redactAttributes(s.attributes), links: s.links,
    events: s.events.map((e) => ({ ...e, name: redactText(e.name), attributes: redactAttributes(e.attributes) })),
    resource: s.resource, instrumentationScope: s.instrumentationScope, droppedAttributesCount: s.droppedAttributesCount,
    droppedEventsCount: s.droppedEventsCount, droppedLinksCount: s.droppedLinksCount,
  };
}

function redactLog(r: LogLike): LogLike {
  return {
    hrTime: r.hrTime, hrTimeObserved: r.hrTimeObserved, spanContext: r.spanContext, severityText: r.severityText,
    severityNumber: r.severityNumber, body: redactValue(r.body), eventName: r.eventName, resource: r.resource,
    instrumentationScope: r.instrumentationScope, attributes: redactAttributes(r.attributes),
    droppedAttributesCount: r.droppedAttributesCount,
  };
}

class Redacting<T> implements Exporter<T> {
  readonly inner: Exporter<T>;
  readonly redact: (item: T) => T;
  constructor(inner: Exporter<T>, redact: (item: T) => T) { this.inner = inner; this.redact = redact; }
  export(items: T[], cb: Callback): void {
    const out: T[] = [];
    for (const item of items) {
      try { out.push(this.redact(item)); } catch { /* fail closed: drop a record we can't redact */ }
    }
    this.inner.export(out, cb);
  }
  shutdown(): Promise<void> { return this.inner.shutdown(); }
  forceFlush(): Promise<void> { return this.inner.forceFlush?.() ?? Promise.resolve(); }
}

export class RedactingSpanExporter extends Redacting<SpanLike> {
  constructor(inner: Exporter<SpanLike>) { super(inner, redactSpan); }
}
export class RedactingLogRecordExporter extends Redacting<LogLike> {
  constructor(inner: Exporter<LogLike>) { super(inner, redactLog); }
}
```

Adapt it:

- The rule list is a starting set. Add rows from the value patterns table in [surfaces.md](surfaces.md#secret-and-pii-value-patterns) that match what the repo leaks. Every value regex needs the `g` flag, or `replace` stops at the first match. Add a Luhn check for card numbers where false positives matter.
- Add app-specific keys to `CREDENTIAL_KEY`.
- The span copy keeps `spanContext` as a function (`spanContext: () => span.spanContext()`); exporters call it for trace and span IDs.
- The resource is passed through unchanged. Fix resource leaks at the source.
- If the user asked for verification, check it with [verifying.md](verifying.md).

For plain JavaScript, delete the type annotations and the `interface`/`type` lines.

### Loading the `.ts` file

| Project | How | Verified |
|---|---|---|
| ESM (`"type": "module"`), Node ≥22.18 / ≥23.6 | `import { … } from './redactor.ts'` | Node 24.15 |
| CommonJS (no `"type"` or `"type": "commonjs"`), Node ≥22.18 | Name the file `redactor.mts`; `require('./redactor.mts')` (require of ESM) | Node 24.15, `"type": "commonjs"` package |
| CommonJS, `redactor.ts` | `"type": "commonjs"`: fails (`SyntaxError`, ESM syntax in a CJS `.ts`). No `"type"`: loads after a "Reparsing as ES module" warning. Don't rely on it | Node 24.15 |
| Node 22.6–22.17 | Add `--experimental-strip-types` (type stripping is on by default from 22.18 / 23.6, [Node TS docs](https://nodejs.org/api/typescript.html)); `require(esm)` needs ≥22.12 | not run |
| Older Node, a bundled app, or `.ts` that must ship as `.js` | Compile it with the app's build (`tsc`, `esbuild redactor.ts --format=esm\|cjs --outfile=redactor.js`) and import the output | not run |

Node won't strip types for files under `node_modules`. Keep the redactor in the app's source tree. Jest/vitest never see the bootstrap when it's loaded through `NODE_OPTIONS=--import`/`--require`, so no test transform is needed.

### NodeSDK bootstrap (ESM)

```js
// before
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';
...
  traceExporter: new OTLPTraceExporter(),
  logRecordProcessors: [new BatchLogRecordProcessor({ exporter: new OTLPLogExporter() })],
```

```js
// after
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';
import { RedactingSpanExporter, RedactingLogRecordExporter } from './redactor.ts';
...
  traceExporter: new RedactingSpanExporter(new OTLPTraceExporter()),
  logRecordProcessors: [new BatchLogRecordProcessor({ exporter: new RedactingLogRecordExporter(new OTLPLogExporter()) })],
```

`traceExporter` accepts any `SpanExporter`, and NodeSDK wraps it in a batch processor itself. If the app passes `spanProcessors: [new BatchSpanProcessor(exp)]` instead, wrap `exp` there. Wrap every exporter (console, a second vendor exporter). With `sdk-logs` 3, `BatchLogRecordProcessor` takes `{ exporter }`.

### NodeSDK bootstrap (CommonJS)

```js
const { RedactingSpanExporter } = require('./redactor.mts');
...
  traceExporter: new RedactingSpanExporter(new OTLPTraceExporter()),
```

### Zero-code (`--require @opentelemetry/auto-instrumentations-node/register`)

The register entry point builds exporters from `OTEL_*` env vars and offers no hook for wrapping them ([auto-instrumentations-node README](https://github.com/open-telemetry/opentelemetry-js-contrib/blob/main/packages/auto-instrumentations-node/README.md)). Replace it with an `instrumentation.mjs`/`.js` that runs `new NodeSDK({ traceExporter: new RedactingSpanExporter(new OTLPTraceExporter()), logRecordProcessors: [...], instrumentations: [getNodeAutoInstrumentations()] }).start()`, and change the start command to `node --import ./instrumentation.mjs app.js` (ESM) or `--require ./instrumentation.js` (CJS). ESM apps also need `register('@opentelemetry/instrumentation/hook.mjs', import.meta.url)` (see the `@opentelemetry/instrumentation` README).

### HMAC key

`OTEL_PII_HMAC_KEY` keys the `hmac` action: `hmac:` + the first 16 hex chars of HMAC-SHA256. If it's unset, `hmac` rules mask to `[REDACTED]` (fail closed). Provision it from the secret manager as a per-environment env var with at least 32 random bytes (`node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`). Never commit it or log it. Rotating it resets every hashed ID.

## 2. Critical config fixes

| Finding | Fix |
|---|---|
| `http.request.header` | Remove credential names from `headersToSpanAttributes.{client,server}.{requestHeaders,responseHeaders}`. Example: `requestHeaders: ['authorization', 'cookie', 'x-api-key', 'x-request-id']` → `requestHeaders: ['x-request-id']`. There's no sanitize option |
| Query tokens (`url`) | Write one merged list to both options (below) |
| URL userinfo | Build outbound URLs without `user:pass@`. Pass credentials in an `Authorization` header |
| Committed OTLP headers (`exporter.config`) | Replace the literal (`OTEL_EXPORTER_OTLP_HEADERS=x-api-key=…` in `.env*`, compose, k8s, Dockerfile, or `headers: {…}` passed to `OTLPTraceExporter`) with an env/secret reference. Add it to the rotation list with file and first commit SHA, and tell the user to rotate |
| `resource` | Move secrets out of argv. Set `OTEL_NODE_RESOURCE_DETECTORS=env,host,os,serviceinstance` (the default `all` includes `process`, which records `process.command_args`), or pass `resourceDetectors` without `processDetector`. Remove secrets from `OTEL_RESOURCE_ATTRIBUTES` |

### Query parameter redaction

Both lists replace the built-in one and don't fall back to each other (`instrumentation-http` 0.300.0 README). Always set both:

```js
const REDACTED_QUERY_PARAMS = [
  // built-ins: keep them, the option replaces this list
  'sig', 'Signature', 'AWSAccessKeyId', 'X-Goog-Signature',
  'X-Amz-Signature', 'X-Amz-Credential', 'X-Amz-Security-Token',
  // app params (exact, case-sensitive)
  'token', 'access_token', 'api_key',
];

new HttpInstrumentation({
  redactedQueryParams: REDACTED_QUERY_PARAMS,        // client spans (url.full)
  redactedQueryParamsServer: REDACTED_QUERY_PARAMS,  // server spans (url.query)
});
```

A bare `redactedQueryParams: ['token']` is the trap: it drops the AWS/GCS signature built-ins on client spans and does nothing on server spans. Values become `REDACTED`. Both options are marked experimental, so re-check the README for the installed version.

## 3. Source fixes (High/Medium: propose a diff)

### Stable IDs and HMAC helper

```js
import { createHmac } from 'node:crypto';

export function piiHmac(value) {
  const key = process.env.OTEL_PII_HMAC_KEY;
  if (!key) return '[REDACTED]';
  return 'hmac:' + createHmac('sha256', key).update(value, 'utf8').digest('hex').slice(0, 16);
}

// before: span.setAttribute('user.email', user.email);
span.setAttribute('enduser.id', String(user.id));          // preferred
span.setAttribute('user.email_hash', piiHmac(user.email)); // only if a join on email is needed
```

This produces the same output as `piiHmac` in the redactor and `pii_hmac` in the Python redactor. Never use a plain SHA-256 of an email.

### Exception messages

Fix the throw site first. Example: ``new Error(`coupon rejected: ${JSON.stringify(req.body)}`)`` → `new Error('coupon rejected')`.

`recordException` copies `name`/`code`, `message` and `stack` (`sdk-trace` 3 `Span.recordException`), and V8's `stack` begins with `Name: message`. To record a library error safely, pass a sanitized object with the stack frames only:

```js
function safeException(err, message) {
  const stack = typeof err?.stack === 'string' ? err.stack : '';
  const frames = stack.indexOf('\n    at ');
  return { name: err?.name ?? 'Error', message, stack: frames >= 0 ? stack.slice(frames + 1) : undefined };
}

span.recordException(safeException(err, 'coupon validation failed'));
span.setStatus({ code: SpanStatusCode.ERROR, message: 'coupon validation failed' }); // never err.message
```

### Span names

Use route templates (`GET /users/:id`), never `req.url` or user input in `startSpan`/`updateName`.

### Logs

Example: ``body: `login ${email} pw=${password}` `` → ``body: `login ${email}` ``. Never emit request bodies, headers or auth objects through the logs bridge.

### Database statements

Use parameterized queries (`client.query('SELECT … WHERE email = $1', [email])`). Turn off value capture where it's offered (`instrumentation-pg` `enhancedDatabaseReporting: false`; Redis/Mongo `dbStatementSerializer` returning the command name only). Many JS DB instrumentations record statements unsanitized ([js-contrib#3471](https://github.com/open-telemetry/opentelemetry-js-contrib/issues/3471)). Check the README of the installed version for option names.

### GenAI content

Unset `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT` (or set it to `false`). Turn off vendor SDK content flags. If content is required, send it to a separate, restricted pipeline.

### Baggage

```js
// before: propagation.setBaggage(ctx, propagation.createBaggage({ 'user.email': { value: email } }))
propagation.setBaggage(ctx, propagation.createBaggage({ 'enduser.id': { value: String(user.id) } }));
```

Baggage goes out on every outbound request, third parties included.

### Metric attribute allowlist

```js
import { createAllowListAttributesProcessor } from '@opentelemetry/sdk-metrics';

new NodeSDK({
  metricReaders: [reader],
  views: [{
    instrumentName: '*',
    attributesProcessors: [createAllowListAttributesProcessor(['http.request.method', 'http.route', 'http.response.status_code'])],
  }],
});
```

`views` is `ViewOptions[]` on NodeSDK 0.300. `createAllowListAttributesProcessor(string[])` is exported from `sdk-metrics` 3.0.0 (`dist/view/AttributesProcessor.d.mts`).

## 4. Browser OTel

`instrumentation-fetch` / `instrumentation-xml-http-request` options ([fetch README](https://github.com/open-telemetry/opentelemetry-js/blob/main/experimental/packages/opentelemetry-instrumentation-fetch/README.md), [XHR README](https://github.com/open-telemetry/opentelemetry-js/blob/main/experimental/packages/opentelemetry-instrumentation-xml-http-request/README.md)):

```js
const FIRST_PARTY = [/^https:\/\/api\.example\.com\//];

function stripQuery(span, url) {
  if (typeof url !== 'string' || !url) return; // RequestInit carries no URL: leave the span untouched
  try {
    const u = new URL(url, location.href);
    u.search = '';
    u.username = '';
    u.password = '';
    span.setAttribute('url.full', u.toString());
    span.setAttribute('http.url', u.toString()); // old semconv key; harmless if unused
  } catch { /* leave as is */ }
}

new FetchInstrumentation({
  propagateTraceHeaderCorsUrls: FIRST_PARTY,  // never /.*/: trace context (and baggage) goes to every origin listed
  ignoreUrls: [/\/healthz/],
  applyCustomAttributesOnSpan: (span, request) => stripQuery(span, request instanceof Request ? request.url : undefined),
});
new XMLHttpRequestInstrumentation({
  propagateTraceHeaderCorsUrls: FIRST_PARTY,
  applyCustomAttributesOnSpan: (span, xhr) => stripQuery(span, xhr.responseURL),
});
```

`applyCustomAttributesOnSpan` runs before the span ends, so `setAttribute` overwrites the recorded URL. Fetch passes `(span, request, result)`, where `request` is a `Request` or `RequestInit`. If it's `RequestInit`, the URL isn't on it, so wrap the app's fetch helper or move tokens out of query strings in source (preferred). The page URL and `@opentelemetry/instrumentation-user-interaction` attributes (`target_element`, `target_xpath`) must never carry user text. Session replay is covered in [session-replay.md](session-replay.md).
