// Preloaded by canary_run.py via NODE_OPTIONS (--import, ahead of the app's bootstrap). Imports no
// packages. It does two things:
//
// 1. Redirects exports. Any http/https request (request() and get()) or fetch() whose path ends in
//    /v1/traces, /v1/logs or /v1/metrics and whose target is not the receiver is sent to the receiver
//    (OTEL_PII_RECEIVER_ENDPOINT) over plain http instead, with every header except content-type,
//    content-encoding, transfer-encoding and content-length dropped. This catches OTLP/HTTP
//    exporters with a hardcoded `url` (and headers), so neither canary values nor real credentials
//    reach a real backend. @opentelemetry/otlp-exporter-base 0.300 resolves `request` from
//    `await import('http')` at send time, so syncBuiltinESMExports() makes it see the wrapper.
//    OTLP gRPC exporters (http2) are not redirected and cannot be captured.
//
// 2. Flushes. It reads the globally registered OpenTelemetry providers and force-flushes them
//    before the process exits (beforeExit, once) and on SIGTERM, capped at 3 s:
//      @opentelemetry/api 1.10:  globalThis[Symbol.for('opentelemetry.js.api.1')]
//                                .trace — ProxyTracerProvider; getDelegate() returns the SDK provider
//                                .logs  — the SDK LoggerProvider itself
//      @opentelemetry/api-logs:  globalThis[Symbol.for('io.opentelemetry.js.api.logs')]
//                                — a getter; call it with the compatibility version to get the provider
//    Limit: vitest's threads/vmThreads pools end workers with worker.terminate(), so beforeExit never
//    fires there and each worker's last (<100 ms) batch is lost; vitest's default forks pool and jest
//    workers flush. canary_run.py recommends --pool=forks when a vitest run captures nothing.

import http from 'node:http';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';

const API_KEY = Symbol.for('opentelemetry.js.api.1');
const LEGACY_LOGS_API_KEY = Symbol.for('io.opentelemetry.js.api.logs');
const LEGACY_LOGS_API_COMPAT_VERSION = 1;
const FLUSH_CAP_MS = 3000;

// --- 1. export redirect ----------------------------------------------------------------------

const OTLP_PATH = /\/v1\/(traces|logs|metrics)$/;
const KEPT_HEADERS = new Set(['content-type', 'content-encoding', 'transfer-encoding', 'content-length']);
// fetch computes framing itself and rejects these.
const FETCH_DROPPED_HEADERS = new Set(['transfer-encoding', 'content-length']);

function parseReceiver(value) {
  try {
    return value ? new URL(value) : undefined;
  } catch {
    return undefined;
  }
}

const receiver = parseReceiver(process.env.OTEL_PII_RECEIVER_ENDPOINT);

function effectivePort(url) {
  return url.port || (url.protocol === 'https:' ? '443' : '80');
}

function redirectTarget(url) {
  if (!receiver) return undefined;
  const match = OTLP_PATH.exec(url.pathname);
  if (!match) return undefined;
  if (url.hostname === receiver.hostname && effectivePort(url) === effectivePort(receiver)) return undefined;
  return new URL(`/v1/${match[1]}`, receiver);
}

const reported = new Set();
function report(url) {
  const key = `${url.host}${url.pathname}`;
  if (reported.has(key)) return;
  reported.add(key);
  process.stderr.write(`otel-pii: redirected OTLP export for ${url.protocol}//${key} to the local receiver\n`);
}

function keptHeaders(headers) {
  const kept = {};
  if (!headers) return kept;
  const entries = Array.isArray(headers)
    ? Array.from({ length: Math.floor(headers.length / 2) }, (_, i) => [headers[2 * i], headers[2 * i + 1]])
    : headers instanceof Map || headers instanceof Headers
      ? Array.from(headers.entries())
      : Object.entries(headers);
  for (const [name, value] of entries) {
    if (KEPT_HEADERS.has(String(name).toLowerCase()) && value !== undefined) kept[String(name).toLowerCase()] = value;
  }
  return kept;
}

// Target URL of an http(s).request/get call: (url[, options][, cb]) or (options[, cb]).
function requestTarget(args, defaultProtocol) {
  let i = 0;
  let url;
  if (typeof args[0] === 'string' || args[0] instanceof URL) {
    url = new URL(String(args[0]));
    i = 1;
  }
  const options = args[i] && typeof args[i] === 'object' ? args[i] : {};
  if (options === args[i]) i += 1;
  const callback = typeof args[i] === 'function' ? args[i] : undefined;
  if (!url || options.protocol || options.hostname || options.host || options.port || options.path) {
    const protocol = options.protocol || url?.protocol || defaultProtocol;
    let host = options.hostname || (options.host && String(options.host).split(':')[0]) || url?.hostname || 'localhost';
    if (host.includes(':') && !host.startsWith('[')) host = `[${host}]`;
    const port = options.port ?? url?.port;
    const path = options.path || (url ? `${url.pathname}${url.search}` : '/');
    url = new URL(`${protocol}//${host}${port ? `:${port}` : ''}${path}`);
  }
  return { url, options, callback };
}

const originalHttpRequest = http.request;

function maybeRedirectRequest(args, defaultProtocol) {
  let parsed;
  try {
    parsed = requestTarget(args, defaultProtocol);
  } catch {
    return undefined;
  }
  const target = redirectTarget(parsed.url);
  if (!target) return undefined;
  report(parsed.url);
  const { options, callback } = parsed;
  const redirected = { method: options.method || 'POST', headers: keptHeaders(options.headers) };
  if (options.timeout !== undefined) redirected.timeout = options.timeout;
  if (options.signal) redirected.signal = options.signal;
  const req = originalHttpRequest(target, redirected, callback);
  const setHeader = req.setHeader.bind(req);
  req.setHeader = (name, value) => (KEPT_HEADERS.has(String(name).toLowerCase()) ? setHeader(name, value) : req);
  return req;
}

if (receiver) {
  for (const [mod, protocol] of [[http, 'http:'], [https, 'https:']]) {
    const originalRequest = mod.request;
    const originalGet = mod.get;
    mod.request = function request(...args) {
      return maybeRedirectRequest(args, protocol) ?? originalRequest.apply(this, args);
    };
    mod.get = function get(...args) {
      const req = maybeRedirectRequest(args, protocol);
      if (!req) return originalGet.apply(this, args);
      req.end();
      return req;
    };
  }
  syncBuiltinESMExports();

  const originalFetch = globalThis.fetch;
  if (typeof originalFetch === 'function') {
    globalThis.fetch = function fetch(input, init) {
      let url;
      try {
        url = new URL(input instanceof Request ? input.url : String(input));
      } catch {
        return originalFetch(input, init);
      }
      const target = redirectTarget(url);
      if (!target) return originalFetch(input, init);
      report(url);
      const request = new Request(input, init);
      const headers = {};
      for (const [name, value] of request.headers) {
        if (KEPT_HEADERS.has(name) && !FETCH_DROPPED_HEADERS.has(name)) headers[name] = value;
      }
      return originalFetch(target, {
        method: request.method,
        headers,
        body: request.body,
        duplex: 'half',
        signal: request.signal,
      });
    };
  }
}

// --- 2. flush --------------------------------------------------------------------------------

function unwrap(entry) {
  if (!entry) return undefined;
  if (typeof entry.getDelegate === 'function') return entry.getDelegate();
  if (typeof entry._getDelegate === 'function') return entry._getDelegate();
  return entry;
}

function providers() {
  const found = new Set();
  const registry = globalThis[API_KEY];
  const legacyLogs = globalThis[LEGACY_LOGS_API_KEY];
  const candidates = [
    () => unwrap(registry?.trace),
    () => unwrap(registry?.logs),
    () => unwrap(typeof legacyLogs === 'function' ? legacyLogs(LEGACY_LOGS_API_COMPAT_VERSION) : legacyLogs),
  ];
  for (const get of candidates) {
    try {
      const provider = get();
      if (provider && typeof provider.forceFlush === 'function') found.add(provider);
    } catch {
      // A broken registry entry must not crash the test process.
    }
  }
  return [...found];
}

async function flushAll() {
  const flushes = providers().map((provider) => {
    try {
      return Promise.resolve(provider.forceFlush()).catch(() => {});
    } catch {
      return Promise.resolve();
    }
  });
  if (flushes.length === 0) return;
  let timer;
  const cap = new Promise((resolve) => {
    timer = setTimeout(resolve, FLUSH_CAP_MS);
  });
  await Promise.race([Promise.allSettled(flushes), cap]);
  clearTimeout(timer);
}

let flushedOnExit = false;
process.on('beforeExit', async () => {
  if (flushedOnExit) return;
  flushedOnExit = true;
  await flushAll();
});

async function onSigterm() {
  await flushAll();
  // Restore default termination when nobody else handles SIGTERM.
  if (process.listenerCount('SIGTERM') === 0) process.kill(process.pid, 'SIGTERM');
}
process.once('SIGTERM', onSigterm);
