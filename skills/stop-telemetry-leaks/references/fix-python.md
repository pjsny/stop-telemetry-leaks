# Fixing Python telemetry

Checked against `opentelemetry-sdk` 1.45.2 and contrib 0.66b2. The redactor below was run against SDK 1.45.2 with `InMemorySpanExporter` / `InMemoryLogRecordExporter` as the inner exporter.

## 1. Add a redacting exporter wrapper

Write this file next to the bootstrap module, in a package the app already imports from (for example `app/redactor.py`), and adapt it. It depends only on `opentelemetry-sdk`. It rebuilds each span and log record with redacted attributes, event attributes, span name, status description and log body, and passes the copies to the real exporter. A record it can't copy is dropped, never exported raw.

```python
"""Redacting exporter wrappers. Depends only on opentelemetry-sdk."""

import copy
import hashlib
import hmac
import os
import re
from collections.abc import Mapping, Sequence

from opentelemetry.sdk._logs import ReadableLogRecord
from opentelemetry.sdk._logs.export import LogRecordExporter
from opentelemetry.sdk.trace import Event, ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter
from opentelemetry.trace import Status

MASK = "[REDACTED]"
# Keys whose whole value is masked. Extend from the patterns table in surfaces.md.
CREDENTIAL_KEY = re.compile(
    r"(?:^|[._-])(?:proxy-authorization|authorization|set-cookie|cookie|x-api-key|api[_-]?key"
    r"|access_token|refresh_token|client_secret|token|secret|passw(?:or)?d|session[_-]?(?:id|token))(?:$|[._-])",
    re.IGNORECASE,
)
# (regex, action) applied to the matching part of every string value.
VALUE_RULES = [
    (re.compile(r"\b[Bb]earer[ \t]+[A-Za-z0-9._~+/-]{8,}=*"), "mask"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), "mask"),
    (re.compile(r"(?:^|[?&;])(?:api_key|apikey|token|access_token|password|secret)=[^&#\s]+", re.I), "mask"),
    (re.compile(r"(?:\b|_)(?:password|passwd|secret|token|pwd|pw)[\"']?[ \t]*[=:][ \t]*[\"']?[^\s\"'&,;]{4,}", re.I), "mask"),
    (re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), "mask"),  # add a Luhn check to cut false positives
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "hmac"),
]


def pii_hmac(value: str) -> str:
    key = os.environ.get("OTEL_PII_HMAC_KEY")
    if not key:
        return MASK  # fail closed
    return "hmac:" + hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()[:16]


def redact_text(text: str) -> str:
    for regex, action in VALUE_RULES:
        text = regex.sub(lambda m, a=action: pii_hmac(m.group(0)) if a == "hmac" else MASK, text)
    return text


def redact_value(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return redact_attributes(value)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return tuple(redact_value(v) for v in value)
    return value


def redact_attributes(attrs) -> dict:
    return {k: MASK if CREDENTIAL_KEY.search(str(k)) else redact_value(v) for k, v in (attrs or {}).items()}


def redact_span(span: ReadableSpan) -> ReadableSpan:
    status = span.status
    if status.description:
        status = Status(status.status_code, redact_text(status.description))
    return ReadableSpan(
        name=redact_text(span.name), context=span.context, parent=span.parent, resource=span.resource,
        attributes=redact_attributes(span.attributes),
        events=[Event(redact_text(e.name), redact_attributes(e.attributes), e.timestamp) for e in span.events],
        links=span.links, kind=span.kind, status=status, start_time=span.start_time, end_time=span.end_time,
        instrumentation_scope=span.instrumentation_scope,
    )


def redact_log(record: ReadableLogRecord) -> ReadableLogRecord:
    log_record = copy.copy(record.log_record)
    log_record.body = redact_value(log_record.body)
    log_record.attributes = redact_attributes(log_record.attributes)
    return ReadableLogRecord(log_record=log_record, resource=record.resource,
                             instrumentation_scope=record.instrumentation_scope, limits=record.limits)


class _Redacting:
    def __init__(self, inner):
        self._inner = inner

    def export(self, batch):
        out = []
        for item in batch:
            try:
                out.append(self._redact(item))
            except Exception:
                pass  # fail closed: drop a record we can't redact
        return self._inner.export(out)

    def shutdown(self):
        return self._inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._inner.force_flush(timeout_millis)


class RedactingSpanExporter(_Redacting, SpanExporter):
    _redact = staticmethod(redact_span)


class RedactingLogRecordExporter(_Redacting, LogRecordExporter):
    _redact = staticmethod(redact_log)
```

Adapt it:

- The rule list is a starting set. Add rows from the value patterns table in [surfaces.md](surfaces.md#secret-and-pii-value-patterns) that match what the repo leaks (JWT, AWS keys, phone numbers, IP truncation). Add validators where the table names one: a Luhn check for card numbers keeps order IDs and timestamps intact.
- Python `re` accepts every pattern in that table; keep the case-insensitive ones on `re.IGNORECASE`.
- Add app-specific keys (for example `customer.phone`) to `CREDENTIAL_KEY` or to a separate key pattern with the `hmac` action.
- The resource is passed through unchanged. Fix resource leaks at the source.
- If the user asked for verification, check it with [verifying.md](verifying.md): the fake values must be absent from what the inner exporter receives.

### Manual SDK bootstrap (`TracerProvider` / `LoggerProvider` in app code)

Wrap the exporter itself, inside the existing processor. Leave the processor alone.

```python
# before
from opentelemetry.sdk.trace.export import BatchSpanProcessor
...
tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
...
logger_provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))
```

```python
# after
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from app.redactor import RedactingLogRecordExporter, RedactingSpanExporter
...
tracer_provider.add_span_processor(BatchSpanProcessor(RedactingSpanExporter(OTLPSpanExporter())))
...
logger_provider.add_log_record_processor(BatchLogRecordProcessor(RedactingLogRecordExporter(OTLPLogExporter())))
```

Wrap every exporter the app registers, including console/debug exporters and a second vendor exporter. A `SimpleSpanProcessor` is wrapped the same way.

### Zero-code bootstrap (`opentelemetry-instrument`)

`opentelemetry-instrument` builds the providers from env vars, so app code never sees an exporter. Options, in order of preference:

1. **Attach a redacting exporter to the auto-configured providers** (recommended). Set `OTEL_TRACES_EXPORTER=none` and `OTEL_LOGS_EXPORTER=none` (the distro defaults them to `otlp`), so `opentelemetry-instrument` still creates and registers the SDK providers but gives them no exporters. Then, in a module the app imports at startup, add the wrapped exporters to the global providers. `trace.set_tracer_provider` can't replace a provider that's already set, so add to it:

   ```python
   # app/otel_attach.py
   from opentelemetry import _logs, trace
   from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
   from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
   from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
   from opentelemetry.sdk.trace.export import BatchSpanProcessor

   from app.redactor import RedactingLogRecordExporter, RedactingSpanExporter

   trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(RedactingSpanExporter(OTLPSpanExporter())))
   _logs.get_logger_provider().add_log_record_processor(BatchLogRecordProcessor(RedactingLogRecordExporter(OTLPLogExporter())))
   ```

   Use the exporter classes that match `OTEL_EXPORTER_OTLP_PROTOCOL` (the distro defaults to `grpc`). Telemetry emitted before this module runs is lost, which is safe. Set `none` in **every** environment that runs the app (Dockerfile `ENV`, compose, k8s). Without it each span is exported twice, once raw and once redacted. The other route is to drop `opentelemetry-instrument` and switch to the full manual bootstrap above.

   With both variables at `none`, the providers export exactly one redacted copy of each span and log record (checked on SDK 1.45.2 / distro 0.66b2).

   **Verifying this route.** A mock-exporter test from [verifying.md](verifying.md) has to load `app.otel_attach` the way production does, then add its in-memory exporter wrapped in the same `RedactingSpanExporter`, or replace the OTLP exporter inside `otel_attach` with the in-memory one for the run. Keep `OTEL_TRACES_EXPORTER=none` and `OTEL_LOGS_EXPORTER=none` set during the run so the result matches production. The mock collector option needs no changes here.
2. **Configurator subclass** (only when the app is an installed package with entry points). The SDK's `_initialize_components` accepts `export_span_processor` and `export_log_record_processor` callables (`opentelemetry/sdk/_configuration/__init__.py`), and `_OTelSDKConfigurator._configure(**kwargs)` forwards kwargs to it. These are private (`_`-prefixed) APIs and can change in any release:

   ```python
   # app/otel_configurator.py
   from opentelemetry.sdk._configuration import _OTelSDKConfigurator
   from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
   from opentelemetry.sdk.trace.export import BatchSpanProcessor

   from app.redactor import RedactingLogRecordExporter, RedactingSpanExporter


   class RedactingConfigurator(_OTelSDKConfigurator):
       def _configure(self, **kwargs):
           kwargs.setdefault("export_span_processor", lambda e, *a, **k: BatchSpanProcessor(RedactingSpanExporter(e)))
           kwargs.setdefault(
               "export_log_record_processor", lambda e, *a, **k: BatchLogRecordProcessor(RedactingLogRecordExporter(e))
           )
           super()._configure(**kwargs)
   ```

   ```toml
   # pyproject.toml
   [project.entry-points.opentelemetry_configurator]
   redacting = "app.otel_configurator:RedactingConfigurator"
   ```

   Set `OTEL_PYTHON_CONFIGURATOR=redacting`. `_load_configurators` in `opentelemetry/instrumentation/auto_instrumentation/_load.py` loads only the first matching entry point, so without this variable the distro's own configurator can win. With `OTEL_CONFIG_FILE` set, configurator kwargs are ignored (warning logged), so this path doesn't apply.

Never monkeypatch exporters from `sitecustomize`.

### HMAC key

- `OTEL_PII_HMAC_KEY` keys the `hmac` action: `hmac:` + the first 16 hex chars of HMAC-SHA256(key, UTF-8 value).
- If it's unset, every `hmac` rule falls back to `[REDACTED]` (fail closed). Nothing breaks. You only lose joinability.
- Provision it like any production secret: secret manager → env var at deploy (k8s `secretKeyRef`, ECS/Cloud Run secrets, Vault agent). Use one key per environment, at least 32 random bytes (`python3 -c "import secrets; print(secrets.token_hex(32))"`). Never commit it, never put it in `.env.example` with a real value, never log it. Rotating it changes every hash, so dashboards keyed on hashed IDs reset.

## 2. Critical config fixes

| Finding | Fix |
|---|---|
| `http.request.header` capture list | Delete credential names from `OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST`/`_SERVER_RESPONSE`/`_CLIENT_REQUEST`/`_CLIENT_RESPONSE` wherever they're set (code `os.environ.setdefault`, `.env`, compose, k8s, Dockerfile). Example: `"authorization,cookie,user-agent,x-request-id"` → `"user-agent,x-request-id"`. Also set `OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS=authorization,cookie,set-cookie,x-api-key,.*token.*,.*secret.*` (case-insensitive regexes → `[REDACTED]`). The real name has no `PYTHON_` infix (`opentelemetry/util/http/__init__.py`) |
| Query tokens (`url`) | Python has no option for this: `PARAMS_TO_REDACT` is fixed at `AWSAccessKeyId, Signature, sig, X-Goog-Signature`. Move the token to a header in source. The redactor's `token=` value rule masks the rest |
| URL userinfo | Build URLs without `user:pass@`. Pass credentials with `auth=`/headers. Client instrumentations call `remove_url_credentials`, but app-set attributes and span names don't go through it |
| Committed OTLP headers (`exporter.config`) | Replace the literal with a reference: `OTEL_EXPORTER_OTLP_HEADERS=${OTEL_EXPORTER_OTLP_HEADERS}` in compose, `valueFrom.secretKeyRef` in k8s, remove `ENV` from the Dockerfile. Add the secret to the report's rotation list with file and first commit SHA (`git log --diff-filter=A --format=%H -S'<first 4 chars>' -- <file>`, and don't print the value). It's still in git history, so the user must rotate it |
| `resource` | Move secrets out of argv. Drop `process` from `OTEL_EXPERIMENTAL_RESOURCE_DETECTORS` if it's there (`ProcessResourceDetector` copies `sys.argv` to `process.command_args`/`process.command_line`). Remove secrets from `OTEL_RESOURCE_ATTRIBUTES` and `Resource.create({...})` |

## 3. Source fixes (High/Medium: propose a diff)

### Stable IDs instead of PII

```python
# before
span.set_attribute("user.email", user.email)
# after
span.set_attribute("enduser.id", str(user.id))           # internal ID, preferred
span.set_attribute("user.email_hash", pii_hmac(user.email))  # only when a join on email is needed
```

### HMAC helper

Same algorithm as the redactor, so app-side and exporter-side hashes match:

```python
import hashlib
import hmac
import os


def pii_hmac(value: str) -> str:
    key = os.environ.get("OTEL_PII_HMAC_KEY")
    if not key:
        return "[REDACTED]"
    return "hmac:" + hmac.new(key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
```

Never use a plain `sha256(email)`: low-entropy values can be reversed by brute force.

### Exception messages

Fix the raise site first, for example `ValueError(f"invalid card {payload.card}")` → `ValueError("invalid card")`. Put safe context in attributes.

When the exception comes from a library and has to be recorded anyway, override message and stacktrace. The SDK's default `exception.stacktrace` is `traceback.format_exception(e)`, which ends with the message, so overriding only the message still leaks. `record_exception` merges your `attributes` over its defaults (`opentelemetry/sdk/trace/__init__.py`):

```python
import traceback

span.record_exception(
    exc,
    attributes={
        "exception.message": "payment validation failed",
        "exception.stacktrace": "".join(traceback.format_tb(exc.__traceback__)),  # frames only, no message
    },
)
span.set_status(StatusCode.ERROR, "payment validation failed")  # never str(exc)
```

Instrumentations (FastAPI/ASGI) that record unhandled exceptions automatically use the original message, so a fixed raise-site message is the only complete fix.

### Span names

Use the route template, never the raw path or user input. Server instrumentations already name spans `METHOD /route/{param}`; check custom `span.update_name(...)` and `tracer.start_as_current_span(f"... {email}")`.

### Logs

Example: `logger.info("login %s password=%s", payload.username, payload.password)` → `logger.info("login %s", payload.username)`. Never log request bodies or auth objects. `extra={...}` keys become log attributes.

### Database statements

```python
# before: literal ends up in db.statement
cur.execute(f"SELECT * FROM customers WHERE email = '{email}'")
# after: db.statement holds only the placeholder
cur.execute("SELECT * FROM customers WHERE email = ?", (email,))
```

The dbapi/sqlite3 instrumentations copy the statement verbatim (no sanitizing in 0.66b2). Keep `capture_parameters=False` (the default) on `DatabaseApiIntegration`/`trace_integration`. `enable_commenter` only adds sqlcommenter tags.

### GenAI content

Remove `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT` or set it to `false` (legacy) / `no_content` (with `OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental`). `span_only`, `event_only`, `span_and_event` and `true` all capture content ([openai-v2 README](https://github.com/open-telemetry/opentelemetry-python-contrib/blob/main/instrumentation-genai/opentelemetry-instrumentation-openai-v2/README.rst)). If content is required, send it to a separate pipeline with restricted access and short retention.

### Baggage

```python
# before
ctx = baggage.set_baggage("user.email", user.email)
# after: opaque ID or nothing; baggage goes to every downstream hop
ctx = baggage.set_baggage("enduser.id", str(user.id))
```

### Metric attribute allowlist

```python
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.view import View

provider = MeterProvider(
    metric_readers=[reader],
    views=[View(instrument_name="*", attribute_keys={"http.request.method", "http.route", "http.response.status_code"})],
)
```

Keys not in `attribute_keys` are dropped from the stream (`opentelemetry/sdk/metrics/_internal/view.py`). Every View that matches an instrument produces its own stream, so give any extra Views their own `attribute_keys` too.
