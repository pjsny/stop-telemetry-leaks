# Fixtures

Four small apps with leaks planted in normal-looking code. Nothing in the source hints at where they are. Each app's `expected.toml` is the answer key, and it's left out of the copies agents get.

| App | Stack | Planted leaks |
|---|---|---|
| `py-fastapi-pytest` | FastAPI, pytest, gRPC OTLP exporters | auth headers on spans, exporter key in `.env`, password in a log line, emails in spans, SQL and baggage, card number in an exception |
| `js-express-vitest` | Express, vitest | auth headers, `api_key` in URLs, the `redactedQueryParams` trap, request body in an exception, password in a log line |
| `js-fastify-jest` | Fastify, jest | `access_token` in an outbound URL, cookie header, DB password in resource attributes, phone number, SSN in SQL |
| `web-replay` | browser app | Sentry, PostHog, Datadog, rrweb and Clarity with masking off, recorded auth headers and bodies, unmasked card fields |

All secrets are fake.

Each `[[plant]]` in `expected.toml` has an `id`, `surface`, `key`, `file`, a `match` string that appears once in that file, a `severity`, and `runtime = true` if the leak shows up in exported telemetry.

## Setup

```sh
uv venv evals/fixtures/py-fastapi-pytest/.venv
uv pip install --python evals/fixtures/py-fastapi-pytest/.venv/bin/python -r evals/fixtures/py-fastapi-pytest/requirements.txt
(cd evals/fixtures/js-express-vitest && npm ci)
(cd evals/fixtures/js-fastify-jest && npm ci)
```

`web-replay` needs nothing installed.

One gotcha: jest gives each test file its own global, so app spans in `js-fastify-jest` never reach the exporter under jest. The grader runs that app with a small driver script outside jest instead (`evals/canary_tests/js-fastify-jest/canary-driver.cjs`).
