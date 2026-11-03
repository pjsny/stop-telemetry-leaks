# Leak surfaces

One table per surface group. **Surface** is the name to use in the report. "Runtime" surfaces show up in captured spans and log records, so an optional verification run ([verifying.md](verifying.md)) can confirm them. Static-only surfaces never reach a span or log payload; mark them `static-only` in the report. Severity is the default. Downgrade it only with a reason in the report.

The **Detect** rows give ripgrep patterns to run from the repo root. Add `-g '!node_modules' -g '!.venv' -g '!dist'` (or rely on `.gitignore`) and read every hit: a pattern finds candidates, the surrounding code decides whether a value is user data. Patterns use Rust regex syntax (no lookarounds); `-i` makes them case-insensitive, `-P` switches to PCRE2 when a pattern needs lookarounds.

Versions checked: Python `opentelemetry-sdk` 1.45.2 / contrib 0.66b2 (`tests/fixtures/py-fastapi-pytest/.venv`), JS `@opentelemetry/sdk-node` and `instrumentation-http` 0.300.0, `sdk-logs`/`sdk-metrics` 3.0.0 (`tests/fixtures/js-express-vitest/node_modules`).

Fix order for every row: source fix → redacting exporter wrapper → Collector. The redactor and Collector are added on top of the source fix and never replace it. How to apply each fix: [fix-python.md](fix-python.md), [fix-js.md](fix-js.md), [collector.md](collector.md).

## HTTP headers: `http.request.header`

| | |
|---|---|
| Keys | `http.request.header.<name>`, `http.response.header.<name>` (old semconv JS: hyphens become `_`) |
| How it leaks | A header capture list names `authorization`, `cookie`, `set-cookie`, `x-api-key`, `proxy-authorization`, or a custom auth header |
| Python knobs | `OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST`, `..._SERVER_RESPONSE`, `..._CLIENT_REQUEST`, `..._CLIENT_RESPONSE` (comma list, regex allowed, `.*` = all). `OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS`: comma list of case-insensitive regexes, matching values become `[REDACTED]` (`opentelemetry/util/http/__init__.py` 0.66b2). Note: the variable has **no** `PYTHON_` infix |
| JS Node knobs | `HttpInstrumentation({ headersToSpanAttributes: { client: { requestHeaders, responseHeaders }, server: { requestHeaders, responseHeaders } } })`. No sanitize option exists, so remove the names from the list |
| JS browser | Fetch/XHR instrumentations record no headers. Custom `applyCustomAttributesOnSpan` code can add them |
| Detect | `rg -n -i 'OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_'` (env files, compose, k8s, Dockerfiles, `os.environ` calls; a credential name or `.*` in the list is the leak, minus names covered by `..._SANITIZE_FIELDS`). `rg -n -U 'headersToSpanAttributes' -A8` and check the `requestHeaders`/`responseHeaders` arrays for `authorization`, `cookie`, `set-cookie`, `x-api-key`, `proxy-authorization` or custom auth headers |
| Severity | Critical |
| Fix | Remove the credential headers from every list (applied automatically). Python: also set `..._SANITIZE_FIELDS` to `authorization,cookie,set-cookie,x-api-key,.*token.*,.*secret.*` as a backstop. Redactor key rules mask whatever is left |

## URLs and span names: `url`, `span.name`

| | |
|---|---|
| Keys | `url.full`, `url.query`, `url.path`, `http.url`, `http.target`, `http.route` (safe template); span names |
| How it leaks | Tokens in query strings (`?token=`, `access_token`, `api_key`, signed URLs), userinfo (`https://user:pass@host`), emails/IDs in paths, span names built from raw paths (`span.name = f"GET {request.url}"`) |
| Python knobs | `redact_query_parameters` in `opentelemetry-util-http` hard-codes `PARAMS_TO_REDACT = ["AWSAccessKeyId", "Signature", "sig", "X-Goog-Signature"]` with no config option. `remove_url_credentials` replaces userinfo with `REDACTED:REDACTED@`. Excluding a URL: `OTEL_PYTHON_<FRAMEWORK>_EXCLUDED_URLS` |
| JS Node knobs | `redactedQueryParams` (client) and `redactedQueryParamsServer` (server). See the trap below |
| JS browser | `@opentelemetry/instrumentation-fetch` / `instrumentation-xml-http-request`: `ignoreUrls`, `applyCustomAttributesOnSpan` (overwrite `url.full`/`http.url` with a query-less URL) |
| Detect | Tokens in URLs: `rg -n -i '[?&](token\|access_token\|api_key\|apikey\|sig\|signature\|password\|secret\|code)='`. Userinfo: `rg -n '[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]*@'`. Span names: `rg -n 'start_as_current_span\(f\|start_span\(f\|update_name\(\|startSpan\(\|startActiveSpan\(\|updateName\('`. JS query redaction: `rg -n 'redactedQueryParams(Server)?'` (one set without the other is a leak) |
| Severity | Critical for tokens and userinfo; High for PII in paths or span names |
| Fix | Move tokens out of URLs (header or body). Strip userinfo before the request. Name spans after the route template (`GET /users/{id}`). JS: set the merged list on both options. Redactor value rules mask `token=` and userinfo |

### JS replace-not-merge trap

From `@opentelemetry/instrumentation-http` 0.300.0 README ("Query parameter redaction"): by default both sides redact

```text
sig, Signature, AWSAccessKeyId, X-Goog-Signature,
X-Amz-Signature, X-Amz-Credential, X-Amz-Security-Token
```

- Passing an array **replaces** the built-in list. Nothing is merged.
- The two options are independent. Setting only `redactedQueryParams` leaves server spans on the built-in list, so custom params still leak on server spans.
- Names match exactly and are case-sensitive.
- `[]` disables redaction on that side.

Always write one merged array (the built-ins plus the app's params) and pass it to both options. Snippet: [fix-js.md](fix-js.md#query-parameter-redaction).

## Database: `db`

| | |
|---|---|
| Keys | `db.query.text`, `db.statement`, `db.statement.parameters`, `db.query.parameter.*`, Redis/Mongo command args |
| How it leaks | Statements built by string interpolation (literals hold emails, card numbers), parameter capture switched on, Redis/Mongo value capture |
| Python knobs | `opentelemetry-instrumentation-dbapi`/`sqlite3` 0.66b2 record the statement text **unsanitized** (`_set_db_statement` copies it verbatim). `capture_parameters=False` is the default; `True` adds `db.statement.parameters`. `enable_commenter`/`enable_attribute_commenter` only add sqlcommenter tags and do no sanitizing |
| JS Node knobs | Per instrumentation: `@opentelemetry/instrumentation-pg` `enhancedDatabaseReporting` (adds parameter values), `instrumentation-redis` `dbStatementSerializer`, `instrumentation-mongodb` `enhancedDatabaseReporting`/`dbStatementSerializer`. Many record statements with no sanitizing ([js-contrib#3471](https://github.com/open-telemetry/opentelemetry-js-contrib/issues/3471)). Check the README of the installed version |
| Detect | Interpolated SQL: `` rg -n '(execute\|executemany\|query\|raw)\(\s*(f["\x27]\|`[^`]*\$\{)' `` and `rg -n '(execute\|query)\([^)]*(%\|\.format\(\|\+ )'`. Value capture: `rg -n 'capture_parameters\s*=\s*True\|enhancedDatabaseReporting\|dbStatementSerializer\|responseHook'` |
| Severity | High |
| Fix | Use parameterized queries so the statement holds placeholders only. Turn off parameter capture. Where an instrumentation offers a serializer, pass one that drops values |

## Exceptions: `exception`

| | |
|---|---|
| Keys | Event `exception` attributes: `exception.message`, `exception.stacktrace`, `exception.type`. Also the span status message (`span.status`) |
| How it leaks | `record_exception(e)`/`recordException(err)`, or automatic recording by instrumentations, when the message embeds input: `ValueError(f"invalid card {card}")`, ``new Error(`rejected: ${JSON.stringify(req.body)}`)``. `set_status(StatusCode.ERROR, str(e))` copies it into status |
| Knobs | None. Instrumentations record the original exception |
| Detect | Messages built from input: `` rg -n '(Error\|Exception)\((f["\x27]\|`[^`]*\$\{)' ``, `rg -n 'raise \w+\(f["\x27]'`. Sinks: `rg -n 'record_exception\(\|recordException\('`, `rg -n 'set_status\([^)]*str\(\|setStatus\([^)]*\.message'` |
| Severity | High; Critical when the message carries passwords, tokens, or whole request bodies |
| Fix | Raise with a fixed message and pass identifiers as separate safe attributes. When the exception must be recorded, record type and a safe message and keep the stack ([fix-python.md](fix-python.md#exception-messages), [fix-js.md](fix-js.md#exception-messages)). A redactor can't recognise an opaque secret inside free text |

## GenAI content: `gen_ai`

| | |
|---|---|
| Keys | `gen_ai.input.messages`, `gen_ai.output.messages`, `gen_ai.system_instructions`, legacy events `gen_ai.{role}.message`, `gen_ai.choice` |
| How it leaks | Content capture switched on |
| Python knobs | `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT`: legacy `true`/`false`; with `OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental` it takes `no_content` (default), `span_only`, `event_only`, `span_and_event` ([openai-v2 README](https://github.com/open-telemetry/opentelemetry-python-contrib/blob/main/instrumentation-genai/opentelemetry-instrumentation-openai-v2/README.rst), [util-genai `ContentCapturingMode`](https://github.com/open-telemetry/opentelemetry-python-contrib/blob/main/util/opentelemetry-util-genai/src/opentelemetry/util/genai/types.py)) |
| JS Node knobs | Same env var in OTel JS GenAI instrumentations. Vendor SDKs use their own flags (e.g. `captureMessageContent`, `traceContent`). Check the installed package |
| Detect | `rg -n -i 'OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT'` (any value except `false`/`0`/`no`/`off`/`none`/`no_content` captures), `rg -n 'captureMessageContent\s*:\s*true\|traceContent\s*:\s*true\|capture_message_content\s*=\s*True'` |
| Severity | High |
| Fix | Unset the variable or set it to `false`/`no_content`. If the team needs content, route it to a separate pipeline with its own retention and access control |

## Custom attributes and events: `attribute`

| | |
|---|---|
| Keys | Anything set by app code: `user.email`, `customer.phone`, `request.body`, `card.number` |
| How it leaks | `set_attribute`/`setAttribute`/`setAttributes`, `add_event`/`addEvent` with user data or whole request objects |
| Detect | `rg -n 'set_attribute\|set_attributes\|setAttribute\|setAttributes\|add_event\|addEvent'`. Read each call: flag keys that match the credential key pattern below or name PII (`email`, `phone`, `name`, `address`, `card`, `ssn`, `dob`, `body`, `payload`), and values taken from request objects (`req.body`, `request.json()`, `payload.`). GraphQL: `rg -n 'allowValues\s*:\s*true'` |
| Severity | High; credentials Critical |
| Fix | Use a stable internal ID or an HMAC of the value ([fix-python.md](fix-python.md#hmac-helper)). Never attach whole bodies. Add the key to the redactor's key pattern so it catches the next one |

## Quasi-identifiers: `attribute`

| | |
|---|---|
| Keys | `enduser.id`, `user.id`, `client.address`, `network.peer.address`, `user_agent.original` |
| How it leaks | Set by app code or by HTTP instrumentations by default (`client.address`) |
| Detect | `rg -n 'enduser\.id\|user\.id\|client\.address\|network\.peer\.address\|user_agent\.original'` for app-set values. HTTP server instrumentations set `client.address` themselves, so a static run reports it from the instrumentation in use and a verification run confirms it |
| Severity | Medium |
| Fix | HMAC IDs. Truncate addresses (zero the last IPv4 octet, keep the first three IPv6 groups) in the redactor or with the Collector `transform` recipe. The proposal lists dashboards/alerts in the repo that reference the key |

## Logs: `log.body`, `log.attribute`

| | |
|---|---|
| Keys | Log record body; log attributes (`extra=`, structured fields) |
| How it leaks | Logs bridge (`LoggingHandler`, `instrumentation-pino`/`winston`/`bunyan`, `logs.getLogger().emit`) exporting messages that interpolate passwords, emails, request objects |
| Python knobs | `OTEL_PYTHON_LOGGING_AUTO_INSTRUMENTATION_ENABLED`; `LoggingHandler` takes no filter, so fix the call site or wrap the exporter |
| JS Node knobs | `logRecordProcessors: [new BatchLogRecordProcessor({ exporter })]` in NodeSDK; bridge instrumentation options per package |
| Detect | Bridges: `rg -n 'LoggingHandler\|OTEL_PYTHON_LOGGING_AUTO_INSTRUMENTATION_ENABLED\|instrumentation-(pino\|winston\|bunyan)\|getLogger\([^)]*\)\.emit\|logs\.getLogger'`. Call sites: `rg -n '\b(logger\|log\|logging)\.(info\|warn\|warning\|error\|debug\|exception)\('` and `rg -n '\.emit\(\{'`, then read each one for passwords, tokens, emails or whole request objects in the message or `extra=`/`attributes` |
| Severity | High; Critical when the message carries passwords, tokens, or whole request bodies |
| Fix | Remove the value from the message. Wrap the log exporter with `RedactingLogRecordExporter` |

## Resource: `resource`

| | |
|---|---|
| Keys | `process.command_args`, `process.command_line`, `process.command`, custom `OTEL_RESOURCE_ATTRIBUTES` entries |
| How it leaks | Python `ProcessResourceDetector` sets `process.command_line`/`process.command_args` from `sys.argv` when the `process` detector is enabled (`OTEL_EXPERIMENTAL_RESOURCE_DETECTORS`). JS NodeSDK defaults to `OTEL_NODE_RESOURCE_DETECTORS=all`, which includes `process` (detector names `env`, `host`, `os`, `process`, `serviceinstance`). Secrets passed as CLI flags (`--password=…`) or put in `OTEL_RESOURCE_ATTRIBUTES` |
| Detect | Detector config: `rg -n 'OTEL_NODE_RESOURCE_DETECTORS\|OTEL_EXPERIMENTAL_RESOURCE_DETECTORS\|processDetector\|ProcessResourceDetector'`. Secrets in argv: `rg -n -i '(--?[a-z_-]*(password\|token\|secret\|api[_-]?key)[a-z_-]*[ =])'` in Dockerfiles (`CMD`, `ENTRYPOINT`, `RUN`), compose `command:`/`entrypoint:`, k8s `args:`, and `package.json` scripts. `rg -n 'OTEL_RESOURCE_ATTRIBUTES'` and check the keys |
| Severity | Critical |
| Fix | Pass secrets through env/secret files instead of argv. JS: `OTEL_NODE_RESOURCE_DETECTORS=env,host,os,serviceinstance`. Python: remove `process` from `OTEL_EXPERIMENTAL_RESOURCE_DETECTORS`. Remove secrets from `OTEL_RESOURCE_ATTRIBUTES`. The redactor doesn't touch the resource |

## Static-only surfaces

These never appear in captured span/log payloads, so a verification run can't confirm them. Find and fix them by reading the code.

| Surface | Keys / location | How it leaks | Detect (static) | Severity | Fix |
|---|---|---|---|---|---|
| `baggage` | Baggage entries | `baggage.set_baggage`/`propagation.setBaggage` with user data. Baggage propagates to every downstream service, including third parties (`traceparent`/`baggage` headers) | `rg -n 'set_baggage\|setBaggage\|createBaggage\|setEntry\('` (flag user data in keys or values); `rg -n 'propagateTraceHeaderCorsUrls'` (High for `/.*/`, `/.+/`) | High | Carry only opaque internal IDs, or nothing. Don't copy baggage into span attributes wholesale. Browser: scope `propagateTraceHeaderCorsUrls` to your own origins |
| `metric.attribute` | Metric data point attributes | User IDs/emails as labels: `counter.add(1, {"user.email": …})` | `rg -n '\.(add\|record)\([^,]+,\s*\{'` (attributes object/dict on a counter or histogram). Missing View allowlist: `rg -n 'View\(\|views:'` | Medium; Critical for credential keys | Remove the label. Add a View allowlist (Python `View(instrument_name="*", attribute_keys={...})`; JS `attributesProcessors: [createAllowListAttributesProcessor([...])]`) |
| `exporter.config` | `OTEL_EXPORTER_OTLP_HEADERS`, `..._TRACES_HEADERS`, vendor API keys in `.env*`, compose, k8s manifests, Dockerfiles, Collector `headers:` | Committed credentials | `rg -n --hidden 'OTEL_EXPORTER_OTLP_.*HEADERS'` (any literal value is a leak; `${...}` references are fine), `rg -n --hidden -U 'headers\s*:' -A3` in Collector configs and exporter constructors, plus the credential rows of the value patterns table below run over `.env*`, compose, k8s, Dockerfiles and OTel bootstrap files | Critical | Replace with an env/secret reference and add the secret to the report's rotation list (file and first commit SHA). Rotate it: it's in git history |
| `instrumentation.config` | Instrumentation hooks: JS `requestHook`/`responseHook`/`applyCustomAttributesOnSpan`; Python `server_request_hook`/`client_request_hook`/`client_response_hook`/`request_hook`/`response_hook`; `new UserInteractionInstrumentation(` | Hooks can copy headers, bodies, query strings or element text onto spans. The user-interaction instrumentation records DOM element identity | `rg -n 'requestHook\|responseHook\|applyCustomAttributesOnSpan\|server_request_hook\|client_request_hook\|client_response_hook\|request_hook\|response_hook\|UserInteractionInstrumentation'` | Medium | Read each hook body. Remove anything that sets attributes from request data, headers or element text. Keep hooks that only strip or allowlist |
| `session_replay`, `session_replay.option`, `session_replay.field`, `session_replay.text` | Recorder init, options, form fields, PII-rendering templates | DOM, input, network and console capture | Per-vendor patterns in [session-replay.md](session-replay.md#finding-recorders-with-ripgrep) | Critical: input masking off, credential headers/bodies captured, unmasked card/CVV/CSC/SSN/IBAN/passport fields (or `autocomplete` `cc-number`/`cc-csc`). High: other sensitive fields and text | [session-replay.md](session-replay.md) |

## Browser OTel (web SDK)

| | |
|---|---|
| Keys | `url.full`/`http.url` on fetch/XHR spans; user-interaction span attributes (`event_type`, `target_element`, `target_xpath`); propagated `traceparent`/`baggage` headers |
| How it leaks | Tokens in fetch URLs. `propagateTraceHeaderCorsUrls: /.*/` sends trace context (and baggage, when the registered propagator includes W3C baggage) to third-party origins. `@opentelemetry/instrumentation-user-interaction` records element identity, and custom hooks can add element text |
| Knobs | fetch/XHR: `propagateTraceHeaderCorsUrls` (string/RegExp list), `ignoreUrls`, `applyCustomAttributesOnSpan`, `ignoreNetworkEvents` ([fetch README](https://github.com/open-telemetry/opentelemetry-js/blob/main/experimental/packages/opentelemetry-instrumentation-fetch/README.md), [XHR README](https://github.com/open-telemetry/opentelemetry-js/blob/main/experimental/packages/opentelemetry-instrumentation-xml-http-request/README.md)). user-interaction: `eventNames`, `shouldPreventSpanCreation` |
| Detect | Static only (verification runs use no browser). `rg -n 'propagateTraceHeaderCorsUrls'` (flag `/.*/`, `/.+/` and third-party origins), `rg -n 'applyCustomAttributesOnSpan\|UserInteractionInstrumentation\|shouldPreventSpanCreation'` (read each hook), and tokens in fetch/XHR URLs: `rg -n '(fetch\|\.open)\([^)]*(token\|api_key\|access_token)='` in browser sources |
| Severity | Critical (tokens), High (other) |
| Fix | List only first-party origins in `propagateTraceHeaderCorsUrls`. Strip query strings in `applyCustomAttributesOnSpan` ([fix-js.md](fix-js.md#browser-otel)). Never put user text in interaction attributes |

## Secret and PII value patterns

Run these over source, config and captured telemetry. Every pattern compiles in Python `re` and JavaScript `RegExp` (add `re.IGNORECASE` / the `i` flag where noted), so the same text goes into the redactor rule list. Ripgrep needs `-P` for the patterns with lookaheads. In this table `\|` is an escaped pipe: type a plain `|`.

| Id | Matches | Regex | Notes | Severity |
|---|---|---|---|---|
| `jwt` | JSON Web Token | `\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*` | Confirm the first segment base64url-decodes to JSON with an `alg` field | Critical |
| `aws-access-key-id` | AWS access key ID | `\b(?:AKIA\|ASIA\|ABIA\|ACCA)[A-Z0-9]{16}\b` |  | Critical |
| `github-token` | GitHub token | `\b(?:gh[pousr]_[A-Za-z0-9]{36,255}\|github_pat_[A-Za-z0-9_]{22,255})\b` |  | Critical |
| `slack-token` | Slack token | `\bxox[abposr]-[A-Za-z0-9-]{10,}` |  | Critical |
| `stripe-live-key` | Stripe live secret/restricted key | `\b(?:sk\|rk)_live_[A-Za-z0-9]{24,}\b` |  | Critical |
| `google-api-key` | Google API key | `\bAIza[0-9A-Za-z_-]{35}` |  | Critical |
| `private-key-block` | PEM private key header | `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----` |  | Critical |
| `bearer-token` | `Bearer <token>`; the token must contain a digit or one of `._~+/-`, so prose doesn't match | `\b[Bb]earer[ \t]+(?=[A-Za-z0-9._~+/-]*[0-9._~+/-])[A-Za-z0-9._~+/-]{8,}=*` | Lookahead: `rg -P` | Critical |
| `basic-auth` | `Basic <base64>` | `\b[Bb]asic[ \t]+[A-Za-z0-9+/]{8,}={0,2}` | Confirm the token base64-decodes to printable `user:pass` | Critical |
| `url-userinfo` | `scheme://user:pass@`, `scheme://token@` | `\b[A-Za-z][A-Za-z0-9+.-]*://(?:[^/?#\s:@]+(?::[^/?#\s@]*)?\|:[^/?#\s@]+)@` |  | Critical |
| `url-query-secret` | Secret query parameter | `(?:^\|[?&;])(?:api_key\|apikey\|api-key\|token\|access_token\|sig\|signature\|password\|secret\|client_secret\|code)=[^&#\s]+` | Case-insensitive (`-i`) | Critical |
| `inline-secret-assignment` | `password=...`, `pw: ...`, `{"token":"..."}` in free text; value of 4+ chars | `(?:\b\|_)(?:client_secret\|access_token\|refresh_token\|auth_token\|api[_-]?key\|passphrase\|password\|passwd\|secret\|token\|pwd\|pw)["']?[ \t]*[=:][ \t]*["']?[^\s"'&,;]{4,}` | Case-insensitive (`-i`) | Critical |
| `credit-card` | Card number, 13-19 digits with optional spaces/dashes | `\b(?:\d[ -]?){12,18}\d\b` | Confirm with a Luhn check | High |
| `email` | Email address | `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}` | HMAC when joins are needed, else mask | High |
| `us-ssn` | US SSN | `\b(?!000\|666\|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b` | Lookaheads: `rg -P` | High |
| `phone-e164` | E.164 phone number | `\+[1-9]\d{7,14}\b` | HMAC when joins are needed, else mask | High |
| `ipv4` | IPv4 address | `\b(?:(?:25[0-5]\|2[0-4]\d\|1?\d?\d)\.){3}(?:25[0-5]\|2[0-4]\d\|1?\d?\d)\b` | Quasi-identifier: truncate, don't mask | Medium |
| `ipv6` | IPv6 address, full or compressed | `\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b\|\b(?:[0-9A-Fa-f]{1,4}:){1,6}(?::[0-9A-Fa-f]{1,4}){1,6}\b` | Quasi-identifier: truncate | Medium |

### Credential attribute keys

Mask the whole value of any attribute, header or log field whose key matches this pattern (case-insensitive). The sensitive word must be a whole `.`/`_`/`-` delimited segment, so `gen_ai.usage.input_tokens` and `session.id` don't match:

```text
(?:^|[._-])(?:proxy-authorization|authorization|set-cookie|cookie|x-api-key|api[_-]?key|access_token|refresh_token|id_token|client_secret|token|secret|passw(?:or)?d|session[_-]?id|session[_-]?token|private[_-]?key)(?:$|[._-])
```

Severity: Critical.
