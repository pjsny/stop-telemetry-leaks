---
name: stop-telemetry-leaks
description: Use when a codebase uses OpenTelemetry, browser RUM, or a session replay recorder (Interfere, rrweb, Sentry Replay, Datadog RUM, PostHog, LogRocket, FullStory, Clarity, Hotjar, etc.) and credentials, tokens, cookies, API keys, emails, card numbers, or other PII may reach spans, span events, span names, logs, metrics, baggage, resource attributes, committed OTLP exporter config, or recorded DOM text, inputs, and network payloads.
license: MIT
---

# Stop telemetry leaks

Find credentials and personal data that leave a service through OpenTelemetry or a session replay recorder, and fix them. Checking at runtime with fake values is optional and off unless the user asks for it.

Rules that hold through every step:
- **Static by default.** Findings come from reading code and config. Only call a finding `confirmed` when a fake value showed up in exported telemetry, and never call a repo clean: some attributes are added by instrumentation at runtime and only a verification run sees them.
- **Fix the source first.** An exporter redactor or Collector rule goes on top of a source fix, never instead of one.
- **Credentials get fixed now. Other personal data gets proposed.** Changing how emails or user IDs are recorded can break dashboards and alerts, so show those as diffs and wait for approval.
- **Never print a real secret.** In chat, commits, and the report, show at most the first 4 characters and the length (`Bear…(41 chars)`).
- **Nothing leaves the machine.** Never point a verification run at a real exporter endpoint. Reading vendor docs on the web is fine; sending repo content anywhere is not.

## When not to use

- The repo has no OpenTelemetry, RUM, or session replay.
- The data is already in a backend, or the ask is a git history rewrite. Flag committed secrets for rotation instead.

## Workflow

Make a todo for each step and work through them in order.

### 1. Preflight

- `git status --porcelain` must be empty. If not, ask the user to commit or stash.
- `git switch -c otel-pii/$(date +%F)`. Each fix becomes its own commit.
- Note the stacks (`package.json`, `pyproject.toml`, `requirements*.txt`) and the test runner (pytest, vitest, jest, `node:test`).
- Ask the user once, with these options, and default to the first if they don't choose:
  1. **Static only** (default): read the code and config, fix, and run the repo's own tests. Fastest.
  2. **Mock exporter**: a temporary test swaps the app's exporter for an in-memory one and sends fake values through it, before and after the fixes.
  3. **Mock collector**: run the app the way production does, pointed at a throwaway local Collector, and send fake values over HTTP, before and after the fixes. Needs Docker or an `otelcol-contrib` binary.

### 2. Inventory

Write down, with versions from the lockfiles:
- the OTel bootstrap production uses: the file passed to `node --import`/`--require`, `opentelemetry-instrument` in the entrypoint, or a `setup_telemetry()`-style function;
- exporters and instrumentations, with their options;
- OTel env vars in `.env*`, compose, k8s, and Dockerfiles, plus any Collector config;
- browser RUM SDKs and session replay recorders, including `<script>` snippets.

### 3. Find candidates

Work through [references/surfaces.md](references/surfaces.md). For each surface, run its grep patterns, open every hit, and decide whether the value comes from a secret, user input, an identifier, or nothing sensitive. Also search config files and committed env files with the value patterns in that reference. Keep a findings list: file, line, surface, attribute key, severity, evidence (masked).

### 4. Optional: verify with fake values

Skip this step unless the user picked option 2 or 3. Then follow [references/verifying.md](references/verifying.md):
1. Generate one seed and the fake values.
2. Mock exporter: write a temporary `*otel_pii_canary*` test that builds telemetry the way production does, with an in-memory exporter innermost. Mock collector: start the local Collector and run the app with its exporters pointed at it.
3. Send the fake values through every route and run it before any fix. Mark each finding `confirmed` (fake value seen), and add any leak the run found that step 3 missed.
4. Surfaces no request reached stay `unverified`, with the reason (no route, jest global, hardcoded vendor endpoint).

### 5. Session replay and browser RUM

Replay payloads are checked against config and vendor docs, not at runtime. Label these findings `static-only` in the report.

1. For each recorder, read its section in [references/session-replay.md](references/session-replay.md), then open the vendor's privacy docs **for the installed major version**. Defaults change between majors.
2. Unknown recorder: find its docs and search them for "privacy", "mask", "redact", "sanitize". No input masking at all is Critical.
3. Required end state for every recorder:
   1. all inputs masked by a global option;
   2. text masked globally, or every element that shows personal data carries the vendor's mask attribute or class;
   3. no request or response headers or bodies recorded, or only through an allowlist that excludes auth headers, cookies, and personal data;
   4. console capture off or reviewed;
   5. recorded URLs stripped of tokens.
4. Dashboard-only settings (FullStory, Clarity, Hotjar, and others listed in the reference): ask the user to confirm them. Until then they stay `unverified`.

For the OTel web SDK, check fetch/XHR spans for tokens in URLs and `propagateTraceHeaderCorsUrls` for third-party origins, which receive `baggage`.

### 6. Classify

| Severity | Examples | Action |
|---|---|---|
| Critical | auth, cookie, and API-key headers; tokens in URLs; URL userinfo; connection strings; committed `OTEL_EXPORTER_OTLP_*HEADERS`; secrets in resource attributes; passwords or tokens in log bodies, span events, or exception messages (including whole request bodies); replay input masking off; replay recording auth headers or credential-bearing bodies; unmasked card, CVV, SSN, IBAN, and passport fields | Fix now |
| High | emails, phones, names, card numbers, SSNs, prompts, SQL with literal values, other user input in exception messages, personal data in span names or baggage, replay text unmasked | Propose |
| Medium | user IDs, IPs, other indirect identifiers, personal data as metric labels | Propose |

### 7. Fix

Per finding, in this order: **source fix, then exporter redactor, then Collector config.**

Critical, applied now, one commit per fix (follow the repo's commit conventions):
- Remove credential headers from capture lists (`headersToSpanAttributes`, `OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_*`). In Python, also list them in `OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS`.
- Node `@opentelemetry/instrumentation-http`: set one merged list (built-ins plus app params) on **both** `redactedQueryParams` and `redactedQueryParamsServer`. Each option replaces the built-in list and covers one direction only.
- Python has no setting for custom query params. Use the exporter redactor.
- Stop interpolating passwords, tokens, or whole request bodies into log lines and exception messages.
- Move committed exporter secrets to env references, and add them to the rotation list. They are already in git history.
- Wrap every span and log exporter with a redactor as a second layer: [references/fix-python.md](references/fix-python.md), [references/fix-js.md](references/fix-js.md).
- Session replay: turn on global input masking, and stop recording headers and bodies that carry credentials.

High and Medium, proposed: show each diff with the finding, why it matters, and any dashboards, alerts, or queries in the repo that use the key. Apply only what the user approves. Common fixes: stable IDs or HMAC instead of raw values (never plain SHA-256 or MD5), route templates in span names, parameterized SQL, exception messages without input, no personal data in baggage, metric View allowlists, replay text masking.

If the repo has a Collector config, also propose the `redaction` processor from [references/collector.md](references/collector.md). It does nothing for SDKs that export straight to a vendor.

### 8. Verify

Done when:
- the repo's own tests pass;
- re-running step 3's patterns finds none of the fixed issues;
- if the user chose a verification run in step 1: the same run with the same fake values shows no fake value for any fixed finding.

A fix that breaks tests: revert its commit, mark the finding `proposed`, and continue.

### 9. Report and clean up

Write `otel-pii-report.md` in the repo root. Its first line says whether a verification run happened (static only, mock exporter, or mock collector).
- counts by severity and status (`fixed`, `proposed`, `unverified`, `static-only`, plus `confirmed` when verified);
- rotation list: each committed secret with its file and the commit that added it (`git log --diff-filter=A -- <file>`), never the value;
- one row per finding: severity, surface, key, file:line, fix, and seen before/after when verified;
- unverified surfaces and dashboard-only settings, with reasons;
- per recorder: version, doc URL checked, which end-state items are met;
- for a static-only run, one line offering a verification run.

After a verification run, delete the `*otel_pii_canary*` files, any driver script, and the Collector output, unless the user wants to keep the test as a regression check.

## Red flags

- Deleting an attribute that carries useful data instead of replacing its value.
- Calling the repo clean after a static-only run.
- Plain hashes of identifiers. Low-entropy values are reversible; use HMAC.
- Setting `redactedQueryParams` without the built-ins, or on one side only.
- Treating the Collector as the fix when the SDK exports straight to a vendor.
- Trusting a replay default from memory instead of the docs for the installed version.
- Applying a High or Medium change without approval.
- Pointing a verification run at a real exporter endpoint.

| Thought | Reality |
|---|---|
| "The tests pass, so it's fixed." | Tests rarely look at telemetry. Re-check the code, or run a verification if the user wants proof. |
| "The redactor catches everything." | It can't recognize an opaque secret inside free text. Fix the source. |
| "Password inputs are masked by default." | Only in some recorders and some versions. Check the docs. |
| "jest showed no spans, so nothing leaks." | jest hides app spans. Use a driver script, or report `unverified`. |
