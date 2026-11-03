# Collector layer

The Collector is the third layer, after source fixes and the SDK redacting exporter. Propose it only when the repo contains a Collector config (`otel-collector*.yaml`, `otelcol*.yaml`, Helm `config:` values, an `opentelemetry-collector` image in compose/k8s). Never offer it instead of a source fix.

**It does nothing for direct-to-vendor export.** When the SDK's `OTEL_EXPORTER_OTLP_ENDPOINT` (or a vendor exporter) points straight at the vendor, the data never passes through the Collector. Check every service's endpoint. Services that skip the Collector need the redactor.

The `redaction` and `transform` processors ship in `otelcol-contrib` (and `otelcol-k8s`), not in the core distribution. Check the image in use.

## `redaction` processor recipe

Source: [redactionprocessor README](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/redactionprocessor/README.md) (stability: beta for traces, alpha for logs/metrics; read 2026-11-03).

```yaml
processors:
  redaction/pii:
    allow_all_keys: true
    blocked_key_patterns:
      - "(?i).*(authorization|cookie|api[-_]?key|token|secret|passw(or)?d|session).*"
    blocked_values:
      - "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"   # JWT
      - "AKIA[0-9A-Z]{16}"                                       # AWS access key ID
      - "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"        # email
      - "\\b(?:\\d[ -]?){13,19}\\b"                              # card-like digit runs
    redact_all_types: true
    hash_function: hmac-sha256
    hmac_key: "${env:OTEL_PII_HMAC_KEY}"
    summary: info

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [redaction/pii, memory_limiter, batch]   # redaction first
      exporters: [otlphttp]
    logs:
      receivers: [otlp]
      processors: [redaction/pii, memory_limiter, batch]
      exporters: [otlphttp]
```

Derive `blocked_values` from the value patterns table in [surfaces.md](surfaces.md#secret-and-pii-value-patterns). Copy the patterns rather than retyping them, and drop or rewrite the ones with lookaheads (`bearer-token`, `us-ssn`). The Collector uses Go RE2: no lookarounds, no backreferences. Keep any `memory_limiter` the config already has right after the receivers if the team insists on it running first. The rule that matters is that no processor that exports, fans out or copies data runs before redaction.

| Option | Meaning | Recipe value |
|---|---|---|
| `allow_all_keys` | `false` (default) deletes every attribute not in `allowed_keys`, and an empty `allowed_keys` deletes all attributes. `true` disables the allowlist, while blocking still applies | `true`. A full allowlist breaks dashboards; propose one only if the team asks |
| `allowed_keys` | Keys kept when `allow_all_keys: false` | unset |
| `ignored_keys`, `ignored_key_patterns` | Pass through with no value checks | `http.route` and any keys the team has confirmed safe |
| `blocked_key_patterns` | Regexes on keys. A match masks/hashes the **whole value** | credential key names (the credential key pattern in [surfaces.md](surfaces.md#credential-attribute-keys)) |
| `blocked_values` | Regexes on values of allowed keys. Only the **matching part** is masked, and patterns apply in list order | value patterns from the surfaces.md table |
| `allowed_values` | Regexes that exempt values. They take precedence over `blocked_values` | unset; a broad one silently disables blocking |
| `redact_all_types` | Checks non-string values through their string form (catches card numbers stored as ints) | `true` |
| `hash_function` | `md5`, `sha1`, `sha3`, `hmac-sha256`, `hmac-sha512`. Default: mask with `masking_string` | `hmac-sha256` |
| `hmac_key` | Key for HMAC functions. Load it from the env, never inline it | `${env:OTEL_PII_HMAC_KEY}` |
| `masking_string` | Mask text, default `****`. Must be unset when `hash_function` is set | unset |
| `summary` | `debug` adds the names of redacted/masked keys (a list of names can itself leak), `info` adds counts only, `silent` adds nothing | `info` |
| `url_sanitizer` | `enabled`, `attributes`, `sanitize_span_name`. Removes variable path segments (UUIDs, timestamps) to cut cardinality. It isn't a token scrubber | optional |

The README documents attribute processing for spans, logs (including map bodies) and metric data points. It doesn't document span names (outside `url_sanitizer`), span event attributes, or string log bodies. Use `transform` for those, or better, fix the source.

The Collector's HMAC output is not the redactor's `hmac:` + 16-hex format. Don't expect hashes from the two layers to join.

## `transform` (OTTL) recipes

Source: [transformprocessor README](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/transformprocessor/README.md), [OTTL functions](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/pkg/ottl/ottlfuncs/README.md). In collector YAML, `$` must be written `$$` (env substitution), so a capture group is `$$1`.

```yaml
processors:
  transform/pii:
    error_mode: ignore
    trace_statements:
      # truncate IPv4: last octet -> 0
      - replace_pattern(span.attributes["client.address"], "^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\.\\d{1,3}$$", "$$1.0")
      # drop a key outright
      - delete_key(span.attributes, "user.email")
      # mask token-bearing query params in URLs and span names
      - replace_pattern(span.attributes["url.full"], "([?&](?:token|access_token|api_key|sig)=)[^&#]*", "$$1REDACTED")
      - replace_pattern(span.attributes["url.query"], "((?:^|&)(?:token|access_token|api_key|sig)=)[^&]*", "$$1REDACTED")
      - replace_pattern(span.name, "([?&](?:token|access_token|api_key)=)[^&#\\s]*", "$$1REDACTED")
    log_statements:
      - replace_pattern(log.body, "(?i)(password|passwd|pwd)=\\S+", "$$1=REDACTED")
      - delete_key(log.attributes, "user.email")
```

Put `transform/pii` right after `redaction/pii` in the same pipelines. Use `context`-qualified paths (`span.`, `log.`, `resource.`). Statements in `trace_statements` can't use `log.*` paths.

### Hashing: SHA256 is not HMAC

OTTL offers `SHA1`, `SHA256`, `SHA512` (e.g. `replace_pattern(..., SHA256, "%s")`) but no HMAC converter. An unkeyed hash of an email, phone number, IP or user ID can be reversed by enumerating candidates. Never propose `SHA256` for PII. Hash in the `redaction` processor with `hash_function: hmac-sha256` and an `hmac_key` from the secret store, or truncate/drop instead.

## Checklist

1. Every service that should go through the Collector exports to it (no direct vendor endpoint).
2. The image is `otelcol-contrib` or a build that includes `redaction`/`transform`.
3. `redaction/pii` comes first in every `traces` and `logs` pipeline, including named ones (`traces/vendor`).
4. `OTEL_PII_HMAC_KEY` reaches the Collector from the secret store, not from a committed file.
5. Collector `exporters.*.headers` hold no literal API keys (use `${env:…}`). Committed ones are `exporter.config` Critical findings and go on the rotation list.
