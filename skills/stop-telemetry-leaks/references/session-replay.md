# Session replay and browser RUM privacy

Session replay recorders serialize the DOM (usually rrweb or a fork of it) and often network and console activity too. None of this traffic goes through OTel exporters, so a verification run from [verifying.md](verifying.md) never sees it: every finding here is `static-only`. Find recorders and their options with the ripgrep patterns below, then confirm each option against the vendor facts in this file.

Facts were checked against vendor docs on 2026-11-03. Option names and defaults change between major versions, so confirm each one against the docs for the version the repo has installed (`package.json` / lockfile) before you change config. "not documented" means the vendor docs we read don't state the fact. Find it in the docs for the installed version, or test it; don't assume.

## Required end state

Check each recorder against the docs for its installed version:

1. **All input values are masked** by a global option, not field by field.
2. **Text is masked globally.** The alternative is that every page rendering PII masks those elements with the vendor's mask attribute, class or selector.
3. **Network request/response headers and bodies are not captured.** If they are, capture goes through an allowlist that excludes `Authorization`, cookies, and payloads containing PII.
4. **Console capture is off,** or has been reviewed for PII.
5. **Recorded URLs are sanitized** whenever query strings carry tokens.

Some settings live in the vendor's web app, not in code (FullStory, Clarity, Hotjar, Contentsquare, Dynatrace, Mouseflow, Amplitude console tracking). For those, report the setting as `unverified` with the exact setting name. Never assume a dashboard value.

## Unknown or generic recorders

1. Look for rrweb usage:
   - dependencies `rrweb`, `@rrweb/record`, `@rrweb/all`, `rrweb-snapshot`;
   - imports or `record({ emit` calls;
   - `cdn.rrweb.com` scripts;
   - mask classes such as `rr-mask` and `rr-block`.
2. Look for any other dependency or script tag whose docs mention "session replay" or "session recording". Vendored rrweb forks often keep `maskAllInputs`, `maskTextSelector` and `blockClass`.
3. Find the installed version in the lockfile, `package.json` or the CDN URL.
4. Search the vendor's docs for that version for "privacy", "mask", "redact", "sanitize", "network", "headers", "console". Record each option name, its default and the doc URL in the report.
5. Check the five end-state points above. A recorder with no input-masking support is a **Critical** finding.

## Finding recorders with ripgrep

Search source, HTML templates and lockfiles from the repo root, skipping `node_modules` and build output. First find every recorder (column 2, one `rg -n -i` per vendor). Then, in each file that matched and in any file that builds the config object, run the option patterns:

- **Risky**: each hit is a finding unless the note says otherwise. Header-list options (Sentry `networkRequestHeaders`/`networkResponseHeaders`, Amplitude `requestHeaders`/`responseHeaders`, Highlight `headerKeysToRecord`, Mixpanel `recordHeaders`) are findings only when the list names a credential-like header: Authorization, Proxy-Authorization, Cookie, Set-Cookie, (X-)API-Key, or a name containing token, secret or session. "unless" names a sibling option that removes the risk when it's set in the same config.
- **Required**: missing means the documented default applies, which is unsafe for that vendor (see the next section). If the config is built elsewhere, open that file before reporting it missing.

| Vendor | Find the recorder | Risky | Required |
|---|---|---|---|
| Interfere | `InterfereProvider\|@interfere/(next\|vite)` | No `maskAllInputs` (only passwords masked); no `logs: false` (console captured). `replay:\s*false` means replay is off. Review where `interfere-(mask\|block\|ignore)` is used | `maskAllInputs:\s*true`, `maskTextSelector` |
| rrweb | `from\s*['"](rrweb\|@rrweb/record\|@rrweb/all)['"]\|rrweb\.record\(\|rrwebRecord\s*\(\|cdn\.rrweb\.com/record/` | `maskAllInputs['"]?\s*:\s*false`, `password['"]?\s*:\s*false`, `recordHeaders['"]?\s*:\s*true`, `recordBody['"]?\s*:\s*true`, `getRecordConsolePlugin\(`, `recordCanvas['"]?\s*:\s*true` | `maskAllInputs['"]?\s*:\s*true`, `maskTextSelector` |
| Sentry | `replayIntegration\(\|new\s+Sentry\.Replay\(\|browser\.sentry-cdn\.com/.*replay` | `maskAllInputs\s*:\s*false`, `maskAllText\s*:\s*false`, `networkRequestHeaders`, `networkResponseHeaders` (credential names in the list), `networkDetailAllowUrls` (unless networkCaptureBodies:\s*false), `unmask\s*:\s*\[\s*\S`, `blockAllMedia\s*:\s*false` | - |
| Datadog | `startSessionReplayRecording\(\|sessionReplaySampleRate\|replaySampleRate\|datadoghq-browser-agent\.com/.*datadog-rum` | `defaultPrivacyLevel['"]?\s*:\s*['"](allow\|mask-user-input)['"]`, `data-dd-privacy\s*=\s*['"]?allow`, `dd-privacy-allow`, `enablePrivacyForActionName\s*:\s*false`, `trackResourceHeaders['"]?\s*:\s*(true\|\[)` | `defaultPrivacyLevel['"]?\s*:\s*['"]mask(-unless-allowlisted)?['"]\|DefaultPrivacyLevel\.MASK` |
| PostHog | `session_recording\s*:\|startSessionRecording\(\|posthog\.init\(\|posthog\.com/static/array\.js` | `maskAllInputs\s*:\s*false`, `password['"]?\s*:\s*false`, `recordHeaders\s*:\s*true`, `recordBody\s*:\s*true`, `enable_recording_console_log\s*:\s*true` | `maskTextSelector` |
| LogRocket | `LogRocket\.init\(` | `inputSanitizer\s*:\s*false`, `textSanitizer\s*:\s*false`, `console\s*:\s*\{\s*isEnabled\s*:\s*(true\|\{)`, `data-public` | `inputSanitizer['"]?\s*:\s*(true\|['"])`, `textSanitizer['"]?\s*:\s*(true\|['"])` |
| FullStory | `@fullstory/browser\|FS\(\s*['"]init\|fullstory\.com/s/fs\.js\|_fs_org` | `fs-unmask` | Dashboard setting; report `unverified` |
| Microsoft Clarity | `Clarity\.init\(\|www\.clarity\.ms` | `data-clarity-unmask\s*=\s*['"]?true` | Dashboard setting; report `unverified` |
| Hotjar | `Hotjar\.init\(\|static\.hotjar\.com/c/hotjar-` | `data-hj-allow` | Dashboard setting; report `unverified` |
| OpenReplay | `@openreplay/tracker\|static\.openreplay\.com/.*openreplay\.js` | `defaultInputMode\s*:\s*(0\|\w+\.Plain)`, `obscureInputEmails\s*:\s*false`, `obscureInputNumbers\s*:\s*false`, `obscureTextEmails\s*:\s*false`, `ignoreHeaders\s*:\s*(false\|\[\s*\])`, `capturePayload\s*:\s*true` | `consoleMethods['"]?\s*:\s*(null\|\[\s*\])` |
| Highlight / LaunchDarkly | `H\.init\(\|new\s+SessionReplay\(\|LDRecord\.start\(` | `privacySetting\s*:\s*['"](none\|default)['"]`, `recordHeadersAndBody\s*:\s*true`, `headerKeysToRecord` (credential names), `disableConsoleRecording\s*:\s*false`, `data-hl-record` | `disableConsoleRecording['"]?\s*:\s*true` |
| New Relic | `features/session_replay\|session_replay\s*:\s*\{\|new\s+BrowserAgent\(\|NREUM\.init\|js-agent\.newrelic\.com` | `mask_all_inputs\s*:\s*false`, `mask_text_selector\s*:\s*(null\|''\|"")`, `capture_payloads\s*:\s*['"](all\|failures)['"]`, `nr-unmask` | - |
| Splunk | `SplunkSessionRecorder\.init\(\|splunk-otel-web-session-recorder\.js` | `maskAllInputs\s*:\s*false`, `maskAllText\s*:\s*false`, `rule\s*:\s*['"]unmask['"]` | `maskAllText['"]?\s*:\s*true` |
| Amplitude | `sessionReplayPlugin\(\|sessionReplay\.(init\|plugin)\(\|cdn\.amplitude\.com/libs/(plugin-)?session-replay-browser` | `defaultMaskLevel\s*:\s*['"]light['"]`, `unmaskSelector\s*:\s*\[\s*\S`, `amp-unmask`, `(requestHeaders\|responseHeaders)\s*:\s*true` or credential names, `(requestBody\|responseBody)\s*:\s*\{` | `defaultMaskLevel['"]?\s*:\s*['"]conservative['"]` (dashboard can override) |
| Mixpanel | `record_sessions_percent\|start_session_recording\(` | `record_mask_all_inputs\s*:\s*false`, `record_mask_all_text\s*:\s*false`, `record_unmask_(text\|input)_selector`, `recordHeaders` (credential names), `recordBodyUrls\s*:\s*\{` (both unless record_network:\s*false), `record_console\s*:\s*true` | `record_console['"]?\s*:\s*false` |
| Grafana Faro | `new\s+ReplayInstrumentation\(` | `maskAllInputs\s*:\s*false`, `maskTextSelector\s*:\s*(null\|''\|""\|undefined)`, `sanitizeMetaHref\s*:\s*false`, `captureConsoleDisabledLevels\s*:\s*\[\s*\]` (unless captureConsole:\s*false) | `captureConsole['"]?\s*:\s*false` |
| Dynatrace | `dtrum\.enableSessionReplay\(\|js-cdn\.dynatrace\.com/jstag/` | - | Dashboard setting; report `unverified` |
| Contentsquare | `injectContentsquareScript\(\|t\.contentsquare\.net/uxa/` | `replay:consent:unanonymized:granted`, `data-cs-capture\|setCapturedElementsSelector` | Dashboard setting; report `unverified` |
| Smartlook | `Smartlook\.init\(\|smartlook\(\s*['"]init\|web-sdk\.smartlook\.com/recorder\.js` | `forms\s*:\s*true`, `(emails\|numbers\|ips)\s*:\s*true` in the record call, `data-sl\s*=\s*['"]unmask`, `advancedNetwork\s*:` | - |
| Mouseflow | `cdn\.mouseflow\.com/projects/\|window\._mfq` | - | Dashboard setting; report `unverified` |

Then look for sensitive fields the recorder could capture: `rg -n -i 'autocomplete=["\x27]?(cc-number\|cc-csc\|cc-exp)\|name=["\x27]?(card\|cvv\|cvc\|csc\|ssn\|iban\|passport)'`. Unmasked card, CVV/CSC, SSN, IBAN or passport fields are Critical when inputs aren't masked; other PII fields and PII-rendering templates are High when text isn't masked.

## Unsafe defaults and dashboard-controlled vendors

Some recorders are unsafe even with no risky option set, because the documented default is unsafe. These options must be set where the recorder is configured:

| Vendor | Must set | Why (documented default) |
|---|---|---|
| Interfere | `plugins={{ replay: { maskAllInputs: true, maskTextSelector: '*' } }}` (critical); `logs: false` or a reviewed console (high) | Only password inputs are masked by default; the `logs` plugin captures console output and is on by default |
| rrweb | `maskAllInputs: true` (critical); `maskTextSelector` (high) | Inputs other than passwords are unmasked; no text is masked |
| Datadog | `defaultPrivacyLevel: 'mask'` (high) | v7 (and v4) default `mask-user-input` records text; v5–v6 defaulted to `mask` |
| PostHog | `maskTextSelector` (high) | Inputs are masked by default; text is not |
| LogRocket | `inputSanitizer: true` (critical); `textSanitizer: true` (high) | Both default `false` |
| OpenReplay | `consoleMethods: null` (high) | Console is recorded by default |
| Highlight / LaunchDarkly | `disableConsoleRecording: true` (high) | Console is recorded by default |
| Splunk | `maskAllText: true` (high) | README says the default is `false`; the help site says `true` |
| Amplitude | `defaultMaskLevel: 'conservative'` (high) | Default `medium` records page text |
| Mixpanel | `record_console: false` (high) | `record_console` defaults to `true` |
| Grafana Faro | `captureConsole: false` (medium) | Faro console instrumentation is on by default |

Dashboard-controlled vendors (FullStory, Microsoft Clarity, Hotjar, Amplitude, Dynatrace, Contentsquare, Mouseflow) configure masking only or mainly in their web app. Amplitude's project settings override its SDK. Report them as `unverified`, with the reason "privacy settings live in the vendor dashboard; confirm there", and ask the user to check the settings named in that vendor's section below.

## Interfere

| Fact | Value | Source |
|---|---|---|
| Packages | Next.js: `@interfere/next`, provider from `@interfere/next/provider`, client init `@interfere/next/instrument-client`. Vite + React and TanStack Start: `@interfere/vite`, provider `@interfere/vite/provider`, init `@interfere/vite/init` | [if-config] |
| Enablement | Replay is the `replay` plugin on `InterfereProvider`. All plugins default to enabled, subject to consent. Disable with `plugins={{ replay: false }}` | [if-config] |
| Input masking | Password inputs masked by default. `plugins={{ replay: { maskAllInputs: true } }}` masks all inputs; `maskInputOptions` (for example `{ email: true }`) masks selected input types. The docs say to configure additional masking before recording customer sessions | [if-privacy] |
| Text masking | No global default. `plugins.replay` accepts rrweb options, including `maskTextSelector`, `maskTextFn`, `maskInputFn`, `blockSelector`, `ignoreSelector`, `recordCanvas` | [if-privacy] |
| Per element | `interfere-block` replaces the element with a placeholder of the same size; `interfere-ignore` excludes keystrokes and input changes (the element stays visible); `interfere-mask` masks rendered text in the element and its children, not input values. The classes still apply when rrweb options are set | [if-privacy] |
| Network | Header/body capture: not documented. Telemetry requests don't send cookies | [if-config] |
| Console | The `logs` plugin captures console output and is on by default. Disable with `plugins={{ logs: false }}` | [if-config] |
| URL hook | Not documented | |

Defaults mask only password inputs and no text, and console capture is on. A provider with no `plugins` prop fails end-state points 1, 2 and 4.

```tsx
<InterfereProvider plugins={{ replay: { maskAllInputs: true, maskTextSelector: '*' }, logs: false }}>
```

Add `interfere-block` to payment sections. If the team needs console logs, review what the app logs instead of setting `logs: false`. Masking changes apply to new recordings only, so check a new session replay after changing the config.

[if-config]: https://interfere.com/docs/sdk/configuration.md
[if-privacy]: https://interfere.com/docs/sdk/replay-privacy.md

## rrweb

| Fact | Value | Source |
|---|---|---|
| Packages | `@rrweb/record`, `@rrweb/replay`, `@rrweb/all`; `rrweb` still works | [rrweb-guide] |
| Enablement | `import { record } from '@rrweb/record'; record({ emit(e) {…} })`; CDN `https://cdn.rrweb.com/record/<ver>/dist/record.js`; UMD global `rrwebRecord` | [rrweb-guide] |
| Input masking | `maskAllInputs`, default `false`. `maskInputOptions`, default `{ password: true }`. `maskInputFn` | [rrweb-guide] |
| Text masking | No global default. `maskTextClass` default `'rr-mask'`, `maskTextSelector` default `null`, `maskTextFn` | [rrweb-guide] |
| Per element | `.rr-mask` masks text; `.rr-block` replaces the element with a placeholder (`blockClass`/`blockSelector`); `.rr-ignore` drops input events (`ignoreClass`/`ignoreSelector`) | [rrweb-guide] |
| Network | Opt-in via `getRecordNetworkPlugin` (`@rrweb/rrweb-plugin-network-record`). `recordHeaders: false`, `recordBody: false` by default. No allowlist; filter in `transformRequestFn` | [rrweb-network] |
| Console | Opt-in via `getRecordConsolePlugin` (`@rrweb/rrweb-plugin-console-record`). `level` defaults to all console methods | [rrweb-console] |
| URL hook | No page-URL hook: not documented. Network URLs can be edited in `transformRequestFn` (`request.name`) | [rrweb-network] |

Defaults leave inputs other than passwords and all text **unmasked**. A plain `record({ emit })` call fails end-state points 1 and 2.

```js
record({ emit, maskAllInputs: true, maskTextSelector: '*', blockClass: 'rr-block' });
// no network or console plugins
```

[rrweb-guide]: https://raw.githubusercontent.com/rrweb-io/rrweb/master/guide.md
[rrweb-network]: https://raw.githubusercontent.com/rrweb-io/rrweb/master/docs/recipes/network.md
[rrweb-console]: https://raw.githubusercontent.com/rrweb-io/rrweb/master/docs/recipes/console.md

## Sentry Session Replay

| Fact | Value | Source |
|---|---|---|
| Packages | `@sentry/browser` or a framework SDK (`@sentry/react`, …) | [sentry-replay] |
| Enablement | `Sentry.replayIntegration(` in `integrations`; lazy `Sentry.addIntegration(…replayIntegration())`. `replaysSessionSampleRate` / `replaysOnErrorSampleRate` default `0`. CDN `browser.sentry-cdn.com/<ver>/bundle.replay.min.js` and `bundle.tracing.replay.min.js` | [sentry-replay], [sentry-config] |
| Input masking | `maskAllInputs`, default `true` | [sentry-privacy] |
| Text masking | `maskAllText`, default `true`; `blockAllMedia`, default `true`; `maskFn` | [sentry-privacy] |
| Per element | `mask`: `.sentry-mask`, `[data-sentry-mask]`. `block`: `.sentry-block`, `[data-sentry-block]`. `ignore`: `.sentry-ignore`, `[data-sentry-ignore]`. `unmask`/`unblock` default `[]` (since v8, `.sentry-unmask` and friends only apply when listed) | [sentry-privacy] |
| Network | Only URL, method, status and sizes by default. Details are opt-in via `networkDetailAllowUrls` (default `[]`) and `networkDetailDenyUrls`. `networkCaptureBodies` defaults to `true` for allowlisted URLs. `networkRequestHeaders` / `networkResponseHeaders` default to `[]` | [sentry-config] |
| Console | Recording events include console logs; no replay-specific switch documented. Filter with `beforeAddRecordingEvent` | [sentry-config], [sentry-privacy] |
| URL hook | `beforeAddRecordingEvent` (7.53.0+); `addEventProcessor` on `replay_event` (`event.urls`) | [sentry-privacy] |

```js
Sentry.replayIntegration({ maskAllText: true, maskAllInputs: true, blockAllMedia: true,
  networkDetailAllowUrls: [], networkCaptureBodies: false });
```

[sentry-replay]: https://docs.sentry.io/platforms/javascript/session-replay.md
[sentry-privacy]: https://docs.sentry.io/platforms/javascript/session-replay/privacy.md
[sentry-config]: https://docs.sentry.io/platforms/javascript/session-replay/configuration.md

## Datadog RUM Session Replay

| Fact | Value | Source |
|---|---|---|
| Packages | `@datadog/browser-rum`; CDN `www.datadoghq-browser-agent.com/…/datadog-rum.js`, global `DD_RUM` | [dd-setup] |
| Enablement | From v5: `sessionReplaySampleRate` > 0 records automatically (default `0`). Before v5: `startSessionReplayRecording()` and `replaySampleRate`. `startSessionReplayRecordingManually: true` defers recording | [dd-setup], [dd-upgrade] |
| Input/text masking | `defaultPrivacyLevel`: `'allow'` / `'mask-user-input'` / `'mask'` (3.6.0+); v7 also accepts `'mask-unless-allowlisted'` ([dd-types], [dd-changelog]). Default by major: **v4 `mask-user-input`; v5–v6 `mask`; v7 `mask-user-input`** ([dd-types] `@defaultValue mask-user-input`). The privacy page still says `mask` | [dd-upgrade], [dd-privacy] |
| Always masked | `password`, `email` and `tel` inputs and `autocomplete` card fields | [dd-privacy] |
| Per element | `data-dd-privacy` = `allow`, `mask`, `mask-user-input` or `hidden`; classes `dd-privacy-allow`, `dd-privacy-mask`, `dd-privacy-mask-user-input`, `dd-privacy-hidden`. `enablePrivacyForActionName` masks action names (default `true` in v7) | [dd-privacy], [dd-upgrade] |
| Network | Replay header/body capture: not documented. RUM resource events: `trackResourceHeaders` (v7), default `false`; `true` or a matcher list collects headers; built-in filter drops names containing token/cookie/secret/authorization/api-key/forwarded/real-ip | [dd-types], [dd-changelog] |
| Console | Replay console capture: not documented | - |
| URL hook | `beforeSend(event, context)`; return `false` to drop | [dd-advanced] |

On v7, omitting `defaultPrivacyLevel` means **text is recorded** (`mask-user-input`), which fails end-state point 2.

```js
datadogRum.init({ applicationId, clientToken, site, sessionReplaySampleRate: 20,
  defaultPrivacyLevel: 'mask', enablePrivacyForActionName: true,
  beforeSend: (e) => { if (e.view?.url) e.view.url = e.view.url.split('?')[0]; return true; } });
```

[dd-privacy]: https://docs.datadoghq.com/session_replay/privacy_options.md
[dd-setup]: https://docs.datadoghq.com/session_replay/browser/setup_and_configuration.md
[dd-upgrade]: https://docs.datadoghq.com/real_user_monitoring/guide/browser-sdk-upgrade.md
[dd-advanced]: https://docs.datadoghq.com/real_user_monitoring/browser/advanced_configuration.md
[dd-changelog]: https://raw.githubusercontent.com/DataDog/browser-sdk/main/CHANGELOG.md
[dd-types]: https://unpkg.com/@datadog/browser-rum-core@7.16.2/cjs/domain/configuration/configuration.d.ts

## PostHog Session Replay

| Fact | Value | Source |
|---|---|---|
| Packages | `posthog-js`; snippet loads `<region>-assets.i.posthog.com/static/array.js` | [ph-js] |
| Enablement | Turned on in project settings or the `session_recording` config of `posthog.init`; `posthog.startSessionRecording()`; opt out with `disable_session_recording: true` | [ph-control] |
| Input masking | All inputs masked by default; `maskAllInputs: false` disables. `maskInputOptions` per type; `maskInputFn` | [ph-privacy] |
| Text masking | Not masked by default. `maskTextSelector: '*'` masks all; `maskTextFn` | [ph-privacy] |
| Per element | `ph-no-capture` class blocks the element. `ph-mask` for web: not documented | [ph-privacy] |
| Network | `session_recording.recordHeaders` / `recordBody`, off by default. A local `false` overrides remote. Header deny-list always applied (authorization, cookie, set-cookie, x-api-key, proxy-authorization, x-csrf-token, …) | [ph-network] |
| Console | `enable_recording_console_log: true`; off by default | [ph-console] |
| URL hook | `session_recording.maskCapturedNetworkRequestFn` (also applied to page URL) | [ph-privacy] |

Because replay can be switched on remotely, treat `posthog.init(` as enablement.

```js
posthog.init(KEY, { enable_recording_console_log: false, session_recording: {
  maskAllInputs: true, maskTextSelector: '*', recordHeaders: false, recordBody: false,
  maskCapturedNetworkRequestFn: (r) => { r.name = r.name.split('?')[0]; return r; } } });
```

[ph-privacy]: https://posthog.com/docs/session-replay/privacy.md
[ph-network]: https://posthog.com/docs/session-replay/network-recording.md
[ph-console]: https://posthog.com/docs/session-replay/console-log-recording.md
[ph-control]: https://posthog.com/docs/session-replay/how-to-control-which-sessions-you-record.md
[ph-js]: https://posthog.com/docs/libraries/js.md

## LogRocket

docs.logrocket.com could not be fetched from this environment. The facts below come from the SDK's bundled types ([lr-types]) and from docs.logrocket.com page excerpts. Re-check them on the live docs.

| Fact | Value | Source |
|---|---|---|
| Packages | `logrocket`, `logrocket-react` | [lr-types] |
| Enablement | `LogRocket.init(appID, options)`. CDN snippet host: not documented | [lr-types] |
| Input masking | `dom.inputSanitizer`, default `false`; `true` obfuscates all inputs. Password inputs never recorded | [lr-dom] |
| Text masking | `dom.textSanitizer`, default `false` | [lr-dom] |
| Per element | `data-private` (redact; `="lipsum"` variant); `data-public` allowlists when a sanitizer is on; `dom.redactSelectors`, `dom.hideSelectors` | [lr-dom], [lr-types] |
| Network | `network.isEnabled`; `network.requestSanitizer` / `responseSanitizer` receive headers and body; return `null` to drop. Web default: not documented | [lr-network], [lr-types] |
| Console | `console.isEnabled` (boolean or per level). Default: not documented | [lr-types] |
| URL hook | `browser.urlSanitizer(url)` | [lr-browser] |

Defaults leave inputs and text **unmasked**. An init call without `inputSanitizer: true` fails end-state point 1.

```js
LogRocket.init(APP_ID, { dom: { inputSanitizer: true, textSanitizer: true },
  network: { requestSanitizer: (r) => ({ ...r, headers: {}, body: null }),
             responseSanitizer: (r) => ({ ...r, headers: {}, body: null }) },
  console: { isEnabled: false }, browser: { urlSanitizer: (u) => u.split('?')[0] } });
```

[lr-types]: https://unpkg.com/logrocket@12.4.0/dist/types.d.ts
[lr-dom]: https://docs.logrocket.com/reference/dom
[lr-network]: https://docs.logrocket.com/reference/network
[lr-browser]: https://docs.logrocket.com/reference/browser

## FullStory

| Fact | Value | Source |
|---|---|---|
| Packages | `@fullstory/browser` (`init({ orgId })`; v1 `FullStory.init`) | [fs-readme] |
| Enablement | `init({ orgId })` or snippet `FS('init', …)`; script `edge.fullstory.com/s/fs.js`, global `window['_fs_org']` | [fs-config] |
| Input masking | App setting. Form Privacy (default for accounts from 2021-11-10) masks `input`, `textarea`, `select`, `contenteditable`. Always excluded: `input[type=password]`, `[autocomplete^=cc-]`, `input[type=hidden]` | [fs-privacy] |
| Text masking | App setting **Private by Default** (on request) masks all text; otherwise text is recorded | [fs-pbd], [fs-privacy] |
| Per element | `.fs-exclude` (replaces `.fs-block`), `.fs-mask`, `.fs-unmask`; consent variants `.fs-exclude-without-consent`, `.fs-mask-without-consent`, `.fs-unmask-with-consent` | [fs-privacy] |
| Network | App setting "Network Data Capture". Never captures `authorization`, `cookie`, `proxy-authorization`. Bodies only for allowlisted URLs. Default: not documented | [fs-network] |
| Console | App setting "Console Data Capture", **on by default** | [fs-console] |
| URL hook | App "URL Privacy Rules"; the default rule blocks `password`, `token`, `jwt`, `code` and `#access_token`. Code hook: not documented | [fs-url] |

```js
init({ orgId: 'o-XXXX-na1' });
// App: Private by Default; Network Data Capture off; Console Data Capture off. Markup: class="fs-exclude" on PII.
```

[fs-config]: https://developer.fullstory.com/browser/fullcapture/configure-capture/
[fs-readme]: https://raw.githubusercontent.com/fullstorydev/fullstory-browser-sdk/main/README.md
[fs-privacy]: https://help.fullstory.com/hc/en-us/articles/360020623574
[fs-pbd]: https://help.fullstory.com/hc/en-us/articles/360044349073
[fs-network]: https://help.fullstory.com/hc/en-us/articles/360020828393
[fs-console]: https://help.fullstory.com/hc/en-us/articles/360020828533
[fs-url]: https://help.fullstory.com/hc/en-us/articles/14314063803671

## Microsoft Clarity

| Fact | Value | Source |
|---|---|---|
| Packages | `@microsoft/clarity` (`Clarity.init(projectId)`) | [clarity-npm] |
| Enablement | `Clarity.init(` or the snippet; domain `www.clarity.ms` | [clarity-api], [clarity-csp] |
| Input masking | Inputs and drop-downs always masked, in every mode | [clarity-mask] |
| Text masking | App "Masking mode": Strict (all), **Balanced (default; numbers and emails)**, Relaxed (none) | [clarity-mask] |
| Per element | `data-clarity-mask="true"`, `data-clarity-unmask="true"`. Block/ignore: not documented | [clarity-mask], [clarity-api] |
| Network / Console / URL hook | not documented | - |

```html
<form data-clarity-mask="true">…</form>  <!-- App: Settings > Masking > Strict -->
```

[clarity-mask]: https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-masking
[clarity-api]: https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-api
[clarity-csp]: https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-csp
[clarity-npm]: https://unpkg.com/@microsoft/clarity@1.0.2/README.md

## Hotjar

| Fact | Value | Source |
|---|---|---|
| Packages | `@hotjar/browser` (`Hotjar.init(siteId, 6)`) | [hj-readme] |
| Enablement | `Hotjar.init(` or the snippet from `static.hotjar.com/c/hotjar-` | [hj-readme], [hj-csp] |
| Input masking | All keystrokes suppressed by default. A field is recorded only with `data-hj-allow` **and** the setting "Suppress keystroke data on allowed input fields" unchecked | [hj-allow] |
| Text masking | Site setting "On-page text" suppression, **off by default**; numeric text and emails suppressed by default | [hj-suppress] |
| Per element | `data-hj-suppress` (attribute or class) suppresses; `data-hj-allow` unmasks inputs | [hj-suppress], [hj-allow] |
| Network / Console / URL hook | not documented | - |

```html
<div data-hj-suppress>…PII…</div>  <!-- Site settings: suppress all on-page text; never add data-hj-allow -->
```

[hj-readme]: https://raw.githubusercontent.com/hotjar/hotjar-js/master/README.md
[hj-suppress]: https://help.hotjar.com/hc/en-us/articles/36819956605329-How-to-Suppress-Text-Images-Videos-and-User-Input-from-Collected-Data
[hj-allow]: https://help.hotjar.com/hc/en-us/articles/36820034730641-How-to-Show-Elements-and-Keystrokes-in-Data-Collection
[hj-csp]: https://help.hotjar.com/hc/en-us/articles/36820026388881-Content-Security-Policies

## OpenReplay

| Fact | Value | Source |
|---|---|---|
| Packages | `@openreplay/tracker`; snippet `static.openreplay.com/latest/openreplay.js` | [or-ctor], [or-network] |
| Enablement | `new OpenReplay({ projectKey })` / `new Tracker({ projectKey })` then `tracker.start()` | [or-ctor], [or-sanitize] |
| Input masking | `defaultInputMode`: `0` plain, `1` obscured, `2` ignored. Default: docs conflict (constructor page `2`, sanitize page `1`). `obscureInputEmails` default `true`; `obscureInputNumbers` docs conflict; `obscureInputDates` default `false` | [or-ctor], [or-sanitize] |
| Text masking | No global option. `obscureTextEmails` default `true`, `obscureTextNumbers` default `false` | [or-ctor], [or-sanitize] |
| Per element | `data-openreplay-obscured` (mask), `data-openreplay-hidden` (remove content); `domSanitizer(node)` returns `SanitizeLevel` | [or-sanitize] |
| Network | `network.capturePayload` default `false`; `ignoreHeaders` default `['Cookie','Set-Cookie','Authorization']` (`false` = record all, `true` = none); `network.sanitizer` | [or-network] |
| Console | `consoleMethods`, default `['log','info','warn','error','debug','assert']`; `null` disables | [or-ctor] |
| URL hook | `urls.urlSanitizer`, `resourceNameSanitizer` | [or-ctor] |

```js
new OpenReplay({ projectKey, defaultInputMode: 2, obscureTextEmails: true, obscureTextNumbers: true,
  consoleMethods: null, network: { capturePayload: false, ignoreHeaders: true },
  urls: { urlSanitizer: (u) => u.split('?')[0] } }).start();
```

[or-ctor]: https://docs.openreplay.com/en/sdk/constructor/
[or-sanitize]: https://docs.openreplay.com/en/sdk/sanitize-data/
[or-network]: https://docs.openreplay.com/en/sdk/network-options/

## Highlight.io / LaunchDarkly Session Replay

highlight.io docs now redirect to LaunchDarkly. `highlight.run` is a compatibility alias of `@launchdarkly/o11y` ([hl-readme]).

| Fact | Value | Source |
|---|---|---|
| Packages | `highlight.run`, `@launchdarkly/session-replay`, `@launchdarkly/observability` | [hl-readme], [ld-js] |
| Enablement | `new SessionReplay(` in LaunchDarkly client `plugins`; `LDRecord.start(` with `manualStart`; legacy `H.init(projectId, opts)` (docs page gone). `disableSessionRecording: true` turns replay off | [ld-js], [hl-options] |
| Input/text masking | `privacySetting`: `'strict'` (**default** in the LaunchDarkly plugin; all text and inputs), `'default'` (inputs plus regex-matched PII), `'none'`. Legacy `highlight.run` default: not documented | [ld-replay] |
| Per element | `highlight-mask`, `highlight-block`, `highlight-ignore` classes; `data-hl-record` unmasks under `'default'` | [ld-replay] |
| Network | `networkRecording.enabled` default `true` (URL, size, timing); `recordHeadersAndBody` default `false`; `networkHeadersToRedact`, `headerKeysToRecord`, `bodyKeysToRecord`, `urlBlocklist`; `Authorization`, `Cookie`, `Proxy-Authorization` never recorded by default | [hl-network], [ld-obs] |
| Console | `disableConsoleRecording` default `false` (**console recorded**); `consoleMethodsToRecord` | [hl-options] |
| URL hook | `networkRecording.requestResponseSanitizer`. Page-URL hook: not documented | [hl-network] |

```js
new SessionReplay({ privacySetting: 'strict', disableConsoleRecording: true,
  networkRecording: { enabled: true, recordHeadersAndBody: false } });
```

[ld-replay]: https://launchdarkly.com/docs/sdk/features/session-replay-config.md
[ld-js]: https://launchdarkly.com/docs/sdk/observability/javascript.md
[ld-obs]: https://launchdarkly.com/docs/sdk/features/observability-config-client-side.md
[hl-options]: https://launchdarkly.github.io/observability-sdk/packages/@launchdarkly/observability/types/client_types_types.HighlightOptions.html
[hl-network]: https://launchdarkly.github.io/observability-sdk/packages/@launchdarkly/observability/types/client_types_client.NetworkRecordingOptions.html
[hl-readme]: https://raw.githubusercontent.com/launchdarkly/observability-sdk/main/sdk/highlight-run/README.md

## New Relic Browser Session Replay

| Fact | Value | Source |
|---|---|---|
| Packages | `@newrelic/browser-agent` (`new BrowserAgent({ init, info, loader_config })`; `features/session_replay`); copy-paste snippet sets `window.NREUM.init` | [nr-init], [nr-obfuscate] |
| Enablement | Since agent 1.259.0, on/off and sampling come from the UI; the deployed agent must include the replay feature. `init.session_replay.enabled` default `false` in code | [nr-setup], [nr-init] |
| Input masking | `session_replay.mask_all_inputs`, default `true`; `mask_input_options` per type (password always masked) | [nr-privacy], [nr-init] |
| Text masking | `session_replay.mask_text_selector`, default `'*'`; `''`/`null` leaves only `[data-nr-mask]` | [nr-init] |
| Per element | Mask `nr-mask` / `data-nr-mask`; unmask `nr-unmask` / `data-nr-unmask` (1.256.0+); block `nr-block` / `data-nr-block` (`block_selector`); ignore `nr-ignore` | [nr-privacy], [nr-init] |
| Network | `init.ajax.capture_payloads`: `'none'` (default), `'failures'`, `'all'` (1.317.0+). When on, request/response headers, query and bodies are captured (4096-byte cap) and shown in replay; `ajax.deny_list` | [nr-ajax] |
| Console | In replay: not documented | - |
| URL hook | `init.obfuscate: [{ regex, replacement }]` rewrites all harvested payloads | [nr-obfuscate] |

```js
new BrowserAgent({ info, loader_config, init: {
  session_replay: { enabled: true, mask_all_inputs: true, mask_text_selector: '*' },
  ajax: { capture_payloads: 'none' },
  obfuscate: [{ regex: /([?&](token|code|key)=)[^&]+/g, replacement: '$1REDACTED' }] } });
```

[nr-privacy]: https://docs.newrelic.com/docs/browser/browser-monitoring/browser-pro-features/session-replay/configuration/customize-privacy-settings.md
[nr-setup]: https://docs.newrelic.com/docs/browser/browser-monitoring/browser-pro-features/session-replay/configuration/setup-session-replay.md
[nr-ajax]: https://docs.newrelic.com/docs/browser/new-relic-browser/configuration/configure-ajax-request-events.md
[nr-obfuscate]: https://docs.newrelic.com/docs/browser/new-relic-browser/configuration/obfuscate-browser-agent-data.md
[nr-init]: https://raw.githubusercontent.com/newrelic/newrelic-browser-agent/main/src/common/config/init.js

## Splunk RUM Session Recorder

| Fact | Value | Source |
|---|---|---|
| Packages | `@splunk/otel-web-session-recorder` (needs `@splunk/otel-web`); CDN `…/o11y-gdi-rum/<ver>/splunk-otel-web-session-recorder.js` | [splunk-readme], [splunk-help] |
| Enablement | `SplunkSessionRecorder.init({ realm, rumAccessToken, … })` after `SplunkRum.init(` | [splunk-readme] |
| Input masking | `maskAllInputs`, default `true` | [splunk-readme], [splunk-help] |
| Text masking | `maskAllText`. Default: docs conflict (README `false`, help.splunk.com `true`). Set it explicitly | [splunk-readme], [splunk-help] |
| Per element | `sensitivityRules: [{ rule, selector }]` with `rule` = `'mask'`, `'unmask'` or `'exclude'`, default `[]`; no fixed class/attribute names | [splunk-help] |
| Network / Console / URL hook | Not documented for the recorder | - |

```js
SplunkSessionRecorder.init({ realm, rumAccessToken, maskAllInputs: true, maskAllText: true,
  sensitivityRules: [{ rule: 'exclude', selector: '.payment-form' }] });
```

[splunk-readme]: https://github.com/signalfx/splunk-otel-js-web/blob/main/packages/session-recorder/README.md
[splunk-help]: https://help.splunk.com/en/splunk-observability-cloud/digital-experience-monitoring/real-user-monitoring/replay-user-sessions/record-browser-sessions

## Amplitude Session Replay

| Fact | Value | Source |
|---|---|---|
| Packages | `@amplitude/plugin-session-replay-browser`, `@amplitude/session-replay-browser`, `@amplitude/unified`; CDN `cdn.amplitude.com/libs/(plugin-)session-replay-browser-…` | [amp-plugin], [amp-standalone] |
| Enablement | `amplitude.add(sessionReplayPlugin({ sampleRate }))` or `sessionReplay.init(KEY, {…})`; `sampleRate` default `0` | [amp-plugin], [amp-standalone] |
| Input masking | `privacyConfig.defaultMaskLevel`: `'light'` / **`'medium'` (default; all inputs)** / `'conservative'`. Remote (UI) settings override the SDK. HTML attribute values are not masked | [amp-privacy] |
| Text masking | `'medium'` records page text; `'conservative'` masks all text; `maskSelector` / `unmaskSelector` | [amp-privacy], [amp-standalone] |
| Per element | `.amp-mask`, `.amp-unmask`, `.amp-block`; `[data-amp-mask]`; `privacyConfig.blockSelector` | [amp-standalone], [amp-privacy] |
| Network | Analytics SDK `autocapture.networkTracking` default `false`; per rule `requestHeaders` / `responseHeaders` default `false` (`true` = safe headers, array = named headers); `requestBody` / `responseBody` allowlist rules, none by default | [amp-browser-sdk], [amp-errors] |
| Console | UI setting "Console Tracking" only; SDK option: not documented | [amp-settings] |
| URL hook | `interactionConfig.ugcFilterRules` | [amp-ugc] |

```js
amplitude.add(sessionReplayPlugin({ sampleRate: 0.1, privacyConfig: { defaultMaskLevel: 'conservative' } }));
amplitude.init(KEY, { autocapture: { networkTracking: false } });
```

[amp-plugin]: https://amplitude.com/docs/sdks/session-replay/session-replay-plugin
[amp-standalone]: https://amplitude.com/docs/sdks/session-replay/session-replay-standalone-sdk
[amp-privacy]: https://amplitude.com/docs/session-replay/manage-privacy-settings-for-session-replay
[amp-settings]: https://amplitude.com/docs/session-replay/session-replay-settings
[amp-errors]: https://amplitude.com/docs/session-replay/inspect-replay-errors
[amp-browser-sdk]: https://amplitude.com/docs/sdks/analytics/browser/browser-sdk-2
[amp-ugc]: https://amplitude.com/docs/session-replay/configure-ugc-filter-rules

## Mixpanel Session Replay

| Fact | Value | Source |
|---|---|---|
| Packages | `mixpanel-browser` ≥ 2.50.0 | [mp-sdk], [mp-replay] |
| Enablement | `mixpanel.init(token, { record_sessions_percent: N })` (default `0`); `mixpanel.start_session_recording()` | [mp-replay] |
| Input masking | `record_mask_all_inputs`, default `true`; `record_unmask_input_selector`; passwords always masked | [mp-replay], [mp-privacy] |
| Text masking | `record_mask_all_text`, default `true`; `record_unmask_text_selector`; `record_mask_text_class` defaults to a regex matching `mp-mask`, `fs-mask`, `amp-mask`, `rr-mask`, `ph-mask` | [mp-replay], [mp-privacy] |
| Per element | Mask classes `mp-mask`, `fs-mask`, `amp-mask`, `rr-mask`, `ph-mask`; block classes `mp-block`, `fs-exclude`, `amp-block`, `rr-block`, `ph-no-capture`; `record_block_selector` (default documented as `"img, video"` on one page, `'img, video, audio'` on another) | [mp-replay], [mp-privacy] |
| Network | `record_network` default `false` (2.76.0+); `record_network_options.recordHeaders` and `recordBodyUrls` allowlists, empty by default | [mp-replay] |
| Console | `record_console`, **default `true`** | [mp-replay] |
| URL hook | not documented | - |

```js
mixpanel.init(TOKEN, { record_sessions_percent: 10, record_mask_all_inputs: true,
  record_mask_all_text: true, record_network: false, record_console: false });
```

[mp-replay]: https://docs.mixpanel.com/docs/tracking-methods/sdks/javascript/javascript-replay
[mp-privacy]: https://docs.mixpanel.com/docs/session-replay/session-replay-privacy-controls
[mp-sdk]: https://docs.mixpanel.com/docs/tracking-methods/sdks/javascript

## Grafana Faro Session Replay

Faro **does** record replays, through the public-preview add-on `@grafana/faro-instrumentation-replay` (rrweb-based, Faro Web SDK ≥ 2.8.2) ([faro-how], [faro-replay]).

| Fact | Value | Source |
|---|---|---|
| Packages | `@grafana/faro-instrumentation-replay` with `@grafana/faro-web-sdk` | [faro-replay] |
| Enablement | `new ReplayInstrumentation({…})` in `initializeFaro({ instrumentations })`; `samplingRate` default `1` | [faro-replay] |
| Input masking | `maskAllInputs`, default `true`; `maskInputOptions` default `{ password: true }`; `maskInputFn` | [faro-replay] |
| Text masking | `maskTextSelector`, default `'*'` | [faro-replay] |
| Per element | `grafana-mask`, `grafana-block`, `grafana-ignore`; `blockSelector`, `ignoreSelector` | [faro-replay] |
| Network | Replay does not capture network. Faro fetch/XHR header/body capture options: not documented | [faro-how] |
| Console | Faro console instrumentation **on by default** (`debug`, `trace`, `log` levels off); `captureConsoleDisabledLevels`; disable with `getWebInstrumentations({ captureConsole: false })` | [faro-console] |
| URL hook | `sanitizeMetaHref` default `true`; replay `beforeSend`; core `beforeSend` | [faro-replay], [faro-core] |

```js
new ReplayInstrumentation({ maskAllInputs: true, maskTextSelector: '*', sanitizeMetaHref: true });
```

[faro-replay]: https://github.com/grafana/faro-web-sdk/tree/main/experimental/instrumentation-replay
[faro-how]: https://grafana.com/docs/grafana-cloud/monitor-applications/frontend-observability/session-replay/how-it-works
[faro-console]: https://grafana.com/docs/grafana-cloud/monitor-applications/frontend-observability/instrument/console-instrumentation
[faro-core]: https://github.com/grafana/faro-web-sdk/blob/main/packages/core/README.md

## Dynatrace Session Replay

| Fact | Value | Source |
|---|---|---|
| Packages | Recorder ships with the injected RUM JavaScript (`js-cdn.dynatrace.com/jstag/…`, global `dtrum`); `@dynatrace/rum-javascript-sdk` is an API wrapper | [dt-snippet] |
| Enablement | UI (Enablement and cost control); in opt-in mode `dtrum.enableSessionReplay(` | [dt-classic] |
| Input/text masking | UI "Content masking", separate for recording and playback: Mask all / **Mask user input (default since 1.262; earlier Mask all)** / Allow list / Block list. Mask user input leaves page text unmasked | [dt-masking] |
| Per element | `data-dtrum-mask`; `data-dt-mask` (RUM JS 1.345+). `data-dtrum-allow` only works as a configured allow-list rule | [dt-masking], [dt-strong] |
| Network / Console / URL hook | not documented (UI regex URL exclusion only) | [dt-classic] |

Safe config lives in the UI: set recording masking to Mask all or Allow list, and mark PII elements with `data-dtrum-mask`.

[dt-masking]: https://docs.dynatrace.com/docs/observe/digital-experience/session-replay-latest/configure-session-replay-web/configure-session-replay/url-exclusion-and-masking
[dt-classic]: https://docs.dynatrace.com/docs/observe/digital-experience-classic/session-replay-classic/configure-session-replay-web
[dt-strong]: https://docs.dynatrace.com/docs/observe/digital-experience/session-replay/session-replay-strong-privacy-req
[dt-snippet]: https://docs.dynatrace.com/docs/observe/digital-experience-classic/rum-classic/web-applications/initial-setup/snippet-formats

## Contentsquare Session Replay

| Fact | Value | Source |
|---|---|---|
| Packages | `@contentsquare/tag-sdk` (`injectContentsquareScript(`) | [cs-npm] |
| Enablement | Tag `t.contentsquare.net/uxa/<id>.js`, global `window._uxa`; replay is an account feature; `_uxa.push(['excludeURLforReplay', …])` | [cs-web], [cs-pii] |
| Input masking | Always on: `input`, `textarea`, `select`, `contenteditable` values never collected (select option text is; add `data-cs-mask`) | [cs-pii] |
| Text masking | Project "Data masking": Full / Partial / No masking. Default for new projects: not documented | [cs-pii] |
| Per element | `data-cs-mask`, `setPIISelectors`; unmask `data-cs-capture`, `setCapturedElementsSelector`; `data-cs-encrypt`; `data-cs-hide-title` | [cs-pii] |
| Network | API error details (headers, bodies) only when configured for the project; query strings stripped; `networkRequest:maskUrls` | [cs-pii] |
| Console | not documented | - |
| URL hook | `setPath`, `setQuery`, `referrer:maskUrl`, `networkRequest:maskUrls` | [cs-pii] |

```js
window._uxa = window._uxa || [];
window._uxa.push(['setPIISelectors', { PIISelectors: ['.pii'] }]);  // project Data masking: Full masking
```

[cs-pii]: https://docs.contentsquare.com/en/web/personal-data-handling/index.md
[cs-web]: https://docs.contentsquare.com/en/web/index.md
[cs-npm]: https://registry.npmjs.org/@contentsquare/tag-sdk

## Smartlook

| Fact | Value | Source |
|---|---|---|
| Packages | `smartlook-client` (`Smartlook.init(key, opts)`) | [sl-client] |
| Enablement | `Smartlook.init(` or snippet `smartlook('init', KEY)` loading `web-sdk.smartlook.com/recorder.js` | [sl-start], [sl-client] |
| Input masking | `smartlook('record', { forms })`; forms **not recorded by default**; passwords never | [sl-consent], [sl-record] |
| Text masking | Page text recorded; `emails`, `numbers`, `ips` not recorded by default | [sl-consent], [sl-record] |
| Per element | `data-sl="mask"`, `data-sl="unmask"`, `data-sl="exclude"` | [sl-privacy] |
| Network | `advancedNetwork` (needs DevTools in project settings): bodies only for `allowedUrls`; a default "safe" header list is recorded and **includes `Cookie`**; `allowedHeaders` adds more | [sl-network] |
| Console | not documented | - |
| URL hook | `interceptors.url`, `interceptors.network` | [sl-interceptors] |

```js
Smartlook.init(KEY, { interceptors: { url: (d) => { d.url = d.url.split('?')[0]; } } });  // no advancedNetwork, no record({ forms: true })
```

[sl-start]: https://web.developer.smartlook.com/docs/getting-started.md
[sl-consent]: https://web.developer.smartlook.com/docs/consent-and-sensitive-data.md
[sl-record]: https://web.developer.smartlook.com/reference/smartlookrecord.md
[sl-privacy]: https://web.developer.smartlook.com/docs/privacy-api.md
[sl-network]: https://web.developer.smartlook.com/docs/advanced-network-recording.md
[sl-interceptors]: https://web.developer.smartlook.com/docs/interceptors.md
[sl-client]: https://github.com/smartlook/smartlook-client

## Mouseflow

| Fact | Value | Source |
|---|---|---|
| Packages | None official for the recorder (snippet only) | [mf-install] |
| Enablement | `window._mfq` command queue plus `cdn.mouseflow.com/projects/<id>.js` | [mf-install] |
| Input masking | Keystrokes not recorded by default; fields with emails, cards or names cannot be whitelisted | [mf-privacy], [mf-vpt] |
| Text masking | No global option documented; mask per element | [mf-privacy] |
| Per element | `mf-masked` (+ `mf-listen`), `mf-excluded`, `data-mf-replace="…"`, `data-mf-replace-inner="…"` | [mf-code] |
| Network / Console / URL hook | not documented | - |

```html
<span class="mf-masked mf-listen">Welcome back, Jane</span> <p data-mf-replace="**REMOVED**">…</p>
```

[mf-code]: https://help.mouseflow.com/en/articles/4368378-excluding-masking-and-replacing-content-via-code
[mf-privacy]: https://help.mouseflow.com/en/articles/9055379-mouseflow-and-the-privacy-of-the-website-visitors
[mf-vpt]: https://help.mouseflow.com/en/articles/4263776-excluding-masking-and-whitelisting-content-with-the-visual-privacy-tool
[mf-install]: https://help.mouseflow.com/en/articles/4264201-installation-guide
