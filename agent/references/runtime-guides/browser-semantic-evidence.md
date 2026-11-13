---
description: Browser-mode decision guide for real-browser semantics, headless Chromium/Playwright evidence capture, headed browser + mitmproxy escalation, and cases where browser mode is the wrong tool
skill: browser-semantic-analysis
---

# Browser Semantic Evidence

Browser mode answers one question: does the target behave differently for a real browser runtime
than for curl/httpx or a plain crawler? Use it to correct evidence, not to bypass target defences.
Fast HTTP tooling still maps the breadth. `vigil assess kali browser` owns Playwright execution,
attribution and bounded evidence capture, and this file covers when to use it and what evidence
it has to produce.

## When to use browser mode

Use it when a non-browser probe may be seeing the edge, a fallback page or incomplete client
state rather than the application:

- **Edge or bot-management ambiguity.** An interstitial, a generic access-denied body, a
  TLS/JA3/JA4-shaped discrepancy, or a response that changes for a normal browser. Separate app
  behaviour, CDN policy, egress reputation, challenge pages and fingerprint false negatives. If a
  headed browser reaches the app but headless does not, record the delta and ask the operator
  whether the program authorizes browser-based coverage. Stealth plugins, CAPTCHA solvers,
  anti-detect browsers and unapproved proxy rotation are out of scope.
- **JavaScript-first apps.** A shell HTML page, History API or fragment routes, or API calls that
  appear only after hydration.
- **Universal 200s and soft errors.** Compare the browser's final URL, status, title and DOM with
  a random-path HTTP baseline, including its body hash.
- **Client-side navigation.** `window.location`, meta refresh, router guards, or URLs built on
  click.
- **Browser-originated APIs.** fetch/XHR, WebSocket, SSE, GraphQL clients, gRPC-web and service
  workers. The runner records resource type, method, URL and status. When content type or body
  size/hash matters, add the metadata-only HAR or bounded body capture.
- **Browser-enforced semantics.** CORS and preflight; CSP, Trusted Types, mixed content and MIME
  sniffing; SameSite/Secure/HttpOnly; framing; DOM XSS, postMessage and storage; and
  download/preview handling. Curl can capture the headers but can't prove the browser outcome.
- **UI-state routes.** Routes behind hover, scroll, viewport, mobile emulation, permission
  prompts or gestures. Keep the interaction set small and record it.

## Tool choice

### Default: audited headless Chromium path

For repeatable LLM-driven evidence, prefer an audited headless Chromium path
that emits bounded structured artifacts. Use Katana headless for broad
JS-aware crawling; its full crawl doctrine lives in
`agent/references/tools/recon/katana.md`.

```bash
vigil assess kali katana \
  -u https://target.example -d 3 -headless \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_headless.txt \
  --technique DISCOVERY --intent "browser-semantic crawl for JS-generated routes" \
  --probe-kind fingerprint --phase collect --timeout 600
```

Use `--extra-args` for Katana flags the typed wrapper does not expose, after
checking `vigil assess kali katana --help` and `katana -h` in the runtime. For
example, newer Katana builds expose a system-Chrome option; only pass it when
the installed version supports it.

### Precise observation: typed Playwright runner

`vigil assess kali browser` is the typed Playwright/system-Chromium path for
deterministic, bounded browser evidence. It can capture:

- final URL, HTTP status, title, and DOM length;
- a bounded request/response event list with method, URL, resource type,
  response status, and header names;
- route candidates observed on the page, plus origins where required
  attribution was omitted;
- bounded console and page-error events;
- screenshot, DOM, and optional metadata-only HAR artifacts;
- optional bounded document/XHR/fetch body artifacts.

```bash
vigil assess kali browser https://target.example \
  --wait-selector '#app' \
  --screenshot scans/browser/target.png \
  --dom-out scans/browser/target.html \
  --har-out scans/browser/target.har \
  --technique DISCOVERY --intent "capture SPA routes and browser-only requests" \
  --probe-kind fingerprint --phase collect --timeout 180
```

Use `--steps-file` for at most 50 typed navigate/click/fill/wait/assert/eval
steps. Use `--identity` with an engagement-relative `--storage-state` artifact
for an approved authenticated flow; the command fails rather than silently
running anonymously when the identity cannot be applied. Enable bounded
document/XHR/fetch body capture only when needed with `--capture-bodies`,
`--body-dir`, and `--max-body-bytes`. Check
`vigil assess kali browser --help` before constructing a run.

### Adjacent tools

- `curl_chrome116`, when present, is useful for a browser-like HTTP/TLS/UA
  baseline. It does not execute JavaScript, maintain DOM state, or prove a
  browser-enforced outcome, so treat it as a baseline check rather than browser
  evidence.
- `vigil assess gau js-endpoints` owns static JavaScript route extraction. It
  complements browser mode by finding route strings before runtime execution.
- `jwt_tool` and SAML toolkits belong to `jwt-testing` and `saml-sso-testing`.
  Browser mode may capture tokens or redirects, but protocol manipulation is
  owned by the auth skills.
- `aem-hacker` is conditional AEM tooling. Use it after AEM fingerprints, not as
  a generic browser-semantic path.

### Headed real browser plus mitmproxy

Use a headed browser through mitmproxy when the browser itself is the
measurement instrument, not just a crawler:

- headless and headed browser behavior diverge and the delta affects coverage;
- visual state, layout, rendering, iframe behavior, or user gestures decide the
  security outcome;
- the flow needs manual observation to avoid destructive clicks or confusing
  multi-step state;
- browser extensions or profile/container separation are needed to label
  sessions or traffic sources;
- the target presents a consent page, legal notice, or non-auth challenge where
  a human must decide whether continuing is authorized;
- Burp/ZAP-style proxy history is needed as a durable request corpus.

This is still target-facing work. Start mitmproxy through `vigil mitmproxy`,
follow the engagement boundary in `agent/shared-constraints.md` §1, and register
useful captures or derived artifacts. If a challenge asks for CAPTCHA,
proof-of-human, device binding, or policy acceptance not covered by the
engagement authorization, stop and ask the operator.

## When browser mode is the wrong tool

Don't use it for API-only endpoints that curl already reaches with no browser rule under test, for
raw protocol or service checks, for high-volume fuzzing or template scanning, or for payload
spraying where prefetch, cache or retry behaviour could repeat actions uncontrollably. Avoid it
too where a service worker or cache would mask server behaviour unless the test controls cache
state, for third-party interaction outside `agent/shared-constraints.md` §1, and for CAPTCHA or
anti-bot bypass without explicit program approval.

## Evidence contract

Every browser-mode handoff should include:

- `trigger`: why browser semantics were needed;
- `baseline`: command-run ids for the curl/httpx/non-headless observation;
- `browser_observation`: command-run ids and artifact paths for the browser run;
- `delta`: what changed between non-browser and browser observations;
- `routes`: newly observed same-site routes and API calls;
- `soft_error_baseline`: random-path status/title/body-hash comparison when
  universal 200s or soft 404s are suspected;
- `coverage_gaps`: challenge pages, out-of-scope third-party loads, permissions,
  headless/headed mismatch, or an unavailable browser runtime.

The useful output is the delta. A screenshot alone is not evidence; pair it with
the runner's request/response metadata, relevant baseline or captured-body
hashes, and the typed interaction sequence that caused the browser to reach the
state.
