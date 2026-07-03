---
name: browser-semantic-analysis
description: Use when browser execution semantics matter: bot/edge interstitial ambiguity, JS-heavy SPAs, universal 200 soft errors, browser-originated APIs, DOM/client-side security behavior, or headless-vs-headed deltas
origin: Vigil
---

# Browser Semantic Analysis

Use this skill when curl/httpx/non-headless crawling may not be observing the
same application state a real browser sees. The purpose is evidence correctness:
separate app behavior from edge policy, soft errors, client-side routing, and
browser-enforced security semantics.

## When to Activate

Load this skill when any of these triggers appears:

- CDN/WAF/bot-management ambiguity: interstitials, generic access-denied pages,
  JA3/JA4-shaped failures, or browser-vs-curl response deltas.
- JavaScript-first app: SPA shell HTML, client-side route tables, hydration-only
  API calls, or routes hidden behind clicks/scroll/viewport changes.
- Suspicious universal `200`: unrelated paths return identical body size, title,
  or content hash.
- Client-side redirects/navigation: fragments, History API, `window.location`,
  meta refresh, router guards, or dynamically constructed links.
- Browser-originated APIs: `fetch`, XHR, WebSocket, SSE, GraphQL clients,
  service workers, or background workers.
- Browser-enforced security outcome: CORS, CSP, SameSite/Secure/HttpOnly
  cookies, MIME sniffing, mixed content, iframe/clickjacking, DOM XSS,
  postMessage, storage APIs, or preview/download rendering.
- Headless and headed browser behavior disagree in a way that changes coverage.

Do not load this skill just because a browser exists. API-only work, raw
protocol checks, and high-volume fuzzing stay with the normal tools unless a
browser-enforced outcome is the point of the test.

## Load First

- `agent/references/runtime-guides/browser-semantic-evidence.md` — trigger
  matrix, tool-selection guidance, headed-browser escalation, and evidence
  contract.
- `agent/references/tools/recon/katana.md` — when the browser-semantic path uses
  Katana headless for broad JS-aware crawling.
- `agent/references/runtime-guides/cdn-ip-blocking.md` — when the trigger is
  edge/CDN egress or JA3/JA4 ambiguity.
- `agent/references/tools/proxy/mitmproxy.md` — only when a headed browser or
  proxy-backed capture is needed.

## Procedure

### 1. Name the trigger

Before running browser-mode tooling, write the trigger in the dispatch notes or
handoff draft:

- `edge_interstitial`
- `js_spa_routes`
- `universal_200_soft_error`
- `client_side_redirect`
- `browser_originated_api`
- `browser_enforced_security`
- `headed_required`

If none fits, continue with the normal non-browser skill.

### 2. Preserve the non-browser baseline

Fetch or create the baseline command-run rows before browser mode:

- httpx or curl response with status, title, server, content length, and body
  hash when possible.
- Random-path baseline for soft-error suspicion.
- Prior Katana/gau/source-analysis artifact ids when this is a crawl delta.

The browser result is only useful as a delta against this baseline.

### 3. Pick the lightest browser path

Use the smallest tool that answers the trigger:

1. **Katana headless** for broad JS-aware crawling and endpoint discovery.
2. **Playwright/system Chromium** for precise request/DOM/console/screenshot
   evidence when an audited runner or operator-approved one-off script exists.
3. **Headed browser plus mitmproxy** when visual/manual state, headless-vs-headed
   deltas, browser-extension traffic labeling, or proxy history is the actual
   evidence source.

Current repo reality: `vigil assess kali katana` exposes `-headless`; a clean
first-class Playwright runner is not yet a stable CLI contract. Do not report a
Playwright observation unless you actually ran one through `vigil assess kali`.

### 4. Run browser-mode collection conservatively

For Katana:

```bash
vigil assess kali katana \
  -u https://TARGET -d 3 -headless \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_headless_TARGET.txt \
  --technique DISCOVERY --intent "browser-semantic crawl: <trigger>" \
  --probe-kind fingerprint --phase <recon|collect|consume-test> --timeout 1800
```

For a headed browser, ask the operator to start or confirm mitmproxy, then keep
navigation scoped to `scope.json` hosts. Do not continue through CAPTCHA,
proof-of-human, policy-acceptance, or device-binding prompts unless the operator
confirms that the engagement authorization covers it.

### 5. Reduce to structured evidence

Return bounded facts, not a transcript dump:

- trigger and baseline command-run ids;
- browser command-run ids and artifact paths;
- final URL, title, visible-text sample, and screenshot path if captured;
- same-site requests grouped by type: document, script, fetch/XHR, WebSocket,
  SSE, GraphQL, form/action, download/preview;
- status, content type, content length, and body hash for material responses;
- newly discovered routes and parameters to ingest;
- soft-error random-path comparison when relevant;
- console/security-policy errors when relevant;
- out-of-scope third-party loads omitted or summarized by domain only.

### 6. Route follow-up

- New requestable endpoints: ingest with `vigil assess ingest-endpoints "$DB"
  browser-semantic` or include them in a curated candidate JSONL for
  `ingest-candidates`.
- Browser-enforced vulnerability lead: dispatch `vulnerability-analyst` with the
  matching vuln-class skill and this skill as secondary context.
- Edge or bot-management block: surface an operator decision with the exact
  baseline/browser delta and do not improvise bypasses.
- Headed-only success: record the coverage gap and ask the operator whether
  headed-browser collection is authorized for the engagement.

## Stop Conditions

Stop and report a coverage gap when:

- the browser reaches only a CAPTCHA/proof-of-human/challenge page;
- headless and headed behavior diverge but no headed-browser run is authorized;
- a service worker/cache state may be hiding server behavior and you cannot
  reset it safely;
- the browser would need to interact with out-of-scope third-party systems;
- the action path may mutate server state and the dispatch did not authorize it.

## Output Checklist

- [ ] Trigger named.
- [ ] Non-browser baseline command-run id(s) cited.
- [ ] Browser-mode command-run id(s) and artifacts cited, or the missing runner
      recorded as a coverage gap.
- [ ] Delta summarized in bounded JSON/prose.
- [ ] Newly discovered same-site routes ingested or handed off for ingestion.
- [ ] CAPTCHA/challenge/out-of-scope/state-mutation blockers surfaced instead
      of bypassed.
