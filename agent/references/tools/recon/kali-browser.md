---
description: Audited Playwright/system-Chromium browser workflows with scoped attribution, typed steps, and bounded application evidence.
skill: web-recon
---

# kali browser

**Purpose:** Drive Playwright against system Chromium inside the runtime container to
render a target, execute bounded typed workflows, and return the **origin HTTP status,
final rendered DOM, screenshot, console/network metadata, route candidates, and step
results**. It remains the recovery path when a plain HTTP probe
(`curl`/`httpx`/`nuclei`/...) comes back with a **WAF / bot-challenge interstitial** rather
than the real origin response.

For live engagement targets, run it via `vigil assess kali browser` (typed verb,
audit-flag-aware — it reaches the target, so it is recorded like every other kali probe).

**Where it lives:** the verb runs a JSON execution plan through Playwright 1.61.0 using
the apt-installed system Chromium in `runtime-full`. Selenium and chromedriver are not
part of this path.

## When to reach for it (WAF-challenge recovery)

`kali_exec` runs a WAF/bot-challenge detector on every HTTP-prober run. When a response is
the WAF's challenge page (Cloudflare *"Just a moment"*, Akamai *"Access Denied"*, Imperva
*"Pardon Our Interruption"*, or a generic JS-only challenge shell behind a CDN/edge), the
run surfaces `KaliResult.status='waf_challenge'`. That body is the WAF's, **not** the
origin app's — so its status/content **must not** be read as a target verdict
(404 / patched / gated). The loud stderr line tells you to re-render here.

A headless browser executes the challenge JS, which clears most JS-based bot-challenges, so
the rendered DOM + the captured origin status reflect the **real** application.

## Flags

- `url` (positional, required) — the URL to render.
- `--screenshot <path>` — engagement-relative PNG output (default `scans/browser/<host>-<id>.png`).
- `--dom-out <path>` — engagement-relative rendered-DOM output (default `scans/browser/<host>-<id>.html`).
- `--wait-selector '<css>'` — explicit-wait for a specific element before capture (bounded by `--page-timeout`); omit to fall back to `--settle`.
- `--page-timeout <s>` — per-page load + explicit-wait timeout in seconds (default `30`).
- `--settle <s>` — extra settle wait after load when no `--wait-selector` is given (default `2`).
- `--attribution-scope all|document-origin` — `all` preserves the historical global
  header behavior; `document-origin` applies program attribution to the top-level document's
  navigations and their same-origin requests, preventing cross-origin CORS preflight failures.
- `--steps-file <json>` — up to 50 typed `navigate`, `click`, `fill`, `wait`, `eval`, or
  `assert` steps. Unknown actions/fields, non-HTTP navigation, and excessive timeouts fail
  before the browser starts.
- `--storage-state <path>` — explicit engagement-relative Playwright storage-state JSON.
  Pair it with `--identity <name>`; Vigil resolves that identity and refuses missing, dead, stale,
  or request-disabled material before replaying the state. Credential records never inject storage
  state implicitly, and symlinks cannot escape the engagement root.
- `--har-out <path>` — optional metadata-only HAR.
- `--capture-bodies --body-dir <path> --max-body-bytes <n>` — opt-in bounded capture of
  document/XHR/fetch response bodies.

Required attribution routing is installed before the first navigation when matching metadata is
available. Missing or inapplicable attribution metadata does not refuse the browser run. Scope and
path metadata never abort a navigation; the specialist owns the engagement boundary in
`agent/shared-constraints.md` §1. Failed typed steps still write owned screenshot/DOM artifacts and
return non-zero rather than being mistaken for completed coverage.

## Invocation

```bash
# Re-render a login surface that a curl/httpx probe flagged status=waf_challenge.
vigil assess kali browser https://app.target.example/login \
  --technique RECON --intent "headless render of WAF-flagged login surface" \
  --probe-kind baseline --phase recon --timeout 120

# Wait for a specific element (SPA) before capturing, with a custom screenshot path.
vigil assess kali browser https://app.target.example/dashboard \
  --wait-selector '#root' --page-timeout 45 \
  --attribution-scope document-origin \
  --identity member \
  --storage-state tools/auth/dashboard-state.json \
  --screenshot scans/browser/dashboard.png \
  --technique RECON --intent "render SPA dashboard after JS settles" \
  --probe-kind baseline --phase consume-test --timeout 180
```

Example steps file:

```json
[
  {"action": "fill", "selector": "#search", "value": "invoice"},
  {"action": "click", "selector": "button[type=submit]"},
  {"action": "wait", "selector": "#results", "timeout_ms": 10000},
  {"action": "assert", "selector": "#results", "contains": "invoice"}
]
```

Set `--destructive` whenever the URL or any workflow step can change target state.

## Cross-reference

- WAF/bot-challenge detector + the `waf_challenge` status that routes here: `agent/scripts/assess/lib/kali_output.py` (`detect_waf_challenge`).
- Why a challenge body must never be read as a target verdict (sibling of the http=000 false-negative guard): `agent/references/tools/recon/curl.md`.
- Web probing skill: `agent/skills/web-recon/SKILL.md`.
