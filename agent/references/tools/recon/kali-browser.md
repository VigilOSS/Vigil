---
description: Audited Playwright/system-Chromium browser workflows with scope-routed attribution, typed steps, and bounded application evidence.
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
- `--wait-selector '<css>'` — explicit-wait for a specific element before capture (bounded by `--page-timeout`).
- `--wait-state attached|visible|hidden|detached` — the state `--wait-selector` waits for
  (default `attached`). Use `visible` when the element is rendered empty first, `hidden` to
  wait a spinner out.
- `--wait-until domcontentloaded|load|networkidle` — completion event for the initial
  navigation (default `domcontentloaded`). `networkidle` is the one to reach for when the
  evidence only exists after late XHRs land.
- `--page-timeout <s>` — per-page load + explicit-wait timeout in seconds (default `30`).
  `--wait-selector` gets its own `--page-timeout` budget on top of the load.
- `--settle <s>` — extra settle wait (default `2`), applied **after** the load *and* after any
  `--wait-selector` resolves — the two compose, so "wait for `#root`, then settle 5s" is
  `--wait-selector '#root' --settle 5`. Pass `--settle 0` to skip it.
- `--attribution-scope scope|all` — which requests carry the program's mandated attribution
  headers. `scope` (default) sends them to every host `scope.json` admits (wildcards and
  `out_of_scope` carve-outs included, via the same matcher every other scope surface uses) and
  to nothing else, so in-scope sibling hosts stay deconflicted and third-party
  analytics/CDN/vendor origins never see the program handle. `all` is the explicit escape
  hatch: it attributes every origin the page touches and prints a loud stderr line naming the
  leak. Origins left unattributed are listed in `omitted_attribution_origins`.
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

Attribution routing is installed before the first navigation. Scope decides **only** which
requests carry the attribution headers — it never aborts, blocks or filters a navigation or a
request, and the specialist still owns the engagement boundary in `agent/shared-constraints.md`
§1. An engagement with no mandated header runs unattributed without complaint; the single
fail-closed case is a program that **does** mandate a header while `scope.json` declares no
usable `hosts` entry — that run is refused before navigation rather than sending unattributed
in-scope traffic (declare the hosts, or pass `--attribution-scope all`).

The near-miss to watch for: scope is a **predicate, never a gate**, so a run against a host `scope.json` `hosts` does not declare still executes — and under `scope` routing it navigates that host with **no** attribution header. Recon-discovered siblings live in `discovered_hosts`, which does not count. The verb WARNs on stderr naming every such host (the initial URL plus every declared `navigate` step) before launching; declare the host in `hosts`, or pass `--attribution-scope all`, before treating the run as deconflicted traffic.

`--timeout` (the wrapper's wall-clock kill) should exceed the in-container budget
`--page-timeout` + `--page-timeout` again when `--wait-selector` is set + `--settle`. When it
does not, the verb **WARNs on stderr before launch** with both numbers named and still runs —
that budget is a **ceiling, not a cost** (a page that renders in 3s finishes well inside a 45s
`--page-timeout`), so the tight pairing usually completes. Heed the warning on a slow surface:
the DOM and screenshot are written at the end and the HAR flushes at context close, so a
wrapper kill mid-run yields **zero** artifacts and is indistinguishable from a clean negative.
Raise `--timeout` above the named budget rather than trimming the page waits.

Identity headers follow the hosts the run was explicitly told to visit — the initial URL and
every `navigate` step — so a multi-step workflow keeps its session across a declared hop;
cookies follow Chromium's own domain/path scoping. Failed typed steps still write owned
screenshot/DOM artifacts and return non-zero rather than being mistaken for completed coverage.

## Invocation

```bash
# Re-render a login surface that a curl/httpx probe flagged status=waf_challenge.
vigil assess kali browser https://app.target.example/login \
  --technique RECON --intent "headless render of WAF-flagged login surface" \
  --probe-kind baseline --phase recon --timeout 120

# Wait for an SPA element to become visible, then let late XHR-driven DOM mutations settle.
vigil assess kali browser https://app.target.example/dashboard \
  --wait-selector '#root' --wait-state visible --page-timeout 45 --settle 5 \
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
  {"action": "wait", "selector": "#results", "state": "visible", "timeout_ms": 10000},
  {"action": "assert", "selector": "#results", "contains": "invoice"}
]
```

Set `--destructive` whenever the URL or any workflow step can change target state.

## Cross-reference

- WAF/bot-challenge detector + the `waf_challenge` status that routes here: `agent/scripts/assess/lib/kali_output.py` (`detect_waf_challenge`).
- Why a challenge body must never be read as a target verdict (sibling of the http=000 false-negative guard): `agent/references/tools/recon/curl.md`.
- Web probing skill: `agent/skills/web-recon/SKILL.md`.
