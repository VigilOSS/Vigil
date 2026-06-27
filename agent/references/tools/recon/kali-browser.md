---
description: Headless chromium (selenium) render of one URL inside the runtime — the trustworthy-signal recovery for a curl/httpx run the WAF-challenge detector flagged (status=waf_challenge). Returns origin HTTP status + final rendered DOM + a screenshot.
skill: web-recon
---

# kali browser

**Purpose:** Drive a real headless Chromium (selenium) inside the runtime container to
render one URL, execute its JavaScript, and return the **origin HTTP status + the final
rendered DOM + a screenshot**. This is the recovery path when a plain HTTP probe
(`curl`/`httpx`/`nuclei`/...) comes back with a **WAF / bot-challenge interstitial** rather
than the real origin response.

For live engagement targets, run it via `vigil assess kali browser` (typed verb,
audit-flag-aware — it reaches the target, so it is recorded like every other kali probe).

**Where it lives:** the verb runs `python3 -c <selenium-driver>` as the **system** python3
inside `runtime-full`, driving the apt-installed `chromium` + `chromium-driver`. The
`selenium` package is installed into the system interpreter (see
`agent/docker/runtime-full/Dockerfile`).

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

The driver is reliability-hardened: `--no-sandbox`, `--disable-dev-shm-usage`, explicit
waits, a bounded page-load timeout, and a best-effort JSON result (DOM/screenshot still
captured) rather than a crash when one capture step fails. It prints one JSON object on
stdout: `http_status`, `final_url`, `title`, `dom_length`, the `screenshot`/`dom_path`
paths, plus any per-step `*_warning`.

## Invocation

```bash
# Re-render a login surface that a curl/httpx probe flagged status=waf_challenge.
vigil assess kali browser https://app.target.example/login \
  --technique RECON --intent "headless render of WAF-flagged login surface" \
  --probe-kind baseline --phase recon --timeout 120

# Wait for a specific element (SPA) before capturing, with a custom screenshot path.
vigil assess kali browser https://app.target.example/dashboard \
  --wait-selector '#root' --page-timeout 45 \
  --screenshot scans/browser/dashboard.png \
  --technique RECON --intent "render SPA dashboard after JS settles" \
  --probe-kind baseline --phase consume-test --timeout 180
```

Read-only navigation — leave `--destructive` off unless the URL itself is state-changing.

## Cross-reference

- WAF/bot-challenge detector + the `waf_challenge` status that routes here: `agent/scripts/assess/lib/kali_output.py` (`detect_waf_challenge`).
- Why a challenge body must never be read as a target verdict (sibling of the http=000 false-negative guard): `agent/references/tools/recon/curl.md`.
- Web probing skill: `agent/skills/web-recon/SKILL.md`.
