---
name: browser-automation
description: Use when you need to DRIVE a browser for testing — automate a defended login, hold an authenticated session, or extract cookies for downstream API replay. Headed stealth Playwright Chromium is the primary tool (beats headless and beats curl against Akamai/Cloudflare bot defense). Covers the two capture modes (through-proxy auto-capture vs direct + cookie-dump when the proxy trips the edge), stealth hardening, login-flow automation, and context.cookies() -> Netscape jar for curl_chrome116 replay. NOT for deciding whether a browser is needed (that is browser-semantic-analysis).
origin: Vigil
---

# Browser Automation

Drive a real browser to get past a bot-defended login and hold a session, then
hand that session to faster headless tooling. This skill is the *mechanics*;
the *should I use a browser at all* decision lives in
`agent/skills/browser-semantic-analysis/SKILL.md`. If the question is evidence
correctness (soft 404s, browser-enforced CORS/CSP, headless-vs-headed deltas),
start there. If you already know you need to log in and capture a session, you
are in the right place.

## When to Activate

- You must automate an authenticated login against a bot-defended target
  (Akamai Bot Manager, Cloudflare, PerimeterX) and a plain curl/httpx login
  fails or returns a "system unavailable" block.
- You hold valid creds and need a live session (cookies / bearer) for BOLA,
  authz, or surface-mapping work on the authenticated app or its API.
- A JS-first SPA only reveals its real request surface after an interactive,
  in-browser login.
- You need to extract `context.cookies()` into a cookie jar for
  `curl_chrome116` / API replay.

Do **not** activate just to crawl JS routes with no auth wall — that is Katana
`-headless` (see `browser-semantic-analysis`). Do not activate to defeat a
CAPTCHA / proof-of-human gate — stop and ask the operator.

## Primary tool: headed stealth Playwright Chromium

**Headed real Chromium + stealth beats headless and beats curl for bot-defended
sites** (verified 2026-06-22 against Akamai-fronted bank.acme.example): a headless or
MITM-proxied automated browser hit Akamai Bot Manager at the login step; a
HEADED Chromium on a residential IP with stealth hardening passed and reached the
authenticated dashboard.

| Tool | Role |
|---|---|
| **Headed Playwright + stealth Chromium** | **Primary** — solve the interactive challenge, log in, hold the session |
| `curl_chrome116` (curl-impersonate) | JA3-correct *replay* once you hold the session — cannot solve the login challenge |
| Headless Chromium / Katana `-headless` | Weak/no bot defense, broad JS crawl only — detectable, blocked at defended logins |
| Selenium | Legacy harnesses only — leaks `navigator.webdriver`, weaker structured output |

Full rationale table and the load-bearing finding:
`agent/references/web/browser-automation-playwright.md`.

## Procedure

### 1. Install (first time)

```bash
cd "$ENGAGEMENT_DIR"
npm i playwright && npx playwright install chromium
```

### 2. Pick the capture mode

- **Mode A — through-proxy auto-capture.** `vigil mitmproxy start`,
  then launch the browser with `PROXY=http://127.0.0.1:8080`. The proxy addon
  auto-detects login and POSTs the captured credentials to the backend store /
  records traffic to `cases.db`. Use when the edge tolerates the proxy.
- **Mode B — direct + cookie-dump.** Launch headed Chromium with **no** proxy on
  the residential IP; after login, dump `context.cookies()` to a Netscape jar.
  **The MITM proxy in the TLS path can itself trip Akamai** — switch to Mode B
  the moment the proxied browser hits a "system unavailable" block the direct
  browser does not.

Try Mode A first; fall back to Mode B on a bot-manager block. Record which mode
you used (Mode B captures outside the mitmproxy pipeline).

### 3. Run the login + cookie-dump skeleton

`agent/scripts/browser/playwright-login.js` is parameterized, takes creds from
env (no hardcoded secrets), and implements headed stealth, both modes,
multi-selector two-step login, akredirect/bot-block detection, screenshot-every-
step, and the Netscape jar dump.

```bash
cd "$ENGAGEMENT_DIR"
TARGET_URL="https://www.target.example/login" \
USERNAME="$U" PASSWORD="$P" \
JAR="$ENGAGEMENT_DIR/sessions/target.cookies.txt" \
SHOTS_DIR="$ENGAGEMENT_DIR/scans/login-shots" \
node agent/scripts/browser/playwright-login.js
# Mode A: prepend  PROXY="http://127.0.0.1:8080"  (after vigil mitmproxy start)
# Two-step IdP: the script submits username, waits, then fills password.
# OTP step-up: supply OTP="123456" just-in-time; never hardcode.
```

Stealth hardening (all jointly necessary to clear Akamai): spoof
`navigator.webdriver` / languages / plugins / `window.chrome` / permissions,
realistic UA + locale + timezone, real viewport,
`--disable-blink-features=AutomationControlled`, `headless:false`. The script
applies all of these; details in the reference.

### 4. Replay the session headless

Hand the jar to `curl_chrome116` so the JA3 fingerprint survives the edge:

```bash
curl_chrome116 -sS -b "$JAR" \
  -H "X-CSRF-Token: <MemberGlobalSession value from jar>" \
  -H "Accept: application/json" "https://api.target/v1/..."
```

To *refresh* a short-lived access_token from these cookies on demand (silent-PKCE
self-mint + cross-issuer X-CSRF envelope), follow
`agent/references/web/oauth-spa-session-replay.md`.

## Stop Conditions

- CAPTCHA / proof-of-human / device-binding / policy-acceptance prompt outside
  the engagement authorization — stop, ask the operator.
- Both Mode A and Mode B hit a hard bot-manager block — the egress IP itself may
  be flagged; cross to `agent/references/runtime-guides/cdn-ip-blocking.md`.
- OTP/MFA factor you do not hold.
- The flow would mutate account state beyond read-only session establishment.

## Load First

- `agent/references/web/browser-automation-playwright.md` — install, two modes,
  stealth hardening, login-flow tips, cookie-jar build, tool-choice rationale,
  the runnable script.
- `agent/scripts/browser/playwright-login.js` — the copy-pasteable skeleton.

## Cross-references

- `agent/skills/browser-semantic-analysis/SKILL.md` — decide whether a browser is
  needed at all (the upstream decision skill).
- `agent/references/runtime-guides/browser-semantic-evidence.md` — browser-mode
  decision tree and evidence contract.
- `agent/references/web/oauth-spa-session-replay.md` — turn captured cookies into
  fresh API tokens (silent-PKCE self-mint, X-CSRF envelope).
- `agent/references/tools/proxy/mitmproxy.md` — Mode A capture pipeline + CA trust.
- `agent/references/tools/recon/curl.md` — `curl_chrome116` JA3 replay baseline.
- `agent/references/runtime-guides/cdn-edge-behavior.md` — Bot-Manager UA blocks,
  Akamai worked example, 403 disambiguation.
- `agent/references/runtime-guides/cdn-ip-blocking.md` — egress-IP block vs
  fingerprint block; browser-based tool is mitigation option 3.
