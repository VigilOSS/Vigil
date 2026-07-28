---
description: How to actually drive a browser for testing — headed stealth Playwright Chromium as the primary tool, the two capture modes (A through-proxy auto-capture, B direct + cookie-dump when the proxy trips bot defense), stealth hardening that beats Akamai Bot Manager, login-flow automation (multi-selector fields, two-step username→password, akredirect interstitial detection, OTP/email step-up, screenshot-every-step), and context.cookies() → Netscape jar for curl_chrome116 replay. Tool-choice rationale vs curl-impersonate / headless-chromium / Selenium. Verified 2026-06-22 against Akamai-fronted bank.acme.example.
skill: browser-automation
---

# Browser Automation — headed stealth Playwright + session extraction

This is the "how to drive a browser to *get past a defended login and hold a
session*" reference. It is the mechanics behind `browser-automation/SKILL.md`.
For the *should I use a browser at all* decision (evidence correctness, soft
404s, browser-enforced security semantics), read
`agent/references/runtime-guides/browser-semantic-evidence.md` first — this file
assumes you already decided the answer is yes.

## Tool choice — why headed Playwright Chromium is primary

| Tool | What it is | Use when | Why not primary |
|---|---|---|---|
| **Headed Playwright + real Chromium + stealth** | Full browser runtime, scriptable, deterministic JSON/screenshot/HAR output | **Default** for defended logins, JS-first SPAs, session capture, anything where a real browser fingerprint + DOM execution is the point | — (this is the recommendation) |
| `curl_chrome116` (curl-impersonate) | curl with a Chrome TLS/JA3 fingerprint and header order | **Headless API replay once you already hold a session** (cookie jar / bearer); JA3-shaped 403 on a pure HTTP probe | No JS, no DOM, no challenge-token solving — cannot *pass* an Akamai/Cloudflare interactive challenge, only replay a session that already cleared one |
| Headless Chromium (Playwright/Katana `-headless`/Puppeteer) | Browser with no UI | Broad JS-aware crawling where bot defense is weak/absent | **Headless is detectable** — Akamai Bot Manager fingerprints headless and blocks at the login step even with the right TLS (see below) |
| Selenium | Older WebDriver automation | Legacy harnesses that already use it | WebDriver leaks `navigator.webdriver`, slower to harden, weaker structured output for LLM consumption than Playwright |

**The load-bearing finding (verified 2026-06-22, Akamai-fronted bank.acme.example):**
a headless or MITM-proxied automated browser hit Akamai Bot Manager at the login
step — `"We are unable to complete your request / our system is currently
unavailable"`. A **HEADED** Chromium on a **residential IP** with stealth
hardening passed the same challenge and reached the authenticated dashboard.
Headed + stealth + residential beats both headless and curl for bot-defended
sites. `curl_chrome116` gets the TLS fingerprint right but cannot solve the
interactive `_abck` challenge — it is the *replay* complement, not the *login*
tool.

## Install

The host has node. Install Playwright + the Chromium build once per machine:

```bash
cd "$ENGAGEMENT_DIR"      # or any working dir with a package.json
npm i playwright
npx playwright install chromium
```

`curl_chrome116` (curl-impersonate) ships in the Kali runtime image; on the host
install via the curl-impersonate release or `brew install curl-impersonate` if
you want to run the replay leg outside the runtime.

## The two capture modes

Bot defense and the MITM proxy interact badly. Pick the mode by whether the
proxy trips the edge.

### Mode A — through-proxy (auto-capture into the engagement)

Route the headed browser through `vigil mitmproxy` so the proxy addon
auto-detects the login and POSTs the captured credentials to the backend store,
and posts request observations that the backend derives into the work buffer
(`assessment_work_items`, ADR 0013) server-side. This is the clean path *when
the edge tolerates the proxy* — you get engagement-pipeline capture for free.

```bash
vigil mitmproxy start
# launch the Playwright script with PROXY=http://127.0.0.1:8080 (see skeleton)
```

Trust the mitmproxy CA in the browser context (the script accepts a CA path; or
use `ignoreHTTPSErrors` for a throwaway capture). Capture workflow and CA
install: `agent/references/tools/proxy/mitmproxy.md`.

### Mode B — direct + cookie-dump (when the proxy trips bot defense)

**The MITM proxy in the TLS path can itself trip Akamai.** Routing the automated
browser through mitmproxy produced the same `"system currently unavailable"`
block on bank.acme.example — the extra TLS hop / cert / timing was enough to fail the
challenge. Going **DIRECT** on the residential IP and dumping
`context.cookies()` *after* login worked.

In Mode B you give up the proxy auto-capture and instead extract the session
yourself:

1. Launch headed Chromium **without** a proxy (direct egress, residential IP).
2. Drive the login (see login-flow section).
3. After reaching the authenticated state, call `context.cookies()` and write a
   Netscape cookie jar.
4. Hand the jar to `curl_chrome116` for downstream API replay, or import the
   cookies into the engagement.

Decision rule: **try Mode A first; the moment the proxied browser hits a
bot-manager "system unavailable" page that the direct browser does not, switch
to Mode B.** Record which mode you used — Mode B sessions are captured outside
the mitmproxy pipeline, so note the jar path and how it was extracted.

## Stealth hardening (what makes headed Chromium pass)

Plain Playwright Chromium still leaks automation signals. Apply all of these —
they were jointly necessary, not optional, to clear Akamai Bot Manager:

**Launch flags / context:**
- `--disable-blink-features=AutomationControlled` (removes the primary
  `navigator.webdriver` tell at the CDP level).
- Realistic `userAgent` matching the actual Chromium major version.
- `locale` + `timezoneId` consistent with the residential IP's geo (e.g.
  `en-US` / `America/Chicago`).
- A real `viewport` (e.g. 1280×800), `deviceScaleFactor`, `hasTouch:false`.
- `headless: false` — **headed is the point**; do not "optimize" to headless.

**`addInitScript` patches (run before any page script):**
- `navigator.webdriver` → `false` (delete the property descriptor).
- `navigator.languages` → `['en-US','en']`.
- `navigator.plugins` / `navigator.mimeTypes` → non-empty realistic arrays.
- `window.chrome` → a populated object (`{ runtime: {} }` at minimum).
- `navigator.permissions.query` → return `{ state: Notification.permission }`
  for `notifications` instead of the headless default that throws/leaks.
- Spoof `WebGL` `UNMASKED_VENDOR/RENDERER` to a common GPU string if the target
  fingerprints canvas/WebGL.

All of these are in the skeleton script below. Do **not** reach for anti-detect
browser products, CAPTCHA solvers, or paid stealth plugins — the program
authorization covers *you logging in as yourself with valid creds through a real
browser*, not defeating proof-of-human gates. If you hit a CAPTCHA / device
binding / proof-of-human prompt, stop and ask the operator.

## Login-flow automation

Robust login automation against an enterprise IdP-fronted SPA:

- **Multi-selector field finding.** Username/password inputs vary
  (`input[name=...]`, `input[type=email]`, `#username`, aria-label). Try a list
  of selectors and use the first that is visible+editable; do not hard-code one.
- **Two-step username→password flows.** Many IdPs (ForgeRock, Okta, Azure AD)
  show username first, submit, *then* render the password field on a new view.
  Submit username, wait for the password field to appear (`waitForSelector`),
  then fill password. A single-page fill fails silently on these.
- **Detect interstitials / akredirect bounces.** Akamai inserts an `akredirect`
  / `akamai`-edge interstitial between OAuth hops that *looks like* a bounce back
  to `/Logon` ("session expired") but is a transient edge gate — let the browser
  follow it (it does so automatically; just `waitForURL`/`waitForLoadState`
  rather than asserting failure on the intermediate URL). The same trap bit the
  curl replay flow — see `oauth-spa-session-replay.md` §A.
- **Detect the bot-manager block explicitly.** After submit, check the page for
  the unavailable-system text and bail with a clear "BOT-MANAGER BLOCK — switch
  to Mode B / residential IP" message rather than timing out on a missing
  dashboard selector.
- **Screenshot every step.** Capture a screenshot before username, after
  username submit, after password submit, and on the final state. When a login
  silently fails the screenshot tells you *which* step (challenge page? wrong
  selector? OTP?) far faster than logs.
- **Handle email/OTP step-up.** If a one-time-code field appears, pause for the
  operator to supply the code (read from an `OTP` env var set just-in-time, or an
  interactive prompt) — never hard-code or auto-bypass. Re-screenshot after.

## Session extraction → Netscape cookie jar for curl_chrome116

After login, dump cookies and build a host-scoped Netscape jar that
`curl_chrome116 -b jar` reads. This is the bridge from "browser holds a session"
to "headless curl-impersonate replays the API with the right JA3":

```js
// inside the Playwright script, after reaching the authenticated state
const cookies = await context.cookies();
const lines = ['# Netscape HTTP Cookie File'];
for (const c of cookies) {
  const domain = c.domain.startsWith('.') ? c.domain : '.' + c.domain;
  const flag = 'TRUE';
  const path = c.path || '/';
  const secure = c.secure ? 'TRUE' : 'FALSE';
  const expiry = Math.floor(c.expires && c.expires > 0 ? c.expires : Date.now()/1000 + 3600);
  lines.push([domain, flag, path, secure, expiry, c.name, c.value].join('\t'));
}
fs.writeFileSync(process.env.JAR || 'cookies.txt', lines.join('\n') + '\n');
```

Then on the replay side (no JS needed, JA3 preserved):

```bash
curl_chrome116 -sS -b cookies.txt \
  -H "X-CSRF-Token: <MemberGlobalSession value from the jar>" \
  -H "Accept: application/json" \
  "https://api.target/v1/..."
```

The full silent-PKCE self-mint that *refreshes* a short-lived access_token from
these cookies (so you are not chained to a 3–10 min token) is
`agent/references/web/oauth-spa-session-replay.md`. That reference is the
downstream complement: this file gets you the cookies; that one turns them into
fresh API tokens on demand.

## Working script skeleton

A parameterized, copy-pasteable login + cookie-dump script lives at
`agent/scripts/browser/playwright-login.js`. Creds and target come from env
(`TARGET_URL`, `USERNAME`, `PASSWORD`, optional `PROXY`, `OTP`, `JAR`,
`SHOTS_DIR`, `REQUIRED_HEADERS`) — **no hardcoded secrets**. For engagements
created with a program attribution header (`--program`/`--header`), export
`REQUIRED_HEADERS` as a JSON object so it rides on every browser request (the
proxy only observes traffic, it does not inject these):
`REQUIRED_HEADERS="$(jq -c .required_headers "$ENGAGEMENT_DIR/scope.json")"`. It implements headed stealth, both
capture modes (set `PROXY` for Mode A, leave it unset for Mode B), multi-selector
two-step login, akredirect/bot-block detection, screenshot-every-step, and the
Netscape jar dump. Run it:

```bash
cd "$ENGAGEMENT_DIR"
npm i playwright && npx playwright install chromium     # first time
TARGET_URL="https://www.target.example/login" \
USERNAME="$U" PASSWORD="$P" \
JAR="$ENGAGEMENT_DIR/sessions/target.cookies.txt" \
SHOTS_DIR="$ENGAGEMENT_DIR/scans/login-shots" \
node agent/scripts/browser/playwright-login.js
# Mode A: prepend PROXY="http://127.0.0.1:8080" after `vigil mitmproxy start`
```

## Authorization + stop conditions

This is target-facing, authenticated work. Follow the engagement boundary in
`agent/shared-constraints.md` §1. Stop and ask the operator when:

- a CAPTCHA / proof-of-human / device-binding / policy-acceptance prompt appears
  that the engagement authorization does not cover;
- both Mode A and Mode B hit a hard bot-manager block (the residential IP itself
  may be flagged — cross to `agent/references/runtime-guides/cdn-ip-blocking.md`);
- the login requires an OTP/MFA factor you do not hold;
- the flow would mutate account state (transfers, profile changes) beyond
  read-only session establishment.

## Cross-references

- `agent/skills/browser-automation/SKILL.md` — the skill this reference backs.
- `agent/references/runtime-guides/browser-semantic-evidence.md` — the
  *should I use a browser* decision tree and evidence contract (read first).
- `agent/skills/browser-semantic-analysis/SKILL.md` — browser-semantic evidence
  skill (soft 404s, browser-originated APIs, headless/headed deltas).
- `agent/references/web/oauth-spa-session-replay.md` — downstream: silent-PKCE
  self-mint + cross-issuer X-CSRF envelope to refresh API tokens from the cookies
  this flow captures.
- `agent/references/tools/proxy/mitmproxy.md` — Mode A capture pipeline, CA trust.
- `agent/references/tools/recon/curl.md` — `curl_chrome116` baseline + JA3 replay.
- `agent/references/runtime-guides/cdn-edge-behavior.md` — Bot-Manager UA blocks,
  the Akamai worked example, 403 disambiguation.
- `agent/references/runtime-guides/cdn-ip-blocking.md` — when the egress IP (not
  the fingerprint) is the block; browser-based tool is mitigation option 3.
- `agent/scripts/browser/playwright-login.js` — the runnable skeleton.
