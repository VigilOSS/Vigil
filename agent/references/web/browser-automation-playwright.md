---
description: How to drive a browser for testing — headed stealth Playwright Chromium, proxy and direct cookie-dump capture modes, bot-defense handling, login-flow automation, screenshots, and context.cookies() to Netscape-jar replay. Examples use fictional targets.
skill: browser-automation
---

# Browser Automation — headed stealth Playwright + session extraction

The mechanics behind `agent/skills/browser-automation/SKILL.md`, which owns the procedure (install,
the audited `vigil assess host-exec` run, replay through `vigil assess kali exec`, stop conditions).
Whether to use a browser at all is `agent/references/runtime-guides/browser-semantic-evidence.md`.
The runnable script is `agent/scripts/browser/playwright-login.js`; it implements everything below.

## Tool choice — why headed Playwright Chromium is primary

| Tool | What it is | Use when | Why not primary |
|---|---|---|---|
| **Headed Playwright + real Chromium + stealth** | Full browser runtime, scriptable, deterministic JSON/screenshot/HAR output | **Default** for defended logins, JS-first SPAs, session capture, anything where a real browser fingerprint + DOM execution is the point | — (this is the recommendation) |
| `curl_chrome116` (curl-impersonate) | curl with a Chrome TLS/JA3 fingerprint and header order | **Headless API replay once you already hold a session** (cookie jar / bearer); JA3-shaped 403 on a pure HTTP probe | No JS, no DOM, no challenge-token solving — cannot *pass* an Akamai/Cloudflare interactive challenge, only replay a session that already cleared one |
| Headless Chromium (Playwright/Katana `-headless`/Puppeteer) | Browser with no UI | Broad JS-aware crawling where bot defense is weak/absent | **Headless is detectable** — Akamai Bot Manager fingerprints headless and blocks at the login step even with the right TLS |
| Selenium | Older WebDriver automation | Legacy harnesses that already use it | WebDriver leaks `navigator.webdriver`, slower to harden, weaker structured output for LLM consumption than Playwright |

**The load-bearing pattern (fictional `www.acme-bank.example`):** a headless or MITM-proxied
automated browser hit Akamai Bot Manager at the login step ("We are unable to complete your request
/ our system is currently unavailable"). A headed Chromium on a residential IP with stealth
hardening passed the same challenge and reached the authenticated dashboard. `curl_chrome116` gets
the TLS fingerprint right but cannot solve the interactive `_abck` challenge; it is the replay
complement, not the login tool. It ships in the Kali runtime image (`brew install
curl-impersonate` to run the replay leg on the host).

## The two capture modes

### Mode A — through-proxy (auto-capture into the engagement)

Route the headed browser through `vigil mitmproxy` (`PROXY=http://127.0.0.1:8080`). The addon
captures the login into the credential store, posts request observations that become work-buffer
rows, and injects the program's attribution headers on in-scope requests. With `PROXY` set the
script turns on `ignoreHTTPSErrors`, so the browser context needs no CA install; system CA trust for
a manual browser and the capture pipeline are `agent/references/tools/proxy/mitmproxy.md`.

### Mode B — direct + cookie-dump (when the proxy trips bot defense)

The MITM proxy in the TLS path can itself trip Akamai: on the fictional target the proxied browser
got the same "system currently unavailable" block, and the extra TLS hop, certificate or timing was
enough to fail the challenge. Going direct on the residential IP and dumping `context.cookies()`
after login worked. Mode B gives up proxy capture and attribution injection: export
`REQUIRED_HEADERS="$(jq -c .required_headers "$ENGAGEMENT_DIR/scope.json")"` so the script attaches
the program headers to every browser request, then import the cookies
(`vigil auth import`) or hand the jar to `curl_chrome116`.

Try Mode A first; switch to Mode B the moment the proxied browser hits a bot-manager block the
direct browser does not. Record the mode, and for Mode B the jar path and how it was extracted,
since that session was captured outside the mitmproxy pipeline.

## Stealth hardening (what makes headed Chromium pass)

These were jointly necessary to clear Akamai Bot Manager, and the script applies all of them:

- Launch and context: `--disable-blink-features=AutomationControlled`, a `userAgent` matching the
  real Chromium major version, `locale` and `timezoneId` consistent with the residential IP's geo,
  a real `viewport` / `deviceScaleFactor` / `hasTouch:false`, and `headless: false`.
- `addInitScript` patches before any page script: `navigator.webdriver` false, `navigator.languages`,
  non-empty `navigator.plugins` / `mimeTypes`, a populated `window.chrome`, a
  `navigator.permissions.query` that returns `Notification.permission` for `notifications`, and a
  WebGL `UNMASKED_VENDOR/RENDERER` spoof when the target fingerprints canvas/WebGL.

Do not reach for anti-detect browser products, CAPTCHA solvers or paid stealth plugins: the
authorization covers logging in as yourself with valid credentials through a real browser, not
defeating proof-of-human gates.

## Login-flow automation

What the script handles against an enterprise IdP-fronted SPA, and what to check when it fails:

- **Two-step username→password flows** (ForgeRock, Okta, Azure AD) render the password field on a
  new view after the username submit; a single-page fill fails silently. The script tries a list of
  selectors and waits for the password field.
- **akredirect bounces.** Akamai inserts an `akredirect` / edge interstitial between OAuth hops that
  looks like a bounce back to `/Logon` ("session expired") but is a transient edge gate. Let the
  browser follow it (`waitForURL` / `waitForLoadState`) rather than asserting failure on the
  intermediate URL. The same trap affects curl replay
  (`agent/references/web/oauth-spa-session-replay.md` "2. Run the silent authorization request").
- **Bot-manager block.** The script matches the unavailable-system text after submit and exits with
  a block message instead of timing out on a missing dashboard selector; that is the Mode B signal.
- **Screenshots every step** (`SHOTS_DIR`) show which step failed (challenge page, selector, OTP).
- **OTP step-up** reads `OTP` set just-in-time by the operator; never hard-code or bypass it.

## Session extraction → Netscape cookie jar for curl_chrome116

The script writes `context.cookies()` to a host-scoped Netscape jar at `JAR`, which
`curl_chrome116 -b` reads; the replay command is the skill's step 4. To refresh a short-lived
access token from those cookies instead of being chained to a 3–10 minute token, use the silent-PKCE
self-mint in `agent/references/web/oauth-spa-session-replay.md`.

Script inputs (all env, no hardcoded secrets): `TARGET_URL`, `USERNAME`, `PASSWORD`, and optional
`PROXY` (Mode A), `OTP`, `JAR`, `SHOTS_DIR`, `REQUIRED_HEADERS`, `UA`, `LOCALE`, `TZ_ID`,
`SUCCESS_SEL`, `HEADLESS=1` (not recommended).

## Cross-references

- `agent/skills/browser-semantic-analysis/SKILL.md` — soft 404s, browser-originated APIs,
  headless/headed deltas.
- `agent/references/tools/recon/curl.md` — `curl_chrome116` baseline and JA3 replay.
- `agent/references/runtime-guides/cdn-edge-behavior.md` — Bot-Manager UA blocks, the Akamai worked
  example, 403 disambiguation.
- `agent/references/runtime-guides/cdn-ip-blocking.md` — when the egress IP, not the fingerprint, is
  the block (both modes blocked).
