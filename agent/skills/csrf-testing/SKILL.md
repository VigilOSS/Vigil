---
name: csrf-testing
description: Test for cross-site request forgery in state-changing operations
origin: Vigil
vuln_class: csrf
---

# CSRF Testing (Cross-Site Request Forgery)

## When to Activate

- State-changing operations authenticated by cookies, especially legacy apps, admin panels and
  internal tools, services setting `SameSite=None` (embedded widgets, payment and SSO
  integrations), and OAuth/SSO flows.

`--technique CSRF`; probes via `vigil assess kali exec --technique CSRF …`
(`agent/references/payloads/csrf-payloads.md` "Useful Curl for Testing" has token-removal,
method-switch and Referer templates; "Auto-Submit Forms", "Form-Based JSON (Content-Type Trick)",
"Token Bypass Techniques" and "Referer Header Bypass" carry the PoC shapes). PoC pages are host-side
artefacts, verified in a browser session of an owned victim identity (`vigil assess kali browser`).

## Where CSRF still works

Chromium defaults cookies without a `SameSite` attribute to `Lax`; Firefox and Safari do not, so
classic cross-site POST CSRF remains live for non-Chromium victims when cookies carry no explicit
attribute. Check each session cookie's `Set-Cookie`:

- **`SameSite=None`:** classic CSRF in full.
- **GET state changes:** `Lax` sends cookies on top-level GET navigations (links, `window.open`,
  GET forms), not on subresources such as `<img>`.
- **Lax+POST window:** Chromium sends a defaulted-`Lax` cookie on cross-site top-level POSTs for
  two minutes after the cookie is created. If the attacker page can make the target mint a fresh
  session cookie (a login or SSO round-trip opened top-level), a POST form submitted inside the
  window carries it. Outside the window `Lax` withholds the cookie.
- **Same-site attacker origin:** `SameSite` stops cross-site, not cross-origin. A controlled
  subdomain (takeover, user content, XSS on a sibling) sends `Lax` and `Strict` cookies, and a
  token cookie scoped to the parent domain can be overwritten from there.
- **Token reads through CORS:** a reflected `Origin` with `Access-Control-Allow-Credentials: true`
  lets the attacker read the token and submit it (`agent/skills/cors-testing/SKILL.md`);
  `ACAO: *` carries no cookies and does not.
- **JSON bodies:** if the endpoint parses JSON sent as `text/plain` (same response after changing
  the Content-Type), a `text/plain` form delivers it without a preflight. Endpoints that require
  `application/json` or a custom header are protected by the preflight unless CORS allows the
  header for an attacker origin.
- **WebSockets:** cross-site WebSocket hijacking is owned by `agent/skills/websocket-testing/SKILL.md`.

Bearer-token (`Authorization` header) auth is not CSRF-able: browsers do not attach it
cross-origin.

## Is the defence real?

Framework defaults (Rails `protect_from_forgery`, Django `CsrfViewMiddleware`, Spring Security,
ASP.NET `[AutoValidateAntiforgeryToken]`) hold unless a controller opts out
(`skip_before_action :verify_authenticity_token`, `@csrf_exempt`, `csrf().disable()`, per-action
`[ValidateAntiForgeryToken]` gaps). Then test: token removed or blank, a token from another
session (not bound), method switch (POST validates, GET does not), a double-submit cookie you can
set independently (subdomain-scoped cookie, CRLF), and Referer/Origin checks that use
`startsWith`/`endsWith` (`attackertarget.example`, `https://target.example.evil.example`) or
accept a missing Referer.

## Targets and proof

Highest value: password change without the current password, email change, API key creation, 2FA
disable, admin actions (users, roles), financial actions, login CSRF (victim logged into the
attacker's account), OAuth account linking. Chains: CSRF + self-XSS → stored XSS; CSRF + CORS
token read; subdomain control + CSRF. Proof is the PoC page changing state for an owned victim
identity in a real browser (`agent/rules/hunting.md` §2). A missing token with a compensating
control (SameSite, preflight) is not a finding (`agent/references/finding-fp-and-severity-gate.md`).

## What to Record

Standard finding fields (`agent/references/runtime-guides/web-finding-recording.md`) plus which
protection was missing or bypassable (no token, cookie `SameSite` value, broken validation), the
browser and cookie attributes the PoC depends on, and the state change observed.

## Kill and escalate

- `SameSite=Strict` everywhere and no same-site attacker origin; or a custom header or validated,
  session-bound token on every state change → move on with the negative recorded
  (`agent/rules/hunting.md` §13).
- A working PoC on one endpoint → check the other high-value actions
  (`agent/rules/hunting.md` §6).
- Escalate when a removed, blank or foreign token is accepted, a state change answers GET, or a
  JSON endpoint accepts `text/plain`.
