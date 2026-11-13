---
name: auth-bypass
description: Test for authentication and authorization flaws including credential attacks, session issues, and access control bypasses
origin: Vigil
vuln_class: auth-bypass, session, bfla
---

# Authentication & Authorization Bypass

## When to Activate

- Login/register/reset/MFA flows, protected resources, admin panels, API-key or session auth,
  role-based access.
- An auth gate (login wall, SSO redirect, WAF challenge, API-key guard) fronts the surface: the
  operator's "Perimeter / Auth-Gate Bypass" step (`agent/phases/phase-2-collect.md`) runs the
  gate sweep below before anyone probes through the gate.

All probes run through `vigil assess kali exec --technique AUTH --intent "<purpose>" --probe-kind
<baseline|payload|exploit> --phase consume-test --timeout <N> -- curl …` (or a typed verb).
Switch to `--technique JWT` for token attacks. Record trusted routing headers as probes with
`vigil assess record-probe --input-slot header:<name>` (`agent/rules/hunting.md` §10).

## Routing

Standard authentication and session technique applies and is not repeated here: default/weak
credentials, password-reset flaws (token predictability/reuse/binding, Host-header poisoning of
the reset link, parameter pollution of the email), session fixation/entropy/invalidation/cookie
scope, MFA bypass families (direct post-auth navigation, response flipping, code reuse, an
unenforced alternate path, disable without re-auth). Credential and code brute force are in
scope unless the VDP forbids them (`agent/rules/hunting.md` §10); where it does, test the
lockout/rate control itself (`agent/skills/rate-limit-bypass/SKILL.md`). Username enumeration:
`agent/skills/user-enumeration/SKILL.md`.

Hand off the specialist classes: object IDs → `idor-testing` (and `split-brain-idor`); JWTs →
`jwt-testing`; OAuth/OIDC → `oauth-oidc-testing`; SAML → `saml-sso-testing`; privileged fields on
register/profile → `mass-assignment`; client-supplied identity params → `bff-parameter-override`.
Function-level authz (BFLA) checklist: `agent/references/api-security/API05-broken-function-authz.md`;
session/token lifecycle: `API02-broken-authentication.md`.

**Forced browsing:** a `302` to login whose **body** still carries the protected content (request
without following redirects) is a bypass.

## Attack the gate itself

0. **Identify the gate product** (WAF, reverse proxy, API gateway, IdP) from `server`, `via`,
   cookies, `cf-ray`, vendor headers and the login redirect, then pull its published bypass
   inventory (`agent/references/web/`, `agent/references/access-control/`, CVE and researcher
   writeups) before manual work; a product brief narrows the surface considerably.
1. **Static-extension exemption.** Gates often exempt `.js .css .png .ico .json .woff .svg .html
   .txt .xml`. Append or substitute one on a protected path. It is a bypass only when the body is
   the protected resource, not a static asset.
2. **Parser divergence.** The gate and backend parse URLs differently: case, trailing slash,
   dot-segments, `//`, encoded whitespace/slashes, `;.js` suffix, and `..;/` on Tomcat/Spring
   backends. Variants: `/PROTECTED`, `/protected/`, `/./protected`, `/protected/.`, `//protected`,
   `/protected%20`, `/protected%09`, `/protected;.js`, `/protected..;/`, `/protected%2f`,
   `/%2fprotected`, `/protected%2e%2e`, `/../protected`; more `..;/` and encoding forms in
   `agent/references/payloads/directory-traversal-payloads.md`.
3. **Routing-header injection.** Proxies trust upstream headers that rewrite path, host or
   client IP (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host`/`-For`, `X-Real-IP`,
   `CF-Connecting-IP`, and the less common `X-Custom-IP-Authorization` and `X-ProxyUser-Ip`
   that some 403 gates trust). Probe the ones plausible for the architecture; the per-edge
   client-IP set is in `agent/references/payloads/rate-limit-bypass-payloads.md`.
4. **Verb tampering** and method-override headers (API05 "HTTP Method-Based").
5. **Desync lead.** When a proxy fronts a backend with different CL/TE parsing, fingerprint once
   per host:

   ```bash
   vigil assess kali nuclei -u https://TARGET -t http/misconfiguration/http-desync/ \
     -severity medium,high,critical -o /engagements/$ENGAGEMENT_KEY/scans/desync_nuclei.jsonl \
     --technique REQUEST-SMUGGLING --intent "CL.TE / TE.CL desync fingerprint" \
     --probe-kind payload --phase consume-test --timeout 600
   ```

   A candidate goes to `agent/skills/request-smuggling/SKILL.md` for hand-built confirmation.

## Fail-open auth

The high-yield class: the client sees 401/403 but the protected side effect (write, email, state
change, queued job) still fires, typically because the handler sends the error without returning.
Black-box detection is the side effect, never the status:

1. Send a state-changing request with no auth, an invalid/expired/malformed token, or an empty
   (not missing) `Authorization` header, carrying a unique marker.
2. Read the resource back with valid auth, and check activity/audit logs; a logged action
   usually executed.
3. Also try: a slow or timing-out auth backend (does the timeout grant access?), a failing rate
   limiter (unlimited instead of blocked), async/webhook endpoints (the auth failure is logged
   but the queued action runs), an invalid session cookie that mints a new authenticated session,
   and a removed CSRF token.

## What to Record

Endpoint, parameter and technique; control request, bypassed request and proof of the
privileged result. Prove the attacker outcome with one minimal sample (`agent/rules/hunting.md`
§2 and §10): the forged token reached the admin user list, the forced browse loaded the admin
panel controls, one other user's profile was read. Severity follows
`agent/references/finding-fp-and-severity-gate.md`; an existence oracle alone is a downgrade or
informational, not Medium. Format: `agent/references/runtime-guides/web-finding-recording.md`.
