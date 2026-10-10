---
name: gf-patterns:auth
description: Authentication-entry path and credential-key patterns (login, MFA, SAML assertion endpoints)
origin: local overlay (gf upstream only had interestingparams at weight 15)
bucket: auth
skill: auth-bypass
weight: 40
---

# gf: auth

## What this bucket classifies

Authentication entry points and credential-bearing parameters: login pages, MFA/OTP flows,
SAML assertion consumer services, and sign-out routes. These are the primary surfaces for
credential-stuffing, brute-force, MFA-bypass, and session-fixation attacks.

## Load this reference when

- Authenticated routes are in scope and login/MFA surfaces appear in the corpus
- Producer type is `auth_entry`, `form`, or `portal_session` (type-floors fire at 40/30/35)
- Operator is mapping account-takeover surfaces before a credential-based test

## Parameter keys that match

`username, password, mfa_code, otp, totp`

`email` and `token` are intentionally excluded: `email` is too generic (profile updates, subscriptions),
and `token` is owned by `interestingparams` and `jwt`. Both would generate substantial noise.

## Path patterns that match

Login/session initiation:
`/login`, `/signin`, `/sign-in`, `/signon`, `/sign-on`

Session termination (logout — useful for CSRF and post-logout redirect chains):
`/logout`, `/sign-out`

MFA / step-up authentication:
`/mfa`, `/2fa`, `/totp`, `/otp`

Authentication service endpoints:
`/authenticate`, `/auth/login`, `/auth/signin`

Verification (COMPOUND forms only — bare `/verify` is excluded; captcha and email-verify
endpoints would generate substantial noise):
`/auth/verify`, `/email/verify`

SAML assertion surfaces (auth keeps these; `/saml/acs` and `/saml/sso` are
compound-auth forms, not generic SSO routing — see SSO disambiguation below):
`/saml/acs`, `/saml/sso`

## Weight and priority interpretation

- Baseline priority score: 40
- Type floors: `auth_entry` → 40; `portal_session` → 35; `form` → 30 (via `_TYPE_FLOOR`)
- Terminal reasons that suppress this bucket: `inert_type`

## SSO-route disambiguation

When an SSO PATH fragment fires (e.g. `/sso/login`) and no auth PARAM key is present and
the path contains no `/saml/acs`|`/saml/sso` compound, `_suppress_auth_on_sso_route` removes
the `auth` entry from matches so the row clusters as `gf:sso` not `gf:auth`. Auth keeps
winning when: (a) a SAML-auth compound fires (`/saml/acs`, `/saml/sso`), or (b) an auth
param key fires (e.g. `SAMLResponse` on a `/login` landing page).

## Example URLs that match

Path-fragment matches:

- `https://target.example/login` — credential entry point
- `https://target.example/efi/signin` — custom-prefix sign-in surface
- `https://target.example/api/auth/sessions/ttl` — session lifetime API
- `https://target.example/mfa` — MFA challenge surface
- `https://target.example/saml/acs` — SAML assertion consumer (kept in auth)

Param-key matches:

- `https://target.example/submit?username=admin&password=x` — credential POST
- `https://target.example/verify?otp=123456` — OTP submission

## What it does NOT classify

- OAuth/OIDC authorize/token endpoints — those belong in `oauth-oidc` (weight 35) and
  `trust_surface` (weight 35); auth does not duplicate those path fragments
- SSO routing pages (bare `/sso/login`) — routed to `sso` bucket by the
  SSO-route disambiguation rule above
- Session tokens in parameters — those belong in `interestingparams`
- Password-reset/recovery flows — `/reset`, `/recover` are in `trust_surface`

## Corpus grounding

Authentication entry points repeatedly fell through at priority 0 across unrelated estates,
including `/efi/*` account lifecycle, Spring Security login, PIV login, and portal-session routes.
The dedicated bucket gives that security-critical surface a stable home without widening generic
email or token parameters. See `docs/research/classify-surface/README.md` for the public
evidence summary.

## Sources

- [OWASP Testing Guide — Authentication Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/)
- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — `interestingparams` is the closest upstream analog (weight 15, param-key only)

## Related

- `agent/references/gf-patterns/sso.md` — overlaps on SAML surfaces; SSO routing disambiguation
- `agent/references/gf-patterns/oauth-oidc.md` — OAuth/OIDC token and authorize endpoints
- `agent/references/gf-patterns/jwt.md` — bearer-token surfaces that follow authentication
- `agent/references/gf-patterns/interestingparams.md` — credential token params at weight 15
