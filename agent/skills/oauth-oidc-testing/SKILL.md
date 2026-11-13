---
name: oauth-oidc-testing
description: Detect and exploit OAuth 2.0 and OpenID Connect security flaws in authentication flows
origin: Vigil
vuln_class: oauth
---

# OAuth 2.0 / OpenID Connect Testing

## When to Activate

- The app authenticates or authorizes through OAuth 2.0 / OIDC: a redirect to an external IdP
  (Google, GitHub, Entra ID, Okta, Auth0, custom) or endpoints such as `/authorize`, `/token`,
  `/callback`, `/.well-known/openid-configuration`.

`--technique OAUTH` for flow attacks (it credits the `oauth` class); `JWT` when attacking the
id_token's signature or claims (`agent/skills/jwt-testing/SKILL.md`). Every target request runs
through `vigil assess kali exec … --intent … --phase consume-test --timeout <N> -- curl …`.

On-demand references (`vigil assess list-references --skill oauth-oidc-testing`):
`agent/references/gf-patterns/oauth-oidc.md` — load when the AS metadata advertises a
`registration_endpoint` (dynamic client registration abuse, PingFederate specifics, client_id
enumeration); `agent/references/web/oauth-spa-session-replay.md` — load when an SPA access token
must be replayed or renewed by silent authorization-code + PKCE (per-host issuer checks, complete
gateway envelopes, a same-batch liveness control).

## Methodology

Start from `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`:
supported flows, `response_type`s, PKCE methods, `registration_endpoint`, `jwks_uri`.

The standard OAuth attack families apply and are not restated: `redirect_uri` allow-list bypass
(path traversal, subdomain, parameter pollution, `@`/fragment tricks, localhost, encoding), missing
or unbound `state` (login CSRF), code replay and cross-client code injection, `redirect_uri` not
re-checked at token exchange, token leakage (Referer, query string, logs), scope escalation
including at refresh, PKCE absent / verifier unchecked / S256→plain downgrade, implicit-flow
fragment theft (forcing `response_type=token`, chained with an open redirect), id_token `aud` and
`nonce` binding.

Less obvious surfaces:

- **Device flow:** the `user_code` is short (6-8 chars). Brute force is in scope unless the VDP
  forbids it (`agent/rules/hunting.md` §10); where it does, test the polling rate limit and code
  expiry.
- **Token exchange (RFC 8693):** weak `subject_token` validation at
  `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` can allow impersonation.

**Capturing a leaked code:** mint an OOB host and submit its `http` URL (or the bypass variant
under test) as `redirect_uri`; poll the same client for the request carrying the code
(`agent/references/offensive-tactics/frp-tunneling.md` "OOB Procedure (mint→poll→correlate)").
Testing uses your own authorized session, so a captured code is your own: the finding needs the
cross-user step (a victim-initiated flow delivering *their* code, then the exchange reading their
data) per `agent/references/finding-fp-and-severity-gate.md`.

## What to Record

Flow type, the vulnerable parameter, the exact request chain (authorization and token exchange),
decoded token claims and scope differences, and the attacker outcome (`agent/rules/hunting.md` §2):
e.g. a code delivered to the attacker `redirect_uri` exchanged for a token that reads the victim's
profile. Format: `agent/references/runtime-guides/web-finding-recording.md`.
