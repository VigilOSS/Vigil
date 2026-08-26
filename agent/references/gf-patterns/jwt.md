---
name: gf-patterns:jwt
description: JWT/bearer-token surface patterns (access_token, refresh_token, id_token param keys)
origin: local overlay (gf upstream had interestingparams at weight 15; this adds path coverage)
bucket: jwt
skill: jwt-testing
weight: 30
---

# gf: jwt

## What this bucket classifies

Endpoints that issue, refresh, or consume JSON Web Tokens where an attacker can exploit
algorithm downgrade, `alg:none` bypass, weak secret brute-force, `kid` injection, or
`jku`/`jwk` header claims to forge a token.

## Load this reference when

- The corpus contains `/jwt`, `/bearer`, or `/refresh-token` paths
- Param keys `access_token`, `refresh_token`, `id_token`, `jwt`, or `bearer` appear in query
  strings or body params
- Operator is assessing token issuance and refresh flows

## Parameter keys that match

`access_token, refresh_token, id_token, jwt, bearer`

`token` is deliberately EXCLUDED — bare `token` is already in `interestingparams` (weight 15)
and `trust_surface` owns `/token` as a path fragment. Including `token` here would cause
double-firing on every `?token=` parameter and push generic session/CSRF tokens into the JWT
specialist queue.

## Path patterns that match

`/jwt`, `/bearer`, `/refresh-token`

`/token` is deliberately OMITTED — it is owned by `trust_surface` (weight 35). Bare `/token`
fires trust_surface, which already routes to the correct specialist. The `jwt` bucket adds only
the explicitly JWT/bearer-named paths that trust_surface does not cover.

## Weight and priority interpretation

- Baseline priority score: 30
- Secondary/incremental signal — JWT surfaces mostly co-fire with `oauth-oidc` (35) or
  `auth` (40); in those co-fires the JWT reason appears in `priority_reason` but does not
  raise the cluster key above the higher-weight bucket
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

Path-fragment matches:

- `https://target.example/jwt/validate` — token validation endpoint
- `https://target.example/bearer/revoke` — bearer token revocation
- `https://target.example/api/refresh-token` — refresh endpoint (not `/token`, which is trust_surface)

Param-key matches:

- `https://target.example/api/user?access_token=eyJhbGciOiJSUzI1NiJ9...` — token in query string
- `https://target.example/api/data?jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...` — explicit JWT param
- `https://target.example/sso/exchange?id_token=eyJ...` — ID token exchange

## What it does NOT classify

- `?token=` alone — owned by `interestingparams` and `trust_surface`; deliberately excluded
- `/oauth2/token` — the OAuth token endpoint is primarily `oauth-oidc` (35) or
  `trust_surface` (35); `jwt` may appear as a secondary reason
- JWT header attacks from request headers (`Authorization: Bearer`) — not in URL param space;
  those require manual inspection after this bucket surfaces the endpoint

## Attack classes

- **Algorithm downgrade (`alg: none`):** attacker strips the signature and sets `alg: none`;
  server accepts the unsigned token if it does not explicitly reject `none`
- **Algorithm confusion (RS256 → HS256):** attacker signs the token with HMAC using the
  server's RSA public key; server validates with `HS256` using the same public key as secret
- **Weak secret brute-force:** `HS256` tokens signed with short or dictionary secrets can be
  cracked offline (jwt_tool, hashcat)
- **`kid` SQL/path injection:** the `kid` (key ID) header is used to look up the signing key
  in a database or filesystem; attacker injects SQL or path traversal to control the key used
- **`jku`/`jwk` JWKS URL injection:** attacker supplies a `jku` header pointing to their own
  JWKS document; server fetches and uses attacker-controlled public key to verify

## Sources

- [PortSwigger — JWT attacks](https://portswigger.net/web-security/jwt)
- [jwt_tool](https://github.com/ticarpi/jwt_tool)
- [RFC 7519 — JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)

## Related

- `agent/references/gf-patterns/oauth-oidc.md` — token issuance in OAuth2/OIDC flows
- `agent/references/gf-patterns/auth.md` — authentication entry that precedes JWT issuance
- `agent/references/gf-patterns/interestingparams.md` — bare `token` param at weight 15
- `agent/references/gf-patterns/trust_surface.md` — owns `/token` path fragment
