---
name: gf-patterns:oauth-oidc
description: OAuth2/OIDC flow endpoints and discovery keys (authorize, token, JWKS, well-known config)
origin: local overlay (no upstream gf equivalent)
bucket: oauth-oidc
skill: oauth-oidc-testing
weight: 35
---

# gf: oauth-oidc

## What this bucket classifies

OAuth2 and OpenID Connect flow endpoints, discovery documents, and JWKS URIs where an attacker
can exploit redirect-URI bypass, PKCE downgrade, implicit-flow token theft, client-credential
misuse, or JWKS-substitution for JWT forgery.

## Load this reference when

- The corpus contains `/.well-known/openid-configuration`, `/oauth2/`, or `/oidc/` paths
- OAuth2/OIDC param keys (`client_id`, `redirect_uri`, `response_type`) appear in query strings
- Operator is mapping the full authorization-server attack surface
- A `/.well-known/oauth-authorization-server` metadata document advertises a
  `registration_endpoint` (dynamic client registration is enabled), or a
  `/oidc/register` route is present

## Parameter keys that match

`client_id, redirect_uri, response_type, scope, state, nonce, code_challenge, grant_type`

These are the canonical OAuth2/OIDC request parameters (RFC 6749, RFC 7636, OpenID Core 1.0).

## Path patterns that match

Discovery and metadata:
`/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`,
`/jwks.json`, `/.well-known/jwks.json`

Protocol endpoints:
`/oauth2/`, `/oidc/`, `/connect/authorize`, `/connect/token`, `/connect/userinfo`

### Dynamic Client Registration (DCR) and PingFederate (classify-context-and-surface 2026-06, Part 3 §C.11)

Part 3 §C.11 extends this bucket with dynamic-client-registration (DCR) and
PingFederate surfaces, realized through one new literal fragment
(`/connect/register`) plus the existing oauth-oidc fragments and the new
`idp_admin` bucket:

- **AS metadata / DCR discovery** — `/.well-known/oauth-authorization-server`
  (RFC 8414, added under *Discovery and metadata*) is the discovery anchor: it
  advertises the `registration_endpoint`, `token_endpoint`, and `jwks_uri`, so it
  is the entry point for probing a DCR-enabled authorization server.
- **`/oidc/register` DCR endpoint** — caught by the existing boundary-anchored
  `/oidc/` fragment (`/oidc/register` → core `/oidc` + segment boundary), so no
  separate fragment is needed.
- **`/connect/register`** — the OIDC DCR endpoint, added as an explicit oauth-oidc
  fragment. Because oauth-oidc is declared BEFORE `trust_surface` (whose `/connect`
  fragment would otherwise capture it, both weight 35), a DCR route clusters
  `gf:oauth-oidc` — keeping DCR abuse on the OAuth-flow specialist rather than the
  generic callback bucket.
- **PingFederate `/as/authorization.oauth2`, `/as/token.oauth2`,
  `/as/clients.oauth2`** — routed to the new `idp_admin` bucket (weight 35),
  which models the IdP admin / realm / DCR-config surface. `oauth-oidc`
  continues to model the OAuth *flow*; `idp_admin` models the *admin* surface.
  See `agent/references/gf-patterns/idp_admin.md`.

## Tie-break ordering (override vs trust_surface)

`oauth-oidc` is declared BEFORE `trust_surface` in `_BUCKETS` (both weight 35). When
a fragment shared between the two buckets fires (e.g. `/oauth2/authorize` contains both
`/oauth2/` from oauth-oidc and `/authorize` from trust_surface), the first-at-max-weight
tie-break resolves to `gf:oauth-oidc`. The bare `/oauth/callback` does NOT contain `/oauth2/`
(the `2` is required), so trust_surface retains ownership of bare OAuth callback paths
(regression pin §10.5 in `classify_buckets.py`).

## Weight and priority interpretation

- Baseline priority score: 35
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

Discovery:

- `https://target.example/.well-known/openid-configuration` — OIDC discovery (exposes full provider endpoint map; was priority 0 before 2026-06)
- `https://target.example/.well-known/oauth-authorization-server` — RFC 8414 metadata
- `https://target.example/.well-known/jwks.json` — JWKS public key set

Protocol endpoints:

- `https://target.example/oauth2/authorize?client_id=app&response_type=code&redirect_uri=...` — authorization code flow
- `https://target.example/connect/token` — token endpoint (code exchange, refresh)
- `https://target.example/oidc/userinfo` — user-info endpoint (scope-bounded attributes)
- `https://target.example/jwks.json` — public key document used for JWT signature validation

Param-key only:

- `https://target.example/auth?response_type=token&client_id=web` — implicit flow (param fires)

## What it does NOT classify

- Bare `/oauth/callback` — owned by `trust_surface`; the bare callback is a redirect surface,
  not the authorization-server endpoint set
- `/authorize` alone without an `/oauth2/`/`/oidc/` prefix — owned by `trust_surface`
- JWT bearer tokens in API requests — those belong in `jwt` (weight 30)

## Attack classes

- **Redirect-URI bypass:** attacker registers a redirect_uri that bypasses the allow-list
  (subdomain confusion, path traversal, open-redirect chaining)
- **PKCE downgrade:** server accepts code-exchange without `code_verifier` despite
  PKCE challenge in the authorization request
- **Implicit-flow token theft:** `response_type=token` leaks the access token in the fragment
  to browser history and referrer headers
- **JWKS substitution:** an attacker supplies a `jku`/`jwk` claim pointing to their own JWKS
  to have the server validate a forged JWT
- **Client-credential enumeration:** `/oauth2/authorize?client_id=` is iterable when the
  server returns distinct errors for registered vs. unknown clients
- **Dynamic Client Registration (DCR) abuse:** an open `registration_endpoint`
  (advertised by `/.well-known/oauth-authorization-server`, reached via
  `/oidc/register` or `/connect/register`) lets an attacker self-register a
  client with an attacker-controlled `redirect_uri`, `jwks_uri`, or
  `request_uri`, then drive a redirect-URI bypass or JWKS-substitution attack
  with a freshly minted, server-trusted client

## Corpus grounding

1 `missed_high_value` (`/.well-known/openid-configuration`, xfinity, proposed priority 60) and
2 `unknown_should_classify` (`.well-known/change-password`, `.well-known/openid-configuration`)
in the initial 535-template sample. Long-tail cms-gov sweeps: 2 additional actionable templates.
Zendesk third corpus corroborates OIDC discovery presence on modern SaaS.
See `docs/research/classify-surface-2026-06/README.md` §4b.

## Sources

- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 8414 — OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414)
- [RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591)
- [PortSwigger — OAuth vulnerabilities](https://portswigger.net/web-security/oauth)

## Related

- `agent/references/gf-patterns/auth.md` — credential-entry surfaces that precede the OAuth flow
- `agent/references/gf-patterns/jwt.md` — bearer-token surfaces that follow OAuth token issuance
- `agent/references/gf-patterns/redirect.md` — redirect_uri bypass at the URL-redirect level
- `agent/references/gf-patterns/trust_surface.md` — broader trust-delegation bucket that owns bare `/oauth`, `/authorize`, `/token`, and `/connect/register`
- `agent/references/gf-patterns/idp_admin.md` — IdP admin / realm surface that owns the PingFederate `/as/*.oauth2` and DCR-config endpoints (the admin counterpart to this flow bucket)
