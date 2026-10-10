---
name: gf-patterns:idp_admin
description: Identity-provider admin / realm-config surfaces (Keycloak, PingFederate, ADFS, generic IdP admin and realm management)
origin: local overlay (no upstream gf equivalent)
bucket: idp_admin
skill: auth-bypass
weight: 35
---

# gf: idp_admin

## What this bucket classifies

Identity-provider **admin and realm-configuration** surfaces — the management plane of an
IdP rather than the end-user authentication flow. It catches Keycloak admin/realm routes
(`/auth/realms`, `/realms/`, `/auth/admin`, `/admin/master/console`), PingFederate
authorization-server endpoints (`/as/authorization.oauth2`, `/as/token.oauth2`,
`/as/clients.oauth2`), generic IdP/NetIQ Access Manager identity-server roots (`/idp/`,
`/nidp/`), and AD FS federation login (`/adfs/ls`). These routes expose realm metadata,
client/connection registration, and admin consoles where misconfiguration leads to
authentication bypass, realm enumeration, or full admin takeover.

It deliberately **complements** `oauth-oidc`: that bucket models the OAuth2/OIDC *flow*
(authorize/token/JWKS/userinfo); `idp_admin` models the *admin / realm* surface that sits
behind the same product.

## Load this reference when

- The corpus contains `/auth/realms/`, `/realms/`, `/admin/master/console`, `/idp/`,
  `/nidp/`, `/adfs/ls`, or PingFederate `/as/*.oauth2` paths
- An IdP is fingerprinted (Keycloak, PingFederate, AD FS, NetIQ/Micro Focus Access Manager)
  and you are checking its management plane rather than its login flow
- Operator is checking for unauthenticated admin-console exposure, realm/metadata
  disclosure, or dynamic client/connection registration abuse

## Parameter keys that match

None. `idp_admin` is a **path-only** bucket — the IdP admin/realm signal lives entirely in
the path shape, so no canonical query-parameter key is registered (the bucket's key set is
`frozenset()` in `classify_buckets.py`).

Generic OAuth/OIDC query params (`client_id`, `redirect_uri`, `code`, `response_type`) were
not added here: they belong to the *flow* and are owned by `oauth-oidc`. Pinning them to
`idp_admin` would conflate the two surfaces and cross-fire on every login URL.

## Path patterns that match

Keycloak admin / realm:
`/auth/realms`, `/realms/` (Keycloak ≥17 dropped the `/auth` prefix), `/auth/admin`,
`/admin/master/console`

PingFederate authorization server:
`/as/authorization.oauth2`, `/as/token.oauth2`, `/as/clients.oauth2`

Generic IdP / AD FS:
`/idp/`, `/nidp/` (NetIQ / Micro Focus Access Manager identity server), `/adfs/ls`

All fragments use boundary-anchored `fragment_in_path` semantics. Both the `/auth/realms`
and the prefix-less `/realms/` forms are listed because Keycloak 17+ removed the legacy
`/auth` context root, so modern deployments serve realms directly at `/realms/`.

## Weight and priority interpretation

- Baseline priority score: 35
- Equal in weight to `sso` (35) and `trust_surface` (35). `idp_admin` is declared **after**
  both in `_BUCKETS`, so on a shared-fragment co-fire the existing cluster wins under the
  first-at-max-weight tie-break, and `idp_admin` is recorded **additively** in the reason
  chain. Concretely: `/adfs/ls` clusters as `gf:sso` (sso owns the `/adfs/` fragment) and
  `/as/token.oauth2` clusters as `gf:trust_surface` (trust_surface owns the `/token`
  fragment) — `idp_admin` still appears in the reason chain on both.
- Co-fires with `oauth-oidc` (35) on IdP products; the boost is additive and never lowers a
  path-driven cluster.
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

Keycloak:

- `https://target.example/auth/realms/master/.well-known/openid-configuration` — legacy
  realm-config disclosure (`/auth/realms`)
- `https://target.example/realms/customer/account` — prefix-less realm route (Keycloak ≥17)
- `https://target.example/admin/master/console/` — Keycloak master admin console
- `https://target.example/auth/admin/realms/master/clients` — admin REST client list

PingFederate:

- `https://target.example/as/authorization.oauth2?client_id=app` — PingFederate authorize
- `https://target.example/as/clients.oauth2` — PingFederate client registry

Generic IdP / AD FS:

- `https://target.example/idp/startSSO.ping` — IdP-initiated SSO root
- `https://target.example/nidp/app/login` — NetIQ Access Manager identity server
- `https://target.example/adfs/ls/?wa=wsignin1.0` — AD FS federation login (clusters as
  `gf:sso`, with `idp_admin` in the reason chain)

## What it does NOT classify

- OAuth/OIDC **flow** endpoints (`/oauth2/authorize`, `/.well-known/openid-configuration`
  on its own, `/userinfo`, bare `/token`) — those model the flow and are owned by
  `oauth-oidc`; `idp_admin` only models the admin/realm surface
- A bare `/auth/` or `/login` path with no realm/admin segment — the fragments require
  `/auth/realms` or `/auth/admin`, so a plain `/auth/login` does NOT fire here (it routes
  to `auth` / lexical auth rescue)
- Generic application or CMS admin panels (`/wp-admin`, `/administrator`, `/phpmyadmin`) —
  those are not IdP-specific and belong to `cms_db_admin`

## Attack classes

- **Unauthenticated admin-console exposure:** `/admin/master/console` or `/auth/admin/...`
  reachable without authentication (or with default credentials) yields full realm admin —
  user, client, and role management
- **Realm / metadata enumeration:** `/realms/{realm}` and `/auth/realms/{realm}/.well-known`
  disclose realm names, supported flows, and endpoints, letting an attacker map every
  tenant/realm an IdP serves
- **Dynamic client / connection registration abuse:** `/auth/admin/.../clients`,
  `/as/clients.oauth2` allow registering or mutating OAuth clients (redirect-URI injection,
  privilege escalation) when registration is open or weakly authorized
- **Federation login / SAML abuse:** `/adfs/ls` and `/nidp/`/`/idp/` SSO roots are the entry
  point for SAML assertion replay, golden-SAML, and federation-metadata disclosure
- **Authentication bypass via misconfigured realm:** weak realm defaults (open registration,
  permissive token settings, disabled brute-force protection) surfaced through the admin
  plane

## Corpus grounding

`/realms` and `/idp` routes demonstrated that IdP administration signals had no classification
home. PingFederate `/as/*.oauth2`, AD FS `/adfs/ls`, and NetIQ `/nidp/` extend the same generic
coverage across near-ubiquitous enterprise identity providers. See ADR 0008, `DRIFT.md`, and the
focused classifier regressions for the accepted rationale.

## Sources

- [Keycloak — Server Administration Guide (realms, admin console)](https://www.keycloak.org/docs/latest/server_admin/)
- [Keycloak — Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html)
- [PingFederate — OAuth 2.0 / authorization-server endpoints](https://docs.pingidentity.com/pingfederate/)
- [Microsoft — Active Directory Federation Services (AD FS)](https://learn.microsoft.com/en-us/windows-server/identity/active-directory-federation-services)
- [NetIQ / Micro Focus — Access Manager (Identity Server / nidp)](https://www.microfocus.com/documentation/access-manager/)

## Related

- `agent/references/gf-patterns/oauth-oidc.md` — the OAuth2/OIDC *flow* surface (this bucket
  models the *admin/realm* surface of the same products)
- `agent/references/gf-patterns/sso.md` — SAML/SSO federation; `/adfs/ls` co-fires and
  clusters there with `idp_admin` in the reason chain
- `agent/references/gf-patterns/trust_surface.md` — owns the `/token` fragment that
  `/as/token.oauth2` co-fires on
- `agent/references/gf-patterns/auth.md` — generic authentication-entry surfaces (login/MFA)
- `agent/references/gf-patterns/cms_db_admin.md` — generic (non-IdP) CMS and DB admin panels,
  the sibling admin bucket
