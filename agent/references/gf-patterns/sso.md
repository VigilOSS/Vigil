---
name: gf-patterns:sso
description: SAML/SSO routing and federation endpoint patterns (/sso/, /saml, /cas/, /adfs/)
origin: local overlay (no upstream gf equivalent)
bucket: sso
weight: 35
---

# gf: sso

## What this bucket classifies

SAML and enterprise SSO federation endpoints where an attacker can exploit SAML assertion
injection, XML signature wrapping, IdP-initiated SSO bypass, or cross-tenant SSO token
confusion. Distinct from `auth` (credential entry) and `oauth-oidc` (OAuth2/OIDC flows).

## Load this reference when

- The corpus contains `/sso/`, `/saml`, `/saml2`, `/cas/`, `/adfs/`, or
  `/federationmetadata` paths
- Param keys `samlresponse`, `samlrequest`, `relaystate`, `wctx`, or `wresult` appear in
  query strings (WS-Federation passive endpoint params)
- Operator is assessing enterprise identity federation or Okta/AD FS integration

## Parameter keys that match

`samlresponse, samlrequest, relaystate, wctx, wresult`

These are the canonical SAML 2.0 POST-binding parameter names (lowercased after
`collect_keys` normalization) and the WS-Federation passive endpoint params (`wctx`,
`wresult` from the WS-Fed passive profile).

## Path patterns that match

`/sso/`, `/sso`, `/saml`, `/saml2`, `/cas/`, `/adfs/`, `/fed/`, `/sts/`, `/federationmetadata`

`/saml` is boundary-anchored (via `_fragment_pattern`): it matches `/saml`, `/saml/acs`,
`/saml/metadata` but NOT `/saml2` — the `2` is not a boundary character. `/saml2` is
listed separately for SAML 2.0 explicit paths.

### Federation-metadata extension (classify-context-and-surface 2026-06, Part 3 §C.12)

`/federationmetadata` was added to catch the AD FS federation-metadata document
(`/FederationMetadata/2007-06/FederationMetadata.xml`) — a SAML/WS-Fed metadata
disclosure and SP-enumeration surface. It is a metadata-only route with no auth
sibling, so it cleanly raises previously-unmatched federation-metadata URLs from
priority 0 to `gf:sso` (additive, never a demotion).

The other §C.12 candidates were deliberately NOT added, to keep the change additive:

- `/saml/metadata` and `/adfs/ls` — already covered by the existing `/saml` and
  `/adfs/` fragments (boundary-anchored), so adding them would be a no-op.
- `/simplesaml` and `/shibboleth.sso` — NOT added. The canonical product
  endpoints under them (`/Shibboleth.sso/Login`, `/Shibboleth.sso/Logout`,
  `/simplesaml/logout.php`) carry an auth fragment that
  `_suppress_auth_on_sso_route` would then suppress, DEMOTING those rows from
  `gf:auth` (40) to `gf:sso` (35). That is a non-additive score decrease, so
  they are left out.

## Tie-break ordering (override vs trust_surface and auth)

`sso` is declared BEFORE `trust_surface` (both weight 35) so a co-fire on fragments shared
between the two (e.g. `/sso/callback` contains `/sso/` from sso and `/callback` from
trust_surface) resolves to `gf:sso` by first-at-max-weight tie-break.

The `_suppress_auth_on_sso_route` function removes a generic `auth` match when an SSO PATH
fragment fires AND no auth param key fires AND no SAML-auth compound (`/saml/acs`,
`/saml/sso`) fires. This ensures SSO routing pages cluster as `gf:sso` (matrix W8) while:
- `/saml/acs` pages stay as `auth` (SAML assertion consumer is an auth surface — matrix X3)
- A `/login` page with a `SAMLResponse` POST param stays as `auth` (matrix W10)

## Weight and priority interpretation

- Baseline priority score: 35
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

Path-fragment matches:

- `https://target.example/sso/login` — SSO-routed login page
- `https://target.example/saml/metadata` — SAML metadata document (enumerate IdP/SP config)
- `https://target.example/FederationMetadata/2007-06/FederationMetadata.xml` — AD FS federation-metadata XML (signing certs, entity IDs, ACS/SLO endpoints, claim mappings)
- `https://target.example/saml2/idp/SSO` — SAML 2.0 IdP SSO service
- `https://target.example/cas/login?service=https://app.example` — CAS authentication
- `https://target.example/adfs/ls/` — AD FS passive login service
- `https://target.example/fed/` — WS-Federation endpoint
- `https://target.example/sts/` — Security Token Service endpoint

Param-key matches:

- `https://target.example/saml/acs` (POST with `SAMLResponse=PH...`) — SAML assertion POST
- `https://target.example/adfs/ls?wctx=...&wresult=...` — WS-Fed passive response params

## What it does NOT classify

- `/saml/acs` when combined with a SAML auth param key — `auth` wins (SAML assertion consumer
  is an auth surface; SSO disambiguation rule keeps `auth` in that case)
- Generic OAuth flows (`/oauth2/authorize`) — those belong in `oauth-oidc` (weight 35);
  the two can co-fire and `oauth-oidc` wins (declared before `sso` in `_BUCKETS`)
- Okta JavaScript config artifacts (`/static/js/oktaConfig.js`) — these may expose Okta
  client IDs and tenant URLs but are typed as `static` or `script` at ingest; they do not
  match any sso fragment

## Attack classes

- **SAML assertion injection:** attacker modifies the `SAMLResponse` payload (XML) to change
  the `NameID` or add unauthorized `AttributeStatement` entries before the SP validates
- **XML signature wrapping (XSW):** move the signed `Assertion` element to a different
  position in the XML tree so the SP validates the signed copy but processes the unsigned
  attacker-modified copy
- **IdP-initiated SSO bypass:** an attacker-controlled IdP sends an unsolicited SSO assertion
  to the SP; if the SP accepts IdP-initiated responses without a valid `InResponseTo`, the
  attacker can log in as any user
- **RelayState open redirect:** the `RelayState` parameter is a return URL that is typically
  URL-decoded and followed post-authentication without host allow-list validation
- **WS-Federation `wresult` injection:** the `wresult` token in WS-Fed passive responses is
  an XML security token; equivalent XSW and signature bypass apply
- **Federation-metadata disclosure / SP enumeration:** an unauthenticated AD FS
  `/FederationMetadata/.../FederationMetadata.xml` (or SAML SP metadata) document
  leaks signing certificates, entity IDs, ACS/SLO endpoints, and claim mappings —
  the reconnaissance basis for assertion-injection and XSW attacks against the
  federation

## Corpus grounding

3 actionable `sso` templates (371 rows) in the first cms-gov deep sweep (Okta login, profile
Okta endpoint, Okta config JavaScript). See `docs/research/classify-surface-2026-06/README.md` §4b.

## Sources

- [OWASP — SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [PortSwigger — SAML vulnerabilities](https://portswigger.net/web-security/oauth/saml)
- [CAS Protocol 3.0 Specification](https://apereo.github.io/cas/6.6.x/protocol/CAS-Protocol-Specification.html)
- [WS-Federation Passive Profile](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc)

## Related

- `agent/references/gf-patterns/auth.md` — credential-entry surfaces; SSO disambiguation rule
- `agent/references/gf-patterns/oauth-oidc.md` — OAuth2/OIDC flows on the same authorization server
- `agent/references/gf-patterns/redirect.md` — RelayState open-redirect chaining
