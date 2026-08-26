---
name: gf-patterns:servicenow
description: ServiceNow guest Service Portal, GlideRecord, and Struts-style `.do` action path/param patterns (sysparm_* family)
origin: local overlay (no upstream gf equivalent)
bucket: servicenow
skill: idor-testing, split-brain-idor
weight: 30
---

# gf: servicenow

## What this bucket classifies

ServiceNow surfaces where an attacker can reach data or actions across an object/ACL
boundary: the REST Table API (`/api/now`), UI/Struts action endpoints (`/nav_to.do`,
`auth_redirect.do`), scoped/system table routes (`/sys_`, `/x_`), the GlideRecord `/$`
entry points, and the guest Service Portal (`/sp?`). The `sysparm_*` query family and
`glide_sso_id` carry the table/query/redirect targets that drive GlideRecord IDOR,
unauthenticated guest-widget data exposure, and the `auth_redirect.do?sysparm_url=`
open-redirect / SSO-relay surface. Maps to canonical class `idor`. ServiceNow is a
ubiquitous enterprise SaaS, so this bucket is generic, not engagement-specific.

## Load this reference when

- The corpus contains `/api/now`, `*.do` action endpoints (`nav_to.do`, `auth_redirect.do`),
  `/sys_*` or `/x_*` table routes, GlideRecord `/$` paths, or `/sp?` Service Portal pages
- Param keys `sysparm_url`, `sysparm_query`, `sysparm_table`, or `glide_sso_id` appear in
  query strings
- Operator is checking for ServiceNow guest-portal data exposure, GlideRecord ACL bypass,
  or `auth_redirect.do` open-redirect / SSO abuse

## Parameter keys that match

`sysparm_url, sysparm_query, sysparm_table, glide_sso_id`

These are matched as WHOLE keys. The `auth_redirect.do?sysparm_url=` open-redirect / SSO
surface fires here off the literal `sysparm_url` key; once compound-key decomposition lands
(plan Part 4, Fix 4), the inner `url` token would additionally route the same row to
`ssrf` / `redirect`, and `glide_sso_id` would expose `sso` / `id`. Bare `sysparm` (without a
suffix) is not a key on its own and does not match.

## Path patterns that match

ServiceNow REST / UI / scoped-table discriminators:
`/api/now`, `/nav_to.do`, `auth_redirect.do`, `/sys_`, `/$`, `/sp?`, `/x_`

`/api/now` is the REST Table/Import/Attachment API root. `/nav_to.do` and `auth_redirect.do`
are the high-value UI/Struts actions (the redirect action is the open-redirect / SSO relay).
`/sys_` and `/x_` are the system-table and scoped-application prefixes (`sys_user`,
`x_acme_app`). `/$` is the GlideRecord/UI entry-point token (e.g. `/$pa_dashboard.do`), and
`/sp?` is the guest Service Portal page route. Fragments use the boundary-anchored
`fragment_in_path` semantics.

## Weight and priority interpretation

- Baseline priority score: 30
- Below the specific high-signal vulnerability buckets (rce=50, secret_vault=45, graphql=45,
  ssrf=40, auth=40, idor=35) — when those co-fire their param signal dominates ordering
- Equal weight (30) to its sibling context buckets `jwt`, `privileged_action`, and
  `devops_console`. `servicenow` is declared in `_BUCKETS` immediately BEFORE
  `privileged_action` (also 30), so among equal-weight matches the first-at-max-weight
  tie-break resolves the cluster to whichever fires first; both are still recorded additively
  in the reason chain
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

REST Table API and scoped tables:

- `https://target.example/api/now/table/incident?sysparm_query=active=true` — ServiceNow REST Table API with a GlideRecord query
- `https://target.example/sys_user_list.do?sysparm_table=sys_user` — system user table action
- `https://target.example/x_acme_app/record` — scoped-application route (`x_` prefix)

UI actions, GlideRecord, and guest portal:

- `https://target.example/auth_redirect.do?sysparm_url=https://idp.example/saml2` — open-redirect / SSO relay
- `https://target.example/nav_to.do?uri=/sys_user_list.do` — UI navigation action
- `https://target.example/$pa_dashboard.do?sysparm_dashboard=overview` — GlideRecord `/$` entry point
- `https://target.example/sp?id=guest_portal&sysparm_table=sys_user` — guest Service Portal page

## What it does NOT classify

- Generic Struts/legacy `.do` actions with no ServiceNow discriminator (e.g. `/checkout.do`,
  `/login.do`) — these are typed `page` by the URL typer and rely on co-firing buckets, not
  on `servicenow`; only the ServiceNow-specific `.do` actions (`nav_to.do`, `auth_redirect.do`)
  and the `sysparm_*` family are claimed here
- A bare `sysparm` substring embedded in an unrelated token — only the four whole `sysparm_*`
  / `glide_sso_id` keys match
- The OAuth/OIDC token-exchange flow itself — that is modeled by `oauth-oidc`; this bucket
  models the ServiceNow product surface and its redirect/SSO entry point

## Attack classes

- **GlideRecord IDOR / ACL bypass:** REST Table API or `sysparm_query`/`sysparm_table` lets a
  low-privilege or guest principal read arbitrary tables (`sys_user`, `sys_user_has_role`)
  when table ACLs default to public/guest
- **Unauthenticated guest-portal data exposure:** misconfigured Service Portal widgets
  (e.g. Simple List) served to the built-in `guest` user expose records without auth
- **Open redirect / SSO relay:** `auth_redirect.do?sysparm_url=` performs an attacker-controlled
  post-authentication redirect to an external IdP or phishing target
- **SSRF via redirect target:** once `sysparm_url` decomposes to its inner `url` token, a
  server-side fetch of an attacker-supplied URL becomes reachable (co-fires `ssrf`)

## Corpus grounding

In the reference enterprise corpus, **877** `auth_redirect.do?...sysparm_url=...` rows were
zero-priority (the `sysparm_url` compound key never decomposed), and **2,826 of 2,879** `.do`
action rows scored 0 because no bucket fired on the ServiceNow surface (plan Issue B / Issue 4).
This bucket, together with the compound-key fix, recovers the ServiceNow subset of that tail.
The forward-looking fragments (`/api/now`, `/sys_`, `/x_`, `/sp?`, `/$`) provide coverage for
future engagements where ServiceNow is deployed even when current hit counts are
low. See ADR 0008 and `DRIFT.md` for the accepted rationale.

## Sources

- [ServiceNow — REST Table API](https://docs.servicenow.com/bundle/utah-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html)
- [ServiceNow — Access control list (ACL) rules](https://docs.servicenow.com/bundle/utah-platform-security/page/administer/contextual-security/concept/access-control-rules.html)
- [ServiceNow — Service Portal public pages and guest access](https://docs.servicenow.com/bundle/utah-application-development/page/build/service-portal/concept/c_ServicePortal.html)
- [AppOmni / Aaron Costello — ServiceNow data exposure via misconfigured guest widgets](https://www.appomni.com/resources/blog-posts/servicenow-data-exposure/)
- [OWASP — Unvalidated Redirects and Forwards](https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards)

Note: the plan does not cite a ServiceNow-specific CVE for this bucket; its evidence is the
877 + 2,826 zero-priority row counts above. The references here are the authoritative vendor
and research sources for the GlideRecord/guest-portal and `auth_redirect.do` surfaces.

## Related

- `agent/references/gf-patterns/idor.md` — canonical class for this bucket; GlideRecord and `/sys_*` object references
- `agent/references/gf-patterns/redirect.md` — `auth_redirect.do?sysparm_url=` open-redirect target
- `agent/references/gf-patterns/ssrf.md` — inner `url` token SSRF once the compound key splits
- `agent/references/gf-patterns/sso.md` — `glide_sso_id` / SSO-relay surface
- `agent/references/gf-patterns/privileged_action.md` — sibling weight-30 bucket declared adjacently in `_BUCKETS`
