---
name: gf-patterns:api
description: REST/Apex API path patterns that surface generic API routes for baseline triage
origin: local overlay (no upstream gf equivalent)
bucket: api
weight: 20
---

# gf: api

## What this bucket classifies

Generic REST and Apex API routes that carry no specific vulnerability-class signal in their
parameter keys but deserve triage attention as data-bearing endpoints. This bucket provides a
low-floor catch for API paths that would otherwise score 0 and disappear into a `path:api`
cluster.

## Load this reference when

- The corpus has large volumes of `/api/...`, `/rest/...`, or `/services/apexrest/...` routes
  with no query/body parameters that match a higher-weight bucket
- Producer type is `api_route` (type-floor fires at weight 20 via `_TYPE_FLOOR`)
- Operator wants a rapid scan of all API surfaces before param-level testing begins

## Parameter keys that match

None — this bucket is intentionally path-only. API endpoints are typed by their path
shape, not parameter name, and a param-key hit from any higher-weight bucket will always
dominate this bucket's weight of 20.

## Path patterns that match

`/rest/`, `/rest/v`, `/services/apexrest/`, `/apexrest/`

Note: `/api/` and `/api/v` are deliberately OMITTED as literal path fragments. A bare
`/api/` fragment would append `gf:api` to `/api/users/avatar` and break the pinned exact
reason chain `gf:lfi+gf:upload_fields`. The generic `/api/...` rescue is delivered by
the `api_route` TYPE FLOOR (weight 20); `/api/v<n>/` is covered by the `api-versioning`
regex bucket. This design ensures higher-specificity buckets are never shadowed by the
generic api fragment.

## Weight and priority interpretation

- Baseline priority score: 20
- Type floor: `api_route` producer type sets floor of 20 via `_TYPE_FLOOR`; `api_spec`
  (OpenAPI/Swagger/WSDL) sets floor of 40 and clusters as `gf:api_spec` (a label-only
  floor bucket with no `_BUCKETS` entry)
- Weight 20 is intentionally below all specific vulnerability buckets (ssrf=40, sqli=40,
  lfi=40, auth=40, graphql=45, rce=50) — a param-key hit from any of those always wins
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/rest/v1/users` — REST versioned resource (path `/rest/v` fires)
- `https://target.example/rest/sessions` — REST session management
- `https://target.example/services/apexrest/account/summary` — Salesforce Apex REST endpoint
- `https://target.example/apexrest/leads/create` — abbreviated Apex prefix

Type-floor only (no path fragment fires, `api_route` type rescues the row):

- `https://target.example/api/agent/a2a` — producer typed as `api_route`
- `https://target.example/api/cnap/cga-audit/batch` — producer typed as `api_route`

## What it does NOT classify

- `/api/v1/`, `/api/v2/` routes — those match the `api-versioning` regex bucket (weight 25)
- GraphQL endpoints under `/api/graphql` — matched by the `graphql` bucket (weight 45)
- Authenticated REST endpoints with object-reference parameters — those fire `idor` (weight 35)
  or higher-weight buckets; `api` only appears in their reason chain as a secondary signal

## Corpus grounding

Generic API routes were the largest recurring missed class across unrelated surface shapes, while
modern SaaS review confirmed that routes such as `/api/v2/users/me.json`,
`/api/v2/account/settings.json`, `/billing/api/subscriptions`, and onboarding workflows are common
production surfaces. The low floor preserves that coverage without claiming every API route is
urgent. See `docs/research/classify-surface/README.md` for the public evidence summary.

## Sources

- [OWASP API Security Top 10:2023](https://owasp.org/API-Security/)
- [Salesforce Apex REST API](https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_rest.htm)

## Related

- `agent/references/gf-patterns/api-versioning.md` — `/v[0-9]+/` path segment detection
- `agent/references/gf-patterns/graphql.md` — GraphQL under `/api/graphql`
- `agent/references/gf-patterns/idor.md` — object-reference params on API routes
