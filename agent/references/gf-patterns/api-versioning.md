---
name: gf-patterns:api-versioning
description: Versioned-API path patterns that expose deprecated-endpoint and version-downgrade attack surfaces
origin: local overlay (no upstream gf equivalent); regex bucket
bucket: api-versioning
weight: 25
---

# gf: api-versioning

## What this bucket classifies

URL paths that contain a versioned API segment (`/v1/`, `/v2/`, `/v3/`, etc.) at a segment
boundary. These surfaces expose version-downgrade attacks, deprecated-endpoint IDOR, and missing
authentication controls that were removed in newer versions but still active in older ones.

## Load this reference when

- The corpus has large volumes of `/v1/`, `/v2/`, `/api/v1/...`, or deeply-nested versioned
  paths (e.g. `/dhrp/rns/v3/actions`)
- Operator is hunting deprecated-version auth gaps or version-enumeration surfaces

## Parameter keys that match

None — this is a regex-only bucket with no key set and no literal path fragments. Its sole
match signal is the `_REGEX_BUCKET_RULES["api-versioning"]` pattern.

## Regex rule (override #1)

Pattern: `/v[0-9]+(?=[/?#]|$)`

Matches a path segment that is `v` followed by one or more digits, bounded by `/`, `?`, `#`,
or end-of-string. The lookahead ensures only the segment boundary ends the token; a trailing
non-boundary character (letter, dash) does NOT fire.

Matches: `/v1/`, `/v2/`, `/v3`, `/api/v1/`, `/dhrp/rns/v3/actions`, `/person/prefs/api/v1/`,
`/v4/dcs/device`

Does NOT match: `/version/1.0` (segment `version`), `/v/1` (segment `v` with no digits),
`/vue/app` (segment `vue`), `/v1beta/x` (lookahead rejects `beta` after the digits)

The empty `_BUCKETS` entry (frozenset key set, empty literal fragments) keeps this bucket
in the single declaration-ordered iteration for tie-break and reason-chain order.

## Weight and priority interpretation

- Baseline priority score: 25
- Sits above `redirect`/`ssti`/`cors`/`xss` in the triage queue but below specific
  vulnerability classes (auth=40, ssrf=40, sqli=40, lfi=40, graphql=45, rce=50)
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/v1/` — bare version root (version enumeration signal)
- `https://target.example/v3/account/planinfo` — versioned account data API
- `https://target.example/api/v1/appInfo/display` — nested version segment
- `https://target.example/dhrp/rns/v3/actions` — deep nested version prefix
- `https://target.example/templates/v2/:namespace/:templateName` — template system API
- `https://target.example/v4/dcs/device` — device configuration API

## What it does NOT classify

- `/graphql/v1`, `/graphql/v2` — these fire the `graphql` bucket (weight 45) which wins;
  `api-versioning` may appear as a secondary reason in the chain
- Plain `/api/...` routes with no version segment — those use the `api_route` type-floor
- Semantic version numbers in query params (`?version=1.2.3`) — key is not in the key set

## Attack classes

- **Version-downgrade:** an attacker requests `/v1/...` when the application has moved to
  `/v3/...`, reaching an endpoint that lacks newer authentication or authorization controls
- **Deprecated-endpoint IDOR:** object-reference checks added in v2 may be absent in v1
  (e.g. tenant ownership check skipped on older version)
- **Version enumeration:** iterating `/v1/` through `/v9/` can discover undocumented API
  versions still accepting traffic
- **Missing rate-limit on deprecated version:** v1 endpoints often inherit no rate-limiting
  because traffic was expected to migrate to v2

## Corpus grounding

30 `unknown_should_classify` templates across xfinity (all at priority 0 before 2026-06),
covering `/v1/` through `/v4/`, deeply-nested versioned Comcast API paths, and
`/templates/v2/:namespace/:templateName`. Long-tail cms-gov sweeps: 2 additional actionable
templates. See `docs/plans/classify-surface-rd-2026-06-15.md` §4b and §3.1.

## Sources

- [OWASP API Security Top 10:2023 — API9 Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)
- [HackTricks — API Versioning](https://book.hacktricks.xyz/pentesting-web/api-pentesting)

## Related

- `agent/references/gf-patterns/api.md` — generic REST routes without a version segment
- `agent/references/gf-patterns/idor.md` — object-reference params often co-fire on versioned routes
