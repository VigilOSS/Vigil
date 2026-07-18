---
name: gf-patterns:graphql
description: GraphQL endpoint and request-key patterns that signal introspection, query-injection, and BOLA surfaces
origin: local overlay (no upstream gf equivalent)
bucket: graphql
weight: 45
---

# gf: graphql

## What this bucket classifies

GraphQL endpoints and request bodies where an attacker can issue arbitrary queries, trigger
introspection, exploit missing field-level authorization, or inject malicious operation strings.
These are the primary surfaces for OWASP API1:2023 (BOLA via GraphQL node IDs), API8:2023
(injection via operation strings), and introspection-based reconnaissance.

## Load this reference when

- The corpus contains `/graphql`, `/graphiql`, `/api/graphql`, or `/gql` paths
- Producer type is `graphql` (type-floor fires at weight 45 independent of path/key match)
- Operator is mapping the full GraphQL attack surface before a dedicated introspection probe

## Parameter keys that match

`query, mutation, subscription, operationname, variables`

These are the canonical GraphQL-over-HTTP request keys (POST body or query-string form).
`operationname` is the lowercased form of `operationName` after `collect_keys` normalization.

## Path patterns that match

`/graphql`, `/graphiql`, `/graphql/v1`, `/graphql/v2`, `/api/graphql`, `/gql`

Note: `/query` is deliberately NOT a path fragment — it would mis-bucket ordinary REST search
routes (e.g. `/search/query`, `/api/query`) at weight 45. The `query` PARAM key already
carries that signal for true GraphQL requests.

## Weight and priority interpretation

- Baseline priority score: 45 (second only to `rce` at 50)
- Type floor: `graphql` producer type also sets a floor of 45 via `_TYPE_FLOOR`
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

Path-fragment matches:

- `https://target.example/graphql` — canonical GraphQL endpoint (single worst corpus miss at priority 0 pre-2026-06)
- `https://target.example/graphiql` — GraphiQL IDE, often left enabled in production
- `https://target.example/api/graphql` — common SaaS mounting point
- `https://target.example/api/lotus/graphql` — product-namespaced mounting point
- `https://target.example/gql` — abbreviated alias

Param-key matches:

- `https://target.example/api/data?query={users{id,email}}` — inline GraphQL query
- `https://target.example/api/search?operationname=GetUser&variables={"id":1}` — named operation

## What it does NOT classify

- REST search endpoints with a `q=` or `search=` parameter — those belong in `sqli`/`xss`
- REST endpoints that happen to use a `query` key for filtering (no path fragment co-fires)
- GraphQL-over-WebSocket upgrade paths (those also fire `websocket` at weight 30)

## Attack classes

- **Introspection probe**: `__schema` / `__type` queries enumerate the full type system when
  introspection is not disabled in production. `graphiql` UI being served is a strong indicator.
- **BOLA via node IDs**: `node(id: "base64-opaque-id")` resolvers often bypass field-level
  authorization — swap the ID for another user's opaque GraphQL ID.
- **Query injection / batching abuse**: attacker-controlled `query`/`mutation` strings can
  exfiltrate data in a single round-trip; unbounded depth/complexity enables DoS.
- **Persisted-query bypass**: endpoints that only accept allowlisted persisted queries often
  fall back to arbitrary query execution when the allowlist check is missing.

## Corpus grounding

`/graphql` was the single highest-priority miss in both the cms-gov and xfinity corpora
(proposed priority 75, present in both, falling to `path:/` at priority 0 before 2026-06).
Zendesk (modern SaaS, third validation corpus): 392 of 1,540 proxy-captured rows are
`graphql`-typed, confirming graphql is a dominant surface shape in production SaaS, not a
niche class. See `docs/research/classify-surface-2026-06/README.md` §4b.

## Sources

- [GraphQL Foundation — Introspection](https://graphql.org/learn/introspection/)
- [OWASP API Security Top 10:2023 — API8 Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [HackTricks — GraphQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)

## Related

- `agent/references/gf-patterns/idor.md` — overlaps on object-reference access via node IDs
- `agent/references/gf-patterns/ssrf.md` — GraphQL mutation to a URL-fetch resolver can be SSRF
- `agent/references/gf-patterns/api-versioning.md` — `/graphql/v1` vs `/graphql/v2` version surface
