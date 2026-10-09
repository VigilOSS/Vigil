---
name: gf-patterns:graphql
description: GraphQL endpoint and request-key patterns that signal introspection, query-injection, and BOLA surfaces
origin: local overlay (no upstream gf equivalent)
bucket: graphql
skill: graphql-testing
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

`mutation`, `subscription`, `operationname` and `variables` are unambiguous and fire on their own.
**`query` alone does not** — it is simultaneously a member of `sqli` (40) and `xss` (20), and only
`rce` (50) outranks this bucket, so a bare `?query=shoes` on a REST search route used to win
`gf:graphql` at 45 with no GraphQL evidence at all. `_suppress_graphql_on_bare_query` therefore
requires a `query`-only row to be **corroborated** by one of:

- a GraphQL path fragment (below), or
- a second, unambiguous GraphQL request key, or
- the producer type `graphql` (`classify_type()` assigns it to a POST whose BODY carries a braced
  `query` value), or
- a braced selection set as the `query` **value** itself — the GET form of that same evidence,
  which no producer type can express because `classify_type()` never reads the query string.

An uncorroborated row is only re-ranked, never dropped: it keeps its real `sqli`/`xss` matches and
moves from `45 gf:graphql` to `40 gf:sqli`.

## Path patterns that match

`/graphql`, `/graphiql`, `/graphql/v1`, `/graphql/v2`, `/api/graphql`, `/gql`

Note: `/query` is deliberately NOT a path fragment — it would mis-bucket ordinary REST search
routes (e.g. `/search/query`, `/api/query`) at weight 45. The `query` PARAM key carries that
signal for true GraphQL requests, but only once corroborated (see above) — an uncorroborated
`query` key would reproduce exactly the misroute this fragment exclusion exists to avoid.

## Weight and priority interpretation

- Baseline priority score: 45 (second only to `rce` at 50)
- Type floor: `graphql` producer type also sets a floor of 45 via `_TYPE_FLOOR`
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

Path-fragment matches:

- `https://target.example/graphql` — canonical GraphQL endpoint that previously fell through to the generic path fallback
- `https://target.example/graphiql` — GraphiQL IDE, often left enabled in production
- `https://target.example/api/graphql` — common SaaS mounting point
- `https://target.example/api/lotus/graphql` — product-namespaced mounting point
- `https://target.example/gql` — abbreviated alias

Param-key matches:

- `https://target.example/api/data?query={users{id,email}}` — inline GraphQL query over GET.
  Corroborated by the braced selection set in the VALUE, which is how GraphQL-over-GET (the form a
  historical-URL corpus captures, and the one GraphiQL itself issues) survives the bare-`query`
  suppression.
- `https://target.example/api/search?operationname=GetUser&variables={"id":1}` — named operation;
  `operationname` and `variables` are unambiguous and need no corroboration.

## What it does NOT classify

- REST search endpoints with a `q=` or `search=` parameter — those belong in `sqli`/`xss`
- REST endpoints that happen to use a `query` key for filtering, e.g.
  `/api/v2/products/search?query=shoes` — an unbraced value on a non-GraphQL path corroborates
  nothing, so the row clusters `gf:sqli` and keeps its `xss` match
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

`/graphql` repeatedly fell to the generic `path:/` fallback at priority 0 across unrelated estates.
Independent modern-SaaS review confirmed that GraphQL is a dominant production surface rather than
a niche class. See `docs/research/classify-surface/README.md` for the public evidence
summary.

## Sources

- [GraphQL Foundation — Introspection](https://graphql.org/learn/introspection/)
- [OWASP API Security Top 10:2023 — API8 Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [HackTricks — GraphQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)

## Related

- `agent/references/gf-patterns/idor.md` — overlaps on object-reference access via node IDs
- `agent/references/gf-patterns/ssrf.md` — GraphQL mutation to a URL-fetch resolver can be SSRF
- `agent/references/gf-patterns/api-versioning.md` — `/graphql/v1` vs `/graphql/v2` version surface
