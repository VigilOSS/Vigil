---
name: gf-patterns:nosqli
description: NoSQL operator-injection patterns (MongoDB / Elasticsearch query operators and search-aggregation routes)
origin: local overlay (no upstream gf equivalent)
bucket: nosqli
weight: 35
---

# gf: nosqli

## What this bucket classifies

NoSQL operator-injection surfaces — request parameters that smuggle MongoDB /
Elasticsearch query operators (`$ne`, `$gt`, `$regex`, `$where`, ...) into a
backend query, and the search / aggregation routes those operators are evaluated
on (`/_search`, `/aggregate`, `/_msearch`). The seven-year-old upstream gf
taxonomy was written for monolithic SQL-backed apps and has **no NoSQL concept**;
this is a net-new local-overlay bucket that gives the `$`-operator family a home.

The operator tokens normally arrive in the bracket form `username[$ne]=` rather
than as a bare query key. `expand_compound_key` (which splits on `[` / `]`)
decomposes `username[$ne]` into the `$ne` token, so the operator survives into the
param matcher and this bucket fires.

## Load this reference when

- The corpus contains query params with MongoDB/ES operators —
  `?username[$ne]=`, `?password[$gt]=`, `?filter[$regex]=`, `?q[$where]=`
- A route ends in `/_search`, `/aggregate`, or `/_msearch` (Elasticsearch /
  MongoDB query or aggregation surface)
- Operator is testing JSON/document-store back ends (MongoDB, Elasticsearch,
  CouchDB) for authentication bypass or operator injection

## Parameter keys that match

`$ne, $gt, $gte, $lt, $regex, $where, $in, $or, $exists`

These are the MongoDB / Elasticsearch query operators. They are matched **after**
`expand_compound_key` splits the bracket form (`username[$ne]` → `$ne`); a raw
`$ne` sitting only inside a param *value* is not a key and does not match.

`$where` and `$gt` overlap conceptually with the `sqli` bucket's SQL-keyword
params (`where`, `select`, ...): the same query surface can carry both a SQL
keyword and a Mongo operator. When both fire that is intentional — the reason
chain is multi-bucket, not exclusive.

## Path patterns that match

Elasticsearch / MongoDB query and aggregation routes:
`/_search`, `/aggregate`, `/_msearch`

These anchor the operator-evaluation surface even when the request body (not the
query string) carries the operator payload — the route alone is enough signal to
classify and route to the NoSQL-injection skill.

## Weight and priority interpretation

- Baseline priority score: 35
- Declared **after** `cms_db_admin` (also weight 35): on a same-weight co-fire the
  first-declared bucket keeps the cluster key by the first-at-max-weight tie-break,
  with `nosqli` additively recorded in the reason chain
- Below the weight-40 injection/SSRF buckets — `sqli` (40) and `ssrf` (40)
  dominate the cluster key when they co-fire on the same row; `nosqli` is still
  recorded as a co-firing reason
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/api/login?username[$ne]=&password[$ne]=` —
  authentication bypass via `$ne` operator injection (both bracket keys decompose
  to `$ne`)
- `https://target.example/api/users?role[$regex]=^admin` — `$regex` predicate
  injection to widen a result set
- `https://target.example/api/account?balance[$gt]=0` — `$gt` boolean/range
  injection for blind extraction
- `https://target.example/orders/aggregate` — MongoDB aggregation-pipeline route
- `https://target.example/products/_search` — Elasticsearch query-DSL surface
- `https://target.example/logs/_msearch` — Elasticsearch multi-search surface
- `https://target.example/api/items?filter[$where]=this.x==1` — server-side
  JavaScript evaluation via `$where`

## What it does NOT classify

- A plain `?q=term` or `?search=...` with no `$`-operator and not on a
  `/_search` / `/aggregate` / `/_msearch` route — that is generic search /
  `sqli` territory, not NoSQL operator injection
- A `$ne` / `$where` string appearing inside response *content* or a param
  *value* — only param **keys** (after compound-key expansion) and the three
  route fragments match
- Plain relational-DB SQL injection on string-keyword params — owned by `sqli`
  (the two buckets may co-fire, but the SQL-keyword params alone live in `sqli`)

## Attack classes

- **Authentication bypass:** `username[$ne]=&password[$ne]=` (or `[$gt]=`) makes a
  document query always-true, logging in without valid credentials
- **Blind / boolean data extraction:** `$gt` / `$lt` / `$regex` predicate
  manipulation to exfiltrate field values one comparison at a time
- **Server-side JavaScript execution:** MongoDB `$where` evaluates an arbitrary JS
  predicate, enabling logic abuse and (legacy) RCE-adjacent behavior
- **Predicate / set widening:** `$or`, `$in`, `$exists` to bypass filters,
  enumerate documents, or return records outside the intended authorization scope
- **Elasticsearch query-DSL injection:** crafted operators on `/_search` /
  `/_msearch` returning unauthorized documents, or aggregation abuse on
  `/aggregate`

## Corpus grounding

Forward-looking coverage. The plan records **no DB hit count** for this bucket —
gf has no NoSQL concept and the operator tokens only surface after the
compound-key split, so there is no pre-existing classified volume to point to.
The bucket is added as generic, future-engagement coverage for document-store
back ends rather than to recover a measured local cluster (see Part 3 §A.8 and the
"forward-looking coverage for future engagements" note in the plan).

## Sources

- [OWASP — Testing for NoSQL Injection (WSTG-INPV-05)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- [MongoDB — Query and projection operators (`$ne`, `$gt`, `$regex`, `$where`, ...)](https://www.mongodb.com/docs/manual/reference/operator/query/)
- [Elasticsearch — Query DSL and `_search`/`_msearch` APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html)
- [PortSwigger Web Security Academy — NoSQL injection](https://portswigger.net/web-security/nosql-injection)
- [HackTricks — NoSQL injection](https://book.hacktricks.xyz/pentesting-web/nosql-injection)

## Related

- `agent/references/gf-patterns/sqli.md` — SQL-keyword params (`where`,
  `select`, ...) share the same query surfaces; expected to co-fire (multi-bucket
  reason chain)
- `agent/references/gf-patterns/idor.md` — operator-injection auth bypass often
  pivots into broken object-level access
- `agent/skills/nosql-injection/` — the skill this bucket routes to (canonical
  class `nosqli`)
- `agent/references/runtime-guides/vuln-taxonomy.md` — canonical class mapping
  (`nosqli` bucket → `nosqli` class → `injection` taxonomy)
