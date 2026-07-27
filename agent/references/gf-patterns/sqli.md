---
name: gf-patterns:sqli
description: Query-identifier and search parameter patterns that signal SQL injection surfaces
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
bucket: sqli
skill: sqli-testing
weight: 40
---

# gf: sqli

## What this bucket classifies

Parameters that commonly feed raw database queries: numeric identifiers, sort/filter
columns, and search strings. These are the highest-yield targets for `sqlmap` once the
endpoint is confirmed reachable.

## Load this reference when

- The corpus has `?id=`, `?q=`, `?search=`, `?sort=`, `?category=`, or `?filter=` keys
- Operator is picking which endpoints to send to sqlmap first on a large corpus
- The operator wants to de-duplicate with `idor` — both buckets share `id` so co-occurrence is common

## Parameter keys that match

`id, uid, pid, sid, tid, order, sort, filter, q, search, query, category, where, select, table,
column, field, from, row, sleep, fetch`

### Upstream gf param additions (2026-06)

The SQL-keyword-flavored keys `where`, `select`, `table`, `column`, `field`, `from`, `row`,
`sleep`, and `fetch` were folded in from the upstream gf pattern sets. A param literally named
after a SQL clause or function (`?where=`, `?select=`, `?sleep=`) is a genuine injection signal,
and `sleep`/`fetch` in particular hint at time-based and cursor-style query surfaces.

FP guard: `where` and `select` also overlap the `nosqli` bucket (Mongo/ES `$`-operators flow in
via compound-key expansion), so both buckets firing on the same row is expected and fine — the
reason chain is multi-bucket, and bucket weight only orders triage rather than gating inclusion,
so the overlap never suppresses a row. No path fragments were added.

### ORM sort/group compound family (deepened, vuln-taxonomy-audit 2026-07)

"SQLi via sort/orderBy parameter" — an ORM building `ORDER BY <param>` or `GROUP BY <param>`
directly from a request value (column names generally cannot be parameterized/bound the way
literal values can) — is a recurring bug-bounty pattern and a direct extension of the same
rationale as the upstream additions above. `order`/`sort` bare keys already existed; the
compound `_by` forms and `having` did not:

`order_by, orderby, sort_by, sortby, group_by, groupby, having`

## Path patterns that match

None — sqli is keyed entirely off parameter names.

## Weight and priority interpretation

- Baseline priority score: 40
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/search?q=shoes&sort=price_desc` — search + sort combo
- `https://target.example/api/products?category=outdoor&filter=in_stock` — filter-based query
- `https://target.example/users/detail?uid=412` — numeric detail key
- `https://target.example/reports/list?sid=quarterly&tid=2024` — session-ish ids feeding a filter
- `https://target.example/forum/thread?pid=98123&order=asc` — paginated thread id

## What it does NOT classify

- Free-text comment and message fields — those land in `xss`
- SSO / refresh-token session ids — those are `interestingparams` (credential-style) not query keys
- Numeric IDs that are pure object handles with no query DSL surface — those land primarily in `idor`

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [PayloadsAllTheThings SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

## Related

- `agent/skills/sqli-testing/SKILL.md` — the follow-up test skill
- `agent/references/payloads/sqli-payloads.md` — payload library
- `agent/references/gf-patterns/idor.md` — adjacent bucket (both share `id` keys)
