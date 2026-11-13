---
name: elasticsearch-injection
description: Detect and exploit Elasticsearch/Lucene query injection — query_string manipulation, field enumeration, data extraction, cross-index access, and access control bypass in ES-backed search
origin: Vigil
vuln_class: elasticsearch-injection
---

# Elasticsearch / Lucene Injection Testing

## When to Activate

- Search backed by Elasticsearch, OpenSearch or Solr: `X-Elastic-Product` header,
  `hits`/`_source`/`_score`/`took` in responses, Lucene or `query_shard_exception` /
  `SearchPhaseExecutionException` errors, search accepting `field:value`, wildcards or boolean
  operators.

`--technique ELASTICSEARCH-INJECTION`; deliver via `vigil assess kali exec --technique
ELASTICSEARCH-INJECTION --intent "<purpose>" --probe-kind payload --phase consume-test --timeout
30 -- curl …` (`--probe-kind exploit` for confirmed extraction). Detection, `_exists_` and wildcard
field discovery, regex/range extraction, filter negation, cross-index and `_source` overrides,
direct-API enumeration, JSON-body breakout, aggregation leaks, scripts and WAF evasion:
`agent/references/payloads/elasticsearch-injection-payloads.md`. Rank blind sweeps with
`vigil assess anomaly-score <responses.jsonl>`.

## Method

1. **Query type decides the surface.** `query_string` processes full Lucene syntax;
   `simple_query_string` processes `+`/`-`/quotes and never errors; `match`/`term` treat
   everything as literal text (no injection). Probe with `test AND *:*` vs `test AND NOT *:*`
   (SQL-style `AND 1=1` is just terms to the analyzer), `*` vs a specific term, and `field:value`
   vs `value`.
2. **Negate the app's filter.** Apps often append `AND tenant_id:<current>`, `deleted:false` or
   `visibility:public`; an injected `OR` group or `NOT` around it is an access-control bypass.
3. **Enumerate fields** with `_exists_:<field>` and `<field>:*` against a nonexistent-field
   control; the fields the UI never shows (credentials, PII, internal flags) are the finding.
4. **Extract** confirmed fields by regex or range binary search, or by count differentials when
   only totals come back.
5. **Parameter passthrough:** `index=`, `_source=`/`_source_includes=*` or similar reaching the
   query reads other indices or hidden fields.
6. **Direct cluster access** (`/_cat/indices`, `/_mapping`, `/_cluster/health` reachable without
   auth) is its own finding; read-only enumeration only. Snapshots, reindexing and any write need
   explicit operator approval (`agent/shared-constraints.md` §1); expensive-query probing is a
   denial-of-service test and needs it too.

## What to Record

Endpoint and parameter, query type, the fields reachable that the UI does not expose, the
extracted pattern shown working, cross-index or filter-bypass proof, and the attacker outcome
(`agent/rules/hunting.md` §2). Severity: `agent/references/finding-fp-and-severity-gate.md`;
format: `agent/references/runtime-guides/web-finding-recording.md`.

## Kill and escalate

- `match`/`term` only, or every metacharacter escaped, or `AND`/`OR`/`*`/`field:value` all
  literal → no injection surface. Bracket the negative with a positive control on a known-good
  syntax probe (`agent/rules/hunting.md` §13).
- Escalate when `*` widens results, `_exists_` or `field:value` changes them, errors expose index
  names or mappings, or cluster endpoints answer without auth.
