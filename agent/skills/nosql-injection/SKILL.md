---
name: nosql-injection
description: NoSQL injection detection and exploitation — MongoDB operator injection, Mongoose/ORM bypass, blind extraction, and modern defense realities
origin: Vigil
---

# NoSQL Injection Testing

## When to Activate

- Application uses MongoDB, CouchDB, or another document database
- Login forms, search features, or API filters backed by document databases
- Node.js/Express stack with Mongoose ORM (most common target)
- Parameters may reach NoSQL queries via operator injection or JavaScript execution

## Reality Check

NoSQL injection in 2025 primarily targets MongoDB through Mongoose/Express apps that pass `req.body` directly to queries without type checking. The classic `{$ne:""}` auth bypass is well-known but still works on roughly 20% of Node.js apps tested. The attack surface has narrowed — `$where` JavaScript execution is removed since MongoDB 5.0, and inline scripting in Elasticsearch has been off by default since ES 5.x. The real game is operator injection through type confusion: sending JSON objects where the application expects strings.

## Tools

- `vigil assess kali exec -- curl ...` (manual injection probing and payload delivery — all target-facing curl must go through the kali exec wrapper; use `--technique NOSQLI --probe-kind payload --phase consume-test --timeout 30` for injection attempts)
- `vigil assess anomaly-score <responses.jsonl>` (rank a boolean/blind response population to find the odd-one-out — see "Boolean via Response Differences" below)
- `vigil assess classify-payload <value> --mutations` (type and mutate a scalar auth-bypass value such as a username or email — see Step 2 below)
- Browser DevTools (observe JSON request bodies and responses)

---

## Decision Tree

### Step 1: Identify the Database

Before spraying payloads, determine what you are targeting. Wrong payloads waste time and trigger defenses.

**MongoDB indicators:**
- Error messages containing `MongoServerError`, `$operator`, `BSONObj`, `CastError`, `ValidationError`
- Mongoose-style validation errors: `"message": "Cast to string failed for value"`
- ObjectId format in URLs or responses: 24-character hex strings (`507f1f77bcf86cd799439011`)
- Node.js/Express stack (check `X-Powered-By: Express`, npm package indicators in JS)

**CouchDB indicators:**
- `/_utils/` Fauxton admin panel accessible
- Response JSON with `_id`, `_rev` fields
- Error format: `{"error":"not_found","reason":"missing"}`
- Endpoints like `/_all_dbs`, `/_session`

**Elasticsearch indicators:**
- `/_cluster/health`, `/_cat/indices` endpoints responding
- Lucene query syntax in search parameters (`field:value`, `+`, `-`, `AND`, `OR`)
- Response format with `hits`, `_source`, `_score` fields

**If you cannot identify the database**, start with MongoDB operator injection — it is the most common target and the payloads are distinctive enough to confirm or rule out quickly.

### Step 2: Test Operator Injection First

Operator injection has the highest success rate because it exploits type confusion — the application expects a string but receives a JSON object with a MongoDB query operator.

**Auth bypass (test both JSON and URL-encoded):**

JSON body (requires `Content-Type: application/json`):
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
```

URL-encoded (works on Express apps that use `qs` parser with bracket notation):
```
username[$ne]=&password[$ne]=
username=admin&password[$gt]=
username[$regex]=.*&password[$regex]=.*
```

**What to look for:**
- Auth bypass: login succeeds without valid credentials → immediate finding
- Different error message: "Invalid password" vs "User not found" → username enumeration via operators
- Application crash or stack trace: confirms injection point even if exploitation needs refinement

**Typing the target identity value.** The operator payload's structure (`{"$ne": ""}`) is fixed, but the *username/email side* you pair it with is a scalar worth mutating. Classify it and pull the `escalation` bucket to enumerate likely-privileged accounts deterministically:

```bash
vigil assess classify-payload "user@example.com" --mutations   # type: email → escalation: admin@example.com, root@localhost, administrator@example.com
vigil assess classify-payload "507f1f77bcf86cd799439011" --mutations   # an ObjectId-shaped value (type: hex) → neighbor yields the adjacent ObjectIds for IDOR-style pivots
```

Use these as the `username` in `{"username": "<escalation-variant>", "password": {"$gt": ""}}` to target a specific admin identity rather than relying on the operator alone. The operator objects themselves are not value-typed (they are query structures, not scalar values) — keep pulling those from the payload reference.

### Step 3: If Operators Blocked, Test $where JavaScript

`$where` allows JavaScript execution in the query context. It is deprecated since MongoDB 4.2 and removed in 5.0, but many production databases run older versions.

```json
{"$where": "1==1"}
{"$where": "this.username == 'admin'"}
{"$where": "this.password.match(/^a/) ? true : false"}
```

**Gate check**: if the application returns results for `{"$where": "1==1"}` but not `{"$where": "1==2"}`, JavaScript execution is confirmed. On MongoDB 5.0+, these will return an error about `$where` not being supported.

### Step 4: Blind Extraction via $regex

When you have confirmed operator injection but need to extract data (passwords, tokens, internal fields), `$regex` binary search is the standard method.

---

## Mongoose/ORM Bypass Techniques

These bypasses target the common pattern where developers believe Mongoose or Express middleware protects them.

### Content-Type Switching

The single most effective bypass. Many applications sanitize URL-encoded form parameters but pass JSON bodies directly to MongoDB queries.

```
# Application expects form data, sanitizes it
POST /login
Content-Type: application/x-www-form-urlencoded
username=admin&password=test123

# Switch to JSON — same endpoint, operators now parsed as objects
POST /login
Content-Type: application/json
{"username": "admin", "password": {"$gt": ""}}
```

**Why this works**: Express `body-parser` (or `express.json()`) parses the JSON body into a native JavaScript object. `{"$gt": ""}` becomes an actual object with a `$gt` key, which MongoDB interprets as a query operator. URL-encoded `password[$gt]=` relies on `qs` bracket parsing, which some sanitizers strip. JSON bypasses that layer entirely.

### Array Injection via Query String

Express `qs` parser converts bracket notation to nested objects. This works even when the application only expects flat string parameters:

```
# These create operator objects in req.query:
GET /api/users?username[$ne]=&role[$ne]=
GET /api/search?filter[$gt]=&sort[$regex]=.*

# Nested operators:
GET /api/users?password[$regex]=^a&password[$options]=i
```

**When to use**: API endpoints that accept query parameters for filtering/searching. The developer tested with Postman sending strings but never tested what happens when the query parser creates objects.

### Prototype Pollution to Query Manipulation

If the application has a separate prototype pollution vulnerability (check with `__proto__` or `constructor.prototype` injection), it can be chained:

1. Pollute `Object.prototype` with a MongoDB operator key
2. All subsequent query objects inherit the polluted property
3. Queries that were safe now contain injected operators

This is a chain — not a standalone NoSQL injection technique — but it converts "no injection point" into a viable attack path.

---

## Blind Extraction Methodology

### $regex Binary Search

When operator injection is confirmed but the application only returns boolean signals (login success/failure, result count changes, different error messages):

**Character-by-character extraction:**

```
Step 1: Confirm injection — {"password": {"$regex": "^.*"}} → true
Step 2: Find first character
  {"password": {"$regex": "^a"}} → false
  {"password": {"$regex": "^b"}} → false
  ...
  {"password": {"$regex": "^s"}} → true
Step 3: Find second character
  {"password": {"$regex": "^sa"}} → false
  ...
  {"password": {"$regex": "^se"}} → true
Step 4: Continue until {"password": {"$regex": "^secret123$"}} → true
```

**Optimization**: instead of linear search (26+ requests per character), use binary search on character ranges:

```
{"password": {"$regex": "^[a-m]"}} → narrows to first/second half of alphabet
{"password": {"$regex": "^[a-g]"}} → further narrows
{"password": {"$regex": "^[a-d]"}} → etc.
```

This reduces to approximately 5-6 requests per character instead of ~36 (alphanumeric + special).

**Realistic speed**: 5-6 requests per character, ~10 characters average password = 50-60 requests per field extraction. At 2 requests/second with rate limiting consideration, expect 30-60 seconds per field. Plan accordingly — extracting 50 user passwords is 25-50 minutes.

**Case sensitivity**: MongoDB regex is case-sensitive by default. Add `$options: "i"` if you need case-insensitive matching, but be aware this makes extraction ambiguous (uppercase vs lowercase).

### Time-Based Blind (MongoDB < 5.0 only)

If `$where` JavaScript execution is available but the application returns identical responses:

```json
{"$where": "if(this.password.match(/^a/)){sleep(3000);return true}else{return false}"}
```

**Baseline protocol** (same as command injection):
1. Send 3 normal requests, record response times
2. Test with 3-second sleep
3. Confirm with 6-second sleep
4. Look for consistent differential, not absolute timing

**Limitation**: `sleep()` in `$where` blocks the MongoDB query thread. On busy databases, this can cause visible performance degradation. Use sparingly and with short delays.

### Boolean via Response Differences

Often more reliable than timing. Look for:
- Login success vs failure (most obvious)
- Different HTTP status codes (200 vs 401)
- Different response body length
- Different error messages ("invalid password" vs "user not found")
- Different redirect targets
- Result count in search/list endpoints

**Finding the differential mechanically.** When the always-true (`{"$ne":""}`) and always-false (`{"$eq":"__nope__"}`) responses look nearly identical, do not eyeball them — capture each as a record and let the anomaly oracle surface which attribute actually flipped:

```bash
# one JSONL line per probe: {"url":"login#ne","status":200,"content_length":842,"words":61,"lines":12}
vigil assess anomaly-score nosql_probes.jsonl --top 5
```

The oracle ranks on `status`, `length_bucket`, `words_bucket`, and `title`, bucketing near-equal sizes so login-form jitter clusters and a per-response CSRF token cannot dominate the score. If the true-operator and false-operator rows split into different buckets, that is your boolean oracle — use it to drive the `$regex` binary search below (the field flips the response the same way). If both score ~0 alongside a benign string baseline, the query is not attacker-controllable on this signal: move on. This is also the triage pass for a `$regex`-range fuzz: feed the per-range responses in and investigate the top-ranked outlier first.

---

## CouchDB Testing

CouchDB has a different attack surface than MongoDB. Test these if CouchDB is identified.

- [ ] **Admin panel**: `GET /_utils/` — Fauxton admin interface, often exposed
- [ ] **Admin party**: `PUT /_config/admins/attacker` with password value — if no admins are configured, anyone can create one
- [ ] **Database listing**: `GET /_all_dbs` — enumeration of all databases
- [ ] **Document dump**: `GET /dbname/_all_docs?include_docs=true` — full content of all documents
- [ ] **Mango query injection**: if user input reaches `_find` selectors:
  ```json
  POST /dbname/_find
  {"selector": {"password": {"$regex": "^a"}}}
  ```
- [ ] **View injection**: if views accept user input in map functions (rare but devastating):
  ```json
  {"map": "function(doc) { emit(doc._id, doc.password); }"}
  ```

---

## Elasticsearch Testing

If Elasticsearch is identified (via Step 1 indicators), load the dedicated skill:

**→ `agent/skills/elasticsearch-injection/SKILL.md`** — full methodology for query_string injection, field enumeration, data extraction, cross-index access, and access control bypass.

**Quick gate check (3 probes to confirm ES injection surface exists):**

- [ ] `search=test AND 1=1` vs `search=test AND 1=2` — result sets differ → query_string confirmed
- [ ] `search=*` — returns more results than specific term → Lucene syntax active
- [ ] `search=_exists_:password` — results change → field-qualified queries work

If any gate fires, switch to the dedicated ES skill. Do not improvise ES testing from this skill.

---

## Modern Defenses and Their Gaps

### mongo-sanitize (npm package)

**What it does**: strips keys starting with `$` from objects before they reach MongoDB.

**Known bypasses:**
- Does not sanitize nested objects by default in some versions — `{"password": {"nested": {"$gt": ""}}}` may pass through depending on query structure
- Does not protect against `$where` injection when the entire value is passed to `$where`
- Only works on the specific object passed to it — if the developer sanitizes `req.body` but the query also uses `req.query`, the query parameters are unprotected

### Mongoose Strict Mode

**What it does**: `strict: true` (default) prevents saving fields not defined in the schema.

**What it does NOT do**: it does not prevent operator injection in query conditions on defined fields. If `password` is a defined String field, `{"password": {"$gt": ""}}` still works as a query operator — strict mode only applies to document creation/updates, not query filters.

### Express Query Parser (qs)

**What it does**: parses `?password[$gt]=` into `{password: {$gt: ""}}`.

**Defense attempt**: some apps set `app.set('query parser', 'simple')` to use Node's native `querystring` module, which does NOT parse bracket notation.

**Bypass**: switch to JSON body (`Content-Type: application/json`) — the query parser setting does not affect body parsing.

### Input Type Validation

The actually effective defense: validate that `req.body.password` is a string before passing it to the query.

```javascript
// This is what stops NoSQL injection:
if (typeof req.body.password !== 'string') return res.status(400).send('Invalid input');
```

If the application does type checking, operator injection is blocked. Look for endpoints where type checking was missed — search endpoints, filter APIs, and bulk operations are commonly overlooked even when login is protected.

---

## WAF / Filter Bypass

- [ ] Unicode encoding of operators: `\u0024ne` for `$ne` — bypasses string-matching WAFs
- [ ] Nested object depth: `{"password": {"$not": {"$eq": ""}}}` — semantically equivalent to `$ne` but different structure
- [ ] Mixed Content-Type: send JSON body with `application/x-www-form-urlencoded` Content-Type header — some WAFs only inspect bodies matching the declared Content-Type
- [ ] Double encoding: `%2524ne` for `$ne` — bypasses single-decode WAFs
- [ ] `$not` + `$eq` instead of `$ne`: `{"password": {"$not": {"$eq": "wrong"}}}` — equivalent result, different operator name
- [ ] `$nin` with empty array: `{"password": {"$nin": []}}` — matches all documents, less commonly filtered than `$ne`

---

## What to Record

- Injection point (endpoint, parameter, Content-Type variant that worked)
- Operator syntax accepted (e.g., `$ne`, `$gt`, `$regex`, `$where`)
- Proof of exploitation — confirming a different response to operator vs string input is not enough; you must show the **attacker outcome** (e.g., `{"username":"admin","password":{"$ne":""}}` logged in as admin without credentials and the session token granted access to `/admin/users` listing 1,500 accounts; `$regex` blind extraction recovered the admin password `Hunter2!` after 340 requests, and the password authenticated via the normal login flow; auth bypass via `$gt: ""` confirmed by the response containing the admin JWT with `role: "admin"` claim)
- Extraction speed and feasibility (requests/second, characters/minute)
- MongoDB version indicators (from error messages or behavior differences)
- Severity: Critical (auth bypass → admin access), High (data extraction), Medium (confirmed injection, limited extraction)

## Kill Signals — Stop Testing When
- Application validates input types (string fields reject objects/arrays) on all parameters → operator injection blocked, move on
- $ne and $gt operator injection fail AND $where returns error "not allowed" → MongoDB 5.0+ with scripting disabled, move on
- Blind $regex extraction exceeds 100 requests with rate limiting >2s/request → record as confirmed (HIGH) but note "manual extraction required", stop automated extraction
- Auth bypass via operator injection succeeds → CRITICAL, record finding immediately

## Escalate When
- Sending `{"field": {"$ne": null}}` or `field[$ne]=x` produces a different response (different length, different count, different status) than the literal string `x` — the backend is parsing operator syntax, enumerate `$gt`, `$regex`, `$exists`, `$in`, `$where`, `$function` before declaring the parameter safe
- A JSON body is accepted where the route originally took URL-encoded form data (or vice versa) — body-parser confusion lets attacker inject operator objects the validator never sees, retest every param with both encodings
- `$regex` or `$where` triggers a measurable timing delta (regex catastrophic backtracking, sleep via `$where: "sleep(1000)"`, `$function` in modern Mongo) — blind extraction works even without body parity, build the per-character oracle
- Login/search/filter endpoints accept nested JSON on any authentication, password-reset, or 2FA-verify route — these are auth-bypass gold, walk every operator against every auth-surface parameter
- Response length or count differs when injecting an always-true operator (`{"$ne":""}`) vs an always-false operator (`{"$eq":"__nope__"}`) — the query is attacker-controllable, extract via boolean-blind regex even if errors are suppressed

## Extended Resources

- `agent/references/payloads/nosql-injection-payloads.md` — MongoDB operators ($gt, $ne, $regex, $where), auth bypass, blind extraction
