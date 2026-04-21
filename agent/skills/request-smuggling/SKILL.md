---
name: request-smuggling
description: HTTP request smuggling via CL.TE/TE.CL desync and cache poisoning
origin: AI Threat Hunting
---

# HTTP Request Smuggling Testing

> **Kali MCP audit headers:** when calling Kali MCP for work governed by this skill, set `X-Technique: REQUEST-SMUGGLING` and `X-Probe-Kind` per the phase — `fingerprint` for frontend/backend discrepancy probes (CL vs TE parsing), `payload` for crafted desync requests (CL.TE, TE.CL, TE.TE, HTTP/2 downgrade), `exploit` for cache-poisoning or request-queue-hijack proof against another user.

## When to Activate

- Application behind reverse proxy, load balancer, or CDN
- Multiple HTTP servers in request processing chain
- HTTP/1.1 in use between frontend and backend

## Tools

- `curl` (raw request crafting)
- Burp Suite Repeater (disable auto content-length update)
- smuggler.py (automated detection)
- HTTP Request Smuggler (Burp extension)
- Custom scripts for precise byte-level control

## Methodology

### 1. Identify Architecture

- [ ] Determine if frontend proxy exists (CDN, load balancer, WAF)
- [ ] Check HTTP version between client→frontend and frontend→backend
- [ ] Identify server software from headers (nginx, Apache, HAProxy, Cloudflare)
- [ ] Note: HTTP/2 downgraded to HTTP/1.1 internally = also vulnerable

### 2. CL.TE Detection (Frontend uses Content-Length, Backend uses Transfer-Encoding)

- [ ] Send request with both CL and TE headers:
      ```
      POST / HTTP/1.1
      Host: target.example
      Content-Length: 6
      Transfer-Encoding: chunked

      0

      G
      ```
- [ ] If next request gets `GPOST` → CL.TE confirmed
- [ ] Time-based: backend waits for more chunked data → timeout difference

### 3. TE.CL Detection (Frontend uses Transfer-Encoding, Backend uses Content-Length)

- [ ] Send:
      ```
      POST / HTTP/1.1
      Host: target.example
      Content-Length: 3
      Transfer-Encoding: chunked

      1
      G
      0

      ```
- [ ] If next request returns unexpected response → TE.CL confirmed
- [ ] Time-based: backend reads CL bytes only, rest poisons next request

### 4. Transfer-Encoding Obfuscation

- [ ] `Transfer-Encoding: chunked` (standard)
- [ ] `Transfer-Encoding : chunked` (space before colon)
- [ ] `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`
- [ ] `Transfer-Encoding: x\r\nTransfer-Encoding: chunked`
- [ ] `Transfer-Encoding:\tchunked` (tab)
- [ ] `Transfer-Encoding: chunked` (extra space)
- [ ] `X: x\r\nTransfer-Encoding: chunked` (header injection)
- [ ] Mixed case: `TrAnSfEr-EnCoDiNg: chunked`
- [ ] Line folding: `Transfer-Encoding:\n chunked`

### 5. Exploitation — Access Control Bypass

- [ ] Smuggle request to internal-only endpoint
- [ ] Access `/admin` path that frontend blocks
- [ ] Bypass IP-based restrictions by smuggling past frontend

### 6. Exploitation — Web Cache Poisoning

- [ ] Smuggle request that poisons cached response
- [ ] Victim receives attacker-controlled content from cache
- [ ] Inject malicious JavaScript via poisoned response

### 7. Exploitation — Credential Theft

- [ ] Smuggle partial request that captures next user's request:
      ```
      POST /store-comment HTTP/1.1
      Content-Length: 400

      comment=
      ```
- [ ] Next user's request (with cookies/auth) appended to comment body
- [ ] Read stolen headers from stored location

### 8. HTTP/2 Specific

- [ ] H2.CL smuggling: HTTP/2 with Content-Length to HTTP/1.1 backend
- [ ] H2.TE smuggling: inject Transfer-Encoding in HTTP/2
- [ ] Request splitting via header injection in HTTP/2 pseudo-headers
- [ ] CRLF injection in HTTP/2 header values

### 9. Validation

- [ ] Confirm desync with timing differential (10+ second difference)
- [ ] Use unique identifiers to track smuggled requests
- [ ] Test multiple times — smuggling can affect other users
- [ ] Be cautious: smuggling is disruptive in shared environments

## What to Record

- Frontend/backend architecture
- Smuggling type: CL.TE, TE.CL, H2.CL, or H2.TE
- Exact request bytes used for detection
- TE obfuscation technique that worked
- Exploitation achieved (access bypass, cache poison, credential theft)
- Severity: Critical (credential theft, cache poisoning) or High (access bypass)
- Remediation: normalize CL/TE handling, use HTTP/2 end-to-end, reject ambiguous requests

## Kill Signals — Stop Testing When
- Target uses HTTP/2 end-to-end with no downgrade → classic smuggling not applicable, test H2-specific only
- No proxy/load balancer detected (single server) → smuggling requires parsing disagreement between 2+ servers, move on
- CL.TE or TE.CL detection confirmed → record finding, proceed to exploitation, do NOT test remaining variants
- All detection techniques (CL.TE, TE.CL, TE.TE, H2) fail → infrastructure is aligned, move on

## Escalate When
- A timing-based smuggle probe (long CL + short body, or vice versa) produces a >5s hang on one payload but returns immediately on its control — parser disagreement is present, walk the full CL.TE / TE.CL / TE.TE variant set before declaring
- Response differs between `Content-Length: X` and `Transfer-Encoding: chunked` with the same body — the front and back disagree on framing, craft a smuggled prefix and hunt a cross-user cache or queue poison
- Headers like `Transfer-Encoding: chunked\r\nX-Foo: bar` or obfuscated forms (`Transfer-Encoding : chunked`, `Transfer-encoding: xchunked`, tabbed whitespace, duplicate TE) change behavior between requests — one proxy ignores them, the other parses them, that is the disagreement
- HTTP/2 is terminated at the edge and downgraded to HTTP/1.1 upstream — H2.CL and H2.TE request-splitting are live, test pseudo-header injection and H2 body desync even when H1 detection fails
- A smuggled request lands authentication/auth-bypass semantics on another user's connection (prefix injection of `X-Forwarded-For`, cache-key manipulation, host-header rewrite) — escalate immediately to cross-user impact, this is the real severity driver

## Extended Resources

- `agent/references/payloads/request-smuggling-payloads.md` — CL.TE, TE.CL, TE.TE obfuscation, HTTP/2 downgrade
