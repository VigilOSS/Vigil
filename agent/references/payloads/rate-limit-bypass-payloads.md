---
description: Rate-limit bypass payloads — client-IP header semantics per CDN/proxy (Cloudflare, ALB/CloudFront, nginx, Akamai, Fastly, direct-to-origin), path variation, account-input normalization, parameter pollution, GraphQL query-hash variation
skill: rate-limit-bypass
---

# Rate Limit Bypass Payloads

Load once the edge in front of the target is identified (wafw00f, headers, rDNS) and the limiter
is known to key on client IP. Spoofing a header only matters if the **application** (or the
limiter) reads it and the edge passes your value through unchanged.

## Client-IP headers by edge

- **Cloudflare.** The edge overwrites `CF-Connecting-IP` (and `True-Client-IP` where that
  Enterprise option is on) with your real address, so spoofing them through Cloudflare does
  nothing. It **appends** your address to `X-Forwarded-For` and forwards any value you sent, so
  an origin that reads the leftmost XFF entry trusts your spoof. `CF-Connecting-IP` /
  `True-Client-IP` are spoofable only when you reach the origin directly.
- **AWS ALB / CloudFront.** Both append: the origin sees `X-Forwarded-For: <spoofed>, <real>`.
  Leftmost-reading apps trust the spoof; rightmost-minus-trusted readers do not.
- **nginx `realip`.** `real_ip_header` names one header (commonly `X-Real-IP` or
  `X-Forwarded-For`); with XFF and `real_ip_recursive on` it takes the rightmost untrusted
  entry. `set_real_ip_from` limits which peers are trusted: a direct request carrying the header
  from an untrusted address is ignored, and no header bypass exists in that configuration.
- **Akamai / Fastly.** `True-Client-IP` (Akamai) and `Fastly-Client-IP` are set at the edge;
  they are spoofable only direct-to-origin or when the edge is configured to pass client values.
- **Direct to origin** (origin IP from asnmap/cero, history, or a misrouted vhost): send the
  edge's own header with your value and `Host: target.example`. Finding the origin is
  `agent/references/recon/cdn-edge-and-bff-reachability.md`.
- **Generic set** for an unidentified proxy: `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`,
  `X-Cluster-Client-IP`, `X-Originating-IP`, `X-Remote-Addr`, `X-Remote-IP`,
  `Forwarded: for=<ip>`, `True-Client-IP`, `CF-Connecting-IP`, `Fastly-Client-IP`, plus
  `X-Custom-IP-Authorization` and `X-ProxyUser-Ip`, which some 403 gates trust for an IP allowlist.

Confirm a candidate over a longer run (e.g. 100 requests rotating the value): all succeeding is
a bypass; 429s after N mean a secondary limiter.

## Path variation

`/api/login/`, `/API/LOGIN`, `/api//login`, `/api/./login`, `/api/login?`, `/%61%70%69/login`,
`/api/login;` (Tomcat), `/api/..;/api/login` (Spring). Frameworks normalise before middleware
limiters, so these mostly matter when the limit is applied at the CDN/WAF/proxy on the raw path.

## Account input normalization

`user@example.com`, `User@example.com`, `user@Example.com`, `user+tag@example.com`,
`user%40example.com`. Works when the limiter keys on the raw string but the ORM normalises
before lookup: hit the limit with the baseline, then check the variant both succeeds and acts on
the same account.

## Parameter pollution / cache busting

`?_=<timestamp>`, `?nocache=<random>`, `?utm_source=x`, duplicated or mixed-case keys
(`user=a&user=b`) when the key includes the raw query string.

## GraphQL query-hash variation

Limiters that hash the query string treat these as distinct while the operation is identical:

```graphql
query { login(username: "admin", password: "pass1") { token } }
query { login(username: "admin", password: "pass1") { token ...Noop } }
fragment Noop on LoginResult { __typename }
```

Alias and array batching (many operations per HTTP request) are in
`agent/references/payloads/graphql-payloads.md`.
