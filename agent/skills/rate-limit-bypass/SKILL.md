---
name: rate-limit-bypass
description: Identify rate limiting mechanisms and bypass them — CDN-specific header behavior, race condition exploitation, GraphQL batching, and practical impact calculation
origin: Vigil
vuln_class: rate-limit
---

# Rate Limit Bypass

Implementations differ: some count per IP (header spoofing), some per session/token (auth
rotation), some per request signature (structural mutation). Identify what is counted first;
most failed reports come from spraying `X-Forwarded-For` values without knowing what the
application counts.

`--technique RATE-LIMIT`; each probe sequence runs inside one `vigil assess kali exec … --intent …
--phase consume-test --timeout <N>` call as a named identity (idor-testing "Vigil mechanics").
Volume brute force (passwords, OTPs) is in scope unless the VDP forbids it (`agent/rules/hunting.md`
§10). Either way a small run that shows the limit no longer applies, plus the arithmetic (how long
the full keyspace now takes), is usually the proof.

## 1. Identify the limiter

Read `X-RateLimit-*`, `Retry-After` and `RateLimit-Policy` to size the window, then test which
key moves the counter: fresh session tokens from one IP (per-IP vs per-token), a second endpoint
after the first is limited (per-endpoint vs global), a changed User-Agent (rarely part of the
key, but exploitable when it is).

## 2. Bypass by key

- **Client-IP headers.** What works depends on the edge: Cloudflare overwrites
  `CF-Connecting-IP` but appends to and forwards `X-Forwarded-For`; ALB/CloudFront append; nginx
  trusts one configured header from configured peers; edge-set headers are spoofable only
  direct-to-origin. Per-edge semantics and payloads: `agent/references/payloads/rate-limit-bypass-payloads.md`
  (load once the edge is identified). Confirm over a longer rotation to spot a secondary limiter.
- **Counter race.** A non-atomic read-check-increment lets a single-packet burst through the
  window (`agent/skills/race-condition-testing/SKILL.md`). An atomic `INCR`/Lua-script limiter
  has no such window; a wide curl burst proves nothing either way.
- **GraphQL** usually limits per HTTP request, not per operation: alias/array batching
  (`agent/references/payloads/graphql-payloads.md`) and query-hash variation via no-op fragments
  (payload reference). Resolver injection patterns: `agent/references/code-vuln-patterns/web-app-injection.md` §6. Check support first with `[{"query":"{__typename}"},…]` and aliased
  `__typename`.
- **Account input normalization:** case, plus-addressing and encoding variants of the account
  key reset the counter when the limiter and the ORM normalise differently; confirm the variant
  acts on the same account.
- **Usually fails, works when:** random XFF fails behind appending proxies unless the app reads
  the leftmost entry; path variants fail when the framework normalises before a middleware
  limiter and work when the CDN/WAF limits the raw path; UA rotation is reconnaissance, not a
  bypass; method switching works only when the limiter is path-only and the path accepts other
  methods.
- **Unrated edges:** the same action on an alternate vhost, origin IP, API subdomain, mobile API,
  GraphQL mutation or WebSocket RPC is often outside the limiter.

## 3. Impact arithmetic

Severity rests on what the bypass makes feasible, so compute it from the measured rate and the
code's validity window: a 4-digit OTP is 10,000 guesses (100 s at 100 req/s; 17 min at 10 req/s);
a 6-digit OTP is 1,000,000 (2.8 h at 100 req/s, so infeasible inside a 5-minute expiry); top-100
passwords per account take 10 s at 10 req/s; UUID or 8-char alphanumeric API keys stay
infeasible regardless. A limit bypass on a harmless action is not a finding
(`agent/references/finding-fp-and-severity-gate.md`). Credential stuffing with breach data or
scraped directories needs explicit ROE.

## What to Record

Endpoint and method; what the limiter keys on; the baseline count and cooldown; the technique;
requests achieved beyond the limit (a number); whether it is repeatable; the impact arithmetic;
the edge/proxy identified. Format: `agent/references/runtime-guides/web-finding-recording.md`.

## Kill and escalate

- Per-session limiting with no header, path or race window → move on. A "no bypass" negative
  names the techniques, run ids and a positive control (`agent/rules/hunting.md` §13).
- A rotated IP header changes the remaining-quota header → enumerate the full set incl. CDN ones.
- Path, parameter-case/order or pollution variants yield different counters → walk them all.
- HTTP/2 plus an OTP/password/coupon/2FA field → single-packet burst.
