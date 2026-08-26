---
name: cors-testing
description: CORS misconfiguration testing for data theft and access control bypass
origin: Vigil
vuln_class: cors
---

# CORS Misconfiguration Testing

> **`vigil assess kali` audit flags:** use `--technique CORS` — `--probe-kind fingerprint`
> for the header-only baseline/reflection/preflight probes, `--probe-kind exploit` once you
> host and fire the credential-theft PoC. Route every crafted-`Origin` curl call and every
> Corsy run through `vigil assess kali exec`.

## When to Activate

- API returns `Access-Control-Allow-Origin` header
- Cross-origin requests observed in application flow
- Sensitive data served via API endpoints
- Single-page application with API backend

## Tools

- `vigil assess kali exec -- corsy -u <url>` — automates the origin-reflection / null-origin /
  wildcard / pre-flight sweep faster than hand-crafted curl; run this first.
- `vigil assess kali exec -- curl ...` — hand-craft the specific bypass classes Corsy doesn't
  try (suffix/prefix parser-confusion, verb tampering, Content-Type-based pre-flight dodge).

## Payload and Checklist Reference

`agent/references/payloads/cors-payloads.md` carries the full working checklist (baseline
capture, origin reflection, null origin, subdomain/regex bypass, wildcard, pre-flight bypass)
and the PoC HTML for each — work it top to bottom against the target.

## What to Record

Standard finding-record fields (`agent/shared-specialist-core.md`) plus the two values that
prove this class: the exact `Access-Control-Allow-Origin` / `Access-Control-Allow-Credentials`
values returned, and the `Origin` value that triggered them.

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
