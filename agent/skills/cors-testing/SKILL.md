---
name: cors-testing
description: CORS misconfiguration testing for data theft and access control bypass
origin: Vigil
vuln_class: cors
---

# CORS Misconfiguration Testing

> **`vigil assess kali` audit flags:** use `--technique CORS` — `--probe-kind fingerprint`
> for the header-only baseline/reflection/preflight probes, `--probe-kind exploit` once you
> host and fire the credential-theft PoC. Route every crafted-`Origin` curl call through
> `vigil assess kali exec`.

## When to Activate

- API returns `Access-Control-Allow-Origin` header
- Cross-origin requests observed in application flow
- Sensitive data served via API endpoints
- Single-page application with API backend

## Tools

- `vigil assess kali exec -- curl -s -i -H "Origin: …" …` for single probes; sweep a list of
  origins with `vigil assess kali sweep --values-file origins.txt -- curl -s -i -H "Origin: {}" …`.
  Include the classes scanners miss: suffix/prefix parser confusion, verb tampering, and the
  Content-Type pre-flight dodge.

## Payload and Checklist Reference

`agent/references/payloads/cors-payloads.md` carries the working checklist (baseline capture,
origin reflection, null origin, subdomain/regex bypass, pre-flight bypass) with the null-origin and
reflected-origin PoC HTML — work it top to bottom against the target.

## What to Record

Standard finding-record fields (`agent/references/runtime-guides/web-finding-recording.md`) plus the two values that
prove this class: the exact `Access-Control-Allow-Origin` / `Access-Control-Allow-Credentials`
values returned, and the `Origin` value that triggered them.

## Kill Signals — Stop Testing When
- Origin reflection + `Access-Control-Allow-Credentials: true` is the primitive, not the finding:
  prove a credentialed cross-origin read of sensitive data from a victim-shaped browser session.
  Chromium defaults cookies to `SameSite=Lax`, which withholds them from cross-site fetches, so
  the read works only for `SameSite=None` cookies, a same-site attacker origin (a subdomain), or
  non-Chromium victims. Without that proof it is chain-only
  (`agent/references/finding-fp-and-severity-gate.md`).
- `ACAO: *` → browsers never send credentials with it; impact is limited to IP- or network-based
  authorization (intranet APIs).
- Every origin variant rejected (null, subdomain, encoding, parser confusion) → restrictive;
  record the negative with a positive control (`agent/rules/hunting.md` §13).

## Escalate When
- The server reflects `Origin: null` with `Access-Control-Allow-Credentials: true` — sandboxed iframes, data: URIs, and redirected requests all produce null origin, the attack surface is real
- An allowlist check can be tricked by suffix/prefix match (`https://trusted.example.attacker.example`, `https://attacker-trusted.example`, `https://trusted.example@attacker.example`) — the regex is wrong, enumerate the full URL-parser confusion set
- Any subdomain of the target reflects or is whitelisted (`*.target.example`) AND you can get XSS/content control on any subdomain (old marketing site, staging, S3 takeover, user-controlled subdomain) — subdomain-to-apex CORS abuse is the classic chain
- The pre-flight response permits custom request headers, credentials, or non-simple methods for a broader origin set than the actual request check — CORS policies often diverge between preflight and actual response, test both
- A non-credentialed CORS read returns sensitive data (user profile, API keys, session metadata) even without `Allow-Credentials` — IP- or network-based authorization still leaks through a wildcard ACAO
