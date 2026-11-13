---
name: crlf-injection
description: Test for CRLF injection enabling HTTP response splitting, header injection, and log forging
origin: Vigil
vuln_class: crlf
---

# CRLF Injection Testing

## When to Activate

- Input is reflected into a response header (`Location`, `Set-Cookie`, custom headers), a
  redirect target, or a log line; or a proxy chain may re-encode characters.

`--technique CRLF`; send via `vigil assess kali exec --technique CRLF --intent "<purpose>"
--probe-kind payload --phase consume-test --timeout 30 -- curl -sv …` and read the raw response
headers (the injected header must appear as its own header line).

Most modern stacks (Node, Go, Java servlet containers, Python frameworks) reject CR/LF in header
values, so hits cluster in legacy code, custom header writers, and proxies or CDNs that decode
before forwarding.

## What to try

- **Targets:** header injection (`%0d%0aX-Injected:1`), `Set-Cookie` injection (session
  fixation), `Location` injection, full response splitting (double CRLF, then a body → XSS),
  and log forging in logged parameters.
- **Encodings:** `%0d%0a`, lone `%0a` or `%0d`, mixed case, double-encoded `%250d%250a`, a `%00`
  prefix, tab/space continuation after the CRLF, and the UTF-8 sequences some proxies normalise
  to CR/LF (`%E5%98%8A%E5%98%8D`, `%C4%8D%C4%8A`).
- **HTTP/2 downgrade:** CR/LF in a header value or pseudo-header that a front-end passes to an
  HTTP/1.1 back-end. curl cannot set pseudo-headers with `-H`; use a raw HTTP/2 client script run
  through `vigil assess kali exec` (`agent/skills/request-smuggling/SKILL.md` covers the
  downgrade family).
- **Log forging** proves itself with an inert marker line. Forged alert-looking lines
  (`[CRITICAL] …`) can page a real SOC, so they need the side-effect preflight
  (`agent/shared-constraints.md` §2d).

## What to Record

Injection point, the exact payload and encoding that worked, the raw response showing the injected
header or split body, and the outcome it enables (`agent/rules/hunting.md` §2): a fixed session
cookie, script execution in the split response, a redirect to an attacker origin. Header injection
with no outcome is a chain component (`agent/references/finding-fp-and-severity-gate.md`). Format:
`agent/references/runtime-guides/web-finding-recording.md`.
