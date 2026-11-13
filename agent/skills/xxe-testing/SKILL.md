---
name: xxe-testing
description: Detect and exploit XML External Entity injection for file read, SSRF, and blind data exfiltration
origin: Vigil
vuln_class: xxe
---

# XXE Testing (XML External Entity Injection)

## When to Activate

- XML is parsed anywhere: XML/SOAP APIs, a JSON endpoint that also accepts `application/xml`
  (switch the Content-Type and see), SVG/DOCX/XLSX/XHTML uploads, RSS/Atom import, SAML
  assertions, XML configs.

`--technique XXE`; deliver via `vigil assess kali exec --technique XXE --intent "<purpose>"
--probe-kind payload --phase consume-test --timeout 30 -- curl …`. `php://filter` source
read, external-DTD and error-based exfiltration, local-DTD override,
"XInclude and Encoding Bypasses" (XInclude when you control a value but not the DOCTYPE, UTF-16,
the CDATA wrapper), and SOAP/SVG/DOCX/XLSX carriers:
`agent/references/payloads/xxe-payloads.md`. Internal reach after an SSRF entity works:
`agent/skills/ssrf-testing/SKILL.md`.

## Method and the hard parts

- **Reflected:** a `SYSTEM "file:///…"` entity echoed in the response is file read; aim it at a
  file that matters (config, credentials), not only `/etc/passwd`. Java parsers sometimes list
  directories for `file:///etc/`.
- **Blind detection:** a parameter entity pointing at a minted host
  (`agent/references/offensive-tactics/frp-tunneling.md` "OOB Procedure (mint→poll→correlate)")
  shows the parser resolves external entities. That is the primitive, not impact.
- **Blind exfiltration** needs the target to fetch an attacker DTD, and the interactsh server
  serves nothing. Either ask the operator for a hosted listener (`$DIR/.listener_url`,
  `agent/shared-constraints.md` §12) and exfiltrate the file as a subdomain label of `$OOB_HOST`,
  or use the **local-DTD override** (redefine an entity from a DTD already on disk, e.g.
  fontconfig's) for error-based exfiltration with no hosting. Newlines break URL and label forms:
  single-line secrets go in a label; multi-line files need error-based or FTP exfiltration.
- **Bypasses:** UTF-16 encoding, XInclude where you control only a value, nested entity
  definitions against WAF patterns, HTML entities.
- **Entity expansion** (billion laughs, recursive entities, `/dev/random`) is a denial of service:
  only with operator approval and a single bounded probe (`agent/shared-constraints.md` §1).

## What to Record

Endpoint and vector (body, upload, header), payload, reflected vs blind, the matched callback pair
for blind cases, and what was read or reached (`agent/rules/hunting.md` §2): the contents of a
meaningful file, or metadata credentials via the SSRF entity. A blind callback with nothing read
is chain-only. Severity: `agent/references/finding-fp-and-severity-gate.md`; format:
`agent/references/runtime-guides/web-finding-recording.md`.
