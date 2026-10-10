---
name: gf-patterns:xxe
description: XML/SOAP endpoint and parameter patterns that signal XML external entity (XXE) injection surfaces
origin: Vigil (no upstream 1ndianl33t/Gf-Patterns equivalent exists)
bucket: xxe
skill: xxe-testing
weight: 40
---

# gf: xxe

## What this bucket classifies

Endpoints and parameters that hint the server parses attacker-influenced XML — SOAP web
services, XML-RPC-style APIs, WSDL-described services, and generic XML/RSS import features.
These are the raw surfaces for XML external entity injection: local file read via `SYSTEM`
entities, blind OOB exfiltration via a parameter entity + external DTD, and XXE-driven SSRF
(an entity that resolves to an internal URL).

## Load this reference when

- The corpus contains a `/soap` path segment or a `.wsdl` file
- A request's query/body/path params contain the key `xml`, `soap`, `wsdl`, or `rss`
- Tech fingerprinting shows a Java/.NET enterprise stack (WCF, Axis2, CXF, Spring-WS) — these
  overwhelmingly expose SOAP/XML endpoints
- The operator is triaging a `.svc`/`.asmx` row already clustered `gf:dotnet_handler`, or an
  `/xmlrpc.php` row already clustered `gf:wordpress` — both are real ADDITIONAL XXE surfaces
  (see "Related" below); this bucket does not re-claim those fragments (see next section)

## Parameter keys that match

`xml, soap, wsdl, rss`

All four are DELIBERATELY NOVEL — none collide with any other bucket's key set, so adding this
bucket cannot recluster a single existing row.

## Path patterns that match

`/soap`, `.wsdl`

Both fragments are also novel. Two related, genuinely XXE-relevant surfaces are
**intentionally not re-declared here** because another bucket already owns them at a higher or
tied weight and this bucket would only ever be a secondary (non-winning) match on those rows:

- `.svc` / `.asmx` (WCF/ASMX SOAP services) — already a `gf:dotnet_handler` fragment (weight 40)
- `/xmlrpc.php` (XML-RPC pingback) — already a `gf:wordpress` fragment (weight 35)

An operator triaging either cluster should still consider XXE alongside the bucket's primary
class (deserialization / user-enumeration respectively) — see "Related".

## Weight and priority interpretation

- Baseline priority score: 40 (tied with `ssrf`/`sqli`/`lfi`/`auth`/`deserialization`/
  `dotnet_handler`) — XXE is a serious, often-critical injection class
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/api/soap/orders?wsdl` — SOAP service with WSDL description
- `https://target.example/services/legacy.wsdl` — exposed WSDL definition
- `https://target.example/import?xml=<data>` — generic XML import endpoint
- `https://target.example/feeds/subscribe?rss=http://internal/feed.xml` — RSS/Atom import
  (also worth cross-checking against `ssrf` if the feed URL itself is server-fetched)
- `https://target.example/legacy/service.asmx?wsdl` — clusters `gf:dotnet_handler` (weight 40,
  declared first) but also matched here via `.wsdl`; both classes are worth testing

## What it does NOT classify

- Plain JSON/REST APIs with no XML surface — the mere presence of an `xml` query param on an
  otherwise-JSON API is weak-but-real signal; verify content-type before assuming XXE
- Static `.xml` **data** files served read-only (sitemaps, RSS feeds nobody parses server-side)
  — `interestingext` deliberately excludes bare `.xml` for the same flood reason

## Sources

- [OWASP WSTG — Testing for XML Injection (includes XXE)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection)
- [PortSwigger — XXE injection](https://portswigger.net/web-security/xxe)
- [YesWeHack — XML external entity: the ultimate Bug Bounty guide](https://www.yeswehack.com/learn-bug-bounty/xml-external-entity-guide-xxe)
- [PayloadsAllTheThings XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a/XXE%20Injection)

## Related

- `agent/skills/xxe-testing/SKILL.md` — the follow-up test skill (already existed before this bucket)
- `agent/references/gf-patterns/dotnet_handler.md` — adjacent bucket; `.svc`/`.asmx` SOAP
  endpoints are a real XXE surface even though they cluster there
- `agent/references/gf-patterns/wordpress.md` — adjacent bucket; `/xmlrpc.php` pingback is a
  real XXE/SSRF surface even though it clusters there
- `agent/references/gf-patterns/ssrf.md` — cross-check when an XML/SOAP endpoint also fetches
  a URL server-side (XXE-driven SSRF)
