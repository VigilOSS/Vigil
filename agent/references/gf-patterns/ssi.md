---
name: gf-patterns:ssi
description: Legacy Server-Side Includes extension patterns that signal SSI directive injection surfaces
origin: Vigil (no upstream 1ndianl33t/Gf-Patterns equivalent exists)
bucket: ssi
weight: 30
---

# gf: ssi

## What this bucket classifies

Pages served under the classic Server-Side Includes extensions, where the web server parses
`<!--#directive ...-->` comments in the response before sending it — including
`<!--#exec cmd="..."-->`, which executes an OS command with the web-server process's
permissions. When user input reaches an SSI-parsed page unsanitized, an attacker can inject
their own directive for file disclosure (`<!--#include virtual="..."-->`) or command
execution. This is a legacy but real class — OWASP WSTG 4.7.8 "Testing for SSI Injection" is a
current, numbered test case.

## Load this reference when

- The corpus contains a `.shtml`, `.shtm`, or `.stm` extension — the traditional SSI-enabled
  extensions (note: some server configs enable SSI on plain `.html`/`.htm` too, which this
  bucket cannot see — extension absence does not prove SSI is off)
- A legacy Apache/IIS stack is fingerprinted, or the target is a long-lived enterprise app
  likely to carry pre-2010s pages
- A reflected-input page (search results, guestbook, comment page) is served under one of the
  matching extensions

## Parameter keys that match

None — SSI injection rides on whatever input field the page already reflects (search terms,
form fields, headers); there is no distinctive SSI-specific parameter name, so this bucket is
extension-only, mirroring `dotnet_handler`'s legacy-handler-extension idiom.

## Path patterns that match

`.shtml, .shtm, .stm`

All three are DELIBERATELY NOVEL — verified against `interestingext`'s extension list and
every other bucket's path fragments — so this bucket cannot recluster a single existing row.

## Weight and priority interpretation

- Baseline priority score: 30 (below `dotnet_handler`'s 40 — SSI is rarer and a lower triage
  priority in 2026 stacks than ASP.NET legacy handlers, but real and RCE-capable when present)
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/search.shtml?q=<!--#exec cmd="id"-->` — classic SSI command exec
  via a reflected search field
- `https://target.example/guestbook.shtm` — legacy guestbook page, common historical SSI target
- `https://target.example/includes/header.stm` — SSI-parsed page fragment

## What it does NOT classify

- SSI-enabled pages served under a non-legacy extension (`.html`/`.htm` with SSI turned on via
  server config) — no reliable extension signal exists for that case; confirm via response
  behavior (inject a harmless `<!--#echo var="DATE_LOCAL"-->` and check if it's evaluated),
  not via this classifier
- Client-side template injection or the modern SSTI engines (Jinja2/Twig/Freemarker) — those
  are the `ssti` bucket's signal

## Sources

- [OWASP WSTG — Testing for SSI Injection (4.7.8)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/08-Testing_for_SSI_Injection)
- [OWASP — Server-Side Includes (SSI) Injection](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection)
- [PortSwigger — SSI injection](https://portswigger.net/kb/issues/00101100_ssi-injection)

## Related

- No dedicated skill exists yet for this rare/legacy class — the `ssi-injection` canonical
  class is allowlisted skill-less in `test_vuln_taxonomy.KNOWN_SKILLLESS_CLASSES`, mirroring
  `ldap-injection`/`path-authz`. Dispatch to `command-injection` for exploitation methodology
  once an SSI-parsed reflection point is confirmed (the `<!--#exec-->` primitive is OS command
  execution).
- `agent/references/gf-patterns/dotnet_handler.md` — sibling legacy-extension bucket (the
  extension-only detection idiom this bucket mirrors)
