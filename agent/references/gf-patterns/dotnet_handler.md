---
name: gf-patterns:dotnet_handler
description: ASP.NET / WCF HTTP-handler path and ViewState parameter patterns (.axd/.ashx/.asmx/.svc, _vti_bin, ELMAH, trace.axd)
origin: local overlay (no upstream gf equivalent)
bucket: dotnet_handler
weight: 40
---

# gf: dotnet_handler

## What this bucket classifies

ASP.NET and WCF HTTP-handler surfaces — the `.axd`/`.ashx`/`.asmx`/`.svc` handler
extensions, SharePoint/FrontPage `_vti_bin` SOAP endpoints, and the ELMAH and ASP.NET
trace handlers — where an attacker can reach a deserialization/RCE primitive
(ViewState/Telerik gadget chains), a padding-oracle, a SOAP/WCF service description
(`?wsdl`/MEX), or an unauthenticated log/trace disclosure. These surfaces are framework
infrastructure rather than application content, so they are high-value even when no
obviously vulnerable parameter is present.

## Load this reference when

- The corpus contains `.axd`, `.ashx`, `.asmx`, or `.svc` handler paths, `/_vti_bin/`
  SharePoint routes, or `/elmah.axd` / `/trace.axd` diagnostic handlers
- Param keys `__viewstate` or `__eventvalidation` appear in query strings or POST bodies
- Operator is assessing an ASP.NET / IIS / WCF / SharePoint application where the typer
  would otherwise drop these handlers to `unknown` (Issue A — pairs with typer Fix #15,
  which adds `axd|ashx|asmx|svc` to `_APP_ROUTE_EXT` so they type `page` instead of `unknown`)

## Parameter keys that match

`__viewstate, __eventvalidation`

`__viewstate` is the highest-signal key: it identifies an ASP.NET ViewState object graph
the server deserializes, and is the entry point for ViewState tampering / gadget-chain RCE.
`__eventvalidation` is the companion postback-integrity field; its presence confirms a
WebForms postback surface. This key set deliberately overlaps `deserialization`'s
`__viewstate` (see the tie-break note under "Weight and priority interpretation").

## Path patterns that match

ASP.NET / WCF handler extensions (leading-dot, boundary-anchored):
`.axd`, `.ashx`, `.asmx`, `.svc`

Specific diagnostic / SharePoint handlers:
`/_vti_bin/`, `/trace.axd`, `/elmah.axd`

The leading-dot extension fragments (`.axd`, `.ashx`, `.asmx`, `.svc`) are
boundary-anchored by `fragment_in_path` exactly like `interestingext`'s `.env`/`.bak`, so
`/WebResource.axd`, `/api.asmx`, `/Service.svc` and `/trace.axd` match, but a path like
`/report.axdx` does NOT (the trailing character is not a boundary). `/_vti_bin/`,
`/trace.axd`, and `/elmah.axd` are listed explicitly as the canonical product endpoints for
SharePoint SOAP, ASP.NET request tracing, and the ELMAH error log respectively.

## Weight and priority interpretation

- Baseline priority score: 40
- A .NET handler reachable from the edge is a direct deserialization/RCE pathway — weight
  matches `deserialization`, `ssrf`, `sqli`, `lfi`, and `auth` at 40, below only `rce` (50),
  `graphql` (45), and `secret_vault` (45)
- Declared AFTER `deserialization` in `_BUCKETS` (both weight 40) so that the shared
  `__viewstate` param resolves to `gf:deserialization` by the first-at-max-weight tie-break.
  The pinned `__VIEWSTATE` → `gf:deserialization` cluster
  (`test_classify_buckets_storage_deser_debug`) is preserved; `dotnet_handler` is recorded
  additively in the `priority_reason` chain alongside it.
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

Handler extensions (path-fragment):

- `https://target.example/WebResource.axd?d=...&t=...` — WebResource handler (padding-oracle surface)
- `https://target.example/Telerik.Web.UI.WebResource.axd?type=rau` — Telerik RadAsyncUpload handler
- `https://target.example/api/users.asmx?wsdl` — ASMX SOAP web service description
- `https://target.example/services/Account.svc?wsdl` — WCF service contract / MEX
- `https://target.example/handlers/upload.ashx` — generic ASP.NET HTTP handler

Diagnostic / SharePoint (path-fragment):

- `https://target.example/elmah.axd` — ELMAH error-log handler
- `https://target.example/trace.axd` — ASP.NET request-trace handler
- `https://target.example/_vti_bin/Lists.asmx` — SharePoint Lists SOAP endpoint

ViewState (param-key):

- `https://target.example/Default.aspx` (POST with `__VIEWSTATE=...&__EVENTVALIDATION=...`) —
  ASP.NET WebForms postback

## What it does NOT classify

- A page that merely renders `.aspx` with no handler extension or ViewState field — that is
  ordinary `page` content typed by `classify.py`, not a handler surface
- MAC-verified / encrypted ViewState whose payload cannot be tampered — the bucket fires on
  the param/path, not the integrity check; the specialist confirms exploitability
- `/report.axdx` and similar near-misses — the extension fragments are boundary-anchored, so
  a non-`.axd` trailing token does not match
- Generic `data=`/`payload=` serialized bodies with no .NET handler shape — those belong to
  `deserialization`; check the full `priority_reason` chain

## Attack classes

- **ViewState deserialization RCE:** an unprotected or MAC-bypassed `__VIEWSTATE` allows
  arbitrary object-graph injection (TypeConfuseDelegate / `LosFormatter` gadgets) leading to
  code execution
- **Telerik UI RadAsyncUpload RCE:** insecure deserialization of the `rauPostData` /
  encrypted upload-configuration field in `Telerik.Web.UI.WebResource.axd` (CVE-2019-18935)
- **WebResource/ScriptResource padding oracle:** the `.axd` `d=` ciphertext parameter is a
  CBC padding-oracle that yields plaintext recovery and forged-resource download
  (CVE-2010-3332 / MS10-070)
- **ELMAH log disclosure:** an unauthenticated `/elmah.axd` exposes captured exceptions,
  request bodies, cookies, and credentials
- **ASP.NET trace disclosure:** an enabled `/trace.axd` leaks per-request server variables,
  headers, and session data
- **SOAP/WCF metadata & service abuse:** `.asmx?wsdl`, `.svc?wsdl`, and `_vti_bin` SOAP
  endpoints disclose operation contracts and expose callable, often unauthenticated, methods

## Corpus grounding

835 `.axd`/`.ashx`/`.asmx`/`.svc` handler rows in the validation corpus, all at priority 0
before this bucket existed because the typer dropped the handler extensions to `unknown`
(Issue A). The `dotnet_handler` bucket plus the typer Fix #15 `_APP_ROUTE_EXT` addition
recover that surface. The zero-hit forward-looking endpoints (e.g. `/_vti_bin`, `?wsdl`)
are coverage for future ASP.NET / SharePoint engagements under the generic
coverage rule. See ADR 0008 and `DRIFT.md` for the accepted rationale.

## Sources

- [Microsoft MS10-070 — ASP.NET padding-oracle vulnerability (CVE-2010-3332)](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070)
- [NVD — CVE-2019-18935 (Telerik UI for ASP.NET AJAX insecure deserialization RCE)](https://nvd.nist.gov/vuln/detail/CVE-2019-18935)
- [Bishop Fox — Telerik UI RadAsyncUpload deserialization (CVE-2019-18935) write-up](https://bishopfox.com/blog/cve-2019-18935-remote-code-execution-in-telerik-ui)
- [ELMAH — Error Logging Modules and Handlers (elmah.axd)](https://elmah.github.io/)
- [Microsoft — WCF metadata endpoints (`?wsdl` / MEX)](https://learn.microsoft.com/en-us/dotnet/framework/wcf/feature-details/publishing-metadata-endpoints)
- [HackTricks — IIS / ASP.NET handlers and ViewState](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services)

## Related

- `agent/references/gf-patterns/deserialization.md` — canonical class sibling (`dotnet_handler` → `deserialization`); shares the `__viewstate` param and owns the tie-break cluster
- `agent/references/gf-patterns/rce.md` — direct RCE surface (Telerik/ViewState handlers are an indirect RCE pathway via gadget chains)
- `agent/references/gf-patterns/debug_logic.md` — diagnostic/debug disclosure surfaces overlapping ELMAH / `trace.axd`
- `agent/references/gf-patterns/interestingEXT.md` — boundary-anchored extension detection, the same `fragment_in_path` mechanism used for the `.axd`/`.ashx` fragments
