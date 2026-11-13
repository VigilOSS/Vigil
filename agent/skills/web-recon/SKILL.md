---
name: web-recon
description: Enumerate web technologies, headers, endpoints, and metadata from a target
origin: Vigil
---

# Web Reconnaissance

## When to Activate

- Beginning of engagement, a new domain/subdomain, or a stack that needs fingerprinting before
  deeper testing.

Exact invocations: `agent/references/recon/web-recon-commands.md` (load when you run a step);
`vigil assess list-references --skill web-recon` lists per-tool references (plus
`agent/references/tools/recon/{nmap,katana}.md`, `agent/references/tools/fuzzing/ffuf.md`,
`agent/references/payloads/info-disclosure-probes.md` for those steps).

## Ordering

Default per live host on unknown internet-facing HTTP targets:
`wafw00f → nmap → httpx → whatweb → nuclei → ffuf → (nikto, aem-hacker IF triggered)`.

Declare an alternate ordering when the target shape warrants it, and record it with a one-line
rationale under `#### Coverage Gaps` (or `#### Tool Sequencing`); an undeclared skip is a
dispatch failure, a declared one is auditable:

- **IP-only scope** — start with nmap; the open ports decide whether HTTP fingerprinting applies.
- **Non-standard ports** — httpx against the explicit port URLs before nmap.
- **Internal / no-WAF target** — skip wafw00f; use the Origin / single-server row of
  `agent/references/recon/rate-calibration.md`.
- **Reactive sweep on an already-fingerprinted stack** — nuclei on the URL delta only.

## Steps

Treat each fingerprint as a hypothesis about deployment shape (proxy layers, framework, auth
boundaries, privileged workflows) and hand it to the next skill or phase.

**Step 0 — WAF detection, first.** The WAF result picks the row of
`agent/references/recon/rate-calibration.md` that sets the rate for every later tool
(`agent/references/tools/recon/wafw00f.md` "WAF-tier rate adjustment table" maps result to row).

**Step 0b — Egress reputation (operator-run; you review the verdict).** The operator runs
`vigil assess egress-check` once the live-host set exists. Review its `egress_decision`: repeated
403/000 are candidates, not cause proof (`000` = no HTTP answer observed; a WAF/edge response is
inconclusive; one control proves nothing estate-wide or per-route). On `cluster_blackholed` (at
least 80% of the sample blackholed with controls live, the `--block-threshold` default), stop
target-facing recon, wait five minutes and re-run the check; only a second `cluster_blackholed`
surfaces the operator's Egress reputation checkpoint
(`agent/references/runtime-guides/cdn-ip-blocking.md` owns the four mitigations and the give-up
rule). Only an observed blackhole's blocked-hosts file goes to
`vigil assess ingest endpoints --egress-blocked-hosts <file>` (defers as
`cluster_key=deferred:egress-blocked`). The appendix's manual sample is a fallback when the
verdict is missing.

**Step 1 — nmap.** `-T3` on shared infrastructure or an unknown WAF tier; the cautious profile
above on CDN/WAF-fronted or regulated targets (`agent/skills/port-scanning/SKILL.md` owns
profiles and the per-host port-data assertion). A cautious follow-up pass routinely captures
what `-T4` trips over: TLS SAN expansion (staging/internal names), rDNS vendor ownership,
per-host WAF tier, edge-auth identifiers (e.g. CDN-issued access JWTs), dense API clusters. The
depth comes from the rate, not extra scripts. Feed nmap SAN hosts back into enumeration/httpx.

**Step 2 — httpx** (`-tech-detect -title -tls-grab -status-code`). Capture `Server:`,
basic-auth realm, OPTIONS `DAV:`/`MS-Author-Via` and status patterns (the nikto triggers), and
diff headers across unauthenticated, error and alternate routes to expose proxies, app servers
and auth boundaries. **Browser-semantic trigger check:** when the curl/httpx baseline may not
be what a browser sees (interstitial, soft-200, SPA shell, browser-vs-curl delta), load
`agent/skills/browser-semantic-analysis/SKILL.md` before settling coverage and record the
baseline and browser command-run ids (or the gap) and the delta.

**Step 3 — whatweb** `-a 3` cross-validates httpx; it catches legacy ColdFusion, classic ASP and
niche WebSphere banners httpx misses. The union feeds the nikto triggers.

**Step 4 — nuclei, mandatory.** Run `agent/skills/nuclei-scanning/SKILL.md` "Reactive Sweep
Mode" on the URL delta (live hosts, SAN expansions, vhost hits) with
`-t http/cves/,http/exposures/,http/misconfiguration/,http/default-logins/,http/exposed-panels/,http/technologies/`,
so hits become candidates before Phase 4 dispatches.

**Step 5 — directory fuzz, mandatory L1.** `raft-small-directories.txt` plus stack extensions
(PHP `.phps,.phtml,.inc`; ASP `.aspx,.config,.asmx`; Java `.jsp,.do,.action`; generic
`.bak,.old,.orig,.swp,~`). Under-coverage here costs as much downstream as skipping nmap. L2/L3,
recursion and SaaS API namespaces: `agent/skills/directory-fuzzing/SKILL.md`.

**Step 6 — nikto, only on a trigger** from `agent/references/tools/recon/nikto.md` (legacy
Apache/IIS/nginx, ColdFusion, Tomcat < 8, JBoss, WebLogic, WebSphere, Domino, SAP NetWeaver,
Siebel, embedded servers, WebDAV, basic-auth realms, intranet scope). Otherwise skip: nuclei
covers the common surface and blind nikto adds false positives.

**Step 7 — product-specific probes.** On a CMS fingerprint run the quick CMS checks (WordPress
login and `wp-json/wp/v2/users`, Joomla `/administrator/`, Drupal `CHANGELOG.txt`). On Adobe
Experience Manager (`/crx/`, `/content/dam/`, `/libs/granite/`) run `aem-hacker` inventory/read-only
checks through `vigil assess kali exec`; destructive or exploit modules need a VA/exploit-developer
dispatch and explicit authorization.

**Step 8 — TLS.** Pull SAN/CN/issuer/validity and supported protocol versions per host; SANs are adjacent surface.
**TLS / SAN / vhost cross-host:** when SANs span tenants, a CDN/edge fingerprint appears, or rDNS
points at a shared platform, load `agent/skills/tls-vhost-correlation/SKILL.md` (multi-time DNS
split-VIP check, cross-host SAN collision, vhost-cert mismatch; recipes in
`agent/references/tools/recon/openssl-sans.md`) before leaving Phase 1.

**Step 8b — vendor-template CSP/CORS re-baseline.** When a vendor product is fingerprinted
(Salesforce Communities, ServiceNow, Drupal, Pexip Infinity, appliances), re-capture headers and
check for installer-template defaults: placeholder literals (`example.org`, `localhost`,
`domain-here.tld`, `your-domain.tld`, `placeholder`) in CSP / ACAO / Permissions-Policy /
X-Frame-Options; `'unsafe-inline'` and `'unsafe-eval'` together in one `script-src`; broad
sources (`*.amazonaws.com`, `*.cloudfront.net`, bare `https:`, `data:`/`blob:`) in `script-src`.
One hit means fetch the vendor's hardening checklist: three or more failed items is the finding
pattern ("the checklist was skipped"), not the single directive. Regexes and per-vendor known
defaults: `agent/references/payloads/csp-default-grep.md`.

**Step 9 — well-known files**: robots, sitemap, security.txt, crossdomain/clientaccesspolicy,
`.well-known/openid-configuration`.

**Step 10 — JS surface.** List bundles and hand them to source-analyzer. The recon job's
`vigil assess js-mining` stage (jsluice + route patterns + trufflehog, ingested as `js-extract`)
complements the deep pass; include its endpoint and secret counts in the completeness verdict.
Queue only endpoints that are directly requestable and evidenced by a real response or real
HTML/form/link extraction; directory stems, SPA routes and guessed names stay notes or surface
candidates.

**Step 11 — API surface**: OpenAPI/Swagger paths and GraphQL endpoints (POST `{__typename}`).

**Step 12 — recon to hypothesis.** Proxy + framework leakage → route normalisation, cache
confusion, trust-boundary mistakes. Auth-protected admin/internal routes → realistic escalation
paths. Error traces/versions → validate in stages. Shared cookie scope, API prefixes or odd host
routing → cross-app chains and auth-context drift.

## What to Record

Live hosts (status, title, server), stack (framework, CMS, server, WAF, CDN), WAF tier and the
rate profile chosen (every wafw00f result per host, a negative included, as a tech-component row
with `provenance.waf` and the `command_run_id` of a successful run whose target is that host), auth mechanism, API specs, admin endpoints, TLS details and SAN-surfaced
hosts, rDNS vendor identification, JS handed to source-analyzer, surface candidates, and a
coverage gap for every mandatory step that did not complete.

## Output Contract

Backend writes (`finding record`, `intel record`, `record-surface`, `vigil assess agent handoff`)
are the durable record; these sections make the return payload parseable downstream.

| Section | Holds |
|---|---|
| `#### Summary` | What was scanned, WAF tier, live-host count, vendor-SaaS hits, egress block %. |
| `#### Live Hosts` | Live in-scope hosts with status, title, server banner, tech-detect. |
| `#### Findings` | Findings the recon pass already proved, each also recorded via `vigil assess finding record`. |
| `#### Surface Candidates` | Routes/hosts evidenced by a real response, ready for `vigil assess record-surface`. |
| `#### Intelligence` | Stack, TLS/SAN, rDNS vendor, versions, vendor-template CSP/CORS placeholders, build constants — each via `vigil assess intel record <type>`. |
| `#### Coverage Gaps` | Every mandatory step not completed, conditional steps fired and why, declared skips, untriggered shared-frontend sub-procedures. |
| `#### Recommended Phase 4 Ordering` | Risk-ranked surface clusters with the recommended specialist + skill. |
