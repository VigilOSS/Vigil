---
description: nikto web scanner — conditional, fingerprint-gated (legacy/odd-stack triggers; nuclei is the primary web-vuln pass); --host flag, production-safe -Tuning x60, pacing, the plugins that justify it, and where each result class is recorded
skill: web-recon
---

# nikto — Conditional Web Vulnerability Scanner

The mandatory web-vuln pass is `kali nuclei` with the curated template set. Run `kali nikto` only
when the httpx/whatweb fingerprint matches a trigger below; otherwise it duplicates nuclei with
more false positives, slower runs and no signature-freshness advantage. Its value is a few plugins
no nuclei template covers.

## Trigger fingerprints — run nikto only when at least one of these is true

The triggers come from httpx/whatweb output already produced, so adding nikto is a routing
decision, not an extra fingerprint pass.

- **`Server:` header** contains `Apache/2.[02]`, `IIS/[67]`, `nginx/1.0` through `nginx/1.10`, or
  an unrecognised embedded-webserver banner (old banners map to modules in nikto's `outdated.db`).
- **Technology fingerprint** includes Siebel, ColdFusion, classic ASP, PHP < 7, Tomcat < 8, JBoss,
  WebLogic, WebSphere, Oracle HTTP Server, Lotus Domino or SAP NetWeaver Java.
- **Internal, intranet or appliance scope:** a network device, appliance or vendor management UI,
  where `cgi` and `put_del_test` find what internet-tuned templates miss.
- **`401` with a basic-auth realm** (the `apacheusers` and credential plugins' surface).
- **OPTIONS shows `DAV:` or `MS-Author-Via`** (WebDAV): `put_del_test` demonstrates write
  capability, where nuclei's WebDAV templates only read OPTIONS.

If none match, skip nikto; the reactive nuclei sweep covers the common surface.

## Standard invocation

```bash
vigil assess kali nikto \
  --host www.example.com -ssl \
  -Tuning x60 -Pause 2 -maxtime 300 \
  -Format json -output /engagements/$ENGAGEMENT_KEY/scans/nikto_www.json \
  --technique INFO-DISCLOSURE --intent "nikto on legacy IIS/7.5 fingerprint" \
  --probe-kind payload --phase recon --timeout 600
```

The target flag is `--host`: argparse reserves `-h` for help, and the wrapper builds nikto's own
`-h <host>`. Program attribution headers are injected through nikto's `-Add-header`.

**`-Tuning x60` is the production-safe default.** The `x` prefix excludes the listed categories:
`6` is Denial of Service and `0` is File Upload, so `x60` runs every other check class. The bare
form without `x` inverts the meaning to "run only these", and `-Tuning 6` runs only the DoS checks.
Keep both `0` and `6` in any exclusion string; `agent/shared-constraints.md` §1 and the program's
no-DoS ROE govern these checks.

## Pause and rate control

`-Pause 2` or more between requests on cautious-tier (rate-limited, regulated, WAF-protected)
targets; `-Pause 1` is usually enough on default-tier WAF-fronted ones. `-maxtime 300` ends the
scan before typical WAF lockout windows. When standard requests trip the WAF, nikto's `-evasion`
modes (combinable digits; `vigil assess kali tool-help nikto`) re-encode the request.

## Plugins that justify the run

- `apacheusers`: `mod_userdir` brute (`/~root`, `/~admin`, ...).
- `put_del_test`: uploads and removes a temporary file over WebDAV. It writes, so pass
  `--destructive`.
- `negotiate`: `mod_negotiation` MultiViews abuse that leaks alternate file content.
- `outdated.db`: banner-driven "N versions behind" advisory engine; nuclei has fingerprints but no
  curated outdated-version engine.
- `siebel`: Oracle Siebel probes.
- `cgi`: `/cgi-bin/` discovery plus a ~6,400-script database in one pass, faster than ffuf plus
  SecLists on legacy targets.

If the trigger that fired matches none of these, re-check whether nuclei alone is enough.

## Recording results

- Outdated server version: `vigil assess intel record tech-component` with `version` and
  `note=outdated`; it becomes a finding only after osint-analyst confirms a relevant CVE with a
  working PoC.
- Exposed `.htaccess` / `.svn` / `.git`: `vigil assess finding record` with
  `defect_family=info-disclosure` and the leaked path in `details.evidence`.
- Dangerous methods: TRACE is usually finding-worthy alone. PUT/DELETE need `put_del_test` to show
  the write before promotion; a methods banner alone is intel.
- Default or backup pages (admin consoles, install scripts, phpMyAdmin defaults):
  `vigil assess record-surface` with `type=privileged_write` or `type=auth_entry`.
- `outdated.db` CVE matches: `vigil assess intel record cve`, then a vulnerability-analyst dispatch
  validates applicability.
