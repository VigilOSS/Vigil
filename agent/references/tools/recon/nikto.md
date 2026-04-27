# nikto — Conditional Web Vulnerability Scanner

`nikto` is a **conditional** tool in the recon methodology. The mandatory web-vuln pass is `kali nuclei` with the curated template set (`http/cves/`, `http/misconfiguration/`, `http/exposures/`, `http/default-logins/`, `http/exposed-panels/`, `http/technologies/`). Run `kali nikto` only when the httpx fingerprint matches one of the trigger patterns below — otherwise nikto duplicates nuclei coverage with a higher false-positive rate, slower execution, and no signature-freshness advantage.

The unique value over nuclei sits in a small set of plugins (`apacheusers`, `put_del_test`, `negotiate`, `outdated.db`, `siebel`, `cgi`) plus the eight built-in WAF evasion modes. When the trigger fingerprints fire, those plugins do real work no nuclei template currently covers.

## Trigger fingerprints — run nikto only when at least one of these is true

The triggers come from the httpx output already produced during recon, so adding nikto is a routing decision, not an extra fingerprint pass.

- **`Server:` header** contains any of: `Apache/2.[02]`, `IIS/[67]`, `nginx/1.0` through `nginx/1.10`, or an unrecognized embedded webserver banner. Older banners often advertise unpatched modules nikto's `outdated.db` knows about.
- **Technology fingerprint** includes Siebel, ColdFusion, classic ASP, PHP < 7, Tomcat < 8, JBoss, WebLogic, WebSphere, Oracle HTTP Server, Lotus Domino, or SAP NetWeaver Java. These legacy stacks have nikto-specific plugins (e.g. `siebel`) with no nuclei equivalent.
- **Internal / intranet / appliance scope.** When the target is an internal network device, network appliance, or vendor management UI, nikto's exhaustive `cgi` and `put_del_test` checks find issues that public-internet-tuned templates miss.
- **`401 Unauthorized` with a basic-auth realm string** in the response. nikto's `apacheusers` and credential-discovery plugins are designed for this surface.
- **OPTIONS response contains `DAV:` header or `MS-Author-Via`** (WebDAV indicator). The `put_del_test` plugin actively demonstrates write capability — nuclei's WebDAV templates are read-only OPTIONS checks.

If none of these match, skip nikto entirely. The reactive nuclei sweep already covers the common-case web-vuln surface.

## Standard invocation

```bash
aith assess kali nikto \
  --host www.example.com --ssl \
  -Tuning x60 -Pause 2 -maxtime 300 \
  -Format json -output /engagements/$ENGAGEMENT_KEY/scans/nikto_www.json \
  --technique INFO-DISCLOSURE --intent "nikto on legacy IIS/7.5 fingerprint" \
  --probe-kind payload --phase recon --timeout 600
```

**CLI flag note:** `kali nikto` uses `--host <h>`, NOT `-h`. argparse reserves `-h` for help, so the typed wrapper exposes the target as `--host`. The underlying nikto invocation builds `nikto -h <host>` correctly inside the helper. Do not pass `-h` — argparse will print help and exit.

## Tuning — what to include and what to never include

`-Tuning x60` is the standard production-safe profile:

- `x6` excludes File Upload checks (which can write to the target).
- `x0` excludes DoS checks (never run against production).
- Combined as `x60` it skips both categories while keeping every other check class.

**NEVER use `-Tuning 6`** (no `x` prefix flips it from "exclude" to "only run") and **never include `6` in the tuning set** against any production-like target. The DoS checks are exactly what they sound like — they will impact target availability. The `agent/rules/hunting.md` "no destructive tests against production" rule applies here.

The full tuning category list (use only when researching a specific check class):

| Category | Code | Description |
|----------|------|-------------|
| Interesting File / Seen in logs | `1` | Files of interest, files mentioned in logs |
| Misconfiguration / Default File | `2` | Default install files, misconfigurations |
| Information Disclosure | `3` | Server status, robots.txt, etc. |
| Injection (XSS/Script/HTML) | `4` | Cross-site scripting checks |
| Remote File Retrieval — Inside Web Root | `5` | Inside-webroot file disclosure |
| Denial of Service | `6` | DoS — **NEVER run against production** |
| Remote File Retrieval — Server Wide | `7` | Server-wide file retrieval |
| Command Execution / Remote Shell | `8` | OS command injection |
| SQL Injection | `9` | SQL injection probes |
| File Upload | `0` | File upload abuse — destructive |
| Authentication Bypass | `a` | Auth bypass attempts |
| Software Identification | `b` | Banner / version fingerprinting |
| Remote Source Inclusion | `c` | RFI checks |
| WebService | `d` | SOAP / WebService probes |
| Administrative Console | `e` | Admin-panel discovery |

`x60` translates to "all categories EXCEPT DoS (`6`) and File Upload (`0`)" — the production-safe default.

## Pause and rate control

`-Pause N` inserts N seconds between requests. Cautious-tier (rate-limited / regulated) targets need `-Pause 2` (or higher). For default-tier WAF-fronted targets, `-Pause 1` is usually enough. Combine with `-maxtime 300` (5-minute wall-clock cap) so the scan ends before WAF lockout windows.

## Eight evasion modes — `-evasion <mode>`

When standard nikto requests trip the WAF, switch evasion mode. Each mode encodes the request differently; pick based on what the target is filtering:

| Mode | Technique | When to use |
|------|-----------|-------------|
| `1` | Random URI encoding (non-UTF8) | First evasion attempt against generic regex filters |
| `2` | Directory self-reference (`/./`) | When path-prefix matching is the filter |
| `3` | Premature URL ending | When the WAF examines the trailing path |
| `4` | Prepend long random string | When the WAF has a length cutoff before it inspects payloads |
| `5` | Fake parameter | When parameter-name filtering is suspected |
| `6` | TAB as request spacer (instead of space) | When whitespace normalization is the filter |
| `7` | Change case of URL | When the WAF is case-sensitive |
| `8` | Use Windows directory separator (`\`) | Only useful against Windows hosts |

Combine modes by adding the digits (e.g. `-evasion 124` for modes 1, 2, and 4). Most WAFs require mode-2 or mode-7 to be combined with another mode to slip through.

## cautious profile (rate-limited, WAF-protected)

```bash
aith assess kali nikto \
  --host www.example.com --ssl \
  -Tuning x60 -Pause 2 -maxtime 300 \
  --technique INFO-DISCLOSURE --intent "cautious-tier nikto, x60 production-safe" \
  --probe-kind payload --phase recon --timeout 600
```

Cross-reference the cautious-tier rate-limit profile in `agent/references/tools/recon/wafw00f.md` (run wafw00f FIRST so the WAF tier is known before nikto calibrates).

## Output formats

`-Format` accepts `csv | htm | json | txt | xml`. JSON is the most ingestion-friendly:

```bash
aith assess kali nikto \
  --host app.example.com \
  -Format json -output /engagements/$ENGAGEMENT_KEY/scans/nikto_app.json \
  --technique INFO-DISCLOSURE --intent "nikto JSON output for app.example.com" \
  --probe-kind payload --phase recon --timeout 600
```

The output file lands at `/engagements/$ENGAGEMENT_KEY/scans/nikto_app.json` because the runtime bind mounts engagement state at `/engagements/$ENGAGEMENT_KEY/`. Subsequent `aith assess` ingestion can pick it up directly without ferrying.

## Common findings

Nikto produces these classes of result; map each to the right intel/finding write:

- **Outdated server versions** (`outdated.db` plugin) — record as `aith assess record-intel tech-component` with `version` and `note=outdated`. Promote to a finding only after osint-analyst confirms a relevant CVE has a working PoC.
- **Exposed `.htaccess` / `.svn` / `.git` directories** — record as a finding via `aith assess record-finding` with `defect_family=info-disclosure` and the leaked path in `details.evidence`.
- **Dangerous methods enabled (PUT, DELETE, TRACE)** — TRACE is usually finding-worthy on its own (cross-site tracing). PUT/DELETE require `put_del_test` to actively demonstrate write capability before promoting to a finding; a methods-allowed banner alone is intel.
- **Default / backup pages** (admin consoles, install scripts, phpMyAdmin defaults) — record as `record-surface` with `type=privileged_write` or `type=auth_entry` depending on what the page exposes.
- **Known CVE matches** (`outdated.db` advisory engine) — record via `aith assess record-intel cve` and dispatch exploit-developer to validate before promoting to a finding.

## Plugin set — the unique-value-add over nuclei

These are the plugins that justify the conditional invocation. Nikto loads all of them by default unless `-Tuning` excludes their category:

- **`apacheusers`** — UserDir mod brute-force. Probes `/~root`, `/~admin`, `/~user`, etc. against Apache servers with `mod_userdir` enabled. No comprehensive nuclei equivalent.
- **`put_del_test`** — Active WebDAV PUT/DELETE write test. Uploads a temporary file and removes it. **This plugin does perform writes** — pair it with `--destructive` on the audit row. Nuclei's WebDAV templates are method-OPTIONS read-only.
- **`negotiate`** — Apache `mod_negotiation` MultiViews abuse. Almost no nuclei coverage. Useful when the target's MultiViews configuration leaks alternate file content.
- **`outdated.db`** — Banner-driven version advisory engine. Compares the `Server:` and tech banner against a curated database of known-vulnerable versions and emits "N versions behind latest" advisories. Nuclei has `http/technologies/` fingerprints but not a curated outdated-version advisory engine.
- **`siebel`** — Oracle Siebel-specific probes. Almost no nuclei coverage; if the fingerprint shows Siebel, this plugin is the reason to run nikto.
- **`cgi`** — Exhaustive `/cgi-bin/` discovery + ~6,400 dangerous-script database in one pass. ffuf+SecLists covers the directory side; nikto combines find-the-cgi-dir with test-every-known-script in one invocation, which is faster than the two-step alternative on legacy targets.

If the fingerprint that triggered nikto does not match one of those plugins, the unique-value-add is small — re-evaluate whether nuclei alone is sufficient.

## Notes

- All paths use `/engagements/$ENGAGEMENT_KEY/` because the runtime bind mounts engagement state there. Writing to `/tmp` loses output on container recreate.
- `kali nikto` records its audit row before exec so a crashed run still has a row showing what was attempted. Stdout and stderr stream to `${ENGAGEMENT_DIR}/scans/kali/<run-id>.{out,err}` from line one.
- For long sweeps (>30 minutes wall clock), wrap nikto in `aith assess kali job start --container-name security-research -- nikto ...` — the synchronous `kali nikto` call is killed cleanly on `--timeout` expiry.
