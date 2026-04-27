---
name: web-recon
description: Enumerate web technologies, headers, endpoints, and metadata from a target
origin: AI Threat Hunting
---

# Web Reconnaissance

## When to Activate

- Beginning of engagement, new domain/subdomain, need tech stack before deeper testing

## Tools

The recon methodology is mandatory by default — run every Mandatory step against every live
in-scope host. Conditional tools only fire when the fingerprint matches their trigger list.
"Optional only when the target clearly warrants it" is not a recon mode that exists in this
skill; under-coverage is the most expensive failure path because downstream specialists can
only test what the recon pass surfaces.

### Mandatory per target (run for every live host, in this order)

Tool order summary: `wafw00f → nmap → httpx → whatweb → nuclei → ffuf → (nikto IF triggered)`.

1. **`wafw00f`** — WAF identification. Run FIRST because the WAF tier drives the rate-limit
   choice for every later tool (nmap, httpx, ffuf, nuclei). See
   `agent/references/tools/recon/wafw00f.md` for the WAF-tier rate adjustment table.
2. **`nmap` port + service scan** — port and service discovery. Use the cautious-tier
   profile (CDN-fronted / WAF-protected / rate-limited regulated targets) documented in
   `agent/skills/port-scanning/SKILL.md` when the target is rate-limited or sitting
   behind shared infrastructure. The follow-up nmap pass is also where TLS SAN
   expansion, rDNS vendor identification, and per-host port-data assertions land.
3. **`httpx` fingerprint** — `-tech-detect -title -tls-grab -status-code` for live host
   confirmation, technology fingerprint, TLS metadata, and status. Drives the conditional
   nikto trigger evaluation in step 6 (server banner, basic-auth realm, WebDAV indicators).
4. **`whatweb`** — second-source technology fingerprinting. Cross-validate the httpx
   `-tech-detect` output; whatweb catches stacks httpx misses (and vice versa).
5. **`nuclei` with curated templates** — mandatory web-vuln pass. Templates:
   `-t cves/ -t exposures/ -t misconfiguration/ -t default-logins/ -t exposed-panels/
   -t technologies/`. The reactive sweep procedure lives in
   `agent/skills/nuclei-scanning/SKILL.md` "Reactive Sweep Mode"; this is the
   web-recon-side reminder that the pass is mandatory, not optional.
6. **`ffuf` or `feroxbuster` directory fuzz** — minimum L1 wordlist
   (`/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt`), tech-extension
   variants (PHP `.phps,.phtml,.inc`; ASP `.aspx,.config`; Java `.jsp,.do,.action`).
   Deeper passes live in `agent/skills/directory-fuzzing/SKILL.md`.

### Conditional (fingerprint-gated)

7. **`nikto` on legacy / odd-stack fingerprints** — only run when the httpx fingerprint
   matches one of the trigger patterns documented in
   `agent/references/tools/recon/nikto.md` (Apache/2.x, IIS/[67], nginx/1.0-1.10, Siebel,
   ColdFusion, Tomcat<8, JBoss, WebLogic, WebSphere, Domino, SAP NetWeaver, embedded
   webserver banners, WebDAV, basic-auth realms, internal/intranet scope). Skip nikto
   entirely when no trigger fires — nuclei already covers the common-case web-vuln
   surface.

When dispatching parallel scans, use the `aith assess kali job start` lifecycle (and stop
them with `kali job stop <id>`) instead of background-and-pkill — broad `pkill -f nmap` /
`pkill -f ffuf` stomps on sibling agents' processes in the shared runtime. See
`agent/references/runtime-guides/kali-cli.md` "Process cleanup discipline" for the full
pattern.

## Methodology

Treat each fingerprint as a hypothesis, not a trophy. Infer proxy layers, framework choices,
auth boundaries, and likely privileged workflows from small signals, then hand those
hypotheses to the next skill or phase for validation.

### Step 0 — WAF Detection (run FIRST)

```bash
# Single host
aith assess kali wafw00f --target https://TARGET \
  --technique RECON --intent "WAF tier identification, drives rate-limit choice for later tools" \
  --probe-kind fingerprint --phase recon --timeout 300

# Multi-host batch
aith assess kali wafw00f --input-list /engagements/$ENGAGEMENT_KEY/scans/live_hosts.txt \
  --technique RECON --intent "WAF tier sweep across in-scope live hosts" \
  --probe-kind fingerprint --phase recon --timeout 1200
```

Map the WAF identity to a rate-limit tier before starting nmap/httpx/ffuf/nuclei:

- **No WAF** → aggressive defaults (nmap `-T4`, httpx default rate, ffuf `-t 40`).
- **Basic WAF (modsec-rules tier)** → drop nmap rate by 50%, ffuf threads to 20.
- **CDN-fronted (any major CDN/edge)** → drop nmap to `-T3 --max-rate 200`, ffuf to
  `-rate 25`, nuclei `-rate-limit 75`.
- **WAF-protected / cautious-tier (enterprise WAF or high-friction policy target)** →
  `-T3 --max-rate 100 --max-retries 2 --host-timeout 300s`, ffuf `-rate 10`, nuclei
  `-rate-limit 25` and `-c 10`.

Full table and detection commands: `agent/references/tools/recon/wafw00f.md`. The
canonical per-target rate calibration table is in `agent/operator-core.md` "Recon
Dispatch Resource Policy" — the values above pull from that table.

### Step 1 — Port + Service Scan

```bash
aith assess kali nmap-scan --target www.example.gov \
  --scan-type top-1000 --scripts safe --extra-args "-T3 --max-rate 200 --max-retries 2 --host-timeout 300s" \
  --output-prefix /engagements/$ENGAGEMENT_KEY/scans/nmap_top1000 \
  --technique RECON --intent "cautious rate (CDN/WAF-fronted) initial nmap pass" \
  --probe-kind fingerprint --phase recon --timeout 900
```

Profile selection (see `agent/skills/port-scanning/SKILL.md` for the full list):

- **Lab / unrestricted** → default `-T4`.
- **Shared infrastructure / unknown WAF tier** → `-T3` (do not assume `-T4` is safe).
- **Cautious-tier profile (CDN-fronted / WAF-protected / rate-limited regulated targets)**
  → `-T3 --max-rate 200 --max-retries 2 --host-timeout 300s`.
- **Multi-host batch** → `-iL <hosts.txt>` with the same rate profile; the per-batch
  port-data assertion in port-scanning/SKILL.md catches host-timeout failures.

The follow-up nmap pass at a cautious rate routinely surfaces signal that aggressive
default `-T4` profiles miss: TLS SAN expansion (staging / internal subdomains),
rDNS vendor identification (CDN / SaaS edge ownership), per-host WAF tier mapping,
edge-auth identifiers (e.g. CDN-issued access JWTs), and dense API-cluster
footprints invisible to every other tool. The depth comes from the rate
calibration, not from extra scripts — defaulting to `-T4` against a regulated or
CDN-fronted host trips the rate limit and leaves this data uncaptured.

After the scan completes, extract TLS SAN hosts from the nmap output:

```bash
grep -oE 'DNS:[^ ,]+' /engagements/$ENGAGEMENT_KEY/scans/nmap_top1000.nmap | \
  sed 's/DNS://' | sort -u > /engagements/$ENGAGEMENT_KEY/scans/nmap_san_hosts.txt
```

Feed `nmap_san_hosts.txt` back into subdomain enumeration / httpx — TLS SANs
routinely surface staging hosts and adjacent services that passive sources miss.

### Step 2 — httpx Fingerprint

```bash
aith assess kali httpx --input-list /engagements/$ENGAGEMENT_KEY/scans/live_hosts.txt \
  --extra-args "-tech-detect -title -tls-grab -status-code -server -content-length -follow-redirects" \
  --output /engagements/$ENGAGEMENT_KEY/scans/httpx_fingerprint.jsonl \
  --technique RECON --intent "httpx tech + tls-grab fingerprint" \
  --probe-kind fingerprint --phase recon --timeout 900
```

Capture the `Server:` header, basic-auth realm, OPTIONS `DAV:`/`MS-Author-Via`, and
status-code patterns — those are the trigger inputs for the conditional nikto step.

```bash
# Compare headers across unauthenticated, error, and alternate routes
aith assess kali exec --technique RECON --intent "header diff across routes" \
  --probe-kind fingerprint --phase recon --timeout 60 -- \
  curl -sI -L https://TARGET
aith assess kali exec --technique RECON --intent "OPTIONS for DAV / methods detection" \
  --probe-kind fingerprint --phase recon --timeout 60 -- \
  curl -sI -X OPTIONS https://TARGET
```

Differences across routes often expose reverse proxies, app servers, framework routing,
and auth enforcement boundaries.

### Step 3 — whatweb (verify httpx tech)

```bash
aith assess kali exec --technique RECON --intent "whatweb deep technology fingerprint" \
  --probe-kind fingerprint --phase recon --timeout 300 -- \
  whatweb -a 3 https://TARGET
```

Cross-validate the httpx `-tech-detect` output. whatweb catches stacks httpx misses
(legacy ColdFusion banners, classic ASP signatures, niche WebSphere variants); the union
of httpx + whatweb is the input to the conditional nikto trigger logic.

### Step 4 — Nuclei (mandatory curated template set)

The mandatory invocation lives in `agent/skills/nuclei-scanning/SKILL.md` "Reactive
Sweep Mode" — run that procedure against the URL delta this step produces (httpx live
hosts, TLS SAN expansions, vhost-fuzz live hits). The template set:

```
-t cves/ -t exposures/ -t misconfiguration/ -t default-logins/ -t exposed-panels/ -t technologies/
```

Run nuclei reactively after the httpx pass so template hits become intel/finding
candidates *before* Phase 3 specialists dispatch. Treat the recon-side nuclei sweep
as required, not as the optional "broad scan before exploitation" of older runbooks.

### Step 5 — Directory Fuzzing (mandatory L1 wordlist + tech extensions)

```bash
aith assess kali ffuf --target https://TARGET/FUZZ \
  --wordlist /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt \
  --extra-args "-e .php,.html,.js,.txt,.bak,.old,.conf,.xml,.json,.yml,.env,.log,.sql,.zip -ac" \
  --output /engagements/$ENGAGEMENT_KEY/scans/ffuf_dirs.json \
  --technique RECON --intent "L1 directory fuzz with tech-extension variants" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

Tech-extension variants by stack:
- **PHP** — `.phps,.phtml,.inc`
- **ASP** — `.aspx,.config,.asmx`
- **Java** — `.jsp,.do,.action`
- **Generic** — `.bak,.old,.orig,.swp,~`

Deeper passes (L2/L3 wordlists, recursive feroxbuster, SaaS API namespace fuzzing) live
in `agent/skills/directory-fuzzing/SKILL.md`. The web-recon-mandatory minimum is L1 +
tech extensions; under-coverage at this step has the same downstream cost as skipping
nmap.

### Step 6 — Conditional Nikto

Evaluate the trigger fingerprints from `agent/references/tools/recon/nikto.md` against
the httpx + whatweb output. Run nikto only when at least one trigger fires:

```bash
aith assess kali nikto --host www.example.gov --ssl \
  -Tuning x60 -Pause 2 -maxtime 300 \
  -Format json -output /engagements/$ENGAGEMENT_KEY/scans/nikto_www_gov.json \
  --technique INFO-DISCLOSURE --intent "nikto on legacy IIS/7.5 fingerprint" \
  --probe-kind payload --phase recon --timeout 600
```

Skip nikto entirely when the fingerprint is a modern stack with no trigger match. The
reactive nuclei pass already covers the common-case surface; running nikto blindly
duplicates coverage at higher false-positive rate.

### Step 7 — CMS-Specific Probes

When httpx/whatweb identifies a CMS, the targeted probes still fire (these are quick
and not redundant with nuclei `technologies/`):

```bash
aith assess kali exec --technique RECON --intent "CMS detection probes" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -s https://TARGET/wp-login.php -o /dev/null -w "%{http_code}\n"     # WordPress
  curl -s https://TARGET/wp-json/wp/v2/users
  curl -s https://TARGET/administrator/ -o /dev/null -w "%{http_code}\n"   # Joomla
  curl -s https://TARGET/CHANGELOG.txt | head -5                            # Drupal
  curl -s https://TARGET/readme.html -o /dev/null -w "%{http_code}\n"
'
```

### Step 8 — SSL/TLS Analysis

```bash
aith assess kali exec --technique RECON --intent "TLS cert SAN/CN/issuer extraction" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  echo | openssl s_client -connect TARGET:443 -servername TARGET 2>/dev/null \
    | openssl x509 -noout -text \
    | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:"
  for proto in tls1 tls1_1 tls1_2 tls1_3; do
    echo | openssl s_client -connect TARGET:443 -$proto 2>/dev/null \
      | grep -q "Protocol" && echo "$proto: supported"
  done
'
```

The TLS cert SAN list often exposes adjacent hosts that should be added to the
engagement's discovered surface.

### Step 9 — Well-Known Files

```bash
aith assess kali exec --technique RECON --intent "well-known file checklist" \
  --probe-kind fingerprint --phase recon --timeout 120 -- bash -c '
  curl -s https://TARGET/robots.txt
  curl -s https://TARGET/sitemap.xml | head -50
  curl -s https://TARGET/.well-known/security.txt
  for path in crossdomain.xml clientaccesspolicy.xml humans.txt .well-known/openid-configuration; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$path")
    [ "$code" != "404" ] && echo "$path -> $code"
  done
'
```

### Step 10 — JS / HTML Surface (deferred to source-analyzer)

```bash
aith assess kali exec --technique RECON --intent "JS extraction for source-analyzer handoff" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -sL https://TARGET | grep -oE "src=\"[^\"]*\\.js\"" | sed "s/src=\"//;s/\"//"
'
```

Surface-level extraction only. Hand JS bundles to source-analyzer for deep route /
secret extraction — the source-analysis skill has the methodology depth for that pass.

Only queue endpoints that are directly requestable and evidenced by a real response or
real HTML/form/link extraction. Directory stems, SPA routes, and guessed names should
stay as follow-up notes or surface candidates, not queue inputs.

### Step 11 — API Surface Discovery

```bash
aith assess kali exec --technique RECON --intent "OpenAPI / Swagger / GraphQL endpoint sweep" \
  --probe-kind fingerprint --phase recon --timeout 120 -- bash -c '
  for path in /swagger.json /openapi.json /api-docs /swagger/v1/swagger.json /v2/api-docs /v3/api-docs; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET$path")
    [ "$code" != "404" ] && echo "$path -> $code"
  done

  for path in /graphql /gql /api/graphql /graphql/console; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://TARGET$path" \
      -H "Content-Type: application/json" -d "{\"query\":\"{__typename}\"}")
    [ "$code" != "404" ] && echo "$path -> $code"
  done
'
```

### Step 12 — Recon-to-Hypothesis Conversion

- Reverse-proxy plus framework leakage: test for route normalization, cache confusion,
  and trust-boundary mistakes.
- Auth-protected admin or internal-looking routes: treat them as realistic escalation
  paths, not dead ends.
- Error traces, version strings, or verbose debug hints: validate in stages before
  attempting full exploitation.
- Reused cookie scope, shared API prefixes, or odd host routing: look for cross-app
  chains and auth-context drift.

## What to Record

- Live targets with status codes, titles, and server headers
- Technology stack (framework, CMS, server, WAF, CDN)
- WAF tier and the rate-limit profile chosen for downstream tools
- Authentication mechanism identified
- API specs discovered (OpenAPI, GraphQL)
- Admin/management endpoints found
- TLS certificate details (SANs, CN, issuer) and any hosts surfaced from SAN extraction
- rDNS vendor identification for shared / CDN-fronted infrastructure
- JavaScript files queued for source-analyzer
- Surface candidates for operator ingestion
- Coverage gaps when any mandatory step did not complete (record explicitly — the
  recon-specialist's pre-output self-check fails loudly when a mandatory step is missing)

## Extended Resources

- `agent/operator-core.md` "Recon Dispatch Resource Policy" — canonical per-target rate calibration table (cautious tier, CDN-fronted, WAF-protected, vendor SaaS, origin)
- `agent/references/tools/recon/nmap.md` — port/service discovery, cautious-tier profile, TLS SAN extraction, rDNS, multi-host `-iL`, port-data presence assertion
- `agent/references/tools/recon/whatweb.md` — web technology fingerprinting depth levels
- `agent/references/tools/recon/httpx.md` — HTTP probing, tech detection, live host confirmation
- `agent/references/tools/recon/wafw00f.md` — WAF identification, scan-ordering ("run FIRST"), WAF-tier rate adjustment table, multi-host batch
- `agent/references/tools/recon/nikto.md` — conditional trigger fingerprint list, `-Tuning x60` profile, cautious-tier rate guidance, evasion modes
- `agent/references/tools/recon/curl.md` — HTTP request crafting and manual inspection
- `agent/references/tools/fuzzing/ffuf.md` — directory/parameter/vhost fuzzing, L1/L2/L3 wordlist escalation
- `agent/references/payloads/info-disclosure-probes.md` — standard endpoint checklist (/metrics, /.env, /actuator, cloud metadata)
