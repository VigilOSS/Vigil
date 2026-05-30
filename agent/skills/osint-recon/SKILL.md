---
name: osint-recon
description: Open-source intelligence gathering — CVE lookup, breach search, DNS history, social profiling
origin: AI Threat Hunting
---

# OSINT Reconnaissance

## When to Activate

- After TEST phase, the backend intel tables (`intel_tech_components`, `intel_people`, `intel_domains`, and `assessment_credentials`) have accumulated tech stack, people, domains, and credentials — query via `aith assess list-intel <type>` or `aith assess fetch intel`
- Parallel with exploit phase to enrich attack context

## Tools

searchsploit, h8mail, theHarvester, bbot, subfinder, whois, dig,
gau, curl, jq

(amass v5 is intentionally dropped on shared runtimes — graph-DB OOM/RC137; use
`subfinder -all` + `bbot` passive for the same source coverage.)

Optional when installed: `waymore`

## Methodology

Treat OSINT as a hypothesis generator for realistic attack paths, not a passive appendix.
Prioritize intel that changes exploit decisions, auth testing, chain construction, or log review.
The engagement dir is bind-mounted into Kali at `/engagements/$ENGAGEMENT_KEY/` — write durable
artifacts directly under `/engagements/$ENGAGEMENT_KEY/scans/` (the host sees the same files as
`$ENGAGEMENT_DIR/scans/`). Reserve `/tmp` for transient scratch files that do not need to survive
the container, because anything under `/tmp` disappears on container recreate.

> **Audit envelope is mandatory.** Every command in sections 1–6 below is illustrative shell —
> execution wraps each network probe in `aith assess kali exec --` with the audit envelope
> (`--technique OSINT --intent "<purpose>" --probe-kind fingerprint --phase recon --timeout N`).
> The bare `searchsploit`/`theHarvester`/`bbot`/`curl`/`whois`/`dig`/`subfinder`/`gau`/`waymore`
> invocations shown without the wrap are *examples of the underlying tool argv*; running them
> on the host bypasses the audit pipeline that downstream specialists rely on as a coverage map.
> Use `--technique OSINT` for passive external-source lookups (CT logs, public APIs, registries),
> `--technique RECON` only when the probe sends traffic at the assessed target's own
> infrastructure (theHarvester DNS resolution, bbot active modules). Each wrapped invocation
> below shows the canonical form; pattern-match it for any tool that doesn't appear here yet.

### 1. CVE & Exploit Lookup

Pull the tech stack from the backend (`aith assess list-intel tech-component`) — for each component+version:

```bash
# Exploit-DB local search (canonical wrapped form — copy this for every other tool below)
aith assess kali exec \
  --technique OSINT --intent "searchsploit lookup for <component> <version>" \
  --probe-kind fingerprint --phase recon --timeout 60 -- \
  searchsploit -j "<component> <version>"
```

    # NVD API (rate limit: 5 req/30s without API key)
    curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<component>+<version>&resultsPerPage=10" \
      | jq '.vulnerabilities[].cve | {id, descriptions: .descriptions[0].value, metrics: .metrics}'

    # GitHub Advisory Database
    curl -s "https://api.github.com/advisories?affects=<component>&per_page=10" \
      | jq '.[].ghsa_id, .[].summary'

    # GitHub PoC search
    curl -s "https://api.github.com/search/repositories?q=CVE+<component>+poc&sort=updated&per_page=5" \
      | jq '.items[] | {name, html_url, description}'

For every component+version row in the tech stack, the four lookups above are **mandatory** (not "if you have time"). Specialists historically rediscovered CVEs via initiative when the OSINT pass should have surfaced them. Walk the full `list-intel tech-component` output before moving to step 2.

**Systematic nuclei CVE-template pass** — for containerized app platforms and well-known products with public CVE templates (ShinyProxy, R-Shiny, Jenkins, Confluence, GitLab, Grafana, Argo CD, Sentry, MinIO, Splunk Web, Spring Boot Actuator, anything with `http/cves/` template coverage), record the tech-component intel, then trigger a targeted nuclei pass scoped to that product:

```bash
aith assess kali nuclei \
  -l /engagements/$ENGAGEMENT_KEY/scans/<product>-hosts.txt \
  -t http/cves/ -tags <product-slug> \
  -severity medium,high,critical -jsonl \
  -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_<product>_$RID.jsonl \
  --technique CVE-VALIDATION --intent "targeted CVE templates for <product> <version>" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

This is **not** the reactive Phase 1c sweep (which is `-as` against all live hosts); it's an explicit per-product validation that the reactive sweep would have missed because `-as` underperforms on the suppression cases documented in `agent/skills/nuclei-scanning/SKILL.md` "Known fingerprint-suppression cases."

**Recording rule.** After the CVE lookup + targeted nuclei pass, record each version-matched CVE as intel:

```bash
aith assess record-intel cve <cve-json-file>
```

Then the operator dispatches `exploit-developer` to validate. Version-matched CVE is **intel, not finding** until the exploit-developer pass produces target-proven evidence. Do NOT call `record-finding` from the osint-recon pass — that breaks the no-theoretical-findings rule in `agent/rules/hunting.md`.

### 2. Breach & Credential Intelligence

Pull emails and domains from the backend (`aith assess list-intel email` and `aith assess list-intel domain`):

```bash
# theHarvester wrapped form — note --technique RECON when modules touch target DNS.
aith assess kali exec \
  --technique RECON --intent "theHarvester email + subdomain enum on <domain>" \
  --probe-kind fingerprint --phase recon --timeout 1800 -- \
  theHarvester -d <domain> -b all -f /engagements/$ENGAGEMENT_KEY/scans/osint_harvester.json
```

    # theHarvester — email and subdomain enumeration (illustrative argv — wrap as above)
    theHarvester -d <domain> -b all -f scans/osint_harvester.json

    # h8mail — breach lookup for discovered emails
    h8mail -t <email1>,<email2> -o scans/osint_h8mail.csv

    # HIBP API (requires API key in env)
    curl -s -H "hibp-api-key: $HIBP_API_KEY" \
      "https://haveibeenpwned.com/api/v3/breachedaccount/<email>?truncateResponse=false" | jq '.'

    # Paste search
    curl -s -H "hibp-api-key: $HIBP_API_KEY" \
      "https://haveibeenpwned.com/api/v3/pasteaccount/<email>" | jq '.'

### 3. DNS & Infrastructure History

Pull domains from the backend (`aith assess list-intel domain`):

```bash
# WHOIS wrapped form (illustrative — every tool in this section follows the same wrap pattern).
aith assess kali exec \
  --technique OSINT --intent "WHOIS lookup for <domain>" \
  --probe-kind fingerprint --phase recon --timeout 60 -- \
  whois <domain>
```

    # WHOIS (illustrative argv — wrap as above)
    whois <domain> | tee scans/osint_whois.txt

    # Certificate transparency
    curl -s "https://crt.sh/?q=%25.<domain>&output=json" \
      | jq '.[0:20] | .[] | {name_value, issuer_name, not_before, not_after}'

    # DNS records
    for type in A AAAA MX NS TXT SOA CNAME; do
      dig +short $type <domain>
    done | tee scans/osint_dns.txt

    # Passive subdomain enum — use subfinder -all + bbot passive, NOT amass v5.
    # amass v5 builds a memory-heavy graph DB that OOM-kills (RC137) under the
    # shared cgroup and stalls at 0% with unconfigured datasources; subfinder -all
    # + bbot cover the same passive sources. See agent/skills/subdomain-enumeration.
    subfinder -d <domain> -all -t 20 -silent -o scans/osint_subs.txt

    # Historical URL discovery with gau (queries Wayback, AlienVault OTX, Common Crawl, URLScan)
    gau <domain> --threads 5 --o /tmp/osint_gau.txt

    # Persist durable output back to $ENGAGEMENT_DIR/scans/ if you need it outside the runtime

    # waymore for deeper Wayback discovery with filtering, when installed
    waymore -i <domain> -mode U -oU /tmp/osint_waymore.txt

    # SecurityTrails API (requires API key in env)
    curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" \
      "https://api.securitytrails.com/v1/domain/<domain>/subdomains" | jq '.subdomains[]'

    # Historical DNS
    curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" \
      "https://api.securitytrails.com/v1/history/<domain>/dns/a" | jq '.records[]'

### 4. Social & Organizational Intelligence

Pull people and org facts from the backend (`aith assess list-intel person` and `aith assess list-intel org-fact`):

```bash
# theHarvester social wrapped form. Use --technique OSINT here — the
# linkedin/google modules query third-party search APIs, not the target.
aith assess kali exec \
  --technique OSINT --intent "theHarvester linkedin/google enumeration for <domain>" \
  --probe-kind fingerprint --phase recon --timeout 1200 -- \
  theHarvester -d <domain> -b linkedin,google -f /engagements/$ENGAGEMENT_KEY/scans/osint_social.json
```

    # theHarvester — people and email enumeration (illustrative argv — wrap as above)
    theHarvester -d <domain> -b linkedin,google -f scans/osint_social.json

    # bbot recursive recon (modular, JSON output, pipeline-friendly)
    bbot -t <domain> -p subdomain-enum email-enum -o /tmp/osint_bbot/ --json

    # GitHub user/org search
    curl -s "https://api.github.com/search/users?q=<person>+<org>" \
      | jq '.items[] | {login, html_url, type}'

    # GitHub org repos (potential source code leaks)
    curl -s "https://api.github.com/orgs/<org>/repos?per_page=30&sort=updated" \
      | jq '.[] | {name, html_url, description, visibility}'

    # Hunter.io — email pattern discovery (requires API key)
    curl -s "https://api.hunter.io/v2/domain-search?domain=<domain>&api_key=$HUNTER_API_KEY" \
      | jq '.data.emails[] | {value, type, confidence}'

### 5. Org-name Pattern Enumeration

Once one GitHub org is discovered for a target organization, enumerate the org-name pattern
space before declaring GitHub OSINT done. Single-name lookups miss sibling orgs that share
the same parent (research arms, internal-tooling orgs, OSS forks, contractor accounts) —
those siblings frequently carry the most exploitable artifacts because they receive less
scrutiny than the flagship org.

1. **Variants on the literal org name** — capitalization, hyphenation, suffixes. For an org
   "Acme" probe `acme`, `Acme`, `ACME`, `acme-corp`, `acmegov`, `acme-internal`, `acme-tools`,
   `acme-research`, `acme-oss`, `Acme-Inc`. Issue each as a `/search/users?q=<pattern>+type:org`
   query (see `agent/references/tools/recon/github-osint.md` for the curl + jq pipeline).
2. **Variants on the parent agency or parent corporation name** — same suffix family
   (`-internal`, `-research`, `-oss`, `-tools`, `-Inc`) applied to the parent's literal name.
3. **Cross-search public code for discovered org names** — once you have a confirmed org name,
   run a GitHub global code search for that name appearing in OTHER public repos (forks,
   contributor README links, CI config that pulls private packages by org slug). Hits in
   forks are gold — they expose internal repo names that the org's owner page hides behind
   private visibility.
4. **Per discovered org, enumerate public members and recent commit author emails** — list
   members via `/orgs/<org>/members` and recent commits via `/repos/<org>/<repo>/commits`,
   then jq-extract `author.email` and `committer.email`. The email pattern that emerges
   (e.g. `FirstName.LastName@<corp>`) confirms the corporate email format and identifies
   named developers whose handles map to LinkedIn / personal repos.
5. **Cross-reference contractor and vendor names** — when procurement records, public
   case studies, or LinkedIn show a consulting firm working with the target, search GitHub
   for tagged forks or affiliated repos under the contractor's org slug. Contractor repos
   often contain target-specific configuration, deployment scripts, or proof-of-concept
   code with hardcoded internal URLs and credentials.

Wrap every HTTP probe in `aith assess kali exec --` with the audit envelope so the run
lands in the audit pipeline. Concrete commands and rate-limit guidance live in
`agent/references/tools/recon/github-osint.md`.

### 6. Exact-version Triangulation

When vendor exact version is needed for CVE matching, multi-source triangulate before
committing to a range. A version-only inferred range (e.g. "2.x because the login page
shows 2.0 features") routinely fails: backported security patches keep an old major
running while sister-package fingerprints reveal the precise patch level. Triangulation
prevents both false-negative CVE misses (patched version that still matches a CVE
published against an unpatched line) and false-positive findings (a CVE filed against
a version older than what is actually deployed).

1. **Source-map APP_VERSION / BUILD_HASH constants** — webpack/Vite bundles routinely
   inline `APP_VERSION`, `BUILD_HASH`, `__GIT_SHA__`, `__BUILD_VERSION__`, and Sentry
   release-tag identifiers. Cross-link to `agent/skills/source-analysis/SKILL.md`'s
   "APP_VERSION / BUILD_HASH / Sentry-release extraction" section for the grep recipes.
2. **Package registry sister-package publish dates** — vendors that publish their
   libraries from a monorepo ship sister packages on the same release day. Cross-checking
   the publish dates of two or three sibling packages narrows the deployed version to
   one release. Query the registry directly:
   - npm: `https://registry.npmjs.org/<pkg>/<version>` → `time` field (per-version timestamps).
   - pypi: `https://pypi.org/pypi/<pkg>/<version>/json` → `urls[].upload_time`.
   - maven central: `https://search.maven.org/solrsearch/select?q=g:<group>+a:<artifact>+v:<version>&wt=json` → `response.docs[].timestamp`.
3. **Vendor public release notes / changelog** — convert each candidate version to a
   release date and confirm at least one externally-visible feature in the deployed app
   matches a feature the changelog attributes to that version.
4. **Vendor security bulletins for the patched-version line** — confirms which CVEs are
   NOT applicable to the deployed version. A CVE published against `<X.Y.Z` is still in
   play for `X.Y.(Z-1)` even if the vendor backported the patch into a downstream branch;
   the bulletin tells you which downstream branch carries the fix.
5. **Sentry release tag in minified bundles** — Sentry's `Sentry.init({release: ...})`
   call is often pinned to the build's git tag or short SHA. Grep source-maps for `release:`
   and cross-reference against the vendor's tag list to derive the exact commit.

Worked examples per vendor (npm/pypi/maven probe pipelines and Sentry grep recipes) are
in `agent/references/payloads/version-fingerprint-probes.md`. Wrap every HTTP probe in
`aith assess kali exec --` with the audit envelope.

## CVE Validation Gate

CVE recording rules are defined in `agent/agents/osint-analyst.md` § Finding Recording.
In short: version-only CVE matches are intel, not findings — record via `aith assess record-intel cve <cve-json-file>` and list them under `#### Intelligence` in your output. The operator dispatches exploit-developer to validate before any CVE becomes a durable finding via `record-finding`.

## Priority Order

1. CVE + version match with public PoC (immediate exploit-developer validation candidate)
2. Leaked/breached credentials for target emails (direct access — record if target-proven)
3. Historical endpoints not in current attack surface (hidden functionality)
4. Organizational intel enriching social engineering context
5. DNS/cert history revealing infrastructure changes

## Output Contract

The skill produces these structured sections in the osint-analyst's return payload.
Backend writes (`record-intel <type>`, `record-finding` for target-proven results) are
the durable record; this contract names what each markdown section should hold so
the operator and downstream specialists can parse the output consistently. The
"Output Integration" table below this section maps each section's intel rows to the
specific `record-intel <type>` call.

| Section | Holds |
|---|---|
| `#### Summary` | One-paragraph headline: tech components researched, CVE matches, breach hits, GitHub orgs enumerated, exact-version triangulation outcomes. |
| `#### Findings` | Decisive findings the OSINT pass already proved against the live target (e.g., a breach-leaked credential validated to log in, a CVE PoC reproduced). Each must also be recorded via `aith assess record-finding`. CVE matches without target-specific proof stay in `#### Intelligence` per the CVE Validation Gate. |
| `#### Intelligence` | The bulk of OSINT output. CVE matches → `record-intel cve`. Breach records → `record-intel breach-record`. Historical URLs → `record-intel dns-record`. Social profiles → `record-intel social-profile`. Org facts → `record-intel org-fact`. Tech-component fingerprints → `record-intel tech-component`. Free-form prose → `record-intel note`. See "Output Integration" below for the per-type mapping. |
| `#### Surface Candidates` | Historical URLs / hidden endpoints surfaced via `gau` / `waymore` / SecurityTrails that warrant active probing, fed back via `aith assess ingest-endpoints` so they enter the work buffer. |
| `#### Coverage Gaps` | API keys missing for SecurityTrails / Hunter / HIBP, rate-limited GitHub queries that did not complete, theHarvester modules that errored, exact-version triangulation that could not pin a single patch level. The operator uses this section to decide whether to re-dispatch with credentials. |

## Output Integration

Raw OSINT collection is recorded via `aith assess record-intel <type> <json-file>` so the
backend intel tables (`intel_cves`, `intel_breach_records`, `intel_dns_records`,
`intel_social_profiles`, etc.) are the canonical destination. CVE matches stay as intel until
exploit-developer validates them.
- CVE matches → `record-intel cve` + `#### Intelligence` (NOT findings — needs validation)
- Breached credentials → `record-intel breach-record`; credentials with target-specific proof additionally go to `aith assess post credentials <json-file>` and a finding
- Historical URLs → `record-intel dns-record` (record-type=URL or equivalent), then ingest confirmed or high-value paths into backend coverage state via `aith assess ingest-endpoints`
- Social/org intel → `record-intel social-profile` for platform accounts, `record-intel org-fact` for structured organizational metadata
- Free-form prose intel that doesn't fit a structured row → `record-intel note`
- For each meaningful lead, record the hypothesis it supports: vulnerable component, reachable hidden surface, reusable credential, or escalation path

## Extended Resources

- `agent/references/tools/recon/gau.md` — historical URL discovery (Wayback, OTX, Common Crawl)
- `agent/references/tools/recon/httpx.md` — HTTP probing for validating discovered URLs
