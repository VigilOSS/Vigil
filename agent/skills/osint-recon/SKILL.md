---
name: osint-recon
description: Open-source intelligence gathering — CVE lookup, breach search, DNS history, social profiling
origin: AI Threat Hunting
---

# OSINT Reconnaissance

## When to Activate

- After TEST phase, the backend intel tables (`intel_tech_components`, `intel_people`, `intel_domains`, and `assessment_credentials`) have accumulated tech stack, people, domains, and credentials — query via `./scripts/assess.py list-intel <type>` or `./scripts/assess.py fetch intel`
- Parallel with exploit phase to enrich attack context

## Tools

searchsploit, h8mail, theHarvester, bbot, amass, whois, dig,
gau, curl, jq

Optional when installed: `waymore`

## Methodology

Treat OSINT as a hypothesis generator for realistic attack paths, not a passive appendix.
Prioritize intel that changes exploit decisions, auth testing, chain construction, or log review.
The shared Kali runtime does not mount `$ENGAGEMENT_DIR` at `/engagement`. Use `/tmp` for runtime-local
output, then persist durable artifacts into `$ENGAGEMENT_DIR/scans/` on the host when they need to be
ingested, reviewed, or handed off.

### 1. CVE & Exploit Lookup

Pull the tech stack from the backend (`./scripts/assess.py list-intel tech-component`) — for each component+version:

    # Exploit-DB local search
    searchsploit "<component> <version>"
    searchsploit -j "<component> <version>" | jq '.RESULTS_EXPLOIT[]'

    # NVD API (rate limit: 5 req/30s without API key)
    curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<component>+<version>&resultsPerPage=10" \
      | jq '.vulnerabilities[].cve | {id, descriptions: .descriptions[0].value, metrics: .metrics}'

    # GitHub Advisory Database
    curl -s "https://api.github.com/advisories?affects=<component>&per_page=10" \
      | jq '.[].ghsa_id, .[].summary'

    # GitHub PoC search
    curl -s "https://api.github.com/search/repositories?q=CVE+<component>+poc&sort=updated&per_page=5" \
      | jq '.items[] | {name, html_url, description}'

### 2. Breach & Credential Intelligence

Pull emails and domains from the backend (`./scripts/assess.py list-intel email` and `./scripts/assess.py list-intel domain`):

    # theHarvester — email and subdomain enumeration
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

Pull domains from the backend (`./scripts/assess.py list-intel domain`):

    # WHOIS
    whois <domain> | tee scans/osint_whois.txt

    # Certificate transparency
    curl -s "https://crt.sh/?q=%25.<domain>&output=json" \
      | jq '.[0:20] | .[] | {name_value, issuer_name, not_before, not_after}'

    # DNS records
    for type in A AAAA MX NS TXT SOA CNAME; do
      dig +short $type <domain>
    done | tee scans/osint_dns.txt

    # Amass passive enum
    amass enum -passive -d <domain> -o scans/osint_amass.txt

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

Pull people and org facts from the backend (`./scripts/assess.py list-intel person` and `./scripts/assess.py list-intel org-fact`):

    # theHarvester — people and email enumeration
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

## CVE Validation Gate

CVE recording rules are defined in `agent/agents/osint-analyst.md` § Finding Recording.
In short: version-only CVE matches are intel, not findings — record via `./scripts/assess.py record-intel cve <cve-json-file>` and list them under `#### Intelligence` in your output. The operator dispatches exploit-developer to validate before any CVE becomes a durable finding via `record-finding`.

## Priority Order

1. CVE + version match with public PoC (immediate exploit-developer validation candidate)
2. Leaked/breached credentials for target emails (direct access — record if target-proven)
3. Historical endpoints not in current attack surface (hidden functionality)
4. Organizational intel enriching social engineering context
5. DNS/cert history revealing infrastructure changes

## Output Integration

Raw OSINT collection is recorded via `./scripts/assess.py record-intel <type> <json-file>` so the
backend intel tables (`intel_cves`, `intel_breach_records`, `intel_dns_records`,
`intel_social_profiles`, etc.) are the canonical destination. CVE matches stay as intel until
exploit-developer validates them.
- CVE matches → `record-intel cve` + `#### Intelligence` (NOT findings — needs validation)
- Breached credentials → `record-intel breach-record`; credentials with target-specific proof additionally go to `assess.py post credentials <json-file>` and a finding
- Historical URLs → `record-intel dns-record` (record-type=URL or equivalent), then ingest confirmed or high-value paths into backend coverage state via `assess.py ingest-endpoints`
- Social/org intel → `record-intel social-profile` for platform accounts, `record-intel org-fact` for structured organizational metadata
- Free-form prose intel that doesn't fit a structured row → `record-intel note`
- For each meaningful lead, record the hypothesis it supports: vulnerable component, reachable hidden surface, reusable credential, or escalation path

## Extended Resources

- `agent/references/tools/recon/gau.md` — historical URL discovery (Wayback, OTX, Common Crawl)
- `agent/references/tools/recon/httpx.md` — HTTP probing for validating discovered URLs
