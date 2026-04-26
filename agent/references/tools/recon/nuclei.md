# nuclei

**Purpose:** Vulnerability scanning with community templates
For live engagement targets, run `nuclei` via `aith assess kali nuclei` (typed verb, audit-flag-aware).

## Basic Scanning

**Single target:** `nuclei -u https://target`
**Multiple targets:** `nuclei -l /engagements/$ENGAGEMENT_KEY/scans/targets.txt`
**By severity:** `nuclei -u https://target -severity critical,high`
**By tag:** `nuclei -u https://target -tags cve,rce,misconfig`
**Exclude tags:** `nuclei -u https://target -exclude-tags dos,fuzz`

## Template Selection

**Specific template:** `nuclei -u https://target -t http/cves/2021/CVE-2021-44228.yaml`
**Template directory:** `nuclei -u https://target -t /custom/templates/`
**Auto-scan (tech-based):** `nuclei -u https://target -as` (detects tech stack, runs matching templates)
**List templates:** `nuclei -tl`
**Workflows:** `nuclei -u https://target -w http/workflows/wordpress-workflow.yaml`

Note: Template paths use protocol prefix (e.g., `http/cves/`, `dns/`, `network/`).

## Auth & Headers

**Custom header:** `nuclei -l targets.txt -header "Cookie: session=abc"`
**Header from file:** `nuclei -l targets.txt -header-file headers.txt`
**Proxy through Burp:** `nuclei -l targets.txt -proxy http://127.0.0.1:8080`

## OOB Callbacks

**Custom interactsh URL:** `nuclei -u target -interactsh-url https://YOUR_ID.oast.fun`
**Disable interactsh:** `nuclei -u target -no-interactsh`

## Rate Limiting & Performance

**Rate limit:** `-rate-limit 100` (requests/second)
**Concurrency:** `-c 25` (template concurrency)
**Bulk size:** `-bs 25` (hosts per template)
**Timeout:** `-timeout 10`
**Retries:** `-retries 2`
**Stats display:** `-stats`

## Output

**Text:** `-o results.txt`
**JSON Lines:** `-jsonl -o results.jsonl`
**Markdown:** `-me /path/to/dir` (markdown export)

## Template Management

**Update templates:** `nuclei -ut`
**Custom template directory:** `nuclei -td /path/to/templates/` (override default template location)

## Triage Rules

From the nuclei-scanning skill — apply these to results:
- **Critical/High:** Validate manually, record as findings if confirmed
- **Medium/Low:** Intelligence — inform testing priorities
- **Info:** Tech stack enrichment for recon data
