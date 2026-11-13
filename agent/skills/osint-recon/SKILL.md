---
name: osint-recon
description: Open-source intelligence gathering — CVE lookup, breach search, DNS history, social profiling
origin: Vigil
---

# OSINT Reconnaissance

## When to Activate

- After consume-test, when the backend intel tables (tech components, people, domains,
  credentials) have accumulated material (`vigil assess intel list <type>`,
  `vigil assess fetch intel`), or alongside exploitation to enrich attack context.

Treat OSINT as a hypothesis generator for realistic attack paths. Prioritise intel that changes
exploit decisions, auth testing, chain construction or log review.

## Mechanics

Every network lookup runs through `vigil assess kali exec --technique OSINT --intent "<purpose>"
--probe-kind fingerprint --phase recon --timeout N -- <tool argv>`, so it lands in the audit
history other specialists use as a coverage map. `--technique OSINT` is for passive third-party
sources (CT logs, public APIs, registries, search engines); `--technique RECON` when the probe
touches the target's own infrastructure (theHarvester DNS resolution, bbot active modules).
Durable artefacts go under `/engagements/$ENGAGEMENT_KEY/scans/` (the host sees `$DIR/scans/`);
`/tmp` in the container is lost on recreate. Tools in the image: searchsploit, theHarvester,
h8mail, bbot, subfinder, whois, dig, gau, curl, jq; waymore when installed. For passive subdomains
use `subfinder -all` plus bbot passive (`agent/skills/subdomain-enumeration/SKILL.md`): amass's
graph database OOM-kills (RC137) under the shared cgroup. API-keyed sources (HIBP, SecurityTrails,
Hunter, NVD, GitHub) need their keys in the runtime environment; a missing key is a coverage gap
to report.

## 1. CVE and exploit lookup

For **every** component and version in `vigil assess intel list tech-component` (mandatory, not
"if time allows": a CVE this pass misses surfaces only by chance later): searchsploit (`-j`), NVD,
the GitHub Advisory Database and a public PoC search.

**Per-product nuclei CVE pass** for products with public `http/cves/` coverage (ShinyProxy,
R-Shiny, Jenkins, Confluence, GitLab, Grafana, Argo CD, Sentry, MinIO, Splunk Web, Spring Boot
Actuator, and similar), after recording the tech component:

```bash
vigil assess kali nuclei -l /engagements/$ENGAGEMENT_KEY/scans/<product>-hosts.txt \
  -t http/cves/ -tags <product-slug> -severity medium,high,critical -jsonl \
  -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_<product>_$RID.jsonl \
  --technique CVE-VALIDATION --intent "targeted CVE templates for <product> <version>" \
  --probe-kind fingerprint --phase recon --timeout 600
```

This is not the reactive Phase 1c `-as` sweep; `-as` underperforms on the cases in
`agent/skills/nuclei-scanning/SKILL.md` "Known fingerprint-suppression cases."

**Recording:** each version-matched CVE is `vigil assess intel record cve <file>`, never
`finding record` (`agent/agents/osint-analyst.md` "CVE Validation Gate"; the no-theoretical-findings
rule in `agent/rules/hunting.md`). The operator dispatches `vulnerability-analyst` to validate.

## 2. Breach, infrastructure, social

- **Breach and credentials:** theHarvester for emails, h8mail and HIBP (breaches, pastes) for
  discovered addresses. A breached credential becomes a finding only with target-specific proof.
- **Infrastructure history:** WHOIS, CT (crt.sh), DNS records per type, historical URLs (gau,
  waymore), SecurityTrails subdomain and DNS history.
- **Social and organisational:** theHarvester search-engine modules, GitHub user and org
  search, Hunter email patterns, bbot email-enum.

## 3. Org-name Pattern Enumeration

Once one GitHub org surfaces, enumerate the pattern space before declaring GitHub OSINT done:
sibling orgs (research arms, internal tooling, OSS forks, contractor accounts) receive less
scrutiny and often carry the most exploitable artefacts. Pipelines and rate-limit guidance:
`agent/references/tools/recon/github-osint.md`.

1. Variants of the literal name (case, hyphenation, suffixes such as `-corp`, `-internal`,
   `-tools`, `-research`, `-oss`, `-Inc`) as `type:org` searches.
2. The same suffix family on the parent agency's or corporation's name.
3. Global code search for each confirmed org name in **other** repos: forks, README links and CI
   configs pulling private packages expose internal repo names the owner page hides.
4. Per org, public members and recent commit author/committer emails: the email format and the
   named developers it resolves to.
5. Contractors and vendors seen in procurement records, case studies or profiles: their orgs often
   hold target-specific configuration, deployment scripts and hard-coded internal URLs.

Declare the pattern set you enumerated in `#### Intelligence`.

## 4. Exact-version Triangulation

Triangulate the patch level before matching CVEs: an inferred range ("2.x because the login page
shows 2.0 features") misses backported fixes and invents CVEs filed against older versions.

1. Bundle and source-map constants (`APP_VERSION`, `BUILD_HASH`, `__GIT_SHA__`,
   `__BUILD_VERSION__`; `agent/skills/source-analysis/SKILL.md`).
2. Sister-package publish dates in the registry (npm `time`, PyPI `upload_time`, Maven Central
   `timestamp`): monorepo vendors ship siblings on the same day, which pins one release.
3. Vendor changelogs: one externally visible feature must match the candidate version.
4. Vendor security bulletins for the patched line: which CVEs do **not** apply, and which
   downstream branch carries a backport.
5. The Sentry `release:` tag in bundles, against the vendor's tag list, for the exact commit.

Per-vendor probe pipelines: `agent/references/payloads/version-fingerprint-probes.md`. When
sources disagree or are thin, say so and record the CVE as lower-confidence pending live
validation.

## Output Contract

The skill produces these sections in the osint-analyst's return payload. Backend writes are the
durable record; this contract names what each markdown section holds.

| Section | Holds |
|---|---|
| `#### Summary` | Components researched, CVE matches, breach hits, GitHub orgs enumerated, triangulation outcomes. |
| `#### Findings` | Results already proved against the live target (a breached credential that logs in, a reproduced CVE PoC), each also recorded via `vigil assess finding record`. Version-only CVE matches stay in Intelligence. |
| `#### Intelligence` | The bulk of the output, each row recorded by type (below). |
| `#### Surface Candidates` | Historical URLs and hidden endpoints worth active probing, fed in with `vigil assess ingest endpoints`. |
| `#### Coverage Gaps` | Missing API keys, rate-limited queries, failed modules, triangulation that could not pin a patch level. |

## Output Integration

`vigil assess intel record <type> <json-file>` (types: `cve`, `breach-record`, `dns-record`,
`domain`, `email`, `person`, `social-profile`, `org-fact`, `tech-component`, `note`):

- CVE matches → `cve` (intel until validated).
- Breached credentials → `breach-record`; with target-specific proof also
  `vigil assess post credentials <json-file>` and a finding.
- DNS history (A/CNAME/MX/TXT records over time) → `dns-record`, whose `record_type` is a DNS
  record type.
- Historical URLs → `vigil assess ingest endpoints` for the work buffer; a summary of what the
  history showed → `note`.
- Platform accounts → `social-profile`; structured organisational metadata → `org-fact`.
- Anything else → `note`. Each meaningful lead names the hypothesis it supports: vulnerable
  component, hidden surface, reusable credential, or escalation path.

Further references: `agent/references/tools/recon/gau.md`, `agent/references/tools/recon/httpx.md`.
