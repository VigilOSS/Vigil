---
name: surface-collection
description: URL collection pipeline and intelligent triage methodology for Phase 2 work-buffer population
origin: AI Threat Hunting
---

# Surface Collection

> **`aith assess kali` audit flags:** use `--technique DISCOVERY` (Katana, gau, and wayback URL collection plus triage expand the attack-surface inventory without sending attack payloads).

Guides surface-collector through the Phase 2 URL collection pipeline: live crawling, historical
enrichment, deduplication, intelligent triage, and work-buffer population. The goal is to turn
raw tool output into a prioritized, attack-signal-enriched work buffer that drives Phase 3.

## When to Activate

- Phase 2 (Collect) of a web/runtime engagement
- After Phase 1 (Recon) completes and endpoint artifacts are available
- When the operator dispatches surface-collector with targets and Phase 1 output

## Pipeline

Set variables from dispatch context:
```bash
DIR="${ENGAGEMENT_DIR:?set by the engagement launcher}"
DB="$DIR/cases.db"
```

### Step 1: Ingest Phase 1 Endpoints

Recon-specialist and source-analyzer produce endpoint lists during Phase 1. Ingest them
as the baseline work-buffer seed:

```bash
cat "$DIR/scans/endpoints.txt" | aith assess ingest-endpoints "$DB" recon
```

If source-analyzer produced a separate endpoint file, ingest it with a distinct source tag:

```bash
cat "$DIR/scans/source-endpoints.txt" | aith assess ingest-endpoints "$DB" source-analysis
```

### Step 2: Live Crawl via Katana

Run Katana via `aith assess kali katana` to crawl live targets. Katana is installed in the
runtime container; the typed verb wraps it with audit recording.

```bash
aith assess kali katana \
  -u https://target.example -d 3 -jc -jsl -c 10 -rl 20 \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_output.txt \
  --technique DISCOVERY --intent "live crawl of target.example" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

**TLS handling:** Katana does not provide a TLS-verification-skip flag in the runtime this
repo builds. If a target only responds behind an invalid or self-signed certificate, use
`aith assess kali exec -- curl -k` for spot validation and continue with other collection
sources instead of relying on Katana to bypass TLS checks.

**Auth-aware crawl:** If `auth.json` has `use_for_requests` set to `true` and `state` set
to `available`, pass cookies/headers:

```bash
aith assess kali katana \
  -u URL -H "Cookie: ..." -H "Authorization: ..." -d 3 -jc -jsl -c 10 -rl 20 \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_auth_output.txt \
  --technique DISCOVERY --intent "auth-aware crawl of URL" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

**Multi-target:** Run Katana once per in-scope web target from `scope.json` hosts. Combine
output files or ingest each separately with the same source tag.

Ingest:
```bash
cat "$DIR/scans/katana_output.txt" | aith assess ingest-endpoints "$DB" katana
```

### Step 3: Historical URL Enrichment via gau

Run gau via `aith assess kali gau` against each in-scope domain. gau queries Wayback Machine,
AlienVault OTX, Common Crawl, and URLScan for historical URLs:

```bash
aith assess kali gau TARGET_DOMAIN --subs --threads 5 \
  --blacklist png,jpg,gif,css,woff,svg \
  --providers wayback,otx,commoncrawl,urlscan \
  -o /engagements/$ENGAGEMENT_KEY/scans/gau_output.txt \
  --technique DISCOVERY --intent "historical URL harvest for TARGET_DOMAIN (passive)" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

gau output contains duplicates — deduplicate before ingestion:

```bash
sort -u "$DIR/scans/gau_output.txt" > "$DIR/scans/gau_deduped.txt"
cat "$DIR/scans/gau_deduped.txt" | aith assess ingest-endpoints "$DB" gau
```

**Multi-domain:** Run gau for each domain in scope.json hosts. Use `--subs` when wildcard
subdomains are in scope.

**Why gau matters:** Katana only discovers what is currently linked. gau finds endpoints that
existed historically — deprecated routes, old API versions, test endpoints, admin paths that
were once public. These are often still functional but hidden from the live sitemap.

### Step 4: OpenAPI/Swagger Spec Ingestion

If Phase 1 discovered API specifications (source-analyzer may have saved them to `scans/`):

```bash
aith assess ingest-spec "$DB" "$DIR/scans/openapi.json"
```

This creates `api-spec` work items with full endpoint/parameter schemas and generates
coverage candidates automatically.

### Step 5: Dedup Verification

After all sources are ingested, verify the work buffer is clean:

```bash
aith assess dispatch "$DB" stats
```

The ingestion pipeline handles param-structure deduplication automatically (same endpoint
with different parameter values = one work item). Review stats to confirm reasonable
counts — if a single source contributed disproportionately, investigate whether dedup
is working correctly.

### Per-host URL Budget (replaces global URL caps)

The work buffer is bounded per-host, not globally. A single global URL ceiling either
truncates a sitemap-bearing host that legitimately exposes thousands of pages or fails
to defer a 50,000-URL CDN dump that pollutes Phase 3 priority for every other host. The
per-host formula keeps budget proportional to the host's likely attack-surface depth:

| Host class | Budget | Rationale |
|---|---|---|
| content-rich hosts (typical web app: HTML pages, blog, marketing content) | **1000 URLs / host** | Default for hosts not matching the API-tier or sitemap-bearing rules. |
| API-tier hosts (`api.*`, `*.api.example.test`, hosts whose URL surface is mostly endpoints) | **1000 URLs / host** | Same as content-rich. The earlier 200 cap silently truncated real microservice clusters with hundreds of legitimate REST routes; operators still cap a noisy API host lower with `--budget-override`. |
| sitemap-bearing hosts (sitemap.xml provides an explicit upper-bound list) | **2000 URLs / host** | Don't truncate below the sitemap's count; the sitemap is the host's own declaration of canonical surface. |

Operator override: pass `--budget-override <host>:<n>` on the dispatch context when a
specific host needs a non-default cap (a host known to expose thousands of legitimate
endpoints, or a CDN host that should be capped lower than 1000). Surface-collector
honors the override at ingestion time; URLs beyond the budget land as
`cluster_key=deferred:per-host-budget-exceeded` rather than `pending`, so the operator
sees them in `aith assess dispatch peek` output without polluting the work-buffer
priority queue.

#### Recovery flow when classify-work scores deferred clusters above default

When classify-work assigns a high priority to any cluster on a host that already
deferred surplus URLs (e.g., a host that hit the 1000 cap and where the
`gf:ssrf` cluster surfaces with 50 candidates), the operator should auto-raise
the budget for that host and re-ingest:

1. Inspect the deferred bucket: `aith assess dispatch "$DB" peek deferred:per-host-budget-exceeded 50`.
2. If high-priority clusters appear in the deferred set, re-run gau for the host
   with a wider scope: `aith assess kali gau X --subs --threads 5 ... -o /engagements/$ENGAGEMENT_KEY/scans/gau_<host>_followup.txt --technique DISCOVERY --intent "follow-up gau after classify-work scored deferred cluster" --probe-kind fingerprint --phase consume-test --timeout 1800`.
3. Re-ingest with the override: pipe the new gau output into `aith assess ingest-endpoints` and pass `--budget-override <host>:<n>` so the new URLs admit beyond the default cap. Pick `<n>` large enough to cover the deferred surplus you just inspected.
4. Re-run `aith assess classify-work` to score the newly-admitted rows before the next dispatch.

This loop keeps the default cap conservative while surfacing the recovery path
the moment classify-work flags real signal in the deferred set.

#### Egress-blocked hosts

A host that responds to every probe with HTTP 403 (CDN-IP-blocked egress) belongs in a
`deferred` cluster with `terminal_reason=egress-blocked, see CDN-IP playbook` and a
cross-link to `agent/references/runtime-guides/cdn-ip-blocking.md`. The egress-blocked
deferral path is owned by W4a-1; per-host budget enforcement here coexists with that
deferral by adding distinct ingestion-time functions rather than reshaping the existing
egress-blocked path.

#### Newly-discovered hosts post-OSINT

Subdomain enumeration deltas and Phase 1 OSINT discoveries that surface a new host
AFTER initial ingestion MUST receive their own gau pass — surface-collector cannot
skip them on the assumption that initial collection was exhaustive. A new host
inherits the default per-host budget and is ingested through the standard path.

#### Admin / internal / config URL preservation under egress block

When historical gau discovers admin / internal / config paths on a host that is
currently egress-blocked, save those URLs as intel-notes via
`aith assess record-intel note` even though the live work item lands in the
deferred bucket. The path patterns themselves reveal target-environment exposure
(staging hostnames, internal-tooling routes, config endpoints) and feed the report
narrative even when live testing is blocked.

### Step 6: Intelligent Triage

This is the core value-add over the previous operator-orchestrated pipeline. After
mechanical ingestion is complete, analyze the full URL corpus for attack signals.

**Deep triage (large corpora):** when the gau output exceeds ~500 URLs, or response-body
secret scanning is in scope, stop here and ask the operator to dispatch a follow-up
surface-collector invocation loaded with `agent/skills/gau-triage/SKILL.md`. That skill
layers `gf` parameter classification, `httpx` body capture, and `trufflehog` secret
scanning on top of the URL corpus this step produces — it is a deeper pass, not a
replacement.

**Retrieve work items for analysis:**
```bash
aith assess dispatch "$DB" fetch api 50 surface-collector
aith assess dispatch "$DB" fetch page 50 surface-collector
aith assess dispatch "$DB" fetch unknown 50 surface-collector
```

Analyze the fetched URLs (without testing them — triage is classification, not probing)
and produce the priority manifest. Then release them back:

```bash
aith assess dispatch "$DB" reset-stale 0
```

**Triage categories** (see agent prompt for full pattern lists):

1. **Leaked secrets in parameters** — credential-like query param names
2. **Admin/debug paths** — privileged path patterns
3. **API version spread** — older versions of the same resource path
4. **Backup/config files** — sensitive file extensions from historical URLs
5. **Injectable parameter surfaces** — search, ID, file, redirect, template params

For each category, produce:
- Count of matching URLs
- Representative examples (3-5 per category)
- Recommended Phase 3 priority and vuln-class skill

### Step 7: Surface and Finding Recording

Before returning to the operator:

**Record surfaces** for all high-signal discoveries:
```bash
aith assess record-surface <surface-type> <url> <source> \
  --rationale "<why this is high-signal>" \
  --status discovered
```

**Record findings** when triage produces decisive evidence (e.g., an API key with a
non-empty value visible in a URL parameter):
```bash
aith assess record-finding surface-collector <finding-json-file>
```

### Step 8: Stats and Priority Manifest

Produce the final stats:
```bash
aith assess dispatch "$DB" stats
```

Build the priority manifest in the output — a ranked list of attack surface clusters
with triage signals, recommended dispatch order, and suggested vuln-class skills.

## Key Rules

- Keep all URL crawling and enrichment in `aith assess kali katana` / `aith assess kali gau` — host-side crawling bypasses the audit pipeline that downstream specialists rely on
- Use `aith assess ingest-endpoints` for all work-buffer writes — direct DB inserts bypass backend sync
- Use `aith assess record-surface` for all surface writes — bypassing loses backend sync
- Use `aith assess record-finding` for any findings — unrecorded findings are lost data
- Triage is classification and pattern matching — analyze URLs without sending target-facing probes during triage
- Tag each ingestion source correctly (recon, katana, gau, source-analysis, spec) — source provenance matters for coverage tracking

## Output Contract Reference

The surface-collector agent prompt defines the full output format. Key sections:

| Section | Purpose |
|---------|---------|
| `#### Summary` | Collection totals by source, dedup stats |
| `#### Stats` | Work-buffer breakdown by type |
| `#### Priority Attack Surfaces` | Ranked triage clusters — the key deliverable |
| `#### Coverage Gaps` | Which sources failed and why |
| `#### Intelligence` | Extracted attack signals |
| `#### Recommended Phase 3 Ordering` | Risk-informed dispatch order |

## Extended Resources

- `references/tools/recon/gau.md` — gau CLI reference and pipeline patterns
- `references/tools/recon/httpx.md` — HTTP probing reference for URL validation
- `agent/skills/gau-triage/SKILL.md` — deeper follow-up pass (gf classification + httpx body capture + trufflehog secret scan) for large historical URL corpora
