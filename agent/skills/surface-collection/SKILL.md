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
`aith assess kali exec --technique RECON --intent "spot-validate invalid TLS response" --probe-kind baseline --phase collect --timeout 60 -- curl -k` for spot validation and continue with other collection
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

Use the cache-aware pipeline wrapper. It runs gau (or reuses a fresh cached corpus),
ingests the URLs into `work_items` with inline classification, and emits a structured
JSON summary with `cache_reused: true|false` so the dispatch decision is auditable.

```bash
aith assess gau-endpoints TARGET_DOMAIN --subs \
  --providers wayback,otx,commoncrawl,urlscan
```

That single verb runs `kali gau` (or reuses `<engagement>/scans/gau_output.txt` when a
fresh run is cached), then pipes the output through `ingest-endpoints` so inline
classification scores every URL at insert time and inert types (images, fonts) are
filtered downstream. The `--max-cache-age-hours` flag (default 24) tunes reuse
aggressiveness; pass `--refresh` to force a fresh gau run.

**Multi-domain:** Run `gau-endpoints` for each in-scope domain. Each run writes its own
sidecar meta keyed by target so reuse decisions stay per-host.

**Follow-on verbs that share the same cached corpus:**

- `aith assess gau-secrets TARGET_DOMAIN` — body capture + trufflehog secret scan.
  Defaults to `--no-verification`; pass `--verify` to enable trufflehog's verification.
- `aith assess gau-js-endpoints TARGET_DOMAIN --fetch-if-missing` — extract endpoints
  hidden in minified JS bundles (LinkFinder-derived regex) and ingest them as
  `source='js-extract'`. Catches admin/internal routes that exist only in JS code
  paths — a class of endpoint live crawls and HTML-only inspection consistently miss.

**Why gau matters:** Katana only discovers what is currently linked. gau finds endpoints
that existed historically — deprecated routes, old API versions, test endpoints, admin
paths that were once public. These are often still functional but hidden from the live
sitemap. Pairing gau with `gau-js-endpoints` closes the additional gap of routes that
were never linked anywhere except inside compiled JS.

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

### Volume control happens at ingest, not via budgets

There is no per-host URL cap. Volume control happens at ingest:

- **Inert types skip the dispatch queue at insert time.** `image`, `video`, `font`,
  `archive`, `sourcemap`, and `manifest` types are stamped `status='skipped'` in
  `db_insert_work_item()` so they never enter the priority-mode dispatch.
- **Classification runs inline at ingestion** so every URL gets a `cluster_key` and
  `priority_score` immediately. Run `aith assess list-clusters "$DB"` to review the
  resulting cluster set and `aith assess dispatch "$DB" defer-cluster <key> --reason "…"`
  to drop low-signal clusters before Phase 3.
- **Egress-blocked hosts still defer** (see "Egress-blocked hosts" below) — that is a
  network-failure class, not a volume cap.

If a real-world ingest produces a cluster the operator does not want to deal with right
now, defer that cluster explicitly. Do not introduce a new budget gate — the silent
truncation is the bug, not the verbose buffer.

#### Egress-blocked hosts

A host that responds to every probe with HTTP 403 (CDN-IP-blocked egress) belongs in a
`deferred` cluster with `terminal_reason=egress-blocked, see CDN-IP playbook` and a
cross-link to `agent/references/runtime-guides/cdn-ip-blocking.md`. The egress-blocked
deferral path is owned by `_insert_egress_blocked_work_item` in
`ingest_endpoints.py` and is the only deferral class that still gates URLs at insert
time — every other URL is admitted and classified inline.

#### Newly-discovered hosts post-OSINT

Subdomain enumeration deltas and Phase 1 OSINT discoveries that surface a new host
AFTER initial ingestion MUST receive their own gau pass — surface-collector cannot
skip them on the assumption that initial collection was exhaustive. A new host
ingests through the standard path; inline classification scores its rows
immediately, and any low-signal cluster gets explicit operator control via
`aith assess dispatch defer-cluster` rather than an automatic URL cap.

#### Admin / internal / config URL preservation under egress block

When historical gau discovers admin / internal / config paths on a host that is
currently egress-blocked, save those URLs as intel-notes via
`aith assess record-intel note` even though the live work item lands in the
deferred bucket. The path patterns themselves reveal target-environment exposure
(staging hostnames, internal-tooling routes, config endpoints) and feed the report
narrative even when live testing is blocked.

### Step 6: Intelligent Triage

After mechanical ingestion is complete, analyze the full URL corpus for attack signals.

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
aith assess record-surface <type> <target> <source> \
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

- Keep all URL crawling and enrichment in `aith assess kali katana` / `aith assess gau-endpoints` (or `gau-secrets` / `gau-js-endpoints`) — host-side crawling bypasses the audit pipeline that downstream specialists rely on
- Use the `gau-*` wrappers for gau collection — they pair gau with ingest in one shot and emit a structured JSON summary with cache-decision metadata
- Use `aith assess ingest-endpoints` directly only for non-gau sources (katana output, OpenAPI specs, mitmproxy captures) — gau callers should use `gau-endpoints` instead
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
- `agent/skills/gau-triage/SKILL.md` — deeper follow-up pass for large historical URL corpora: cluster review on top of inline-classified buffer, httpx body capture, and trufflehog secret scan
