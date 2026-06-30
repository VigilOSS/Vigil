---
name: surface-collection
description: URL collection pipeline and intelligent triage methodology for Phase 2 work-buffer population
origin: Vigil
---

# Surface Collection

> **`vigil assess kali` audit flags:** use `--technique DISCOVERY` (Katana, gau, and wayback URL collection plus triage expand the attack-surface inventory without sending attack payloads).

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
cat "$DIR/scans/endpoints.txt" | vigil assess ingest-endpoints "$DB" recon
```

If source-analyzer produced a separate endpoint file, ingest it with a distinct source tag:

```bash
cat "$DIR/scans/source-endpoints.txt" | vigil assess ingest-endpoints "$DB" source-analysis
```

### Step 2: Live Crawl via Katana

Run Katana via `vigil assess kali katana` to crawl live targets. Katana is
installed in the runtime container; the typed verb wraps it with audit
recording. Use `agent/references/tools/recon/katana.md` for crawl depth,
headless escalation, rate, exclusion, and ingestion doctrine.

```bash
vigil assess kali katana \
  -u https://target.example -d 3 -c 10 -rl 20 \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_output.txt \
  --technique DISCOVERY --intent "live crawl of target.example" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

**Browser-semantic crawl trigger:** add `-headless` and load
`agent/skills/browser-semantic-analysis/SKILL.md` when that skill's activation
triggers apply. Browser mode is a targeted evidence-correction lane because
API-only and high-volume work stays more accurate in the normal
gau/httpx/fuzzing path.

```bash
vigil assess kali katana \
  -u https://target.example -d 3 -headless -c 5 -rl 10 \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_headless_output.txt \
  --technique DISCOVERY --intent "browser-semantic crawl of target.example" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

**TLS handling:** If the installed Katana version cannot skip invalid TLS, use
audited `curl -k` for spot validation and continue with other collection sources
instead of assuming Katana can crawl it. See the Katana reference before using
version-specific `--extra-args`.

**Auth-aware crawl:** If the engagement's credential record (`vigil auth status`) has
`use_for_requests` set to `true` and a usable credential available, pass cookies/headers:

```bash
vigil assess kali katana \
  -u URL -d 3 -c 10 -rl 20 \
  -H "Cookie: ..." -H "Authorization: Bearer ..." \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_auth_output.txt \
  --technique DISCOVERY --intent "auth-aware crawl of URL" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

**Multi-target:** Run Katana once per in-scope web target from `scope.json` hosts. Combine
output files or ingest each separately with the same source tag.

Ingest:
```bash
cat "$DIR/scans/katana_output.txt" | vigil assess ingest-endpoints "$DB" katana
```

If triage produced metadata-rich candidate JSONL (for example `candidate_records.jsonl`
with curated score, signals, rationale, selected signal, bucket, or live status), ingest
that file through the metadata-preserving path instead of flattening it to URLs:

```bash
vigil assess ingest-candidates "$DB" surface-collector-curated \
  "$DIR/scans/surface-collector/candidate_records.jsonl"
```

### Step 3: Historical URL Enrichment via gau

Use the cache-aware pipeline wrapper. It runs gau (or reuses a fresh cached corpus),
ingests the URLs into `work_items` with inline classification, and emits a structured
JSON summary with `cache_reused: true|false` so the dispatch decision is auditable.

```bash
vigil assess gau-endpoints TARGET_DOMAIN --subs \
  --providers wayback,otx,commoncrawl,urlscan
```

That single verb runs `kali gau` (or reuses
`<engagement>/scans/gau-pipeline/<target_slug>/<cache_key_slug>/gau_output.txt` when a
fresh run is cached for this exact target + flag combination), then pipes the output
through `ingest-endpoints` so inline classification scores every URL at insert time
and inert types (images, fonts) are filtered downstream. The `--max-cache-age-hours`
flag (default 24) tunes reuse aggressiveness; pass `--refresh` to force a fresh gau
run. Different targets — or the same target with different `--subs`/`--providers` —
land in disjoint directories, so caches never cross-contaminate.

**Multi-domain:** Run `gau-endpoints` for each in-scope domain. Each run writes its own
sidecar meta keyed by target so reuse decisions stay per-host.

**Follow-on verbs that share the same cached corpus:**

- `vigil assess gau-secrets TARGET_DOMAIN` — body capture + trufflehog secret scan.
  Defaults to `--no-verification`; pass `--verify` to enable trufflehog's verification.
- `vigil assess gau-js-endpoints TARGET_DOMAIN --fetch-if-missing` — extract endpoints
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
vigil assess ingest-spec "$DB" "$DIR/scans/openapi.json"
```

This creates `api-spec` work items with full endpoint/parameter schemas and generates
coverage candidates automatically.

### Step 5: Dedup Verification

After all sources are ingested, verify the work buffer is clean:

```bash
vigil assess work-buffer "$DB" stats
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
  `priority_score` immediately. Run `vigil assess list-clusters "$DB"` to review the
  resulting cluster set and `vigil assess work-buffer "$DB" defer-cluster <key> --reason "…"`
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
`vigil assess work-buffer defer-cluster` rather than an automatic URL cap.

#### Admin / internal / config URL preservation under egress block

When historical gau discovers admin / internal / config paths on a host that is
currently egress-blocked, save those URLs as intel-notes via
`vigil assess record-intel note` even though the live work item lands in the
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
vigil assess work-buffer "$DB" fetch api 50 surface-collector
vigil assess work-buffer "$DB" fetch page 50 surface-collector
vigil assess work-buffer "$DB" fetch unknown 50 surface-collector
```

Analyze the fetched URLs (without testing them — triage is classification, not probing)
and produce the priority manifest. Then release them back:

```bash
vigil assess work-buffer "$DB" reset-stale 0
```

**Auth-gate redirect classification:** A URL that returns a 302 (or 301/307/308) redirect to a login page, SSO entry point, or policy wall is NOT a terminal "covered / gated" classification — it is a **bypass-test LEAD.** The redirect proves the route exists and is being enforced, which is exactly the signal the auth-bypass sweep needs. Emit a `bypass-lead` surface record for it rather than closing the work item:

```bash
vigil assess record-surface auth-bypass-lead "https://TARGET/protected" surface-collector \
  --rationale "302 -> /login: gate confirmed; route exists and is enforced — bypass-test target" \
  --status discovered
```

Triage must not consume the redirect signal and silently close the work item as "gated." Closing it ends the lead. The auth-bypass sweep (see `agent/skills/auth-bypass/SKILL.md` "Attack the Gate Itself") consumes these leads in Phase 3. See `agent/rules/hunting.md §23` for the general lead-not-verdict doctrine.

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

### Step 6.5: URL-shape body-field harvest (SSRF candidates)

URL / host fields inside admin / settings POST and PUT bodies are SSRF candidates regardless of where the URL appears in the request *path*. The triage in Step 6 keys on URL path patterns; this step keys on *body field names* so SSRF-shaped fields are not missed.

Run this against every captured POST/PUT body in the work buffer:

```bash
vigil assess work-buffer "$DB" --json \
  | jq -r '.[] | select(.method=="POST" or .method=="PUT")
           | "\(.url)\t\(.body_params // empty)"' \
  | grep -iE '\b(url|uri|host|hostname|endpoint|callback|webhook|notify|postback|target|destination|return|redirect|next|continue|origin|fetch|import|source|metadata|discovery)\b\s*[:=]'
```

For each hit, record the candidate so Phase 3 dispatching does not lose it:

```bash
vigil assess record-surface ssrf-candidate "<endpoint>" surface-collector-url-shape \
  --rationale "POST/PUT body field <field> accepts a URL — server-side fetch on save / connection-test (SaaS connector pattern)" \
  --status discovered
```

Then dispatch `vulnerability-analyst` with `--skills ssrf-testing` against the highest-yield candidates — typically admin/settings/enterprise pages, integration list endpoints, and any connection-test handler. See `agent/skills/ssrf-testing/SKILL.md` "SaaS Integration Connector Pattern" for the full testing recipe.

### Step 6.6: Hidden-parameter discovery via Arjun (collect→consume bridge)

The triage above keys on parameters the corpus already shows. Arjun discovers parameters an
endpoint silently accepts but never advertised — inputs no crawl or archive surfaced. Run it on
the param-poor dynamic endpoints with a **bounded first pass** (focused wordlist + `--stable --rate-limit`), escalating for depth.

```bash
# Gate the target list (live + dynamic + template-deduped + param-poor).
# This engagement has no liveness ledger? add --include-unknown.
vigil assess arjun-select "$DB" -o "$DIR/scans/arjun/targets.txt" --param-poor-only --max-per-host 5

# arjun-select also writes a per-method list (targets.txt.GET / .POST / .JSON / .XML) for each verb
# the buffer exposes on a route. `kali arjun -i` takes ONE global -m, so scanning the union under a
# single method would miss the others' hidden params — run one bounded pass per method-list present,
# so POST/JSON body surfaces are scanned under their own verb (not silently as GET).
# Bounded first pass — a focused -w list + --stable --rate-limit keep each run gentle; the default
# list expands to ~100+ chunks/host, enough to overload a rate-sensitive or production target. Keep
# batches small (--max-per-host above) for politeness and a small blast radius. (The runtime patches
# Arjun so one endpoint returning 4xx/5xx is skipped, not fatal — a 429 no longer ends the batch.)
for M in GET POST JSON XML; do
  [ -s "$DIR/scans/arjun/targets.txt.$M" ] || continue   # only methods the buffer actually exposed
  vigil assess kali arjun -i /engagements/$ENGAGEMENT_KEY/scans/arjun/targets.txt.$M -m "$M" \
    -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt --stable --rate-limit 10 \
    --technique PARAM-DISCOVERY --intent "bounded hidden-param discovery over gated buffer" \
    --probe-kind fingerprint --phase collect --timeout 1800
done

# Fold discovered params back in — they re-route the endpoint to its real bucket:
vigil assess ingest-arjun "$DB" /engagements/$ENGAGEMENT_KEY/scans/arjun/<target>/<hash>.json
```

For more depth on a high-value endpoint, drop `-w` (full default list) and/or add `--passive`
(it archive-augments the wordlist — note it still actively scans, so it adds traffic, not
politeness; see `agent/skills/parameter-fuzzing/SKILL.md` and `references/tools/recon/arjun.md`).
Enriched rows carry `selected_by=arjun` and a `triage_rationale` (which names `kali sqlmap` for
DB-class params), so Phase 3 dispatch picks them up like any other high-priority cluster.

### Step 7: Surface and Finding Recording

Before returning to the operator:

**Record surfaces** for all high-signal discoveries:
```bash
vigil assess record-surface <type> <target> <source> \
  --rationale "<why this is high-signal>" \
  --status discovered
```

**Record findings** when triage produces decisive evidence (e.g., an API key with a
non-empty value visible in a URL parameter):
```bash
vigil assess record-finding surface-collector <finding-json-file>
```

### Step 8: Stats and Priority Manifest

Produce the final stats:
```bash
vigil assess work-buffer "$DB" stats
```

Build the priority manifest in the output — a ranked list of attack surface clusters
with triage signals, recommended dispatch order, and suggested vuln-class skills.

## Key Rules

- Keep all URL crawling and enrichment in `vigil assess kali katana` / `vigil assess gau-endpoints` (or `gau-secrets` / `gau-js-endpoints`) — host-side crawling bypasses the audit pipeline that downstream specialists rely on
- Use the `gau-*` wrappers for gau collection — they pair gau with ingest in one shot and emit a structured JSON summary with cache-decision metadata
- Use `vigil assess ingest-candidates` whenever a triage step produced rich candidate JSONL — flattening those records to URLs discards the priority metadata specialists rely on
- Use `vigil assess ingest-endpoints` directly only for non-gau sources (katana output, OpenAPI specs, mitmproxy captures) — gau callers should use `gau-endpoints` unless they have a curated candidate JSONL output
- Use `vigil assess record-surface` for all surface writes — bypassing loses backend sync
- Use `vigil assess record-finding` for any findings — unrecorded findings are lost data
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

- `agent/references/tools/recon/katana.md` — live crawl doctrine, JS-aware defaults, headless escalation, and ingestion handoff
- `references/tools/recon/gau.md` — gau CLI reference and pipeline patterns
- `references/tools/recon/httpx.md` — HTTP probing reference for URL validation
- `agent/skills/browser-semantic-analysis/SKILL.md` — browser execution decision tree for JS-heavy apps, soft errors, browser-originated APIs, and headless/headed deltas
- `agent/references/runtime-guides/browser-semantic-evidence.md` — evidence contract and headed-browser escalation rules
- `agent/skills/gau-triage/SKILL.md` — deeper follow-up pass for large historical URL corpora: cluster review on top of inline-classified buffer, httpx body capture, and trufflehog secret scan
