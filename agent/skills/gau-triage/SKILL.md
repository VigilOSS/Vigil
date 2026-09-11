---
name: gau-triage
description: Decide which gau pipeline verb to run, interpret its structured output, and write findings/surfaces from secrets and JS-discovered endpoints. The full bash pipeline (gau → uro → httpx → trufflehog) is now packaged as `vigil assess gau secrets`; this skill is the dispatch + interpretation layer.
origin: Vigil
---

# GAU Triage

> **`vigil assess kali` audit flags:** the inner kali invocations (gau, uro, httpx, trufflehog) carry their own audit rows; the wrappers stamp `--technique RECON --probe-kind fingerprint --phase recon` automatically.

The gau pipeline is now three composable verbs that all share one cached gau corpus:

| Verb | What it does | Output written to |
|---|---|---|
| `vigil assess gau endpoints <target>` | Cache-aware gau, then ingest into work_items with inline classification | `work_items` rows + cluster assignments |
| `vigil assess gau secrets <target>` | Cache-aware gau → uro dedup → httpx body capture → trufflehog scan | bodies, trufflehog JSON, secrets manifest |
| `vigil assess gau js-endpoints <target>` | route-pattern extraction over JS bodies → resolve to absolute URLs → ingest as `source=js-extract` | new `work_items` rows hidden in JS bundles |

Artifacts for each `(target, gau-flag-set)` pair live under `<engagement>/scans/gau-pipeline/<target_slug>/<cache_key_slug>/`, including `gau_output.txt`, the sidecar `gau_output.meta.json`, intermediate filtered/dedup files, `bodies/`, and `trufflehog.json`. Two targets — or the same target run with different `--subs`/`--providers` — never share `bodies/` or trufflehog input. The wrapper announces cache reuse on stderr and includes `cache_reused: true|false` in the JSON summary so the dispatch-time decision is auditable.

> `gau js-endpoints` is a post-processor — it does not run gau. Pass it the **same** `--subs` and `--providers` values you used on `gau secrets`/`gau endpoints` so it locates the right `<target>/<cache_key>/bodies/` directory.

## When to Activate

Dispatch this skill when the operator wants signal beyond what live crawling produced — typically right after Phase 2 surface collection lands:

1. **Suspect missing endpoints** (small work buffer, large historical surface) → run `gau endpoints` first, then `gau js-endpoints` to catch JS-only routes.
2. **Secret scanning is in scope** → run `gau secrets`. The default keeps trufflehog in `--no-verification` mode; pass `--verify` to enable trufflehog's verification step.
3. **Reviewing existing clusters** → no fresh run needed; read clusters via `vigil assess work-buffer clusters`. Inline classification already scored every URL at ingest time.

Skip the pipeline entirely when the corpus is small (<500 URLs), no JS bundles are present, and secret scanning is out of scope.

## Verb Decision Tree

```
gau endpoints <target>
  └─ work_items grew by N rows? Inspect clusters via `work-buffer clusters`.
     ├─ many `gf:trust_surface` / `gf:upload_fields` → dispatch vulnerability-analyst
     └─ many `gf:interestingext` (e.g., `.bak`, `.env`, `.sql`) → run a targeted `nuclei -t exposures/` check and manually reproduce any hit

gau js-endpoints <target>  (after gau secrets, or with --fetch-if-missing)
  └─ "ingested_count" > 0 → JS-hidden routes added; classification scored them
     └─ inspect new clusters; routes named like `/admin/*`, `/internal/*` are high-value

gau secrets <target>
  └─ "findings_count" > 0 → review trufflehog output, reproduce each hit before recording finding
     ├─ verified=true (only when --verify used) → high-confidence; finding record draft
     └─ verified=false → still worth review; many regex-only hits are exploitable secrets
```

## Cache reuse semantics

`gau endpoints` and `gau secrets` are the verbs that actually call gau, so they
own cache reuse. Each looks up `<engagement>/scans/gau-pipeline/<target_slug>/<cache_key_slug>/gau_output.txt`
and checks six conditions before reusing it:

1. Operator did NOT pass `--refresh`
2. The cached output file exists and is non-empty
3. Sidecar `gau_output.meta.json` exists and parses
4. Cached run's `exit_code == 0` and `target` matches the current target
5. Cached run's `cache_key` matches the current corpus-affecting flags
   (`--subs`, `--providers`) — toggling one of those triggers a fresh run
   so the operator does not silently get the wrong corpus
6. Cached output age ≤ `--max-cache-age-hours` (default 24)

Failure of any condition triggers a fresh gau run and an explicit stderr message
naming which condition failed. The JSON summary always carries
`cache_reused: true|false` and `cache_decision_reason: <human string>`.

`gau js-endpoints` is a post-processor: it reads the existing cache + bodies
that `gau endpoints`/`gau secrets` produced and does not run gau itself. It
intentionally does not expose `--refresh` or `--max-cache-age-hours` — refresh
the corpus by re-running the verb that produced it.

## Output Contract (per verb)

### `gau endpoints` JSON keys

`verb`, `target`, `cache_reused`, `cache_decision_reason`, `cache_age_hours`, `gau_status`, `gau_exit_code`, `gau_argv`, `gau_output_path`, `gau_line_count`, `ingest_source`, `db_path`, `work_items_total`, `work_items_pending`, `work_items_skipped`, `top_clusters`.

### `gau secrets` JSON keys

All of `gau endpoints`'s cache keys, plus `gau_raw_count`, `filtered_count`, `deduped_count`, `bodies_dir`, `bodies_captured`, `httpx_results_path`, `reused_bodies`, `trufflehog_path`, `verify_enabled`, `detector_counts`, `findings_count`, `findings_preview`.

### `gau js-endpoints` JSON keys

`verb`, `target`, `bodies_dir`, `bodies_fetched`, `js_bodies_scanned`, `raw_endpoints_extracted`, `unique_in_scope_urls`, `ingested_count`, `ingest_source`, `db_path`, `per_body_preview`.

## Recording high-confidence hits

For each reproducible high-confidence trufflehog or JS-extracted endpoint where the secret demonstrably leaks material an attacker can use (token, key, credential, session id), record a finding via the host script. Unverified-but-suspicious hits → `record-surface`, not `finding record`. No speculative findings per `rules/hunting.md`.

```bash
# Inspect required fields, then write the finding draft.
vigil assess contract finding record
vigil assess finding record gau-triage <path-to-finding-json> --agent-id <your-agent_id>
```

## Key Rules

- **Use the wrapper verbs** — they pair the gau call with the ingest step in one shot, so the work buffer cannot end up empty after a successful gau run.
- **Cache reuse is intentional and auditable** — the stderr `[gau-pipeline] REUSING ...` message and the `cache_reused: true` JSON field both surface the decision; if you want a fresh run, pass `--refresh`.
- **Reproduce each hit before recording it as a finding** — speculative findings pollute the backend and mislead Phase 4 specialists.
- **JS-extracted endpoints get `source='js-extract'`** so report-writer can audit which work_items came from bundle extraction versus crawl/spec ingestion.

## Extended Resources

- `agent/scripts/assess/lib/gau_pipeline.py` — shared cache logic, sidecar metadata, and JS route patterns
- `agent/scripts/assess/commands/gau_endpoints.py` — Stream A wrapper source
- `agent/scripts/assess/commands/gau_secrets.py` — Stream B wrapper source
- `agent/scripts/assess/commands/gau_js_endpoints.py` — Stream C wrapper source
- `agent/references/tools/recon/gau.md` — gau CLI reference (provider list, output format)
- `agent/references/tools/recon/httpx.md` — httpx body capture and rate tuning
- `agent/references/tools/recon/trufflehog.md` — TruffleHog v3 detector list, verification flag semantics
- `agent/scripts/assess/lib/classify_buckets.py` — gf-style bucket weights inline classification uses
- `agent/skills/surface-collection/SKILL.md` — Phase 2 collection upstream (operator typically calls gau endpoints from there)
- `agent/skills/sensitive-data-detection/SKILL.md` — ad-hoc body/secret scanning for single responses (not bulk corpora)
