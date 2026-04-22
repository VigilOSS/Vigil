---
name: gau-triage
description: Deep triage of large historical URL corpora — load gf buckets with stated reasons, emit a cluster manifest for classify-work/defer-cluster, download inert content, and scan for secrets with trufflehog + jsleak
origin: AI Threat Hunting
---

# GAU Triage

> **Kali MCP audit header:** use `X-Technique: DISCOVERY` (gau harvests historical URLs from public archives; triage runs classify them without attacking the live target).

Operator-dispatched deeper pass over a gau (or any large URL) corpus **after** mechanical
ingestion in Phase 2. Produces a cluster manifest the operator feeds into `assess.py
classify-work` and `assess.py dispatch defer-cluster`, plus stored response bodies and
secret-scan results. This skill does not replace `surface-collection` — it extends it by
adding the depth that surface-collector cannot afford inline at high URL counts.

## When to Activate

- Run when the corpus holds **~500+ URLs** — surface-collector's inline triage loses fidelity at that scale because the bucket analysis is context-bound.
- Run mandatorily when the corpus holds **~5000+ URLs** — the cluster manifest produced here is the only way the operator can defer low-signal clusters without re-reading every URL.
- Run when response-body secret scanning is in scope — stored bodies feed `trufflehog` and optionally `jsleak` for a complementary regex pass.
- Skip when the corpus is small (<500 URLs), when auth-only surfaces dominate, or when Phase 3 is mid-flight and further triage would delay exploitation — surface-collector already covers that case.

## Tools

All run inside the shared Kali MCP runtime:

- `uro` — smart structural URL deduplication (collapses `/page/1`, `/page/2` → one representative)
- `gf` — parameter-pattern classifier. Cite the matching bucket reference from `agent/references/gf-patterns/<bucket>.md` before loading it
- `httpx` with `-store-response` — live probe with body capture for downstream secret scanning
- `trufflehog` — mandatory secret scan across stored bodies (800+ detectors, v3 filesystem mode)
- `jsleak` — optional complementary regex-based JS secret scanner. If not in the Kali image, trufflehog-only coverage is acceptable and the install hint belongs in `agent/docker/runtime-full/Dockerfile` as a follow-up (out of scope for this skill)
- `jq` — output formatting and manifest assembly

Host side: `./scripts/assess.py record-surface`, `./scripts/assess.py record-finding`,
`./scripts/assess.py classify-work`, `./scripts/assess.py dispatch defer-cluster`.

## Storage Rule

Kali mounts the engagement dir at `/engagements/$ENGAGEMENT_KEY/`. Stage ephemeral work under `/tmp/gau-triage-$RID/` inside the container; persist durable artifacts directly to `/engagements/$ENGAGEMENT_KEY/scans/gau-triage/$RID/` — the host sees the same files under `$DIR/scans/gau-triage/$RID/`. Engagement-scoped artifacts never land in `/data/` — that path is reserved for shared-infrastructure state.

Pick `RID` (run id) as a timestamped slug, e.g. `RID=$(date -u +%Y%m%dT%H%M%SZ)`.

## Pipeline

Set up variables inside the Kali MCP shell — `$ENGAGEMENT_KEY` is exported by the engagement launcher and visible inside the container:

```bash
KEY="${ENGAGEMENT_KEY:?exported by the engagement launcher}"
RID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="/engagements/$KEY/scans/gau-triage/$RID"
CT_WORK="/tmp/gau-triage-$RID"
mkdir -p "$OUT" "$CT_WORK" "$CT_WORK/bodies"
```

The canonical input is the gau corpus already produced by surface-collection at `/engagements/$KEY/scans/gau_output.txt`. If it is missing, stop and ask the operator to run surface-collector first — gau-triage extends that pipeline, it does not replace it.

### Step 1 — Stage input from the engagement mount

Read the gau corpus straight from the mount so downstream steps keep scratch work off the durable directory:

```bash
cp "/engagements/$KEY/scans/gau_output.txt" "$CT_WORK/gau_raw.txt"
wc -l "$CT_WORK/gau_raw.txt"
```

### Step 2 — Filter inert extensions and structural-dedup

Drop images, fonts, and binaries before gf runs — these waste gf cycles and trufflehog will not extract secrets from them. Then collapse structurally similar URLs with `uro`:

```bash
INERT_EXT='jpg|jpeg|png|gif|webp|svg|ico|woff|woff2|ttf|eot|otf|ttc|mp3|mp4|webm|avi|mov|flac|wav|ogg|pdf|zip|tar|gz|rar|7z|exe|dll|so|dylib'
grep -viE "\\.(${INERT_EXT})(\\?|$)" "$CT_WORK/gau_raw.txt" \
  | grep -vE '^\S+\?ver=[0-9.]+$' \
  | uro \
  > "$CT_WORK/gau_deduped.txt"
wc -l "$CT_WORK/gau_raw.txt" "$CT_WORK/gau_deduped.txt"
```

### Step 3 — Load gf buckets with stated reasons

Before invoking any bucket, cite the matching reference file and the observed corpus signal that justifies loading it. This keeps the skill aligned with the `AGENTS.md` "Positive instructions with reasoning" standard — the operator sees *why* a bucket is in play, not just that it ran.

Check each bucket's load conditions (documented in `agent/references/gf-patterns/<bucket>.md`) against the corpus. Only run buckets whose conditions are present; running every bucket blindly drains the per-engagement context budget without adding signal.

Example load-and-run template (report the reason in output, then run):

```bash
# Announce: "Loading `ssrf` bucket because N URLs in this corpus contain url=/redirect=/callback= query parameters — see agent/references/gf-patterns/ssrf.md."
gf ssrf < "$CT_WORK/gau_deduped.txt" > "$CT_WORK/gf_ssrf.txt" 2>/dev/null || true

# Announce: "Loading `sqli` bucket because N URLs carry id=/q=/sort= — see agent/references/gf-patterns/sqli.md."
gf sqli < "$CT_WORK/gau_deduped.txt" > "$CT_WORK/gf_sqli.txt" 2>/dev/null || true

# Repeat for buckets whose load conditions fire. Reference the per-bucket file for each.
```

Candidate buckets (each has a reference at `agent/references/gf-patterns/<bucket>.md`):
`rce, ssrf, sqli, lfi, idor, debug_logic, redirect, ssti, xss, interestingparams`. The
`interestingsubs` and `interestingEXT` concepts are handled via ingest-time hostname
routing and the extension filter in Step 2 — they are documented in the reference library
for analyst context but are not direct `gf` runs.

For each loaded bucket, capture: the URL count, 3-5 sample URLs, and the proposed
`cluster_key` that will be attached to matching work items when the operator runs
`assess.py classify-work`. Prefixes the classifier emits:

- `gf:<bucket>` — standard vuln-class buckets (`gf:ssrf`, `gf:sqli`, `gf:rce`, ...)
- `overlay:<name>` — narrowly-scoped platform overlays (e.g. `overlay:salesforce` for
  Aura/Lightning controllers such as `ApexActionController.execute`). Overlays sit below
  full gf buckets in weight and are meant to catch high-volume platform surfaces whose
  controller names don't map cleanly to a generic bucket.
- `path:/<first-two-segments>` — fallback when nothing matched.

Capture overlay clusters in the manifest too — they are a valid defer target when the
overlay fired on a low-signal corner of the platform (static asset CDN, localization paths).

If `gf` patterns are missing, the Dockerfile install of Gf-Patterns is broken — stop and reseed `~/.gf/` from `github.com/1ndianl33t/Gf-Patterns`.

### Step 4 — Emit cluster manifest for the operator handoff

Write a structured manifest the operator can feed into `assess.py classify-work` and `assess.py dispatch defer-cluster`. The operator contract: after gau-triage returns, the operator runs `assess.py classify-work $DB` (which derives `cluster_key` and `priority_score` from URL structure using the same bucket weights documented in the reference library) and then `assess.py dispatch $DB defer-cluster <key> --reason "..."` for any cluster the manifest flagged as defer-worthy.

Assemble the manifest with `jq` rather than Python heredocs:

```bash
MANIFEST="$CT_WORK/cluster_manifest.json"
# Build the loaded_buckets array from the gf_*.txt files that fired.
LOADED_BUCKETS=$(
  for f in "$CT_WORK"/gf_*.txt; do
    [ -s "$f" ] || continue
    bucket="$(basename "$f" .txt | sed 's/^gf_//')"
    count="$(wc -l < "$f")"
    samples="$(head -n 5 "$f" | jq -R . | jq -sc .)"
    jq -nc --arg bucket "$bucket" --argjson count "$count" --argjson samples "$samples" \
      --arg reason "Loaded because $count URLs matched; see agent/references/gf-patterns/$bucket.md" \
      '{bucket:$bucket, reason:$reason, url_count:$count, samples:$samples}'
  done | jq -sc .
)
jq -n --arg rid "$RID" \
      --argjson raw "$(wc -l < "$CT_WORK/gau_raw.txt")" \
      --argjson dedup "$(wc -l < "$CT_WORK/gau_deduped.txt")" \
      --argjson buckets "$LOADED_BUCKETS" \
  '{run_id:$rid, gau_raw_count:$raw, dedup_count:$dedup,
    loaded_buckets:$buckets, proposed_defers:[],
    sensitive_files_found:[], secrets_detected:[]}' > "$MANIFEST"
```

Populate `proposed_defers` with clusters the operator should skip — static asset paths, CDN-backed mirrors, and localization directories. Each entry carries `cluster_key`, a free-text `reason`, and the `url_count` so the operator can judge the throughput win.

### Step 5 — Download inert-filtered bodies and scan for secrets

Download all `.js`, `.css`, `.map`, and `.json` responses with `httpx -store-response`. Filter the input list so images/fonts/binaries never leave the URL queue — the Step 2 inert filter already did this on the deduped corpus, so reuse it. Cap per-body size at 1 MB to prevent runaway disk use:

```bash
grep -iE '\.(js|css|map|json)(\?|$)' "$CT_WORK/gau_deduped.txt" > "$CT_WORK/body_targets.txt"
wc -l "$CT_WORK/body_targets.txt"

httpx -l "$CT_WORK/body_targets.txt" -silent \
  -store-response -store-response-dir "$CT_WORK/bodies" \
  -mc 200,301,302,401,403 \
  -status-code -content-length -title -tech-detect \
  -follow-redirects -threads 20 -rate-limit 30 \
  -response-size-to-save 1048576 \
  -o "$CT_WORK/httpx_results.txt"
```

Mandatorily run `trufflehog` in filesystem mode across the downloaded bodies — it carries the primary detector set (800+ detectors) and covers the widest secret surface. Default is `--no-verification` so trufflehog will not send discovered tokens to AWS/GitHub/Slack/etc. to test them; opt-in verification (`--results=verified`) requires explicit operator authorization of out-of-scope traffic.

```bash
trufflehog filesystem "$CT_WORK/bodies/" \
  --no-update --no-verification --concurrency 8 --json \
  > "$CT_WORK/trufflehog.json"
wc -l "$CT_WORK/trufflehog.json"
```

Run `jsleak` as a complementary regex pass over the `.js` subset when it is installed — it catches a narrower class of JS-specific secret patterns that trufflehog's default detectors may miss. If `jsleak` is not present in the current Kali runtime, trufflehog-only coverage is acceptable; flag the gap in the returned output so the operator can track the install follow-up on `agent/docker/runtime-full/Dockerfile`.

```bash
if command -v jsleak >/dev/null 2>&1; then
  find "$CT_WORK/bodies" -name '*.js' -print0 \
    | xargs -0 jsleak --json \
    > "$CT_WORK/jsleak.json" 2>/dev/null || true
else
  echo "jsleak not installed — trufflehog coverage is acceptable; install hint belongs in Dockerfile." \
    > "$CT_WORK/jsleak.missing"
fi
```

Merge trufflehog (and jsleak when present) findings into the cluster manifest's `secrets_detected` array so the operator reads one file, not three:

```bash
TH_FINDINGS=$(jq -sc '[.[] | {detector:.DetectorName, file:.SourceMetadata.Data.Filesystem.file, raw:(.Raw[0:120])}]' "$CT_WORK/trufflehog.json" 2>/dev/null || echo '[]')
jq --argjson secrets "$TH_FINDINGS" '.secrets_detected = $secrets' "$MANIFEST" > "$MANIFEST.tmp" && mv "$MANIFEST.tmp" "$MANIFEST"
```

### Step 6 — Persist artifacts and record high-signal findings

Copy durable artifacts to the engagement mount:

```bash
cp -r "$CT_WORK/." "$OUT/"
ls "$OUT"
```

For each reproducible high-confidence trufflehog or jsleak hit where the secret demonstrably leaks material an attacker can use (token, key, credential, session id), record a finding via the host script. Unverified hits that cannot be reproduced → `record-surface`, not `record-finding`. No speculative findings per `rules/hunting.md`.

```bash
# Host side. $DIR is the repo-side twin of /engagements/$KEY — same bytes on disk.
./scripts/assess.py contract record-finding   # inspect required fields
./scripts/assess.py record-finding surface-collector "$DIR/scans/gau-triage/$RID/findings/<slug>.json"
```

## Operator Handoff

After gau-triage returns the manifest, the operator runs:

```bash
# Derive cluster_key/priority_score for all pending work_items using the same bucket weights
# documented in agent/references/gf-patterns/*.md.
./scripts/assess.py classify-work "$DB"

# For each cluster the manifest flagged in proposed_defers, defer it so downstream dispatch skips it.
./scripts/assess.py dispatch "$DB" defer-cluster "<cluster_key>" --reason "<manifest reason>"

# Inspect the resulting cluster set ahead of Phase 3 dispatch.
./scripts/assess.py list-clusters "$DB"
```

## Output Contract

Return to the operator:

- The run directory (`$DIR/scans/gau-triage/$RID/` on the host) containing `cluster_manifest.json`, per-bucket `gf_*.txt` files, `httpx_results.txt`, `bodies/`, `trufflehog.json`, and optional `jsleak.json`
- Totals: raw count, deduped count, per-bucket counts, unique trufflehog detector names
- The list of proposed defer clusters with stated reasons
- Any recorded finding slugs and surface ids
- Explicit statement of whether `--results=verified` live verification was enabled (must be `false` unless the operator authorized external validation traffic)
- Whether `jsleak` ran or was flagged missing for the Dockerfile follow-up

## Key Rules

- All target-facing probes go through Kali MCP — host-side curl or wget against in-scope targets bypasses runtime isolation
- Cite `agent/references/gf-patterns/<bucket>.md` with a "Load because X" reason before running any gf bucket — blind per-bucket drains miss the signal calibration the reference library provides
- Filter inert extensions (images, fonts, binaries) before httpx body download — scanning them wastes disk and yields no trufflehog signal
- `trufflehog` is mandatory on every run; `jsleak` is optional and gated on runtime availability
- `trufflehog` default is `--no-verification`; `--results=verified` (live verification) requires operator consent
- Cap body storage at 1 MB per response via httpx `-response-size-to-save`
- No speculative findings — reproduce the hit before recording

## Extended Resources

- `agent/references/INDEX.md` (GF Pattern Library section) — per-bucket reference library with load conditions, parameter keys, weights, and examples
- `agent/references/tools/recon/trufflehog.md` — TruffleHog v3 CLI, filesystem mode, verification flags
- `agent/references/tools/recon/gf.md` — gf load order, gf-before-uro rule
- `agent/references/tools/recon/httpx.md` — httpx body storage and rate tuning
- `agent/references/tools/recon/gau.md` — gau (upstream source for the corpus this skill triages)
- `agent/skills/surface-collection/SKILL.md` — Phase 2 collection upstream of this skill (gau-triage is a follow-up pass)
- `agent/skills/sensitive-data-detection/SKILL.md` — ad-hoc body/secret scanning for single responses (not bulk corpora)
