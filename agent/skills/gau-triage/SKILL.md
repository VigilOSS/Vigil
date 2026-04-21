---
name: gau-triage
description: Deep triage of large historical URL corpora — gf classification, httpx body fetch, trufflehog secret scan, ranked priority output
origin: AI Threat Hunting
---

# GAU Triage

> **Kali MCP audit header:** use `X-Technique: DISCOVERY` (gau harvests historical URLs from public archives; triage runs classify them without attacking the live target).

Operator-dispatched deeper pass over a gau (or any large URL) corpus **after** mechanical
ingestion in Phase 2. Produces classified URL buckets, stored response bodies, secret-scan
results, and a ranked review list. This skill does not replace `surface-collection` — it
extends it.

## When to Activate

- Phase 2 has completed ingestion but the raw gau corpus has not been deeply scanned
- Historical URL set is large (~500+) or spans multiple subdomains
- Operator wants pre-Phase-3 triage of high-signal parameter patterns (SSRF, IDOR, redirect, LFI, SQLi, debug)
- Response-body secret scanning is in scope (stored bodies → trufflehog)

Skip when the gau corpus is small (< ~200 URLs), when auth-only surfaces dominate, or when
Phase 3 is already mid-flight and further triage would delay exploitation.

## Tools

All run inside the shared Kali MCP runtime:

- `uro` — smart structural URL deduplication (collapses `/page/1`, `/page/2` → one representative)
- `gf` — parameter-pattern classifier with community patterns from 1ndianl33t/Gf-Patterns
- `httpx` — live probe with `-store-response` body capture
- `trufflehog` — 800+ secret detectors, used in **filesystem mode** against stored bodies
- `jq` — output formatting

Host side: `base64`, `tar`, `./scripts/assess.py record-surface|record-finding`.

## Storage Rule

The shared Kali runtime does not mount `$ENGAGEMENT_DIR`. Stage ephemeral work under
`/tmp/gau-triage-<RID>/` inside the container; persist durable artifacts under
`$DIR/scans/gau-triage/<RID>/` on the host before returning. **Do not** write
engagement-scoped artifacts into `/data/` — that path is reserved for operator-infrastructure
state (OOB logs, pwncat sessions, frpc config).

Pick `RID` (run id) as a timestamped slug, e.g. `RID=$(date -u +%Y%m%dT%H%M%SZ)`.

## Pipeline

Set up variables:

```bash
DIR="${ENGAGEMENT_DIR:?set by the engagement launcher}"
RID="$(date -u +%Y%m%dT%H%M%SZ)"
HOST_OUT="$DIR/scans/gau-triage/$RID"
CT_WORK="/tmp/gau-triage-$RID"
mkdir -p "$HOST_OUT"
```

The input is a gau corpus at `$DIR/scans/gau_output.txt` (produced by surface-collection
Step 3). If it does not exist, stop and ask the operator to run gau first via surface-collector.

### Step 1 — Stage input (host → container)

Ferry the raw gau output into the container's ephemeral work dir. Run via Kali MCP
command-execution so the audit trail records the stage:

```bash
# Kali MCP — inside container
mkdir -p $CT_WORK && echo "ready"
```

Then stream the host file in via the MCP command tool. Prefer `cat` piped into a heredoc-free
shell write — the gau output is plain text:

```bash
# Kali MCP — inside container (the operator pipes the host file into this stdin)
cat > $CT_WORK/gau_raw.txt
# (operator feeds $DIR/scans/gau_output.txt to this command's stdin)
```

If the MCP tool does not expose stdin piping from host, fall back to the tar+base64 ferry:

```bash
# host
tar czf - -C "$DIR/scans" gau_output.txt | base64 | \
  <kali-mcp-exec> "mkdir -p $CT_WORK && cd $CT_WORK && base64 -d | tar xzf -"
# rename to canonical name
<kali-mcp-exec> "mv $CT_WORK/gau_output.txt $CT_WORK/gau_raw.txt"
```

Record the raw input count for the manifest: `wc -l $CT_WORK/gau_raw.txt`.

### Step 2 — Filter static assets and structural-dedup

Inside Kali MCP. Drop media, fonts, and cache-buster-only URLs, then collapse structurally
similar URLs with `uro`:

```bash
grep -viE '\.(jpg|jpeg|png|gif|webp|svg|ico|woff2?|ttf|eot|otf|ttc|mp3|mp4|webm|avi|mov|flac|wav|ogg|pdf)(\?|$)' \
  $CT_WORK/gau_raw.txt \
  | grep -vE '^\S+\?ver=[0-9.]+$' \
  | uro \
  > $CT_WORK/gau_deduped.txt
wc -l $CT_WORK/gau_raw.txt $CT_WORK/gau_deduped.txt
```

### Step 3 — gf parameter classification (run before per-bucket uro)

`gf` buckets URLs by suspicious parameter patterns. Run against the deduped set. Running
`gf` **before** any further uro pass per bucket preserves the representative URLs for each
attack class:

```bash
for pat in xss ssrf redirect idor sqli lfi debug_logic interestingparams interestingsubs; do
  gf "$pat" < $CT_WORK/gau_deduped.txt > "$CT_WORK/gf_${pat}.txt" 2>/dev/null || true
done
wc -l $CT_WORK/gf_*.txt

# Priority superset = union of gf hits (ssrf, redirect, idor, sqli, lfi, debug_logic are highest signal)
cat $CT_WORK/gf_ssrf.txt $CT_WORK/gf_redirect.txt $CT_WORK/gf_idor.txt \
    $CT_WORK/gf_sqli.txt $CT_WORK/gf_lfi.txt $CT_WORK/gf_debug_logic.txt \
  | sort -u > $CT_WORK/gf_priority.txt
wc -l $CT_WORK/gf_priority.txt
```

If `gf` returns patterns are missing, the Dockerfile install of Gf-Patterns is broken —
stop and reseed `~/.gf/` from `github.com/1ndianl33t/Gf-Patterns`.

### Step 4 — Live fetch with body storage

One `httpx` pass over the deduped superset. `-response-size-to-save 1048576` caps each
stored body at 1 MB to prevent runaway disk use:

```bash
httpx -l $CT_WORK/gau_deduped.txt -silent \
  -store-response -store-response-dir $CT_WORK/responses \
  -mc 200,301,302,401,403 \
  -status-code -content-length -title -tech-detect \
  -follow-redirects -threads 20 -rate-limit 30 \
  -response-size-to-save 1048576 \
  -o $CT_WORK/httpx_results.txt
wc -l $CT_WORK/httpx_results.txt
du -sh $CT_WORK/responses
```

**Rate limiting**: `-rate-limit 30` is a safe default. Drop to `10-15` for WAF-fronted
targets; raise to `50` for CDN-fronted static content. Large URL sets (> 5k) should split
input and run sequentially rather than tuning rate-limit up.

### Step 5 — Secret scan with TruffleHog (no external HTTP)

Default is **`--no-verification`** — TruffleHog will not send discovered tokens to AWS/
GitHub/Slack/etc. to test them. Opt-in verification uses `--results=verified` and requires
explicit operator authorization of out-of-scope traffic.

```bash
trufflehog filesystem $CT_WORK/responses \
  --no-update --no-verification --json \
  > $CT_WORK/trufflehog.json
wc -l $CT_WORK/trufflehog.json
# Unique detector types hit
jq -r '.DetectorName' $CT_WORK/trufflehog.json 2>/dev/null | sort -u
```

**Opt-in live verification** (only if operator explicitly enables out-of-scope traffic for
this engagement):

```bash
trufflehog filesystem $CT_WORK/responses \
  --no-update --results=verified --json \
  > $CT_WORK/trufflehog_verified.json
```

TruffleHog v3 takes the scan path as a positional argument (the `--directory` flag also
works in v3 but positional is preferred for single-path scans).

### Step 6 — Format ranked review list

Use `jq` — do not embed Python heredocs:

```bash
# Detector summary
jq -r '"\(.DetectorName)\t\(.SourceMetadata.Data.Filesystem.file)\t\(.Raw[0:120])"' \
  $CT_WORK/trufflehog.json 2>/dev/null \
  | sort -u \
  > $CT_WORK/review_secrets.tsv

# Per-bucket counts
{ echo "=== gf bucket summary ==="
  for f in $CT_WORK/gf_*.txt; do
    printf "%-30s %6d\n" "$(basename "$f" .txt)" "$(wc -l < "$f")"
  done
  echo
  echo "=== input / dedup ==="
  printf "raw      : %d\ndeduped  : %d\npriority : %d\n" \
    "$(wc -l < $CT_WORK/gau_raw.txt)" \
    "$(wc -l < $CT_WORK/gau_deduped.txt)" \
    "$(wc -l < $CT_WORK/gf_priority.txt)"
  echo
  echo "=== trufflehog detectors (unique) ==="
  jq -r '.DetectorName' $CT_WORK/trufflehog.json 2>/dev/null | sort | uniq -c | sort -rn
} > $CT_WORK/manifest.txt
cat $CT_WORK/manifest.txt
```

### Step 7 — Persist artifacts to host

Ferry everything under `$CT_WORK/` back to `$HOST_OUT/` on the host. Responses may be
large; archive and stream:

```bash
# Kali MCP — inside container
tar czf - -C $CT_WORK . | base64
# host — decode stdout into $HOST_OUT
# (wrapped by the MCP tool as output capture -> host shell)
# e.g. <mcp-output-capture> | base64 -d | tar xzf - -C "$HOST_OUT/"
ls "$HOST_OUT"
```

Sanity check that `/data/` was not polluted:

```bash
# Kali MCP — should return CLEAN (only operator-infra files present)
ls /data | grep -vE '^(oob-|shell-|frpc|start-oob)' || echo CLEAN
```

### Step 8 — Record surfaces and findings

For each high-signal hit, record via the backend. The dispatching agent is
`surface-collector`; findings use the `SC` prefix allocated by `assess.py record-finding`.

`record-surface` takes **positional** `type target source`, with `--rationale`,
`--evidence-ref`, and `--status` as flags. Valid `--status` values are
`covered, deferred, discovered, not_applicable` (not `pending`). Map gf buckets to
surface types like this:

| gf bucket | Surface type |
|---|---|
| `gf_ssrf` | `dynamic_render` |
| `gf_redirect` | `workflow_token` |
| `gf_idor` | `object_reference` |
| `gf_lfi` | `file_handling` |
| `gf_sqli` | `object_reference` |
| `gf_debug_logic` | `privileged_write` |
| `gf_xss` / `gf_interestingparams` | closest match; skip recording if none fits |

```bash
# Representative: record an SSRF-candidate surface per high-signal URL
./scripts/assess.py record-surface dynamic_render "$URL" surface-collector \
  --rationale "gf ssrf parameter pattern in historical URL (gau-triage)" \
  --status discovered
```

Before recording a finding, run the live contract helper — do **not** guess fields from
memory:

```bash
./scripts/assess.py contract record-finding
```

Then construct a JSON payload matching `schemas/finding-record.schema.json` (root required:
`title, severity, workflow_status, verification_state, verification_disposition,
defect_family, root_cause_key, auth_context, canonical_location, summary, evidence_ref,
notes, details`; `details` requires `evidence, impact`). Record:

```bash
./scripts/assess.py record-finding surface-collector "$HOST_OUT/findings/<slug>.json"
```

Record a finding **only** when:

- A trufflehog hit is reproducible (the string is present in the corresponding response body), **and**
- The secret demonstrably leaks material the attacker can use (token, key, credential, session id)

Unverified trufflehog hits that look suspect but cannot be reproduced → **surface**, not
finding. No speculative findings per `rules/hunting.md`.

## Output Contract

Return to the operator:

- `$HOST_OUT/` path containing `gf_*.txt`, `httpx_results.txt`, `responses/`, `trufflehog.json`, `review_secrets.tsv`, `manifest.txt`
- Totals: raw count, deduped count, per-gf-bucket counts, unique trufflehog detectors
- Any recorded finding slugs and surface ids
- Explicit statement of whether `--results=verified` live verification was enabled
  (must be `false` unless the operator authorized external validation traffic for this engagement)

## Key Rules

- All target-facing probes go through Kali MCP — host-side curl or wget against in-scope
  targets bypasses runtime isolation
- `gf` runs before `uro` per-bucket — reversing loses high-signal representatives
- `trufflehog` default is `--no-verification`; `--results=verified` (live verification) requires operator consent
- Engagement-scoped artifacts never land in `/data/`
- No speculative findings — reproduce the hit before recording
- Cap body storage at 1 MB per response via httpx `-response-size-to-save`

## Extended Resources

- `references/tools/recon/trufflehog.md` — TruffleHog v3 CLI, filesystem mode, verification flags
- `references/tools/recon/gf.md` — gf patterns, load order, gf-before-uro rule
- `references/tools/recon/httpx.md` — httpx body storage and rate tuning
- `references/tools/recon/gau.md` — gau (upstream source for the corpus this skill triages)
- `agent/skills/surface-collection/SKILL.md` — Phase 2 collection upstream of this skill
- `agent/skills/sensitive-data-detection/SKILL.md` — ad-hoc body/secret scanning (use this
  skill when the input is a single response or JS bundle, not a bulk corpus)
