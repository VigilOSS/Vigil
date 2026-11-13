---
description: Shell recipes for nuclei reactive-delta construction, the Phase 4a gap audit, and the per-directory Phase-4 substrate sweep loop
skill: nuclei-scanning
---

# Nuclei sweep recipes

Load when you build a reactive delta, run the Phase 4a coverage audit, or run a Phase-4
substrate sweep from `agent/skills/nuclei-scanning/SKILL.md`. Delta and gap computation is
host-side `vigil assess` work; files go under `$ENGAGEMENT_DIR/scans/`, which Kali sees as
`/engagements/$ENGAGEMENT_KEY/scans/` (bind mount; `/tmp` disappears on container recreate).

## Reactive delta

The delta is live in-scope URLs not yet in any prior reactive run's **input list**. Input lists
are the right exclusion set: a URL a prior run attempted needs no retry because it returned zero
matches, and JSONL `matched-at` would list only URLs that hit.

```bash
DIR="${ENGAGEMENT_DIR:?set by the engagement launcher}"
RID=$(date -u +%Y%m%dT%H%M%SZ)

# 1. Live-URL universe from backend state (or splice in the file that triggered this sweep,
#    e.g. subdomains_live.txt or katana output).
vigil assess fetch summary > "$DIR/scans/_summary_$RID.json"
jq -r '.. | .url? // empty' "$DIR/scans/_summary_$RID.json" | sort -u > "$DIR/scans/_all_live_$RID.txt"

# 2. Already attempted: every prior reactive and gap input list.
find "$DIR/scans" \( -name 'nuclei_reactive_*.txt' -o -name 'nuclei_gap_*.txt' \) -print0 \
  | xargs -0 -r cat 2>/dev/null | sort -u > "$DIR/scans/_already_scanned_$RID.txt"
#    `vigil assess command-run list --q nuclei --json` shows the runs themselves when a list is missing.

# 3. Subtract, then scope-filter (wildcard-aware against scope.json; a plain grep -Ff treats
#    `*.example.com` as a literal and is not a scope check).
comm -23 "$DIR/scans/_all_live_$RID.txt" "$DIR/scans/_already_scanned_$RID.txt" \
  | vigil assess scope filter - > "$DIR/scans/nuclei_reactive_$RID.txt"
```

## Phase 4a gap audit

```bash
DIR="${ENGAGEMENT_DIR:?set by the engagement launcher}"
RID=$(date -u +%Y%m%dT%H%M%SZ)
vigil assess fetch summary > "$DIR/scans/_summary_audit_$RID.json"
jq -r '.. | .url? // empty' "$DIR/scans/_summary_audit_$RID.json" | sort -u \
  | vigil assess scope filter - > "$DIR/scans/_in_scope_live_audit_$RID.txt"
find "$DIR/scans" \( -name 'nuclei_reactive_*.txt' -o -name 'nuclei_gap_*.txt' \) -print0 \
  | xargs -0 -r cat 2>/dev/null | sort -u > "$DIR/scans/_already_swept_audit_$RID.txt"
comm -23 "$DIR/scans/_in_scope_live_audit_$RID.txt" "$DIR/scans/_already_swept_audit_$RID.txt" \
  > "$DIR/scans/nuclei_gap_$RID.txt"
if [ ! -s "$DIR/scans/nuclei_gap_$RID.txt" ]; then
  COVERED=$(wc -l < "$DIR/scans/_in_scope_live_audit_$RID.txt")
  vigil assess log recon-specialist "Phase 4a nuclei coverage audit" \
    "Compared in-scope live URLs against every nuclei reactive/gap input list" \
    "Reactive sweeps covered all ${COVERED} in-scope live URLs; no rerun needed."
fi
```

When the gap file is non-empty, run the skill's standard invocation with
`-l /engagements/$ENGAGEMENT_KEY/scans/nuclei_gap_$RID.txt`,
`-o .../nuclei_gap_$RID.jsonl`, `--intent "Phase 4a gap-only nuclei coverage audit"` and
`--phase consume-test`.

## Phase-4 substrate sweep, one pass per directory

Build `nuclei_substrate_$RID.txt` from the bounded host subset the skill's "Phase-4 substrate sweep
scoping" picks. The rate flags are the standard invocation's ceiling; lower them to the dispatch
budget or to the nuclei column of the WAF-tier row in `agent/references/recon/rate-calibration.md`,
whichever is lower.

```bash
for D in http/takeovers/ http/exposed-panels/ http/default-logins/; do
  CAT=$(echo "$D" | tr '/' '_')
  vigil assess kali nuclei \
    -l /engagements/$ENGAGEMENT_KEY/scans/nuclei_substrate_$RID.txt \
    -t "$D" -severity high,critical -as -stream -jsonl \
    -rate-limit 150 -c 25 -bs 25 --extra-args="-stats -si 30" \
    -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_substrate_${CAT}_$RID.jsonl \
    --technique CVE-VALIDATION --intent "Phase-4 substrate sweep ($D)" \
    --probe-kind fingerprint --phase consume-test --timeout 600
done
```

Each pass has its own `--timeout` (a hung category times out alone) and its own `-o` (no
output-lock contention).
