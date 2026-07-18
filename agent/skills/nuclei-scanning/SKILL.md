---
name: nuclei-scanning
description: Template-based vulnerability scanning with nuclei for CVEs, misconfigs, and exposures
origin: Vigil
---

# Nuclei Scanning

> **`vigil assess kali` audit flags:** set `--technique` per the template-tag focus — `CVE-VALIDATION` for `-tags cve` runs, `DISCOVERY` for tech-detect and fingerprint templates, `INFO-DISCLOSURE` for exposure templates, and `OTHER` for mixed sweeps spanning many classes.

## When to Activate

- After recon/collect phases when live targets and tech stacks are identified
- When known CVEs match discovered software versions
- Broad vulnerability sweep before targeted manual testing
- Checking for common misconfigurations and exposures across many endpoints

## Tools

- `nuclei` — template-based vulnerability scanner (community templates updated weekly)

## Reactive Sweep Mode (Phase 1-2 primary use)

Reactive sweeps run in-phase against URL deltas each phase produces — they are additive to the
phase they belong to, not a reason to jump ahead. Every time new live URLs land during Phase 1
or Phase 2, fire a focused CVE/misconfig/exposure scan on that delta so template hits become
intel (`intel record tech-component`, `intel record note`, `intel record cve`) and finding
candidates *before* Phase 4 specialists dispatch — that way specialists inherit the signal
rather than rediscovering it from the buffer. Phase 4a below is a coverage audit that re-runs
nuclei **only against gaps** left by the reactive passes — when reactive coverage was thorough,
Phase 4a is a no-op summary, not a second broad sweep.

### When to trigger a reactive sweep

Run one as soon as any Phase 1-2 step adds live URLs to the engagement — early hits change
priority_score on fresh work-buffer entries before specialists pull them. Trigger points:

- After `recon-specialist` returns with an endpoint list (`endpoints.txt` or surfaces)
- After `source-analyzer` harvests JS/HTML URLs (scans/js_urls.txt, extracted endpoint arrays)
- After `surface-collector` ingests Katana / gau output (`vigil assess ingest endpoints` just ran)
- After `subdomain-enumeration` produces live hosts (`subdomains_live.txt` entries land)
- After wildcard expansion adds apex siblings that passed the httpx liveness check

### Build the delta file (host-side `vigil assess`, runtime-side `vigil assess kali`)

The delta is "live URLs not yet covered by a prior reactive nuclei run with the same template
set." Build it on the host (coverage lookup is host-side `vigil assess` work), then write the file
under `/engagements/$ENGAGEMENT_KEY/scans/` so Kali sees it at the same path.

```bash
# Host side — compute the delta
DIR="${ENGAGEMENT_DIR:?set by the engagement launcher}"
KEY=$(basename "$DIR")
RID=$(date -u +%Y%m%dT%H%M%SZ)

# 1. Gather the current live-URL universe from backend state.
vigil assess fetch summary > "$DIR/scans/_summary_$RID.json"
# Take services/hosts plus any freshly-ingested URLs you want covered. Example shape:
jq -r '.. | .url? // empty' "$DIR/scans/_summary_$RID.json" | sort -u \
  > "$DIR/scans/_all_live_$RID.txt"
# (Or splice in the specific file that triggered this sweep — e.g. subdomains_live.txt or
# katana output — so the reactive pass scans only the newly-added URLs.)

# 2. Gather already-scanned URLs from prior reactive runs with the same template bucket.
vigil assess command-run list --q nuclei --tool-bin nuclei --json > \
  "$DIR/scans/_nuclei_runs_$RID.json"
# Every prior reactive run wrote its input list at /engagements/$KEY/scans/nuclei_reactive_<RID>.txt
# and its output JSONL alongside. Extract URLs already covered — use the JSONL artifacts as the
# authoritative "scanned" set because the command field may be truncated.
find "$DIR/scans" -name 'nuclei_reactive_*.jsonl' -print0 | \
  xargs -0 -r jq -r '.["matched-at"] // .host // empty' 2>/dev/null | \
  sort -u > "$DIR/scans/_already_scanned_$RID.txt"

# 3. Subtract already-scanned from all-live, then filter the result to scope via vigil assess
#    scope filter. scope filter does exact-host and wildcard-aware matching against scope.json,
#    so it correctly handles `*.example.com` entries that naive `grep -Ff` treats as literals.
comm -23 \
  "$DIR/scans/_all_live_$RID.txt" \
  "$DIR/scans/_already_scanned_$RID.txt" | \
  vigil assess scope filter - \
  > "$DIR/scans/nuclei_reactive_$RID.txt"
```

The `scope filter` step is the scope boundary — reactive nuclei only scans URLs that are both
new this pass AND attached to a scope.json host (including wildcard expansions). Skipping this
guard risks sweeping an out-of-scope host that was pulled in from a passive source, which would
break the engagement's authorization envelope.

### Invocation (`vigil assess kali nuclei`, exact)

```bash
vigil assess kali nuclei \
  -l /engagements/$ENGAGEMENT_KEY/scans/nuclei_reactive_$RID.txt \
  -t http/cves/,http/misconfiguration/,http/exposures/,http/default-logins/,http/technologies/,http/exposed-panels/ \
  -severity medium,high,critical \
  -as -stream -jsonl \
  -rate-limit 150 -c 25 -bs 25 \
  -stats -si 30 \
  -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_reactive_$RID.jsonl \
  --technique CVE-VALIDATION --intent "reactive nuclei sweep on URL delta" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

Flags explained — each flag earns its place because removing it breaks an assumption downstream:

- `-l <delta file>` reads targets from the computed delta rather than an inline URL, because the
  delta is the whole point of reactive mode — scanning the universe each time bills the same
  templates repeatedly and inflates `command-run list`.
- `-t http/cves/,http/misconfiguration/,http/exposures/,http/default-logins/,http/technologies/,http/exposed-panels/` scopes template
  directories to the discovery-phase classes, because fuzzing/ and payload-heavy templates belong
  to Phase 4 targeted work and would drown early signal in noise.
- `-severity medium,high,critical` suppresses info/low during discovery, because info findings are
  tech-detect data that nuclei's `-as` flag already produces elsewhere.
- `-as` auto-aligns templates with detected tech stack, because untargeted template execution
  wastes rate budget on irrelevant CVEs (no WordPress templates on a Spring app).
- `-stream` processes inputs without buffering, because Phase 1-2 deltas can arrive in small
  batches and buffering delays early hits that should land as intel/findings before Phase 4
  specialists dispatch.
- `-jsonl` emits one JSON object per line, because ingestion tooling and `jq` both expect JSONL
  and regular `-o` text loses the template metadata.
- `-rate-limit 150 -c 25 -bs 25` caps outbound rps, concurrency, and bulk size, because in-scope
  targets are often production-like and WAFs block aggressive scans.
- `-stats -si 30` prints a 30-second stats tick so the operator sees progress without tailing the
  JSONL file — useful when the delta is large.

Run each sweep synchronously — one blocking `vigil assess kali <verb> … --timeout N` at a time. Specialists do NOT background target traffic or use `vigil assess kali job start` (operator-only; see `agent/shared-constraints.md` §2); a long sweep is handled by a generous `--timeout`. Never use broad `pkill`/`killall` (e.g. `pkill -f nmap`) — it stomps sibling agents' processes in the shared runtime. See
`agent/references/runtime-guides/kali-cli.md` "Process cleanup discipline" for the full pattern.

### Template selection rationale

During discovery, stick to `http/cves/`, `http/misconfiguration/`, `http/exposures/`, `http/default-logins/`, `http/technologies/`,
and `http/exposed-panels/`. Skip `http/fuzzing/` and payload-heavy template directories — they belong to
Phase 4 targeted work because (1) their false-positive rate is higher, (2) they generate noisy
request volume that trips WAFs before real testing starts, and (3) their matches require the
specialist skill context to triage correctly. Dropping them from the reactive pass keeps the
intel/finding writes (and any future priority-boost mechanism) aligned with genuine
CVE/misconfig/exposure signal rather than fuzzing noise.

### Per-output lock + zero-byte detection

Concurrent `vigil assess kali nuclei` runs corrupt each other only when they
append to the **same** `-o` jsonl file. The wrapper therefore locks on the
**output path**, not the whole engagement: runs with **distinct `-o` files (or
no `-o`) run fully in parallel** — give each parallel sweep its own `-o` path so
the 4–6-agent swarm is never serialized. Two runs that target the *same* `-o`
file serialize: the second **blocks** until the first finishes (it does not
fail), and only a genuinely hung holder past the timeout raises a clear error.

If a holding PID has died (crashed mid-run), the lock auto-recovers on the next
invocation. Manual cleanup: remove the matching `$ENGAGEMENT_DIR/scans/.<output>.lock`
sidecar only when the PID is dead AND the engagement directory is otherwise stable.

After each run, the wrapper checks the output artifact and stderr together:
- Empty `stdout_path` + stderr lacks `"Templates loaded for current scan: N"` → loader failed at startup; the wrapper prints a WARN telling the operator the run is not a legitimate "no matches" result. The audit row records the failed run for sweep-orphans.
- Empty output AND stderr contains the templates-loaded line → legitimate no-match run; nothing to flag.

This complements the `-as` suppression-cases section above: that section explains why `-as` returns 0 matches on Salesforce/Akamai/CDN edges; the zero-byte detection here distinguishes those legitimate 0-match runs from actual loader failures.

### Known fingerprint-suppression cases (`-as` returns 0 matches)

`-as` selects templates via wappalyzer fingerprinting. On some host classes the fingerprint is too generic for auto-selection and the run returns zero matches even though the templates loaded fine. This is **expected behavior, not tool failure** — confirm via stderr (`Templates loaded for current scan: NNNN`) before treating zero results as a runtime issue.

Hosts where `-as` is known to suppress:

- **Salesforce Experience Cloud / Lightning** — the CDN edge serves a generic chrome that doesn't match any wappalyzer signature. Use explicit `-t http/technologies/salesforce*,http/cves/CVE-*-salesforce-*` (or the vendor-platform-enum skill's payload reference) instead.
- **Akamai-fronted hosts** — the CDN layer hides the underlying stack from wappalyzer. Use `-t http/cves/,http/exposures/,http/misconfiguration/` with explicit paths and rely on dedup to avoid re-scanning.
- **Cloudflare with aggressive bot rules** — fingerprint requests get challenged before wappalyzer can score them. Same workaround.
- **WAF-fronted enterprise edges in general** — when `wafw00f` already flagged a WAF on the host, expect `-as` to underperform.

When you see `Templates loaded for current scan: NNNN` in stderr but zero result rows in stdout, do NOT report nuclei as broken. Re-run with explicit `-t` paths against the same target. Confirm with `vigil assess command-run get <id>` — the stderr preview is the source of truth for "did the run actually execute templates."

### Dedup across runs (Option A — no schema change)

Use `vigil assess command-run list --q nuclei --tool-bin nuclei --json` to compute the "already-scanned" set from prior
reactive runs, then subtract it from the current delta before invoking nuclei. The artifact
filenames and JSONL outputs are durable engagement state — no new column on
`assessment_command_runs` is needed because the inputs (delta file) and outputs (JSONL) live
under `/engagements/$ENGAGEMENT_KEY/scans/` and survive container recreate.

```bash
# jq exclusion-set pattern (runs before nuclei invocation)
vigil assess command-run list --q nuclei --tool-bin nuclei --json | \
  jq -r '.[].command
         | capture("(?<path>/engagements/[^ ]+/scans/nuclei_reactive_[^ ]+\\.txt)")?.path
         // empty' | \
  while IFS= read -r input_list; do
    host_path="${input_list/\/engagements\//$DIR/../}"
    # Concatenate prior input lists into the exclusion set. The nuclei JSONL outputs
    # are the source of truth for "what was actually scanned and returned" — the input
    # list tells us what the run *attempted*, which is the correct exclusion semantic
    # because a URL covered by a prior run doesn't need a retry just because that run
    # returned zero matches.
    [ -f "$host_path" ] && cat "$host_path"
  done | sort -u > "$DIR/scans/_already_scanned_$RID.txt"
```

Option B (add a `coverage_key` column to `assessment_command_runs`) is deferred — Option A covers
the reactive-dedup need today, and schema changes ripple through backend tests and migrations for
little additional value.

### Result ingestion

Reactive nuclei hits enter the engagement as candidates, not auto-recorded findings — manual
revalidation catches template false positives (SSRF probes against patched endpoints,
version-string collisions, etc.) before they reach the finding lifecycle.

- **Critical / high hits** — draft a finding JSON (see `vigil assess contract
  finding record` for the schema), re-validate the template's PoC manually via `vigil assess kali exec` (or the matching typed verb), then
  record with `vigil assess finding record vulnerability-analyst <finding-json-file>`
  only if the re-test reproduces the hit.
- **Medium hits** — record as intel with `vigil assess intel record note <json-file>`,
  noting the template-id and matched URL. Medium hits often seed Phase 4 targeted testing
  rather than standalone findings.
- **Tech fingerprints** (from `-as` template matches like `http/technologies/`) — record via
  `vigil assess intel record tech-component <json-file>` so downstream tooling can match them
  against CVE intel.

### Safety and scope boundary

Reactive nuclei runs only against URLs present in the scope.json host list (enforced by the
`vigil assess scope filter` step above, which handles wildcards correctly). Never sweep a host
whose presence in the delta came from passive sources alone — an out-of-scope sweep breaks
the authorization envelope even if the finding would be accurate.

## Coverage Audit Mode (Phase 4a)

Phase 4a is not a second broad sweep — it is an audit that confirms every in-scope live host
received a reactive pass with the expected template set, and fills any gaps. When Phase 1 and
Phase 2 reactive sweeps were thorough, Phase 4a prints a coverage summary and advances without
running nuclei again. The audit replaces the old "broad nuclei sweep before the work-buffer
loop" pattern because a blind rerun wastes rate budget and inflates `command-run list`
without finding new signal.

### Audit procedure

```bash
DIR="${ENGAGEMENT_DIR:?set by the engagement launcher}"
KEY=$(basename "$DIR")
RID=$(date -u +%Y%m%dT%H%M%SZ)

# 1. Universe: every in-scope live URL the engagement has observed. vigil assess scope filter
#    handles wildcard entries in scope.json correctly; the raw grep -Ff pattern misses
#    `*.example.com` expansions and must not be reintroduced.
vigil assess fetch summary > "$DIR/scans/_summary_audit_$RID.json"
jq -r '.. | .url? // empty' "$DIR/scans/_summary_audit_$RID.json" | sort -u \
  | vigil assess scope filter - \
  > "$DIR/scans/_in_scope_live_audit_$RID.txt"

# 2. Already-covered: every URL that appeared in a prior reactive run's input list.
find "$DIR/scans" -name 'nuclei_reactive_*.txt' -print0 | \
  xargs -0 -r cat 2>/dev/null | sort -u \
  > "$DIR/scans/_already_swept_audit_$RID.txt"

# 3. Gap: in-scope live ∖ already-covered.
comm -23 \
  "$DIR/scans/_in_scope_live_audit_$RID.txt" \
  "$DIR/scans/_already_swept_audit_$RID.txt" \
  > "$DIR/scans/nuclei_gap_$RID.txt"

GAP_COUNT=$(wc -l < "$DIR/scans/nuclei_gap_$RID.txt")
if [ "$GAP_COUNT" -eq 0 ]; then
  COVERED_COUNT=$(wc -l < "$DIR/scans/_in_scope_live_audit_$RID.txt")
  vigil assess log operator \
    "Phase 4a nuclei coverage audit" \
    "check-phase-readiness --phase consume" \
    "Reactive sweeps covered all ${COVERED_COUNT} in-scope live URLs; no rerun needed." \
    --actor-kind operator
  exit 0
fi
```

### Invocation (gaps only, `vigil assess kali nuclei`)

```bash
vigil assess kali nuclei \
  -l /engagements/$ENGAGEMENT_KEY/scans/nuclei_gap_$RID.txt \
  -t http/cves/,http/misconfiguration/,http/exposures/,http/default-logins/,http/technologies/,http/exposed-panels/ \
  -severity medium,high,critical \
  -as -stream -jsonl \
  -rate-limit 150 -c 25 -bs 25 \
  -stats -si 30 \
  -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_gap_$RID.jsonl \
  --technique CVE-VALIDATION --intent "Phase 4a gap-only nuclei coverage audit" \
  --probe-kind fingerprint --phase consume-test --timeout 1800
```

Same template set and severity as reactive mode so Phase 4a coverage is directly comparable to
what the reactive passes attempted. Any host reaching Phase 4a without reactive coverage usually
came from a late ingestion (e.g., an endpoint `vulnerability-analyst` discovered mid-Phase-4 and
re-ingested) — the audit picks it up.

### Triage and ingestion

Results triage identically to reactive mode: critical/high → finding candidates after manual
revalidation; medium → intel; `-as` tech fingerprints → `intel record tech-component`. Record
the audit result in the engagement activity log even when the gap list is empty — the absence
of a run is itself coverage evidence, which matters for the report.

## Phase-4 substrate sweep scoping & safety (CR-27 / CR-30)

A broad Phase-4 nuclei sweep (full CVE/exposure/misconfig sets × every in-scope
host) is **not politely completable** and collides with per-host VA lanes. Scope it
deliberately along every dimension below before running it.

### Severity: default high+critical for a broad substrate sweep

For a broad host-scale substrate sweep, **default to `-severity high,critical`** — the
signal-to-request-volume ratio is what makes the sweep completable. (The in-phase
*reactive* and *gap-audit* passes above deliberately keep `medium,high,critical`
because their host/template scope is already small and medium hits seed Phase-4
intel; do not widen a broad substrate sweep to medium.)

### Curated cheap-template subset, scoped by template DIRECTORIES — not broad tags

Even a curated **tag** selection over-pulls at host-scale (a real engagement
resolved one tag selection to 1,515 templates × 155 hosts = ~561k requests). Bound
the template dimension by specific template **directories**, not tags:

```
-t http/takeovers/ -t http/exposed-panels/ -t http/default-logins/
```

Stick to the cheap, high-signal discovery-phase directories (`http/cves/`,
`http/misconfiguration/`, `http/exposures/`, `http/default-logins/`,
`http/technologies/`, `http/exposed-panels/`, `http/takeovers/`); skip
`http/fuzzing/` and payload-heavy directories — higher FP rate and noisy request
volume that trips WAFs before real testing starts.

### Host-scale guard: bound the host dimension on large surfaces

`-as` and gap/delta dedup shrink the *template* and *redundant-host* dimensions but
never cap the **host** dimension, so the templates × hosts blowup can still occur.
When the in-scope live-host count is large (≳25–50), **bound a broad substrate
sweep to a small host subset** — dedicated / origin / non-CDN hosts (use the
asnmap→cero origin-IP axis and the Cloud-fronted-vs-Origin trait rows in
`agent/references/recon/rate-calibration.md` to identify them). Size the subset
against the request budget: `templates × hosts ≈ total requests`.

> **Corollary — prefer OSINT CVE matching at host-scale.** OSINT version→CVE
> matching (`intel record cve` via osint-analyst) often delivers most of nuclei's
> CVE-detection value *without* the per-host request volume. On high-friction /
> large-host-count surfaces, prefer OSINT CVE matching + targeted exploit-developer
> validation over a broad CVE-template host-scale sweep.

### Per-category split with per-pass watchdogs

Run **one nuclei pass per template directory** rather than a single monolithic
invocation. Give each pass its own `--timeout` (the per-pass watchdog) and its own
`-o` path. Distinct `-o` files do not contend on the output lock, so the per-directory
passes parallelize, and a single hung category times out on its own watchdog instead
of stalling the whole sweep:

```bash
for D in http/takeovers/ http/exposed-panels/ http/default-logins/; do
  CAT=$(echo "$D" | tr '/' '_')
  vigil assess kali nuclei \
    -l /engagements/$ENGAGEMENT_KEY/scans/nuclei_substrate_$RID.txt \
    -t "$D" -severity high,critical -as -stream -jsonl \
    -rate-limit 150 -c 25 -bs 25 -stats -si 30 \
    -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_substrate_${CAT}_$RID.jsonl \
    --technique CVE-VALIDATION --intent "Phase-4 substrate sweep ($D)" \
    --probe-kind fingerprint --phase consume-test --timeout 1200
done
```

The wrapper **injects `-exclude-tags dos,fuzz,intrusive,brute-force` by default**
(politeness/safety guard) so these passes never fire DoS/fuzz/intrusive/brute-force
templates against production-like targets — you do not need to pass it yourself
(passing your own `-exclude-tags`/`-etags` overrides it verbatim).

### Operator-sweep vs VA-lane collision avoidance (CR-30)

A separate operator-run substrate sweep **collides** with the Phase-4 VA fan-out
when both touch the same hosts (shared rate budget, duplicated traffic, racing
tools). Pick one of two collision-free patterns:

1. **Run-to-completion first.** Run the bounded substrate sweep to *completion*
   before any VA lane touches that host subset, so the VA lanes inherit the signal
   instead of racing it. (This is what the Phase-4a coverage audit already does — it
   runs once, before the work-buffer/VA loop.)
2. **Fold into the owning VA lane.** Hand the scoped, per-host-subset nuclei call to
   the vulnerability-analyst lane that *owns* that subset, so a single lane is the
   only thing touching those hosts. Use this when the substrate work is naturally
   per-host-subset rather than engagement-wide.

Never run a third concurrent operator sweep across hosts a VA lane is actively
testing.

### Prerequisites & lead-quality caveats

- **Templates are not pre-installed.** The runtime images install only the nuclei
  binary, so the **first** nuclei run in a fresh runtime pays the
  `nuclei -update-templates` auto-install latency (the templates download before any
  scan executes). Budget for it: either run the manual `Update Templates` step below
  before the first sweep, or give the first sweep a generous `--timeout`. This is a
  one-time, per-runtime cost.
- **OOB infra must be up before blind-class testing.** Templates that rely on
  out-of-band callbacks produce false negatives if the shared interactsh
  infrastructure or persisted tenant route is not ready. Confirm `vigil oob status
  --json` shows `server=true`, `frpc=true`, and `route_matches=true` **before** running
  blind/OOB templates, then use the typed wrapper's `--oob-mode vigil` — see
  `nuclei.md` "OOB Callbacks". When OOB is unavailable, keep the default
  `--oob-mode none` and defer blind-class testing rather than recording a clean OOB
  template as a true negative.
- **gf candidate tags are leads, not verdicts.** gf buckets (and any `gf:<bucket>`
  priority signal) are **high false-positive** — treat a gf hit as a *lead* that
  points a template/probe at a candidate, never as a confirmed match. Downstream
  validation (a real template hit or a manual PoC) is always required.
- **Authenticated surfaces need an authed pass.** Some surfaces only yield to
  authenticated testing; when credentials are in scope, defer those hosts to an
  authenticated nuclei pass rather than recording an unauth sweep as full coverage.

## Methodology

The engagement dir is bind-mounted into Kali at `/engagements/$ENGAGEMENT_KEY/` — write input lists
and scan output directly under `/engagements/$ENGAGEMENT_KEY/scans/` so the host sees the same
files as `$ENGAGEMENT_DIR/scans/` without a ferry. Reserve `/tmp` for transient scratch, because
anything in `/tmp` disappears on container recreate.

### 1. Update Templates
```bash
nuclei -update-templates
```
Always update before an engagement to get the latest CVE and misconfiguration checks.

### 2. Targeted Severity Scan
```bash
# Critical and high severity only (fast, high-signal)
nuclei -u https://TARGET -severity critical,high -o /tmp/nuclei_crithigh.txt

# All severities for thorough coverage
nuclei -u https://TARGET -o /tmp/nuclei_full.txt
```

### 3. Technology-Specific Scanning
```bash
# Scan by technology tags (from recon fingerprinting)
nuclei -u https://TARGET -tags apache,nginx,php,wordpress,spring
nuclei -u https://TARGET -tags cve -severity critical,high

# Specific CVE template
nuclei -u https://TARGET -t cves/2024/ -severity critical,high
```

### 4. Bulk Target Scanning
```bash
# Scan all live targets from recon
nuclei -l /tmp/live_targets.txt -severity critical,high \
  -rate-limit 100 -o /tmp/nuclei_bulk.txt -jsonl

# With concurrency control
nuclei -l /tmp/live_targets.txt -c 25 -rate-limit 50
```

### 5. Misconfiguration and Exposure Checks
```bash
# Common misconfigs: exposed panels, debug endpoints, default creds
nuclei -u https://TARGET -tags misconfig,exposure,default-login

# Specific checks
nuclei -u https://TARGET -tags takeover       # Subdomain takeover
nuclei -u https://TARGET -tags tech           # Technology detection
nuclei -u https://TARGET -tags file           # Sensitive file exposure
```

### 6. Output and Triage
```bash
# JSON lines for structured processing
nuclei -u https://TARGET -severity critical,high -jsonl -o /tmp/nuclei.jsonl

# Parse results
cat /tmp/nuclei.jsonl | jq '.info.name, .info.severity, .matched-at'
```

## Triage Rules

- **Critical/High nuclei hits**: Validate manually before recording as findings. Nuclei templates can have false positives.
- **`http/takeovers/` hits are a signature, not a verdict.** A takeover template firing confirms the dangling-DNS *signature*, not that the resource is *claimable by you* — claimability depends on the provider's current re-binding controls (CloudFront cert gate, Azure reserved labels, owned parent zones, S3 region pinning / global-namespace already-taken). Treat the hit as a screening lead: load `agent/skills/cloud-exposure/SKILL.md` (which owns the per-provider claimability rules and the prove-or-kill benign own-account claim, citing `agent/references/subdomain-takeover.md`) and confirm claimability there before recording a takeover finding. The bare signature is the #1 false-positive class for this bug type (one engagement saw 7 perfect-signature CloudFront candidates, all non-claimable).
- **Medium/Low hits**: Log as intelligence or surface candidates. Only promote to findings after manual confirmation.
- **Info-level detections**: Use for tech stack enrichment and hypothesis generation, not findings.

## What to Record

- Validated vulnerabilities with exact nuclei template ID and manual confirmation
- False positives identified (helps future template selection)
- Tech stack detections that inform further testing choices

## Extended Resources

- `agent/references/runtime-guides/dispatch-resource-policy.md` "Recon Dispatch Resource Policy" — canonical per-target rate calibration table; `--rate-limit / -bs / -c` defaults pulled from the trait row.
- `agent/references/tools/recon/nuclei.md` — nuclei flags, template management, output formats
- `agent/references/subdomain-takeover.md` — why an `http/takeovers/` hit is a screening signature, not a verdict: the per-provider claimability rules and the benign own-account claim that proves or kills a takeover candidate before a finding is recorded.
