---
description: Multi-module passive preset (Phase 0 deep); `subdomain-enum -rf passive`, `--allow-deadly` gated behind `--destructive`
skill: subdomain-enumeration
---

# bbot

**Purpose:** Multi-module passive recon orchestrator. The `subdomain-enum` preset chains 50+ passive sources (CT, DNS aggregators, security feeds, GitHub) in one invocation. High-coverage but slow (15-30 min wall-clock per target).

For live engagement targets, run bbot via `vigil assess kali bbot` (typed verb, audit-flag-aware). `--allow-deadly` is hard-gated behind `--destructive` because deadly modules attack the target.

**Where it lives:** `/usr/local/bin/bbot` in `runtime-full` (`pipx install bbot` into `/opt/pipx` — see `agent/docker/runtime-full/Dockerfile`). RAM usage during a run is 200-500 MB.

## Resource-safe invocation (passive-only preset)

`-rf passive` filters to passive-only modules, so no traffic touches the target during the run. This is the canonical Phase 0 deep-passive invocation.

```bash
vigil assess kali bbot -t target.example -p subdomain-enum -rf passive \
  -o /engagements/$ENGAGEMENT_KEY/scans/bbot_subs \
  --technique OSINT --intent "Phase 0 deep passive enum (bbot subdomain-enum preset)" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

To narrow to specific modules when the canonical preset is too broad or too slow:

```bash
vigil assess kali bbot -t target.example -m crt -m dnsdumpster -rf passive \
  -o /engagements/$ENGAGEMENT_KEY/scans/bbot_narrow \
  --technique OSINT --intent "narrow bbot module set (crt + dnsdumpster only)" \
  --probe-kind fingerprint --phase recon --timeout 600
```

## Output reliability — harvest JSON, never the final txt (CR-24 / I-011)

bbot v2.6.0's `dnsresolve` module crash-loops mid-run and **truncates the final
`*.txt` outputs to ~250 B**, and the `excavate` module emits mangled, false
hostnames. Trusting bbot's raw txt output is therefore unsafe. The
`vigil assess kali bbot` wrapper neutralizes this by **emitting machine-parseable
JSON by default**: it injects `-om json` and writes `output.json` into the output
dir (defaulting the dir to `/engagements/$ENGAGEMENT_KEY/scans/bbot_<ts>` when you
do not pass `-o`). The injection is idempotent — if you supply your own `-om` via
`--extra-args` the wrapper does not add a second one, and an explicit `-o` is never
overridden.

**Harvest workflow (always JSON, never txt):**

1. Read `output.json` from the bbot output dir — one JSON event per line.
2. Select **only events of type `DNS_NAME`** (`jq -r 'select(.type=="DNS_NAME") | .data'`).
   Do NOT harvest `excavate`-derived hostnames — they are frequently mangled/false.
3. **DNS-validate every harvested name before it enters the candidate set** — resolve
   each via the host resolver (the host-exec / dnsx host path, never the container
   resolver) and keep only names that resolve. Drop unresolvable / excavate-false names.

```bash
# After the bbot run, harvest validated DNS_NAME candidates from output.json:
jq -r 'select(.type=="DNS_NAME") | .data' \
  /engagements/$ENGAGEMENT_KEY/scans/bbot_<ts>/output.json | sort -u \
  > /engagements/$ENGAGEMENT_KEY/scans/bbot_dns_names.txt
# Then DNS-validate (host path) before merging into the candidate set.
```

**Positioning: passive convergence cross-check only.** Because of the output
unreliability above, treat bbot as a *passive convergence cross-check* — a final
mop-up source that confirms/adds the occasional name the keyed-passive + CT + brute
pipeline missed — **not** a trusted standalone breadth source whose raw output you
ingest wholesale. Run it `-rf passive` (no target traffic), harvest validated
DNS_NAME events, and feed them through the same DNS-validate gate as every other
recon source.

## When to use vs. alternatives

- **vs. subfinder alone:** bbot is materially deeper. Run subfinder first as Phase 0 baseline; reach for bbot when subfinder returned a thin set or budget allows the wall-clock.
- **vs. the manual Phase 0+1+3 pipeline:** bbot replaces the manual pipeline for one-shot bug-bounty triage. The manual pipeline wins when you need surgical pacing or custom orchestration — see `agent/skills/subdomain-enumeration/SKILL.md` "When bbot replaces the manual pipeline".
- **`--allow-deadly`:** required for active modules (fuzzing, brute-force, exploit attempts). The `vigil assess kali bbot` wrapper hard-fails when `--allow-deadly` is passed without `--destructive` so the audit row reflects destructive intent.

## Cross-reference

- Comparison matrix and module rationale: `agent/references/tools/recon/subdomain-enumeration-tools.md` "bbot — passive preset rationale".
- Phase 0 deep-passive in the staged composition: `agent/skills/subdomain-enumeration/SKILL.md`.
