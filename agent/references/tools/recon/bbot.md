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

## When to use vs. alternatives

- **vs. subfinder alone:** bbot is materially deeper. Run subfinder first as Phase 0 baseline; reach for bbot when subfinder returned a thin set or budget allows the wall-clock.
- **vs. the manual Phase 0+1+3 pipeline:** bbot replaces the manual pipeline for one-shot bug-bounty triage. The manual pipeline wins when you need surgical pacing or custom orchestration — see `agent/skills/subdomain-enumeration/SKILL.md` "When bbot replaces the manual pipeline".
- **`--allow-deadly`:** required for active modules (fuzzing, brute-force, exploit attempts). The `vigil assess kali bbot` wrapper hard-fails when `--allow-deadly` is passed without `--destructive` so the audit row reflects destructive intent.

## Cross-reference

- Comparison matrix and module rationale: `agent/references/tools/recon/subdomain-enumeration-tools.md` "bbot — passive preset rationale".
- Phase 0 deep-passive in the staged composition: `agent/skills/subdomain-enumeration/SKILL.md`.
