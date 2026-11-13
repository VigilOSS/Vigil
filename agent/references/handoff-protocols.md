---
description: Agent-to-agent handoff rules and expected downstream actions
category: Shared Runtime References
---

# Agent Handoff Protocols

This is the operator's quick reference for processing each role's return. The phase docs
(`agent/phases/`, via the Phase Index in `operator-core.md`) take precedence: process a return within
the current phase and queue the rest for later phases. Exploit-developer work belongs to Phase 6,
after Verify, under `exploit_policy`.

Every specialist closes with `vigil assess agent handoff` (schema:
`agent/references/runtime-guides/handoff-schema.md`). Render it with `vigil assess agent
render-handoff <agent-id>` for the next dispatch. A final handoff carries `handoff_status=ready` or
`blocked`. Without one, `agent close` refuses and the row stays `in-progress`, which later shows up
as a `stale_dispatch_ready_handoff` or `handoff_gap` report-readiness blocker.

Every follow-up dispatch names the skill the next agent should load. Each role's `## Handoffs`
section gives the skill or the rule for choosing one. When a handoff says "bring the matching
vuln-class skill", choose by the "Use when:" lines in `vigil assess list-skills`.

## Phase 1 Returns

**recon-specialist** (endpoints, technologies, JS URLs, parameters, surface candidates, gaps):

1. Read its coverage gaps first, because they drive the Recon Coverage Gate. Re-dispatch with a
   targeted objective and skill when a material gap remains.
2. JS file URLs go to source-analyzer with `agent/skills/source-analysis/SKILL.md`, unless it is
   already running.
3. Record the technology stack with `vigil assess intel record tech-component <json-file>`.
4. Turn auth boundaries, framework clues and proxy hints into Phase 4–6 hypotheses.

**source-analyzer** (API endpoints, routes, secrets, config objects, gaps):

1. If JS analysis was incomplete (files behind auth, opaque minification), re-dispatch with more
   context.
2. Ingest new endpoints with `vigil assess ingest endpoints source-analysis --file <urls-file>`.
3. Record secrets and tokens straight away with `vigil assess finding record` plus
   `vigil assess post credentials <credential-json-file>`.
4. Routes, object references, mutation paths and parameter names reach Phase 4 through the work
   buffer, not through an immediate dispatch.

**Phase 1 → 2:** once both have returned and their gaps are resolved or accepted, dispatch
surface-collector with the Phase 1 endpoint artifacts, scope targets and credential state
(`vigil auth status`), bringing `agent/skills/surface-collection/SKILL.md`.

## Phase 2 Returns

**surface-collector:** record each intelligence row with `vigil assess intel record <type>
<json-file>`, use its priority surfaces to order Phase 4 dispatch, check `vigil assess work-buffer
stats`, then advance with `vigil assess transition-phase`.

## Phase 4 Returns (CONSUME & TEST)

**vulnerability-analyst:**

1. Make sure every finding is recorded, then queue live findings for Phase 5 Verify rather than
   exploitation.
2. A finding that is real only as part of a chain stays in the normal table with
   `details.chain_required` / `chain_rationale` / `required_followup`.
3. A `fuzzer_needed` runtime issue means dispatching fuzzer within Phase 4 with
   `agent/skills/parameter-fuzzing/SKILL.md` or `agent/skills/directory-fuzzing/SKILL.md`, and feeding
   its results back through the analyst.
4. Mark the batch done (`vigil assess work-buffer done <ids>`) and continue the Phase 4 loop
   (`agent/phases/phase-4-consume-test.md`).

**fuzzer:** ingest new paths with `vigil assess ingest endpoints <source> --file <urls-file>`, send
anomalous responses to vulnerability-analyst, and check that confirmed findings (valid credentials,
for example) were recorded.

## Phase 5 Returns (VERIFY)

**vulnerability-analyst in review mode:** confirmed and downgraded findings stay eligible for
exploit review. Killed findings drop out of exploit and report output. Chain-only findings keep
their `details.chain_required` metadata, and true duplicates are merged before exploit or report
readiness.

## Phase 6 Returns (EXPLOIT)

`exploit_policy` gates dispatch:

- `pause`: ask the human which backend exploit candidates are approved.
- `selected`: approved slugs that are still current candidates.
- `full_send`: all current candidates.

**exploit-developer:**

1. **Confirmed.** Check that the finding carries full evidence, and that captured credentials,
   access records and credential tests were recorded. Then run Credential Auto-Use
   (`agent/references/runtime-guides/auth-recovery.md`). For a multi-step chain, check that
   `vigil assess record-chain` linked the steps. For new attack surface, ingest the auth-aware
   variants and re-test.
2. **Partial.** Record what the partial proof actually shows, at the severity that proof supports,
   and validate the remaining signals in stages before giving up.
3. **Failed.** Log it (`vigil assess log exploit-developer "<title>" "<action>" "<result>"`) and move
   on. If the lead needs targeted re-evaluation, dispatch a single-finding vulnerability-analyst
   retest with the same vuln-class skill. That is a Phase 6 feedback loop, not a return to the
   Phase 4 buffer.
4. **Needs OSINT context.** Dispatch osint-analyst with `agent/skills/osint-recon/SKILL.md`.

**osint-analyst:**

- **High-value CVE with a PoC match.** Record it with `vigil assess intel record cve` and dispatch
  vulnerability-analyst with the matching skill to validate it against the live target. Promote it
  to a finding only from that lane's evidence, because backported patches and disabled modules
  routinely invalidate version-only matches.
- **Breached credentials with target-specific proof.** Record the finding and the credential, then
  run Credential Auto-Use.
- **Historical endpoints.** Run `vigil assess ingest endpoints`.
- **Medium or low intel without target proof.** Keep it as intel only.

## Phase 8 (REPORT)

`agent/phases/phase-8-report.md` owns the per-finding order: writer → QC → cold reproduction →
blind triage → final export. A finding becomes `reported` only after its final export exits 0.
Report-writers query the backend themselves (`vigil assess finding get <slug>`, `vigil assess
export submission <slug> --draft`), so the operator doesn't pre-assemble context.

Before dispatching writers, run `vigil assess check-phase-readiness --phase report` and resolve any
grouping blockers. Overlapping `root_cause_key`, or `canonical_location` + `defect_family`, across
findings is the signal:

- intentional root/sibling groups: `vigil assess finding link <sibling-slug> --root-cause <root-slug>`
- true duplicates only: `vigil assess finding merge <source-slug> <target-slug> "<reason>"`. The
  source becomes `merged` and leaves report output.

The internal `report.md` is optional (phase 8 step f). A drafting report-writer builds it from
`vigil assess finding report --mode final --json`, `chain list --json`, `surfaces` and `summary`,
then registers it with its own `--agent-id`. A separate QC report-writer
(`agent/skills/report-generation/SKILL.md` "Report QC Mode") records `report_qc_verdict` against
the registered bytes, and the report is published only after a current pass.
