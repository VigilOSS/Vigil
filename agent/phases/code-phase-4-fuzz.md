# Code Phase 4 — Fuzz

**Split load boundary.** During Phase 3, read only the bounded **Pre-entry applicability decision**
section below and persist its `required` or `not_required` receipt before checking readiness for
`fuzz`. After the transition, read the rest of this document before dispatching or executing
anything, and re-read it on a method re-anchor. It carries 4A Target Selection + Harness
Construction, 4B audited Campaign Execution, 4C Crash Triage, the Phase 4 exit gate, and the
terminal submission closeout that applies whether a campaign was required or skipped.
Cross-phase machinery — the Core Loop, the Agent Roster, and the Dispatch Context Template /
Pre-Dispatch Checklist — stays in `agent/operator-core-code.md`; this doc does not restate it.
`code-fuzz-engineer` carries no family mindset lens (see "Phased mindset flow (code)" in
`agent/operator-core-code.md` for why Phase 4 is scoped out of the lens doctrine).

## Pre-entry applicability decision (read during Phase 3 only)

Phase 3 must decide applicability before `code-coverage --require-transition-ready fuzz`: the
backend cannot validate a decision that has not been recorded yet. This bounded pre-entry read is
the only exception to phase-entry loading; do not preload the campaign procedure below.

Record `required` when either condition holds:
- Current backend state contains any non-killed, non-merged `buffer-overflow`, `format-string`,
  `integer-overflow`, `null-dereference`, `type-confusion`, `uninitialized-memory`, or
  `use-after-free` finding. Draft/reopened findings still force `required`; a verified/confirmed
  memory finding cannot be relabeled by an ordinary mutation to waive the obligation. Every such
  finding must be named by the selected target set.
- A critical/high C/C++ target-kind product-reachable parser accepts plausibly untrusted input,
  performs size/lifetime arithmetic, and lacks adequate current fuzz coverage.

Record `not_required` only when there are no forced current findings and the reviewed evidence
proves one sufficient reason: the shipped code is memory-safe with no unsafe/FFI target; no
critical/high C/C++ target-kind parser has plausibly untrusted input; or every otherwise eligible
target has current OSS-Fuzz-equivalent coverage above 70% branch coverage. `not_required` is a
durable current-generation receipt, not an absent campaign, prose handoff, or implicit skip.

Use current backend state, not filesystem guesses:
```bash
vigil assess fetch findings
vigil assess fetch "code/files?repo_id=<id>&limit=5000"
vigil assess contract code-record fuzz-decision
vigil assess code-record fuzz-decision <decision-json-file>
vigil assess code-coverage --require-transition-ready fuzz
vigil assess transition-phase fuzz
```

The decision evidence binds the current source generation/digest and the finding,
classification, parser, and fuzzer-inventory review. Required campaign debt is visible but does
not block entry because Phase 4 exists to close it. A `not_required` receipt clears campaign debt
for this generation while preserving terminal submission/readiness gates.

## Phase 4 entry and execution (read after transition)

Phase 4 uses AI-driven fuzz campaign orchestration to find memory-safety vulnerabilities that
static analysis missed. AI selects targets, writes harnesses, and triages crashes; audited
coverage-guided mutation engines do the exploration.

On entry, re-fetch `vigil assess fetch "code/fuzz/state?repo_id=<id>"`. If the current decision is
`not_required`, do not dispatch a fuzz engineer or run a compiler/fuzzer; continue to **Submission
closeout** and then request the terminal `complete` transition. If it is `required`, verify the
runtime toolchain before Phase 4A:

```bash
vigil assess kali exec --technique FUZZ --intent "verify fuzz compiler and engine toolchain" \
  --probe-kind baseline --phase code-hunt --timeout 60 -- \
  sh -c 'command -v clang && clang --version'
```

If a selected config uses AFL++, run the same audited check for `afl-fuzz` and its configured
compiler wrapper. Missing an optional engine does not invalidate a libFuzzer-only target.

This check and all later compiler, build-system, fuzzer, debugger, sanitizer-repro, and
repository-binary execution run through the audited Kali/runtime surface. Host-side work is
limited to sealed-source reads and engagement-owned configuration/harness authoring. If the
sealed snapshot or required build inputs are not visible beneath `/engagements/$ENGAGEMENT_KEY`,
stop and fix the mount/source boundary; never run the binary on the host as a fallback.

#### Phase 4A: Target Selection + Harness Construction

Dispatch `code-fuzz-engineer` with `agent/skills/code-fuzz-campaign/SKILL.md`.

Provide:

**Backend state (operator fetches and summarizes):**
- Memory-safety findings: `vigil assess fetch findings` — extract non-killed, non-merged findings
  with `defect_family` in `buffer-overflow`, `format-string`, `integer-overflow`,
  `null-dereference`, `type-confusion`, `uninitialized-memory`, or `use-after-free`.
  Include slugs, canonical locations, severity, and
  `verification_state` (confirmed/unreviewed). Pass as a concise summary, not raw JSON dump.
- File classifications: `vigil assess fetch "code/files?repo_id=<id>&limit=5000"` —
  identify critical/high C/C++ files with relevant slot types. The fuzz engineer uses these to
  cross-reference targets against structural index data.

**Filesystem artifact paths (the fuzz engineer reads these directly):**
- Structural index manifest from the Code Source Identity block
- Call graph: `tools/analysis-state/call-graph.json`
- Sealed `snapshot_path` for direct code reads

**Backend threat model:** `vigil assess fetch "code/threat-model/<repo-id>"`; provide the complete
envelope only when `current: true` and its generation/digest match Code Source Identity. A clipped
summary is supplemental and never substitutes for the current envelope.

**Operator-provided context:**
- Build system type (Makefile/CMake/etc.) and the audited Kali toolchain-check result
- Existing fuzzer inventory paths (from `rg 'LLVMFuzzerTestOneInput'` or `ls oss-fuzz/`)
- CWE pattern references: `buffer-overflow.md`, `format-string.md`, `integer-overflow.md`,
  `null-dereference.md`, `type-confusion.md`, `uninitialized-memory.md`, `use-after-free.md`, and
  `fuzz-harness-patterns.md`

The fuzz engineer:
- Selects and ranks targets using structural index, threat model, and Phase 2 findings
- Audits selected targets for specific BOF/integer-overflow patterns
- Writes libFuzzer/AFL++ harnesses using real parser entrypoints
- Compiles under ASAN+UBSAN in the generation-bound build workspace defined by
  `agent/skills/code-fuzz-campaign/SKILL.md`, validates seeds run clean
- Runs quick audited-runtime campaigns (60-second validation runs)
- Configures longer campaigns for overnight execution

**On return from target selection + harness construction:**
```bash
# Campaign state written to tools/fuzz-state/
ls tools/fuzz-state/targets.json
ls tools/fuzz-state/harnesses/*/harness.c
ls tools/fuzz-state/campaigns/*.json

# Record any findings from quick validation runs or pre-fuzz audit
vigil assess finding record code-fuzz-engineer <finding-json>
```

Each file finding follows `vigil assess contract finding record` and carries the current
`provenance.code_snapshot`; a crash produced from a disposable build copy is rechecked against the
sealed source before recording.

#### Phase 4B: Campaign Execution

Campaign execution is a traditional tool run, not an AI agent task. The operator starts campaigns
from Phase 4A configs through the runtime driver's audited execution seam. Before launch or resume,
compare each config's `source_identity` with the current Code Source Identity and reject a
stale/missing tuple. The driver accepts only engagement-root-relative paths, follows symlinks, and
uses `pathlib` component relationships to prove both engagement-root containment and executable
containment beneath the generation-scoped build root; shell globs and string-prefix checks are not
valid containment.

```bash
# Short campaign: repeat once per config so each target has its own audit row.
vigil assess kali exec --technique FUZZ --intent "bounded generation fuzz campaign" \
  --probe-kind payload --phase code-hunt --timeout 1800 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    campaign --config tools/fuzz-state/campaigns/<campaign-id>.json

# Deep campaign: the operator uses the supervised long-job lifecycle, one config per job.
vigil assess kali job start --technique FUZZ --intent "deep generation fuzz campaign" \
  --probe-kind payload --phase code-hunt --timeout 86400 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    campaign --config tools/fuzz-state/campaigns/<deep-campaign-id>.json
```

Record the returned job ID and poll/stop that exact job through the `kali job` lifecycle. Never
detach a host process or use untracked `screen`/`tmux`; never execute a config's binary path
directly from the host.

#### Phase 4C: Crash Triage

After campaigns complete (or produce crashes during quick runs), dispatch `code-fuzz-engineer`
for crash triage.

Provide:
- Current Code Source Identity, its matching structural-index manifest, and the complete current
  threat-model envelope (`current: true` with matching generation/digest)
- Crash artifacts from `tools/fuzz-state/crashes/`
- Campaign configs from `tools/fuzz-state/campaigns/`
- Harness source from `tools/fuzz-state/harnesses/`
- Source code paths beneath the sealed `snapshot_path` for the target functions; a derived build
  copy is execution material, not source evidence

The fuzz engineer triages each crash through the false-positive pipeline:
minimize -> reproduce -> trace -> validate -> classify

**On return from crash triage:**
```bash
# Record true findings
vigil assess finding record code-fuzz-engineer <finding-json>

# Triage reports written to tools/fuzz-state/reports/
ls tools/fuzz-state/reports/*-triage.json

# Persist one terminal receipt per required target only after crash triage.
vigil assess contract code-record fuzz-campaign
vigil assess code-record fuzz-campaign <campaign-receipt-json-file>
```

The campaign receipt names its fuzz-engineer dispatch, current source tuple, selected target,
covered current finding slugs, engine/sanitizers, bounded budget and executions, terminal outcome,
crash count/triage, and engagement-owned evidence. Failed campaigns remain durable but do not
cover the target. This acute receipt is the fuzz engineer's attestation with backend-enforced
binding and evidence integrity; it is not independent proof that the engine ran. A
`completed_crashes_triaged` receipt covers only after every crash is triaged.

**Phase 4 exit gate:**
- [ ] Applicability receipt is current. When it is `not_required`, campaign-only items below are
      not applicable; when it is `required`, all of them must pass.
- [ ] For `required`: all quick campaigns completed
- [ ] For `required`: all crashes triaged (no untriaged crash artifacts)
- [ ] For `required`: true findings recorded with full false-positive gate evidence
- [ ] For `required`: harness bugs fixed and campaigns re-run (if applicable)
- [ ] For `required`: campaign summary written to `tools/fuzz-state/reports/campaign-summary.json`
- [ ] For `required`: each target and forced current native memory-safety finding is covered by
      that target's newest current `completed_no_crash` or `completed_crashes_triaged`
      `code-record fuzz-campaign` receipt
- [ ] `vigil assess code-coverage --require-transition-ready complete` passes

**Submission closeout:**
The code track has no separate `report.md` deliverable — its terminal output is a per-finding
submission, the same as web/runtime engagements. Before dispatching `report-writer`, run a
proactive severity↔CVSS alignment audit, modeled on `agent/operator-core.md` "Mandatory Phase-Exit
Passes" ("Exploit → Report: severity-CVSS alignment audit"): query `vigil assess finding list` and
verify each finding's `severity` matches its `details.cvss_score` band (`high` requires
`cvss_score >= 7.0`, `medium` requires `4.0 <= cvss_score <= 6.9`, `low` requires `cvss_score <
4.0`); fix any mismatch via `vigil assess finding update <slug> --severity <band>
--details-inline '{"cvss_score": <n>, "cvss_vector": "..."}'` —
this catches the most common cleanup-time defect before the transition bounces on it, not after.
Then run `vigil assess check-phase-readiness --phase report` (the shared readiness gate: coverage,
root-cause consolidation, severity/CVSS alignment) and `vigil assess finding report --mode
final --json` (or `--mode draft --json` for interim) to confirm the finding set — this includes
code and web findings from the shared backend with root-cause grouping applied. Fuzz findings
(CF-xxx) carry crash inputs and ASAN reports as evidence.

For each finding to close out, `report-writer` follows the "Submission-First Closeout" procedure in
`agent/skills/report-generation/SKILL.md` — the finding is the source of truth and `submission.md`
is a render of it, so each section is authored once, written back to the finding, and re-rendered.
See `agent/references/examples/submission-direct-buffer-overflow-fuzz.md` for a worked
`--platform direct` example (FUZZ-CONFIRMED buffer overflow, crash input + ASAN report proof):
1. **Scaffold:** `vigil assess export submission <slug> --draft --platform direct` — code findings
   default to `--platform direct` (source review, no external bug-bounty program) unless the code
   work runs under an active bounty engagement (see "Integration with Web Engagement" above), in
   which case use `--platform bugcrowd`/`--platform hackerone` to match the live program. Draft mode
   renders `submissions/<slug>/submission.md` + `submission-context.json` FROM the finding's fields
   and consolidates the finding metadata, any hygiene warnings, the structured proof, and every
   linked command/crash run into ONE "OPERATOR DETAILS — NOT FOR SUBMISSION" reference section below
   the second `---` (present in both draft and final; never pasted), and marks anything missing with
   `[NEEDS: ...]`.
2. **Author + write back to the finding:** author the stable sections and write each back via
   `--payload-file` (the default write path — see "Submission-First Closeout" step 3 in
   `agent/skills/report-generation/SKILL.md`) so the finding holds exactly what would be sent, with
   `steps_to_reproduce` as one authored, self-numbered string.
   Author Evidence from the OPERATOR DETAILS section's structured proof and linked runs plus a
   *targeted* `vigil assess command-run list --q <finding's file/function/parameter>` (keyed tightly
   to this finding, not a broad sweep) to
   catch reproducing runs the linked set missed, then mask any sensitive values and annotate the
   proof lines; store it in `details.evidence`. Fuzz findings (CF-xxx) carry the crash input and
   ASAN report as the gate-satisfying proof (`evidence_ref`/`poc_code`), which the authored Evidence
   references — the raw crash artifact stays under `tools/fuzz-state/` and is not rendered.
3. **Checklist/QA + blind triage:** re-render from the finding (`export submission <slug>
   --platform <same> --draft --overwrite`), run the same review-and-fix QA pass runtime engagements
   use (the consolidated self-review checklist) against the re-rendered `submission.md`, fixing at the source (the
   finding), then blind triage — mandatory for every Medium-or-above finding
   (`agent/skills/blind-triage/SKILL.md`). Record the verdict before publish:
   ```bash
   vigil assess agent decision --kind blind_triage_verdict --payload-json \
     '{"finding_slug":"<slug>","verdict":"<Accept@P1..P5|Need-More-Info|Not-Applicable|Out-of-Scope|Duplicate>","claimed_severity":"<sev>","weak_points":"..."}'
   ```
   Only an `Accept*` verdict clears a finding for submission; anything else routes back to
   `report-writer` or the specialist that owns the finding — an un-recorded verdict reads as no
   triage at all, so record it even for a clean `Accept`.
4. **Publish:** read `vigil assess contract export submission`, then re-run `export submission
   <slug> --platform <same platform> --overwrite` (non-draft) once its executable final gate is
   satisfiable; it reproduces the authored
   content from the finding, registers `submission.md` as a finding-linked artifact
   (`kind="submission"`), and never sets `submission_status` — set that explicitly, per "Submission
   Status Lifecycle" in `agent/skills/report-generation/SKILL.md`, only once the finding is actually
   delivered. Mark included findings `workflow_status=reported` the same way as web engagements once
   delivered.

## Definition of Done

The shared report gate is `vigil assess check-phase-readiness --phase report`; the independent code
source/lifecycle completion gate is `vigil assess code-coverage --require-transition-ready
complete`. Resolve every blocker those report before proceeding — do not re-walk them here by hand. What remains is the
judgment no command can check, modeled on `agent/phases/phase-8-report.md` "Definition of Done":

- [ ] **Cross-finding dedup / lead-selection pass run (judgment: no self-inflicted duplicates).**
  Before submitting any cluster of ≥2 findings that share a root cause, run the explicit
  cross-finding pass in `agent/rules/reporting.md` §18 "Cross-finding dedup pass": cluster the
  submittable set by root cause, designate the lead (highest-impact) finding, and for each
  dup-risk sibling record either a consolidation or a distinct-primitive framing plus
  `vigil assess finding link <sibling-slug> --root-cause <lead-slug>`. `code-variant-hunter`
  output is the textbook case for this here — a confirmed buffer-overflow or taint-path pattern
  found across multiple files/call sites by the variant pass is exactly the multi-file
  same-root-cause cluster §18 exists for; do not file each variant hit as an independent
  submission without running this pass first.
- [ ] **Stale-text scrub clean (judgment: prose vs. current state).** Read each active finding's
  `summary` and `details` text and strip phrases that contradict current state ("severity adjusted
  from X to Y" when it's no longer Y, "originally rated as Z", "merged from W" after W was split
  off, "previously low"/"downgraded to medium" mismatched against the current `severity`). The
  `vigil assess finding list --status active --json | jq -r '.[].slug'` scan loop in
  `agent/skills/report-generation/SKILL.md` "Stale-text scrub" is the executable recipe.
- [ ] **Backend reflects submissions (external reality).** Findings actually delivered (or marked
  accepted/duplicate) have a `submission_status`/`workflow_status` that matches reality — nothing
  stays `draft` if it was sent out. No command can observe the external side of this; only the
  operator can reconcile it.

When both readiness commands are clean AND the judgment items above hold, and every reportable
finding is `reported`, transition phase:

```bash
vigil assess code-coverage --require-transition-ready complete
vigil assess transition-phase complete --track code
```

---

Phase index (path → purpose) lives in `agent/operator-core-code.md` under "Phase Index". Prior:
`agent/phases/code-phase-3-verify-variant.md`. This is the last code-track phase doc; the
submission closeout is described above.
