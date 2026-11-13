# Code Phase 4 — Fuzz

**Split load boundary.** During Phase 3, read only the bounded **Pre-entry applicability decision**
section below and persist its `required` or `not_required` receipt before checking readiness for
`fuzz`. After the transition, read the rest of this document before dispatching or executing
anything, and re-read it on a method re-anchor. Cross-phase machinery stays in
`agent/operator-core-code.md`; `code-fuzz-engineer` carries no family lens.

## Pre-entry applicability decision (read during Phase 3 only)

Decide applicability before `code-coverage --require-transition-ready fuzz`, because the backend
cannot validate a decision that has not been recorded. This is the only exception to phase-entry
loading; do not preload the campaign procedure below.

Record `required` when either condition holds:
- Current backend state holds any non-killed, non-merged `buffer-overflow`, `format-string`,
  `integer-overflow`, `null-dereference`, `type-confusion`, `uninitialized-memory`, or
  `use-after-free` finding. Draft and reopened findings still force `required`, an ordinary
  mutation cannot relabel a verified memory finding to waive the obligation, and the selected
  target set names every such finding.
- A critical/high C/C++ target-kind product-reachable parser accepts plausibly untrusted input,
  performs size/lifetime arithmetic, and lacks adequate current fuzz coverage.

Record `not_required` only when no finding forces `required` and the reviewed evidence proves one
sufficient reason: the shipped code is memory-safe with no unsafe/FFI target; no critical/high
C/C++ target-kind parser takes plausibly untrusted input; or every otherwise eligible target has
current OSS-Fuzz-equivalent coverage above 70% branch coverage. `not_required` is a durable
current-generation receipt, never an absent campaign, prose handoff, or implicit skip.

Decide from current backend state, not filesystem guesses. `vigil assess contract code-record
fuzz-decision` shows the decision payload, whose evidence binds the current source
generation/digest and the finding, classification, parser, and fuzzer-inventory review:
```bash
vigil assess fetch findings --paginate
vigil assess fetch "code/files?repo_id=<id>" --paginate
vigil assess code-record fuzz-decision <decision-json-file>
vigil assess run-audit code-receipt record <run-id> <fuzz-decision-link-json>   # run-accounted work
vigil assess code-coverage --require-transition-ready fuzz
vigil assess transition-phase fuzz
```

The classification read needs `--paginate`: a hand-written `limit` returns one page, and a
`not_required` receipt built from it is silent about the files that never arrived. Required
campaign debt is visible but does not block entry, since Phase 4 exists to close it. A
`not_required` receipt clears campaign debt for this generation and leaves the terminal
submission and readiness gates in place.

## Phase 4 entry and execution (read after transition)

Re-fetch `vigil assess fetch "code/fuzz/state?repo_id=<id>"`. If the current decision is
`not_required`, dispatch no fuzz engineer and run no compiler or fuzzer; continue to **Submission
closeout**, then request the terminal `complete` transition. If it is `required`, verify the
runtime toolchain before Phase 4A:

```bash
vigil assess kali exec --technique FUZZ --intent "verify fuzz compiler and engine toolchain" \
  --probe-kind baseline --phase code-fuzz --timeout 60 -- \
  sh -c 'command -v clang && clang --version'
```

When a selected config uses AFL++, run the same audited check for `afl-fuzz` and its compiler
wrapper; a missing optional engine does not invalidate a libFuzzer-only target. This check and every
later compile, build, fuzz, debug, sanitizer repro, and repository-binary run go through the audited
runtime ("Host reads; the runtime executes" in `agent/operator-core-code.md`). If the sealed
snapshot or required build inputs are not visible beneath `/engagements/$ENGAGEMENT_KEY`, fix the
mount/source boundary rather than run anything on the host.

#### Phase 4A: Target Selection + Harness Construction

Dispatch `code-fuzz-engineer` with `agent/skills/code-fuzz-campaign/SKILL.md` and:
- current Code Source Identity (structural index manifest, sealed `snapshot_path`), the call graph
  at `tools/analysis-state/call-graph.json`, and the complete threat-model envelope from
  `code/threat-model/<repo-id>` when `current: true` with matching generation/digest (a clipped
  summary only supplements it);
- a concise summary, not a raw dump, of the non-killed, non-merged memory-safety findings (the
  seven families above) with slugs, canonical locations, severity, and `verification_status`, and
  of the critical/high C/C++ files and their slot types from the paginated classification read;
- the build system type and the audited toolchain-check result;
- existing fuzzer inventory paths (`rg -l 'LLVMFuzzerTestOneInput' "$snapshot_path"`, or
  `ls "$snapshot_path/oss-fuzz/"`);
- CWE pattern references: `buffer-overflow.md`, `format-string.md`, `integer-overflow.md`,
  `null-dereference.md`, `type-confusion.md`, `uninitialized-memory.md`, `use-after-free.md`, and
  `fuzz-harness-patterns.md`.

**On return**, the fuzz engineer has recorded findings from quick validation runs or the pre-fuzz
audit and written campaign state under `tools/fuzz-state/`:
```bash
ls tools/fuzz-state/targets.json
ls tools/fuzz-state/harnesses/*/harness.c
ls tools/fuzz-state/campaigns/*.json
```

#### Phase 4B: Campaign Execution

Campaigns are tool runs, not agent tasks: you start them from the Phase 4A configs through the
runtime driver's audited seam. Before launch or resume, compare each config's `source_identity`
with the current Code Source Identity and reject a stale or missing tuple. The driver accepts only
engagement-root-relative paths and proves both engagement-root and build-root containment itself,
so run configs only through it. Size each run against the synchronous `--timeout` ceiling
(`agent/shared-constraints.md` §2, "Synchronous execution and process cleanup"), one config
per audit row or job:

```bash
# Short campaign, once per config
vigil assess kali exec --technique FUZZ --intent "bounded generation fuzz campaign" \
  --probe-kind payload --phase code-fuzz --timeout 600 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    campaign --config tools/fuzz-state/campaigns/<campaign-id>.json

# Deep campaign through the supervised long-job lifecycle
vigil assess kali job start --technique FUZZ --intent "deep generation fuzz campaign" \
  --probe-kind payload --phase code-fuzz --timeout 86400 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    campaign --config tools/fuzz-state/campaigns/<deep-campaign-id>.json
```

Record the returned job ID and poll or stop that exact job through the `kali job` lifecycle. A
detached host process or untracked `screen`/`tmux` escapes the audit, and a config's binary path is
never executed directly from the host.

#### Phase 4C: Crash Triage

After campaigns complete, or quick runs produce crashes, dispatch `code-fuzz-engineer` for crash
triage with the bound Code Source Identity, structural-index manifest, and threat-model envelope;
`tools/fuzz-state/crashes/`, `campaigns/`, and `harnesses/`; and the target functions' source paths
beneath the sealed `snapshot_path` (a derived build copy is execution material, not source
evidence).

**On return**, the fuzz engineer has recorded true findings, triage reports under
`tools/fuzz-state/reports/*-triage.json`, and, after triage, one `code-record fuzz-campaign`
receipt per assigned target. That receipt is the fuzz engineer's attestation with backend-enforced
binding and evidence integrity, not independent proof that the engine ran. A failed campaign stays
durable but does not cover its target, and a `completed_crashes_triaged` receipt covers only once
every crash is triaged.

In a run-accounted campaign, record each sanitizer violation or reproducible crash first with
`vigil assess run-audit tool-signal record <run-id> <signal-json>`. A code signal binds the exact
inventoried source, terminal command receipt, observed signature, and (for a crash) input digest,
and creates one deterministic candidate in the same transaction. A confirmed candidate is promoted
in the single `finding record` action by including `run_candidate {run_id, candidate_id, reason,
proof_receipt_ids}` in the finding JSON. Then link the campaign receipt with `vigil assess run-audit
code-receipt record <run-id> <campaign-link-json>`, retaining every triaged signal/candidate and the
exact current-generation receipt; a failed campaign stays blocked debt rather than generic failure
text.

**Phase 4 exit gate:**
- [ ] Applicability receipt is current. When it is `not_required`, the campaign items below do not
      apply; when it is `required`, all of them must pass.
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
Code findings close out as per-finding submissions through the same flow as web. Follow
`agent/phases/phase-8-report.md` from the ticket-count decision through publish (step e), then its
Definition of Done; the variant, chain, and depth items there are web-only, and its step c already
names the code reproduction testers. Code differences:

- Platform: `--platform direct`, unless the code work runs under an active bounty program, which
  uses that program's platform as the web track does.
- Fuzz findings (CF-xxx) use the crash input and ASAN report as proof (`evidence_ref`/`poc_code`);
  the raw crash artifact stays under `tools/fuzz-state/`. Worked example:
  `agent/references/examples/submission-direct-buffer-overflow-fuzz.md`.
- `code-variant-hunter` hits on one pattern across files are the typical same-root-cause cluster;
  settle the ticket count before drafting any of them.

When every reportable finding is `reported`, close with the code gates. `transition-phase complete
--track code` also blocks on `missing_submission_qc` for any registered submission without a passing
independent QC, and on `missing_report_qc` when `report.md` is registered; unlike the coverage debt,
those review blockers accept an audited `--force --reason` override. Both reviews are
engagement-wide, so on a combined web and code engagement code `complete` also waits on the QC of
submissions and a `report.md` the web track registered.

```bash
vigil assess code-coverage --require-transition-ready complete
vigil assess transition-phase complete --track code
```

---

Phase index (path → purpose) lives in `agent/operator-core-code.md` under "Phase Index". Prior:
`agent/phases/code-phase-3-verify-variant.md`. This is the last code-track phase doc.
