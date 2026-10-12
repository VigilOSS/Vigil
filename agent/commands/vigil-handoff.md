---
name: vigil-handoff
description: Write a handoff for the active engagement operator, grounded in backend state rather than recollection
---

Produce a handoff for the next operator session, whether it uses another client or resumes after a
restart. The reader has the engagement directory and backend, not this session's context.

**1. Adopt the session's operator role.** Run `vigil engagement mode` and confirm its
`mode:` matches `VIGIL_OPERATOR_MODE`. Read this engagement's `AGENTS.md`, then only
the canonical prompt shown as `prompt:` in bounded parts. If resolution fails or the
values disagree, STOP before writing a handoff; a handoff in the wrong workflow's
state and exit language hides the work that actually governs completion.

**2. Read the complete shared backend hydration.** Ground every claim in backend
state instead of memory. For `remediation`, read `PROJECT.md`;
run `vigil remediation -k <key> list` and
`vigil remediation -k <key> show <case-id>` for the selected case, then follow
the remediation prompt's evidence and approval checks. For other modes, run:

<!-- vigil:only claude -->
!`if [ "${VIGIL_OPERATOR_MODE:-}" != remediation ]; then vigil assess resume-brief 2>&1; fi`

!`if [ "${VIGIL_OPERATOR_MODE:-}" != remediation ]; then vigil assess agent list --status in-progress 2>&1; fi`

!`if [ "${VIGIL_OPERATOR_MODE:-}" != remediation ]; then vigil assess finding list 2>&1; fi`

!`if [ "${VIGIL_OPERATOR_MODE:-}" != remediation ]; then vigil assess operator-checkpoint show 2>&1; fi`
<!-- vigil:end -->
<!-- vigil:only codex -->
Run all of these and read their complete output:

    vigil assess resume-brief
    vigil assess agent list --status in-progress
    vigil assess finding list
    vigil assess operator-checkpoint show
<!-- vigil:end -->

**3. Read the readiness surface for the loaded mode.** These route to CLI surfaces no operator
prompt owns; run only the applicable one.

### Web/red mode

Run `vigil assess check-phase-readiness --phase <active-phase>` and carry its blockers and
advisories into the handoff. Use `--phase report` only when the workflow is actually approaching
report closeout — it is the web report-readiness projection, not a generic all-mode gate.

### Code mode

Run `vigil assess code-coverage` and pair its coverage/quality output with the current code phase's
readiness obligations from the loaded code operator prompt. When the next target phase is known,
use `--require-transition-ready <target-phase>` to obtain its structural readiness verdict.

### Android mode

Report the declared artifact/package identity and hash, completed and outstanding static/dynamic
Android skill coverage, device or emulator boundary, and every live API host that was explicitly
admitted with `vigil engagement add-host <engagement-key> <host>`. Static artifact work is not
target-facing, and an app-discovered endpoint alone is not authorized. The initial artifact
`ingest` state has no separate Android readiness verb; use the skill coverage checklist there. Once
the workflow is in a canonical web-core phase, run
`vigil assess check-phase-readiness --phase <active-web-phase>` for that active phase (and use
`--phase report` only when the workflow is actually approaching report closeout).

### Blue mode

There is no single read-only readiness command for the blue incident workflow. Use the complete
shared hydration above plus the active blue operator phase checklist: verifier dispositions,
registered evidence, open containment proposals and approvals, and report/closeout state. A
transition is a state change, so readiness inspection does not execute one merely to test it.

### Remediation mode

Use the selected case's state and evidence: issue snapshot, worktree revision,
red and green tests, browser rehearsal, review approval, PR, deployment, and
human verification. `vigil remediation -k <key> show <case-id>` is the case
state surface; do not treat offensive phase readiness as a remediation gate.

**4. Write the brief** with each section below in order. Write `none` when a section is genuinely
empty, because an empty section and a forgotten section are indistinguishable to the next reader.

- **ROE and approval deltas.** Anything the next operator would get wrong from the engagement files
  alone. Use the vocabulary of the loaded mode.
- **Session mode and workflow state.** Name this session's `mode:` and the command to start
  a fresh session in that mode. Record its current phase, readiness result, and unfinished
  exit obligations. For another enabled track, provide a bounded finding or proof pointer
  and a separate `--mode` start command; never ask one session to load both cores.
- **In-flight ownership.** Agent id, role, assigned work, dispatch time, and any ready/blocked
  handoff for every active lane. Existing ownership must remain visible to prevent duplicate work.
- **Findings or incidents by evidence status.** Separate verified facts, unverified reports, killed
  claims, and blocked verification. Name the backend evidence or kill reason for each.
- **Coverage completed and outstanding.** Use the active mode's unit: web surfaces; code queues and
  obligations; Android static/dynamic surfaces,
  artifacts, and admitted live hosts; or blue incident evidence/containment work.
- **Open and settled decisions.** Preserve both questions awaiting the user and decisions that must
  not be re-litigated.
- **Operational landmines.** Expiring auth, rate or tenant-query constraints, parser degradation,
  unavailable telemetry, or other conditions that would waste or mislead the next session.
- **The single next action**, with the backend state and readiness fact that makes it next.

**5. Record it.** Replace the engagement's `RESUME.md` with this one coherent account, then index it
so it is engagement memory rather than scratch — an unlinked markdown note does not survive resume:

    vigil assess artifact register RESUME.md

Then record the same next intent as the operator's durable save-my-place checkpoint:

    vigil assess operator-checkpoint record --intent "<one-sentence statement of where this stands and what is next>"

<!-- vigil:only claude -->
Additional context the operator gave for this handoff (may be empty): $ARGUMENTS
<!-- vigil:end -->
<!-- vigil:only codex -->
If the operator supplied additional context in the message, include it only when the backend and
engagement contract support it.
<!-- vigil:end -->

The checkpoint intent is an operator statement, not evidence. Keep factual claims in the handoff
grounded in the backend outputs above, and report back to the operator in the loaded prompt's own
output conventions — `[operator]` prefix, numbered choices, phase tracker.
