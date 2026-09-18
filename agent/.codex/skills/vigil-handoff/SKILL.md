---
name: vigil-handoff
description: Write a handoff for the active engagement operator, grounded in backend state rather than recollection
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-handoff.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

Produce a handoff for the next operator session, whether it uses another client or resumes after a
restart. The reader has the engagement directory and backend, not this session's context.

**1. Adopt the engagement's operator role.** Read this engagement's `AGENTS.md`, follow its pointer
to the canonical operator prompt, and read that prompt in bounded parts, following its own Map of
This File. Obey its **Engagement-Type Routing Gate** branch for this engagement's `engagement_type`
in `scope.json` — including a branch that says STOP, and including its instruction to stop and
report an `engagement_type` it does not recognize. A handoff must use the loaded workflow's state
and exit language; a single-track template written for a different mode hides the work that actually
governs completion.

**2. Read the complete shared backend hydration.** Ground every claim in these outputs instead of
memory.

Run all of these and read their complete output:

    vigil assess resume-brief
    vigil assess agent list --status in-progress
    vigil assess finding list
    vigil assess operator-checkpoint show

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

### Combined mode

Read both track states and report their readiness separately. Run
`vigil assess check-phase-readiness --phase <active-web-phase>` for the web track (`--phase report`
only when that track is actually approaching report closeout) and `vigil assess code-coverage` for
the code track; when its next code phase is known, add `--require-transition-ready <target-phase>`.
A clear result on one track does not clear the other.

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

**4. Write the brief** with each section below in order. Write `none` when a section is genuinely
empty, because an empty section and a forgotten section are indistinguishable to the next reader.

- **ROE and approval deltas.** Anything the next operator would get wrong from the engagement files
  alone. Use the vocabulary of the loaded mode.
- **Workflow state.** Current phase or track, the applicable readiness result, and unfinished exit
  obligations.
- **In-flight ownership.** Agent id, role, assigned work, dispatch time, and any ready/blocked
  handoff for every active lane. Existing ownership must remain visible to prevent duplicate work.
- **Findings or incidents by evidence status.** Separate verified facts, unverified reports, killed
  claims, and blocked verification. Name the backend evidence or kill reason for each.
- **Coverage completed and outstanding.** Use the active mode's unit: web surfaces; code queues and
  obligations; both units separately for a combined engagement; Android static/dynamic surfaces,
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

If the operator supplied additional context in the message, include it only when the backend and
engagement contract support it.

The checkpoint intent is an operator statement, not evidence. Keep factual claims in the handoff
grounded in the backend outputs above, and report back to the operator in the loaded prompt's own
output conventions — `[operator]` prefix, numbered choices, phase tracker.
