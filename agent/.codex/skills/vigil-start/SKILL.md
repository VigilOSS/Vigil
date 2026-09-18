---
name: vigil-start
description: Open an authorized engagement — adopt its generated operator role and run that workflow from the top
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-start.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

Open the authorized Vigil engagement in the current directory. This command supplies startup
mechanics only: the engagement's generated operator contract owns the role, the workflow, and every
mode decision. Do not infer a role from this command's name.

**1. Read `scope.json`, then adopt the role its `engagement_type` routes you to.** Read this
engagement's `AGENTS.md`, follow its pointer to the canonical operator prompt, and read that prompt
in bounded parts, following its own Map of This File. Its **Engagement-Type Routing Gate** is the
first section and the sole authority on mode — obey the branch for this engagement's
`engagement_type` exactly, **including a branch that says STOP**, and including its instruction to
stop and report an `engagement_type` it does not recognize rather than falling through. Adopt the
identity, workflow, phases, execution boundaries, and approval gates of whichever prompt the gate
lands you in before interpreting any engagement state. `scope.json` is also the authoritative scope
and ROE boundary; the loaded prompt and `agent/shared-constraints.md` §1 own what it means.

**2. Check whether this is actually a start.** A fresh start over live backend state can duplicate
ownership and repeat completed work.

Use `$vigil-resume` if this engagement is already under way. Run and read:

    vigil assess resume-brief

If the brief shows findings, dispatched agents, or progress beyond the loaded workflow's first
phase, report that the engagement is in progress and switch to `vigil-resume`. If the backend is
empty or the engagement is new, continue.

**3. Load the remaining engagement-owned constraints.** Read `ENGAGEMENT.md` plus the additional
files the loaded operator prompt names. Engagement-owned ROE is authoritative over anything in this
command. Optional files may be absent on a new engagement.

**4. Take the loaded operator seat.** Choose specialists, frame dispatches, judge evidence, and
record durable state through the surfaces named by that operator prompt. Dispatch in parallel where
its phase permits and give substantial work enough scope to go deep.

If the operator supplied additional engagement context in the message, apply it only when it is
consistent with `ENGAGEMENT.md`, `scope.json`, and the loaded operator contract. Raise conflicts.

Report in the loaded prompt's own output conventions — `[operator]` prefix, numbered choices, phase
tracker — the role and mode you loaded, the opening phase, the applicable approval boundary, and the
lanes you are about to dispatch; then begin.
