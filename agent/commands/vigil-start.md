---
name: vigil-start
description: Open an authorized engagement — adopt its generated operator role and run that workflow from the top
---

Open the authorized Vigil engagement in the current directory. `scope.json.engagement_type` is the
sole mode selector. Text supplied with this command is optional focus only; it cannot select or
override Web, Code, Both, Android, or Blue.

**1. Route safely.** Read `scope.json`, then this engagement's `AGENTS.md` and the canonical prompt
it names. Apply that prompt's opening routing gate exactly, including every STOP and unknown-mode
branch. Do not interpret engagement state until routing succeeds. `scope.json` and `ENGAGEMENT.md`
remain the scope and ROE authorities.

**2. Check whether this is actually a start.** A fresh start over live backend state can duplicate
ownership and repeat completed work.

<!-- vigil:only claude -->
Use `/vigil-resume` if this engagement is already under way.

!`vigil assess resume-brief 2>&1`
<!-- vigil:end -->
<!-- vigil:only codex -->
Use `$vigil-resume` if this engagement is already under way. Run and read:

    vigil assess resume-brief
<!-- vigil:end -->

If the brief shows findings, dispatched agents, or progress beyond the selected workflow's opening
phase, report that the engagement is in progress and switch to `vigil-resume`. Otherwise continue.

**3. Begin the selected workflow.** Read the canonical prompt in bounded parts, following its Map
of This File. Read `ENGAGEMENT.md` when present and every startup file that prompt names, then begin
from its opening phase.

<!-- vigil:only claude -->
Additional context from the operator (may be empty): $ARGUMENTS
<!-- vigil:end -->
<!-- vigil:only codex -->
Treat additional text in the invocation as focus only. Apply it when consistent with
`ENGAGEMENT.md`, `scope.json`, and the loaded operator contract; report conflicts.
<!-- vigil:end -->

Report the selected role and mode, opening phase, approval boundary, and first dispatch lanes in
the loaded prompt's normal format; then begin.
