---
name: vigil-start
description: Open an authorized engagement — adopt its generated operator role and run that workflow from the top
---

Open the authorized Vigil engagement in the current directory. The launched session's
`VIGIL_OPERATOR_MODE` selects one operator workflow. Text supplied with this command is
optional focus only; it cannot switch modes or enable another track.

**1. Route safely.** Run `vigil engagement mode`. Confirm its `mode:` matches
`VIGIL_OPERATOR_MODE`; read this engagement's `AGENTS.md` and only the canonical prompt
shown as `prompt:`. If resolution fails or the values disagree, STOP before target-facing
work and start a new client with an explicit `--mode`. Do not infer the session's mode
from enabled tracks. `scope.json` and `ENGAGEMENT.md` remain the scope and ROE authorities.

**2. Check whether this is actually a start.** A fresh start over live backend state can duplicate
ownership and repeat completed work. For `remediation`, read `PROJECT.md` and
`remediation-project.json`, then run `vigil remediation -k <key> list` and inspect any
selected case with `vigil remediation -k <key> show <case-id>`. If case work is
already under way, use `vigil-resume`. For other modes, use the bounded assessment brief:

<!-- vigil:only claude -->
Use `/vigil-resume` if this engagement is already under way.

!`if [ "${VIGIL_OPERATOR_MODE:-}" != remediation ]; then vigil assess resume-brief 2>&1; fi`
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
