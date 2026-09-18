---
name: vigil-hunt-deeper
description: Push past a shallow stopping point — wider batches, deeper dispatches, siblings off anything that signals
---

You have stopped short. Restart the hunt at depth.

<!-- vigil:only claude -->
Surfaces or constraints the operator named for this push (may be empty): $ARGUMENTS

Current lane state:

!`vigil assess agent list --status in-progress 2>&1`
<!-- vigil:end -->
<!-- vigil:only codex -->
If the operator named specific surfaces or constraints for this push in their message, start
there — but still cover the rest. Check current lane state first:

    vigil assess agent list --status in-progress
<!-- vigil:end -->

**Re-read `agent/rules/hunting.md` rules 5, 9, 15, 16 and 16a before the first batch.** They
govern this push, including when a surface is genuinely dry and you should rotate off it rather
than grind. This command widens dispatch volume; it does not override those rules, and it does
not widen the target boundary — reconfirm `scope.json` hosts and `exploit_policy` first, and
keep exploit work behind whatever gate the policy sets.

Then dispatch specialists across all surfaces in parallel batches. A thirty-second dispatch is
a lookup, not an assessment: if a lane returns almost immediately with nothing, the dispatch was
too narrow, not the surface.

Every dispatch in this push:

- Sets `hunt_scope: deep` **where the role has that axis**, and exactly one mindset lens where the
  role carries one — `source-analyzer` has neither (`agent/agents/source-analyzer.md`). Copy
  `agent/references/runtime-guides/dispatch-template.md` rather than re-deriving the shape; it
  carries the explicit not-applicable form both fields need.
- Declares its resource envelope — candidate count, rate limit, threads, retries, timeout, output
  mode, stop condition, expected wall-clock — from
  `agent/references/runtime-guides/dispatch-resource-policy.md`. "Enough budget" is not a number,
  and parallel batches against a rate-limited target are how an engagement gets blocked.
- Records to the backend as it goes, not at the end. A lane whose findings exist only in your
  context is a lane whose findings are lost at the next context boundary.

**Stop when every surface in the work buffer has had at least one `hunt_scope: deep` dispatch.**
Then report and hand the next decision back — do not open a second full rotation on your own.

Report back with: batches dispatched and what each owned, what returned, what signalled and what
you did about it, and the honest remaining surface with what it would cost to cover.
