---
name: vigil-hunt-deeper
description: Push past a shallow stopping point — wider batches, deeper dispatches, siblings off anything that signals
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-hunt-deeper.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

You have stopped short. Restart the hunt at depth.

Keep dispatching specialists across **all** surfaces — in batches, in parallel, each with
enough scope and budget to actually run deep. A thirty-second dispatch is a lookup, not an
assessment; if a lane returns almost immediately with nothing, the dispatch was too narrow,
not the surface.

Rules for this push:

- **Exhaust a surface before rotating off it.** Slow is not the same as dry. Rotating early
  is the single most common way real bugs get left behind.
- **Try the non-trivial paths.** Chained state, second-order effects, unusual verbs and
  content types, race and ordering assumptions, anything the obvious scanner would not reach.
- **Hunt siblings and clusters off anything that signals.** One weak signal on one endpoint
  almost always means the same mistake exists on its neighbours. Enumerate the family.
- **Record to the backend as you go**, not at the end. A lane whose findings only exist in
  your context is a lane whose findings are lost at the next context boundary.
- **Do not stop at a stopping point.** When you reach one, push past it, then tell the
  operator explicitly what is still unexplored and what it would cost to cover.
- **Re-read the operator prompt every few batches.** Dispatch discipline is what decays first
  in a long push, and the failure mode is you quietly starting to probe things yourself.

Report back with: batches dispatched and what each owned, what returned, what signalled and
what you did about it, and the honest remaining surface.

If the operator named specific surfaces or constraints for this push in their message, start
there — but still cover the rest. Check current lane state first:

    vigil assess agent list --status in-progress
