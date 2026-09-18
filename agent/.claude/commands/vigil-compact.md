---
description: Show the standing compaction contract and audit whether it is actually being applied
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-compact.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

Compaction instructions are not pasted by hand. A `PreCompact` hook supplies them
automatically on **both** manual `/compact` and automatic context-window compaction, so there
is nothing to copy.

To compact, just compact. If you add your own text (`/compact also keep X`) it is **merged**
with the standing contract rather than replacing it.

**How the contract reaches the summarizer** — stated so this is auditable rather than folklore.
Claude Code collects the stdout of every succeeded, non-blocked `PreCompact` hook and hands it
to the summarizer as its custom instructions, merged with any text the operator typed. Two
consequences worth knowing: the hook steers the **operator** session's compaction but not a
dispatched specialist's, and a `PreCompact` hook that exited 2 would **block** compaction
outright, which is why the shared hook always exits 0.

Run the hook now and show the operator exactly what will be injected:

!`bash -c 'if [ -n "${VIGIL_AGENT_ROOT:-}" ]; then s="$VIGIL_AGENT_ROOT/scripts/hooks/pre-compact.sh"; elif [ -f agent/scripts/hooks/pre-compact.sh ]; then s=agent/scripts/hooks/pre-compact.sh; else s=../../scripts/hooks/pre-compact.sh; fi; echo "hook: $s"; echo; echo "{\"trigger\":\"manual\"}" | bash "$s"'`

Report to the operator, in three lines:

1. whether the contract resolved and printed non-empty output — empty output means the
   contract is **not** available and any compaction is running unsteered;
2. anything in the printed contract that is stale for this engagement;
3. that the source of truth is `agent/scripts/hooks/pre-compact.sh`, and that this engagement
   may add its own rules in a `COMPACT.md` in the engagement directory without editing the
   shared hook. Say whether a `COMPACT.md` is present here and whether its rules appeared in
   the output above.
