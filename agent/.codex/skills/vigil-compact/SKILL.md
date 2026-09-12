---
name: vigil-compact
description: Show the standing compaction contract and audit whether it is actually being applied
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-compact.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

**Vigil wires no compaction hook on Codex.** Nothing is injected for you automatically, so on
this client the contract is something you apply by hand — there is no hook silently doing it,
and you should not assume otherwise.

Print the standing contract and read it in full:

    bash -c 'if [ -n "${VIGIL_AGENT_ROOT:-}" ]; then s="$VIGIL_AGENT_ROOT/scripts/hooks/pre-compact.sh"; elif [ -f agent/scripts/hooks/pre-compact.sh ]; then s=agent/scripts/hooks/pre-compact.sh; else s=../../scripts/hooks/pre-compact.sh; fi; echo "hook: $s"; echo; echo "{\"trigger\":\"manual\"}" | bash "$s"'

That script is the same contract Claude Code applies through its `PreCompact` hook; running it
here is how a Codex operator reads it. Apply it yourself whenever this session is compacted,
truncated or restarted.

Report to the operator, in three lines:

1. whether the contract resolved and printed non-empty output — empty output means the
   contract is **not** available and any compaction is running unsteered;
2. anything in the printed contract that is stale for this engagement;
3. that the source of truth is `agent/scripts/hooks/pre-compact.sh`, and that this engagement
   may add its own rules in a `COMPACT.md` in the engagement directory without editing the
   shared hook. Say whether a `COMPACT.md` is present here and whether its rules appeared in
   the output above.
