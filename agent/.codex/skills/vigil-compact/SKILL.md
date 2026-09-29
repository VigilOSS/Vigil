---
name: vigil-compact
description: Show the standing compaction contract and audit whether it is actually being applied
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-compact.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

Codex is automatic too, through two complementary controls. The engagement's
`.codex/config.toml` carries a `compact_prompt` rendered from Vigil's standing contract, and a
`SessionStart` hook matching `compact` injects mandatory backend rehydration before the immediate
continuation. Both manual and automatic compaction use this path; the operator does not run
`$vigil-resume` afterwards.

Print the canonical contract and read it in full:

    bash -c 'if [ -n "${VIGIL_AGENT_ROOT:-}" ]; then s="$VIGIL_AGENT_ROOT/scripts/hooks/pre-compact.sh"; elif [ -f agent/scripts/hooks/pre-compact.sh ]; then s=agent/scripts/hooks/pre-compact.sh; else s=../../scripts/hooks/pre-compact.sh; fi; echo "hook: $s"; echo; echo "{\"trigger\":\"manual\"}" | bash "$s"'

Then inspect `.codex/config.toml` and confirm that `compact_prompt` is non-empty,
`model_auto_compact_token_limit` is `510000`, and `hooks.SessionStart` contains exactly one
`^compact$` entry invoking `post-compact-resume.sh`. The generated prompt is a mode-neutral
copy of the standing contract; Codex loads it directly as its history compaction override.
The continuation hook uses the session's `VIGIL_OPERATOR_MODE` and `vigil engagement mode`
to restore only the selected operator prompt.

Report to the operator, in three lines:

1. whether the contract resolved and printed non-empty output — empty output means the
   contract is **not** available;
2. anything in the printed contract that is stale for this engagement;
3. that the source of truth is `agent/scripts/hooks/pre-compact.sh`, and that this engagement
   may add its own rules in a `COMPACT.md` in the engagement directory without editing the
   shared hook. Say whether a `COMPACT.md` is present here and whether its rules appeared in
   the output above.
