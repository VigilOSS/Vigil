---
name: vigil-compact
description: Show the standing compaction contract and audit whether it is actually being applied
clients: claude codex opencode zcode
---

<!-- vigil:only claude -->
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
<!-- vigil:end -->
<!-- vigil:only codex -->
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
<!-- vigil:end -->

<!-- vigil:only opencode -->
Run `vigil engagement client-check --client opencode --json` through the context-bound
helper. Inspect the assessment plugin and its native capability observations.
OpenCode's awaited compaction hook adds the canonical preservation contract and current
COMPACT.md to the summarizer; request-time recovery restores the selected operator after
a successful summary. Registration alone does not prove either hook ran in this build.
Print the canonical contract by running the matched agent root's scripts/hooks/pre-compact.sh
with the explicit engagement and mode binding. Report native manual and automatic
compaction verification separately; do not claim an absolute 510000-token setting.
<!-- vigil:end -->
<!-- vigil:only zcode -->
Run `vigil engagement client-check --client zcode --json` through the context-bound
helper. ZCode has no established PreCompact/custom summarizer interface. Its documented
SessionStart(compact) hook is a recovery opportunity, not proof of native dispatch.
Report whether this exact desktop/engine build has actually delivered a compact event;
startup dispatch alone is insufficient. If recovery is unverified or absent, run
/vigil-resume explicitly after native /compact before continuing work. Print the
standing contract from the matched agent root's scripts/hooks/pre-compact.sh using
the explicit engagement and mode. Do not claim a custom auto-compaction token threshold.
<!-- vigil:end -->

Report to the operator, in three lines:

1. whether the contract resolved and printed non-empty output — empty output means the
   contract is **not** available;
2. anything in the printed contract that is stale for this engagement;
3. that the source of truth is `agent/scripts/hooks/pre-compact.sh`, and that this engagement
   may add its own rules in a `COMPACT.md` in the engagement directory without editing the
   shared hook. Say whether a `COMPACT.md` is present here and whether its rules appeared in
   the output above.
