---
description: Show the standing compaction contract and audit whether it is actually being applied
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-compact.md -->


Use the context-bound Vigil helper named in this workspace AGENTS.md for every Vigil invocation. Confirm the selected mode before acting.

Arguments from this invocation: $ARGUMENTS

Run `vigil engagement client-check --client opencode --json` through the context-bound
helper. Inspect the assessment plugin and its native capability observations.
OpenCode's awaited compaction hook adds the canonical preservation contract and current
COMPACT.md to the summarizer; request-time recovery restores the selected operator after
a successful summary. Registration alone does not prove either hook ran in this build.
Print the canonical contract by running the matched agent root's scripts/hooks/pre-compact.sh
with the explicit engagement and mode binding. Report native manual and automatic
compaction verification separately; do not claim an absolute 510000-token setting.

Report to the operator, in three lines:

1. whether the contract resolved and printed non-empty output — empty output means the
   contract is **not** available;
2. anything in the printed contract that is stale for this engagement;
3. that the source of truth is `agent/scripts/hooks/pre-compact.sh`, and that this engagement
   may add its own rules in a `COMPACT.md` in the engagement directory without editing the
   shared hook. Say whether a `COMPACT.md` is present here and whether its rules appeared in
   the output above.
