---
description: Show the standing compaction contract and audit whether it is actually being applied
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-compact.md -->


Use the absolute context-bound Vigil helper supplied by this native task context or Runtime Identity for every Vigil invocation. Read that immutable context router; the stable project helper inspects NEW-task setup only. Confirm the selected mode before acting.

Arguments from this invocation: $ARGUMENTS

Run `vigil engagement client-check --client zcode --json` through the context-bound
helper. ZCode has no established PreCompact/custom summarizer interface. Its documented
SessionStart(compact) hook is a recovery opportunity, not proof of native dispatch.
Report whether this exact desktop/engine build has actually delivered a compact event;
startup dispatch alone is insufficient. If recovery is unverified or absent, run
/vigil-resume explicitly after native /compact before continuing work. Print the
standing contract from the matched agent root's scripts/hooks/pre-compact.sh using
the explicit engagement and mode. Do not claim a custom auto-compaction token threshold.

Report to the operator, in three lines:

1. whether the contract resolved and printed non-empty output — empty output means the
   contract is **not** available;
2. anything in the printed contract that is stale for this engagement;
3. that the source of truth is `agent/scripts/hooks/pre-compact.sh`, and that this engagement
   may add its own rules in a `COMPACT.md` in the engagement directory without editing the
   shared hook. Say whether a `COMPACT.md` is present here and whether its rules appeared in
   the output above.
