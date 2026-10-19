---
description: Dispatch a fresh low-context specialist to attack a finding as a hostile triager would
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-fresh-skeptic-verify.md -->


Use the context-bound Vigil helper named in this workspace AGENTS.md for every Vigil invocation. Confirm the selected mode before acting.

Arguments from this invocation: $ARGUMENTS

This command implements the web workflow. In code mode, explain that limitation and use the selected code operator workflow instead; do not change modes or load a web operator core.

Verify the finding the operator named in their message.

**If no finding was named above, ask which one before doing anything else** — this command has no
default target.

Dispatch `vulnerability-analyst` in review mode, **fresh and low-context**. Fresh is the whole
point: a specialist that already helped build the finding will confirm it, and confirmation is not
verification. Give it the evidence and the target, not your conclusion.

**Build the dispatch context from `agent/phases/phase-5-verify.md` step c — all of it**, including
the trust-boundary / threat-model summary. Reachability and auth-path severity calls depend on that
grounding, and the triager is overconfident without it. The adversarial instruction and the
review-mode skill/reference load live in the same step; a shorter hand-rolled context produces a
reviewer that rubber-stamps.

**The gate is already written — invoke it, do not re-derive it.** The dispatch runs the FP &
severity-downgrade gate (`agent/references/finding-fp-and-severity-gate.md`, C1–C7), which is what a
hostile triager actually checks; any list of questions invented here is a lower-fidelity copy of it.
Tell it to hunt **downgrades**, not confirmations, and to bullet exactly what is off.

**Then apply the disposition.** The reviewer returns one of `PASS` / `UPGRADE` / `DOWNGRADE` /
`KILL`; `agent/phases/phase-5-verify.md` step d owns the backend command each one maps to, with its
required flags — run that one. If the verifier killed it, kill it; do not relitigate a finding back
to life because it was expensive to produce. A finding that dies here would have died at triage
anyway, and dying here is free.
