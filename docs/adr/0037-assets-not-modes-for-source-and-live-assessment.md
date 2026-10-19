# ADR 0037 — Assets replace modes for source and live assessment

- Status: Proposed
- Date: 2026-10-18

## Context

An engagement that holds source and a live application currently chooses between two operator
cores and two specialist constraint bundles. Mode decides which prompt loads, tracks decide
completion, and proof work (ADR 0036) carries an explicit code or web route. A finding owed
runtime proof records `pending_runtime_proof` with a next test and a local/live route hint,
and the operator reads a derived readiness state for each proof item.

The remaining friction is structural. Source arrives mid-engagement and forces a mode decision.
The two bundles disagree on contacting declared hosts, so a specialist cannot safely load both.
Exploit approval has two human-facing paths, engagement-level `exploit approve selected` and
per-work proof approval. Prepare, approve and claim are separate operator steps even when the
route is local and no approval applies. Blind triage is an overridable CLI gate. Report drafts
omit unreviewed findings, so a human sees nothing until verification finishes.

This ADR records the agreed direction for deferred work. None of the decisions below is
implemented yet.

## Decision

1. **Scope is a set of authorized assets.** Hosts, repositories and binaries are each admitted
   explicitly. Source is an asset, never a mode. One operator stays running for the engagement
   and pushes bounded tasks to fresh specialists. Specialists never orchestrate.
2. **Typed records stay; one Work view derives state.** `pending_runtime_proof` remains the
   stored obligation. Dispatch, run, receipt and verification remain separate typed backend
   records. The human and the operator see one Work view whose state is derived from them.
3. **The backend selects specialist rule modules.** Each task declares capabilities (source
   handling, local execution, live-target contact). The backend adds the matching small rule
   modules to the shared specialist core, replacing the two-bundle mode switch. The model does
   not choose them. Loading both current bundles is never the answer, because they contradict
   each other on declared-host contact.
4. **One approval mechanism.** Engagement exploit approval and per-work proof approval merge
   into one human-facing mechanism. Approval keeps its current binding to finding, source,
   scope and objective context. There is no per-operation approval envelope.
5. **Fewer lifecycle steps.** Prepare and approve fold into claim where that is safe. Proof work
   may be created automatically from a next test whose route hint is `local`.
6. **Blind triage becomes a backend readiness check** that the operator cannot override from
   the CLI.
7. **Rolling human review.** Draft reports include unreviewed and pending findings, clearly
   labelled. Findings join a human review queue as they reach confirmed, downgraded or unproven,
   and the operator mentions pending reviews at checkpoints.
8. **Tracks become optional coverage lanes.** A track accounts for breadth and completion. It
   never selects prompts. Targeted proof never creates one (ADR 0036).
9. **One operator core, loaded in stages.** The two operator cores merge into one shared core
   with just-in-time phase and asset-specific method loading. This step is gated on source-only,
   live-only and mixed evals that compare tokens, compactions, dispatch count, false
   confirmations and evidence completeness against the current cores.

## Consequences

- Adding source to a live engagement becomes an asset admission rather than a session change.
- Specialist instructions follow the task's capabilities, so a web proof with source evidence
  loads live-contact rules and source-handling rules without the code bundle's host-contact rule.
- The human answers one kind of approval question, still bound to exact context.
- Reviewers see work early, with labels that keep unverified findings out of final deliverables.
- The prompt merge does not land until evals show it does not regress cost or verification
  quality.

## Not planned

- **Specialists as sub-operators.** Orchestration stays with the one operator.
- **Domain allowlists or traffic tracking.** ADR 0019 and ADR 0021 keep destination policy
  advisory; the operator remains responsible for staying in scope.
- **A separate post-proof adjudicator.** Independent verification already exists in the finding
  lifecycle.
- **Per-operation approval envelopes.** Context-bound approval is sufficient.
- **A provider-neutral launcher.** Deferred until unattended launch is a goal.
- **Runtime isolation for repository code.** Vigil relies on the human's repository-trust
  confirmation before local proof runs repository code in the shared runtime container. An
  ephemeral offline proof container remains an option if that trust model changes.
