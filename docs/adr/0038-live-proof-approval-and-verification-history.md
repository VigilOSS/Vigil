# ADR 0038 — Live proof approval and verification history

- Status: Accepted — implemented
- Date: 2026-10-19

## Context

ADR 0036 bound proof context to approval posture. Policy changes consequently made an
otherwise unchanged task stale, while combining exact-work approval with `full_send` left
revocation ambiguous. Finding edits also need to distinguish documentation enrichment from
a changed claim without erasing the history of completed proof.

## Decision

Keep source, claim, parking transition, route, objective and admitted scope in the work binding.
Evaluate live authority separately on every claim/progress/attachment. Ignore approval posture
when comparing historical bindings; retain historical events unchanged.

For web work, the latest exact-work revoke denies authority under every policy until exact-work
re-approval. An exact approval permits the current task; absent an exact decision, only
`full_send` permits it. Candidate selection does not authorize parked proof. Re-preparation
starts a new approval epoch. Code-local work requires no live approval.

The operator obtains approval once and records actor plus the human's answer, or a revocation
reason. Specialists check current recorded authority without another human conversation.
This is an audit assertion, not authenticated human identity. Revocation blocks authorized
progress; canonical execution controls are still needed to stop an active command.

Keep terminal proof-work history. Derive a separate renewed-verification obligation when a
material edit invalidates prior runtime-backed verification. Same-verifier, evidence-preserving
reproduction enrichment is attributed by dispatch identity resolved against canonical proof
producers. It preserves the original author and records claim digests in the edit audit. Other
changes retain conservative verification/equivalence review; a receipt supports one verdict.

## Consequences

Approval changes retain current context and ownership; approval-specific blockage can be
cleared without clearing an unrelated blocker. Existing evidence remains attributable after
revocation or invalidation. Recovery still requires terminal execution, including continuation
descendants and ambiguous operator executions, rather than a timeout or forced release.
