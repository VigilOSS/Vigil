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

For web work, an exact-work revoke denies authority under every policy until exact-work
re-approval. A stop follows successor preparations of the same finding and route, including
a stop recorded on a stale predecessor after the successor was prepared. Only a later approval
of that successor lifts its stop; approval on an older context cannot grant successor authority.
An exact approval permits the current task. Initial work may use applicable `full_send`;
re-preparation requires a fresh exact approval even under `full_send`. Candidate selection does
not authorize parked proof. Code-local work requires no live approval.

Preparation events retain predecessor work IDs and prior decisions. The response exposes
`approval_renewal_required` and `approval_revocation_work_id` from durable history. Existing
rows derive these states without rewriting their events. Stale work can always be revoked;
current context is required to grant approval.

The operator obtains approval once per work item and records actor plus the human's answer, or a revocation
reason. One answer may name several work IDs and be recorded for each. Specialists check current
recorded authority without another human conversation.
This is an audit assertion, not authenticated human identity. Revocation blocks authorized
progress; canonical execution controls are still needed to stop an active command.

Keep terminal proof-work history. Derive a separate renewed-verification obligation when a
material edit invalidates prior runtime-backed verification. Same-verifier, evidence-preserving
reproduction enrichment is attributed by dispatch identity resolved against canonical proof
producers. It permits appending steps and reproduction runs while retaining each original list
as an exact prefix, and filling empty evidence-reference or evidence-type fields. Replacing
existing values requires review even when attributed to the same verifier. It preserves the
original author and records claim digests in the edit audit. Other
changes retain conservative verification/equivalence review; a receipt supports one verdict.

## Consequences

Approval changes retain current context and ownership; approval-specific blockage can be
cleared without clearing an unrelated blocker. Existing evidence remains attributable after
revocation or invalidation. Recovery still requires terminal execution, including continuation
descendants and ambiguous operator executions, rather than a timeout or forced release.
Ambiguous execution belongs to the interval from claim through finish, resolution, or release;
unrelated operator work started afterward cannot block another proof forever. Directly
attributed execution of current or historical owners and descendants still blocks recovery
regardless of timestamps. The terminal second remains conservatively included because event
timestamps have second precision.
