# ADR 0023 — Source and live proof enrich one finding

- Status: Accepted — implemented
- Date: 2026-09-12

## Context

One defect can first appear in source and later be confirmed through a live
request. Recording those observations as unrelated findings duplicates triage,
splits proof, and can produce contradictory lifecycle decisions. Conversely,
collapsing materially different behavior loses variant information.

## Decision

One underlying defect remains one canonical finding across source analysis and
live validation. Its source location and sealed-source identity remain the
canonical primary binding. Live URLs, requests, responses, command receipts, and
other proof attach to that finding as first-class evidence.

A file/live merge is allowed only when the file side has an unambiguous current
source identity, and it preserves both source rows, evidence links, and history.
Materially different behavior, preconditions, affected components, or attacker
outcomes are recorded as a linked variant rather than forced into the same claim.

## Consequences

- Review, verification, severity, and submission operate on one complete claim.
- Live confirmation cannot erase source provenance, and source provenance cannot
  replace live proof.
- Ambiguous source identity fails the merge instead of guessing.

## Alternatives considered

- **Always create a live duplicate.** Rejected because it fragments one claim and
  its evidence.
- **Make the live URL canonical after confirmation.** Rejected because the source
  defect remains the durable root location.
- **Merge every related behavior.** Rejected because variants can have different
  reachability, impact, and remediation.
