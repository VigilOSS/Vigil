# ADR 0036 — Targeted proof does not create a web campaign

- Status: Accepted — implemented; approval binding amended by [ADR 0038](0038-live-proof-approval-and-verification-history.md)
- Date: 2026-10-18

## Context

A source finding may need a supported local driver or a specific live application
request to establish its impact. Requiring another operator or a full web campaign
for that test creates unrelated recon and completion work and encourages source
identity to select the wrong specialist instructions.

## Decision

Campaign tracks retain their independent phases under ADR 0022. A proof-work item
is a bounded investigation of one current candidate, with an explicit code or web
route, objective, source/finding binding, and selected targets. It neither enables
nor advances a campaign track.

The code route uses audited Kali execution of supported local paths and requires
no live hosts. The web route requires already admitted roots, respects exclusions,
and checks the applicable live exploit approval. Preparing work cannot infer new
authorization from a URL or finding. Exact-work approval binds the prepared
context; changed source, claim, scope or approval posture prevents further claims.

The current operator claims ownership atomically before launching a fresh
specialist. The specialist loads exactly one route's method. The operator does
not load both cores. A broader web campaign remains an explicit add-track action;
a targeted proof does not create its recon or aggregate completion obligations.

## Consequences

- A code audit can verify one live application claim without becoming a full web
  engagement. Its admitted targets and proof approval remain explicit.
- Work completion is distinct from finding verification. Existing proof receipts,
  producer attribution, controls and finding-association requirements still apply.
- Changed context blocks new execution but does not discard the result of work
  already performed. Owners can retain historical evidence and honest blockers.
- Reopening a client is not proof that a worker or detached runtime job died.
  Release requires explicit recovery and terminal execution records, not age.
- These contracts guide and record the trusted operator's work. They are not a
  destination firewall or proof of an agent's independent reasoning.
