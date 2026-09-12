# ADR 0028 — Producer provenance binds proof to the work that produced it

- Status: Accepted — implemented
- Date: 2026-09-12

## Context

Evidence is not trustworthy merely because it exists in the same engagement. A
stale artifact, unrelated command, or result from another specialist can support
the wrong conclusion unless the record names the exact work that produced it.
This is evidence lineage, not credit or authorship recognition.

## Decision

Durable findings, runs, artifacts, and proof receipts retain resolvable producer
identity. A proof run binds to an exact engagement dispatch; its receipts bind to
that run and to the exact command, source-read, or artifact evidence. Terminal
verification accepts only healthy evidence produced by the verifier dispatch,
and report readiness preserves those dependencies.

A valid producer binding is immutable. A new producer creates new evidence rather
than rebinding old proof. Missing or engagement-unresolvable legacy finding-author
provenance may be repaired once through the audited repair operation, which records
the actor, reason, old value, new dispatch, and compare-and-swap version. Proof
receipt producers are never repaired by guessing.

## Consequences

- A finding can be traced to the exact dispatch, run, and evidence-bearing action
  behind its current proof.
- Unrelated or stale evidence cannot become valid through proximity or matching
  prose.
- Display roles and human-readable agent names remain descriptive; they do not
  replace durable producer identity.

## Alternatives considered

- **Use timestamps or filenames as attribution.** Rejected because neither proves
  which dispatch produced the evidence.
- **Allow producer reassignment.** Rejected because it rewrites evidence history.
- **Reject all legacy rows permanently.** Rejected because a narrow audited repair
  can restore a real known finding-author binding without inventing proof.
