# ADR 0044 — Current discovery can associate a historical finding

- Status: Accepted — implemented
- Date: 2026-11-08
- Clarifies: [ADR 0026](0026-sealed-source-generations-own-current-code-truth.md)

## Context

A resumed code hunt can independently rediscover an issue recorded against an earlier
source generation. Requiring that finding to be rebound before recording the hunt's
analysis forces the hunter to mint a duplicate or leave reviewed work open. Finding
verification and source review are different receipts: the hunter owns current discovery,
while an independent verifier owns the finding's proof and generation binding.

## Decision

A lease-owned, current-generation analysis receipt may associate a reportable root file
finding from the same repository, including one whose finding provenance is stale.
The existing receipt records the current generation, exact reviewed source anchors,
lease identity, evidence, and canonical finding slug. Queue closeout applies the same
association rule and continues to require current source review and family coverage.

Association does not rewrite the finding, its original provenance, historical receipts,
or verification status. The stale finding remains stale for proof, report readiness, and
verification. Its earlier conclusions cannot cover the current generation; only the newly
authored analysis receipt covers the source actually reread. Rebinding the finding still
uses the verification lifecycle. Active scan candidate promotion retains its separate exact
source identity requirement. A scan rediscovery instead records a `duplicate` candidate
naming the existing slug, with healthy proof receipts including a source observation for
that exact current run source. A finding analysis receipt can associate that candidate
without promoting the historical finding or changing its verification.

No bulk provenance rewrite is introduced. Resolving a path and line establishes that a
citation exists, not that the previous vulnerability claim remains correct.

## Consequences

- Correct deduplication can close reviewed queue work without a duplicate finding or a
  misleading verifier transition.
- The existing finding remains visible verification debt until independently reviewed
  against current source.
- Receipt-free verdicts have reproduction basis `unknown`; this describes absence of
  current typed receipts and grants no source-only reproduction exemption. Typed proof
  receipts continue to identify the evidence actually observed.
