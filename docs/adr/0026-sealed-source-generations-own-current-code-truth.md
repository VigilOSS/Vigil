# ADR 0026 — Sealed source generations own current code truth

- Status: Accepted — implemented
- Date: 2026-09-12

## Context

Code conclusions are meaningful only for the exact source reviewed. A checkout
path, branch label, or caller-provided “verified” flag cannot prove those bytes,
and an exclusion change can alter review scope even when admitted file hashes do
not change.

## Decision

Code ingest publishes an immutable, content-addressed source snapshot whose
manifest identifies every admitted file and every excluded entry with its reason.
The backend independently attests the engagement-owned snapshot, its exact bytes,
permissions, admitted inventory, excluded inventory, and staged metadata before
granting verified status or promoting a repository generation.

Any admitted-content, language, admission-boundary, exclusion-boundary, or trust
change advances the active generation. Historical snapshots and generation-bound
records are retained for audit, but only the active generation can satisfy
coverage, findings, structural indexes, or readiness.

Each promoted generation has an immutable source record and exact admitted-file
inventory. Promotion marks the replaced generation and its queue items, result
receipts, and cross-file triggers with one supersession timestamp, the
`source_generation_replaced` reason, and the replacement generation. It does not
rewrite queue status, lease ownership, disposition, receipt identity, callable
links, or trigger resolution. Files absent from the replacement inventory are
retired rather than deleted so their generation-bound foreign keys and audit
history remain intact; live file, coverage, and readiness projections exclude
retired rows. The refresh API and CLI call this count `retired`; `deleted` is not
an accepted compatibility alias because no durable source record is deleted.
Explicit history projects each result and trigger through its immutable
generation-file inventory, so a later rename cannot rewrite the path that was
reviewed. Current projections continue to join only the active generation and
live file path.

This decision does not authorize incremental reuse. A later design may define
safe callable lineage and affected-scope reuse; until then, a new generation
makes earlier conclusions non-current. Sealed snapshots and active-generation
gating remain the only reuse policy: a preserved earlier receipt is audit history,
not evidence for the replacement generation.

## Consequences

- “Current” means reviewed against attested bytes and scope, not a familiar path
  or commit label.
- Old conclusions cannot silently cover a changed generation.
- Operators can inspect the original receipt, callable links, disposition, trigger
  resolution, and lease identity after a later generation replaces it.
- Additive migration captures only the source generation still represented by the
  live repository row; it does not fabricate generations or records deleted by an
  older release.
- Incremental scanning cannot be introduced without a separate evidence-backed
  decision and durable identity model.

## Alternatives considered

- **Trust caller metadata.** Rejected because it does not attest filesystem
  content or exclusions.
- **Key only on commit SHA.** Rejected because dirty worktrees and admission rules
  change the reviewed source without changing that label.
- **Reuse unchanged-file results immediately.** Rejected pending stable callable
  lineage and conservative impact accounting.
