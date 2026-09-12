# ADR 0026 — Sealed source generations own current code truth

- Status: Accepted — partially implemented; complete generation-history retention remains pending
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

This decision does not authorize incremental reuse. A later design may define
safe callable lineage and affected-scope reuse; until then, a new generation
makes earlier conclusions non-current. Sealed snapshots and active-generation
gating are implemented, but refresh still deletes some changed-file queue/result
rows rather than retaining a complete generation history.

## Consequences

- “Current” means reviewed against attested bytes and scope, not a familiar path
  or commit label.
- Old conclusions cannot silently cover a changed generation.
- Incremental scanning cannot be introduced without a separate evidence-backed
  decision and durable identity model.

## Alternatives considered

- **Trust caller metadata.** Rejected because it does not attest filesystem
  content or exclusions.
- **Key only on commit SHA.** Rejected because dirty worktrees and admission rules
  change the reviewed source without changing that label.
- **Reuse unchanged-file results immediately.** Rejected pending stable callable
  lineage and conservative impact accounting.
