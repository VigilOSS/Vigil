# ADR 0016 — Target knowledge is derived and negatives are retryable

- Status: Accepted
- Date: 2026-09-08

## Context

Vigil already stores observations, coverage, blocked techniques, authored intel
notes and supersession chains. A second claims graph would duplicate those
sources and introduce another reconciliation problem. The memory review also
found that bad memory persisted in 84.2% of cases, selective repair succeeded
only 56.1%, and deterministic deletion performed poorly on changed identifiers
([MemSecBench](https://arxiv.org/html/2607.27080v1), with the surrounding evidence
preserved in the [memory report](../plans/research-operator-robustness/agent-memory-main-report.md#65-staleness-models-notice-but-do-not-act)).

Human practice supports keeping interpretation attributable: the redteam.guide
operator-log guidance states that only the operator can record how an action was
performed and why it was interpreted that way
([source inventory](../plans/research-operator-robustness/citations-and-provenance.md#pass-1--human-offensive-security-knowledge-practice-message-only)).

## Decision

Current target knowledge is derived at read time from canonical observations and
decision records. Authored interpretation lives in the existing intel-note and
org-fact surfaces with provenance, scope and validity context. Authorization and
human policy remain in their owning scope/approval surfaces and are never
inferred from telemetry.

Negative work is stored in coverage or blocked-technique records with a bounded
`retry_state`, reason, source and revalidation context. A prior negative may
guide retrieval, but it cannot become permanent authority to suppress a future
check. Supersession closes the active view without deleting original sources.

## Consequences

- No new claims table, knowledge graph or write-time deduplicator is introduced.
- Current views can change when sources or decisions change while audit history
  remains recoverable.
- Retry decisions are explicit data rather than ambiguous prose.

## Alternatives considered

- **Repair summaries in place.** Rejected because selective repair is unreliable
  and destroys provenance.
- **Store one giant target profile.** Rejected because current truth and stale
  history become inseparable and retrieval becomes unbounded.
- **Treat old negative prose as permanent.** Rejected because it can prevent the
  observation that would disprove it.

## Relationship to other decisions

This extends ADR 0001's rule against gates built on self-attestation and uses the
selective evidence boundaries from ADR 0012. It does not reopen ADR 0011's
coverage or path-enforcement decisions.
