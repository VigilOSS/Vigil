# ADR 0022 — Web and code tracks advance independently

- Status: Accepted — implemented
- Date: 2026-09-12

## Context

Source analysis and live validation often alternate or run concurrently. A single
phase field would force one track to rewind, erase progress, or impersonate the
other. Inferring a track from traffic or ingestion would also turn observation
into an authorization change.

## Decision

Web and code are independent durable tracks with independent phases and
readiness. Adding a missing track is an explicit, recorded `add-track` operation.
It preserves the existing track exactly and initializes only the new one:

- code to both preserves the code phase and starts web at `recon`;
- web to both preserves the web phase and starts code at `ingest`.

Legacy incomplete track state requires an explicit repair. The aggregate
engagement is complete only when every active track is complete. Work or evidence
from one track may inform the other, but cannot silently satisfy its lifecycle.

## Consequences

- Operators can alternate source and live work without phase toggles or lost
  progress.
- Completion and blockers remain attributable to the track that owns them.
- Adding capability is an operator decision, never a side effect of probing,
  ingestion, or capture.

## Alternatives considered

- **Use one global phase.** Rejected because mixed work cannot be represented
  without overwriting valid state.
- **Activate tracks automatically.** Rejected because observed activity must not
  mutate authorization or workflow scope.
- **Treat either completed track as aggregate completion.** Rejected because it
  hides unfinished required work.
