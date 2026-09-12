# ADR 0030 — Model identity signals remain distinct

- Status: Accepted — partially implemented outside the benchmark harness
- Date: 2026-09-12

## Context

The model and reasoning configuration an operator requests can differ from the
configuration carried by the launcher, and either can differ from what a provider
actually served. Collapsing those signals makes model comparisons and benchmark
claims look more certain than their evidence.

## Decision

Vigil records three separate identity layers for model and reasoning:

1. **Requested** — operator intent.
2. **Launcher-effective** — the exact configuration passed by the supported
   launcher after defaults and overrides.
3. **Provider-observed** — a value from an attributable provider- or client-owned
   session record.

No layer is inferred from another. Missing evidence remains `unknown` or
unavailable; requested identity is never reported as effective or observed, and a
pricing fallback is never provider identity. Aggregates preserve disagreement
instead of selecting a convenient label.

The benchmark manifest and supported session telemetry implement all three model
layers. Ordinary dispatches preserve requested model/reasoning and keep provider
observation unknown, but do not yet persist a separate launcher-effective
model/reasoning value; that general dispatch cutover remains pending.

## Consequences

- Benchmark and run comparisons state what is known and how it was known.
- Unsupported clients can complete work while identity telemetry remains honestly
  unavailable.
- New launchers need an exact effective-config capture and a verified observed
  signal before making stronger identity claims.

## Alternatives considered

- **Treat requested as actual.** Rejected because providers and launchers may
  override it.
- **Infer identity from price or behavior.** Rejected because those are not
  attributable provider observations.
- **Block when observation is unavailable.** Rejected because unavailable
  telemetry is not an execution failure.
