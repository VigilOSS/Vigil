# ADR 0047 — Shared-runtime concurrency limits are tier-scoped

- Status: Accepted — operator guidance in
  `agent/references/runtime-guides/dispatch-resource-policy.md` and
  `agent/phases/phase-4-consume-test.md`
- Date: 2026-11-14

## Context

Three engagements set the concurrency guidance, and the prompts that carry it now state only the
current rules, so the incidents are recorded here:

- On a shared Standard-tier runtime, four parallel recon agents, each running recursive passive
  enumeration (`subfinder -all -recursive`) plus `amass`, drove host load to 36 on a 12-core host and
  nearly crashed the Docker daemon.
- Concurrent in-container probes from different lanes against one host thrashed the container's
  resolver and produced false negatives (the resolver flap the kali probe retry still names I-013).
- Carrying the shared-runtime "one heavy operation at a time" limit onto dedicated hardware left about
  two specialists running, and the long tail of surfaces was written off for lack of lanes.

The first incident argues for a tight limit and the third against one, so the limit cannot be a
single number: it depends on whether the runtime is shared.

## Decision

- **Standard (shared) tier:** one heavy enumeration operation at a time, engagement-wide; Phase 1
  runs as a sequential, monitored pipeline (start the next heavy operation only after host load and
  the daemon health check allow it).
- **Heavy and Comfortable (dedicated) tiers:** 4–6 concurrent specialists is the floor, not a
  ceiling; drop below it only when the box's own health check shows saturation.
- **Every tier:** lanes get disjoint hosts wherever possible, and at most one active target-facing
  tool runs per host across all lanes.
- These are operator cues in the runtime guide and the Phase 4 dispatch rules, not CLI gates.
  `vigil assess` adds a target-concurrency advisory before each target-facing command; it reports
  the count and latest timing of other lanes' recorded target-facing commands and enforces nothing.

## Consequences

- The prompts state each limit with its reason in one clause; this ADR keeps the incidents behind them.
- A shared runtime trades breadth for stability; a dedicated one is expected to run wide, so a thin
  lane count there is a utilisation defect rather than caution.
- Nothing stops an operator from exceeding the shared-tier limit; the guidance and the host health
  check are the only controls.

## Alternatives considered

- **One limit for every tier.** Rejected: the shared-tier limit starved dedicated runtimes, and a
  dedicated-tier floor overloads a shared one.
- **Enforce the limits in the CLI.** Rejected for now: the right number depends on the host's live
  load, which the guidance asks the operator to read, and a fixed gate would either refuse useful work
  on a dedicated box or permit overload on a shared one.
