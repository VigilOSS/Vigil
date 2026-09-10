# ADR 0014 — Rate governance measures recency, not concurrency

- Status: Accepted; implementation pending
- Date: 2026-09-08

## Context

The retired aggregate lease summed declared request rates for simultaneously
running commands. In practice, an ordinary `curl` reservation consumed the
whole cap, so it behaved as a global mutex. More importantly, it measured the
wrong event: the observed 2026-07-24 block followed two lanes alternating 93
requests over 29 minutes, not concurrent requests. The preserved corpus showed
the same distinction: simultaneous-run overlap was 20.0% versus 36.0% of active
multi-agent windows for PCO, and 1.8% versus 46.2% for CrowdStrike. The complete
measurement and its limitations are retained in the
[robustness source](../history/2026-09-08-operator-robustness-plan-source.md#42-what-the-rate-gate-actually-measures--the-decisive-measurement).

## Decision

Delete the aggregate lease rather than presenting it as a rate limiter. Keep
program rate limits as authored rules and present recent same-host activity as
an advisory observation. The advisory must say what was measured—commands or
requests—and must never claim enforcement.

Cooldowns, windows, lock placement, exit codes and configuration keys remain
design parameters, not accepted constants. A control that cannot distinguish a
real block from an authorization response may not latch or suppress work.

This repository task records the decision but does not implement target-facing
rate/control behavior. That implementation remains visible in the Phase 2 plan.

## Consequences

- Requested rate is not confused with observed request throughput.
- Interleaving is visible without a false guarantee that a mutex prevents it.
- No advisory can block a lane or manufacture a clean result.

## Alternatives considered

- **Make the lease mandatory.** Rejected because the measured incident stayed
  far below the configured rate and rarely had simultaneous commands.
- **Choose the recorded cooldown defaults now.** Rejected because a false long
  latch can erase useful evidence; the defaults require build-time review.
