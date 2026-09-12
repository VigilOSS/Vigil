# ADR 0015 — Honest instruments distinguish no measurement from clean

- Status: Accepted
- Date: 2026-09-08

## Context

Several unrelated failures had the same root cause: a check returned its clean
value when it had measured nothing. Examples included a WAF page classified as
live, a challenge detector returning false on the blocking response, a lease
reported as rate governance, and an index silently covering only a prefix. The private source cases
are excluded from the public repository; the invariant and its executable regressions are retained
here.

## Decision

Every instrument must represent at least three outcomes: a supported positive
observation, a supported negative observation, and unavailable/incomplete
measurement. The last outcome is typed and visible. It must not reuse a success
value, and downstream readiness must preserve it as pending, blocked, partial or
unknown according to the owning contract.

Receipts retain producer identity, exact input/evidence references and evidence
health. A result may be promoted only by evidence the instrument actually
observed. Missing output, truncated input, parser failure, transport failure and
unsupported execution are not clean negatives.

### Rate measurement

Rate controls supplied to the actual tool invocation are authoritative: use the
tool's own request-rate and concurrency flags, including any supported clamp to the
operator-authored program ceiling. Vigil does not infer an unapproved numeric
default or substitute a process-level lease for those controls.

Before target-facing execution, Vigil may show the count and latest timing of
other lanes' recorded target-facing **commands**. That bounded cross-lane recency
view is coordination context only. It is not a request count, throughput
measurement, reservation, cooldown, or enforcement claim.

There is no aggregate concurrency lease. Concurrent process overlap neither
measures aggregate request rate nor proves that independently rate-limited tools
are within the engagement-wide budget. The operator remains responsible for
assigning compatible per-tool budgets across active lanes.

## Consequences

- New consumers can reason from explicit evidence health instead of English
  substrings or absence.
- Legacy rows remain readable, but missing proof is not backfilled with invented
  runs, coverage or receipts.
- Recovery paths preserve partial evidence and report what still needs work.
- Rate guidance names the event it actually observed, while request-rate behavior
  remains controlled at the tools that emit the requests.

## Alternatives considered

- **Treat absence as false.** Rejected because it creates false negatives.
- **Use prose warnings alongside a Boolean.** Rejected because consumers can
  still discard the warning and retain the false clean value.
- **Use simultaneous command leases as aggregate rate enforcement.** Rejected
  because process overlap is not request throughput and a coarse lease can become
  a global mutex without providing a trustworthy rate guarantee.
