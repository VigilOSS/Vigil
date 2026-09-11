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

## Consequences

- New consumers can reason from explicit evidence health instead of English
  substrings or absence.
- Legacy rows remain readable, but missing proof is not backfilled with invented
  runs, coverage or receipts.
- Recovery paths preserve partial evidence and report what still needs work.

## Alternatives considered

- **Treat absence as false.** Rejected because it creates false negatives.
- **Use prose warnings alongside a Boolean.** Rejected because consumers can
  still discard the warning and retain the false clean value.
