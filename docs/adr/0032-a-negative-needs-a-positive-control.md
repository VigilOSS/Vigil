# ADR 0032 — A negative needs a positive control and a stated scope

- Status: Accepted
- Date: 2026-10-13
- Relates to: [ADR 0015](0015-honest-instruments-distinguish-no-measurement-from-clean.md),
  [ADR 0016](0016-target-knowledge-is-derived-and-negatives-are-retryable.md)

## Context

False negatives are rarely announced; they look like tests that found nothing. Recorded cases
include a report-rendering surface closed as an empty render on the strength of a small iframe
wrapper, requests that returned 404 before any authorization ran being read as denials, and
empty certificate-transparency and package-registry lookups carried for weeks as "nothing
exposed" when the tooling had returned zero bytes.

ADR 0015 makes instruments report "no measurement" honestly. This ADR covers the agent's side:
what a specialist must establish before writing a negative down.

## Decision

1. **Bracket every negative with a live positive control.** Before recording that a route is
   denied, clean, or absent, the specialist proves a positive on the same route, verb, identity,
   and gateway in the same window. Without it, "denied" cannot be told apart from blocked, not
   found, not provisioned, or not reached.
2. **A negative states where it was proven.** It names the tier (identity or role), the lens, and
   the run it rests on, and covers only those. A sibling tier or a new lens is a fresh test.
3. **An empty result from Vigil's own tooling is a fact about the run.** A refusal, zero-byte
   result, parse error, or empty match set is checked against a known-present query before it is
   treated as a statement about the target.
4. **Inherited negatives are re-derived from raw evidence.** A prior agent's "tested, clean" is
   re-checked against the recorded request and response bytes before it closes a surface.

## Consequences

- Negatives cost a little more traffic and are worth recording.
- Closed surfaces can be reopened precisely, because each negative says what it covered.
- The rules live in `agent/rules/hunting.md` §16b, §23, and §27.

## Alternatives considered

- **Accept a negative when the tool exits cleanly.** Rejected: soft-failure pages, WAF
  intercepts, and rate-limited stubs all exit cleanly.
