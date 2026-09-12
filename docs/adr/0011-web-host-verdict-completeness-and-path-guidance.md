# ADR 0011 — Web host-verdict completeness and path guidance

- Status: Accepted
- Date: 2026-06-30

## Context

A route inventory is useful evidence that a host is an application, but the number of
recorded routes is not a trustworthy measure of how many tests were required or
completed. Treating every route as an independent coverage obligation would reward
mechanical bookkeeping instead of deep investigation. The durable question at
closeout is narrower: did the engagement reach a reasoned outcome for every
in-scope host that has enough application signal to matter?

`scope.json.off_limits_paths` is also useful to the human operator as authored ROE
context. It is not a sound execution boundary: deriving admission decisions from
argv or intercepted paths produces incomplete, surprising enforcement and can hide
the traffic and evidence the operator needs to understand.

## Decision

### Route count classifies a real application; it does not create per-route work

A web host is classified as a real application when it has at least six distinct
recorded routes, or when any recorded route exposes an API, authentication, or
GraphQL surface. The route count is only this classification signal. It does not
require every route to be tested, assign one work item per route, or prove that a
host is covered.

While work is in progress, the classification and missing-host-verdict state are
dashboard and readiness context. At the terminal web report transition and final
web report export, every in-scope real-application host must have one of:

- a finding that records the host's positive verdict;
- an evidence-backed negative recorded as a false-positive finding; or
- an explicit coverage-completeness deferral with a reason, for the host or the
  engagement.

This is a host-level closeout obligation, not a route-count coverage gate. Code and
blue engagements do not inherit it merely because they contain route-like data.

### `off_limits_paths` remains visible human ROE guidance

Vigil preserves and displays operator-authored `off_limits_paths`, but does not
block, rewrite, or suppress commands or proxied requests from that field. It also
does not derive crawler exclusions from it. Operators may still supply explicit
crawler exclusions when that is the intended execution instruction.

## Consequences

- Broad applications cannot disappear from a web report without a recorded
  outcome, but agents are not forced into shallow per-route bookkeeping.
- A small API, authentication service, or GraphQL endpoint still receives a host
  verdict obligation even below the six-route threshold.
- Path ROE remains visible without pretending argv or proxy inspection is a
  complete authorization boundary.
- Evidence and deliberate deferrals, rather than route totals, explain why a host
  is ready for closeout.

## Alternatives considered

- **Require a result for every recorded route.** Rejected because route discovery
  cardinality is noisy and gameable, and route-by-route accounting can suppress
  deeper hypothesis-driven work.
- **Leave real-application hosts entirely advisory at closeout.** Rejected because
  an application host with no finding, negative, or deferral has no durable
  outcome and can silently disappear from the final report.
- **Enforce `off_limits_paths` by parsing commands or proxy traffic.** Rejected
  because those observations are incomplete and would turn human guidance into a
  misleading execution boundary.

## Relationship to other decisions

- Reaffirms ADR 0001's distinction between coverage guidance and trustworthy
  terminal obligations.
- ADR 0012 adds a separate web terminal-transition depth backstop for decisive app
  units; it does not convert route totals into per-route coverage requirements.
