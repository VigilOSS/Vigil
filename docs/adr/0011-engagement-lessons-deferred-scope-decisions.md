# ADR 0011 — Coverage, path no-fire, and mass-scanner decisions

- Status: Accepted
- Date: 2026-06-30

## Context

This ADR records three related decisions that originated in engagement review:
keep route-count coverage advisory, the former authored path-level no-fire
policy, and keep high-rate mass scanners out of the default runtime.

The common thread is the project's standing bias, set in ADR 0001: **harness over
gate, and do not build enforcement on a signal you cannot yet trust or a violation
you have not yet observed.** A speculative gate built on soft signal manufactures
false confidence (worse than an honest gap) and fights the operator instead of
helping it hunt.

## Decision

### 1. Coverage stays an advisory harness, not a route-count gate

> **Superseded-in-part by [ADR 0012](0012-coverage-grain-selective-load-bearing-depth.md):** the
> route-count ≥N-uncovered-routes gate declined below stays declined — ADR 0012 is a different, narrower
> mechanism (a per-class block for decisive units only, on signal already proven durable), not a
> reopening of this decision.

The route-count + per-host-verdict coverage join already exists and works
(`coverage_checks.py` `build_coverage_ledger`), but it ships **non-blocking** by
construction. The §7-L1/L3 proposal was to wire it to **BLOCK** a phase transition
when ≥N routes on a host are uncovered (and to WARN on unreviewed unauthenticated
findings).

**Decision: keep it advisory.** We do not promote the coverage join to a blocking
gate. This reaffirms ADR 0001 ("Coverage and depth as a harness, not a gate"): the
coverage instrument steers the operator mid-engagement (EV-ranked "what you likely
missed and where to dig next") and the only retained hard block is the terminal,
deferrable one at `report`/`complete`. A blocking ≥N-route gate keyed on
route-count is exactly the gameable/skippable choke ADR 0001 rejected — under
pressure the LLM marks routes covered, mass-defers, or `--force`s past it.

The per-host-verdict / unreviewed-unauth WARNs remain as advisory signal the
operator reads, not as a block.

### 2. Authored path-level no-fire policy (superseded)

> **Superseded (2026-07-28):** the fail-closed decision below is historical.
> `off_limits_paths` no longer refuses Kali, browser, or proxied requests and no
> longer generates automatic Katana exclusions. Explicit operator-supplied
> crawler exclusions remain available. Host/wildcard allow-deny matching
> survives where it shapes collected datasets, proxy flow ownership, and
> coverage accounting, but never as outbound or dispatch admission.

`scope.json.off_limits_paths` is now a durable, explicitly authored ROE input.
`agent/scripts/assess/lib/scope.py` refuses a command whose requested http(s)
URLs match one, and `agent/scripts/proxy_addon.py` returns a recorded synthetic
451 before an intercepted request is sent upstream. Malformed authored policy
fails closed for the affected engagement. The path block is independent of host
matching: it names specific URL paths the program put off limits, so it applies
to any command or proxied request that reaches one.

This is deliberately narrower than inferring path restrictions from findings or
content. Only operator-authored scope policy can create the path block.

### 3. masscan / naabu stay deferred (high IDS/legal risk)

Mass L3-L4 port scanners (`masscan`, `naabu`) remain **not installed by default
and not wrapped**. They are high-rate, high-visibility scanners whose default
behavior is exactly the kind of broad, noisy sweep that trips IDS and, on some
programs, crosses a legal/authorization line.

**Decision: keep deferred.** The existing `nmap-scan` verb covers the port/service
need with a controllable, lower-rate, scope-filtered profile (`-sT` connect,
top-ports default, audited). Reach for it instead of a mass scanner.

**Revisit-trigger + guardrails if ever built:** only on a concrete need that
`nmap-scan` cannot meet, and then gated behind an explicit `--consent` flag plus a
tight scope gate (no bare-CIDR sweeps), documented rather than installed by
default — the same posture the plan records for any high-risk capability.

## Consequences

- Route-count coverage remains advisory; explicit path ROE is guidance rather
  than an execution gate.
- A future need that `nmap-scan` cannot meet is the only trigger for revisiting the
  mass-scanner decision.
- The masscan/naabu deferral keeps the runtime's default scanning posture
  conservative (IDS/legal risk minimized), with `nmap-scan` as the sanctioned path.

## Alternatives considered

- **Wire the coverage join to block now (the §7-L1/L3 proposal).** Rejected:
  duplicates the strict-gate mistake ADR 0001 already analyzed and reversed —
  gameable on route-count, skippable via defer/force, and it fights the swarm.
- **Infer path blocks from observations or findings.** Rejected: evidence is not
  authorization. Path enforcement comes only from authored scope policy.
- **Install masscan/naabu behind a flag now.** Rejected: even flag-gated, shipping
  a mass scanner invites use that `nmap-scan` already covers more safely; defer the
  install itself until a concrete need plus `--consent`/scope gating is designed.

## Relationship to other items

- Reaffirms **ADR 0001** (coverage/depth as a harness, not a gate) for decision #1.
- Decision #2 followed **ADR 0009** (operator/specialist division of labor) and
  **ADR 0010** (fail-closed attribution); both fail-closed execution decisions
  are retained here only as history after the 2026-07-28 pass-through change.
