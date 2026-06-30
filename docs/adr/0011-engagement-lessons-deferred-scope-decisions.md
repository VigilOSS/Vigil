# ADR 0011 — Engagement-lessons consolidation: deferred scope decisions

- Status: Accepted
- Date: 2026-06-30

## Context

The engagement-lessons consolidation (`CONSOLIDATED-PLAN.md`) triaged 93 candidate
items into a phased build. Most were built or promoted. A handful were
deliberately **declined or deferred** — not forgotten — because building them now
would either re-litigate a settled posture, add speculative enforcement code with
no observed trigger, or carry disproportionate IDS/legal risk. This ADR records
those NOT-doing decisions (from `CONSOLIDATED-PLAN.md` Appendix C #3, #6, #7) so a
future reader does not mistake the absence of the code for an oversight, and so
each has an explicit revisit-trigger.

The common thread is the project's standing bias, set in ADR 0001: **harness over
gate, and do not build enforcement on a signal you cannot yet trust or a violation
you have not yet observed.** A speculative gate built on soft signal manufactures
false confidence (worse than an honest gap) and fights the operator instead of
helping it hunt.

## Decision

### 1. Coverage stays an advisory harness, not a gate (PROMPT-TODO §7 L1/L3 declined)

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

### 2. Path-level no-fire enforcement is deferred (PT §4c / §5 / I-4)

`scope.py` is **host/wildcard-granular**: it admits or denies whole hosts (with
wildcard semantics and `out_of_scope` carve-outs). The §5/I-4 proposal was to add
`off_limits_paths` to `scope.py` plus a `scope-check.sh` path-level block so the
machinery could refuse a request to a specific *path* on an in-scope host.

**Decision: do not build it speculatively.** We have observed no real path-level
scope violation; adding an `off_limits_paths` model + a path-check block now is
enforcement code with no trigger, and it widens the scope surface (and its failure
modes) for a case that has not occurred. Per PT §4c, this is recorded as
**settled, not pending**.

**Interim mitigation (already in place):**
- katana's `-cos` (crawl-out-scope) flag gives a crawler-level path carve-out, so
  the highest-volume traffic source can already be steered away from a sensitive
  path prefix during the crawl.
- Dispatch discipline: per-engagement path ROE lives in `ENGAGEMENT.md` /
  `scope.json`, and the operator constrains specialists on hard ROE at dispatch
  (ADR 0009 division of labor), not via a global path block.

**Revisit-trigger:** a real, observed path-level target violation (a probe that
reached an off-limits path on an in-scope host). At that point — and only then —
add `off_limits_paths` to `lib/scope.py` and a `scope-check.sh` path-level block,
driven by the concrete case rather than a hypothetical.

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

- **No new enforcement code lands for #1 and #2.** The coverage harness and
  `scope.py` keep their current shape; nothing half-lands. The system continues to
  steer rather than block on soft coverage signal, consistent with ADR 0001.
- **Each deferral has an explicit revisit-trigger**, so re-opening any of these is
  a recorded decision driven by an observed need, not a silent re-litigation. A
  future engagement that hits a path-level violation, or a need `nmap-scan` cannot
  meet, points straight back here.
- **No prompt/generated-file or schema changes** follow from this ADR — it records
  decisions to NOT build, so there is nothing to render or migrate.
- The masscan/naabu deferral keeps the runtime's default scanning posture
  conservative (IDS/legal risk minimized), with `nmap-scan` as the sanctioned path.

## Alternatives considered

- **Wire the coverage join to block now (the §7-L1/L3 proposal).** Rejected:
  duplicates the strict-gate mistake ADR 0001 already analyzed and reversed —
  gameable on route-count, skippable via defer/force, and it fights the swarm.
- **Build `off_limits_paths` pre-emptively "to be safe."** Rejected: speculative
  enforcement on a never-observed violation; the katana `-cos` carve-out +
  ENGAGEMENT.md/scope.json dispatch discipline cover the realistic cases until a
  real path-level violation justifies the model.
- **Install masscan/naabu behind a flag now.** Rejected: even flag-gated, shipping
  a mass scanner invites use that `nmap-scan` already covers more safely; defer the
  install itself until a concrete need plus `--consent`/scope gating is designed.

## Relationship to other items

- Reaffirms **ADR 0001** (coverage/depth as a harness, not a gate) for decision #1.
- Decision #2's dispatch-discipline framing rides **ADR 0009** (operator/specialist
  division of labor) and the `ENGAGEMENT.md` ROE home (`CONSOLIDATED-PLAN.md` §3.10).
- These are the `CONSOLIDATED-PLAN.md` Appendix C items #3 (harness-vs-gate), #6
  (path-level no-fire), and #7 (masscan/naabu). Appendix C #1/#2 (required-header
  attribution) were *built* and are recorded in **ADR 0010**; the remaining
  Appendix C entries (#4 deconfliction-marker placement, #5 takeover-under-pause)
  are per-engagement operator choices with no global code decision to record here.
