# ADR 0012 — Coverage grain is a calibration, not a principle: selective load-bearing depth for decisive units

- Status: Accepted
- Date: 2026-07-05

## Context

ADR 0001 ("harness over gate") settled two things in one move: **(a)** never gate on self-attested or
free-text signal, and **(b)** therefore keep the one retained gate coarse — family-level, never per-input.
(a) is load-bearing: the strict-gate design ADR 0001 rejected was gameable *because* it trusted free-text
`--technique` and a default `result_status="tested"`. (b) was presented as following from (a), but it
doesn't — it is a separate, looser calibration about how much of the already-durable signal gets to be
load-bearing, not about whether to trust self-attestation.

A live-audit review of the depth harness found the evidence that (a) and (b) are separable: the ledger
already computes a **per-class** refinement, `signal_classes_uncovered` (`depth_ledger.py:~545`) — which
classes a unit's own gf-typed coverage-items implied are still lacking a class-specific covering probe.
This signal is derived from exactly the same durable state the family-level gate already trusts: a real
`request_variant`, a coverage-item's structured `attack_family`, a probe's whitelisted
`result_status ∈ {tested, signal}`. It is **not more self-attested than `attack_family`** — the two are
tied to the same rows. The only reason it wasn't load-bearing was (b), not (a). Yet it was computed and
read by nothing (the code's own comment: "does NOT feed `depth_satisfied`, `missing_block`, or the family
math"), and `check-phase-readiness`'s default text never printed it (JSON-only) — a symptom of treating a
durable, non-self-attested signal as decorative. The same review flagged the `hunting.md:401`
"advisory... does not block you" line as a root-cause bug, not a wording nit: the terminal depth block
already exists (family-level, ADR 0001 decision 2), already fires at `report`/`complete`, and had no
preview surface — legibility requires a real, previewable, continuous obligation, not a braver adjective
on the same discontinuity.

## Decision

**Unbundle (a) from (b). Keep (a) and ADR 0011's route-count-gate rejection exactly as they stand. Make
the already-computed per-class signal selectively load-bearing — narrowly, for decisive units only.**

1. **Scope: decisive units only.** The one existing hard block (`terminal_depth_block`, feeding
   `transition_phase.py`'s `_depth_backstop_blockers`) is extended with a second grain, not duplicated
   into a second gate. It now emits blockers of **two grains** from the same call:
   `depth_unsatisfied_units` (`block_grain="family"`, the historical block — decisive/high-confidence,
   unsatisfied, undeferred, **untouched**) and the new `depth_uncovered_classes`
   (`block_grain="class"`) — a decisive-or-high-confidence unit whose `signal_classes_uncovered`,
   restricted to classes in a `BLOCK_HIGH` family (`access-control`, `auth`, `injection`, `ssrf`, `file`),
   is non-empty. The class grain fires **independently of `touched`/family `depth_satisfied`** — it
   catches the single-class blind spot the family collapse leaves open (a sibling-class probe, e.g. one
   `ssti` probe, marks the whole `injection` family covered while a `sqli`-typed coverage-item was never
   demanded), so it can block even a unit that looks family-satisfied or merely touched. Both grains are
   `severity="block"` on the same terminal edge, cleared by the same `depth_deferral`/`--force --reason`
   valves. Every other unit (non-decisive, non-high-confidence) is unaffected — it never reaches either
   grain and keeps today's family-level behavior and the touched→WARN downgrade, unconditionally.
2. **Every existing guard stays intact.** "Covered" still requires a whitelisted `result_status`
   (`tested`/`signal`) or an evidence-bearing coverage-item; `status="completed"` alone never counts.
   `BLOCK_WARN` families (`disclosure`, `client-side`, `business-logic`, `protocol`) never enter the hard
   set alone. `depth_deferral` (with reason) and `--force --reason` remain the escape valves, unchanged.
   One gate, extended — not a second, parallel one.
3. **ADR 0011's route-count-gate rejection stands.** A gate keyed on "≥N routes uncovered" is a different,
   still-gameable shape (route tallying is trivially gamed by marking routes covered). Nothing here
   reopens that; this decision operates per-class on signal already proven durable, at the narrowest
   possible scope.
4. **Headers: capture + the same class-gate, still no per-name coverage-items.** `header_schema` is now
   populated at the two paths that used to drop it (`ingest_endpoints.py:667`, `proxy_addon.py:1013`),
   from data those paths already hold. This lets the ledger's existing CORS(`client-side`)/proxy
   (`protocol`) presence triggers fire across the full ingest breadth instead of only the spec/candidate
   slice. Both families are `BLOCK_WARN`, so this widens *advisory* completeness, not the hard block — a
   header-driven family only reaches the hard set the same indirect way any family would (decisive unit +
   a `BLOCK_HIGH` class gap elsewhere). No per-header-NAME coverage-item is emitted and the coverage-item
   natural key (`db.py:912`) is untouched — per-name header evidence stays on
   `assessment_probe_runs.input_slot`, the advisory grid, same as every other input.
5. **Legibility.** The would-block set now previews at `--phase report` (not only `consume`/`verify`), and
   `signal_classes_uncovered` renders in the DEFAULT `check-phase-readiness` text, not only `--json`. The
   posture is named honestly — a *deferred-terminal* obligation, continuously visible from phase 4 on —
   not an "advisory" signal that silently turns terminal at the exit.

**Why this isn't re-litigating ADR 0001:** nothing here introduces a new category of signal.
`signal_classes_uncovered` already existed, already read only durable structured state, and was already
computed on every `depth_ledger()` call; the only change is whether one narrow, high-stakes slice of units
gets to treat it as load-bearing instead of decorative. Widening the *scope* of an already-trusted signal
is a calibration; trusting a *new, softer* signal would be the principle ADR 0001 actually defends, and
this decision does not do that. **ADR 0010 was the historical in-repo precedent for this shape of
move**: it took a signal already durable and non-self-attested (a required-header marker's literal
presence in an assembled command) and made it selectively fail-closed. That outbound gate was later
superseded for a separate architectural reason — scope data no longer admits execution — but the
calibration principle used here remains: narrow a hard consequence to where the signal is durable and
the stakes are highest, and leave the rest of the harness advisory.

## The ADR 0009 per-input anchoring boundary

ADR 0009 drew a line between what the operator may inject into a specialist dispatch and what it must
not: **coverage/continuity context** (what's covered, what's untouched — guardrail #1, "cross-dispatch
coverage") is a kept operator injection; **the security hypothesis** (which weakness, which payload) is
not — that anchors the specialist and suppresses hypothesis diversity. Making `signal_classes_uncovered`
selectively load-bearing raises the question of which side of that line a per-input/per-class gap falls
on, since it is finer-grained than the family-level coverage summary ADR 0009 already sanctioned.

**Resolving rule:** per-input/per-identity **coverage state** — which class is uncovered, on which unit,
for which identity — is always operator-injectable; it is the same kind of continuity fact ADR 0009
guardrail #1 already permits, just at finer grain. Per-input **hypotheses** — which specific payload or
technique to try against that input — are not, and stay the specialist's to originate. The class-gate this
ADR adds is built entirely from the first category: it tells the operator (and, at the terminal edge, the
transition gate) WHAT is still uncovered, never HOW to cover it.

## Consequences

- The depth harness's most consequential gate now reads the signal it always computed. A decisive unit
  that only ever got a shallow, sibling-class probe (e.g. one `injection` probe that never actually hit
  the `sqli`-typed coverage-item the gf bridge flagged) no longer reads as family-satisfied or
  "touched, so it's fine" — it blocks under `depth_uncovered_classes`, with the specific uncovered
  classes named and the deferral escape stated, whether or not the unit was otherwise touched.
- Non-decisive units see no behavior change; the coarse family-level harness ADR 0001 designed for the
  general case is unchanged.
- Headers stop silently dropping on the two highest-volume ingest paths without reopening the
  coverage-item-grain debate (`docs/data-flow.md` §7 still holds for the write layer).
- The harness becomes legible end-to-end: no operator-facing doc needs to say "it doesn't block you"
  about a signal that, for some units, now does.

## Alternatives considered

1. **Reopen (b) uniformly — make every family a class-level hard block.** Rejected: reintroduces the
   gameable, always-red-backlog failure mode ADR 0001 rejected, at finer grain and for every unit instead
   of the highest-stakes ones.
2. **Fix `hunting.md:401` as a wording change only.** Rejected: a reword without a real gate change leaves
   the underlying discontinuity intact for decisive units — advisory-and-visible in-phase, then
   load-bearing-and-invisible at the terminal edge. The fix is the class-gate plus the preview, together.
3. **Make headers first-class per-name now (coverage-items keyed on `slot:name`).** Rejected for this
   change: still explicitly out of scope per the coarse-coverage-item invariant (`docs/data-flow.md` §7)
   — reversing that is a separate, larger, sign-off-gated decision, not a byproduct of fixing the
   header-drop.

## Relationship to other items

- **Unbundles ADR 0001**: keeps rule (a) intact; narrows rule (b) from "always coarse" to "coarse by
  default, class-level for decisive units on `BLOCK_HIGH` classes."
- **Reaffirms ADR 0011 decision #1** (the route-count gate stays rejected) — a different gate shape,
  operating per-class on already-durable signal rather than a route tally.
- **Cites ADR 0010 historically** for selective fail-closed enforcement on a
  narrow, high-stakes, already-durable signal; ADR 0010's outbound gate is no
  longer active.
- **Resolves an open question under ADR 0009**: coverage state (incl. per-class, per-identity) is
  operator-injectable; hypotheses are not — this ADR's gate is built from the former only.
- Implemented by `depth_ledger.py` / `transition_phase.py` and
  `ingest_endpoints.py` / `proxy_addon.py`, previewed via
  `check_phase_readiness.py`; see `docs/data-flow.md` §4/§5/§6/§7/§8 for the
  current data-flow picture.
