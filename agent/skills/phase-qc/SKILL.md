---
name: phase-qc
description: Low-context per-PHASE completeness critic the operator runs at each phase / wind-down boundary (before declaring a surface done, lifting an account deferral, or generating a report). Reasons AGAINST the coverage ledger + the lanes' handoffs + the findings list (it does NOT recompute coverage) and emits a STRUCTURED, ADVISORY miss-list — the coverage / depth / grading / chain / waf-blind judgment misses a binary gate cannot catch. Extends blind-triage from per-finding to per-phase.
origin: Vigil
---

# Phase QC — per-phase completeness critic (advisory miss-list)

## When to Activate

Run this at every **phase / wind-down boundary**, before you treat the phase's
work as done:

- before declaring a **surface or target's fan-out done** (the Phase-4
  closed-surface re-audit moment),
- before **lifting an account / coverage deferral** (un-deferring an objective,
  or leaning on a `deferred` / `not_applicable` resolution as if it were closed),
- before **generating a report** (the Definition-of-Done wind-down).

It is the per-PHASE analogue of `agent/skills/blind-triage/SKILL.md`: blind-triage
is a per-FINDING QC (it judges one submission's bytes); phase-qc lifts that same
critic's eye to the **whole phase's coverage, grading, and chains**. Run
blind-triage on each Medium-or-above finding; run phase-qc once at the boundary.

## What it is — and what it deliberately is NOT

- **Advisory, never blocking.** phase-qc emits a miss-list; the operator consumes
  it and re-dispatches / re-grades / fixes. It does **not** gate a transition. The
  blocking gates are `check-phase-readiness` / `transition-phase` and blind-triage's
  recorded-verdict gate — phase-qc complements those, it does not replace them.
- **Reasons AGAINST the ledger; does NOT recompute coverage.** `vigil assess
  coverage` is the measured baseline (route counts, `real_app?`, `recorded-verdict?`,
  the computed coverage-state, `needs_browser_reprobe`). phase-qc reasons **on top
  of** those numbers; it never re-derives them. If phase-qc and the ledger disagree
  on a raw count, the ledger wins — the fix is to re-probe so the ledger moves, not
  to argue with it.
- **Catches the JUDGMENT a binary gate cannot.** It does **not** re-walk the
  command-checkable boxes the gate already owns ("does a verdict row exist?", "is
  the variant-rotation dispatch present?", "is the blind verdict recorded?"). It
  catches the misses those binary passes are blind to: *only the obvious endpoints
  were hit*; *this P4 is, impact-if-true, a P2*; *the finding was filed account-gated
  but the gate self-mints accounts*; *a clean verdict came off a WAF challenge page*.

## Inputs (low-context — bounded projections, never transcripts)

phase-qc is cheap by design. Feed it ONLY these three compact projections — not the
phase's full dispatch transcripts:

1. **The coverage ledger (the baseline):** `vigil assess coverage --json` — per
   in-scope host: `route_count`, `real_app?`, `dedicated_lane?`, `recorded-verdict?`,
   coverage-state, and the `needs_browser_reprobe` flag.
2. **The lanes' handoffs:** enumerate the phase's dispatches with `vigil assess agent
   list` (filter by phase / role), then `vigil assess agent render-handoff <agent-id>`
   for each — the bounded blob (summary, coverage gaps, next steps), NOT the transcript.
3. **The findings list:** `vigil assess list-findings` / `vigil assess fetch findings`
   — slug, severity, status, `canonical_location`, and the `details` story (evidence /
   impact / cvss_vector).

## Stage-Completion Audit (Pipeline Gate)

Before running the judgment-question pass below, run the stage-completion audit. This is a prerequisite check — it confirms that every expected pipeline stage has a completed audit row; the judgment pass then reasons on top of those results, not on a pipeline that silently dropped stages.

```bash
vigil assess check-phase-readiness --phase <current-phase> --by-host
```

Walk the output for any stage flagged `timed_out`, `partial`, or never run (absent from the ledger). For each:

- [ ] **Re-run the stage** if it is still worth running (scope unchanged, tool available, budget permits). A `timed_out` nuclei sweep over 500 hosts is not a verdict — it is a coverage gap. Raise `--timeout` or scope the list down and re-dispatch.
- [ ] **Accept with reason** if re-run is not warranted (out-of-scope host discovered mid-run, tool unavailable, operator explicitly deferred): record the deferral via `vigil assess agent decision --kind coverage_deferral --payload-json '{"stage": "...", "host": "...", "reason": "..."}' --surfaced-to-user` so the gap is audited, not invisible.

A stage that is silently absent from the ledger is a coverage gap the five judgment questions cannot see — `coverage` miss kind catches depth and surface gaps but cannot flag a tool that never ran. The stage audit catches what the ledger's binary state cannot.

## Procedure

For each in-scope host/surface (from the ledger) and each finding (from the list),
ask the five judgment questions below and emit a miss row whenever the answer
reveals a gap. Then hand the miss-list back to the operator. After the operator
re-dispatches, **re-run phase-qc** to confirm the miss cleared (the loop closes
only when the boundary is clean or every open miss is a recorded, justified deferral).

### The miss-list schema (one row per miss)

| field | meaning |
|---|---|
| `host_or_surface` | the host, surface, or finding slug the miss is about |
| `expected` | what a thorough phase should have produced here |
| `observed` | what the ledger / handoff / finding actually shows |
| `miss_kind` | one of `coverage` / `depth` / `grading` / `chain` / `waf-blind` |
| `suggested_redispatch` | the concrete next dispatch — role + skill + objective (or "re-grade via FP/severity gate", "record deferral with reason") |

Emit it as a markdown table or as a JSON array of those objects. Keep `expected`
/ `observed` to one line each — this is a critic's punch-list, not a report.

### The five miss kinds (the judgment each catches)

- **`coverage`** — a host/surface the phase left without a *sound* verdict, beyond
  what the ledger's binary state already makes obvious. The ledger already flags
  `uncovered` real-app hosts; phase-qc adds the layer the count cannot see: a host
  the ledger calls `covered` on one verdict but whose **distinct surfaces** (a second
  app on another path, an API root, an admin panel) never got a lane; or a surface
  resolved `deferred` / `not_applicable` **on a timer** rather than because it was
  genuinely dead (the dead-vs-unfinished judgment). *Signal:* ledger row + dispatch
  list + the surface's resolution reason. (NOT "is `route_count` ≥ threshold" — that
  is the gate's job.)
- **`depth`** — *only the obvious endpoints were hit.* The host has a verdict, but
  the lane that produced it ran one shallow pass — a single vuln-class, the homepage
  and a couple of obvious routes — then closed. Premature closure on an app-like
  surface. *Signal:* the handoff's own coverage-gaps / next-steps naming untested
  variants or surfaces; a thin probe footprint against a high `route_count`; a
  `covered` host whose lane touched far fewer routes than the ledger counts.
  *Redispatch:* re-open with a real campaign — the matching vuln-class skill at
  `item-iterating` / `hypothesis-driven` depth, not another quick tick.
- **`grading`** — *this P4 is, impact-if-true, a P2* and *account-gated but the gate
  self-mints.* A finding's recorded severity rests on a preconditions/impact judgment
  that is wrong: a low rating that assumes an auth gate which actually **self-mints**
  (anyone can self-register → the precondition is free → effectively unauthenticated →
  higher band); an "impact-if-true" never proven up to the claimed band; an inflated
  `S:C` / `I:H` with no real object crossing the boundary. *Signal:* the finding's
  severity vs. its proven evidence, run through the C1–C6 FP & severity gate.
  *Redispatch:* re-grade via `agent/references/finding-fp-and-severity-gate.md`, or a
  `vulnerability-analyst` review-mode pass to prove or kill the impact-if-true.
- **`chain`** — A→B primitives left **unsynthesized** across the phase's lanes. Two
  findings/handoffs that compose into something bigger (info-leak + open-redirect,
  SSRF + token-leak, IDOR + impersonation, auth-bypass + IDOR) but no lane connected
  them. *Signal:* read the lanes' handoffs *together* and look across them — the
  single-lane view structurally cannot see this. *Redispatch:* an `exploit-developer`
  chain-construction pass over the pair (the Exploit→Report mandatory pass / the
  system-level synthesis step).
- **`waf-blind`** — *a verdict came from a WAF challenge page.* A verdict — positive
  **or** "clean / no findings" — that rests on an edge / challenge / CDN / soft-error
  page instead of the real origin response. The ledger's `needs_browser_reprobe` flag
  is the binary signal; phase-qc also catches the case the flag misses: a non-browser
  "no findings" lane verdict on a WAF host the WAF may have been lying to. *Signal:*
  ledger `needs_browser_reprobe` + WAF tier + the lane's probe method. *Redispatch:*
  re-probe via `agent/skills/browser-semantic-analysis/SKILL.md` and re-judge against
  the real response.

## Disposition

Each miss is one of: **re-dispatched** (the operator fires the `suggested_redispatch`),
**fixed in place** (a re-grade / a recorded `false_positive` / a corrected `details`
story), or **deferred with a stated reason** — record the deferral so it is audited,
not invisible: `vigil assess agent decision --kind coverage_deferral --payload-json
'{"host": "...", "deferred_objectives": ["..."], "reason": "..."}' --surfaced-to-user`.
A miss that is silently dropped is the failure mode this skill exists to prevent.

## Cross-references

- `agent/skills/blind-triage/SKILL.md` — the per-FINDING QC gate phase-qc extends to
  the per-PHASE level. blind-triage judges one submission's bytes blind; phase-qc
  judges a whole phase's coverage / depth / grading / chains. They stack: blind-triage
  per Medium+ finding, phase-qc once at the boundary.
- `agent/references/finding-fp-and-severity-gate.md` — the C1–C6 FP / severity-downgrade
  catalog phase-qc applies for `grading` misses.
- `vigil assess coverage` (operator-core "Read the coverage ledger…") — the measured
  baseline phase-qc reasons against and never recomputes.
- operator-core "Closed-surface dead-vs-unfinished re-audit" + "Depth Doctrine" — the
  `coverage` / `depth` miss source.
- operator-core "Mandatory Phase-Exit Passes" + Phase-4 "System-level synthesis" — the
  `chain` miss source.
- `agent/skills/browser-semantic-analysis/SKILL.md` — the re-probe for `waf-blind` misses.
- `check-phase-readiness` / `transition-phase` — the binary, blocking gates phase-qc
  complements; phase-qc is the advisory judgment layer on top, not a second gate.
