# Hunting Rules — Operator

Web-operator rules for deciding when a phase is done, how hard the shared egress can be driven, and
where depth is measured. Load it before you declare a phase exhausted or exit a phase, before you add
a concurrent dispatch against a WAF-fronted estate, and when `vigil assess app-unit list` shows
`deep_required` units. The evidence bar itself (attacker outcome, leads versus verdicts, what a
negative needs) is `agent/rules/hunting.md`.

## 1. Phase-exhausted means every flagged host has a recorded verdict

A phase is exhausted only when every real-app host above the route threshold carries a recorded
verdict — a finding, or an evidence-backed negative (`hunting.md` §13) — as the coverage ledger's
`recorded-verdict?` column shows. A feeling of completion after working the highest-route hosts is
not a verdict; "I have seen what this surface is" is the head-sampling bias that buries findings on
hosts nobody opened.

- **Distrust conclusions that retire untested hosts.** "Everything funnels to one account system,"
  "the whole estate is one vendor platform" — a hypothesis whose payoff is ending the hunt has to be
  earned host by host, not extrapolated from the first few.
- **Ledger-green is a floor.** It means every *flagged* host has a verdict. A high-value API below the
  route threshold may never have been flagged, so a green ledger can coexist with an untested
  application (§3).
- **Pull the next uncovered host; do not sample.** Take the next `uncovered` real-app host from
  `vigil assess coverage` and give it a lane rather than choosing by feel; the ledger keeps handing
  you the host you would otherwise skip.

## 2. Aggregate request rate across concurrent dispatches

A WAF-fronted estate rate-limits the shared runtime egress IP, not any single dispatch: four lanes at
a "safe" 5 r/s look like one client at 20 r/s at the edge.

- Budget the aggregate rate across all concurrent dispatches. Before adding a lane against a
  WAF-fronted estate, sum the rates in flight and check the total against the tier's ceiling
  (`agent/references/recon/rate-calibration.md`).
- Do not run an inherently high-volume tool (`arjun`, `ffuf`, a large `nuclei` sweep) alongside
  several deep specialist lanes on the same estate; serialize it, or run it alone at a low rate
  scoped to a few endpoints.
- Run long or high-volume tools as an operator-owned `kali job`. `vigil assess kali job stop` cleanly
  stops the in-container process; a synchronous `kali exec` killed by the agent-harness ceiling
  (exit 144/SIGUSR1, `agent/shared-constraints.md` §2) orphans a scanner that keeps sending traffic
  with nobody able to stop it.
- A WAF/CloudFront 403 block is pending, never a clean negative (`hunting.md` §12(d);
  `agent/references/web/waf-bypass-and-safe-testing.md` for block signatures and WAF-clean routing).

## 3. A URL can be a whole application — go deep on app units

One host often carries several applications under different path prefixes (`host/giving`,
`host/admin`, `host/api/v2`). Each is its own app unit `(host, port-class, path-prefix)` with its own
auth model and surface; a shallow pass that glances at each prefix hides an entire untested
application.

The backend scores each unit and marks the ones worth a dedicated campaign `deep_required`. Through
Phases 1–6 that scoring is advisory and EV-ranked — it says where to dig next and refuses nothing.
At the terminal `report`/`complete` edge, a decisive-surface or high-confidence `deep_required` unit
is held when it fails either grain:

- **Family grain** (`kind=depth_unsatisfied_units`) — never touched for a block-high family
  (`access-control`, `auth`, `injection`, `ssrf`, `file`).
- **Class grain** (`kind=depth_uncovered_classes`) — the family looks covered, but a class its gf
  coverage items flagged (`signal_classes_uncovered`) never got a class-specific probe; an `ssti`
  probe can satisfy `injection` while `sqli` has none.

Deep-test the gap or record a `depth_deferral` decision (the transition refusal prints the exact
command); `vigil assess check-phase-readiness --phase report` previews the hold from Phase 4 on.
Dispatch a `deep_required` unit as a whole application: one lane across every applicable vuln class and auth context.
`vigil assess app-unit list` shows the ledger, `app-unit score` re-runs discovery,
`app-unit mark-deep` / `clear-deep` pin an override that beats the scorer
(`vigil assess contract app-unit`), and `vigil assess work-buffer fetch-by-unit` claims a unit's
next queue batch.
