# ADR 0001 — Coverage and depth as a harness, not a gate

- **Status:** Accepted (planning) — implementation pending, tracked by `docs/plans/harness-master-plan.md`.
  **Superseded-in-part by [ADR 0012](0012-coverage-grain-selective-load-bearing-depth.md):** the coarse,
  family-level scope of the terminal block (decision 2, and the "strict per-item gate" rejection under
  Alternatives considered) is narrowed to a decisive-unit, class-level exception; decision 3 (never gate
  on self-attested/free-text signal) and everything else here stand unchanged.
- **Date:** 2026-06-08
- **Deciders:** Engagement operator (project owner) + Claude (planning).
- **Supersedes / relates to:** establishes `docs/adr/`. Implemented by `docs/plans/harness-master-plan.md`
  (entry point) and `docs/plans/coverage-depth-gate.md` (detailed design).

---

## Context

Vigil is a multi-agent security-assessment system. An "operator" LLM runs a phased web pentest
(recon → collect → consume-test → verify → exploit → report → complete) and dispatches specialist sub-agents
that do the target-facing work. Durable state lives in a SQLite backend (`orchestrator/backend/`); the operator
and specialists mutate it through a `vigil assess <verb>` CLI (`agent/scripts/assess/`). The operator prompt is
generated from `agent/operator-core*.md` + `agent/agents/*.md`.

**The primary goal is to find more, higher-severity vulnerabilities** (this is offensive/bug-bounty work, not
compliance). Two failure modes motivated this decision, observed on a real large engagement:

### Origin evidence (the engagement that triggered this)

- 458 host-roots / 1,553 live hosts discovered, but only ~17 distinct hosts were ever scoped into
  vulnerability-analyst lanes, and ~350+ host-roots were never touched by any VA lane.
- 515 gf-classified candidates left pending — the curated set was never worked through.
- Secrets/JS surface barely touched (no systematic Trufflehog / gau-secrets / JS endpoint+secret extraction);
  IDOR done opportunistically rather than as a per-service campaign with the idor/split-brain/vendor-enum skills.
- The engagement nonetheless reached "complete" by writing the long tail off as "low EV / diminishing returns"
  (an "option D" judgment call presented as exhaustion) — while the backend's own gates still reported coverage
  blockers.

The operator's diagnosis, in their words: **a "surface" can be an entire service — or even a whole domain — that
warrants its own deep campaign (katana crawl, content discovery, parameter/IDOR sweeps, JS/secret extraction, a
dedicated specialist dispatch).** Treating surfaces as quick items, running only ~2 specialists at a time, not
re-anchoring on method mid-run, and losing the long tail to a silent write-off are how real vulnerabilities go
unfound. The operator also wanted the model to run 4–6 specialists concurrently, periodically re-read the core
docs, and stop using CAPS-for-critical / casual ("reddit") severity language.

### What the code actually does (verified during planning)

The existing coverage gates measure **breadth** and **resolution**, never **depth**:
- `assessment_surfaces.status` is a resolution flag — a surface marked `covered` after one curl passes
  `check-coverage` (`coverage.py:coverage_readiness`).
- The consumption gate is satisfied when pending work hits zero *or every pending row carries a terminal_reason*
  — which `classify-work` can set by *deferring*, not testing.
- `per_host_coverage` (the one depth-ish projection) is recon-flavored (did fingerprinting happen) and WARN-only.

There are **four disjoint vuln taxonomies** (gf-buckets, at the time only in the local per-engagement `cases.db` — since folded into the backend `assessment_work_items` ledger, see `docs/adr/0013-work-buffer-folded-into-backend-ledger.md`; a hardcoded `BUCKET_SKILLS` mapping
11/15 buckets; 8 `surface_type`s; free-text `attack_family`), and **24 of 35 offensive testing skills have no
gf-bucket at all** — so a gate keyed on gf-buckets is blind to ~68% of capability, including the access-control,
auth, and business-logic classes where the highest bounties live. The richer primitives that *could* measure
depth — `assessment_coverage_items` (endpoint × auth_context × attack_family) and `assessment_probe_runs` — are
**not gated and barely populated**: probe_runs is never auto-emitted; coverage_items only auto-populate via the
mitmproxy and only with generic families. `auth.json` is single-identity, so IDOR/BOLA depth cannot be measured.

### The pivot that this ADR records

The first design was a **strict depth gate** that would block phase transitions until each service-class surface
was tested across its expected vuln classes. An adversarial review of that plan, then a five-lane sweep of the
existing codebase, showed two things:

1. **The strict gate would be gameable and skippable.** `--technique` is operator-chosen free metadata, and
   `result_status` defaults to `"tested"` → `COVERED`, so one self-labeled curl marks a whole class covered; the
   "consume→exploit" block point wasn't even a real phase adjacency; the deferral escape valve didn't exist in
   the schema (only `--force`); and the scorer was blind to hosts touched only by direct tools.
2. **The same choke/gameable pattern already ships across the codebase** (~45 findings): report-readiness
   hard-blocks on admin hygiene (unlinked notes, stale dispatches); the variant-pass gate matches the word
   "variant" in free-text task; a per-engagement nuclei lock hard-fails concurrent sweeps (killing the 4–6-agent
   swarm); four required kali fields with case-sensitive enums; finding-schema fields required at *record* time
   (losing just-confirmed/theoretical findings); and **silent scope drops** (a `/24` CIDR or a single-label host
   like `intranet` is discarded with no warning — lost coverage = missed bugs).

A hard gate built on soft, self-attested signals does not improve depth; under pressure the LLM games it,
`--force`s it, or mass-defers — manufacturing *false confidence*, which is worse than an honest "we didn't get to
it." And several existing hard gates were already actively fighting the LLM rather than helping it hunt.

---

## Decision

**Reframe coverage/depth from a gate into a harness, and unchoke the surrounding system.**

1. **Harness over gate.** The depth machinery (app-unit scorer, expected-vs-covered ledger, probe/coverage
   instrumentation) becomes a **continuous, advisory, EV-ranked "what you likely missed and where to dig next"
   instrument**, reactive to findings (a confirmed bug raises its service's depth priority and triggers the
   sibling sweep). It *steers* the LLM mid-engagement; it does not stop it.
2. **Blocking is terminal-only and deferrable.** Exactly one hard block remains — at `report`/`complete`: the
   engagement cannot silently finish with high-value (deep-required) application units that were never touched
   *and* never explicitly deferred-with-reason. The deferral mechanism is real, bounded, and visible (a
   deferral-rate metric), so the "option D" write-off becomes a recorded decision instead of a silent one.
3. **Never gate on self-attested or free-text signal.** Gate only on durable, non-self-attested state (a
   *completed* dispatch with structured `vuln_classes`/scope; a finding with evidence; a probe tied to a real
   `request_variant` with a non-self-attested `result_status`).
4. **No silent drops.** Scope filters, classifiers, and schema validators must WARN with the dropped item rather
   than discard it.
5. **Scope rigor by engagement complexity**, not uniformly; cut bureaucracy, keep documented load-bearing rigor
   (no-backgrounding, the sibling/variant pass itself, backend-first recording, the handoff closing sequence).
6. **One canonical, additive, drift-tested vuln-class taxonomy** declared in skill frontmatter, replacing the four
   disjoint ones and the hardcoded map; reconciled with the kali `TECHNIQUE_ENUM`.
7. **Identity becomes first-class** (named user_a/user_b/admin) so access-control depth is real, in a later wave.

### Owner constraints baked into the decision
- No backwards compatibility **except the database** (additive migrations only); renames are total, no aliases.
- No change is too large; consolidate/simplify aggressively; delete anything left unused.
- Robustness over speed; token/time budget is not a constraint.
- Real-attacker framing — OWASP/NIST are attack-surface-enumeration anchors, not the gate's purpose.
- Execute with multiple parallel agents per wave + a QA agent re-reviewing every changed file.
- Tone: stop CAPS-for-critical and casual "reddit" severity language in operator output.
- Cadence: assert a 4–6 concurrent-specialist floor on Heavy tier; periodic core re-read.
- Model currency: prompt model IDs are stale (`claude-opus-4-7`/`gpt-5.5`) vs current (`claude-opus-4-8`,
  Codex 5.6) — refresh as part of the prompt wave (cosmetic, no methodology change).

---

## Consequences

**Positive**
- The system helps the LLM find more bugs (tracking + EV-ranked attention + findings-reactive depth) instead of
  fighting it; the swarm can actually run 4–6 wide; recording a real finding mid-hunt always works; no whole
  subnets vanish silently.
- The one retained block is honest (durable signal) and survivable (real deferral), so it prevents the silent
  "complete" without inducing gaming.
- One vuln vocabulary closes the 68% blind spot and makes coverage queries meaningful.

**Negative / risks**
- The app-unit scorer needs calibration against real engagement data before its *detection* can be trusted to
  hard-block anything; it ships warn-first. (Vuln-class applicability predicates can be trusted from day one.)
- Backend reproducibility requires bridging work-item facts into backend state; hosts touched only by direct
  tools must be made to populate `request_variants` or the scorer is blind to them.
- Large surface area: the rename/consolidation and the choke fixes touch ~60+ files across web/code/blue tracks;
  wave sequencing and per-wave QA are required to keep the tree green and avoid breaking the code/blue tracks.

**Neutral**
- Establishes `docs/adr/` and the multi-agent-with-QA execution model as the norm for large changes here.

---

## Alternatives considered

1. **Strict depth gate (the original design).** Rejected: gameable + skippable + blind on the signals available;
   would manufacture false confidence and choke the LLM into gaming/forcing/mass-deferring.
2. **Do nothing / prompt-only nudges.** Rejected: the failure already happened *with* the prompt-level depth
   guidance present (it lives in `hunting.md` and the steering playbook). Prompts alone don't prevent the silent
   long-tail write-off on long, high-volume runs.
3. **Gate on the existing gf-bucket pipeline (the populated one).** Rejected as the *sole* spine: gf-buckets miss
   ~68% of testing capability (no auth/graphql/business-logic/etc.), so it would be blind exactly where the big
   bugs are — hence the canonical-taxonomy unification instead.
4. **Pure host-level depth unit.** Rejected: a host can carry several apps; host-level hides an untested app.
   Chosen unit is `(host, port-class, path-prefix)` "application unit."

---

## References
- `docs/plans/harness-master-plan.md` — the waved implementation plan (entry point) + the full choke register.
- `docs/plans/coverage-depth-gate.md` — detailed scorer rubric, applicability predicates, storage, anti-staleness.
- `docs/engagement-prompt-playbook.md` — the human-side steering library this complements.
- Verified code anchors are cited inline in both plans (confirm against live code before editing).
