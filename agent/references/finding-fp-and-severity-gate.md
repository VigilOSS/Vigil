---
description: "Shared FP + severity-downgrade gate (C1–C7) — the single home for the impact/overclaim/severity-calibration checks used by BOTH live/web verification (vulnerability-analyst, Phase-4) and code-finding verification (code-finding-verification, Phase-3, which establishes bug-existence then defers its severity-calibration half here): data-sensitivity / public-data / boundary-crossing / id-enumerability checks, per-metric CVSS-vector discipline, orphan-write read-back, by-design/documented/precedent check, net-new/redundancy trigger, kill-trigger catalog, severity ladder."
category: Finding Verification Gates
---

# Finding FP & Severity-Downgrade Gate — real-world impact, not CVSS-fitting

> The shared impact/severity-calibration gate, run before a finding is recorded
> `confirmed`/`downgraded` — by `vulnerability-analyst` at live/web Phase-4 verification AND by
> `code-finding-verification` at code Phase-3 (which establishes bug-existence with its five-check
> protocol, then defers the severity-calibration half here). It asks the question a CVSS
> calculator cannot: *would a real attacker actually achieve meaningful harm here, and is the
> data/impact what we claim?* Score what is **proven and meaningful**, not what fits a band.

**Why this exists.** Findings here have been filed High/near-Critical and then downgraded to Medium
by an independent triager — the calculator produced a number, but the proven real-world impact was
lower (a "read" that exposed no PII because no read endpoint existed; a "file attach" that was an
orphan write never proven to land on a real record). This gate catches that before it ships.

**Applicability.** The catalog below is written against data-exposure and write-impact findings, but
the gate is not limited to them: it applies to **any finding that skips the Phase-4 Ideator-vs-Tracer
debate because it is runtime-proven** (`agent/agents/vulnerability-analyst.md`'s debate-skip rule) —
auth-bypass, race-condition, and business-logic findings included. Runtime proof settles the causal
chain, not the overclaim/severity-inflation question this gate exists to answer, so a debate-skipped
finding still owes this pass before `confirmed`/`downgraded`. Apply C1–C4 where data/object access is
in play; apply C5 (per-metric CVSS discipline), C6 (real-object proof, generalized beyond writes to
any claimed state change — an auth-bypass session, a race's won outcome, a business-logic state
transition), and C7 (by-design/documented/precedent) universally, and read the Fast FP triggers as
patterns to match by shape, not by class.

**One gate, split by purpose — not by finding-origin.** The *bug-existence* half is track-specific
(the code five-check protocol in `agent/skills/code-finding-verification/SKILL.md`; the live
two-context/read-back mechanics in C1–C4 here); the *impact/overclaim* half — C5–C7 plus the
`hunting.md §3` net-new test — is identical whatever the finding's origin, so it lives here once and
both tracks run it. This is why a real, fully-reproduced source injection can still be correctly
closed as no-impact: the five-check protocol answers "is it real?", never "is it net-new?"

This file is the codified home of the recurring FP/overclaim catalog — when a new overclaim pattern
recurs across engagements, land it here (as a kill/downgrade trigger below or a per-metric C-check),
so the verifier and the pre-submission blind gate share one bar. The late, zero-context counterpart
that re-applies these same patterns just before submission is `agent/skills/blind-triage/SKILL.md`.

Each check yields **PASS** (cite evidence at the bar a KILL would), **DOWNGRADE** (lower the
metric/severity, with the reason), **KILL** (false positive — don't record), or **GAP** (cannot
resolve → blocks; do not default to PASS). It maps onto the verifier's existing
`PASS / KILL / DOWNGRADE / UPGRADE` decision framework. C5, C6, and C7 are the net-new core; the rest
cross-references the always-loaded rules rather than restating them.

## The checks

- **C1 — Is the exposed data actually sensitive?** Enumerate the *exact* fields returned/retrievable
  and map each to a sensitivity class. DOWNGRADE/KILL if the "data" is only an opaque internal id, a
  value the attacker supplied, a status/date, or already-public content. (Extends `hunting.md §2`
  existence-vs-exploitation + the verifier's Q7.)
- **C2 — Is the data actually supposed to be private?** Cite the public source if the same data is
  intentionally published; if you cannot produce a public URL, treat it as private. Applies to all
  data-exposure classes. (See `reporting.md §4` + the verifier's Q6.)
- **C3 — Is this really a broken-access-control boundary crossing?** Prove a session/identity that
  does *not* own the object reaches it (two-context demonstration), not just "the id changed"; a
  legitimately public endpoint is not an IDOR. **Anonymous-by-design flows** (public intake, signup,
  password-reset *request*, public search) — the anonymity is the intended UX, so the finding must
  rest on a boundary crossing (acting on an object you don't own, or an unintended capability),
  never on "it's callable without login." (See `reporting.md §5` + the verifier's Q3.)
- **C4 — How are the object IDs obtained? (enumerable vs. insider)** Record the assessment in the
  finding's `evidence`/`impact`: truly enumerable (sequential/dense/low-entropy) raises real-world
  reach; obtainable only with privileged/insider access, a prior leak, or OOB knowledge downgrades
  it. A "High IDOR" whose ids are only knowable to an admin is not a High. (See `reporting.md §3`
  Precondition analysis + `hunting.md §3`; id structure/prediction lives in
  `agent/references/access-control/idor-identifier-prediction.md`.)
- **C5 — Does the CVSS reflect real-world attacker impact (not inflated)?** *(net-new — extends the
  band-level severity-CVSS alignment audit (`agent/operator-core.md` "Mandatory Phase-Exit Passes") to a per-metric one.)* Recompute the vector and confirm it
  equals the stated score (a vector that does not compute to its score is an automatic blocker).
  Justify each base metric against the proof:
  - `S:C` only if the vulnerable component's authority differs from the impacted component's
    (writing via an app's own endpoint into its own store is `S:U`).
  - `I:H` only for proven corruption of a real, meaningful record — a 200-but-rejected write, an
    append to one non-critical free-text field, or an orphan write (C6) is **not** `I:H`.
  - `C:H` only for proven read of real sensitive data (see C1).
  - `C:L`/`C:H` require data that actually **crosses a trust boundary** — a value the attacker
    supplied, an opaque surrogate that resolves to nothing, or an existence/oracle-only signal is **no
    confidentiality impact** (C1, C3). "I could see the id changed" is not data crossing the boundary.
  - `PR:N` / `UI:N` / `AC:L` must match the actual attacker steps.
  - **Gut-check:** *"In one sentence, what does a real attacker walk away with?"* If the sentence is
    weaker than the score, the score is wrong.
- **C6 — Is the impact on a REAL object proven, or just an orphan / unvalidated write?** *(net-new.)*
  A write/read that returns `success` for nonexistent/garbage ids (`99999999`, `-1`, `abcdefgh`) is
  not validating the target — you proved you can create an unlinked/orphan artifact, not that you
  affected a victim's object. Require a **read-back or observable side effect on a real object** (the
  victim's data visibly changes, the file appears on the real record, the value becomes
  retrievable). No read-back **and** success-for-nonexistent-ids ⇒ real-object impact is unproven ⇒
  `I` is not `H`; the finding may be only storage pollution / informational.
- **C7 — Is this by-design / documented / precedented, or a genuine boundary break?**
  *(net-new — first-class gate item; run before scoring, not after.)* Answer explicitly:
  - **Is this documented or intended behavior?** Check the vendor's own docs and any published
    security/trust-boundary statement (a repo's `SECURITY.md`, a platform's trust-and-safety page)
    for the feature the finding touches. If the docs describe the exact behavior observed, the
    finding must show a boundary the docs mark as protected being crossed — not merely "the docs
    describe capability X and X sounds dangerous." The canonical documented-OOS form is "expected
    execution of the app's own build scripts" / the tool processing an artifact the attacker wholly
    controls — when that applies, also run the net-new test (`hunting.md §3`; the "Redundant with the
    attacker's own controlled input" trigger below).
  - **Is the affected resource meant to be public?** Broader than C2's data-exposure framing — also
    covers reachable-but-intentionally-open endpoints, features, or capabilities.
  - **What do the vendor docs actually say?** Cite the exact page/section/line. A finding argued
    from assumption about how a feature "probably" works is weaker than one anchored to the
    documented contract — go read the docs before scoring, don't infer the boundary from the
    behavior alone. (Worked example of doing this systematically: have osint-analyst or the
    vulnerability-analyst build a per-capability "docs SHOULD / documented BOUNDARY" map before
    scoring a cluster of related findings, citing doc URLs/lines against each — this is more
    reliable than re-deriving the boundary ad hoc per finding.)
  - **Are there real-world precedents, and how were they rated?** Check CVE / HackerOne / Bugcrowd
    disclosure history for the same vendor, product, or pattern. A precedent rated Medium is a real
    prior against filing the same primitive as Critical without a materially different proof —
    calibrate from actual comparables, not the best-imaginable attacker outcome.
  - DOWNGRADE/KILL if the observed behavior matches documented intent and the finding cannot show a
    documented boundary being crossed. PASS — citing the doc URL/line, and where a boundary-break
    claim is made, the exact clause marking it out-of-bounds — when the finding demonstrates
    crossing a boundary the vendor's own docs protect. This both **preempts the N/A ("working as
    intended") disposition** before it costs a submission, and **calibrates severity from real
    comparables** instead of the best-imaginable case.

## Fast FP / kill-severity triggers (run alongside C1–C7)

Data-exposure-specific:
- **Anonymous/public by design** — anonymity isn't the bug (C3). **[KILL]**
- **Documented capability, no boundary crossed** — vendor docs describe the exact behavior observed
  and the finding does not show a documented boundary being crossed (C7). **[KILL/DOWN]**
- **Self-only / your-own-data in another shape** — same account, or you swapped to your own id (no
  victim), or your own data via a different route. **[KILL]**
- **Opaque surrogate with no power** — a leaked id/UUID that resolves to nothing and is usable
  nowhere (C1). **[KILL/DOWN]**
- **Existence/oracle-only vs. content read** — "I can tell record N exists" ≠ "I can read N." **[DOWN]**
- **Orphan / unvalidated write** — succeeds for nonexistent ids, no read-back (C6). **[KILL/DOWN]**
- **Insider-only ids** — ids knowable only with privileged/OOB access → not "any user" (C4). **[DOWN]**
- **Single-target dressed as "any/all"** — the mass framing needs enumeration that's actually gated. **[DOWN]**
- **Compensating control already blocks it** — "no CSRF token" but SameSite/custom-header blocks
  CSRF; "no rate limit" but the action is harmless. **[KILL]**

Overclaim / mis-framing (the recurring patterns an independent triager downgrades):
- **Self-induced precondition** — the attacker **manufactured the trigger** (disabled a protection
  they control, supplied their own id/input, set the required state) then presents it as a
  naturally-occurring weakness. Score on the **incremental impact over the precondition**, not on the
  state the attacker created (`hunting.md §3`, `reporting.md §3`). **[KILL/DOWN]**
- **Redundant with the attacker's own controlled input** — the attacker already controls the whole
  artifact the tool ingests (repo/PR/template/archive/build), and the flaw only reproduces what
  writing the payload into their own source/config already achieves by design — zero net-new
  capability over "the victim builds the attacker's project" (`hunting.md §3`). The injection can be
  fully real and still land here. **[KILL/DOWN]**
- **Info-disclosure / stack-trace framed as Medium** — missing headers, stack traces, schema /
  version / path leakage are **informational** unless they **directly enable a proven higher-impact
  attack**; "it helps an attacker" is speculative chaining. Authoritative treatment lives in
  `reporting.md §3` (the "informational unless it directly enables a proven higher-impact attack"
  rule) — apply it as a downgrade trigger here, do not restate the rule.
  **[DOWN → informational]**
- **OOS class in disguise** — a rate-limiting / DoS / third-party issue **re-skinned** as
  access-control (or another in-scope class) to smuggle it past scope. Classify by the **actual
  primitive**, not the label chosen (Q3 OOS, `reporting.md` DoS-severity). **[KILL/DOWN]**
- **"Useful for mapping internals" hand-wave** — "this would help an attacker map the system" with
  **no proven exploit consequence** is not impact (internal IPs / debug leakage with no downstream
  use; Chain-Only). **[KILL/DOWN]**

Generic FP triggers — do **not** re-own these; they already live as the verifier's **Chain-Only
List** + **Fast Kill Signals** in `agent/agents/vulnerability-analyst.md` and `hunting.md §4`
(self-XSS, open-redirect alone, CORS-without-exfil, missing-headers alone, theoretical/no-PoC,
not-reproducible, stacked preconditions, third-party/out-of-scope, 200-but-rejected/soft-fail).

> **No-PoC guard:** "theoretical/no-PoC" means kill when the primitive is *disproven*, not when a
> runtime PoC merely wasn't built. A structurally sound finding that only lacks runtime
> demonstration is parked at `evidence_type=theoretical` + `chain_required=true` (`hunting.md §2`),
> not killed.

## Disposition & severity ladder

- Any **KILL** → don't record (or record as intel/null with the counter-evidence).
- Any **DOWNGRADE** → apply it (lower the metric/severity) and make the finding's `details` match.
- Any unresolved **GAP** → block; resolve with evidence first.
- All **PASS** (each citing evidence) → cleared at the stated severity.

Severity ladder (real-world outcome): proven cross-user **read of real sensitive data** > proven
cross-user **write/corruption of a meaningful record** > **append to a non-critical field /
existence-status oracle** > **orphan write / storage pollution** > self-only / public-data. Reads do
not auto-cap severity, but **unproven** real-object impact is never `I:H`/`C:H`.

**Precondition anchor (sanity-check the band before trusting the CVSS number):**
- 0 preconditions + unauthenticated + network-reachable → Critical / High
- 1–2 preconditions, or requires an authenticated session → Medium
- 3+ stacked preconditions, or local-only access → Low

Count "anonymous network access" as zero preconditions. Use this to catch a vector that computes to
the wrong band — CVSS confirms the score, it does not derive it. (Aligns with `hunting.md §3`
precondition-equivalence: when incremental impact would still reach Medium/High, the precondition
count is a ceiling.)

## Author the result into the finding

This gate's conclusions are not scratch notes — the verifier writes them into the finding's durable
`details` so the report-writer only formats: the corrected `cvss_vector`/`cvss_score`, the
`evidence` (the exact fields + the two-context / read-back proof), the `impact` (the one-sentence
attacker outcome from C5's gut-check), the `remediation`, and — when C7 was material to the
disposition — the exact vendor doc URL/line cited and, if found, the precedent disclosure it was
compared against. See the "Four Validation Gates" (Gate 3) in `agent/agents/vulnerability-analyst.md`.

## Related

- `agent/rules/hunting.md` — §2 (existence-vs-exploitation), §3 (precondition equivalence)
- `agent/operator-core.md` — "Mandatory Phase-Exit Passes" (severity-CVSS alignment audit)
- `agent/rules/reporting.md` — §2 (proof), §3 (severity follows impact + precondition analysis; also the home of the info-disclosure / stack-trace "informational unless it enables a proven higher-impact attack" rule), §4 (non-public data), §5 (distinct identities)
- `agent/skills/osint-recon/SKILL.md` — the CVE/disclosure-history research C7's precedent question
  draws on; also the role best placed to build a per-capability vendor-docs boundary map (docs SHOULD
  vs. documented BOUNDARY, cited by URL/line) ahead of scoring a cluster of related findings
- `agent/skills/blind-triage/SKILL.md` — the zero-context pre-submission blind gate that re-applies the same overclaim catalog on the submission bytes before publish (this gate is the in-context Phase-4 version)
- `agent/agents/vulnerability-analyst.md` — the 8-Question Gate, Chain-Only List, Fast Kill Signals, Four Validation Gates
- `agent/skills/code-finding-verification/SKILL.md` — the code-side bug-EXISTENCE protocol (five-check: reachability, guards, build-config, feasibility, devil's advocate); it establishes that a source finding is real, then defers the severity-calibration half (C5/C7 + the `hunting.md §3` net-new test) to this gate
- `agent/references/api-security/API01-broken-object-level-authz.md` — CWE taxonomy + BOLA/BOPLA/BFLA
- `agent/references/access-control/idor-identifier-prediction.md` — id enumerability / prediction (C4)
