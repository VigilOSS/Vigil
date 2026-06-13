---
description: "General FP + severity-downgrade gate (C1–C6) run at Phase-4 verification: data-sensitivity / public-data / boundary-crossing / id-enumerability checks, per-metric CVSS-vector discipline, orphan-write read-back, kill-trigger catalog, severity ladder. The live/web analog of code-finding-verification."
category: Finding Verification Gates
---

# Finding FP & Severity-Downgrade Gate — real-world impact, not CVSS-fitting

> Run during Phase 4 verification (`vulnerability-analyst`), before a finding is recorded
> `confirmed`/`downgraded`. The live/web-finding analog of the code-side
> `agent/skills/code-finding-verification/SKILL.md` five-check protocol. It asks the question a CVSS
> calculator cannot: *would a real attacker actually achieve meaningful harm here, and is the
> data/impact what we claim?* Score what is **proven and meaningful**, not what fits a band.

**Why this exists.** Findings here have been filed High/near-Critical and then downgraded to Medium
by an independent triager — the calculator produced a number, but the proven real-world impact was
lower (a "read" that exposed no PII because no read endpoint existed; a "file attach" that was an
orphan write never proven to land on a real record). This gate catches that before it ships.

This file is the codified home of the recurring FP/overclaim catalog — when a new overclaim pattern
recurs across engagements, land it here (as a kill/downgrade trigger below or a per-metric C-check),
so the verifier and the pre-submission blind gate share one bar. The late, zero-context counterpart
that re-applies these same patterns just before submission is `agent/skills/blind-triage/SKILL.md`.

Each check yields **PASS** (cite evidence at the bar a KILL would), **DOWNGRADE** (lower the
metric/severity, with the reason), **KILL** (false positive — don't record), or **GAP** (cannot
resolve → blocks; do not default to PASS). It maps onto the verifier's existing
`PASS / KILL / DOWNGRADE / UPGRADE` decision framework. C5 and C6 are the net-new core; the rest
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
  band-level `hunting.md §20` audit to a per-metric one.)* Recompute the vector and confirm it
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

## Fast FP / kill-severity triggers (run alongside C1–C6)

Data-exposure-specific:
- **Anonymous/public by design** — anonymity isn't the bug (C3). **[KILL]**
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
- **Info-disclosure / stack-trace framed as Medium** — missing headers, stack traces, schema /
  version / path leakage are **informational** unless they **directly enable a proven higher-impact
  attack**; "it helps an attacker" is speculative chaining. Authoritative treatment lives in
  `reporting.md §61` (Chain-Only) — apply it as a downgrade trigger here, do not restate the rule.
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
attacker outcome from C5's gut-check), and `remediation`. See the "Four Validation Gates" (Gate 3)
in `agent/agents/vulnerability-analyst.md`.

## Related

- `agent/rules/hunting.md` — §2 (existence-vs-exploitation), §3 (precondition equivalence), §20 (severity-CVSS audit)
- `agent/rules/reporting.md` — §2 (proof), §3 (severity follows impact + precondition analysis), §4 (non-public data), §5 (distinct identities), §61 (info-disclosure / stack-trace is informational unless it enables a proven higher-impact attack — the home of that trigger)
- `agent/skills/blind-triage/SKILL.md` — the zero-context pre-submission blind gate that re-applies the same overclaim catalog on the submission bytes before publish (this gate is the in-context Phase-4 version)
- `agent/agents/vulnerability-analyst.md` — the 8-Question Gate, Chain-Only List, Fast Kill Signals, Four Validation Gates
- `agent/skills/code-finding-verification/SKILL.md` — the code-finding analog (five-check protocol); use that for source-only findings
- `agent/references/api-security/API01-broken-object-level-authz.md` — CWE taxonomy + BOLA/BOPLA/BFLA
- `agent/references/access-control/idor-identifier-prediction.md` — id enumerability / prediction (C4)
