---
name: blind-triage
description: Two-pass pre-submission review gate that stops false-positive / overclaimed / over-severity submissions. Pass 1 is the in-context report-writer QA+fix; Pass 2 is a decisive BLIND zero-context triage (read ONLY the submission bytes, like a real Bugcrowd reviewer) that gates publish — anything other than Accept blocks submission. Run on EVERY Medium-or-above.
origin: Vigil
---

# Blind Triage — pre-submission review gate (QA + blind triage)

## When to Activate

Run this gate on **EVERY Medium-or-above finding** before it is submitted or
published. Its purpose is to **stop false-positive, overclaimed, and
over-severity submissions** before they leave the engagement. It is a two-pass
gate: an in-context QA+fix pass, then a decisive **blind** triage pass that
gates the submission.

The two passes are deliberately separate jobs. Pass 1 has full engagement
context and fixes the report; Pass 2 has **zero** context and judges only the
bytes a real external reviewer would see. Do not collapse them into one — the
blind isolation is the whole point of Pass 2, and mixing context back in defeats
it.

## Pass 1 — Report-writer QA+fix (specialist WITH engagement context)

A report-writer specialist, **with** full engagement context, fixes the
submission in place:

- format and structure,
- AI-tells (Rule 20 human-voice check),
- PoC script hygiene (`submission-format.md` § "PoC Script Authoring" — minimal,
  de-harnessed, no decorative banners or agent-env handling),
- CVSS stated exactly once and consistent with the claimed severity,
- repro-step correctness,
- overclaim language ("I" vs "H" — impact-claimed vs impact-proven).

Pass 1 reliably fixes presentation and language. It does **not** reliably catch
whether **impact was actually demonstrated** — that is what Pass 2 exists for.
Pass 1 produces the clean submission bytes that Pass 2 then judges blind.

(Pass 1 is the existing `agent/skills/report-generation/SKILL.md` "Review-and-Fix
QA Mode" / the `agent/references/submission-format.md` pre-submission
checklist — frame that pass as Pass 1 of this gate; it returns QA PASS / QA
BLOCKED. Do not re-implement it here.)

## Pass 2 — BLIND unbiased triage (the decisive gate)

Pass 2 is an agent with **ZERO engagement context** that judges **only the
submitted bytes**, exactly like a real Bugcrowd / VDP reviewer who never saw the
engagement. It is the decisive gate.

**Reviewer setup (all of these are required):**

- **Non-specialist general agent, strongest model.** Not the report-writer, not
  the vulnerability-analyst who found it — a fresh general agent on the strongest
  available model, so it brings an unbiased, adversarial reviewer's eye.
- **Zero engagement context.** The reviewer is given **only**: (a) the program
  brief facts (in-scope assets, the triage bar, the severity-band policy), and
  (b) the submission `.md` itself. Nothing else.
- **Hard isolation.** The reviewer reads **ONLY the submission `.md`**. It must
  **NOT** read any repo file, run any `vigil` / CLI / `curl` command, query
  the work buffer, or pull in any other engagement artifact. If a claim is not proven
  *inside the submission bytes*, it is unproven for triage purposes — that is the
  reviewer judging exactly what an external triager can see.

**The dispatch prompt must, verbatim, give the blind reviewer:**

> You are an independent bug-bounty triager. You have ZERO context on how this
> finding was produced. Read ONLY the submission text below — do not read any
> repository file, do not run any command, do not query any database, do not
> assume anything not proven in these bytes. Here are the program brief facts
> [in-scope assets / triage bar / severity-band policy]. Here is the submission
> [the `.md` bytes]. Judge it as a real reviewer would: is the impact actually
> demonstrated in what you can see, at the severity claimed?

**Required output — the verdict table.** The reviewer must return:

| Field | Value |
|---|---|
| **Verdict** | one of: `Accept@P1` / `Accept@P2` / `Accept@P3` / `Accept@P4` / `Accept@P5` / `Need-More-Info` / `Not-Applicable-Informational` / `Out-of-Scope` / `Duplicate` |
| **Priority vs claimed severity** | the triaged priority next to the severity the submission claimed (and the delta) |
| **Triage reasoning** | why this verdict — what is proven vs. asserted in the bytes |
| **Weak points** | the specific gaps a real reviewer would push back on |

**Record the verdict (durable, enforced).** The verdict is not advisory prose —
persist it so the report/complete transition gate can SEE it. After the reviewer
returns the table, the operator records one decision row per finding:

```bash
vigil assess agent decision --kind blind_triage_verdict --payload-json \
  '{"finding_slug":"<slug>","verdict":"<Accept@P1..P5|Need-More-Info|Not-Applicable|Out-of-Scope|Duplicate>","claimed_severity":"<sev>","weak_points":"..."}'
```

This writes a `kind='blind_triage_verdict'` row to the `assessment_dispatch_decisions`
table. `vigil assess transition-phase report` (and `complete`) reads these rows and
**blocks** with `kind=missing_blind_triage` for any Medium-or-above active finding
that lacks a recorded verdict whose `verdict` starts `Accept` — so an un-recorded
verdict reads identically to no triage at all. The verdict string must start with
`Accept` (e.g. `Accept@P3`) to clear the gate; any other value records the
disposition but does not unblock publish.

**Gating rule (hard block).** If the blind verdict is **anything other than
`Accept` (at any priority)**, **do NOT submit.** Route the finding back to the
report-writer / operator with the reviewer's weak points, fix or kill it, and
re-run the blind pass (recording the new verdict). Only an `Accept` verdict
clears the finding for submission.

## What this gate catches — recurring FP / overclaim patterns

The blind reviewer's bar. These are the recurring patterns that produce
false-positive / overclaimed / over-severity submissions; a submission that rests
on any of them should **not** get an `Accept`:

1. **Self-induced precondition presented as real** — the attacker manufactured
   the trigger condition (disabled a protection they control, supplied their own
   input/id, set the state) and reports it as a naturally occurring weakness.
2. **Inference-based proof using fabricated IDs** — an IDOR/BOLA "proven" against
   made-up ids (`99999999`, `-1`, `abcdefgh`) instead of a **real cross-object
   read or write**. BOLA/IDOR must show a real object owned by someone else being
   read or written, not a `success` response to a garbage id.
3. **`C:L` with no actual data crossing the boundary** — a confidentiality claim
   where nothing sensitive actually crossed a trust boundary (opaque surrogate
   that resolves to nothing, existence/oracle-only signal, attacker-supplied
   value echoed back).
4. **Info-disclosure / stack-trace framed as Medium** — missing headers, stack
   traces, schema/version/path leakage dressed up as a Medium when it is
   informational unless it directly enables a proven higher-impact attack.
5. **Out-of-scope class in disguise** — a rate-limiting / DoS / third-party issue
   re-skinned as access control (or another in-scope class) to smuggle it past
   scope. Classify by the actual primitive, not the chosen label.
6. **"Useful for an attacker mapping internals" hand-wave** — "this would help an
   attacker map the system" with no proven exploit consequence is not impact.
7. **By-design behavior called a vuln** — anonymous/public-by-design flows (public
   intake, self-registration, password-reset *request*, public search) where the anonymity
   is the intended UX, not a bug.
8. **Documented capability with no proven boundary break** — the vendor's own docs
   describe the exact behavior demonstrated, and the submission does not show a
   boundary the docs mark as protected actually being crossed (C7). "The docs say
   this is possible, and it sounds dangerous" is not the same as "the docs say
   this must not happen, and it happened."

## Cross-references

- `agent/references/finding-fp-and-severity-gate.md` — the in-context C1–C7
  FP/severity-downgrade gate the vulnerability-analyst runs at Phase-4
  verification (the same overclaim catalog, applied earlier in the lifecycle and
  *with* context). This blind gate is the late, zero-context safety net before
  submission.
- `agent/skills/report-generation/SKILL.md` "Review-and-Fix QA Mode" — Pass 1 of
  this gate.
- `agent/references/submission-format.md` — the in-context
  pre-submission checklist (Rule 20 AI-tell + "I is not H" overclaim check) that
  Pass 1 applies.
