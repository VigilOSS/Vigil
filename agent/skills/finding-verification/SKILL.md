---
name: finding-verification
description: Adversarial Phase-5 verification of runtime/web findings produced by other agents — reproduce the PoC, ground severity in the trust boundary, run the C1-C7 FP & severity gate, and author the report-ready story. Loaded by vulnerability-analyst in review mode. The web analog of code-finding-verification.
origin: Vigil
---

# Finding Verification — adversarial Phase-5 review

Before a terminal verdict, finish reproduction/evidence documentation on the same finding.
Use `finding update --agent-id <your-dispatch-id>` for attributed edits and consult its contract
for same-verifier enrichment; claim changes require fresh review and a consumed receipt cannot
support another verdict. The shared specialist core owns approval and receipt discipline.

## When to Activate

Load this skill when `vulnerability-analyst` is dispatched in **review mode** (Phase 5,
`mode=deep-manual` or `mode=root_cause_review`) to verify findings produced by other agents
**before** exploitation investment. Catching a false positive, a severity inflation, or weak
evidence here is far cheaper than discovering it after an exploit-developer pass.

This is the **runtime/web** analog of `code-finding-verification/SKILL.md` (which owns
source-only findings via its five-check protocol). Use that one for `file:<path>:<line>`
findings; use this one for findings with a live HTTP/runtime PoC.

## Scope your mandate (do not inflate)

You are the adversary of the evidence, not of the finding count. Challenge only what
affects a finding's **disposition, severity, or reachability**. Do not manufacture new
findings, re-litigate settled scope, or downgrade on stylistic grounds — a reviewer
prompted to "find gaps" will invent them. Every disposition you write must cite specific
counter-evidence or a reproduced result.

## Division of Labor

- **Operator** selects the review scope — all HIGH/CRITICAL plus MEDIUMs with escalation
  potential get **Tier 1** (full reproduction); every remaining ordinary MEDIUM/LOW gets
  **Tier 2** (spot-check) — and passes the trust-boundary / threat-model summary, the finding
  slugs + payloads, and the matching vuln-class skill. See operator-core Phase 5.
- **You (vulnerability-analyst, review mode)** re-test Tier-1 findings against the live target
  via `vigil assess kali ...` — you reproduce, you do not merely read the evidence text — then
  write a disposition per finding and author the report-ready story for the ones that survive.
  For Tier-2 findings you run the cheaper audit below instead of silently leaving them
  unreviewed.

## Review scope is two-tier, not all-or-nothing

Every finding in scope gets *some* adversarial pass — full reproduction is reserved for the
findings where it earns its cost, not because everything below HIGH/CRITICAL is exempt from
review:

- **Tier 1 — full reproduction.** All HIGH/CRITICAL, plus any MEDIUM with escalation potential
  (chainable into a higher-severity outcome, or a disposition call close enough to the
  high/medium boundary that a wrong verdict matters). Run the full Methodology below.
- **Tier 2 — cheap spot-check.** Every ordinary MEDIUM/LOW that isn't Tier 1. Do not skip these
  in silence. Run the severity↔CVSS band audit (`agent/operator-core.md` "Mandatory Phase-Exit Passes" — `severity` vs.
  `details.cvss_score` band mismatch) plus a quick evidence-presence sanity check: is there a
  captured request/response or command output backing the claim, or is `evidence_type` marked
  `theoretical` without a `chain_required` rationale? This is a few-minute audit, not a re-run of
  the PoC. A Tier-2 finding that fails either check — band mismatch, missing evidence, or a smell
  of a stacked self-induced precondition — gets promoted to Tier 1 and run through the full
  Methodology.

This tiering is a cost control, not a license to wave Mediums/Lows through: you are still the
adversary of the evidence, not of the finding count. Tier 2 exists so "cheap" doesn't collapse
into "unreviewed" — every finding still gets a recorded check.

## Canonical gates — load, do not restate

This skill operationalizes gates that live elsewhere; read them rather than re-deriving:

- **8-Question Gate, Report-ready story gate, Chain-Only List, Fast Kill Signals** —
  `agent/agents/vulnerability-analyst.md`. These are your reviewer toolkit; they are part of
  your role prompt already.
- **C1–C7 FP & severity-downgrade gate** — `agent/references/finding-fp-and-severity-gate.md`.
  Run every confirmed debate-skipped runtime-proven finding through it (data-exposure, write, auth-bypass, race, business-logic): it catches the real-world-impact
  gaps a CVSS-band check misses (no-PII "reads", orphan writes, insider-only enumerability,
  inflated `S:C`/`I:H`).
- **Severity ↔ CVSS bands** — `agent/shared-specialist-core.md` "Finding IDs and the `finding record` Contract" (the canonical band table).

## Methodology

For each finding under review:

1. **Reproduce the PoC against the live target.** Re-run the claimed request via
   `vigil assess kali ...` with an explicit `--timeout`. A finding you cannot reproduce is a
   kill candidate (note transient vs. genuinely-unreproducible). A non-conclusive response
   (validation error short of a real auth decision, a status code with no body captured, an
   `http=000`/connection-failed runtime error) is a **lead, not a verdict** — push it before
   closing (`agent/rules/hunting.md` §23).
2. **Ground severity in the trust boundary.** Using the operator's threat-model summary, decide:
   is the entry point unauthenticated or privileged? Is the input attacker-controlled or
   operator-trusted (config, internal caller)? Reachability and auth-path severity calls depend
   on this grounding — without it the triager is overconfident.
3. **Prove the attacker OUTCOME, not the vulnerability's existence.** Captured credentials must
   be replayed; leaked tokens must be used; a file-read primitive must read a meaningful file.
   "Vulnerability exists" is not a finding — "attacker extracts session token and accesses the
   victim's vault" is. If the proof requires the triager to imagine the next step, send it back.
   **Carve-out — a proven primitive with unfinished exfiltration is HELD, not killed.** Distinguish
   "imagine the next step from no evidence" (kill) from "a reproduced primitive whose extraction is
   merely incomplete" (hold). A boolean / time-based / OOB SQLi differential that reproduces from a
   second independent payload — but whose byte-by-byte data extraction is unfinished (rate-limited,
   slow, partial) — is a real injection primitive: route it to the theoretical holding area
   (`evidence_type=theoretical` + `details.chain_required=true`, verify `pending_runtime_proof`
   with the extraction as its `--next-test-file` plan), NOT a kill. It stays out of the report and
   BLOCKS report-readiness until an exploit-developer runtime pass completes the extraction and
   re-verifies it `confirmed`/`downgraded`. This is the disposition that keeps blind injections — the class most
   dependent on slow extraction — from being silently dropped at the gate.
4. **Run the C1–C7 FP & severity gate** (above) on any debate-skipped runtime-proven finding.
5. **Recompute the CVSS vector** from the reproduced impact; correct `cvss_vector` / `cvss_score`
   if the band drifted.

## Dispositions

Write exactly one per reviewed finding (these are the operator-facing verbs, kept in
operator-core Phase 5 — listed here so the reviewer self-serves them):

- **Confirmed** — reproduced, severity accurate → `vigil assess finding verify <slug> --status confirmed --reason "..." --proof-receipt-id <id> --confirm-check-file <confirm-check.json>`
- **Upgraded** — real, severity understated → `vigil assess finding update <slug> --severity <higher> --reason "..."` then `finding verify ... --status confirmed --proof-receipt-id <id> --confirm-check-file <confirm-check.json>`
- **Downgraded** — real, severity overstated → `vigil assess finding verify <slug> --status downgraded --reason "..." --new-severity <lower> --proof-receipt-id <id> --confirm-check-file <confirm-check.json>`
- **Killed** — a completed counter-check falsifies the claim → `vigil assess finding verify <slug> --status false_positive --reason "..." --counter-check-file <counter-check.json>`
- **Runtime proof owed** — evidence holds but the decisive test belongs to another route or assignment (a local build or harness, or a target this review does not hold) → `vigil assess finding verify <slug> --status pending_runtime_proof --reason "..." --next-test-file <next-test.json>`. The next test is the operator's preparation plan: hypothesis, confirming observation, falsifying observation, and a `local`/`live`/`unknown` route hint. Missing access is `blocked` and a rules-of-engagement wall is `details.roe_blocked` instead (`agent/rules/hunting.md`).

For confirmed/downgraded, the completed `confirm_check` records the attempted
falsification and observed result against the decision's proof receipts; read
`vigil assess contract finding verify` for its fields.

**Dedup:** merge findings with overlapping `canonical_location` + similar `defect_family` across
agent prefixes — `vigil assess finding merge <source-slug> <target-slug> "<reason>"`.

**Chain-only primitives** stay in the normal finding table: when a finding is real only as part
of a proved/expected escalation path, `vigil assess finding update <slug>` to populate
`details.chain_required`, `details.chain_rationale`, `details.required_followup`. Do not invent a
chain-specific status.

## Author the report-ready story (Report-ready story gate)

For every Confirmed/Downgraded finding, write the report-ready `evidence` / `impact` /
`remediation` and the justified CVSS vector into `details`. The report-writer **formats** this
story; it does not re-derive it. A finding disposed but not authored is half-done.

## Output Contract

Per finding: the disposition + verb run, the reproduced evidence (or the kill counter-evidence),
the corrected severity/CVSS if changed, and — for survivors — confirmation the report-ready story
was authored into `details`. End with the review-scope summary: HIGH/CRITICAL all dispositioned
(Tier 1); which MEDIUMs were reviewed at Tier 1 and why; which ordinary MEDIUM/LOW findings
received the Tier-2 spot-check and whether any were promoted to Tier 1 on a band mismatch or
missing evidence; and the disposition counts. If most kills failed on the same check, name that
pattern — a systematic failure mode says the Phase-4 dispatch context is producing a predictable
class of speculative finding, which the operator can fix upstream.

## Root-Cause Review Mode (Phase 5 → 6 exit)

When dispatched as `mode=root_cause_review`, additionally run the operator's root-cause grouping
intent: group intentional root/sibling relationships (`vigil assess finding link`), picking the
root as the broadest attacker-controllable cause. See "Root-Cause Review Mode" in
`agent/agents/vulnerability-analyst.md`.

## Extended Resources

- `agent/agents/vulnerability-analyst.md` — 8-Question Gate, Report-ready story gate, Chain-Only List
- `agent/skills/blind-triage/SKILL.md` — the zero-context pre-submission gate that re-applies the overclaim catalog on the submission bytes (this skill is the in-context Phase-5 version)
- `agent/skills/code-finding-verification/SKILL.md` — the source-only analog (five-check protocol)
