---
name: finding-verification
description: Adversarial Phase-5 verification of runtime/web findings produced by other agents — reproduce the PoC, ground severity in the trust boundary, run the C1-C7 FP & severity gate, and author the report-ready story. Loaded by vulnerability-analyst in review mode. The web analog of code-finding-verification.
origin: Vigil
---

# Finding Verification — adversarial Phase-5 review

Receipt, attribution and terminal-verdict rules are in
`agent/references/specialist-proof-and-scan-lifecycle.md` ("Terminal verdicts and receipts").

## When to Activate

Load it when `vulnerability-analyst` is dispatched in review mode (Phase 5, `mode=deep-manual` or
`mode=root_cause_review`) to verify other agents' findings before exploitation is invested in them.
This skill covers findings with a live HTTP/runtime PoC. Source-only `file:<path>:<line>` findings
belong to `agent/skills/code-finding-verification/SKILL.md`.

You are the adversary of the evidence, not of the finding count. Challenge only what affects a
finding's disposition, severity or reachability, and cite specific counter-evidence or a reproduced
result for every disposition. Don't manufacture findings, re-litigate settled scope or downgrade
on style; a reviewer told to find gaps will invent them.

## Review scope is two-tier, not all-or-nothing

The operator picks the review scope (`agent/phases/phase-5-verify.md` step b) and passes the
trust-boundary summary, the slugs and payloads, and the matching vuln-class skill. Every finding in
scope gets a recorded check:

- **Tier 1, full reproduction**, for every HIGH/CRITICAL and any MEDIUM with escalation potential:
  chainable upward, or close enough to the boundary that a wrong verdict matters. Re-test it live
  through `vigil assess kali ...` (reading the evidence text isn't enough) and run the full
  Methodology.
- **Tier 2, spot-check**, for the other in-scope findings. Audit the severity↔CVSS band (`severity`
  vs `details.cvss_score`) and check that evidence is present: a captured request/response or
  command output, and no `evidence_type=theoretical` without a `chain_required` rationale. A band
  mismatch, missing evidence or the smell of a stacked self-induced precondition promotes it to
  Tier 1.

## Canonical gates — load, do not restate

This skill operationalizes gates that live elsewhere; read them rather than re-deriving:

- **8-Question Gate, Report-ready story gate, Chain-Only List, Fast Kill Signals** —
  `agent/agents/vulnerability-analyst.md`. These are your reviewer toolkit; they are part of
  your role prompt already.
- **C1–C7 FP & severity-downgrade gate** — `agent/references/finding-fp-and-severity-gate.md`.
  Run every confirmed debate-skipped runtime-proven finding through it (data-exposure, write, auth-bypass, race, business-logic): it catches the real-world-impact
  gaps a CVSS-band check misses (no-PII "reads", orphan writes, insider-only enumerability,
  inflated `S:C`/`I:H`).
- **Severity ↔ CVSS consistency** — `vigil assess contract finding record` owns the matching vector version, score and severity contract.

## Methodology

For each finding under review:

1. **Reproduce the PoC against the live target.** Re-run the claimed request via
   `vigil assess kali ...` with an explicit `--timeout`. A finding you cannot reproduce is a
   kill candidate (note transient vs. genuinely-unreproducible). A non-conclusive response
   (validation error short of a real auth decision, a status code with no body captured, an
   `http=000`/connection-failed runtime error) is a **lead, not a verdict** — push it before
   closing (`agent/rules/hunting.md` §12).
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

Write exactly one per reviewed finding (the operator-facing verbs from
`agent/phases/phase-5-verify.md` step d, listed here so the reviewer self-serves them):

- **Confirmed** — reproduced, severity accurate → `vigil assess finding verify <slug> --status confirmed --reason "..." --proof-receipt-id <id> --confirm-check-file <confirm-check.json>`
- **Upgraded** — real, severity understated → `vigil assess finding verify <slug> --status confirmed --new-severity <higher> --reason "..." --proof-receipt-id <id> --confirm-check-file <confirm-check.json>`. `--new-severity` applies to any terminal status, so the re-band and the fresh attestation land in one write; `finding update --severity` first would invalidate the verdict being recorded.
- **Downgraded** — real, severity overstated → `vigil assess finding verify <slug> --status downgraded --reason "..." --new-severity <lower> --proof-receipt-id <id> --confirm-check-file <confirm-check.json>`
- **Killed** — a completed counter-check falsifies the claim → `vigil assess finding verify <slug> --status false_positive --reason "..." --counter-check-file <counter-check.json> --details-inline '{"kill_reason": "...", "kill_check": <1-5>}'`. Record the rationale in `details.kill_reason` and, optionally, the Methodology check (1-5) that produced the kill in `details.kill_check`. The vulnerability-analyst 8-Question Gate maps onto those checks: `KILL Q1` → 1 (not reproducible), `KILL Q5` → 2 (needs privilege the attacker lacks), `KILL Q7` → 3 (no attacker outcome), and `KILL Q2`/`Q3`/`Q6`/`Q8` → 4 (the C1–C7 gate and its fast kill triggers); a Q4 duplicate is merged, not killed. Without a kill_reason the backend stores your `--reason`. `false_positive` needs a completed counter-check backed by receipts from completed runs, so an experiment that could not run is `blocked` (`--details-inline '{"block_reason": "..."}'`). A kill that still owes a settling test names it in `details.required_followup`; readiness tracks it as `killed_finding_settling_test_outstanding`. When you cannot meet the counter-check bar at all, `--status disputed` is the cheap withdrawal — only `--reason` is required and it still survives a later sweep, so the claim does not come back as `unreviewed`.
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

With `mode=root_cause_review`, also walk the confirmed set for root/sibling groups, with the root as
the broadest attacker-controllable cause. Propose each `vigil assess finding link` as a handoff
`next_step` for the operator to run (`agent/references/runtime-guides/va-root-cause-review.md`).

## Extended Resources

- `agent/skills/blind-triage/SKILL.md`: the zero-context pre-submission gate that re-applies the
  overclaim catalog to the submission bytes
