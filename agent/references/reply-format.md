---
description: "Reply voice + budgets for export reply/record-reply — answering a program/company on an already-submitted finding. Not a mini-submission."
skill: report-generation
category: Disclosure & Reporting Formats
---

# Reply Format

Use this when the operator replies to a program or company on an already-submitted finding — a
Bugcrowd comment, a HackerOne activity reply, or a direct vendor follow-up — via `vigil assess
export reply` / `record-reply`. A reply answers one question with the new proof and stops; it is not
a resubmission.

## When to use

Typically triggered by `submission_status=needs_info` (the triager asked a question), but also used
to push new proof to any already-open submission. See "Reply mode" in `agent/agents/report-writer.md`
for the full CLI flow (`export reply --draft` scaffold → author → `record-reply` write-back →
`export reply --overwrite` re-render → send → `record-reply --sent`).

## A reply is not a mini-submission

`submission-format.md`'s structure (`Title:` / `VRT:` / `CVSS` / `### Summary` / `### Steps to
Reproduce` / `### Evidence` / `### Attack Scenario` / `### Impact` / `### Remediation`) does not apply
here — the finding was already submitted with all of that. A reply answers the specific ask and shows
what changed since the last message. Restating any of the submission structure signals the reply was
generated from the submission template rather than written to the ask.

## Budgets (hard ceilings)

A section that exceeds its budget needs to be cut, not wrapped — same rule as
`submission-format.md` "Section budgets".

| Element | Budget |
|---|---|
| Salutation | ≤1 line, optional |
| Reply body | ≤6 sentences / ≤2 short paragraphs |
| New evidence | ≤15 lines of content per fenced block, `<-- proof`-annotated with exact values (submission-format.md "Evidence fidelity") |
| Attachment pointer | the `**Run:**` / `**Pass if:**` block (submission-format.md "PoC block"), only when the new evidence needs one |

## Do

- Lead with what changed — the new proof, or the answer — in sentence one.
- Address the engineer directly: first person, contractions, connected to the actual retest.
- Reference what changed since the last reply when `details.replies` already has entries, so the
  thread reads as a continuation, not a cold restart.
- Answer the one ask before adding anything else.

## Don't

- Re-litigate the finding — no Summary/Impact/CVSS/VRT restatement (reporting.md Rule 15: every
  sentence must be load-bearing, and the platform already carries that text).
- Sell it — no "please prioritize", no urgency framing (reporting.md Rule 20).
- Surface probe counts, telemetry, or ruled-out variants (reporting.md Rule 20).
- Leak internal IDs or agent-tells. Preserve PII and other evidence values verbatim; the formatting
  gate concerns Vigil's internal bookkeeping, not operator-owned data (submission-format.md
  "No internal identifiers", "Evidence fidelity").
- Echo the ask verbatim or restate the title — the triager already has both open.

If a reply gets flagged as AI-generated, the correction is shorter and rougher, never longer or more
polished (reporting.md Rule 20) — that applies doubly here since a reply is already the shortest
surface in the format set.

## Platform note

| Platform | Where the reply lands |
|---|---|
| Bugcrowd | Comment on the submission thread |
| HackerOne | Activity reply |
| Direct | Reply email — borrow tone from `agent/references/disclosure-email-format.md`, but this is a reply, not a fresh disclosure: no Subject/AFFECTED CODE/ROOT CAUSE/CVSS scaffold, just the reply body |

## Pre-send checklist

The reply subset of `submission-format.md`'s pre-submission checklist. Run before every send:

- [ ] Body ≤6 sentences, leads with the new proof or the answer, not a restatement of the ask
- [ ] No Summary/Impact/CVSS/VRT restatement anywhere in the body
- [ ] No internal identifiers — finding slug, engagement path, `vigil assess` breadcrumbs, `cases.db` references (submission-format.md "No internal identifiers")
- [ ] New evidence, if any: every captured value preserved verbatim, each fenced block truncated to the ≤15 lines that prove the point (submission-format.md "Evidence fidelity")
- [ ] No probe counts, telemetry, or ruled-out-variant narration (reporting.md Rule 20)
- [ ] Contractions present, first person, not uniformly formal (reporting.md Rule 20)
- [ ] If the prior reply was flagged AI-generated, this one is shorter and rougher, not longer
