---
description: "Reply voice + budgets for export reply/record-reply — answering a program/company on an already-submitted finding. Not a mini-submission."
skill: report-generation
category: Disclosure & Reporting Formats
---

# Reply Format

Use this when the operator replies to a program or company on an already-submitted finding — a
Bugcrowd comment, a HackerOne activity reply, or a direct vendor follow-up — via `vigil assess
export reply` / `record-reply`. It is typically triggered by `submission_status=needs_info`, and also
used to push new proof to any open submission. "Closing verbs (reply mode)" in
`agent/agents/report-writer.md` owns the CLI flow.

## A reply is not a mini-submission

A reply answers the specific ask with the new proof and stops. The submission structure (`Title:` /
`VRT:` / `CVSS` / Summary / Steps / Evidence / Impact / Remediation) does not apply: the platform
already carries all of it, and restating any of it signals a reply generated from the template rather
than written to the ask.

## Budgets

Ceilings, as in `submission-format.md` "Section budgets": cut to fit rather than wrap.

| Element | Budget |
|---|---|
| Salutation | ≤1 line, optional |
| Reply body | ≤6 sentences / ≤2 short paragraphs |
| New evidence | ≤15 lines of content per fenced block, `<-- proof`-annotated with exact values (submission-format.md "Evidence fidelity") |
| Attachment pointer | the `**Run:**` / `**Pass if:**` block (submission-format.md "PoC block"), only when the new evidence needs one |

## Platform note

| Platform | Where the reply lands |
|---|---|
| Bugcrowd | Comment on the submission thread |
| HackerOne | Activity reply |
| Direct | Reply email in the tone of `agent/references/disclosure-email-format.md`, but only the reply body: no Subject/AFFECTED CODE/ROOT CAUSE/CVSS scaffold |

## Pre-send checklist

The reply subset of `submission-format.md`'s pre-submission checklist. Run before every send:

- [ ] Sentence one is the new proof or the answer to the one ask, not an echo of the ask or the title
- [ ] When `details.replies` already has entries, the reply says what changed since the last one, so the thread reads as a continuation
- [ ] No Summary/Impact/CVSS/VRT restatement and no selling ("please prioritize", urgency framing); the triager sets priority from the proof (reporting.md Rule 15)
- [ ] No internal identifiers — finding slug, engagement path, `vigil assess` breadcrumbs, `cases.db` references (submission-format.md "No internal identifiers")
- [ ] New evidence, if any: every captured value verbatim, PII included, each fenced block truncated to the ≤15 lines that prove the point (submission-format.md "Evidence fidelity")
- [ ] No probe counts, telemetry, or ruled-out-variant narration; a negative control that establishes causality is proof and stays (reporting.md Rule 20)
- [ ] First person and contractions, addressed to the engineer and tied to the actual retest; if a prior reply was flagged as AI-generated, this one is shorter and rougher, never longer or more polished
