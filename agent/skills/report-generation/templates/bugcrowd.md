---
description: "Bugcrowd submission scaffold: VRT category, CVSS vector, PoC, remediation"
skill: report-generation
category: Disclosure & Reporting Formats
---

# Bugcrowd Submission Template

Bugcrowd-specific scaffold for `vigil assess export submission <slug> --platform bugcrowd`.
Every shared rule — voice, section budgets, PII redaction, PoC authoring, de-harnessing, the
pre-submission checklist, and the finding-is-source-of-truth flow (author each section, write it
back to the finding, re-render) — lives in `agent/references/submission-format.md`. This
file only adds what's Bugcrowd-specific: the VRT field, and how Bugcrowd's own P1-P4 scale sits next
to the CVSS vector.

## Strict-gate fields

`export submission bugcrowd` (final, non-`--draft`) refuses to write unless every row below is
populated. `--draft` writes the same scaffold with `[NEEDS: ...]` markers for whatever is missing —
that's the normal report-writer entrypoint.

| Field | Populated from |
|---|---|
| Title | finding `title` |
| Severity + CVSS vector | finding `severity`, `details.cvss_vector` |
| VRT category | `--vrt-category` flag, else `details.vrt_category` |
| Attacker-impact statement | finding `impact` or `details.impact` |
| Durable proof | Per `vigil assess contract export submission`; inline PoC is supporting content |
| Remediation | finding `remediation` |

## Scaffold

```
**Title:** [Bug Class] in [exact component] allows [attacker role] to [impact]

**VRT:** [Bugcrowd VRT category path, most specific leaf — e.g. Broken Access Control > IDOR]

**Severity:** [P1-P4] ([Critical/High/Medium/Low])

**CVSS:** CVSS:3.1/[vector] ([score])

---

### Summary
[2-4 sentences. Attacker outcome first, then the fault, then what the PoC proves.]

### Steps to Reproduce
[Numbered. One action per step. No narrative between steps.]

### Evidence
[AUTHORED from the OPERATOR DETAILS section's structured proof + linked runs + a targeted
`command-run list` search, third-party PII partial-masked only (self-owned/synthetic data shown
in full — see submission-format.md "PII redaction"), truncated to the proof lines, annotated with
<-- proof markers. Stored back on the finding as `details.evidence`; the raw output stays in `scans/`.]

### Attack Scenario
[2-3 sentences. Realistic adversary class + starting access + action, ending at first compromise —
no scope counts (those go in Impact). Optional: drop it when Steps + Impact already show reachability.]

### Impact
[1-2 sentences. Consequence + blast radius, quantified by shape/count. Don't re-describe the actor or
the steps — this is the severity justification. See "Attack Scenario vs Impact" in submission-format.md.]

### Remediation
[≤3 items, primary fix first, ≤1 defense-in-depth.]
```

## Bugcrowd-specific notes

- **VRT is the platform-taxonomy field for this template.** HackerOne uses a CWE weakness instead
  — see `templates/hackerone.md`. Resolve against the live taxonomy at
  bugcrowd.com/vulnerability-rating-taxonomy and pick the leaf, not the category head. Never leave
  it blank, "TBD", or "N/A" — the strict gate rejects those the same as an empty field. Offline,
  grep `agent/references/reporting/bugcrowd-vrt.tsv` for the leaf, its default P1–P5 priority, and
  suggested CVSS; for the IDOR Iterable-vs-Complex fork, the harvestable-identifier exception, and
  other ambiguous-leaf calls, consult `agent/references/reporting/bugcrowd-vrt.md`.
- **P1-P4 is Bugcrowd's own priority scale, not a CVSS band.** A category's default VRT priority
  can sit above its raw CVSS score — Bugcrowd's technical-severity matrix assigns categories like
  broken access control a default P2 even when the calculated vector lands in the CVSS "Medium"
  range. Report the calculated CVSS honestly; justify a priority above the raw score by naming the
  VRT default, not by inflating the vector.
- **PoC is an operator-side attachment, not a rendered body line.** If the proof is a script, stage
  it as `submissions/<slug>/poc.<ext>` and attach it in the Bugcrowd form — see
  `submission-format.md` "PoC block". `export submission` emits no PoC line into the body; a
  hand-inserted one is wiped on the next `--overwrite`.
- Bugcrowd programs frequently require a deconfliction line (researcher ID / source IP / UTC
  window) for active-testing categories. If the brief asks for one, add it after Remediation — 3
  lines max, see "Section budgets" in the generic format.

## Worked example

`agent/references/examples/submission-bugcrowd-idor-invoice-access.md`
