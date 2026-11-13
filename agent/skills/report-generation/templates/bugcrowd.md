---
description: "Bugcrowd submission scaffold: VRT leaf, CVSS vector, PoC, remediation"
skill: report-generation
category: Disclosure & Reporting Formats
---

# Bugcrowd Submission Template

Scaffold for `vigil assess export submission <slug> --platform bugcrowd`. Every shared rule — layout,
section budgets, evidence fidelity, PoC authoring, the pre-submission checklist, and the
finding-is-source-of-truth flow — lives in `agent/references/submission-format.md`. This file adds
only the VRT field and how Bugcrowd's priority sits next to the CVSS vector.

## Strict-gate fields

`--draft` marks whatever is missing with `[NEEDS: ...]`; the final export refuses to write with any
row empty (`vigil assess contract export submission` owns the gate).

| Field | Populated from |
|---|---|
| Title | finding `title` |
| Severity + CVSS vector | finding `severity`, `details.cvss_vector` |
| VRT category | `--vrt-category` flag, else `details.vrt_category` |
| Attacker-impact statement | finding `impact` or `details.impact` |
| Durable proof | per the export contract; inline PoC is supporting content |
| Remediation | finding `remediation` |

## Scaffold

```
**Title:** [Bug Class] in [exact component] allows [attacker role] to [impact]

**VRT:** [Bugcrowd VRT path, most specific leaf — e.g. Broken Access Control (BAC) > Insecure Direct Object References (IDOR) > ...]

**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]

**CVSS:** [complete base vector in the program's required CVSS version] ([score])

---

### Summary
### Steps to Reproduce
### Evidence
### Attack Scenario   (optional)
### Impact
### Remediation
```

Section content and ceilings: submission-format.md "Structure", "Steps to Reproduce vs Evidence",
"Attack Scenario vs Impact", and "Section budgets".

## Bugcrowd-specific notes

- **Name the VRT leaf, not the category head.** Resolve against the live taxonomy at
  bugcrowd.com/vulnerability-rating-taxonomy, or offline by grepping
  `agent/references/reporting/bugcrowd-vrt.tsv` for the leaf, its default P1–P5 priority, and
  suggested CVSS. `agent/references/reporting/bugcrowd-vrt.md` holds the ambiguous-leaf calls (the
  IDOR Iterable-vs-Complex fork, the harvestable-identifier exception, BFLA). The gate rejects
  "TBD" and "N/A" like an empty field.
- **The priority is Bugcrowd's own scale, not a CVSS band.** A leaf's default priority can sit above
  its raw CVSS score: broken access control defaults to P2 even when the vector computes to Medium.
  Report the calculated CVSS honestly and justify a higher priority by naming the VRT default, never
  by inflating the vector. `Severity:` always renders the plain severity word matched to the CVSS
  band, so a P2 access-control finding at 6.5 reads `**Severity:** MEDIUM`; the P2 lives in
  Bugcrowd's priority field. Nothing follows the taxonomy path on the `VRT:` line, because that line
  is pasted verbatim into the VRT selector.
- **PoC script:** stage it as `submissions/<slug>/poc.<ext>` and attach it in the Bugcrowd form
  (submission-format.md "PoC block"); write `details.run` / `details.pass_if` so the header lines
  survive re-render.
- **Deconfliction:** the rendered `**Deconfliction:**` header carries `scope.json:required_headers`.
  A brief that also asks for researcher ID, source IP, and UTC window gets them in at most three
  lines; the default render has no field for them, so they arrive through an operator-selected
  `--body` (submission-format.md "Recipient-specific outgoing body").

## Worked example

`agent/references/examples/submission-bugcrowd-idor-invoice-access.md`
