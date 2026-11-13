---
description: "HackerOne submission scaffold: CWE weakness, CVSS vector, PoC, remediation"
skill: report-generation
category: Disclosure & Reporting Formats
---

# HackerOne Submission Template

Scaffold for `vigil assess export submission <slug> --platform hackerone`. Every shared rule — layout,
section budgets, evidence fidelity, PoC authoring, the pre-submission checklist, and the
finding-is-source-of-truth flow — lives in `agent/references/submission-format.md`. This file adds
only what HackerOne needs in place of Bugcrowd's VRT: a CWE weakness, and its CVSS-derived severity.

## Strict-gate fields

`--draft` marks whatever is missing with `[NEEDS: ...]`; the final export refuses to write with any
row empty (`vigil assess contract export submission` owns the gate).

| Field | Populated from |
|---|---|
| Title | finding `title` |
| Severity + CVSS vector | finding `severity`, `details.cvss_vector` |
| Weakness (CWE) | `--weakness` flag, else `details.weakness`, else `details.cwe_id` |
| Attacker-impact statement | finding `impact` or `details.impact` |
| Durable proof | per the export contract; inline PoC is supporting content |
| Remediation | finding `remediation` |

## Scaffold

```
**Title:** [Bug Class] in [exact component] allows [attacker role] to [impact]

**Weakness:** CWE-[nnn]: [name]

**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]

**CVSS:** [complete base vector in a CVSS version enabled by the program] ([score])

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

## HackerOne-specific notes

- **Weakness replaces VRT.** Pick the single most specific CWE available in HackerOne's current
  weakness selector, the one the PoC actually exercises; `agent/references/reporting/hackerone-weaknesses.md`
  has the selection rule and the severity bands.
- **Severity comes from the CVSS base vector** in a version the program enables (v3.1 or v4.0).
  Platform asset severity caps or environmental adjustments are separate from Vigil's base pair, and
  a Bugcrowd priority never appears on a HackerOne submission.
- **PoC script:** stage it as `submissions/<slug>/poc.<ext>` and attach it in the HackerOne form
  (submission-format.md "PoC block"); write `details.run` / `details.pass_if` so the header lines
  survive re-render.
- **Asset:** some programs map reports to a published scope asset (`api.example.com` vs
  `www.example.com`). The `**Asset:**` header renders `canonical_location`; name the exact in-scope
  asset in Steps to Reproduce as well when the program's asset field differs from it.

## Worked example

`agent/references/examples/submission-hackerone-ssrf-webhook.md`
