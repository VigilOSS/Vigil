---
description: "HackerOne submission scaffold: CWE weakness, CVSS vector, PoC, remediation"
skill: report-generation
category: Disclosure & Reporting Formats
---

# HackerOne Submission Template

HackerOne-specific scaffold for `vigil assess export-submission <slug> --platform hackerone`.
Shared rules (voice, section budgets, PII redaction, PoC authoring, de-harnessing, the
pre-submission checklist) live in `agent/references/bugbounty-submission-format.md` — this file
only adds what HackerOne needs in place of Bugcrowd's VRT: a CWE weakness, and how HackerOne
derives its severity bucket.

## Strict-gate fields

Same gate as Bugcrowd (the strict-gate rule in `export-submission` is platform-agnostic), with
**Weakness (CWE)** in place of VRT:

| Field | Populated from |
|---|---|
| Title | finding `title` |
| Severity + CVSS vector | finding `severity`, `details.cvss_vector` |
| Weakness (CWE) | `--weakness` flag, else `details.cwe_id` |
| Attacker-impact statement | finding `impact` / `summary` |
| Proof (≥1 of) | `poc_request` **and** `poc_response`, OR `poc_code`, OR non-empty `evidence_ref` |
| Remediation | finding `remediation` |

`--draft` marks whatever is missing with `[NEEDS: ...]`; final export refuses to write with any
row above empty.

## Scaffold

```
**Title:** [Bug Class] in [exact component] allows [attacker role] to [impact]

**Weakness:** CWE-[nnn]: [name]

**Severity:** [Critical/High/Medium/Low] — CVSS:3.1/[vector] ([score])

[PoC block — see bugbounty-submission-format.md "PoC block". Omit for inline-only reproductions.]

---

### Summary
[2-4 sentences. Attacker outcome first, then the fault, then what the PoC proves.]

### Steps to Reproduce
[Numbered. One action per step. No narrative between steps.]

### Evidence
[Request/response or PoC output, truncated to the proof lines, annotated.]

### Attack Scenario
[2-3 sentences. Concrete adversary class + action + outcome.]

### Impact
[1-2 sentences. Proven impact only, quantified by shape/count.]

### Remediation
[≤3 items, primary fix first, ≤1 defense-in-depth.]
```

## HackerOne-specific notes

- **Weakness replaces VRT.** Pick the single most specific CWE the fault maps to (`CWE-89`, not
  `CWE-20`). If two CWEs are plausible, use the one the PoC actually exercises.
- **Severity is CVSS-derived, not a separate scale.** HackerOne computes the Critical/High/
  Medium/Low bucket directly from the submitted CVSS:3.1 vector through its own calculator — don't
  hand-pick a severity that disagrees with the vector; fix the vector instead.
- Some HackerOne programs add an "Asset" field mapped to their published scope (e.g.,
  `api.example.com` vs `www.example.com`). Name the exact in-scope asset in Steps to Reproduce —
  this template doesn't carry a separate field for it because it isn't part of the strict gate.

## Worked example

`agent/references/examples/submission-hackerone-ssrf-webhook.md`
