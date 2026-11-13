---
description: "Direct/vendor submission scaffold: Bugcrowd-style structure minus platform-only fields"
skill: report-generation
category: Disclosure & Reporting Formats
---

# Direct Submission Template

Scaffold for `vigil assess export submission <slug> --platform direct`: a structured writeup for a
target with no Bugcrowd or HackerOne program, handed to the vendor's security contact or intake
portal. A plaintext email to a `security@` contact uses `agent/references/disclosure-email-format.md`
instead; use `direct` when the deliverable is a standalone document.

Every shared rule lives in `agent/references/submission-format.md`, including the
finding-is-source-of-truth flow. `direct` drops both platform taxonomy lines: no VRT, and no required
Weakness/CWE (name the CWE in prose if it helps the reader).

## Strict-gate fields

`--draft` marks whatever is missing with `[NEEDS: ...]`; the final export refuses to write with any
row empty (`vigil assess contract export submission` owns the gate). There is no taxonomy row.

| Field | Populated from |
|---|---|
| Title | finding `title` |
| Severity + CVSS vector | finding `severity`, `details.cvss_vector` |
| Attacker-impact statement | finding `impact` or `details.impact` |
| Durable proof | per the export contract; inline PoC is supporting content |
| Remediation | finding `remediation` |

## Scaffold

```
**Title:** [Bug Class] in [exact component] allows [attacker role] to [impact]

**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]

**CVSS:** [complete CVSS v3.1 or v4.0 base vector] ([score])

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

## Direct-specific notes

- **Company-facing tone.** Some vendors receiving a direct report have never handled one, so keep
  the summary self-contained: name the product, not just the endpoint.
- **Severity uses the finding's own Critical/High/Medium/Low label**; there is no program priority
  scale to map onto.
- **PoC script:** stage it as `submissions/<slug>/poc.<ext>` and hand it to the vendor with the
  writeup (submission-format.md "PoC block"); write `details.run` / `details.pass_if` so the header
  lines survive re-render.
- **Researcher contact line** (`**Researcher:** [name] — [email]`), only when the vendor's intake does
  not already capture the researcher (a portal ticket or cover email often does). The default render
  has no field for it, so it arrives through an operator-selected `--body`; the gate does not check it.

## Worked example

`agent/references/examples/submission-direct-sql-injection-login.md`
