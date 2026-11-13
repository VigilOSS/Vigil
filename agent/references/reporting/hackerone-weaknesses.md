---
description: "HackerOne CWE-weakness selection guidance: map a finding to its most-specific current platform weakness. Severity is CVSS-derived and SEPARATE from the weakness (None/Low/Medium/High/Critical from the CVSS score) - do not conflate with Bugcrowd's P1-P5 leaf priority."
skill: report-generation
category: Disclosure & Reporting Formats
---

# HackerOne CWE Weakness Selection

HackerOne's weakness field uses a curated subset of MITRE CWE. The platform taxonomy changes
independently of Vigil, so this repository does not vendor a snapshot: check the current choices in
the submission form or the [weakness documentation](https://docs.hackerone.com/en/articles/8475333-weaknesses),
and use [MITRE CWE](https://cwe.mitre.org/find/index.html) to tell a specific weakness from its parent.

## Pick the single most specific CWE

`CWE-89` (SQL Injection) beats its parent `CWE-74` for a SQL injection; `CWE-639` (Authorization
Bypass Through User-Controlled Key, the IDOR-shaped CWE) beats `CWE-284` for a by-parameter IDOR.
When two CWEs are plausible, use the one the PoC actually exercises, not the one that sounds more
general or more serious.

## Severity comes from the CVSS vector, not the weakness

The weakness is a label with no inherent severity: the same CWE can be Low on one report and Critical
on another. Record the base vector and score in a CVSS version the program enables (v3.1 or v4.0); the
band follows the score — None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0. A
band that looks wrong means the vector is wrong (`agent/rules/reporting.md` Rule 3,
`agent/skills/report-generation/SKILL.md` "CVSS Sourcing and Calculation"). HackerOne may apply asset
severity caps or v3.1 environmental adjustments
([severity](https://docs.hackerone.com/en/articles/8475343-severity),
[CVSS 4.0](https://docs.hackerone.com/en/articles/10502498-cvss-4-0)); keep those separate from
Vigil's base pair. A Bugcrowd P-rating (`agent/references/reporting/bugcrowd-vrt.md`) has no meaning
here and appears nowhere in a HackerOne submission.
