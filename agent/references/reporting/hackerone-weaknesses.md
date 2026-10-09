---
description: "HackerOne CWE-weakness selection guidance: map a finding to its most-specific current platform weakness. Severity is CVSS-derived and SEPARATE from the weakness (None/Low/Medium/High/Critical from the CVSS score) - do not conflate with Bugcrowd's P1-P5 leaf priority."
skill: report-generation
category: Disclosure & Reporting Formats
---

# HackerOne CWE Weakness Selection

HackerOne uses a curated subset of MITRE CWE for its weakness field. Consult the current weakness
choices in the HackerOne submission form or HackerOne's documentation, then use MITRE's CWE entry
to distinguish a specific weakness from its broader parent.

The platform taxonomy can change independently of Vigil, so this repository deliberately does not
vendor a snapshot of HackerOne's weakness list.

Useful sources:

- HackerOne weakness documentation: <https://docs.hackerone.com/en/articles/8475333-weaknesses>
- MITRE CWE search: <https://cwe.mitre.org/find/index.html>

## Pick the single MOST SPECIFIC CWE

HackerOne wants one weakness, not a broad category. `CWE-89` (SQL Injection) beats `CWE-74` (Injection,
the parent) for a SQL injection finding; `CWE-639` (Authorization Bypass Through User-Controlled
Key — the IDOR-shaped CWE) beats `CWE-284` (Improper Access Control, the parent) for a
by-parameter IDOR. If two CWEs are plausible, use the one the PoC actually exercises, not the one
that sounds more general or more serious.

## Severity is CVSS-derived — the CVSS→band table

HackerOne severity comes **only** from the submitted CVSS:3.1 vector's score, run through the
standard bands:

| Score | Band |
|---|---|
| 0.0 | None |
| 0.1 – 3.9 | Low |
| 4.0 – 6.9 | Medium |
| 7.0 – 8.9 | High |
| 9.0 – 10.0 | Critical |

Don't hand-pick a severity that disagrees with the vector — if the band looks wrong, the vector is
wrong; fix the vector (see `agent/rules/reporting.md` Rule 3 and "CVSS Sourcing and Calculation"
in `agent/skills/report-generation/SKILL.md`), not the label.

## GUARDRAIL — weakness != severity

The CWE weakness and the CVSS-derived severity band are **fully decoupled** on HackerOne. A
weakness is a label with no inherent severity; the same CWE can appear on a Low finding in one
report and a Critical finding in another, because severity comes from the specific instance's
CVSS vector, never from the CWE itself.

- **Never carry a Bugcrowd P-rating into an H1 report.** Bugcrowd's P1–P5 is a VRT-leaf priority
  scale (see `agent/references/reporting/bugcrowd-vrt.md`) — it has no meaning on HackerOne and
  must not appear in a HackerOne submission's `Severity:` field or body.
- **Never put a fixed severity on a CWE.** Don't write "CWE-89 is Critical" as a rule of thumb —
  the same weakness can land anywhere on the band table depending on the proved impact. Compute
  the vector from the proof, read the band off the table above, and use that.
