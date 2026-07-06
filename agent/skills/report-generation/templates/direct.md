---
description: "Direct/vendor submission scaffold: Bugcrowd-style structure minus platform-only fields"
skill: report-generation
category: Disclosure & Reporting Formats
---

# Direct Submission Template

Scaffold for `vigil assess export-submission <slug> --platform direct` — a structured writeup for
a target with no Bugcrowd or HackerOne program, handed to the vendor's security contact or intake
portal directly. This is **not** the email path: `agent/references/disclosure-email-format.md`
stays its own plaintext format for git/OSS-style `security@` contacts. Use `direct` when the
deliverable is a standalone document, not an email body.

Shares every writing rule with the platform templates
(`agent/references/submission-format.md`) — including the finding-is-source-of-truth flow
(author each section, write it back to the finding, re-render) — minus the two platform-only fields:

- No VRT line — Bugcrowd's taxonomy doesn't apply outside Bugcrowd.
- No Weakness/CWE line as a mandatory field — name the CWE in prose if it helps the reader, but
  the strict gate doesn't require it here.

## Strict-gate fields

| Field | Populated from |
|---|---|
| Title | finding `title` |
| Severity + CVSS vector | finding `severity`, `details.cvss_vector` |
| Attacker-impact statement | finding `impact` / `summary` |
| Proof (≥1 of) | `poc_request` **and** `poc_response`, OR `poc_code`, OR non-empty `evidence_ref` |
| Remediation | finding `remediation` |

No platform-taxonomy row — `direct` is the one platform where the strict gate doesn't require one.

## Scaffold

```
**Title:** [Bug Class] in [exact component] allows [attacker role] to [impact]

**Severity:** [Critical/High/Medium/Low]

**CVSS:** CVSS:3.1/[vector] ([score])

---

### Summary
[2-4 sentences. Attacker outcome first, then the fault, then what the PoC proves.]

### Steps to Reproduce
[Numbered. One action per step. No narrative between steps.]

### Evidence
[AUTHORED from the OPERATOR DETAILS section's structured proof + linked runs + a targeted
`list-command-runs` search, PII-masked, truncated to the proof lines, annotated with <-- proof
markers. Stored back on the finding as `details.evidence`; the raw output stays in `scans/`.]

### Attack Scenario
[2-3 sentences. Concrete adversary class + action + outcome.]

### Impact
[1-2 sentences. Proven impact only, quantified by shape/count.]

### Remediation
[≤3 items, primary fix first, ≤1 defense-in-depth.]
```

## Direct-specific notes

- **Company-facing tone, not bounty-program tone.** Don't assume the reader triages hundreds of
  these a day — some vendors receiving a direct report have never handled one before. Keep the
  summary self-contained: name the product, not just the endpoint.
- **Severity uses the internal Critical/High/Medium/Low labels**, matching the finding's own
  `severity` field, not Bugcrowd's P1-P4 — there's no bounty-program priority scale to map onto.
- **PoC is an operator-side attachment, not a rendered body line.** If the proof is a script, stage
  it as `submissions/<slug>/poc.<ext>` and hand it to the vendor alongside the writeup — see
  `submission-format.md` "PoC block". `export-submission` emits no PoC line into the body; a
  hand-inserted one is wiped on the next `--overwrite`.
- Add a contact line if the vendor's intake doesn't already capture the researcher elsewhere (the
  writeup may be attached to a portal ticket or a cover email that already carries a From:
  address):
```
**Researcher:** [name] — [email]
```
  This line is optional; the strict gate doesn't check it.

## Worked example

`agent/references/examples/submission-direct-sql-injection-login.md`
