---
description: "HackerOne submission scaffold: CWE weakness, CVSS vector, PoC, remediation"
skill: report-generation
category: Disclosure & Reporting Formats
---

# HackerOne Submission Template

HackerOne-specific scaffold for `vigil assess export submission <slug> --platform hackerone`.
Shared rules (voice, section budgets, evidence fidelity, PoC authoring, de-harnessing, the
pre-submission checklist, and the finding-is-source-of-truth flow — author each section, write it
back to the finding, re-render) live in `agent/references/submission-format.md` — this
file only adds what HackerOne needs in place of Bugcrowd's VRT: a CWE weakness, and how HackerOne
derives its severity bucket.

## Strict-gate fields

Same gate as Bugcrowd (the strict-gate rule in `export submission` is platform-agnostic), with
**Weakness (CWE)** in place of VRT:

| Field | Populated from |
|---|---|
| Title | finding `title` |
| Severity + CVSS vector | finding `severity`, `details.cvss_vector` |
| Weakness (CWE) | `--weakness` flag, else `details.weakness`, else `details.cwe_id` |
| Attacker-impact statement | finding `impact` or `details.impact` |
| Durable proof | Per `vigil assess contract export submission`; inline PoC is supporting content |
| Remediation | finding `remediation` |

`--draft` marks whatever is missing with `[NEEDS: ...]`; final export refuses to write with any
row above empty.

## Scaffold

```
**Title:** [Bug Class] in [exact component] allows [attacker role] to [impact]

**Weakness:** CWE-[nnn]: [name]

**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]

**CVSS:** [complete base vector in a CVSS version enabled by the program] ([score])

---

### Summary
[2-4 sentences. Attacker outcome first, then the fault, then what the PoC proves. Optionally followed
by a `**Exploit flow**` marker + a 3-5 item ordered list of plain sentences, no commands, same string.]

### Steps to Reproduce
[Numbered, ≤10 steps, no narrative between them. Prefix each step with the acting identity
(`[attacker]`/`[administrator]`/`[server]`/`[both]`); one action per step, its outcome on a `**Expect:**` line.]

### Evidence
[AUTHORED, and only proof the steps cannot show — root cause, negative controls, post-exploitation
boundaries, minimum privilege, load-bearing environment facts. From the OPERATOR DETAILS section's structured proof + linked runs + a targeted
`command-run list` search, all captured values preserved verbatim (see submission-format.md
"Evidence fidelity"), truncated to the proof lines, annotated with
<-- proof markers. Stored back on the finding as `details.evidence`; the raw output stays in `scans/`.]

### Attack Scenario
[2-3 sentences. Realistic adversary class + starting access + action, ending at first compromise —
no scope counts (those go in Impact). Optional: drop it when Steps + Impact already show
reachability, and omit it outright whenever the Summary carries an Exploit flow.]

### Impact
[1-2 sentences. Consequence + blast radius, quantified by shape/count. Don't re-describe the actor or
the steps — this is the severity justification. See "Attack Scenario vs Impact" in submission-format.md.]

### Remediation
[≤3 items, primary fix first, ≤1 defense-in-depth.]
```

## HackerOne-specific notes

- **Weakness replaces VRT.** Pick the single most specific CWE the fault maps to (`CWE-89`, not
  `CWE-20`). If two CWEs are plausible, use the one the PoC actually exercises. Confirm that the
  candidate is available in HackerOne's current weakness selector and use MITRE CWE to distinguish
  it from broader parent categories.
- **CVSS-derived severity.** Use a CVSS version enabled by the program; HackerOne supports
  standard v3.1 and v4.0 calculators. Keep Vigil's base vector and score consistent. Platform
  asset severity caps or environmental adjustments are separate from that base pair. See
  `agent/references/reporting/hackerone-weaknesses.md` for the CVSS→band table and the guardrail
  that weakness and severity are decoupled — never carry a Bugcrowd P-rating into this field.
- **PoC is an operator-side attachment, not a rendered body line.** If the proof is a script, stage
  it as `submissions/<slug>/poc.<ext>` and attach it in the HackerOne form — see
  `submission-format.md` "PoC block". `export submission` emits no attachment block into the body;
  the **Run:** / **Pass if:** pointer lines in the operational header ARE rendered, from the
  finding's `details.run` and `details.pass_if` — write there so they reproduce on the next
  `--overwrite` instead of typing them only into the body. The proof pointer itself
  (`evidence_ref`/`poc_code`) stays under OPERATOR DETAILS, not the pasteable header.
- Some HackerOne programs add an "Asset" field mapped to their published scope (e.g.,
  `api.example.com` vs `www.example.com`). Name the exact in-scope asset in Steps to Reproduce —
  this template doesn't carry a separate field for it because it isn't part of the strict gate.

## Worked example

`agent/references/examples/submission-hackerone-ssrf-webhook.md`
