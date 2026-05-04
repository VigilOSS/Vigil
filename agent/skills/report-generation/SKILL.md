---
name: report-generation
description: Backend-first engagement report structure, generation procedure, and formatting guidelines
origin: AI Threat Hunting
---

# Report Generation

## When to Activate

- Phase 7 (Report) — operator dispatches report-writer after Verify and exploit work complete
- On-demand interim report requested by the operator mid-engagement

## Query Backend First

Before writing anything, pull the canonical state from the orchestrator API.
Use the helper script or `curl` — never query the SQLite database file directly.

```bash
# Final report gate and final-mode findings
aith assess check-report-readiness
aith assess fetch "report-findings?mode=final"

# Interim report findings when the operator explicitly wants a draft before final readiness passes
aith assess fetch "report-findings?mode=draft"

# Attack chains with narrative and severity
aith assess fetch attack-chains

# Credentials discovered during exploitation
aith assess fetch credentials

# Access records and footholds confirmed via credential validation
aith assess fetch access-records

# Surfaces for coverage summary
aith assess fetch surfaces

# Assessment-level counts
aith assess fetch summary
```

The `report-findings` endpoint returns each finding with:
- `report_id` — sequential `001`, `002`, etc. (for the report body)
- `slug` — the original backend slug, e.g. `VA-003` (for publish-mode lifecycle updates only; do not expose in the report body)
- `cvss_vector`, `cvss_score` — extracted from `details_json`
- `remediation`, `steps_to_reproduce`, `cwe_id`, `owasp_category` — extracted from `details_json`
- `impact`, `evidence_detail` — extracted from `details_json`

Use these structured fields directly. Do not re-derive CVSS or remediation unless the
proved impact at report time materially differs from what was recorded at validation.

## Severity Definitions

| Severity | Criteria |
|----------|----------|
| **CRITICAL** | Full system compromise, unauthenticated RCE, mass data breach. CVSS 9.0-10.0. |
| **HIGH** | Direct CIA impact, exploitable with minimal effort. Data breach, auth bypass. CVSS 7.0-8.9. |
| **MEDIUM** | Requires conditions or chaining. Stored XSS, IDOR on non-critical data, limited SQLi. CVSS 4.0-6.9. |
| **LOW** | Limited impact or hard to exploit. Reflected XSS, verbose errors. CVSS 0.1-3.9. |
| **INFO** | No direct security impact. Observations, best-practice deviations, tech disclosures. CVSS 0.0. |

## Writing Style

Follow `agent/rules/reporting.md` for all writing rules — banned language, active voice,
evidence formatting, remediation specificity, filler/padding, and section length limits.

**Audience:** Technical reader who knows vulnerability classes. Do not define standard terms.

**Executive summary exception:** The executive summary is for non-technical stakeholders.
Use business language there. "An attacker can download all customer records" not "IDOR on /api/users."

## Report Structure

### 1. Executive Summary (ONE PAGE MAX)

Written for the person who will not read the rest — a director, VP, or CISO.

```markdown
## Executive Summary
**Target:** [target]  **Scope:** [scope]  **Date:** [start] - [end]  **Tester:** AI Threat Hunting

| Severity | Count |
|----------|-------|
| Critical | N |
| High     | N |
| Medium   | N |
| Low      | N |
| Info     | N |
| **Total** | **N** |

[1-2 paragraphs: overall posture in business terms, the most impactful finding described
as attacker outcome with business consequence, one prioritized recommendation.
No unexplained jargon. "SQL injection (direct database access)" not just "SQL injection."]
```

### 2. Methodology

```markdown
## Methodology
**Approach:** [Black/Grey/White-box, Manual/Automated/Hybrid]
**Phases:** 1. Recon 2. Collection 3. Testing 4. Verify 5. Exploitation 6. Optional log investigation 7. Reporting

| Tool | Purpose |
|------|---------|

**Limitations:** [time, scope, rate limiting, unavailable systems]
```

### 3. Findings (sorted CRITICAL -> INFO, each self-contained)

**Length discipline per section:**

| Section | Limit | Rule |
|---------|-------|------|
| Description | 2-4 sentences | First sentence = attacker outcome. No class definitions. No restating the title. |
| Steps to Reproduce | Numbered, 1 action per step | No narrative between steps. Copy-pasteable commands where possible. |
| Evidence | 1 request/response per proof point | Response truncated to 5-15 relevant lines. Bold/annotate the proof line. |
| Impact | 1-2 sentences | Quantified. What the attacker gets, how many records/users/systems affected. |
| Remediation | 1-2 sentences | Names the technology and the specific fix. No generic advice. |

```markdown
### 001: [Title] [SEVERITY]
**OWASP:** A03:2021  **CWE:** CWE-89  **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

#### Description
[2-4 sentences. First sentence: what the attacker gains. Remaining: how, where, auth context.]

#### Steps to Reproduce
1. [Single action — e.g., "Send the following request:"]
2. [Next action]

#### Evidence
**Request:**
```http
[Full HTTP request, payload annotated if not obvious]
```
**Response (truncated):**
```http
[5-15 lines. **Bold the proof line** or annotate with ← leaked data / ← unauthorized]
```

#### Impact
[1-2 sentences. Quantified attacker outcome.]

#### Remediation
[1-2 sentences. Specific technology and control. References: CWE link.]
```

### 4. Attack Path Narrative

```markdown
## Attack Path Narrative
### Scenario 1: [Title]
**Findings Used:** 001, 003
**Starting Point:** [attacker type]
1. **Initial Access** - [X] -> [foothold]
2. **Escalation** - [Y] -> [escalate]
3. **Objective** - [outcome]
**Combined Impact:** [what chain achieves]  **Priority Fix:** [which fix breaks chain]
```

If no chains: "No multi-step attack paths identified."

### 5. Appendix

Tool output in `<details>` blocks, generated scripts, scope verification table, timeline.

## Pre-Report Validation

Before generating the report body, run these checks against the backend data. If any check fails, **stop and flag the issue to the operator** — do not silently fix or ignore it.

1. **Readiness gate:** for final reports, run `aith assess check-report-readiness`. If it fails, stop and flag the blockers to the operator.
2. **Root-cause consolidation check:** scan findings for pairs sharing the same vulnerable component or configuration where one is a direct consequence of the other. These must be consolidated into one finding before the report is written. Flag: "EX-036 (credential extraction) is a consequence of EX-032 (auth bypass on the same TeamCity host) — merge into one finding." Apply the BugCrowd/HackerOne standard: one root cause, one submission.
3. **CVSS↔severity mismatch:** verify each finding's `cvss_score` falls within its `severity` range (critical 9.0–10.0, high 7.0–8.9, medium 4.0–6.9, low 0.1–3.9, info 0.0). Flag any mismatches.
4. **Missing required fields:** flag findings where `evidence`, `impact`, `steps_to_reproduce`, or `remediation` are empty or absent.

Only proceed to report generation after validation passes or the operator resolves flagged issues.

## Generation Procedure

1. **Pull backend state** using the queries in "Query Backend First" above
2. **Use `report-findings?mode=final`** as the authoritative finding list for final reports, or `report-findings?mode=draft` for interim drafts
3. **Use pre-computed CVSS** from finding details. Recalculate only if proved impact at report time would shift at least one CVSS base metric (AV, AC, PR, UI, S, C, I, A) by one or more levels versus the validated vector
4. **Use pre-computed remediation** from finding details. Augment only when one of these is true: (a) the chain revealed a prerequisite weakness the original remediation did not address, (b) the exploit bypassed the suggested fix, or (c) the chain spans multiple findings and fixing this one alone does not close the chain
5. Populate all template fields (flag missing evidence with `[EVIDENCE MISSING]`, never fabricate)
6. Build attack path narrative from `attack-chains` endpoint data and enrich it with `credentials` / `access-records` when those records explain the authenticated foothold or post-auth scope
7. Write executive summary LAST — it depends on the complete finding set and chain analysis
8. Verify: severity counts in executive summary match the actual finding list

## After Writing the Draft

1. **Write report to `$ENGAGEMENT_DIR/report.md`**
2. **Run the post-generation self-review below**
3. **Fix report-local failures before returning to the operator**
4. **Return the completed checklist and current QA status**

Do not emit `report.generated` or mark findings `reported` during draft generation. Publication belongs after the operator dispatches a fresh report-writer in review-and-fix QA mode and receives `QA PASS`, because lifecycle transitions before QA make an unreviewed report look final.

## Post-Generation Self-Review

After writing the report, verify every finding against `agent/rules/reporting.md`. If any check fails, fix it.

1. First sentence states attacker outcome (Rule 6)
2. No title echo in description (Rule 11)
3. No vulnerability class definitions (Rule 11)
4. No banned filler phrases (Rule 11)
5. Active voice throughout (Rule 12)
6. Evidence blocks ≤ 15 lines with annotated proof (Rule 13)
7. Remediation names specific technology (Rule 14)
8. Every sentence is load-bearing (Rule 15)
9. Steps to reproduce: one action per step, copy-pasteable (Rule 10)
10. Executive summary ≤ one page (Rule 10)
11. Severity counts in executive summary match actual finding list
12. No severity labels in titles, no internal slugs/IDs anywhere, no Coverage Summary, no Finding Cross-Reference (Rules 16–19)
13. Findings sharing the same root cause are consolidated — one vulnerable component, one finding (Rule 18)

## Review-and-Fix QA Mode

When the operator dispatches report-writer in review-and-fix QA mode, load the existing `$ENGAGEMENT_DIR/report.md`, pull the same backend report state, and run the 12 checks above against the rendered report.

- Fix report-local failures directly in `report.md`: wording, structure, counts, missing annotations, overlong evidence, title echoes, passive voice, and non-load-bearing sentences.
- Return `QA PASS` only when all 12 checks pass after fixes.
- Return `QA BLOCKED` when the report cannot be corrected without new backend state: missing evidence, missing remediation, unresolved duplicate findings, severity/CVSS mismatch, or a finding that no longer belongs in final output. Include exact finding slugs and the required operator action.

## Publish After QA Pass

Run these publication steps only after the operator confirms the report QA gate passed:

1. **Emit a runtime event** so the orchestrator and UI know the report exists:
   ```bash
   aith assess emit-event \
       "report.generated" \
       "report" \
       "report.md" \
       "report-writer" \
       "Report generated with N findings"
   ```
2. **Update finding workflow status to `reported`** for all findings included in the report:
   ```bash
   # For each finding slug included in the report, use the finding-specific helper so the
   # workflow transition stays explicit at the command line:
   aith assess update-finding VA-003 \
     --status reported \
     --notes "Included in report.md" \
     --reason "Included in the generated report deliverable." \
     --source-name report-writer \
     --provenance-inline '{"reported_by":"report-writer"}'
   ```
   This advances the workflow lifecycle after verification and report QA have established the durable disposition.

## Email Disclosure Reports

When the operator requests a disclosure email instead of an internal report, switch to the
email disclosure format — a separate output mode, not a variation of report.md.

Load before writing:
- `agent/references/disclosure-email-format.md` — authoritative spec (structure, rules, anti-patterns)
- `agent/references/examples/disclosure-email-fast-import.txt` — working example with control test

Output path: `$ENGAGEMENT_DIR/tools/exploit-state/pocs/report-<slug>.txt`

## Bug Bounty Submissions

When the operator requests bug bounty submissions (Bugcrowd, HackerOne, or similar),
each finding becomes a standalone submission — never bundle findings.

Load before writing:
- `agent/references/bugbounty-submission-format.md` — authoritative spec (structure, rules)
- `agent/references/examples/bugbounty-submission-ldap-injection.md` — working example with POC

## Extended Resources

- `agent/references/runtime-guides/engagement-methodology.md` — methodology narrative source
- `agent/references/disclosure-email-format.md` — email disclosure format and rules
- `agent/references/bugbounty-submission-format.md` — bug bounty submission format
- `agent/references/examples/` — working examples for both output modes
