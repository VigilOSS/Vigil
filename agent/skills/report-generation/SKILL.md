---
name: report-generation
description: Backend-first engagement report structure, generation procedure, and formatting guidelines
origin: AI Threat Hunting
---

# Report Generation

## When to Activate

- Phase 5 (Report) — operator dispatches report-writer after exploit phase completes
- On-demand interim report requested by the operator mid-engagement

## Query Backend First

Before writing anything, pull the canonical state from the orchestrator API.
Use the helper script or `curl` — never query the SQLite database file directly.

```bash
# Report-ready findings: sorted by severity, CVSS/remediation extracted, sequential report IDs assigned
./scripts/assess.py fetch report-findings

# Attack chains with narrative and severity
./scripts/assess.py fetch attack-chains

# Credentials discovered during exploitation
./scripts/assess.py fetch credentials

# Access records and footholds confirmed via credential validation
./scripts/assess.py fetch access-records

# Surfaces for coverage summary
./scripts/assess.py fetch surfaces

# Assessment-level counts
./scripts/assess.py fetch summary
```

The `report-findings` endpoint returns each finding with:
- `report_id` — sequential `FINDING-001`, `FINDING-002`, etc. (for the report body)
- `slug` — the original backend slug, e.g. `FINDING-VA-003` (for cross-reference)
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

Factual, evidence-based. No speculation — state conditions if impact is theoretical.
Quantify where possible. No hyperbole or marketing language.

Banned phrases: `could potentially`, `may allow`, `might be possible`, `could lead to`.
Use instead: `An attacker can [exact action] by [exact method].`

## Report Structure

### 1. Executive Summary

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

[1-2 paragraph narrative: posture, most impactful findings, top recommendation.]
```

### 2. Methodology

```markdown
## Methodology
**Approach:** [Black/Grey/White-box, Manual/Automated/Hybrid]
**Phases:** 1. Recon 2. Collection 3. Testing 4. Exploitation 5. Reporting

| Tool | Purpose |
|------|---------|

**Limitations:** [time, scope, rate limiting, unavailable systems]
```

### 3. Findings (sorted CRITICAL -> INFO, each self-contained)

```markdown
### FINDING-001: [Title] [SEVERITY]
**Slug:** FINDING-VA-003  **OWASP:** A03:2021  **CWE:** CWE-89  **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

#### Description
[Precise technical explanation]

#### Steps to Reproduce
1. [Step from steps_to_reproduce array]
2. ...

#### Evidence
**Request:** ```[full HTTP request]```
**Response:** ```[relevant excerpt]```

#### Impact
[From impact field — specific: "attacker can retrieve all 12,000 user credentials"]

#### Remediation
1. [From remediation field]
**References:** [CWE link, relevant standard]
```

### 4. Attack Path Narrative

```markdown
## Attack Path Narrative
### Scenario 1: [Title]
**Findings Used:** FINDING-001 (FINDING-VA-003), FINDING-003 (FINDING-EX-001)
**Starting Point:** [attacker type]
1. **Initial Access** - [FINDING-X] -> [foothold]
2. **Escalation** - [FINDING-Y] -> [escalate]
3. **Objective** - [outcome]
**Combined Impact:** [what chain achieves]  **Priority Fix:** [which fix breaks chain]
```

If no chains: "No multi-step attack paths identified."

### 5. Coverage Summary

```markdown
## Coverage Summary
| Metric | Count |
|--------|-------|
| Targets | N |
| Services | N |
| Surfaces discovered | N |
| Surfaces covered | N |
| Probe runs | N |
```

### 6. Slug Cross-Reference

```markdown
## Finding Cross-Reference
| Report ID | Backend Slug | Title |
|-----------|-------------|-------|
| FINDING-001 | FINDING-VA-003 | Blind SQL injection in search |
| FINDING-002 | FINDING-EX-001 | Auth bypass via JWT alg:none |
```

This table maps report IDs back to canonical backend slugs for traceability.

### 7. Appendix

Tool output in `<details>` blocks, generated scripts, scope verification table, timeline.

## Pre-Report Validation

Before generating the report body, run these checks against the backend data. If any check fails, **stop and flag the issue to the operator** — do not silently fix or ignore it.

1. **Duplicate check:** scan findings for pairs sharing the same root cause + endpoint. Flag: "FINDING-VA-003 and FINDING-EX-001 appear to describe the same root cause on /api/users — resolve before report."
2. **CVSS↔severity mismatch:** verify each finding's `cvss_score` falls within its `severity` range (critical 9.0–10.0, high 7.0–8.9, medium 4.0–6.9, low 0.1–3.9, info 0.0). Flag any mismatches.
3. **Missing required fields:** flag findings where `evidence`, `impact`, `steps_to_reproduce`, or `remediation` are empty or absent.

Only proceed to report generation after validation passes or the operator resolves flagged issues.

## Generation Procedure

1. **Pull backend state** using the queries in "Query Backend First" above
2. **Use `report-findings`** as the authoritative finding list — do not re-read `findings.md`
3. **Use pre-computed CVSS** from finding details. Recalculate only if proved impact at report time materially differs from what was validated
4. **Use pre-computed remediation** from finding details. Augment only if the exploit chain revealed additional fix requirements
5. Populate all template fields (flag missing evidence with `[EVIDENCE MISSING]`, never fabricate)
6. Build attack path narrative from `attack-chains` endpoint data and enrich it with `credentials` / `access-records` when those records explain the authenticated foothold or post-auth scope
7. Compile coverage summary from `summary` endpoint
8. Build the slug cross-reference table
9. Write executive summary LAST — it depends on the complete finding set and chain analysis
10. Verify: severity counts in executive summary match the actual finding list

## After Writing the Report

1. **Write report to `$ENGAGEMENT_DIR/report.md`**
2. **Emit a runtime event** so the orchestrator and UI know the report exists:
   ```bash
   ./scripts/assess.py emit-event \
       "report.generated" \
       "report" \
       "report.md" \
       "report-writer" \
       "Report generated with N findings"
   ```
3. **Update finding statuses to `reported`** for all findings included in the report:
   ```bash
   # For each finding slug included in the report:
   echo '{"slug":"FINDING-VA-003","status":"reported","title":"...","severity":"...","defect_family":"...","root_cause_key":"...","auth_context":"...","canonical_location":"...","summary":"...","evidence_ref":"...","notes":"","details":{"evidence":"...","impact":"..."}}' > /tmp/finding_update.json
   ./scripts/assess.py record-finding report-writer /tmp/finding_update.json
   ```
   This completes the finding lifecycle: draft -> confirmed -> exploited -> reported.

## Extended Resources

- `agent/references/vuln-checklists/` — OWASP category reference for finding classification
- `agent/references/runtime-guides/engagement-methodology.md` — methodology narrative source
