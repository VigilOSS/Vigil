---
name: report-generation
description: Backend-first engagement report structure, generation procedure, and formatting guidelines
origin: Vigil
---

# Report Generation

## When to Activate

- Phase 7 (Report) — operator dispatches report-writer after Verify and exploit work complete
- On-demand interim report requested by the operator mid-engagement

## Query Backend First

Before writing anything, pull the canonical state from the orchestrator API.
Use the helper script or `curl` — never query the SQLite database file directly.

```bash
# Final report gate and grouped final-mode findings
vigil assess check-report-readiness
vigil assess list-report-findings --mode final --json

# Interim grouped findings when the operator explicitly wants a draft before final readiness passes
vigil assess list-report-findings --mode draft --json

# Attack chains with narrative and severity
vigil assess fetch attack-chains

# Credentials discovered during exploitation
vigil assess fetch credentials

# Access records and footholds confirmed via credential validation
vigil assess fetch access-records

# Surfaces for coverage summary
vigil assess fetch surfaces

# Assessment-level counts
vigil assess fetch summary
```

The `list-report-findings --json` helper returns grouped report findings. Root and sibling finding rows include:
- `report_id` — sequential `001`, `002`, etc. (for the report body)
- `slug` — the original backend slug, e.g. `VA-003` (for publish-mode lifecycle updates only; do not expose in the report body)
- `cvss_vector`, `cvss_score` — extracted from `details_json`
- `remediation`, `steps_to_reproduce`, `cwe_id`, `owasp_category` — extracted from `details_json`
- `impact`, `evidence_detail` — extracted from `details_json`

> **Read vs write asymmetry.** The backend stores finding metadata in a column literally named `details_json` (a JSON string) — that's why the `list-report-findings` projection above references `details_json` as a source. When you **write** via `vigil assess update-finding --inline`, the accepted shape is `{"details": {...}}` (a dict under the `details` key). The asymmetry is intentional: the API decodes/encodes the JSON column behind the field name `details` on writes, leaving `details_json` as the raw storage name on reads. If a prompt or recipe says to pass `details_json` to `update-finding`, that's drift — flag it.
- top-level `groups` and `standalone`; each group has a `root` finding and `siblings`

Sibling rows include
`root_cause_effect`, `root_cause_note`, and `sibling_order`. Use this projection
to keep one root-cause narrative while still naming downstream outcomes and residual
standalone paths.

Use these structured fields directly. Recalculate CVSS or remediation only when the
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

**Audience:** Technical reader who knows vulnerability classes. Assume familiarity with standard terms (XSS, SQLi, IDOR, SSRF, etc.).

**Executive summary exception:** The executive summary is for non-technical stakeholders.
Use business language there. "An attacker can download all customer records" not "IDOR on /api/users."

## Report Structure

### 1. Executive Summary (ONE PAGE MAX)

Written for the person who will not read the rest — a director, VP, or CISO.

```markdown
## Executive Summary
**Target:** [target]  **Scope:** [scope]  **Date:** [start] - [end]  **Tester:** Vigil

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
| Steps to Reproduce | Numbered, 1 action per step | No narrative between steps. Each step includes request block + response excerpt (5-15 lines, proof line bolded/annotated) inline. Copy-pasteable commands where possible. |
| Impact | 1-2 sentences | Quantified. What the attacker gets, how many records/users/systems affected. |
| Remediation | 1-2 sentences | Names the technology and the specific fix. No generic advice. |

```markdown
### 001: [Title] [SEVERITY]
**OWASP:** A03:2021  **CWE:** CWE-89  **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

#### Description
[2-4 sentences. First sentence: what the attacker gains. Remaining: how, where, auth context.]

#### Steps to Reproduce
1. Send the following request:
```http
[Full HTTP request, payload annotated if not obvious]
```
**Response (truncated):**
```http
[5-15 lines. **Bold the proof line** or annotate with ← leaked data / ← unauthorized]
```
2. [Next action with its own request/response if applicable]

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

1. **Readiness gate:** for final reports, run `vigil assess check-report-readiness`. If it fails, stop and flag the blockers to the operator.
2. **Root-cause consolidation check:** use `vigil assess list-report-findings --mode final --json` and `vigil assess check-report-readiness` to confirm intentional root/sibling groups are already represented. If two reportable findings still share the same vulnerable component or configuration and are not grouped, stop and ask the operator to run `vigil assess link-finding` or merge them. Apply the BugCrowd/HackerOne standard: one root cause, one submission.
3. **CVSS↔severity mismatch:** verify each finding's `cvss_score` falls within its `severity` range (critical 9.0–10.0, high 7.0–8.9, medium 4.0–6.9, low 0.1–3.9, info 0.0). Flag any mismatches.
4. **Missing required fields:** flag findings where `evidence`, `impact`, `steps_to_reproduce`, or `remediation` are empty or absent.

Only proceed to report generation after validation passes or the operator resolves flagged issues.

## Generation Procedure

1. **Pull backend state** using the queries in "Query Backend First" above
2. **Use `vigil assess list-report-findings --mode final --json`** as the authoritative final finding structure, or `vigil assess list-report-findings --mode draft --json` for interim drafts. Render one section per group root; include siblings as downstream outcomes under the root narrative, and explicitly call out `eliminates_attack_path` siblings as residual remediation paths.
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

Publication (`report.generated`, `closeout.generated`, marking findings `reported`) belongs after the operator dispatches a fresh report-writer in review-and-fix QA mode and receives `QA PASS` — lifecycle transitions before QA make an unreviewed report look final.

## Post-Generation Self-Review

After writing the report, verify every finding against `agent/rules/reporting.md`. If any check fails, fix it.

1. First sentence states attacker outcome (Rule 6)
2. No title echo in description (Rule 11)
3. No vulnerability class definitions (Rule 11)
4. No banned filler phrases (Rule 11)
5. Active voice throughout (Rule 12)
6. Inline response blocks ≤ 15 lines with annotated proof (Rule 13)
7. Remediation names specific technology (Rule 14)
8. Every sentence is load-bearing (Rule 15)
9. Steps to reproduce: one action per step, copy-pasteable (Rule 10)
10. Executive summary ≤ one page (Rule 10)
11. Severity counts in executive summary match actual finding list
12. No severity labels in titles, no internal slugs/IDs anywhere, no Coverage Summary, no Finding Cross-Reference (Rules 16–19)
13. Findings sharing the same root cause are consolidated through grouped report data — one vulnerable component, one finding, with siblings only as downstream outcomes (Rule 18)

## Review-and-Fix QA Mode

When the operator dispatches report-writer in review-and-fix QA mode, load the existing `$ENGAGEMENT_DIR/report.md`, pull the same backend report state, and run the 13 checks above against the rendered report.

- Fix report-local failures directly in `report.md`: wording, structure, counts, missing annotations, overlong evidence, title echoes, passive voice, and non-load-bearing sentences.
- Return `QA PASS` only when all 13 checks pass after fixes.
- Return `QA BLOCKED` when the report cannot be corrected without new backend state: missing evidence, missing remediation, unresolved duplicate findings, severity/CVSS mismatch, or a finding that no longer belongs in final output. Include exact finding slugs and the required operator action.

### Stale-text scrub (runs before every QA pass)

Per `agent/rules/hunting.md` §21, no finding's `summary` or `details` text may contradict the current state. Stale narrative ("severity adjusted from X to Y" when severity is no longer Y, "originally rated as Z" after the rating shifted twice, "merged from W" after W was split off, "previously high" / "downgraded to medium" / "upgraded to high" mismatched against the current `severity` field) is invisible to status fields and ends up verbatim in `report.md`.

Run this scan against the backend BEFORE rendering the report so the underlying findings are clean — fixing it in `report.md` alone leaks back the next time the report is regenerated.

```bash
for slug in $(vigil assess list-findings --status active --json | jq -r '.[].slug'); do
  hit=$(vigil assess fetch findings/$slug --jq '.summary,.details' \
    | grep -iE 'adjusted from|originally rated|previously (high|medium|low)|severity (was|changed)|merged from|downgraded to|upgraded to')
  if [ -n "$hit" ]; then
    echo "==> stale text in $slug:"
    echo "$hit"
  fi
done
```

For each hit, fix the source-of-truth on the finding (NOT in `report.md`):

```bash
vigil assess update-finding <slug> \
  --summary "<rewritten summary without stale narrative>" \
  --inline '{"details": { ... rewritten details ... }}' \
  --reason "stale-text scrub before report QA"
```

The field name on `update-finding --inline` is `details` (dict), not `details_json`. Re-run the scan after the fix to confirm zero hits, then proceed with the 13 checks. `QA BLOCKED` if any finding still carries stale text after the fix attempt.

## Publish After QA Pass

Run these publication steps only after the operator confirms the report QA gate passed:

1. **Emit a runtime event** so the orchestrator and UI know the artifact exists.
   For red engagements and blue verified-incident reports:
   ```bash
   vigil assess emit-event \
       "report.generated" \
       "report" \
       "report.md" \
       "report-writer" \
       "Report generated with N findings"
   ```
   For blue closeout artifacts (false-positive, benign, no-impact, or inconclusive):
   ```bash
   vigil assess emit-event \
       "closeout.generated" \
       "report" \
       "closeout.md" \
       "report-writer" \
       "Closeout generated"
   ```
2. **Update finding workflow status to `reported`** for all findings included in the report:
   ```bash
   # For each finding slug included in the report, use the finding-specific helper so the
   # workflow transition stays explicit at the command line:
   vigil assess update-finding VA-003 \
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

## Blue Mode

When the active engagement is `engagement_type=blue`, the report-writer loads the
template at `agent/skills/report-generation/templates/blue.md` instead of the default
red template above. Red template behavior is unchanged — the blue template is a
parallel file the dispatch points at by name, not a fork of this skill.

Differences from red mode:

- **Disposition vocabulary** — blue uses `verified | false_positive | downgraded | escalated`
  (the canonical four-value vocab written verbatim to `details_json.disposition`). Findings
  with `false_positive` are excluded from the report body but appear in Appendix B's audit
  trail; their artifacts remain in the index marked scratch.
- **Citation vocabulary** — MITRE ATT&CK technique IDs (e.g., `T1078.004`, `T1098.002`)
  replace CWE / OWASP / CVSS. Severity is set from MITRE impact + proved blast radius
  per `agent/rules/triage.md` §2, not from CVSS vectors.
- **Scope unit** — tenant, not host. Pull `scope.json:tenant_reference_paths[]` for the
  tenant-ref citations the report cross-references; never cite cross-tenant artifacts.
- **PII handling** — sections 1–10 carry no PII. PII references (UPN-to-human mappings,
  message bodies, credential fragments, IP/UPN combinations) live in Appendix B, which
  is delivered separately on an encrypted channel.
- **Forbidden vocabulary** — no "PoC", "exploit chain", "weaponized", "Steps to
  Reproduce" (red framing). Blue uses "evidence reproduction" (artifact-id-cited
  command), "kill-chain stage", "adversary capability".
- **Closeout artifact** — every blue engagement ends with a customer-facing
  artifact. False-positive, benign, no-impact, or inconclusive outcomes use
  `closeout.md`; verified incidents use `report.md`.
- **Closing sequence** — after the rendered closeout/report passes the same post-generation
  self-review checks listed above, register the rendered file as an artifact:
  ```bash
  vigil assess artifact register closeout.md \
    --kind ir_closeout \
    --agent-id <report-writer-agent-id>

  vigil assess artifact register report.md \
    --kind ir_evidence \
    --finding <slug-list-or-engagement-ref> \
    --agent-id <report-writer-agent-id>
  ```
  Then run the existing `Publish After QA Pass` steps. Emit `closeout.generated`
  for `closeout.md` or `report.generated` for `report.md`, mark findings terminal,
  and transition phase to `complete`.

Dispatch invocation (worked example):

```bash
vigil blue report --engagement-key <key>
vigil blue closeout --engagement-key <key>
# internally dispatches:
# vigil assess agent start \
#   --role report-writer \
#   --skills report-generation \
#   --task "Render blue incident report from durable backend state. Load
#           template at agent/skills/report-generation/templates/blue.md.
#           Pull findings, timeline, artifacts, containment actions per the
#           template's macros."
```

The macros section at the bottom of `templates/blue.md` lists the exact backend queries
(`list-report-findings`, `fetch activity-entries`, `artifact search`,
`list-command-runs --phase respond`, `agent list`, `agent render-handoff`,
`check-report-readiness`) the writer runs to populate each template section.

## Extended Resources

- `agent/references/runtime-guides/engagement-methodology.md` — methodology narrative source
- `agent/references/disclosure-email-format.md` — email disclosure format and rules
- `agent/references/bugbounty-submission-format.md` — bug bounty submission format
- `agent/references/examples/` — working examples for both output modes
- `agent/skills/report-generation/templates/blue.md` — blue incident report template
