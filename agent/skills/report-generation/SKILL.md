---
name: report-generation
description: Backend-first engagement report structure, generation procedure, and formatting guidelines
origin: Vigil
---

# Report Generation

## When to Activate

- Phase 7/8 (Report) — operator dispatches report-writer after Verify and exploit work complete
- On-demand interim report requested by the operator mid-engagement

**Default closeout: per-finding submissions.** For red, code, and android engagements, the default
terminal deliverable is a per-finding submission drafted via `vigil assess export submission`, not
a `report.md` monolith — see "Submission-First Closeout" below. The `report.md` structure later in
this file is retained for on-demand internal summaries (an operator or client wants one narrative
document mid-engagement) but is no longer the default final artifact. Blue incident reporting is
unaffected by any of this — see "Blue Mode" at the bottom of this file, unchanged.

**Dispatched in default per-finding submission mode? Read only two sections below:** "Proof Standard
by Finding Class" and "Submission-First Closeout". Everything between "Report Structure (Legacy
Internal Report — On-Demand Only)" and "Publish After QA Pass (Legacy Internal Report)" — the
`report.md` template, its generation procedure, and its publish sequence — applies only when the
operator explicitly dispatched internal-report or blue mode. Skip that whole span; nothing in it is
needed to draft, QA, or publish a submission.

## Query Backend First (internal report / blue only)

Per-finding submissions use the lighter pull in `agent/agents/report-writer.md` "Per-Finding
Dispatch" instead of this section — skip to "Submission-First Closeout" below.

Before writing an internal `report.md` or a blue report, pull the canonical state from the
orchestrator API. Use the helper script or `curl` — never query the SQLite database file directly.

```bash
# Final report gate and grouped final-mode findings
vigil assess check-phase-readiness --phase report
vigil assess finding report --mode final --json

# Interim grouped findings when the operator explicitly wants a draft before final readiness passes
vigil assess finding report --mode draft --json

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

The `finding report --json` helper returns grouped report findings. Root and sibling finding rows include:
- `report_id` — sequential `001`, `002`, etc. (for the report body)
- `slug` — the original backend slug, e.g. `VA-003` (for publish-mode lifecycle updates only; do not expose in the report body)
- `cvss_vector`, `cvss_score` — projected from parsed `details`
- `remediation`, `steps_to_reproduce`, `cwe_id`, `owasp_category` — projected from parsed `details`
- `impact`, `evidence_detail` — projected from parsed `details`

> **One public field shape.** Finding reads and writes both expose the parsed object as `details`; `details_json` is an internal database column and is never a second API format. A `--payload-file` document nests the object as `{"details": {...}, "expected_row_version": <n>}`; `--details-inline` takes the object directly as `{...}`. If a prompt, fixture, or recipe teaches public `details_json`, flag it as drift. **`--payload-file` is the default way to write authored prose** — Evidence and Steps to Reproduce routinely carry single quotes, double quotes, newlines, and backtick fences that corrupt `--details-inline`'s shell-single-quoted JSON, and a file has no shell quoting to corrupt. See "Submission-First Closeout" below for the full write-back procedure and payload shape.
- top-level `groups` and `standalone`; each group has a `root` finding and `siblings`

Sibling rows include
`root_cause_effect`, `root_cause_note`, and `sibling_order`. Use this projection
to keep one root-cause narrative while still naming downstream outcomes and residual
standalone paths.

Use these structured fields directly. Recalculate CVSS or remediation only when the
proved impact at report time materially differs from what was recorded at validation.
The verifier owns the evidence/impact/remediation story (per `agent/references/finding-fp-and-severity-gate.md`
and the Report-ready story gate in `agent/agents/vulnerability-analyst.md`); the report-writer **formats**
that authored story and does not re-derive the impact analysis — the narrow recalculation above (proved
impact materially changed at report time) is the only exception.

## Severity Definitions

| Severity | Criteria |
|----------|----------|
| **CRITICAL** | Full system compromise, unauthenticated RCE, mass data breach. CVSS 9.0-10.0. |
| **HIGH** | Direct CIA impact, exploitable with minimal effort. Data breach, auth bypass. CVSS 7.0-8.9. |
| **MEDIUM** | Requires conditions or chaining. Stored XSS, IDOR on non-critical data, limited SQLi. CVSS 4.0-6.9. |
| **LOW** | Limited impact or hard to exploit. Reflected XSS, verbose errors. CVSS 0.1-3.9. |
| **INFO** | No direct security impact. Observations, best-practice deviations, tech disclosures. CVSS 0.0. |

## Writing Style

Follow `agent/rules/reporting.md` for all writing rules — concise prose,
evidence formatting, remediation specificity, filler/padding, and section length limits.

**Audience:** Technical reader who knows vulnerability classes. Assume familiarity with standard terms (XSS, SQLi, IDOR, SSRF, etc.).

**Executive summary exception:** The executive summary is for non-technical stakeholders.
Use business language there. "An attacker can download all customer records" not "IDOR on /api/users."

## Submission-First Closeout (Default Procedure)

This is the default closeout for red, code, and android engagements: each finding intended for
final delivery becomes a standalone submission, not a section of a bundled `report.md`. It reuses
the same evidence bar as the legacy report path — "Pre-Report Validation", "CVSS Sourcing and
Calculation", and "Proof Standard by Finding Class" below apply per-finding here exactly as they
do for the internal report — plus a mandatory blind triage gate before anything external ships.

Canonical finding state owns claims, proof, and corrections. The default layout and field mapping
live in `agent/references/submission-format.md`; use its recipient-specific capture path when the
operator selects another presentation. OPERATOR DETAILS remains local reference material and never
enters the outgoing body. Preserve exact captured evidence values in authored proof.

The canonical submission closing procedure is `agent/agents/report-writer.md` "Mandatory Closing
Sequence". Follow it rather than maintaining a second ordering here. Check proof readiness, author
canonical finding fields, prepare the exact outgoing package, record Pass 1 QA, obtain independent
blind review when required, publish, and finish the durable handoff. Recipient-specific body capture
and presentation guidance are described in `agent/references/submission-format.md` "Recipient-specific
outgoing body". Run `vigil assess contract export submission` for the executable options and gates.

Use `finding update --payload-file <path.json>` for prose, code, quotes, and newlines. A patch uses
`details` (not `details_json`), merges those keys, and requires `expected_row_version`. Do not combine
a payload file with content flags. Include `notes_mode` when patching notes. Example shape:

```json
{
  "summary": "<receipt-backed summary>",
  "details": {
    "steps_to_reproduce": "1. <recorded action>\n2. <recorded action>",
    "repro_runs": [123],
    "evidence": "<annotated proof, exact captured values>",
    "impact": "<proved reach and preconditions>",
    "remediation": "<specific control>"
  },
  "expected_row_version": 1,
  "reason_text": "Author verified report content",
  "source_name": "report-writer"
}
```

`details.evidence` is authored prose; durable proof separately requires the indexed, present,
finding-linked artifact named by `evidence_ref`. Linked runs come from explicit evidence links;
search narrowly for missing reproducing runs and link them before writing. All commands, argv, and
response values must trace to recorded reproduction runs. Internal-ID hygiene warnings block final
capture; prose advisories do not. Resolve source claim changes through independent equivalence review
or verification, never a correction memo outside canonical finding state.

## Report Structure (Legacy Internal Report — On-Demand Only)

The structure below produces `$ENGAGEMENT_DIR/report.md`: one bundled narrative document covering
every finding. It is no longer the default closeout (see "Submission-First Closeout" above) — use
it only when the operator explicitly wants a single internal summary document, e.g. an interim
client update mid-engagement. For final closeout on red/code/android engagements, use per-finding
submissions instead.

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

Length discipline: see `agent/rules/reporting.md` Rule 10.

````markdown
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
````

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

1. **Readiness gate:** for final reports, run `vigil assess check-phase-readiness --phase report`. If it fails, stop and flag the blockers to the operator.
2. **Root-cause consolidation check:** use `vigil assess finding report --mode final --json` and `vigil assess check-phase-readiness --phase report` to confirm intentional root/sibling groups are already represented. If two reportable findings still share the same vulnerable component or configuration and are not grouped, stop and ask the operator to run `vigil assess finding link` or merge them. Apply the BugCrowd/HackerOne standard: one root cause, one submission.
3. **CVSS↔severity mismatch:** verify each finding's `cvss_score` falls within its `severity` range (critical 9.0–10.0, high 7.0–8.9, medium 4.0–6.9, low 0.1–3.9, info 0.0). Flag any mismatches.
4. **Missing required fields:** flag findings where `evidence`, `impact`, `steps_to_reproduce`, `remediation`, `cvss_score`, or `cvss_vector` are empty or absent (blue findings instead require a non-empty `mitre_techniques` list).
5. **Unbacked or unbindable reproduction:** flag any finding whose `steps_to_reproduce` carries no `repro_runs` behind it, or whose steps contain unbound `<PLACEHOLDER>` values (or one placeholder reused across different objects). **Stop and flag — never reconstruct the steps from handoffs, chain narratives, or the finding's prose.** You cannot run probes, so what you would assemble is a plausible narrative, not a transcript; it will read as followable to everyone downstream, including the blind triage, and only the specialist that held the session can supply the real thing. `export submission` names local render gaps as advisories and adds a `[NEEDS: details.repro_runs]` marker in a draft. New authored run IDs must resolve, and final publication requires a current independent reproduction decision covering them.
6. **Required information per finding:** verify every included finding carries: target/feature/affected asset; bug class and exact endpoint or component; request method or triggering action; attacker context (and victim context for cross-user issues); exact request, sequence, or reproduction steps; exact response or artifact proving impact; data exposed, state changed, or access gained; severity rationale and CVSS factors where the report uses CVSS; recommended fix or control that failed.
7. **Verification lifecycle:** flag any report-candidate finding whose `verification_status` is not `confirmed` or `downgraded` (`unreviewed`, `disputed`, `pending_runtime_proof`, `blocked`, and `false_positive` are not report-ready — send it back to the operator or `incident-verifier` rather than including it).
8. **Merge/root-cause pointer integrity:** flag a finding whose `workflow_status` is `merged` without a `merged_into_finding_id` (or vice versa), whose merge target does not exist or points back to itself, or whose `root_cause_key` groups it with a sibling whose own root finding is not itself in the reportable set. This is a backend pointer-integrity check, distinct from the editorial consolidation call in `agent/rules/reporting.md` Rule 18 — resolve it with `vigil assess finding merge` / `vigil assess finding link`, not by rewriting prose.

Only proceed to report generation after validation passes or the operator resolves flagged issues.

## CVSS Sourcing and Calculation

When a finding was validated by `vulnerability-analyst` or `exploit-developer`, the CVSS data may already be stored in the finding's `details` object as `cvss_vector` and `cvss_score`. Use that pre-computed pair as the starting point. Recalculate when the final report scope or proved impact changes a base metric, or the recipient requires a different supported version. CVSS v3.1 and v4.0 use different metrics and scoring algorithms; calculate the pair afresh when changing versions. The shared specialist core owns the supported vector/score contract.

For CVSS v3.1, calculate from the proved attack, not from the imagined worst case:

- `AV`: Network for internet-reachable issues
- `AC`: Low for stable repro, including a race reliably won by ordinary concurrent requests (per the CVSS 3.1 spec, Attack Complexity reflects conditions beyond the attacker's control, not merely that timing is involved). High only when success depends on a narrow window, kernel-level precision, or a chain fragile enough that most attempts fail
- `PR`: None / Low / High based on actual attacker starting point
- `UI`: None unless a victim must click, view, or perform an action
- `S`: Changed only when impact crosses into another trust domain
- `C/I/A`: score only what the proof demonstrates

For CVSS v4.0, distinguish attack complexity (`AC`) from deployment/execution requirements
(`AT`), use its user-interaction values (`N`, `P`, `A`), and assess vulnerable-system
(`VC/VI/VA`) and subsequent-system (`SC/SI/SA`) impacts separately. Do not map v3.1 `S` or
`C/I/A` mechanically into v4.0. Preserve every supported precondition in the report regardless
of which version the recipient requests.

Common patterns:

- `IDOR read PII with normal auth`: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` → around Medium
- `Unauthenticated admin creation or auth bypass`: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → Critical
- `SSRF to metadata or privileged internal API`: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` → Critical

## Proof Standard by Finding Class

Each finding class has a minimum evidence bar. If the evidence does not meet this bar, the finding is not ready for the report — send it back to the operator.

**No-theory rule:** `rules/hunting.md` rule 2 applies to report inclusion. A finding without execution proof from the vendor's code is theory — send it back to the operator rather than including it. Source code analysis supports the description but does not replace a POC that calls the vulnerable function and shows the output.

| Finding Class | Minimum Proof |
|---|---|
| IDOR / Broken Access Control | Request as attacker → response containing victim's data or state change on victim's resource. Both contexts (attacker auth, victim data) must be visible. |
| SQL Injection | Extracted data the attacker should not have, or demonstrated control flow (sleep timing with exact delta, UNION output, error-based extraction). Not just `sqlmap: injectable`. |
| XSS (Stored) | Payload rendered in a victim's authenticated session with DOM proof or session context. |
| XSS (Reflected) | Payload reflected in response with content-type and context showing execution. |
| Auth Bypass | Privileged action performed without valid credentials or with insufficient privilege. Show the unauthorized response containing privileged data or confirming the state change. |
| RCE | Command output from the target (hostname, id, file read). Not just "the payload was accepted." |
| SSRF | Response body from an internal resource, DNS/OOB callback with correlation ID, or cloud metadata content. |
| File Read / Path Traversal | Contents of a file outside the web root (e.g., /etc/passwd, application config). |
| Information Disclosure | The specific sensitive data exposed, with confirmation it is not intentionally public. |
| CSRF | State change on victim's account triggered from attacker-controlled origin, with before/after proof. |
| Buffer Overflow / Memory Safety (fuzz-confirmed) | The crash input plus an ASAN/UBSAN report showing the invalid access (out-of-bounds read/write, use-after-free), with the reproducing harness command. Not just "the fuzzer found a crash." |
| Static Taint-Path Finding (code review, no crash) | Concrete `poc_code` that calls the vulnerable entrypoint and shows the corrupted or leaked value. Source reading alone is theory — the no-theory rule applies here as everywhere else. |

## Generation Procedure (Legacy Internal Report)

Steps below build `report.md` (see "Report Structure" above for when this mode applies instead of
the default submission-first closeout).

1. **Pull backend state** using the queries in "Query Backend First" above
2. **Use `vigil assess finding report --mode final --json`** as the authoritative final finding structure, or `vigil assess finding report --mode draft --json` for interim drafts. Render one section per group root; include siblings as downstream outcomes under the root narrative, and explicitly call out `eliminates_attack_path` siblings as residual remediation paths.
3. **Use pre-computed CVSS** from finding details. Recalculate only if proved impact at report time would shift at least one CVSS base metric (AV, AC, PR, UI, S, C, I, A) by one or more levels versus the validated vector
4. **Use pre-computed remediation** from finding details. Augment only when one of these is true: (a) the chain revealed a prerequisite weakness the original remediation did not address, (b) the exploit bypassed the suggested fix, or (c) the chain spans multiple findings and fixing this one alone does not close the chain
5. Populate all template fields (flag missing evidence with `[EVIDENCE MISSING]`, never fabricate)
6. Build attack path narrative from `attack-chains` endpoint data and enrich it with `credentials` / `access-records` when those records explain the authenticated foothold or post-auth scope
7. Write executive summary LAST — it depends on the complete finding set and chain analysis
8. Verify: severity counts in executive summary match the actual finding list

## After Writing the Draft (Legacy Internal Report)

1. **Write report to `$ENGAGEMENT_DIR/report.md`**
2. **Run the post-generation self-review below**
3. **Fix report-local failures before returning to the operator**
4. **Return the completed checklist and current QA status**

Publication (`report.generated`, `closeout.generated`, marking findings `reported`) belongs after the operator dispatches a fresh report-writer in review-and-fix QA mode and receives `QA PASS` — lifecycle transitions before QA make an unreviewed report look final.

## Post-Generation Self-Review

Runs against either deliverable: `report.md` (legacy internal report) or a drafted
`submissions/<slug>/submission.md` (submission-first closeout, step 4 above). Verify every finding
against `agent/rules/reporting.md`. If any check fails, fix it at the source.

The check items are the **one consolidated pre-submission / report QA checklist** in
`agent/references/submission-format.md` — grouped into Structure & mandatory fields · Proof &
evidence · PII & internal identifiers · Human voice / AI-tell elimination, each row tagged `[both]` /
`[submission]` / `[report]`. Run it against the deliverable: apply the `[both]` and `[report]` rows
for an internal `report.md`, and every row for a submission. Both QA paths — the submission path
(step 4 above) and the internal-report path (Review-and-Fix QA Mode below) — run against that one
checklist, so they cannot drift apart.

## Review-and-Fix QA Mode

When the operator dispatches report-writer in review-and-fix QA mode, load the existing rendered
artifact — `$ENGAGEMENT_DIR/report.md` for the legacy internal report, or
`$ENGAGEMENT_DIR/submissions/<slug>/submission.md` for a submission-first closeout — pull the same
backend report state, and run the consolidated checklist above against it. This is Pass 1 of the
blind-triage gate (`agent/skills/blind-triage/SKILL.md`) when the artifact is a submission.

- Fix local failures directly in the artifact: wording, structure, counts, missing annotations, overlong evidence, title echoes, passive voice, and non-load-bearing sentences.
- Return `QA PASS` only when all applicable checks pass after fixes.
- Return `QA BLOCKED` when the artifact cannot be corrected without new backend state: missing evidence, missing remediation, unresolved duplicate findings, severity/CVSS mismatch, or a finding that no longer belongs in final output. Include exact finding slugs and the required operator action.

### Stale-text scrub (runs before every QA pass)

Per the "Stale-text scrub clean" Definition-of-Done item in `agent/phases/phase-8-report.md`, no finding's `summary` or `details` text may contradict the current state. Stale narrative ("severity adjusted from X to Y" when severity is no longer Y, "originally rated as Z" after the rating shifted twice, "merged from W" after W was split off, "previously high" / "downgraded to medium" / "upgraded to high" mismatched against the current `severity` field) is invisible to status fields and ends up verbatim in `report.md`.

Run this scan against the backend BEFORE rendering the report so the underlying findings are clean — fixing it in `report.md` alone leaks back the next time the report is regenerated.

```bash
for slug in $(vigil assess finding list --status active --json | jq -r '.[].slug'); do
  hit=$(vigil assess fetch findings/$slug --jq '.summary,.details' \
    | grep -iE 'adjusted from|originally rated|previously (high|medium|low)|severity (was|changed)|merged from|downgraded to|upgraded to')
  if [ -n "$hit" ]; then
    echo "==> stale text in $slug:"
    echo "$hit"
  fi
done
```

For each hit, fix the source-of-truth on the finding (NOT in `report.md`) via `--payload-file` — the
default write path (see "Read vs write asymmetry" and "Submission-First Closeout" above):

```json
{
  "summary": "<rewritten summary without stale narrative>",
  "details": { "...": "rewritten details" },
  "reason_text": "stale-text scrub before report QA",
  "expected_row_version": <current row_version>
}
```
```bash
vigil assess finding update <slug> --payload-file <path.json>
```

Re-run the scan after the fix to confirm zero hits, then proceed with the consolidated checklist. `QA BLOCKED` if any finding still carries stale text after the fix attempt.

## Publish After QA Pass (Legacy Internal Report)

This is the legacy `report.md` publish sequence. For the default submission-first closeout, publish
is step 6 of "Submission-First Closeout" above (`export submission` non-draft, artifact registration,
`submission_status` left untouched by the command). Run the steps below only for the on-demand
internal `report.md`, only after the operator confirms the report QA gate passed:

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
   vigil assess finding update VA-003 \
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

Output path: `$ENGAGEMENT_DIR/submissions/<slug>/disclosure.txt`

The `submissions/<slug>/` directory is the staging tree for all external deliverables for that finding (see "Per-Finding Submission Staging" below).

## Per-Finding Submission Staging

Each finding closed out via submission gets a dedicated staging directory under the engagement root:

```
$ENGAGEMENT_DIR/submissions/<slug>/
    submission.md            # the drafted submission text (platform body)
    submission-context.json  # export submission's sourcing record ([NEEDS: ...] markers, evidence used)
    disclosure.txt           # or: the disclosure email text (email disclosure mode)
    poc.<ext>                # any PoC artifact referenced in the submission
```

Rules for the staging tree:
- The directory name is the finding slug (e.g., `submissions/VA-003/`). The slug is internal and never appears inside the submission body — only in the directory name.
- `submission.md` maps to the matching platform template (`bugcrowd.md` / `hackerone.md` / `direct.md`) — title, VRT/weakness (omitted for `direct`), severity, PoC block, body. The operator copies content from it into the platform's submission form, or delivers it directly to the client for `direct`.
- PoC artifacts live alongside `submission.md` in the same directory — NOT under `tools/exploit-state/pocs/`, which is the exploitation artifact store, not a submission staging area.
- The directory is created by `export submission --draft`; it does not exist for findings that have not been drafted for external/final closeout.

## Submission Status Lifecycle

`submission_status` is an independent axis on every finding, orthogonal to `workflow_status`. A finding can be `workflow_status=reported` (included in the internal report) AND `submission_status=accepted` (confirmed by the program) simultaneously — setting one never changes the other.

`export submission` never sets this field — draft and final modes both omit `submission_status`
entirely, so `create` lands `none` and `upsert` preserves whatever is already there. Only the
transitions below, run explicitly once the finding is actually delivered, change it. For `direct`
mode (no external program), read "program" below as "client" — the same post-delivery states
apply to a company-facing writeup.

Allowed values: `none` (default) | `submitted` | `accepted` | `needs_info` | `rejected` | `duplicate` | `withdrawn`

**Every move off `none` must name the report it refers to.** The backend rejects a transition with
no `submission_ref` (400: "a submission state with no referent cannot be joined back to the report
it describes"), so the FIRST transition carries `--submission-ref <program report id>` — pair it
with `--submission-platform` and `--submission-url` while you have them. Later transitions inherit
the stored ref and only need it when it changes. Read `vigil assess contract finding update` for the
full field list.

`withdrawn` is the researcher-initiated retraction — the one state that asserts YOUR action rather
than a program decision, so it additionally requires `details.withdrawal_reason` (400 without it).
Use it instead of `rejected`, which asserts a third-party decision that never happened.

Lifecycle transitions via the CLI:

```bash
# 1. After staging submission.md and submitting to the platform. The FIRST transition
#    off `none` establishes the submission identity; later ones inherit it.
vigil assess finding update <slug> \
  --submission-status submitted \
  --submission-platform <bugcrowd|hackerone|direct> \
  --submission-ref <program report id> \
  --submission-url <report url> \
  --reason "Submitted to program on <date>"

# 2. Program confirms the finding:
vigil assess finding update <slug> \
  --submission-status accepted \
  --reason "Program accepted and assigned bounty"

# 3. Program requests more information — triggers a targeted reply:
vigil assess finding update <slug> \
  --submission-status needs_info \
  --reason "Triager requested reproduction steps for the auth bypass"

# 4. Program closes as known or duplicate:
vigil assess finding update <slug> \
  --submission-status rejected \
  --reason "Program: out of scope"
vigil assess finding update <slug> \
  --submission-status duplicate \
  --reason "Program: duplicate of existing report"

# 5. You retract the report yourself (withdrawn REQUIRES details.withdrawal_reason):
vigil assess finding update <slug> \
  --submission-status withdrawn \
  --details-inline '{"withdrawal_reason":"Re-tested against current build; the bypass no longer reproduces"}' \
  --reason "Withdrawn by researcher"
```

The `needs_info` state is the trigger for a targeted reply, authored through the reply flow and written durably onto the finding's reply record — not a `submission.md` hand-edit, which does not survive the next `export submission --overwrite`. Run the reply flow instead: `vigil assess export reply <slug> --in-response-to "<triager's question>" --platform <p> --draft`, author the answer per `agent/references/reply-format.md`, then `vigil assess record-reply <slug> --seq N ...` to write it back durably. Once sent, `record-reply --seq N --sent --set-submission-status submitted` closes the loop in one call — `record-reply` never sets `submission_status` on its own, so `--set-submission-status` is the explicit opt-in for the `needs_info → submitted` transition. See "Reply mode" in `agent/agents/report-writer.md` for the full closing sequence.

`workflow_status` is unchanged by any submission outcome. A finding that the program rejects as duplicate still carries `workflow_status=reported` in the internal engagement record — the internal report is complete regardless of program outcome.

## Blue Mode

When the active engagement is `engagement_type=blue`, the report-writer loads the
template at `agent/skills/report-generation/templates/blue.md` instead of the default
red template above. Red template behavior is unchanged — the blue template is a
parallel file the dispatch points at by name, not a fork of this skill.

Differences from red mode:

- **Disposition vocabulary** — blue uses `verified | false_positive | downgraded | escalated`
  (the canonical four-value vocab written verbatim to `details.disposition`). Findings
  with `false_positive` are excluded from the report body but appear in Appendix B's audit
  trail; their artifacts remain in the index marked scratch.
- **Citation vocabulary** — MITRE ATT&CK technique IDs (e.g., `T1078.004`, `T1098.002`)
  replace CWE / OWASP / CVSS. Severity is set from MITRE impact + proved blast radius
  per `agent/rules/triage.md` §2, not from CVSS vectors.
- **Scope unit** — tenant, not host. Pull `scope.json:tenant_reference_paths[]` for the
  tenant-ref citations the report cross-references; never cite cross-tenant artifacts.
- **PII handling** — sections 1–10 carry no PII. PII references (UPN-to-human mappings,
  message bodies, exact credentials, IP/UPN combinations) live verbatim in Appendix B,
  which is delivered separately on an encrypted channel and remains operator-visible.
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
#   --no-target-traffic \
#   --prompt-context-json '<wrapper-derived complete report context>' \
#   --task "Render blue incident report from durable backend state. Load
#           template at agent/skills/report-generation/templates/blue.md.
#           Pull findings, timeline, artifacts, containment actions per the
#           template's macros."
```

The blue wrapper derives that complete prompt context from the active scope and
passes it inline; it does not rely on placeholders or an operator-created file.

The macros section at the bottom of `templates/blue.md` lists the exact backend queries
(`finding report`, `fetch activity-entries`, `artifact search`,
`command-run list --phase respond`, `agent list`, `agent render-handoff`,
`check-phase-readiness --phase report`) the writer runs to populate each template section.

## Extended Resources

- `agent/references/runtime-guides/engagement-methodology.md` — methodology narrative source
- `agent/references/disclosure-email-format.md` — email disclosure format and rules
- `agent/references/submission-format.md` — submission format (platform-agnostic reference behind the templates below)
- `agent/references/reporting/bugcrowd-vrt.md` — Bugcrowd VRT leaf/priority/CVSS offline lookup
- `agent/references/reporting/hackerone-weaknesses.md` — HackerOne CWE weakness offline lookup
- `agent/references/examples/` — working examples for both output modes
- `agent/skills/report-generation/templates/bugcrowd.md` — Bugcrowd submission template
- `agent/skills/report-generation/templates/hackerone.md` — HackerOne submission template
- `agent/skills/report-generation/templates/direct.md` — direct/company-facing writeup template (no external program)
- `agent/skills/report-generation/templates/blue.md` — blue incident report template
