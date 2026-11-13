---
name: report-generation
description: Backend-first engagement report structure, generation procedure, and formatting guidelines
origin: Vigil
---

# Report Generation

## When to Activate

- Phase 8 (Report): the operator dispatches report-writer after Verify and exploit work complete.
- An on-demand interim report the operator requests mid-engagement.

**Default closeout: per-finding submissions.** For red, code, and android engagements, the terminal
deliverable is a per-finding submission rendered by `vigil assess export submission` ("Submission-First
Closeout" below). The `report.md` structure serves on-demand internal summaries, when an operator or
client wants one narrative document. Blue incident reporting follows "Blue Mode" at the bottom.

**Dispatched in per-finding submission mode? Read only two sections:** "Proof Standard by Finding
Class" and "Submission-First Closeout". Everything from "Report Structure (Internal Report — On-Demand
Only)" through "Publish After QA Pass" applies only when the operator dispatched internal-report or
blue mode.

## Query Backend First (internal report / blue only)

Per-finding submissions use the lighter pull in `agent/agents/report-writer.md` "Per-Finding
Dispatch" instead. For an internal `report.md` or a blue report, pull canonical state through the CLI,
never the SQLite file:

```bash
vigil assess check-phase-readiness --phase report   # final report gate
vigil assess finding report --mode final --json     # grouped findings (exits non-zero while blockers remain)
vigil assess finding report --mode draft --json     # interim draft before readiness passes
vigil assess chain list --json                      # chains: narrative, stated severity, step verification
vigil assess fetch credentials                      # credentials captured during exploitation
vigil assess fetch access-records                   # footholds confirmed by credential validation
vigil assess fetch surfaces
vigil assess fetch summary
```

`finding report --json` returns top-level `groups` (each a `root` finding and its `siblings`) and
`standalone`. Rows carry `report_id` (sequential `001`, … for the report body), `slug` (the backend
slug, used only for publish-mode lifecycle updates and never shown in the body), and the parsed
`details` projections: `cvss_vector`, `cvss_score`, `remediation`, `steps_to_reproduce`, `cwe_id`,
`owasp_category`, `impact`, `evidence_detail`. Sibling rows add `root_cause_effect`,
`root_cause_note`, and `sibling_order`, so one root-cause narrative can still name downstream outcomes
and residual standalone paths.

The verifier owns the evidence, impact, remediation, and CVSS vector
(`agent/references/finding-fp-and-severity-gate.md`); the report-writer formats that story. When the
proved impact does not match the recorded severity or vector, return the finding to the operator,
because a vector or band change invalidates the verdict ("CVSS Sourcing and Calculation").

## Severity Definitions

Severity is the verifier's stored value and the report never re-rates a finding; class-level
calibration lives in `agent/references/finding-fp-and-severity-gate.md`. Bands pair with CVSS as
Critical 9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, Low 0.1-3.9, Info 0.0.

## Writing Style

`agent/rules/reporting.md` owns the writing rules. Write for a technical reader who knows the
vulnerability classes. The executive summary is the exception: it is for non-technical stakeholders,
so use business language there ("An attacker can download all customer records", not "IDOR on
/api/users").

## Submission-First Closeout (Default Procedure)

The default closeout for red, code, and android engagements: each finding intended for final delivery
becomes a standalone submission. "CVSS Sourcing and Calculation" and "Proof Standard by Finding Class"
apply per finding. Before anything external ships, independent reviews check the authored packet:
submission QC by a second report-writer, a cold reproduction rehearsal and any pending claim review by
a verifier, and blind triage for Medium and above. `agent/phases/phase-8-report.md` owns their order.

Canonical finding state owns claims, proof, and corrections. `agent/references/submission-format.md`
owns the layout, field mapping, and recipient-specific capture; `agent/agents/report-writer.md`
"Mandatory Closing Sequence" owns the writer's procedure, including the fabrication boundary; `vigil
assess contract export submission` owns the executable options and gates. This section holds the
write-back shape that procedure points to.

Use `finding update --payload-file <path.json>` for prose, code, quotes, and newlines, because a file
has no shell quoting to corrupt. A patch uses `details` (never `details_json`), merges those keys, and
appends notes unless `notes_mode` says otherwise. Carry the `expected_row_version` you read the finding
at: a file that changes the claim (summary, severity, evidence_ref, steps, evidence, impact and the
other claim details) or uses replace/rotate is refused without it. Name the editing dispatch in
`dispatch_agent_id`, or pass `--agent-id` beside the file; content flags cannot be combined with a
payload file. Example shape:

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
  "dispatch_agent_id": "<your report-writer agent id>",
  "reason_text": "Author verified report content",
  "source_name": "report-writer"
}
```

`details.evidence` is authored prose; durable proof separately requires the indexed, present,
finding-linked artifact named by `evidence_ref`. Linked runs come from explicit evidence links, so
search narrowly for a missing reproducing run and link it before writing. A changed claim is settled by
an independent claim-equivalence review or fresh verification, recorded on the finding where every
render reads it.

## Report Structure (Internal Report — On-Demand Only)

The structure below produces `$ENGAGEMENT_DIR/report.md`: one narrative document covering every
finding, used when the operator wants a single internal summary such as an interim client update.

### Section length ceilings

Ceilings, not targets: a Description that uses one sentence because one sentence carries the fact is
better than one padded to four.

| Section | Ceiling |
|---------|---------|
| Description | 2-4 sentences |
| Steps to Reproduce | Numbered steps, one action per step, no narrative between steps. Each step that sends a request includes the request block and the relevant response excerpt (truncated to 5-15 lines) inline — proof lives inside the step that produces it. |
| Impact | 1-2 sentences |
| Remediation | 1-2 sentences |

A finding that needs more space is probably two findings. The executive summary is one page maximum.
These ceilings govern `report.md` only; a submission follows `agent/references/submission-format.md`
"Section budgets".

### 1. Executive Summary (ONE PAGE MAX)

Written for the director, VP, or CISO who will not read the rest.

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

[1-2 paragraphs: overall posture in business terms, the most impactful finding as attacker outcome
with business consequence, the worst verified attack chain, one prioritized recommendation. Explain
jargon: "SQL injection (direct database access)".]
```

A verified chain is one whose `chain list` row has `all_finding_steps_verified: true` and every step
slug in this report's finding set. Name the most severe one with its stated severity. A chain with an
unverified or undelivered step, or with no finding steps, is not a verified chain: describe it in the
Attack Path Narrative as unproven, never as the summary's headline.

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

````markdown
### 001: [Title] [SEVERITY]
**OWASP:** A03:2021  **CWE:** CWE-89  **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

#### Description
[First sentence: what the attacker gains. Then how, where, auth context.]

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
[Quantified attacker outcome.]

#### Remediation
[Specific technology and control. References: CWE link.]
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

Run these before generating the report body. When one fails, stop and flag it to the operator rather
than fixing or ignoring it, and proceed only once validation passes or the operator resolves it.

1. **Readiness gate.** Run `vigil assess check-phase-readiness --phase report` for drafts and final
   reports alike. On a draft its blockers are flags: name them to the operator and in the draft, and
   keep drafting. For a final report it (and `finding report --mode final`) blocks candidates that
   are not `confirmed`/`downgraded`, missing structured fields (`evidence`, `impact`,
   `steps_to_reproduce`, `remediation`, the CVSS pair; blue needs `mitre_techniques`), invalid or score-mismatched CVSS vectors, duplicate root-cause or
   location families, and broken merge or root-cause pointers. It lists severity↔band divergence and
   steps without `repro_runs` as advisories; flag those too. Pointer problems resolve through `vigil
   assess finding merge` / `finding link`, not by rewriting prose. An unverified candidate goes back to
   the operator, who re-dispatches `vulnerability-analyst` (red) or `incident-verifier` (blue).
2. **Root-cause consolidation.** Two reportable findings that share a vulnerable component or
   configuration but are not grouped go back to the operator for `finding link` or a merge
   (`agent/rules/reporting.md` Rule 18); the gate sees only matching keys, not the judgment.
3. **Unbacked or unbindable reproduction.** Flag steps with no `repro_runs` behind them (unless the
   `reproduction_basis` is `source`, whose steps trace to the source its receipts observed) and steps
   with an unbound `<PLACEHOLDER>` or one placeholder reused across different objects. Never
   reconstruct steps from handoffs, chain narratives, or finding prose: you cannot run probes, so what
   you would assemble is a plausible narrative rather than a transcript, and it reads as followable to
   every later reviewer, blind triage included. Only the specialist that held the session can supply
   the real steps.
4. **Required information per finding:** affected asset and feature; bug class and exact endpoint or
   component; request method or triggering action; attacker context (and victim context for
   cross-user issues); exact reproduction; the response or artifact proving impact; the data exposed,
   state changed, or access gained; severity rationale; the fix or failed control.

## CVSS Sourcing and Calculation

Report the `cvss_vector` and `cvss_score` the verifier recorded in `details`. The vector is part of the
verified claim: adding or removing it, changing its CVSS version, changing an exploitability metric,
or crossing a band invalidates the verdict and needs a fresh proof run. When the proved impact does not
fit the stored vector, or the recipient requires a different CVSS version, return the finding to the
operator rather than recalculating. The shared specialist core owns the vector/score contract.

A stored vector that overstates the proved attack is a `QA BLOCKED` reason. Score the demonstrated
outcome, not the imagined worst case. Two calls reviewers get wrong: a race reliably won by ordinary
concurrent requests is `AC:L` (Attack Complexity covers conditions beyond the attacker's control, not
the mere presence of timing; `AC:H` needs a narrow window or a chain most attempts lose), and a v4.0
vector is assessed on its own metrics (`AT`, `UI` N/P/A, separate `VC/VI/VA` and `SC/SI/SA`) rather
than mapped mechanically from v3.1 `S` and `C/I/A`. Every supported precondition stays in the report
whichever version the recipient requests.

## Proof Standard by Finding Class

Each finding class has a minimum evidence bar. A finding below it is not ready for the report: send it
back to the operator.

**No-theory rule:** `agent/rules/hunting.md` §2 governs live claims and
`agent/shared-constraints-code.md` §5 owns code-track reachability. A finding without execution proof
from the vendor's code is theory. The exception is a file finding whose `reproduction_basis` is
`source`: its source-observation proof receipts are its verified proof, and its steps cite the source
they observed. Otherwise source analysis supports the description but does not replace a PoC that
calls the vulnerable function and shows the output.

| Finding Class | Minimum Proof |
|---|---|
| IDOR / Broken Access Control | Request as attacker → response containing victim's data or state change on victim's resource. Both contexts (attacker auth, victim data) must be visible. |
| SQL Injection | Extracted data the attacker should not have, or demonstrated control flow (sleep timing with exact delta, UNION output, error-based extraction). Not just `sqlmap: injectable`. |
| XSS (Stored) | Payload rendered in a victim's authenticated session with DOM proof or session context. |
| XSS (Reflected) | Payload reflected in response with content-type and context showing execution. |
| Auth Bypass | Privileged action performed without valid credentials or with insufficient privilege. Show the unauthorized response containing privileged data or confirming the state change. |
| RCE | Command output from the target (hostname, id, file read). Not just "the payload was accepted." |
| SSRF | Response body from an internal resource, cloud metadata content, or a privileged follow-on action through the request. A correlated DNS/OOB callback alone proves the primitive, not impact: it is a lead or `CHAIN REQUIRED`, never report proof. |
| File Read / Path Traversal | Contents of a file outside the web root (e.g., /etc/passwd, application config). |
| Information Disclosure | The specific sensitive data exposed, with confirmation it is not intentionally public. |
| CSRF | State change on victim's account triggered from attacker-controlled origin, with before/after proof. |
| Buffer Overflow / Memory Safety (fuzz-confirmed) | The crash input plus an ASAN/UBSAN report showing the invalid access (out-of-bounds read/write, use-after-free), with the reproducing harness command. Not just "the fuzzer found a crash." |
| Static Taint-Path Finding (code review, no crash) | Concrete `poc_code` that calls the vulnerable entrypoint and shows the corrupted or leaked value. Source reading alone is theory — the no-theory rule applies here as everywhere else. |

## Generation Procedure (Internal Report)

1. Pull backend state with the queries in "Query Backend First".
2. Treat `finding report --mode final --json` (or `--mode draft --json` for an interim draft) as the
   authoritative finding structure. Render one section per group root; include siblings as downstream
   outcomes under the root narrative, and call out `eliminates_attack_path` siblings as residual
   remediation paths.
3. Use the recorded CVSS. If proved impact would shift a base metric, stop and flag the finding
   ("CVSS Sourcing and Calculation").
4. Use the recorded remediation. Augment it only when the chain revealed a prerequisite weakness it
   does not address, the exploit bypassed the suggested fix, or the chain spans findings and fixing
   this one alone does not close it.
5. Populate every template field; mark missing evidence `[EVIDENCE MISSING]` and never fabricate it.
6. Build the attack path narrative from `chain list --json`, enriched with `credentials` /
   `access-records` where they explain the foothold or post-auth scope.
7. Write the executive summary last, from the complete finding set and chain analysis, and check its
   severity counts against the `finding report` projection.

## After Writing the Draft (Internal Report)

1. Run the stale-text scrub below against the backend.
2. Write the report to `$ENGAGEMENT_DIR/report.md`.
3. Run the post-generation self-review below and fix failures: finding-sourced text at the finding,
   report-local structure in `report.md`.
4. Register the file so QC can bind its verdict to these bytes:
   `vigil assess artifact register report.md --kind report`. It records your dispatch as the writer of
   these bytes and stderr names it; pass `--agent-id <your agent id>` if it names another.
5. Return the completed checklist and name the pending QC.

Publication (`report.generated`, marking findings `reported`) follows a current `report_qc_verdict`
pass from a separate report-writer ("Report QC Mode" below), so an unreviewed report never looks final.

### Stale-text scrub

Per the "Finding prose matches current state" Definition-of-Done item in `agent/phases/phase-8-report.md`,
no finding's `summary` or `details` may contradict current state. Stale narrative ("severity adjusted
from X to Y" when severity is no longer Y, "merged from W" after W was split off, "downgraded to
medium" against the current field) is invisible to status fields and lands verbatim in the deliverable.
Scan the backend before rendering, since a fix made only in `report.md` or `submission.md` returns on
the next render. The report projection carries every report-bound finding in one read:

```bash
for slug in $(vigil assess finding report --mode draft --json \
    | jq -r '(.groups[] | .root.slug, .siblings[].slug), .standalone[].slug' | sort -u); do
  hit=$(vigil assess fetch findings/$slug --jq '.summary,.details' \
    | grep -iE 'adjusted from|originally rated|previously (high|medium|low)|severity (was|changed)|merged from|downgraded to|upgraded to')
  if [ -n "$hit" ]; then
    echo "==> stale text in $slug:"
    echo "$hit"
  fi
done
```

The grep only surfaces candidates; read each hit. Rewrite stale text with a `--payload-file` patch
("Submission-First Closeout" has the shape, with `reason_text` "stale-text scrub before report QC"),
read its `verification_effect`, and re-run the scan. A finding that still carries stale text is a
`QA BLOCKED` reason.

## Post-Generation Self-Review

Runs against either deliverable: `report.md`, or a drafted `submissions/<slug>/submission.md` (the
writer's checklist step in `agent/agents/report-writer.md`). The check items are the one
pre-submission / report QA checklist in `agent/references/submission-format.md`, its rows tagged
`[both]` / `[submission]` / `[report]`: apply the `[both]` and `[report]` rows to `report.md` and every
applicable row to a submission. The writer's self-check and both independent QC modes run that one
checklist, so they cannot drift apart. Fix a failure at its source.

## Report QC Mode

A fresh report-writer that did not draft `report.md` checks it and records the verdict. The QC dispatch
is review-only: its verdict attests to bytes someone else wrote, so it never edits `report.md` or a
finding.

1. Read the registered `report.md` and pull the same backend report state the drafter used.
2. Run the `[both]` and `[report]` checklist rows, the "Pre-Report Validation" checks, and "Proof
   Standard by Finding Class" against it.
3. A failed row names the checklist row or rule and quotes the offending report text. An objection you
   cannot tie to a row and a quote is advisory and goes in the handoff only.
4. Record `vigil assess agent decision --kind report_qc_verdict` with the registered `report.md`
   artifact ID and the sha256 `vigil assess artifact get <id>` shows, the drafter's and your dispatch
   IDs, `verdict` `pass` or `blocked`, and the failed rows as `{row, quote}`.
   `vigil assess contract agent decision` owns the payload.
5. Hand off with extras `qc_verdict` and `findings_in_report`.

A `blocked` verdict goes back to a drafting dispatch. Evidence, severity, duplicate-finding, or CVSS
objections go to the operator, because they need new backend state rather than wording. A report
changed after its verdict needs a fresh QC: the drafter re-registers the revised bytes with `vigil
assess artifact register report.md --kind report`. The backend refuses a QC verdict on `report.md`
bytes registered without the writer's attribution, and from a reviewer that has ever registered
`report.md`.

## Publish After QA Pass

The `report.md` publish sequence; a submission publishes through "Closing verbs (submission publish)"
in `agent/agents/report-writer.md`. Run it for an internal red `report.md` only after a current
`report_qc_verdict` pass covers its bytes, and for a blue report after the Blue Mode closing sequence
below:

1. **Emit a runtime event** so the orchestrator and UI know the artifact exists:
   `vigil assess emit-event "report.generated" "report" "report.md" "report-writer" "Report generated with N findings"`
   for red engagements and blue verified-incident reports, or
   `vigil assess emit-event "closeout.generated" "report" "closeout.md" "report-writer" "Closeout generated"`
   for blue false-positive, benign, no-impact, or inconclusive closeouts.
2. **Mark `reported` the findings whose deliverable is this report**: those included in it with no
   per-finding submission workspace. A finding with a submission workspace becomes `reported` through
   its own exit-0 final export, never through this publish.
   ```bash
   vigil assess finding update <slug> --status reported --notes "Included in report.md" \
     --reason "Included in the generated report deliverable." --source-name report-writer \
     --agent-id <report-writer-agent-id> --provenance-inline '{"reported_by":"report-writer"}'
   ```

## Submission Status Lifecycle

`submission_status` is an axis independent of `workflow_status`: a finding can be `reported` and
`accepted` at once, and setting one never changes the other. A finding the program closes as duplicate
stays `workflow_status=reported`. `export submission` never sets it (draft and final both omit it, so
a new row lands `none` and an upsert preserves the stored value); only the explicit transitions below,
run once the finding is actually delivered, change it. For `direct`, read "program" as "client".

Values: `none` (default) | `submitted` | `accepted` | `needs_info` | `rejected` | `duplicate` | `withdrawn`

- **The first move off `none` carries `--submission-ref <program report id>`**, because the backend
  refuses a submission state it cannot join back to the report it describes; pair it with
  `--submission-platform` and `--submission-url` while you have them. Later transitions inherit the
  stored ref.
- **`withdrawn`** is the researcher's own retraction and requires `details.withdrawal_reason`. Use it
  instead of `rejected`, which asserts a program decision that never happened.
- **`needs_info`** triggers a targeted reply through the reply flow ("Closing verbs (reply mode)" in
  `agent/agents/report-writer.md`, format in `agent/references/reply-format.md`), never a
  `submission.md` hand-edit. `record-reply <slug> --seq N --sent --set-submission-status submitted`
  closes the loop; `record-reply` never sets `submission_status` without that flag.

```bash
vigil assess finding update <slug> --submission-status submitted \
  --submission-platform <bugcrowd|hackerone|direct|ghsa> --submission-ref <program report id> \
  --submission-url <report url> --reason "Submitted to program on <date>"
vigil assess finding update <slug> --submission-status accepted --reason "Program accepted and assigned bounty"
vigil assess finding update <slug> --submission-status withdrawn \
  --details-inline '{"withdrawal_reason":"Re-tested against current build; the bypass no longer reproduces"}' \
  --reason "Withdrawn by researcher"
```

`needs_info`, `rejected`, and `duplicate` take the same `--submission-status <value> --reason "<program's
words>"` form. `vigil assess contract finding update` lists the full field set.

## Blue Mode

When the active engagement is `engagement_type=blue`, the report-writer loads the
template at `agent/skills/report-generation/templates/blue.md` in place of the red
template above. The blue template is a parallel file the dispatch points at by name,
not a fork of this skill.

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
  Then run the `Publish After QA Pass` steps. Emit `closeout.generated`
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
#           template's BACKEND QUERIES section."
```

The blue wrapper derives that complete prompt context from the active scope and
passes it inline; it does not rely on placeholders or an operator-created file.

The BACKEND QUERIES section at the bottom of `templates/blue.md` lists the exact backend queries
(`finding report`, `fetch activity-entries`, `artifact search`,
`command-run list --phase respond`, `agent list`, `agent render-handoff`) the writer runs to
populate each template section, and its readiness gate (the operator ran
`vigil assess transition-phase report`).

## Extended Resources

- `agent/references/submission-format.md` — submission format and the shared QA checklist (platform-agnostic, behind the templates below)
- `agent/references/disclosure-email-format.md` — email disclosure format (output `submissions/<slug>/disclosure.txt`), with `agent/references/examples/disclosure-email-fast-import.txt`
- `agent/references/reply-format.md` — replies on an already-submitted finding
- `agent/references/reporting/bugcrowd-vrt.md` — Bugcrowd VRT leaf/priority/CVSS offline lookup
- `agent/references/reporting/hackerone-weaknesses.md` — HackerOne CWE weakness selection
- `agent/references/examples/` — worked submission examples, one per complexity tier (listed in submission-format.md "Examples")
- `agent/skills/report-generation/templates/bugcrowd.md`, `hackerone.md`, `direct.md`, `ghsa.md` — platform scaffolds for `export submission --platform <p>`
- `agent/skills/report-generation/templates/blue.md` — blue incident report template
