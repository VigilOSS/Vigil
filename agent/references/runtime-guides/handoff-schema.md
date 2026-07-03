---
description: Structured handoff schema written by every specialist via vigil assess agent handoff --from-json <path> — fields, length caps, per-role examples, CLI usage
---

# Specialist Handoff Schema

The structured handoff blob is the canonical "what was done, what's missing, what's
next" record every specialist writes before its dispatch returns. The blob lives in
the `assessment_dispatch_handoffs` table and is rendered into the next dispatch's
prompt by `vigil assess agent render-handoff <agent-id>`.

## Purpose

- **Specialists write structured state instead of duplicating it in markdown.** Every
  finding, intel row, surface, credential, and chain already has a backend table.
  The handoff captures the cross-cutting fields that don't have their own table:
  summary, coverage gaps, next steps, runtime issues, working artifacts, open
  questions, and role-specific extras.
- **The operator hands the next dispatch a bounded blob.** `render-handoff` reads the
  handoff row, fetches each finding slug from the backend (404 → "slug missing"),
  checks every working_artifact path on disk (missing → "(state: missing)"), and
  emits a markdown blob hard-capped at `--max-lines` (default 40). The next agent
  rebuilds its mental model from finding slugs, artifact paths, and the next-step
  list — not from a transcript paste.
- **The backend dispatch tables are canonical.** Skipping the handoff write means the
  operator has nothing to feed into the next dispatch.

## Schema

| Field | Type | Required | Notes |
|---|---|---|---|
| `agent_id` | string | yes | The dispatching agent_id (the same id passed to `vigil assess agent start` / `POST /dispatches`). |
| `agent_role` | string | yes | The role file the dispatch ran under (`recon-specialist`, `vulnerability-analyst`, etc.). |
| `phase` | string | yes | The phase tag the dispatch was authorized for (canonical enum via `vigil assess list-commands --phase`; e.g. `recon`, `consume-test`, `exploit`, plus half-phase tags `recon-pivot` / `exploit-recon`). |
| `summary` | string | yes | ≤2000 chars; one paragraph; what was done in your own words. |
| `confidence` | enum | yes | `low` / `medium` / `high` based on what you proved vs. inferred. |
| `finding_slugs` | string[] | optional | Slug strings only — the rich data lives in the findings table. The renderer fetches title + severity from the backend per slug. |
| `coverage_gaps` | object[] | optional | Each entry: `{area, reason, recommended_followup}`. |
| `next_steps` | object[] | optional | Each entry: `{action, target, recommended_agent, rationale}`. |
| `runtime_issues` | object[] | optional | Each entry: `{kind, tool_or_target, detail, severity}`. |
| `working_artifacts` | object[] | optional | Each entry: `{path, description, kind}`. `path` is engagement-relative (e.g. `scans/sans_acme-saas.txt`); the renderer checks each on disk. |
| `open_questions` | string[] | optional | Free-text questions the operator/human must answer (vendor-SaaS in/out, scope ambiguity, missing credential, etc.). |
| `recommended_next_agent` | string | optional | The role you'd hand off to (`vulnerability-analyst`, `exploit-developer`, `report-writer`, ...). |
| `handoff_status` | enum | optional | `checkpointed` / `ready` / `blocked` / `superseded`. Defaults to `checkpointed`; set `ready` or `blocked` in the final handoff so the operator can run `vigil assess agent close <agent_id>`. A `ready` or `blocked` handoff whose dispatch stays `in-progress` past the resume-brief threshold surfaces as a `stale_dispatch_ready_handoff` report-readiness blocker. |
| `closed_dispatch_status` | enum | optional | Dispatch status for `agent close` to apply (`completed`, `blocked`, `failed`, `aborted`). |
| `handoff_version` | integer | backend-managed | Incremented on every checkpoint write. Specialists do not set it; the orchestrator increments it on each PATCH so concurrent updates and audit trails stay ordered. |
| `last_checkpoint_at` | ISO datetime | backend-managed | Timestamp of the most recent handoff write. Backfilled to `created_at` for pre-lifecycle rows; updated by every checkpoint PATCH. Used by `agent reconcile-stale` to find dispatches that have not checkpointed recently. |
| `extras` | object | optional | Opaque JSON object for role-specific fields (osint CVE-match counts, fuzzer hit/miss ratio, recon live_host_count, etc.). |

## Field-by-field guidance

### `summary`

One paragraph, ≤2000 chars, plain prose. Describe what was done and the headline
outcome so the operator can decide the next dispatch quickly — name the hosts,
the count of priority surfaces produced, and any blockers that shape the next
phase. Example: "Phase 1 recon completed against 14 live hosts under
saas.acme.example; five priority surfaces (one admin panel, two upload endpoints,
two GraphQL introspection-open) recorded; nuclei surfaced two medium CVE
matches pending exploit-developer validation."

### `confidence`

Three values — `low` / `medium` / `high`. Pick `high` only when every claim in the
summary is backed by a recorded finding, intel row, or audit-pipeline command run.
Drop to `medium` when results rely on inference (CVE version-only matches, banner
grep, fingerprint heuristics). Drop to `low` when the dispatch hit a hard
runtime issue (target unreachable, runtime image missing tool, scope blocker)
that prevented you from confirming most of your claims. Confidence drives the
operator's decision on whether to trust the summary or re-dispatch.

### `finding_slugs`

A list of canonical slug strings (`["RE-001", "VA-004"]`).
The renderer fetches the title + severity from the findings table per slug, so
you don't repeat them here. If a finding wasn't recorded via `record-finding`, do
not list it here — the renderer would emit "slug missing in backend" and the
next agent has no way to consume it.

### `coverage_gaps`

A list of objects — `{area, reason, recommended_followup}`. Each entry names a
piece of the methodology the dispatch did NOT cover. `area` is the missing
coverage in plain language ("non-web service triage on host X", "JS source-map
extraction for app.foo.com"). `reason` is why the gap exists ("dispatch budget
spent on subdomain enum", "tool failed", "scope ambiguous"). `recommended_followup`
is the action that would close the gap ("re-dispatch source-analyzer with
JS-only objective", "request manual review of vendor-SaaS scope"). The
operator uses this list to plan the next dispatch.

### `next_steps`

A list of objects — `{action, target, recommended_agent, rationale}`. Each entry
is an actionable next-action the operator could dispatch. `action` is the verb
("validate CVE-2024-12345 against live target", "extract auth-aware crawl from
authenticated session", "fuzz the upload parameter"). `target` is the host /
endpoint / finding the action operates on. `recommended_agent` names the role
that should run it. `rationale` is one sentence on why now. The next-step list
is what `render-handoff` shows the next dispatch — the rationale is what the
new agent reads to understand the broader plan.

### `runtime_issues`

A list of objects — `{kind, tool_or_target, detail, severity}`. Use this to
warn the operator and the next dispatch about transient or persistent runtime
problems. `kind` is the category (`tool_failed`, `rate_limited`, `egress_blocked`,
`runtime_image_missing_dep`, `dependency_failure`, `scope_blocker`, etc.).
`tool_or_target` names the affected resource. `detail` is the symptom in plain
language. `severity` is `info` / `warning` / `error` / `blocker`. A `blocker`
runtime issue means the dispatch could not complete its objective; the next
dispatch needs to know that before it tries the same approach.

### `working_artifacts`

A list of objects — `{path, description, kind}`. Each entry is a file the next
agent might consume. `path` is engagement-relative (`scans/sans_acme-saas.txt`,
`tools/exploit-state/EX-001-payload.sql`, `downloads/app.bundle.js`). `kind` is
`data` / `script` / `payload` / `exploit_state` / `scan_output` / `download`.
The renderer checks each path on disk and tags missing files as
`(state: missing)` so the next agent doesn't chase deleted state.

### `open_questions`

A free-text list of strings. Use this for things needing a human / operator
decision that no record-* call can capture: vendor-SaaS in/out scope decisions,
scope ambiguity, missing credentials that block the next phase, ethical /
authorization clarifications. The operator surfaces these to the user before
the next dispatch.

### `recommended_next_agent`

Optional pointer to the role you'd hand off to next (`vulnerability-analyst`,
`exploit-developer`, `report-writer`, etc.). The operator uses this as one
input to the dispatch decision — they may override it based on phase and
parallelism considerations.

### `handoff_status`

Use `checkpointed` while the dispatch is still in progress and the handoff is a
durable progress save. Use `ready` for the final handoff when the operator can
close the dispatch as completed. Use `blocked` when the dispatch cannot complete
without new credentials, scope clarification, runtime repair, or another
operator action. The operator runs `vigil assess agent close <agent_id>` after
reviewing a ready/blocked handoff; agents do not close their own dispatch rows.

### `extras`

Opaque JSON object for role-specific fields. Examples:

- `recon-specialist`: `{"live_host_count": 14, "wildcard_subs_resolved": 86, "egress_block_pct": 12}`
- `osint-analyst`: `{"cve_matches": 3, "high_value_cve_matches": 1, "github_orgs_enumerated": 4}`
- `fuzzer`: `{"payloads_tried": 1200, "hits": 7, "hit_ratio": 0.0058}`
- `code-architect`: `{"modules_classified": 38, "critical_count": 4, "high_count": 11}`

Anything that helps the next agent understand the shape of the prior dispatch
without reading the audit pipeline.

## Per-role examples

### `recon-specialist`

```json
{
  "agent_id": "recon_a3f9",
  "agent_role": "recon-specialist",
  "phase": "recon",
  "summary": "Phase 1 recon completed against 14 live hosts under saas.acme.example; five priority surfaces recorded; nuclei flagged two medium CVE matches pending validation.",
  "confidence": "medium",
  "finding_slugs": ["RE-001"],
  "coverage_gaps": [
    {"area": "non-web triage on saas.acme.example:9001", "reason": "service banner unidentifiable; nmap version probe inconclusive", "recommended_followup": "manual netcat banner grab + protocol fingerprint"}
  ],
  "next_steps": [
    {"action": "validate CVE-2024-12345", "target": "saas.acme.example", "recommended_agent": "exploit-developer", "rationale": "version-match only; needs live confirmation before promotion to finding"}
  ],
  "runtime_issues": [
    {"kind": "tool_failed", "tool_or_target": "puredns", "detail": "massdns binary not found in runtime image", "severity": "warning"}
  ],
  "working_artifacts": [
    {"path": "scans/sans_acme-saas.txt", "description": "Per-host SAN extracts (cross-host collision input)", "kind": "data"}
  ],
  "open_questions": ["Is saas.acme.example in scope? CNAME points at vendor SaaS."],
  "recommended_next_agent": "vulnerability-analyst",
  "handoff_status": "ready",
  "extras": {"live_host_count": 14, "wildcard_subs_resolved": 86, "egress_block_pct": 12}
}
```

### `source-analyzer`

```json
{
  "agent_id": "source_b2c1",
  "agent_role": "source-analyzer",
  "phase": "recon",
  "summary": "Extracted 142 routes and 4 secrets from saas.acme.example bundles; APP_VERSION=2.18.4 captured for osint-analyst version triangulation.",
  "confidence": "high",
  "finding_slugs": ["SA-001", "SA-002"],
  "coverage_gaps": [],
  "next_steps": [
    {"action": "ingest 142 new routes into work buffer", "target": "saas.acme.example", "recommended_agent": "surface-collector", "rationale": "extracted routes are the Phase 2 input"}
  ],
  "runtime_issues": [],
  "working_artifacts": [
    {"path": "scans/extracted_routes.txt", "description": "142 unique routes from JS bundles", "kind": "data"}
  ],
  "open_questions": [],
  "recommended_next_agent": "surface-collector",
  "extras": {"routes_extracted": 142, "secrets_found": 4, "app_version": "2.18.4"}
}
```

### `surface-collector`

```json
{
  "agent_id": "surf_c4d8",
  "agent_role": "surface-collector",
  "phase": "collect",
  "summary": "Ingested 1,847 URLs across 12 clusters; inline classification scored 312 priority items above threshold; one large static-asset cluster deferred.",
  "confidence": "high",
  "finding_slugs": [],
  "coverage_gaps": [],
  "next_steps": [
    {"action": "fetch-by-priority dispatch on top 30 items", "target": "work buffer", "recommended_agent": "vulnerability-analyst", "rationale": "priority score >40 items dominate the queue"}
  ],
  "runtime_issues": [],
  "working_artifacts": [],
  "open_questions": [],
  "recommended_next_agent": "vulnerability-analyst",
  "extras": {"urls_ingested": 1847, "clusters": 12, "deferred_clusters": 1}
}
```

### `vulnerability-analyst`

```json
{
  "agent_id": "va_e7f2",
  "agent_role": "vulnerability-analyst",
  "phase": "consume-test",
  "summary": "Tested 28 candidate surfaces; recorded 4 findings (1 high IDOR, 2 medium info-disclosure, 1 low); one parameter requires fuzzer follow-up.",
  "confidence": "high",
  "finding_slugs": ["VA-001", "VA-002", "VA-003", "VA-004"],
  "coverage_gaps": [],
  "next_steps": [
    {"action": "verify VA-001 IDOR severity", "target": "saas.acme.example/api/users/{id}", "recommended_agent": "vulnerability-analyst", "rationale": "Phase 4 review mode"}
  ],
  "runtime_issues": [
    {"kind": "fuzzer_needed", "tool_or_target": "saas.acme.example/search?q=", "detail": "reflected-XSS hint without payload diversity — needs 100+ payload sweep", "severity": "info"}
  ],
  "working_artifacts": [],
  "open_questions": [],
  "recommended_next_agent": "vulnerability-analyst",
  "extras": {"surfaces_tested": 28, "findings_by_severity": {"high": 1, "medium": 2, "low": 1}}
}
```

### `exploit-developer`

```json
{
  "agent_id": "exp_g8h3",
  "agent_role": "exploit-developer",
  "phase": "exploit",
  "summary": "Chained EX-001 (auth-bypass) → EX-002 (RCE) into authenticated webshell on saas.acme.example; full chain recorded; one credential captured.",
  "confidence": "high",
  "finding_slugs": ["EX-001", "EX-002"],
  "coverage_gaps": [],
  "next_steps": [
    {"action": "draft final report including chain narrative", "target": "engagement", "recommended_agent": "report-writer", "rationale": "exploitation phase complete"}
  ],
  "runtime_issues": [],
  "working_artifacts": [
    {"path": "tools/exploit-state/EX-001-payload.sql", "description": "Auth-bypass SQL payload", "kind": "exploit_state"},
    {"path": "tools/exploit-state/EX-002-poc.py", "description": "RCE chain proof", "kind": "exploit_state"}
  ],
  "open_questions": [],
  "recommended_next_agent": "report-writer",
  "extras": {"chain_id": "chain-7", "credentials_captured": 1, "credential_ids": [17]}
}
```

### `fuzzer`

```json
{
  "agent_id": "fuzz_i4j7",
  "agent_role": "fuzzer",
  "phase": "consume-test",
  "summary": "1200 payloads against /search?q=; 7 anomalous responses; 1 confirmed reflected-XSS recorded; results dumped for vulnerability-analyst follow-up.",
  "confidence": "high",
  "finding_slugs": ["FZ-001"],
  "coverage_gaps": [],
  "next_steps": [
    {"action": "validate the 6 anomalous non-XSS responses", "target": "saas.acme.example/search?q=", "recommended_agent": "vulnerability-analyst", "rationale": "anomalies need analysis before promotion"}
  ],
  "runtime_issues": [],
  "working_artifacts": [
    {"path": "scans/fuzzer/search_q_results.jsonl", "description": "raw fuzzer hit log (7 anomalies marked)", "kind": "scan_output"}
  ],
  "open_questions": [],
  "recommended_next_agent": "vulnerability-analyst",
  "extras": {"payloads_tried": 1200, "hits": 7, "hit_ratio": 0.0058}
}
```

### `osint-analyst`

```json
{
  "agent_id": "osint_k1m5",
  "agent_role": "osint-analyst",
  "phase": "exploit",
  "summary": "Recorded 18 intel rows: 4 CVE matches against live tech stack, 8 domain rows, 3 person rows, 3 social-profile rows; 1 high-value CVE match needs validation.",
  "confidence": "medium",
  "finding_slugs": [],
  "coverage_gaps": [],
  "next_steps": [
    {"action": "validate CVE-2024-12345 against live saas.acme.example", "target": "saas.acme.example", "recommended_agent": "exploit-developer", "rationale": "high-value version-only match; backported patches commonly invalidate"}
  ],
  "runtime_issues": [],
  "working_artifacts": [],
  "open_questions": [],
  "recommended_next_agent": "exploit-developer",
  "extras": {"cve_matches": 4, "high_value_cve_matches": 1, "intel_rows": 18}
}
```

### `report-writer`

```json
{
  "agent_id": "report_n6p9",
  "agent_role": "report-writer",
  "phase": "report",
  "summary": "Final report generated covering 12 confirmed findings (1 critical, 3 high, 6 medium, 2 low) and 1 attack chain; QA pass clean.",
  "confidence": "high",
  "finding_slugs": [],
  "coverage_gaps": [],
  "next_steps": [
    {"action": "publish report and mark engagement complete", "target": "engagement", "recommended_agent": "operator", "rationale": "QA PASS"}
  ],
  "runtime_issues": [],
  "working_artifacts": [
    {"path": "report.md", "description": "final engagement report", "kind": "data"}
  ],
  "open_questions": [],
  "recommended_next_agent": "operator",
  "extras": {"qa_status": "PASS", "findings_in_report": 12}
}
```

### `code-architect`

```json
{
  "agent_id": "carch_q2r4",
  "agent_role": "code-architect",
  "phase": "code-classify",
  "summary": "Classified 38 modules in target repo (4 critical, 11 high, 23 medium); recorded 9 attack hypotheses as intel notes; threat model recorded.",
  "confidence": "high",
  "finding_slugs": [],
  "coverage_gaps": [],
  "next_steps": [
    {"action": "hunt vulnerabilities in critical+high modules", "target": "repo: target-repo", "recommended_agent": "code-vuln-hunter", "rationale": "Phase 2 entry"}
  ],
  "runtime_issues": [],
  "working_artifacts": [],
  "open_questions": [],
  "recommended_next_agent": "code-vuln-hunter",
  "extras": {"modules_classified": 38, "critical_count": 4, "high_count": 11}
}
```

### `code-vuln-hunter`

```json
{
  "agent_id": "cvh_s5t8",
  "agent_role": "code-vuln-hunter",
  "phase": "code-hunt",
  "summary": "Hunted 14 critical+high modules; recorded 6 findings (2 critical, 3 high, 1 medium) across deserialization, path-traversal, auth-bypass classes.",
  "confidence": "high",
  "finding_slugs": ["CH-001", "CH-002", "CH-003", "CH-004", "CH-005", "CH-006"],
  "coverage_gaps": [],
  "next_steps": [
    {"action": "verify each new finding via five-check protocol", "target": "6 finding slugs", "recommended_agent": "code-vuln-verifier", "rationale": "Phase 3 entry"}
  ],
  "runtime_issues": [],
  "working_artifacts": [],
  "open_questions": [],
  "recommended_next_agent": "code-vuln-verifier",
  "extras": {"modules_hunted": 14, "findings_by_severity": {"critical": 2, "high": 3, "medium": 1}}
}
```

### `code-variant-hunter`

```json
{
  "agent_id": "cvh_u9w2",
  "agent_role": "code-variant-hunter",
  "phase": "code-verify",
  "summary": "Found 4 variant instances of CH-002 (path-traversal pattern) across 3 sibling modules; all recorded as new findings linked to the parent.",
  "confidence": "high",
  "finding_slugs": ["CV-001", "CV-002", "CV-003", "CV-004"],
  "coverage_gaps": [],
  "next_steps": [
    {"action": "verify variants via five-check protocol", "target": "4 new finding slugs", "recommended_agent": "code-vuln-verifier", "rationale": "variants follow the same gating as primaries"}
  ],
  "runtime_issues": [],
  "working_artifacts": [],
  "open_questions": [],
  "recommended_next_agent": "code-vuln-verifier",
  "extras": {"parent_finding": "CH-002", "variants_found": 4}
}
```

### `code-vuln-verifier`

```json
{
  "agent_id": "cvv_x4y6",
  "agent_role": "code-vuln-verifier",
  "phase": "code-verify",
  "summary": "Reviewed 10 findings: 6 confirmed, 2 downgraded (severity over-claimed), 2 killed (false-positive on incomplete reachability).",
  "confidence": "high",
  "finding_slugs": [],
  "coverage_gaps": [],
  "next_steps": [
    {"action": "draft code-analysis report from confirmed findings", "target": "repo: target-repo", "recommended_agent": "report-writer", "rationale": "verification gate complete"}
  ],
  "runtime_issues": [],
  "working_artifacts": [],
  "open_questions": [],
  "recommended_next_agent": "report-writer",
  "extras": {"reviewed": 10, "confirmed": 6, "downgraded": 2, "killed": 2}
}
```

## CLI usage

The primary path is JSON-on-disk:

```bash
cat > /tmp/handoff-recon-a3f9.json <<'JSON'
{
  "agent_id": "recon_a3f9",
  "agent_role": "recon-specialist",
  "phase": "recon",
  "summary": "Phase 1 recon ...",
  "confidence": "medium",
  "finding_slugs": ["RE-001"],
  "coverage_gaps": [...],
  "next_steps": [...],
  "runtime_issues": [...],
  "working_artifacts": [...],
  "open_questions": [...],
  "recommended_next_agent": "vulnerability-analyst",
  "extras": {"live_host_count": 14}
}
JSON

vigil assess agent handoff --from-json /tmp/handoff-recon-a3f9.json
# Self-check: confirm the row is readable before exiting (404 → agent_id mismatch)
vigil assess agent render-handoff a3f9
```

For simple cases (one or two findings, no nested fields), flag-based alternatives
exist — see `vigil assess agent handoff --help` for the live flag set.
The `--from-json` form is the canonical path because it's the only way to record
nested fields (`coverage_gaps`, `next_steps`, `runtime_issues`, `working_artifacts`)
without shell-escaping pain.

The renderer reads the row back:

```bash
vigil assess agent render-handoff <agent-id>
```

The output is a markdown blob, hard-capped at `--max-lines` (default 40), with
findings collapsed to "... and N more" before runtime_issues / working_artifacts.
Summary, coverage_gaps, and next_steps are never trimmed. Paste it verbatim into
the next dispatch's prompt.

## Checkpointing — call `vigil assess agent handoff` as you work

`vigil assess agent handoff --from-json <path>` is idempotent: every
call against the same `agent_id` either inserts the row or replaces the prior
payload. Call it after each major step in your methodology — not just at the
end.

The pattern: maintain a local handoff JSON file (e.g.
`/tmp/handoff_<agent-id>.json`). After each tool or methodology step, update
the file with everything-known-so-far, then re-run `vigil assess agent handoff` against it.
Latest write wins; `vigil assess agent render-handoff <agent-id>` always reflects the most
recent state.

Why: durable progress accrues in the backend as you work. If your dispatch
halts before the final closing call (e.g. context exhaustion in Claude Code
sub-agents), the most recent checkpoint is your canonical record. Operators
reading `vigil assess agent render-handoff` see whatever step you were on.

### Suggested checkpoint cadence per role

- **recon-specialist** — checkpoint after each numbered tool in the recon
  sequence (after `wafw00f`, after `nmap`, after `httpx`, after `whatweb`,
  after `nuclei`, after `ffuf`, after conditional `nikto`).
- **source-analyzer** — after each major asset class processed (HTML routes
  extracted, JS routes extracted, secrets scanned, source maps inspected).
- **surface-collector** — after Katana ingest, after gau ingest, after dedup
  pass (classification runs inline at ingest, no separate step).
- **vulnerability-analyst** — after each surface tested. The handoff's
  `finding_slugs` accumulates as you confirm.
- **exploit-developer** — after each chain step proved (per cred captured,
  per access record written).
- **fuzzer** — after each payload family completes (or every 1000 requests,
  whichever first).
- **osint-analyst** — after each intel category (CVE matches, breach data,
  social profiles, DNS history).
- **report-writer** — after each section drafted; final call carries the full
  QA-pass summary.

### Example — recon-specialist after step 3 of 7

```json
{
  "agent_id": "recon_acme-saas_001",
  "agent_role": "recon-specialist",
  "phase": "recon-pivot",
  "summary": "Recon in progress: wafw00f / nmap / httpx complete. Cloudflare CDN, ports 80/443 only, Webflow tech stack identified.",
  "confidence": "low",
  "finding_slugs": [],
  "coverage_gaps": [
    {"area": "whatweb / nuclei / ffuf / nikto", "reason": "not yet run — dispatch in progress"}
  ],
  "next_steps": [],
  "extras": {
    "steps_completed": ["wafw00f", "nmap", "httpx"],
    "steps_remaining": ["whatweb", "nuclei", "ffuf", "nikto"]
  }
}
```

After step 7 completes the same file is rewritten with the full coverage
gaps, next steps, and a confident summary, and `vigil assess agent handoff` is run again
against the same path. The backend row is replaced in place.

### What gets persisted on halt

If the harness halts the dispatch (e.g. Claude Code sub-agent context
exhaustion), the latest checkpoint is what the operator gets. Step 3's
checkpoint shown above tells the operator "wafw00f / nmap / httpx done;
whatweb onward not run" — actionable enough to re-dispatch a continuation,
even though the agent never reached the final synthesis call.
