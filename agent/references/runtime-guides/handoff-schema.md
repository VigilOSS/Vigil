---
description: Structured handoff schema written by every specialist via vigil assess agent handoff --agent-id <agent-id> --from-json <path> — fields, length caps, per-role examples, CLI usage
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
  checks every working_artifact path against the engagement directory (missing →
  "(state: missing)", outside it → "(state: out-of-engagement)"), and
  emits a context excerpt capped at `--max-lines` (default 40). Use `--max-lines 0` for
  the complete recorded handoff, including specialty extras; a capped excerpt is not the full result. The next agent
  rebuilds its mental model from finding slugs, artifact paths, and the next-step
  list — not from a transcript paste.
- **The backend dispatch tables are canonical.** Skipping the handoff write means the
  operator has nothing to feed into the next dispatch.

## Schema

`Required` reads: **yes** — the write is refused without it; **write it** —
every specialist-authored handoff sets it and the operator reads it, but the backend
accepts the row without it, because an operator recovery write for a dispatch that
returned without a handoff cannot attest a phase or a confidence it never saw;
**optional** — supply it when it applies.

| Field | Type | Required | Notes |
|---|---|---|---|
| `agent_id` | string | yes | The dispatching agent_id (the same id passed to `vigil assess agent start` / `POST /dispatches`). |
| `agent_role` | string | yes | The role file the dispatch ran under (`recon-specialist`, `vulnerability-analyst`, etc.). |
| `phase` | string | write it | The phase tag the dispatch ACTUALLY ran at — the lane's own account, not a copy of the grant (canonical enum via `vigil assess list-commands --phase`; e.g. `recon`, `consume-test`, `exploit`, plus half-phase tags `recon-pivot` / `exploit-recon`). Normally equal to the packet's Runtime Identity `authorized_phase`; when the lane ran a narrower or less privileged branch than it was granted, record the phase it ran. `render-handoff` prints this beside `authorized_phase` from the immutable packet and names a divergence rather than reconciling it, so a self-downgraded lane stops looking identical to one that ran as dispatched. |
| `summary` | string | yes | target about 2000 chars; hard limit 16384 characters; what was done in your own words. |
| `confidence` | enum | write it | `low` / `medium` / `high` based on what you proved vs. inferred. |
| `finding_slugs` | string[] | optional | Slug strings only — the rich data lives in the findings table. The renderer fetches title + severity from the backend per slug. |
| `coverage_gaps` | object[] | optional | Each entry: `{area, reason, recommended_followup}`. |
| `next_steps` | object[] | optional | Each entry: `{action, target, recommended_agent, rationale}`. |
| `runtime_issues` | object[] | optional | Each entry: `{kind, tool_or_target, detail, severity}`. |
| `working_artifacts` | object[] | optional | Each entry: `{path, description, kind}`. `path` is engagement-relative (e.g. `scans/sans_acme_social.txt`). Both the write and `render-handoff` resolve it against the engagement directory and report `present` / `missing` / `out-of-engagement`; a path outside the engagement cannot be registered as an artifact at all. |
| `open_questions` | string[] | optional | Free-text questions the operator/human must answer (vendor-SaaS in/out, scope ambiguity, missing credential, etc.). |
| `recommended_next_agent` | string | optional | The role you'd hand off to (`vulnerability-analyst`, `exploit-developer`, `report-writer`, ...). |
| `handoff_status` | enum | optional | `checkpointed` / `ready` / `blocked` / `superseded`. Defaults to `checkpointed`; set `ready` or `blocked` in the final handoff so the operator can run `vigil assess agent close <agent_id>`. A `ready` or `blocked` handoff whose dispatch stays `in-progress` past the resume-brief threshold surfaces as a `stale_dispatch_ready_handoff` report-readiness blocker. |
| `closed_dispatch_status` | enum | optional | Dispatch status for `agent close` to apply (`completed`, `blocked`, `failed`, `aborted`). |
| `handoff_version` | integer | backend-managed | Incremented on every checkpoint write. Specialists do not set it; the orchestrator increments it on each PATCH so concurrent updates and audit trails stay ordered. |
| `last_checkpoint_at` | ISO datetime | backend-managed | Timestamp of the most recent handoff write. Backfilled to `created_at` for pre-lifecycle rows; updated by every checkpoint PATCH. Used by `agent reconcile-stale` to find dispatches that have not checkpointed recently. |
| `extras` | object | optional | Opaque JSON object for role-specific fields (osint CVE-match counts, fuzzer hit/miss ratio, recon live_host_count, etc.). One reserved key: `skills_loaded` — the skills you actually loaded, as a list or a comma-separated string. `render-handoff` reads that exact name, so a dispatch whose `skills` the operator left self-selected has no other way to put its loadout on the record. |
| `expected_handoff_version` | integer | optional | Update-only guard: the `handoff_version` you read. The write is refused (HTTP 409) if the row has moved since, so a recovery write cannot overwrite a checkpoint that landed in between. Never sent when creating the first handoff. |

## Field-by-field guidance

### `summary`

Aim for about 2000 characters of plain prose; up to 16384 characters are accepted verbatim. Describe what was done and the headline
outcome so the operator can decide the next dispatch quickly — name the hosts,
the count of priority surfaces produced, and any blockers that shape the next
phase. Example: "Phase 1 recon completed against 14 live hosts under
acme-social.example; five priority surfaces (one admin panel, two upload endpoints,
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
you don't repeat them here. If a finding wasn't recorded via `finding record`, do
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

### Material observations and the final response

Keep useful observations even when they did not become findings. Put the next experiment and
its rationale in `next_steps`, uncertainty in `open_questions`, and unexpected relationships in
`extras` or existing intel notes. State what was observed and what remains hypothetical. The
final native response should explain those connections and the outcome, not just repeat IDs.
Use free prose when needed; no fixed word quota, separate detailed investigation file, or new
operator acknowledgement is required. The summary is only one field, not a cap
on the investigation or its return. The operator can combine a weak clue with context you lack.

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
agent might consume. `path` is engagement-relative (`scans/sans_acme_social.txt`,
`tools/exploit-state/EX-001-payload.sql`, `downloads/app.bundle.js`). `kind` is
`data` / `script` / `payload` / `exploit_state` / `scan_output` / `download`.

The write and the renderer resolve each path against the engagement directory and
report the same three states, so the state you are told at write time is the state
the next dispatch reads: `present`, `missing`, or `out-of-engagement` for a path
that resolves outside the engagement (the artifact index refuses to register one, so
no artifact row can ever exist for it). A `missing` entry survives the renderer's
line budget ahead of a present one — it is the path the next agent must not chase.
Declare the artifact after writing the file: a `ready` handoff that names a file it
did not write is refused, and the row it already stored says so.

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

#### `extras.skills_loaded` — the one reserved key

Every other name here is yours to invent. `skills_loaded` is not: `render-handoff`
reads that exact spelling and renders it on the blob's **Skills loaded** line, so
any other name (`skills`, `loaded_skills`, `skills_used`) leaves that line reading
"not recorded" for the next dispatch. Write it whenever your dispatch prompt said
`skills: self-selected` — the dispatch row then carries no skill audit at all, and
this is the only record of which procedure context you ran under.

- as a list: `{"skills_loaded": ["code-vulnerability-analysis", "code-variant-analysis"]}`
- or comma-separated: `{"skills_loaded": "code-vulnerability-analysis,code-variant-analysis"}`

Use the bare skill directory names (`vigil assess list-skills`), not paths. When the
operator DID pass `--skills`, the dispatch row already records the request and the
rendered line shows both; a mismatch between them is a real signal, so report what
you loaded rather than echoing what was asked for.

## Per-role examples

Only the fields in the Schema table are top-level keys — `agent handoff` refuses an
unknown top-level name before the request, and `HandoffCreate` would 422 it. Every
role-specific field belongs under `extras`, including the blue roles' `disposition`,
`evidence_refs[]`, `mitre_techniques[]`, `tenant_ref_paths_consulted[]`,
`cross_platform_correlation_notes` and `proposal_ids[]`. `evidence_refs[]` carries
registered artifact IDs, never local paths.

### `alert-triage-specialist` (blue L1 — triage)

```json
{
  "agent_id": "ats_b7c2",
  "agent_role": "alert-triage-specialist",
  "phase": "triage",
  "summary": "Triaged 9 Acme Okta alerts: 6 mechanical false-positive proposals against the known-benign register, 2 escalated to investigation, 1 blocked on a missing tenant-policy entry. No terminal verification status written at L1.",
  "confidence": "medium",
  "finding_slugs": ["BL-001", "BL-002"],
  "coverage_gaps": [
    {"area": "service-account lockouts on acme-sso.example", "reason": "tenant ref has no known-benign entry for the automation principal", "recommended_followup": "request the tenant-policy owner add the principal, then re-triage"}
  ],
  "next_steps": [
    {"action": "investigate the two escalated sign-in clusters", "target": "BL-001, BL-002", "recommended_agent": "investigator", "rationale": "both show impossible-travel pairs that L1 cannot adjudicate"}
  ],
  "runtime_issues": [],
  "working_artifacts": [],
  "open_questions": ["Is the acme-automation service principal in scope for containment?"],
  "recommended_next_agent": "investigator",
  "handoff_status": "ready",
  "closed_dispatch_status": "completed",
  "extras": {
    "disposition": "false_positive_proposed",
    "evidence_refs": [412, 413, 418],
    "mitre_techniques": ["T1078.004", "T1110.003"],
    "tenant_ref_paths_consulted": ["agent/references/tenants/acme-workspace.md"],
    "alerts_triaged": 9
  }
}
```

### `investigator` (blue L2 — investigate)

```json
{
  "agent_id": "inv_d4e8",
  "agent_role": "investigator",
  "phase": "investigate",
  "summary": "Reconstructed the Acme sign-in cluster across Okta and M365: one principal authenticated from two ASNs within 6 minutes, then created an inbox rule. Recorded two findings; no disposition written at L2.",
  "confidence": "medium",
  "finding_slugs": ["BL-003", "BL-004"],
  "coverage_gaps": [
    {"area": "mailbox audit before 2026-09-01", "reason": "tenant retention window expired", "recommended_followup": "request the archived audit export from the customer"}
  ],
  "next_steps": [
    {"action": "verify BL-003 under the five-check protocol", "target": "BL-003", "recommended_agent": "incident-verifier", "rationale": "the inbox-rule write is the load-bearing claim and L2 cannot set a terminal status"}
  ],
  "runtime_issues": [],
  "working_artifacts": [],
  "open_questions": [],
  "recommended_next_agent": "incident-verifier",
  "handoff_status": "ready",
  "closed_dispatch_status": "completed",
  "extras": {
    "disposition": null,
    "evidence_refs": [431, 432, 433],
    "mitre_techniques": ["T1078.004", "T1114.003"],
    "tenant_ref_paths_consulted": ["agent/references/tenants/acme-workspace.md"],
    "cross_platform_correlation_notes": "Okta session id ties to the M365 sign-in by device id and 6-minute window; both platforms were queried for the same UTC range."
  }
}
```

### `incident-verifier` (blue L3 — verify)

```json
{
  "agent_id": "ivf_f9a1",
  "agent_role": "incident-verifier",
  "phase": "verify",
  "summary": "Verified 4 Acme findings: 2 confirmed, 1 downgraded on a symmetric evidence bar, 1 killed as a mechanical false positive with its settling test named. Every verdict carries its five-check record and a devil's-advocate pass.",
  "confidence": "high",
  "finding_slugs": ["BL-003", "BL-004"],
  "coverage_gaps": [],
  "next_steps": [
    {"action": "propose containment for the confirmed account takeover", "target": "BL-003", "recommended_agent": "ir-lead", "rationale": "confirmed with a proven write; containment needs an approved proposal"}
  ],
  "runtime_issues": [],
  "working_artifacts": [],
  "open_questions": [],
  "recommended_next_agent": "ir-lead",
  "handoff_status": "ready",
  "closed_dispatch_status": "completed",
  "extras": {
    "disposition": "confirmed",
    "evidence_refs": [441, 442],
    "mitre_techniques": ["T1078.004"],
    "tenant_ref_paths_consulted": ["agent/references/tenants/acme-workspace.md"],
    "verdicts": {"confirmed": 2, "downgraded": 1, "false_positive": 1}
  }
}
```

### `ir-lead` (blue L4 — respond)

```json
{
  "agent_id": "irl_h2j5",
  "agent_role": "ir-lead",
  "phase": "respond",
  "summary": "Recorded three containment proposals for the confirmed Acme takeover (session revoke, credential reset, inbox-rule removal); the operator executed two and the third is deferred pending the customer's maintenance window. Containment proof registered per executed proposal.",
  "confidence": "high",
  "finding_slugs": ["BL-003"],
  "coverage_gaps": [
    {"area": "blast radius for the delegated mailbox set", "reason": "delegate mapping is not in the tenant ref", "recommended_followup": "obtain the delegate map before the eradication proposal"}
  ],
  "next_steps": [
    {"action": "execute the deferred inbox-rule removal", "target": "BL-003", "recommended_agent": "ir-lead", "rationale": "customer maintenance window opens after the report deadline"}
  ],
  "runtime_issues": [],
  "working_artifacts": [],
  "open_questions": ["Does the customer authorize a tenant-wide session revoke?"],
  "recommended_next_agent": "report-writer",
  "handoff_status": "ready",
  "closed_dispatch_status": "completed",
  "extras": {
    "disposition": null,
    "evidence_refs": [451, 452, 455],
    "mitre_techniques": ["T1078.004"],
    "tenant_ref_paths_consulted": ["agent/references/tenants/acme-workspace.md"],
    "proposal_ids": [71, 72, 73]
  }
}
```

### `osint-analyst` (blue incident mode — IOC enrichment)

```json
{
  "agent_id": "osint_m8n3",
  "agent_role": "osint-analyst",
  "phase": "investigate",
  "summary": "Enriched 14 IOCs from the Acme sign-in cluster: 3 ASNs attributed to a residential proxy provider, 2 domains with passive-DNS overlap, 9 with no reputation signal. Intel rows recorded and linked to BL-003.",
  "confidence": "medium",
  "finding_slugs": ["BL-003"],
  "coverage_gaps": [
    {"area": "passive DNS before 2026-06", "reason": "provider retention", "recommended_followup": "re-run enrichment if an earlier window becomes available"}
  ],
  "next_steps": [
    {"action": "fold the proxy-provider attribution into the investigation narrative", "target": "BL-003", "recommended_agent": "investigator", "rationale": "changes how the impossible-travel pair should be read"}
  ],
  "runtime_issues": [
    {"kind": "rate_limited", "tool_or_target": "passive-dns provider", "detail": "9 of 14 lookups deferred by provider quota", "severity": "warning"}
  ],
  "working_artifacts": [],
  "open_questions": [],
  "recommended_next_agent": "investigator",
  "handoff_status": "ready",
  "closed_dispatch_status": "completed",
  "extras": {
    "evidence_refs": [461, 462],
    "tenant_ref_paths_consulted": ["agent/references/tenants/acme-workspace.md"],
    "iocs_enriched": 14,
    "source_reputation": "two providers agreed on the residential-proxy attribution; one had no record"
  }
}
```

### `recon-specialist`

```json
{
  "agent_id": "recon_a3f9",
  "agent_role": "recon-specialist",
  "phase": "recon",
  "summary": "Phase 1 recon completed against 14 live hosts under acme-social.example; five priority surfaces recorded; nuclei flagged two medium CVE matches pending validation.",
  "confidence": "medium",
  "finding_slugs": ["RE-001"],
  "coverage_gaps": [
    {"area": "non-web triage on api.acme-social.example:9001", "reason": "service banner unidentifiable; nmap version probe inconclusive", "recommended_followup": "manual netcat banner grab + protocol fingerprint"}
  ],
  "next_steps": [
    {"action": "validate CVE-2024-12345", "target": "app.acme-social.example", "recommended_agent": "exploit-developer", "rationale": "version-match only; needs live confirmation before promotion to finding"}
  ],
  "runtime_issues": [
    {"kind": "tool_failed", "tool_or_target": "puredns", "detail": "massdns binary not found in runtime image", "severity": "warning"}
  ],
  "working_artifacts": [
    {"path": "scans/sans_acme_social.txt", "description": "Per-host SAN extracts (cross-host collision input)", "kind": "data"}
  ],
  "open_questions": ["Is sso-vendor.acme-social.example in scope? CNAME points at vendor SaaS."],
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
  "summary": "Extracted 142 routes and 4 secrets from app.acme-social.example bundles; APP_VERSION=2.18.4 captured for osint-analyst version triangulation.",
  "confidence": "high",
  "finding_slugs": ["SA-001", "SA-002"],
  "coverage_gaps": [],
  "next_steps": [
    {"action": "ingest 142 new routes into work buffer", "target": "app.acme-social.example", "recommended_agent": "surface-collector", "rationale": "extracted routes are the Phase 2 input"}
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
    {"action": "verify VA-001 IDOR severity", "target": "app.acme-social.example/api/users/{id}", "recommended_agent": "vulnerability-analyst", "rationale": "Phase 4 review mode"}
  ],
  "runtime_issues": [
    {"kind": "fuzzer_needed", "tool_or_target": "app.acme-social.example/search?q=", "detail": "reflected-XSS hint without payload diversity — needs 100+ payload sweep", "severity": "info"}
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
  "summary": "Chained EX-001 (auth-bypass) → EX-002 (RCE) into authenticated webshell on app.acme-social.example; full chain recorded; one credential captured.",
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
    {"action": "validate the 6 anomalous non-XSS responses", "target": "app.acme-social.example/search?q=", "recommended_agent": "vulnerability-analyst", "rationale": "anomalies need analysis before promotion"}
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
    {"action": "validate CVE-2024-12345 against live app.acme-social.example", "target": "app.acme-social.example", "recommended_agent": "exploit-developer", "rationale": "high-value version-only match; backported patches commonly invalidate"}
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
  "phase": "code-record classify",
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

vigil assess agent handoff --agent-id <agent-id> --from-json /tmp/handoff-recon-a3f9.json
# ...or stream it, without a file on disk:
#   printf '%s' "$handoff_json" | vigil assess agent handoff --agent-id <agent-id> --from-json -
# Self-check: confirm the row is readable before exiting (404 → agent_id mismatch)
vigil assess agent render-handoff a3f9
```

`--from-json` takes a path, `@path`, inline JSON, or `-` for stdin, and it is the
only payload surface: every field above is recorded through it, including the nested
ones (`coverage_gaps`, `next_steps`, `runtime_issues`, `working_artifacts`).
`--agent-id` is the only other flag, and the payload's `agent_id` must equal it — the
match is what stops another dispatch's handoff file from being re-sent under your id.
A key the schema does not list is rejected by name before the request, so a misspelled
`workign_artifacts` cannot be dropped silently.

The receipt names `handoff_version`, `last_checkpoint_at`, `summary_characters`, and
every `working_artifacts` path with its on-disk state. A missing path is a warning; a
`ready` handoff that claims one exits non-zero after the row is written, because a
finished result asserting a file it never wrote is a fabricated result — write the file
or drop the entry, then re-run the same command.

The renderer reads the row back:

```bash
vigil assess agent render-handoff <agent-id>
```

The output is a markdown blob, hard-capped at `--max-lines` (default 40), with
findings collapsed to "... and N more" before runtime_issues / working_artifacts.
Findings, runtime issues, and artifacts collapse first. When multiline summary,
coverage-gaps, or next-step prose alone exceeds the requested hard cap, the
renderer emits an explicit truncation marker; rerun with a larger `--max-lines`
before relying on omitted content. Paste the bounded output verbatim into
the next dispatch's prompt.

## Checkpointing — call `vigil assess agent handoff` as you work

`vigil assess agent handoff --agent-id <agent-id> --from-json <path>` is idempotent: every
call against the same `agent_id` either inserts the row or replaces the prior
payload. Call it after each major step in your methodology — not just at the
end.

The pattern: maintain a local handoff JSON file (e.g.
`/tmp/handoff-<agent-id>.json`). After each tool or methodology step, update
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
  "agent_id": "recon_acme_social_001",
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

A successful handoff write returns `handoff_version`, `last_checkpoint_at`, and
`summary_characters`. Use this receipt to confirm the new checkpoint landed; rendering a prior
checkpoint after a rejected write does not establish success.

Default handoff rendering selects at most 40 lines and 8000 characters, with a visible
omission notice. `render-handoff --max-lines 0` reads the complete recorded handoff;
these display bounds never shorten the persisted summary.
