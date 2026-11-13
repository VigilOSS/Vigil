---
description: Structured handoff every specialist writes via vigil assess agent handoff --agent-id <agent-id> --from-json <path> — what each field is for, role-specific extras, checkpointing, and per-role examples
---

# Specialist Handoff Schema

The handoff is the "what was done, what's missing, what's next" record every specialist writes
before its dispatch returns. It lives in `assessment_dispatch_handoffs`; the operator reads it back
with `vigil assess agent render-handoff <agent-id>` and pastes that bounded blob into the next
dispatch, so the next agent rebuilds its picture from finding slugs, artifact paths and next steps
rather than a transcript. Findings, intel, surfaces, credentials and chains have their own tables;
the handoff carries only what has no other home.

Field types, enums and write rules belong to `vigil assess contract agent handoff`; read it (and
`--field <name>` for one field's rules) before hand-authoring a handoff if you haven't this session.
A refusal prints the section you need. This file covers what to put in each field.

## Schema

**Required:** `agent_id` (equal to `--agent-id`, the id from your Runtime Identity block) and
`summary` are required to create the row. `agent_role` is optional: the backend stores the role the
dispatch was registered with and names it on the response's `derived` list, and it refuses a
different role, so omit it or send your own role file name. Every specialist-authored handoff also
sets `phase` and `confidence`. The backend accepts a row without them only because an operator
recovery write cannot attest a phase or confidence it never saw.

| Field | Entry shape / values | What it is for |
|---|---|---|
| `phase` | phase string | The phase you actually ran, in Runtime Identity `authorized_phase` vocabulary: your track's roster (web `recon` … `report`, code `ingest` … `fuzz`, blue `intake` … `report`) or `recon-pivot` / `exploit-recon`. Code lanes may write the audit tag (`code-hunt`, `code-verify`, `code-classify`); `render-handoff` treats both spellings as one phase. If you ran a narrower branch than you were granted, record that branch. `render-handoff` shows it beside the packet's `authorized_phase` and names the divergence. |
| `summary` | prose, about 2000 chars (hard limit 16384) | What was done and the headline outcome. |
| `confidence` | `low` / `medium` / `high` | How much of the summary is proven rather than inferred. |
| `finding_slugs` | `["RE-001", …]` | Slugs recorded with `finding record`. `render-handoff` fetches title and severity. |
| `coverage_gaps` | `{area, reason, recommended_followup}` | Methodology this dispatch did not cover. |
| `next_steps` | `{action, target, recommended_agent, rationale}` | Dispatchable actions. |
| `runtime_issues` | `{kind, tool_or_target, detail, severity}` | Tool or runtime problems that shaped the result. |
| `working_artifacts` | `{path, description, kind}` | Files you wrote that the next agent may consume. |
| `open_questions` | strings | Decisions only the operator or the human can make. |
| `recommended_next_agent` | role name | Your own view of who picks this up. |
| `handoff_status` | `checkpointed` (default) / `ready` / `blocked` / `superseded` | Lifecycle of this handoff. |
| `closed_dispatch_status` | `completed` / `blocked` / `failed` / `aborted` | Status `agent close` applies. |
| `extras` | object | Role-specific fields. |
| `expected_handoff_version` | integer | Update-only guard: the `handoff_version` you read. A row that has moved since returns 409. Never sent on the first write. |

`handoff_version` and `last_checkpoint_at` are managed by the backend. A key outside this table is
refused by name, so role-specific fields go under `extras`.

## Field-by-field guidance

### `summary`

Name the hosts or modules, what was produced, and any blocker that shapes the next phase, so the
operator can choose the next dispatch from it. For example: "Phase 1 recon against 14 live hosts
under acme-social.example; five priority surfaces (one admin panel, two upload endpoints, two
GraphQL with introspection open); nuclei flagged two medium CVE matches pending validation."
Fit the summary inside the field. Never split prose across other fields to fit it.

### `confidence`

- `high`: every claim in the summary is backed by a recorded finding, an intel row, or an audited
  command run.
- `medium`: results rest on inference, such as version-only CVE matches, banner greps or
  fingerprint heuristics.
- `low`: a hard runtime issue (unreachable target, missing tool, scope blocker) kept you from
  confirming most claims.

The operator uses confidence to decide whether to trust the summary or re-dispatch.

### `finding_slugs`

List only slugs that `finding record` created. An unrecorded slug renders as "slug missing
(deleted or never recorded)" and gives the next agent nothing to consume.

### `coverage_gaps` and `next_steps`

A coverage gap names what was not covered, why, and what would close it. For example: area "JS
source-map extraction for app.acme.example", reason "budget spent on subdomain enum",
recommended_followup "re-dispatch source-analyzer, JS only". A next step is an action the operator
can dispatch, with its target, the role that should run it, and one sentence on why now. The
next dispatch reads the rationale to understand the broader plan.

### Material observations and the final response

Keep useful observations that did not become findings. Put the next experiment in `next_steps`,
uncertainty in `open_questions`, and unexpected relationships in `extras` or intel notes, and say
what was observed versus what is still hypothesis. The operator can combine a weak clue with
context you lack. The summary is one field, not a cap on the investigation. Your final native
response should explain the connections and the outcome, not just list IDs.

### `runtime_issues`

`kind` is a category: `tool_failed`, `rate_limited`, `egress_blocked`, `runtime_image_missing_dep`,
`dependency_failure`, `scope_blocker` and so on. `severity` is `info` / `warning` / `error` /
`blocker`. A `blocker` means the objective could not be completed, and the next dispatch should know
that before it retries the same approach.

### `working_artifacts`

`path` is engagement-relative (`scans/sans_acme_social.txt`, `tools/exploit-state/EX-001-payload.sql`).
`kind` is `data` / `script` / `payload` / `exploit_state` / `scan_output` / `download`. The write and
the renderer both resolve each path and report one of three states:

- `present`
- `missing`
- `out-of-engagement`: no artifact row can exist for it.

`render-handoff` keeps a `missing` entry ahead of present ones, so the next agent knows not to
chase that path. Declare an artifact only after the file exists. A `ready` handoff that names an
absent file exits non-zero after the row is stored, so write the file or drop the entry, then
re-run the same command.

### `open_questions`

Use this for decisions no `record-*` call can capture: whether vendor SaaS is in scope, scope
ambiguity, missing credentials that block the next phase, or authorization questions. The operator
puts these to the user before the next dispatch.

### `handoff_status`

- `checkpointed`: a progress save while you work.
- `ready`: final handoff, and the dispatch can close as completed.
- `blocked`: the dispatch needs new credentials, scope clarification, a runtime repair or another
  operator action before it can finish.

The operator runs `vigil assess agent close <agent_id>` after reviewing a ready or blocked handoff.
Agents do not close their own dispatch rows. A ready or blocked handoff whose dispatch stays
`in-progress` past the resume-brief threshold becomes a `stale_dispatch_ready_handoff`
report-readiness blocker.

### `extras`

Use counters and context that tell the next agent the shape of the dispatch without reading the
audit pipeline. Choose key names freely. Typical keys per role are in the next section.

#### `extras.skills_loaded` — the one reserved key

`render-handoff` reads this exact spelling and renders it on the **Skills loaded** line. Any other
name (`skills`, `loaded_skills`) leaves that line reading "not recorded". Write it whenever your
dispatch said `skills: self-selected`, because the dispatch row then has no other record of your
loadout. Use bare skill directory names, either as a list
(`["code-vulnerability-analysis", "code-variant-analysis"]`) or as a comma-separated string. When
the operator passed `--skills`, report what you actually loaded rather than echoing the request:
the rendered line shows both, and a mismatch is a real signal.

## Per-role examples

Every example below is a payload `agent handoff` accepts as written. Blue role-specific fields
(`disposition`, `evidence_refs[]` (registered artifact IDs, never local paths), `mitre_techniques[]`,
`tenant_ref_paths_consulted[]`, `cross_platform_correlation_notes`, `proposal_ids[]`) live under
`extras` like any other role's.

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

### `recon-specialist` (red; final handoff)

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

### Other red roles

Every red handoff has the shape shown in the recon example. What changes per role is the phase it
usually runs at, the extras that summarise its work, and when it checkpoints:

| Role | Usual `phase` | Typical `extras` | Checkpoint after |
|---|---|---|---|
| `source-analyzer` | `recon` | `routes_extracted`, `secrets_found`, `app_version` | each asset class (HTML routes, JS routes, secrets, source maps) |
| `surface-collector` | `collect` | `urls_ingested`, `clusters`, `deferred_clusters` | Katana ingest, gau ingest, dedup |
| `vulnerability-analyst` | `consume-test` / `verify` | `surfaces_tested`, `findings_by_severity` | each surface tested |
| `fuzzer` | `consume-test` | `payloads_tried`, `hits`, `hit_ratio` | each payload family, or every 1000 requests |
| `osint-analyst` | `exploit` | `cve_matches`, `high_value_cve_matches`, `intel_rows` | each intel category (CVE, breach, social, DNS history) |
| `exploit-developer` | `exploit` | `chain_id`, `credentials_captured`, `credential_ids` | each chain step proved |
| `report-writer` | `report` | `findings_in_report` | each section drafted |
| `code-architect` | `classify-map` | `modules_classified`, `critical_count`, `high_count` | each major step |
| `code-vuln-hunter` | `hunt` | `modules_hunted`, `findings_by_severity` | each module hunted |
| `code-variant-hunter` | `verify-variant` | `parent_finding`, `variants_found` | each major step |
| `code-vuln-verifier` | `verify-variant` | `reviewed`, `confirmed`, `downgraded`, `killed` | each verdict recorded |

The recon specialist checkpoints after each tool in its sequence.

## CLI usage

```bash
vigil assess agent handoff --agent-id <agent-id> --from-json /tmp/handoff-<agent-id>.json
printf '%s' "$handoff_json" | vigil assess agent handoff --agent-id <agent-id> --from-json -
vigil assess agent render-handoff <agent-id>                 # bounded excerpt
vigil assess agent render-handoff <agent-id> --max-lines 0   # complete recorded handoff
```

`--from-json` takes a path, `@path`, inline JSON or `-` for stdin, and it is the only payload
surface. The payload's `agent_id` must equal `--agent-id`, which stops a handoff file written by
another dispatch from being sent under your id. The receipt names `handoff_version`,
`last_checkpoint_at`, `summary_characters` and the state of each artifact path. Use the receipt to
confirm a checkpoint landed. Rendering an earlier checkpoint after a refused write proves nothing.

By default `render-handoff` prints at most 40 lines and 8000 characters. Findings, runtime issues
and artifacts collapse first ("... and N more"), and an explicit marker shows where prose was
truncated. Rerun with a larger `--max-lines` before you rely on omitted content. These display
bounds never shorten the stored row.

## Checkpointing — call `vigil assess agent handoff` as you work

`agent handoff` is idempotent per `agent_id`: the first call inserts the row and each later call
updates it with the fields you send, so the latest write wins. A field you leave out keeps its
stored value, and the stored `agent_role` never changes. Keep one local handoff JSON file. After each major step, update
it with everything you know so far and re-run the command. If the dispatch halts before its final
call (for example on context exhaustion), the operator gets the latest checkpoint as your record
and can re-dispatch a continuation from it. Per-role cadence is in the table above.

An in-progress checkpoint is a valid payload too:

```json
{
  "agent_id": "recon_acme_social_001",
  "agent_role": "recon-specialist",
  "phase": "recon-pivot",
  "summary": "Recon in progress: wafw00f / nmap / httpx complete. Cloudflare CDN, ports 80/443 only, Webflow tech stack identified.",
  "confidence": "low",
  "coverage_gaps": [
    {"area": "whatweb / nuclei / ffuf / nikto", "reason": "not yet run — dispatch in progress"}
  ],
  "extras": {
    "steps_completed": ["wafw00f", "nmap", "httpx"],
    "steps_remaining": ["whatweb", "nuclei", "ffuf", "nikto"]
  }
}
```

The final write rewrites the same file with the full gaps, next steps, a confident summary and
`handoff_status: ready`.
