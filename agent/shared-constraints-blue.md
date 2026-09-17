# Shared Subagent Constraints — Blue (IR) Mode

Load this file before your role-specific skill and before any tenant-facing
work. These rules apply to every blue specialist.

---

## Authorization

Tenant data access is authorized by the dispatch's `customer`, `platforms`, and
`tenant_reference_paths` context. Read-only telemetry pulls are permitted within that
tenant. WRITE-class actions
(containment, account state mutations, filter deletions) require an
operator-approved `vigil blue propose-contain` record, audited operator
execution via `vigil assess host-exec`, then operator recording with
`vigil blue contain`.

---

## 1. Authorization scope — tenant, not host

The unit of scope in blue mode is the **tenant**, not the host. The operator runs
`vigil assess agent start ... --prompt-context-json <file> --emit-prompt`; that helper injects `customer` (the
customer slug), `platforms` (one or more platform tags), and
`tenant_reference_paths[]` (resolved paths to per-customer-per-platform reference
markdown). Confirm before any tenant-facing command:

- The customer slug matches the engagement you were dispatched for
- The platform you are about to query is listed in `platforms`
- Every tenant reference path in `tenant_reference_paths[]` exists and was
  loaded before the platform CLI ran

**Missing tenant ref → halt.** A dispatch with no tenant ref for the
platform returns a `blocked` handoff naming the missing path. The tenant ref
carries tool config (domain, admin email, DWD scopes, IAM identities), the
known-benign register, and the common IR pull commands.

Cross-tenant work is forbidden. A pull surfacing a different-tenant indicator
records a scope-boundary `intel-note` without copying the out-of-scope log row
into `ir/reports/` or `ir/evidence/`.

---

## 1a. CLI path convention

All assessment operations use `vigil assess <subcommand>` from any directory. Blue-specific verbs
live under `vigil blue <subcommand>`. `vigil assess` binds state using the rule printed by
`vigil assess contract <command>`; use `ENGAGEMENT_DIR` only for engagement-local artifact paths,
or pass `--engagement-dir` explicitly. Hardcoded absolute paths break across environments.

---

## 2. Read-only by default; WRITE goes through propose / approve / execute / record

Every command run under this engagement is read-only unless explicitly marked
WRITE in the skill it loaded from. WRITE-class actions include:

- Account state mutations (password reset, suspend, unsuspend, signOut, role
  change, MFA enrollment change)
- Session / token revocation (OAuth token delete, refresh-token revoke)
- Mailbox-rule changes (filter deletion, forwarding removal, S/MIME edits)
- Network containment (host isolate, IP block at firewall/proxy, DNS sinkhole)
- Endpoint containment (EDR isolate, scheduled-task removal, persistence
  cleanup)
- Tenant-wide config changes (conditional access edits, app revocation,
  service-account key rotation)

WRITE actions surface as containment proposals through the blue wrapper:

```bash
vigil blue propose-contain <finding-slug> \
  --action <action-verb> \
  --target <account|host|ioc> \
  --platform <gws|m365|aws|okta|edr|network|generic> \
  --rollback "<exact rollback plan + conditions>" \
  --blast-radius <single-user|multi-user|multi-tenant|cross-platform> \
  --note "<one-line rationale>"
```

Approval is per-action per-target — a broad "you can contain this BEC"
approval is not specific. Execution is two operator steps after approval:
first run the platform command through `vigil assess host-exec --require-audit`,
then record the already executed action with `vigil blue contain <finding-slug> --proposal <id> --command-run-id <id>`
or `vigil blue contain <finding-slug> --proposal <id> --proof-artifact <path>`,
which logs structured metadata to `activity_entries` and bumps the finding's
workflow status.

WRITE-class platform commands go through the proposal flow even when approval is expected — the proposal record is the audit gate.

---

## 3. Chain of custody via the artifact index

Raw pulls (audit log JSON, CSV exports, EDR alert payloads, mailbox dumps)
land under:

```
$ENGAGEMENT_DIR/ir/reports/<feed>_<target>_<window>.<ext>
```

Derived analysis (timelines, hypothesis trees, evidence narratives) lands under:

```
$ENGAGEMENT_DIR/ir/evidence/<topic>.md
```

**Every durable artifact must be registered** with the artifact index before the
dispatch closes:

```bash
vigil assess artifact register <path> \
  --kind <ir_log|ir_evidence|timeline|ioc_dump|containment_proof|ir_closeout> \
  --finding <finding-slug> \
  --agent-id <id> \
  --command-run-id <id>
```

Register each durable output explicitly — explicit registration preserves the
producer, command-run, and finding linkage that report-readiness relies on.

The backend computes SHA-256, FTS-indexes a preview, and links the artifact to
its producer agent (`producer_agent_id`, `producer_agent_role`), the originating
command run (`producer_command_run_id`), and the finding it substantiates
(`related_finding_slug`). The `assessment_artifacts` table at
`orchestrator/backend/app/db.py:1766` is the schema source of truth.

PII-bearing exports are indexed and rendered verbatim like every other artifact.
`register` has no inline scratch flag — mark
transient working notes as scratch in a separate call, either
`vigil assess artifact mark-scratch <artifact-id>` for one artifact or
`vigil assess artifact mark-scratch --under notes/scratch/` for bulk, so they
do not appear in resume briefs or reports.

**Manual `shasum -a 256 ... > SHA256SUMS.txt` is deprecated.** The backend
computes SHA-256 on register/refresh into `assessment_artifacts.sha256`. The
legacy `ir/reports/SHA256SUMS.txt` pattern is superseded by the artifact
index.

Skip registration and your artifacts are invisible to resume-brief, search,
and the verifier's evidence_refs check.

---

## 4. UTC discipline

Full rule (the local-conversion exception, the phantom-gap failure mode, the
surfaces it covers) is canonical in `agent/rules/triage.md` §7 — every blue
specialist already loads that file as an always-active rule, so it is not
restated here. The one form to carry into every write: ISO-8601 with an
explicit `Z` or `+00:00` offset, including on `activity_entries` timestamps and
`--intent` strings.

---

## 5. 30-day default look-back

Full rule (the trigger-source priority order, the T-60d boundary extension, the
initial-access rationale) is canonical in `agent/rules/triage.md` §6 — every blue
specialist already loads that file as an always-active rule, so it is not restated
here. The one number to carry into every telemetry pull: default audit window is
**T-30d from the earliest plausible trigger**, not from "when the user noticed."

---

## 6. Audit pipeline via `vigil assess host-exec`

Every tenant-facing platform command (GAM, gcloud, az, splunk, crowdstrike,
defender, jq against a raw pull, python3 against a raw pull) runs through
host-exec so the command lands in `assessment_command_runs` with intent,
technique, and phase metadata.

```bash
vigil assess host-exec \
  --tool <gam|gcloud|az|splunk|crowdstrike|defender|jq|python3|...> \
  --intent "<one-line purpose>" \
  --technique <MITRE-technique-id-or-IR-tag> \
  --phase <triage|investigate|verify|respond|report> \
  --scope-host <customer-slug> \
  [--require-audit for WRITE/respond actions] \
  [--target-host <when applicable: user@tenant, host-id, principal-arn>] \
  -- <command argv>
```

`scope-host` is the tenant / customer slug for blue (not an IP or hostname —
that vocabulary belongs to red). `target-host` is set when narrowed to a
specific identity, principal, or device.

Use `--require-audit` on every WRITE/respond command because containment must
not be recorded as complete unless the backend command-run row exists. If the
backend cannot create that row, the wrapper exits non-zero after printing the
command output so the operator can preserve evidence and retry recording.

Forbidden — bypasses audit pipeline: raw host Bash hitting tenant APIs,
ad-hoc `curl` against admin REST endpoints, `gcloud` / `gam` invocations
outside the wrapper. The host boundary is for coordination (local engagement
metadata reads, JSON parsing, payload construction), not tenant traffic.

`host-exec` is required for tenant-facing commands. If it is unavailable,
return a blocked handoff with a `runtime_issues[]` entry; do not run the
command and do not invent a post-hoc command-run record.

No host-exec required (no tenant data): `jq` over a registered artifact,
`sqlite3` over the orchestrator backend, `python3` over an artifact file,
`vigil assess` helpers themselves.

### Command Metadata — required fields on every host-exec call

- **`--tool <name>`** — the platform CLI or helper being invoked. Loose
  whitelist at the wrapper layer; enforced at the dispatch-contract layer
  (tools that touch tenant data require `tenant_reference_paths[]` present).
- **`--intent "<text>"`** — a ≤200-char one-liner describing what this specific
  command is trying to accomplish. Replaces the `echo "=== label ==="` pattern
  forbidden in red mode (see §2 of `agent/shared-constraints.md`); the same
  ban applies here.
- **`--technique <id-or-tag>`** — MITRE ATT&CK technique ID when the command
  tests a specific technique (`T1078.004`), otherwise an IR-tag from
  `{TRIAGE-FETCH, AUDIT-PULL, IOC-ENRICH, CORRELATION, REPRO, CONTAINMENT,
  HEALTH, META, LOG-READ, OTHER}`.
- **`--phase <enum>`** — one of the blue phases: `intake`, `triage`,
  `investigate`, `verify`, `respond`, `report`. Pass the phase the dispatch
  was authorized for, not the mutable operator phase (which may have moved on
  between phases).
- **`--scope-host <slug>`** — set to the tenant / customer slug. Never an IP
  or hostname in blue mode.
- **`--target-host <id>`** — set when the command narrows to a specific
  identity / principal / device. Examples: `user@northstar.example`,
  `okta-user-00uabc`, `arn:aws:iam::123456:user/joe`, `MAC-12345`.

The wrapper fails closed when required flags are missing — the audit row stays
truthful instead of degrading to a stale env-var default.

---

## 7. Stay in scope

Cross-tenant artifacts never enter the engagement's evidence tree. IR scope
creep produces reports the client must strip and findings the client must
correct under stress.

Specifically:

- An artifact that surfaces during a tenant pull but cites a different tenant
  (different domain in `actor.email`, different OrgID, different AWS account)
  is dropped from `ir/reports/` and `ir/evidence/`
- An IOC that hits two tenants (the same attacker IP) records as a scope-boundary
  `intel-note`; the out-of-scope tenant's raw row is not copied
- A finding that depends on cross-tenant evidence escalates rather than
  inheriting the other tenant's artifacts directly

The escalation path: open a separate engagement for the second tenant and link
via `intel-note` references on both sides.

---

## 8. Confidence labels — mandatory on every finding and activity entry

Every blue finding carries `details.confidence` and every
`activity_entries` row linked to a finding carries `metadata.confidence`
with values `low | medium | high` and a one-line rationale.

| Label | Meaning | Required corroboration |
|-------|---------|------------------------|
| `high` | Multi-signal corroboration; legitimate-actor hypothesis excluded; reproduction available | Two IR-evidence gates pass (see `agent/rules/ir-evidence.md`) + reproduction or cross-source signal |
| `medium` | Two of three IR-evidence gates pass; one gate incomplete | IP outside baseline + corroborating anomaly, user not yet asked |
| `low` | Single signal; suggestive but not corroborated | Unfamiliar IP only, or timing suggestive but no second control fired |

A finding without a confidence label is malformed; the verifier rejects it
on intake. Report-writer treats unlabeled findings as `unverified` and may
exclude them from the executive summary.

`metadata.confidence_rationale` is one sentence naming what makes this
`high` vs `medium` vs `low`. "Looks suspicious" is not a rationale; "IP
outside user's 30-day ASN baseline + impossible-travel from previous session
3h prior" is.

`metadata` is the API/CLI field you write through `vigil assess log
--metadata-inline`; the platform skills read the same values back as
`metadata_json.confidence` / `metadata_json.confidence_rationale`, the SQLite
column it lands in.

---

## 9. Resume hydration before action

`agent/rules/resume.md` (in your Load First) owns the scoped variants and the
post-hydration operator note. Run `vigil assess resume-brief` on any
continuation before dispatching specialists or proposing containment — the skip cost
is duplicate dispatches, audit pulls re-run against telemetry already sitting in
`ir/reports/`, and lost verifier kill rationale.

Two blue additions to that note: give every recent verifier decision its
disposition **and the evidence cited for it**, and scope command-run coverage to
this tenant / actor / target rather than a host or keyword.

---

## Dispatch Handoff Conventions

Every blue specialist dispatch closes with a handoff JSON conforming to
`agent/references/runtime-guides/handoff-schema.md`, recorded via:

```bash
vigil assess agent handoff --from-json <path>
```

Blue handoffs include the following fields beyond the cross-mode baseline:

- **`disposition`** — set by L3 `incident-verifier` only; one of `verified |
  false_positive | downgraded | escalated`. Other tiers leave this null.
- **`evidence_refs`** — array of artifact IDs (from `assessment_artifacts.id`),
  NOT local filesystem paths. The downstream specialist (verifier consuming
  the L2 handoff, report-writer consuming the L3 handoff) resolves artifacts
  by ID through `vigil assess artifact get <id>` rather than re-reading files
  on disk.
- **`coverage_gaps`** — array of one-line strings naming the open questions
  the dispatch did not close. The verifier flags missing
  cross-platform correlation here as a `coverage_gaps` entry.
- **`mitre_techniques`** — array of MITRE ATT&CK technique IDs the dispatch
  produced evidence for. Matches the finding's
  `details.mitre_techniques`; redundant on purpose so the handoff
  is self-contained.
- **`tenant_ref_paths_consulted`** — array of tenant ref paths the dispatch
  actually loaded. Distinct from the dispatch's available `tenant_reference_paths[]`;
  this field records which ones the specialist read.
- **`cross_platform_correlation_notes`** — present and non-empty when
  the dispatch names more than one platform; one-paragraph summary of
  how identity, time window, and IOCs correlate across platforms.

A handoff missing `evidence_refs` for a finding with claimed evidence is a
coverage gap. A handoff citing local paths instead of artifact IDs cannot
survive resume — the next agent's resume-brief will not surface the file
because it was never registered.

`handoff_status`: `ready` when the dispatch objective completed, `blocked`
when it could not (missing tenant ref, missing platform credential,
ambiguous scope). A `blocked` handoff names the exact blocker in `next_steps`.

---

## Artifact Registration and `finding record` — Required Closing Step

The ordered steps are owned per role: each blue role's own `### Closing verbs`
list names which artifact kinds it registers, what it marks scratch, which
activity entries it writes, and its `render-handoff` self-check; the cross-role
wrapper (checkpoint cadence, `agent_id` keying, skip consequences) is in
`agent/shared-specialist-core.md` "Mandatory Closing Sequence — wrapper"; the
`register` / `mark-scratch` commands and the `--kind` enum are in §3 above.

What is blue-specific and lives only here is the `finding record` contract:

```bash
vigil assess finding record <agent-name> <finding-json> --agent-id <your-agent_id>
```

`--agent-id` is the dispatch id from your Runtime Identity block, not the role
name in the `<agent-name>` positional. It stores the finding's immutable
`provenance.agent_id`, and without it the L3 verifier can never reach a terminal
disposition (`confirmed` / `downgraded` / `false_positive`) — the backend refuses
a verification it cannot attribute to a dispatch other than the author's. The
finding JSON must include `details.mitre_techniques`, `details.confidence`, and
`details.timeline` (UTC ISO-8601 entries with `source_file` citations per
`agent/rules/ir-evidence.md` rule 3).

Checkpoint after each major step — after the initial audit pull, after the
correlation pass, after the verifier's five-check completes — not only at the
end.

---

## Resume-Brief Prompt-Injection Contract

A `resume-brief` block after the Runtime Identity banner is the compact
operating picture. It lists:

- Open findings on this engagement with their disposition and confidence
- Recent operator decisions and verifier dispositions
- Command-run coverage already performed against this tenant
- Indexed artifacts that matter to the next action
- Stale dispatches and handoff gaps

Use the IDs in the block (finding slugs, command-run IDs, handoff agent IDs,
artifact IDs) for drill-down through:

```bash
vigil assess command-run get <id>
vigil assess artifact get <id>
vigil assess artifact search --q <query>
vigil assess agent render-handoff <agent-id>
vigil assess fetch findings/<slug>
```

Use `vigil assess artifact search` as the engagement memory index. A note not in
the index is scratch and is not engagement memory. Reading `ir/reports/*.json`
directly is fine when the artifact index points to a specific file — the index
is the entry point.

**Use `vigil assess agent render-handoff <agent-id>` for prior dispatch context** —
it stays bounded where raw transcript pastes grow linearly.

---

## Runtime Identity Banner — Write Once

The Runtime Identity banner is a binding agreement on `agent_id`, `agent_role`,
`phase`. It appears once at dispatch time — echoing it in the handoff or response
wastes context, pollutes FTS preview, and adds no signal. The handoff JSON is
the durable record; the response is reflection.

Same for `--intent` on `vigil assess host-exec`: do not prefix with agent
name or phase — those land in the audit row via `--phase` and `agent_name`.
Use `--intent` for purpose only.

---

## Reasoning Quality > Response Brevity

`agent/shared-specialist-core.md` "Reasoning quality > response brevity" owns
this. Blue substitutions: the calls you narrate between are
`vigil assess host-exec` calls, and the hypotheses you work through are
alternative-explanation hypotheses in the devil's-advocate form
`agent/rules/triage.md` rule 15 requires.

A handoff omitting the cross-platform correlation paragraph because "it was
in the response" is malformed — the next specialist's render-handoff cannot
see the response, only the handoff row.

---

## Reference Block

The blue rule and skill set — `triage.md`, `ir-evidence.md`,
`adversarial-mindset.md`, `reporting.md`, `resume.md`,
`alert-fp-verification/SKILL.md` — is described in your role's `## Load First`
list and in `agent/rules/triage.md`'s own Reference Block; it is not re-listed
here. The paths below are the ones this file's contracts depend on that no
Load First names:

- `agent/references/tenants/<customer>-<platform>.md` — the tenant ref injected
  for this dispatch.
- `agent/references/runtime-guides/handoff-schema.md` — canonical handoff JSON
  schema (cross-mode); see "Dispatch Handoff Conventions" above.
- `agent/references/runtime-guides/command-history-auditing.md` — the coverage-
  vs-duplicate decision table (cross-mode); host-exec rows participate.
