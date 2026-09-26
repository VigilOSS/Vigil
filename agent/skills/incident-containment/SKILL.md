---
name: incident-containment
description: L4 containment proposal authoring — per-platform pattern tables, target/action/rollback contract, blast-radius assessment, eradication, and recovery patterns for verified incidents
origin: Vigil
---

# Incident Containment (L4)

## When to Activate

- A finding has reached `verification_status=confirmed` with severity
  `≥ high` (or the operator has explicitly authorized containment on a
  `downgraded` finding — by default downgrades do NOT trigger
  containment).
- The verifier's handoff names `next_specialist: ir-lead` and the
  evidence_refs include reproducible adversarial activity.
- The operator dispatches the L4 `ir-lead` role to author containment
  proposals, await per-action approval, then execute via `vigil blue contain`.
- Eradication (persistence removal) or recovery (clean re-enrollment)
  authoring on a previously contained finding.

L4 is the WRITE-class role. Every proposal becomes a `containment_proposal`
dispatch-decision row that the operator individually approves; nothing this
skill produces runs without operator approval per-action and per-target. The
proposal record is the audit gate, not a comment field.

## Always-active references

- `agent/rules/triage.md` — verification-status vocabulary (containment requires
  `confirmed`, not `unreviewed`); containment-proposal shape (rule 18 —
  target/action/rollback); never-delete-evidence (rule 19); UTC (rule 7).
- `agent/shared-constraints-blue.md` — read-only by default (§2);
  WRITE-class actions surface as proposals; `vigil blue contain` is the
  execution verb; artifact chain of custody for the containment-proof
  artifact.
- `agent/rules/ir-evidence.md` — attribution gates; the verifier's
  five-check is the precondition for containment (no containment on
  `unreviewed` or `disputed` findings).
- The platform skill in **containment mode** — `google-workspaces`,
  `m365-signin-investigation`, etc. The platform skill owns the
  vendor-specific containment command (GAM `gam user <email> signout`,
  `gcloud iam service-accounts disable`, etc.); this skill owns the
  proposal contract those commands surface as.
- The tenant ref(s) named in `scope.json:tenant_reference_paths[]` —
  the documented admin identities authorized to execute containment,
  the rollback contacts (security manager, on-call), and the customer's
  documented break-glass procedures.

## Tools

| Verb | Purpose |
|------|---------|
| `vigil blue propose-contain` | Author a containment proposal with `target`, `action`, `rollback`, `blast_radius`, and `note`; prints the backend `decision_id` for approval |
| `vigil blue contain <finding-slug> --proposal <id> --command-run-id <id>` | Records an already-executed proposal: logs to `activity_entries`, bumps finding `workflow_status` to `contained`, and can also register `--proof-artifact <path>`. **Does not** run the platform command itself in v1 — the operator runs `vigil assess host-exec --require-audit ... -- <cmd>` first, then passes the command-run id or captured stdout/screenshot proof. |
| `vigil assess log` | Record the containment decision (proposed, approved, executed, rolled-back) with structured `metadata_json` |
| `vigil assess artifact register` | Register containment-proof artifacts (`kind=containment_proof`) — screenshots, command output, ticket links |
| `vigil assess host-exec` | Out-of-band evidence pulls during eradication / recovery (e.g., post-containment verification that the session is actually revoked) |
| `vigil assess finding update` | Move finding to `workflow_status=contained | eradicated | recovered` after each phase lands |
| `vigil assess agent handoff --from-json <path>` | Close the L4 dispatch with a handoff naming all executed proposals and any remaining gaps |

Forbidden from L4 without an approved proposal: direct platform CLI
(`gam user X signout`, `gcloud iam ... disable`, `crowdstrike isolate-host`).
The discipline is identical to the red-mode exploit-developer's
relationship to the operator approval gate: surface the action, get the
approval, then execute via the audited verb. Silent destructive action
during an investigation is how evidence gets lost and users get locked
out mid-business-hours.

## Methodology — Containment Patterns

Containment maps to four layers; each finding's evidence selects which
layer(s) the proposals address. A BEC compromise touches identity +
endpoint; a phishing-landing-page compromise touches network + identity;
an AWS IAM key abuse touches cloud + identity.

### Identity-layer containment

| Action verb | Target shape | Platform CLI (proposal `command`) | Rollback (proposal `rollback`) |
|-------------|--------------|-----------------------------------|--------------------------------|
| `revoke_session` | user@tenant or user-ID | `gam user <email> signout` (GWS) / `Revoke-AzureADUserAllRefreshToken -ObjectId <id>` (Entra) / `okta-cli user clear-sessions <id>` | None needed — sessions re-issue on next sign-in |
| `reset_credential` | user@tenant | `gam update user <email> password <new-temp> changepassword on` / `Set-AzureADUserPassword -ObjectId <id>` / `okta user reset-password <id>` | None — user re-enrolls via standard recovery |
| `disable_account` | user@tenant | `gam update user <email> suspended on` / `Set-AzureADUser -ObjectId <id> -AccountEnabled $false` / `okta user suspend <id>` | `gam update user <email> suspended off` after out-of-band confirmation of legitimate identity |
| `force_mfa_reenroll` | user@tenant | `gam user <email> deprovision factors` (GWS) / `Reset-MgUserAuthenticationMethod ...` / `okta user reset-factors <id>` | None — user re-enrolls per documented factor policy |
| `enforce_signin_policy` | user-group or tenant-scoped policy ID | `gcloud asset analyze-iam-policy ...` then policy-binding update / Conditional Access policy patch / Okta sign-on policy patch | Revert policy version to pre-change ID |

### Endpoint-layer containment

| Action verb | Target shape | Platform CLI (proposal `command`) | Rollback (proposal `rollback`) |
|-------------|--------------|-----------------------------------|--------------------------------|
| `isolate_host` | device-id (MAC-12345 / sensor-id) | `crowdstrike host isolate <sensor-id>` / `Set-MpPreference -ContainmentMode Strict` (Defender) / `s1 agent isolate <id>` | `crowdstrike host lift-isolation <sensor-id>` |
| `kill_process` | sensor-id + PID | EDR API: process-tree action with PID | None — process restarts only if persistence is also addressed |
| `quarantine_file` | sensor-id + file SHA256 | `crowdstrike file quarantine <hash>` / `Defender custom-indicator block <hash>` | `crowdstrike file restore <hash>` (rare — only if FP confirmed) |
| `rollback_edr` | sensor-id + snapshot-id (where supported) | `s1 agent rollback <id>` (SentinelOne); CrowdStrike does not offer rollback | Snapshot-id specific revert |

### Network-layer containment

| Action verb | Target shape | Platform CLI (proposal `command`) | Rollback (proposal `rollback`) |
|-------------|--------------|-----------------------------------|--------------------------------|
| `block_ioc` | IP or CIDR | Firewall vendor CLI (`paloalto`, `pan-os`, `fortios`, `panorama-api`) — block rule addition | Remove block rule by rule-ID |
| `sinkhole_domain` | domain | DNS RPZ entry add (`isc rpz add <domain>`) / Umbrella block-list API | RPZ entry removal by ID |
| `revoke_api_token` | token-id | Platform-specific (e.g., `gcloud iam service-accounts keys delete`, `aws iam delete-access-key`, `okta api-token revoke <id>`) | None — caller re-issues if needed |
| `rotate_api_key` | key-id + service-account-id | `gcloud iam service-accounts keys create`, then delete old | Restore old key only via backup; not recommended |

### Cloud-layer containment

| Action verb | Target shape | Platform CLI (proposal `command`) | Rollback (proposal `rollback`) |
|-------------|--------------|-----------------------------------|--------------------------------|
| `revoke_iam_credential` | principal ARN or GCP IAM member | `aws iam delete-login-profile --user-name <name>` / `gcloud iam service-accounts disable <email>` / `az ad user update --account-enabled false --id <id>` | Re-enable via inverse command after confirmation |
| `deactivate_access_key` | AWS access-key ID | `aws iam update-access-key --access-key-id <id> --status Inactive` | `aws iam update-access-key --status Active` (only with operator approval) |
| `rotate_service_account_key` | GCP service-account email + key-ID | `gcloud iam service-accounts keys create` (new) then `keys delete <old-id>` | Keep old key disabled but recoverable for N days |
| `disable_oauth_grant` | OAuth client-ID + user-email | `gam user <email> delete token <client-id>` (GWS) / `Remove-MgOauth2PermissionGrant` (M365) | Re-authorize via standard OAuth flow |

## Proposal Contract

Every proposal — regardless of layer — must specify all four fields.
Vague proposals fail the containment proposal contract and the operator's
approval review.

### (a) Action verb

One of: `revoke`, `disable`, `isolate`, `block`, `reset`, `remove`,
`quarantine`, `rotate`, `sinkhole`. (Triage rule 18 vocabulary,
extended with `sinkhole` for DNS work.) Compound actions ("contain the
BEC") are NOT proposals — they decompose into multiple per-action
proposals, each operator-approved separately.

### (b) Specific target

The exact account / host / IOC / key. Wildcards and group references
are forbidden in `target` (except `enforce_signin_policy`, where the
group is the target). Examples:

- `user@northstar.example` (NOT `*@northstar.example`)
- `MAC-12345` (NOT `all-laptops`)
- `arn:aws:iam::123456:user/joe` (NOT `arn:aws:iam::123456:*`)
- `8675309-abc.apps.googleusercontent.com` (NOT `oauth-clients`)
- `203.0.113.7` or `203.0.113.0/24` (CIDR is fine if the entire range
  is adversarial; otherwise enumerate)

If the proposal's target is ambiguous (the verifier's evidence cites
"the attacker IP" but the IP is in a NAT pool shared by legitimate
users), the proposal does NOT advance — the verifier's evidence
needs refinement first.

### (c) Rollback plan with exact undo commands

Two halves:

- **The exact reverse command** — verbatim, not a description. If
  the action is non-reversible (credential reset, key rotation), the
  rollback names the standard recovery procedure ("user re-enrolls
  via documented recovery flow at <URL>"). "No rollback needed" is
  acceptable for non-reversible actions; "unknown" is not.
- **The conditions under which rollback is appropriate** — usually
  "if user confirms legitimate session by out-of-band channel within
  30m" or "if vendor confirms maintenance-window false positive
  within 24h." The condition names the channel (phone, in-person,
  SOC ticket reply) and the time window.

### (d) Blast-radius assessment

One of:

- `single-user` — affects exactly one tenant identity. Most
  identity-layer revocations and resets.
- `single-host` — affects exactly one device. Most endpoint isolations.
- `multi-user` — affects a group of users (sign-in policy change,
  conditional-access policy update). Operator must approve with explicit
  acknowledgment of the user-list.
- `multi-tenant` — should not happen in a single-tenant engagement;
  if a proposal's effect crosses to a different tenant, the proposal
  is malformed (containment is scope-creep here per
  `shared-constraints-blue.md` §7).
- `cross-platform` — the proposal's containment affects both
  identity and endpoint posture (e.g., disabling an account that also
  drives device enrollment). Operator approval names the cascade
  explicitly.

## Approval Flow

```bash
# 1) Author proposal — does NOT execute. Writes a containment_proposal
#    dispatch-decision row whose `decision_id` the operator passes to
#    approve-proposal + blue contain.
vigil blue propose-contain <finding-slug> \
  --action revoke_session \
  --target user@northstar.example \
  --platform gws \
  --rollback "No rollback needed — sessions re-issue on next sign-in. Confirm out-of-band with user before any further actions." \
  --blast-radius single-user \
  --note "Verified compromise; sign-in from unfamiliar IP corroborated; revoke active sessions before pulling other forensics."

# `vigil blue propose-contain` prints JSON like:
#   {"decision_id": 42,
#    "approval_hint": "vigil assess approve-proposal 42 --approved-by <operator>"}

# 2) Operator approves the proposal (decision-row PATCH; gates step 4)
#    vigil assess approve-proposal <decision-id> --approved-by <operator>

# 3) Operator executes the platform command through host-exec so the
#    underlying command and its stdout are audited. v1 keeps this as a
#    separate step from `vigil blue contain` so the operator inspects the
#    command's output before recording the activity row.
#
# IMPORTANT: when dispatching containment commands through
# `vigil assess host-exec`, argv containing `delete`, `--force`, `rm -r`,
# `dd of=/dev/`, or the `format` command will be blocked by the default
# destructive-token gate (see the destructive gate constants in
# `agent/scripts/assess/commands/host_exec.py`). Common containment
# operations — `aws iam delete-access-key`, `aws iam delete-user`,
# `gcloud iam service-accounts delete`, anything with `--force` —
# require BOTH `--allow-destructive` AND a proposal that has been
# approved (`assessment_dispatch_decisions.resolved=true`, set by
# `vigil assess approve-proposal`) before invoking. Example:
#
#   vigil assess host-exec --tool aws \
#     --intent "containment proposal=<decision-id> action=rotate_credential" \
#     --technique CONTAINMENT --finding <finding-slug> --phase respond --scope-host <customer-slug> \
#     --require-audit --allow-destructive \
#     -- aws iam delete-access-key --user-name <user> --access-key-id <id>
vigil assess host-exec \
  --tool gam --intent "containment proposal=<decision-id> action=revoke_session" \
  --technique CONTAINMENT --finding <finding-slug> --phase respond --scope-host <customer-slug> \
  --require-audit \
  -- gam user <target-email> signout
# (No --allow-destructive needed here: `signout` is not in the token
# list. Add the flag only for argv that contains a destructive token.)

# 4) Record the executed containment: registers the proof artifact,
#    writes the activity_entries row, bumps finding workflow_status to
#    `contained`. Refuses unless the proposal's decision row is approved.
vigil blue contain <finding-slug> --proposal <decision-id> --command-run-id <host-exec-run-id> \
  --proof-artifact "$ENGAGEMENT_DIR/ir/evidence/containment-<slug>-host-exec-stdout.json"

# 5) Register any out-of-band supplementary evidence (screenshot of the
#    session list emptied, ticket link in the customer's ITSM system):
vigil assess artifact register \
  "$ENGAGEMENT_DIR/ir/evidence/containment-<slug>-proof.png" \
  --kind containment_proof \
  --finding <finding-slug> \
  --agent-id <runtime-agent-id>
```

The operator-approval step is intentionally explicit. A proposal that
auto-executes on creation breaks the discipline and produces unauditable
containment.

## Eradication Patterns

Eradication runs after containment lands and removes the attacker's
foothold so re-compromise via the same primitive is not possible.

### Persistence removal

| Persistence kind | Removal action | Platform CLI |
|------------------|----------------|--------------|
| Mailbox rules (auto-forward, auto-delete, server-side filter) | Delete rule by rule-ID, citing investigator's pull | `gam user <email> delete filter <filter-id>` (GWS); EXO `Remove-InboxRule -Identity <user>:<rule>` (M365) |
| OAuth grants (third-party app authorizations) | Revoke grant by client-ID | `gam user <email> delete token <client-id>` (GWS); `Remove-MgOauth2PermissionGrant -Id <id>` (M365) |
| Scheduled tasks (Windows Task Scheduler) | EDR-driven removal or live response | `crowdstrike rtr <sensor> -- schtasks /Delete /TN <name> /F` |
| Run keys (HKCU\Software\Microsoft\Windows\CurrentVersion\Run) | Live response delete | `crowdstrike rtr <sensor> -- reg delete <key> /v <value> /f` |
| MDM device-config profiles (rogue Intune/Jamf profile) | MDM console removal | `Remove-IntuneDeviceConfigurationProfile -Id <id>` (M365 MDM) |
| AWS IAM policy attachments (rogue inline policy on a user) | `aws iam delete-user-policy` | `aws iam delete-user-policy --user-name <name> --policy-name <name>` |
| AWS Lambda functions (attacker-deployed) | Disable then delete after evidence preservation | `aws lambda update-function-configuration --state Disabled` then `delete-function` |

### Credential rotation

| Credential kind | Rotation action |
|-----------------|-----------------|
| Service-account keys (GCP) | Create new key, update consumers, delete old key. NEVER delete old key before consumers cut over. |
| API tokens (Okta, Slack, third-party SaaS) | Issue new token; deprecate old token in `inactive` state for 7 days for audit, then revoke. |
| OAuth refresh tokens (per-user, per-client) | Force re-authorization via `revoke_session` + grant deletion. |
| Password-based credentials | Out-of-band password reset + MFA factor refresh; do not rely on "change at next login" alone. |
| AWS access keys | `aws iam create-access-key` (new) → distribute → `aws iam update-access-key --status Inactive` (old) → `delete-access-key` (old) only after observation window confirms no production breakage. |

Every rotation proposal includes the same four contract fields — the
exact new-key issue command, the exact old-key disable command, the
observation window before old-key deletion, and the rollback (re-enable
the deactivated key by ID).

## Recovery Patterns

Recovery restores the affected user / host / tenant to operational state
without re-introducing the adversary's foothold.

| Recovery action | Detail |
|-----------------|--------|
| Restore-from-clean-backup | Confirm backup predates the earliest plausible compromise trigger (per `triage.md` rule 6 — T-30d look-back). Backup-date evidence is a registered artifact. |
| Re-enroll affected identities | New password + new MFA factor + new device enrollment. Re-issued credentials follow the tenant ref's documented onboarding pattern, not an ad-hoc reset. |
| Communicate to affected users | Tenant-ref-documented comms template (often in `agent/references/tenants/<customer>-<tenant-suffix>.md` § "Incident comms"). The comms message is a registered artifact (`kind=evidence`) so the report-writer cites it. |
| Re-verify detection coverage | Confirm the SIEM rule that fired the original alert is still healthy AND the rule's coverage of the compromise pattern is intact. If the rule's coverage was narrower than the actual compromise (i.e., the verifier discovered a sibling primitive that did not fire), record a `detection_gap` intel note. |
| Lessons-learned for tenant ref | Update the customer's tenant ref's "Known-benign register" if the compromise revealed a previously-thought-benign pattern that should now escalate, OR update the "Tenant config baseline" if the compromise revealed a config gap. |

## Closing Sequence

Run all four steps in order. Skipping any step breaks the audit chain,
the report-writer's containment narrative, or the next verifier
dispatch (if a follow-on finding lands).

1. **Link the audited command-run and register supplementary proof artifacts.**
   `vigil blue contain --command-run-id <id>` links the host-exec audit
   row automatically — stdout/stderr are already stored there.
   Supplementary proof (platform admin console screenshot, ITSM ticket
   link, separately-captured output) is registered additionally:
   - Screenshot of the platform admin console showing the executed
     state (sessions empty, account suspended, key inactive).
   - The customer's ITSM ticket link confirming the change.
   For UI-driven actions without a `host-exec` audit row, fall back to
   `vigil blue contain --proof-artifact <path>` which registers the file
   as `kind=containment_proof`.
2. **Record the containment activity entry:**

   ```bash
   vigil assess log <agent-id> \
     "Contained: <finding-slug> via <action_verb> against <target>" \
     "Operator-approved proposal <id>; executed via vigil blue contain at <UTC>; rollback plan: <one-line>" \
     "containment-proof artifact <id> registered" \
     --actor-kind agent
   ```

   `metadata_json` carries `tier: L4`, `containment_action: <verb>`,
   `target: <value>`, `blast_radius: <category>`, `proposal_id: <id>`,
   `finding_slug: <slug>`.

3. **Update the finding workflow status:**

   ```bash
   vigil assess finding update <finding-slug> \
     --workflow-status contained \
     --details-inline '{
       "containment_actions": [
         {"proposal_id": <id>, "action": "revoke_session", "target": "...", "executed_utc": "...", "proof_artifact_id": <id>}
       ]
     }'
   ```

   Subsequent workflow transitions: `contained → eradicated` after
   persistence removal lands; `eradicated → recovered` after the
   recovery patterns land.

4. **Emit the L4 handoff JSON:**

   ```json
   {
     "agent_id": "<runtime-agent-id>",
     "agent_role": "ir-lead",
     "phase": "respond",
     "handoff_status": "ready",
     "finding_slug": "<slug>",
     "evidence_refs": [<containment-proof-artifact-ids>],
     "containment_actions_executed": [
       {"proposal_id": <id>, "action": "revoke_session", "target": "user@northstar.example", "blast_radius": "single-user", "rollback_window_utc": "2026-05-19T18:00:00Z"}
     ],
     "eradication_actions_executed": [...],
     "recovery_actions_pending": [...],
     "next_specialist": "report-writer",
     "coverage_gaps": [],
     "rationale": "Containment landed; eradication next; recovery pending out-of-band user confirmation."
   }
   ```

## Common Failure Modes

- **Executing containment on `unreviewed` or `disputed` findings.** The
  verifier's `confirmed` verification status is the precondition. Containment on
  unverified evidence is the fastest way to lock out a legitimate user
  mid-business-hours.
- **Compound proposals.** "Contain the BEC" is not a proposal — it is a
  category. Each action against each target is its own proposal with
  its own operator approval.
- **Wildcard targets.** A target field with `*` is malformed. If the
  intent is group-level (e.g., suspend a group), `enforce_signin_policy`
  is the right action and the group ID is the target.
- **Missing rollback condition.** "No rollback" is acceptable on
  irreversible actions only when accompanied by the standard recovery
  procedure (URL or document reference). "Unknown" is not.
- **Skipping the audit linkage.** In v1 the operator runs the platform
  command through `vigil assess host-exec --require-audit` and then records
  the containment with `vigil blue contain --command-run-id <id>` so the
  audit row and stdout are linked. UI-driven actions (clicked through the
  GWS admin console, M365 portal) that cannot go through `host-exec` must
  supply `--proof-artifact <path>` instead. Without one of these, the
  report cannot show the containment landed.
- **Deleting evidence in the name of cleanup.** False-positive findings
  retain their artifacts (`triage.md` rule 19). Marking-scratch is the
  cleanup verb, not `rm`. Containment never deletes audit pulls.

## Reference Block

- `agent/rules/triage.md` — containment-proposal shape (rule 18),
  never-delete-evidence (rule 19), disposition prerequisites (rule 3).
- `agent/shared-constraints-blue.md` — WRITE-class-via-containment-proposal
  (§2), artifact chain of custody (§3), audit pipeline (§6).
- `agent/skills/exploit-playbook-authoring/SKILL.md` — red-mode analog;
  the proposal contract here mirrors the exploit playbook's manual-step
  discipline (the operator owns execution; the specialist owns the
  authoring).
- `agent/skills/alert-fp-verification/SKILL.md` — upstream verifier
  skill; produces the `confirmed` verification status that gates containment.
- `agent/skills/google-workspaces/SKILL.md` — example platform skill in
  containment mode; its "WRITE actions" section names the GWS-specific
  commands this skill's proposal table surfaces.
- `agent/references/tenants/<customer>-<tenant-suffix>.md` — tenant ref's
  documented admin identities authorized for containment execution,
  comms templates, break-glass procedures.
- `vigil blue contain` — recording verb (v1): does NOT run the platform
  command itself. The operator runs `vigil assess host-exec --require-audit
  ... -- <cmd>` first, then records the containment via
  `vigil blue contain --command-run-id <id>` (the primary path — links the
  host-exec audit row) or `--proof-artifact <path>` (for UI-driven actions
  without a `host-exec` audit row). Logs to `activity_entries` and bumps
  the finding workflow status to `contained`.
