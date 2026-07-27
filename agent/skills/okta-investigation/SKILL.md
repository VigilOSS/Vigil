---
name: okta-investigation
description: L2 Okta SystemLog + factor + admin-API audit. Push-fatigue detection, session-cookie replay, factor enrollment by attacker, API token anomaly, admin role change, hybrid AD-Okta drift.
origin: Vigil
---

# Okta Investigation (L2)

L2 platform skill for Okta-side compromise. Okta is the SAML IdP that
federates into M365, AWS, Workspace, and most SaaS apps; an Okta
compromise is upstream of every downstream tenant. The Scattered Spider /
0ktapus / LAPSUS$ playbooks land here first, so the cross-skill chain
with `m365-signin-investigation` and `aws-cloudtrail-investigation` is
bidirectional.

## When to Activate

- L1 `alert-triage` dispatches `platform=okta` with category in
  `push-fatigue`, `factor-reset`, `admin-role-change`,
  `api-token-anomaly`, `password-policy-change`, `aitm-token-replay`.
- `aws-cloudtrail-investigation` traced a SAML chain back to the IdP and
  needs Okta sign-in context (the AWS-side trail ends at
  `AssumeRoleWithSAML`; the Okta-side trail starts at
  `user.authentication.sso`).
- `m365-signin-investigation` confirmed an Entra-via-Okta SAML compromise
  and needs the upstream Okta sign-in, factor state, and session
  fingerprint.
- `phishing-triage` identified an AiTM landing page whose target was the
  Okta sign-in flow — pivot here to look for session cookie replay.

L2 does NOT write disposition; the verifier (`alert-fp-verification`)
does. L2 produces registered artifacts, an evidence ladder, a
coverage-gaps list, and a handoff JSON the verifier consumes.

## Operating Rules

Read-only by default. Every Okta API call uses a service-app token with
read-only scopes; suspend/clear-sessions/reset-factors live in
`incident-containment` and require an `vigil blue propose-contain` approval gate.

Always-active references — load before the first API call:

- `agent/rules/triage.md` — disposition vocabulary, severity recompute,
  30-day look-back (rule 6), MITRE on every finding (rule 11),
  tenant-ref first (rule 12), UTC (rule 7).
- `agent/shared-constraints-blue.md` — authorization, artifact chain of
  custody under `$ENGAGEMENT_DIR/ir/reports/`, dispatch handoff schema,
  resume hydration, echo-banner prohibition.
- `agent/rules/ir-evidence.md` — attribution gates, multi-signal
  corroboration, the distinction between "session replay" and
  "credential capture + MFA bypass" claims.
- `agent/references/tenants/<customer>-okta.md` — org URL, documented
  super-admins, API token baseline, factor-reset helpdesk pattern,
  traveling-user pattern, AD-sync lag window, known-benign register.
- `agent/skills/m365-signin-investigation/SKILL.md` and
  `agent/skills/aws-cloudtrail-investigation/SKILL.md` — load when the
  Okta trail terminates with a SAML assertion into either platform.

UTC is the working timezone. Okta SystemLog `published` is UTC ISO-8601
already; do not convert until writing narrative.

Look-back is 30 days minimum on first pass. Push-fatigue, factor
grafting, and API token persistence routinely sit 7-14 days behind
user-visible symptoms.

## Tools

L2 is `vigil assess host-exec` territory for Okta API pulls plus
`artifact register` for every raw response. There is no widely-adopted
`okta-cli` at production grade — `curl` + `jq` is the primary surface.

| Task | Tool | Why |
|---|---|---|
| Org context | `curl -H "Authorization: SSWS $OKTA_API_TOKEN" https://<org>.okta.com/api/v1/org` | One-shot tenant identity confirmation; cheaper than SDK auth dance |
| SystemLog pull (per-actor windowed) | `curl ".../api/v1/logs?since=<iso>&until=<iso>&filter=actor.id eq \"<id>\""` | Paginate via `Link: rel="next"` response header until exhausted |
| User factors enumeration | `curl ".../api/v1/users/{id}/factors"` | Returns every enrolled factor with `created` timestamp; factor diff is step 2's core evidence |
| User profile + attributes | `curl ".../api/v1/users/{id}"` | Compared against `Get-ADUser` for hybrid drift in step 6 |
| API token inventory | `curl ".../api/v1/api/tokens"` | New tokens within incident window are the persistence signal |
| App assignments per user | `curl ".../api/v1/apps?filter=user.id eq \"<id>\""` | Cross-reference against tenant-ref app baseline; new admin-console app assignment = escalation |
| Policies (MFA enroll, access, authenticator) | `curl ".../api/v1/policies?type=MFA_ENROLL"`, `?type=ACCESS_POLICY`, `?type=AUTHENTICATOR` | Policy diff against last verified baseline catches step-up bypass |
| Active sessions | `curl ".../api/v1/users/{id}/sessions"` | Where supported; some tenants restrict this endpoint by feature flag |
| Hybrid AD pivot | PowerShell `Get-ADUser`, `Get-ADGroupMember` | AD-side state for hybrid drift in step 6; runs from a domain-joined admin workstation |
| Filter / project JSON | `jq` | Read-only, fast, no tenant calls |
| AiTM correlation | `vigil assess artifact search "device_fingerprint"` | Sibling-skill artifacts (M365, AWS) often already carry the device fingerprint Okta needs to dedupe |

### Token + scope requirement

Prefer an **OAuth-scoped service-app token** over a static super-admin
SSWS token. Required scopes: `okta.users.read`, `okta.logs.read`,
`okta.policies.read`, `okta.apps.read`. SSWS tokens appear under the
issuing admin's identity in the audit feed and pollute the actor
history; document the issuing identity in `coverage_gaps` if a legacy
tenant forces SSWS. Token lives in `OKTA_API_TOKEN`; never include the
body in artifacts — reference it by service-app name only.

### Pagination discipline

SystemLog returns at most 1000 events per page with a `Link: <...>;
rel="next"` header per page. Pull is not complete until the response
returns no `rel="next"`. Truncated pulls miss the factor-enrollment
event that lives 14 hours into a 30-day window.

```bash
URL="https://<org>.okta.com/api/v1/logs?since=$SINCE&until=$UNTIL&filter=actor.id+eq+%22$USER_ID%22"
while [[ -n "$URL" ]]; do
  resp=$(curl -s -i -H "Authorization: SSWS $OKTA_API_TOKEN" "$URL")
  body=$(printf '%s' "$resp" | awk 'BEGIN{p=0} /^\r?$/{p=1; next} p')
  printf '%s\n' "$body" >> "$ENGAGEMENT_DIR/ir/reports/okta_systemlog_${USER_ID}.json"
  URL=$(printf '%s' "$resp" | awk -F'[<>]' 'tolower($0) ~ /rel="next"/ {print $2; exit}')
done
```

## Methodology

### Step 1 — Hydrate actor + SystemLog window

**Purpose**: Establish actor baseline and surface anomaly candidates.
Every subsequent step reads from the SystemLog pull produced here.

**Action**:
1. Resolve `user.id` from the UPN: `curl ".../api/v1/users?q=<upn>&limit=1"`.
   Capture the `id` (`00u...` prefix) — Okta filters by ID, not email.
2. Set the window: `SINCE=$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ')`,
   `UNTIL=$(date -u '+%Y-%m-%dT%H:%M:%SZ')`. Extend `SINCE` if anomalous
   events cluster near the 30-day boundary.
3. Pull the windowed SystemLog with the pagination loop above.
4. Group events by `eventType`:
   `jq -r '.[] | .eventType' | sort | uniq -c | sort -rn`. The histogram
   seeds the anomaly hypothesis for steps 2-6.

**Evidence**: Paginated SystemLog JSON as `ir_log`; event-type histogram
as `ir_evidence`.

**False positives**: Known automation actors (Okta IT Service, scheduled
provisioning syncs) inflate volume. The tenant ref's `api_token_baseline`
lists these; filter before treating event volume as anomalous.

### Step 2 — MFA factor enumeration + diff

**Purpose**: Detect factor grafting — adversary enrolls a new factor
(typically a TOTP authenticator they control) under a stolen session so
subsequent step-up succeeds against the adversary's device. `T1556.006`,
the canonical Scattered Spider TTP since 2022.

**Action**:
1. `curl ".../api/v1/users/{id}/factors"` — returns every enrolled
   factor with `factorType`, `provider`, `status`, `created`,
   `lastUpdated`, `profile`.
2. Compare to the tenant-ref baseline. A factor `created` inside the
   incident window that is not on the baseline is the primary signal.
3. Cross-check SystemLog for `user.mfa.factor.activate` and
   `user.mfa.factor.update` events — factor record shows what is
   enrolled now; SystemLog shows who enrolled it, from what IP, with
   what session.

**Evidence**: Factor JSON as `ir_log`; factor-diff markdown as
`ir_evidence` with SystemLog event IDs cited inline.

**False positives**: Legitimate phone-add via helpdesk-initiated reset.
The tenant ref's `factor_reset_helpdesk_pattern` lists the helpdesk
identity and ticket pattern; a factor-add paired with a same-window
ticket is benign. A factor-add with no ticket and an actor IP outside
the user's 30-day ASN baseline is adversarial.

### Step 3 — Push-fatigue detection

**Purpose**: Detect MFA-fatigue exploitation (`T1621`) — adversary
holds the stolen password and spams push challenges until the user
accepts one. Canonical LAPSUS$ / Scattered Spider pattern.

**Action**:
1. Filter SystemLog for `user.authentication.auth_via_mfa` over the
   window.
2. Compute the 60-second sliding window of `outcome.result=DENIED`.
3. Surface clusters where ≥3 `DENIED` occur within 60 seconds followed
   by a single `ALLOWED` within 90 seconds of the last `DENIED`.
4. For each cluster, capture the IP, ASN, and user-agent of the
   `ALLOWED` event — the adversary's session is fingerprinted there.

```bash
jq '[.[] | select(.eventType == "user.authentication.auth_via_mfa")
  | {ts: .published, outcome: .outcome.result, ip: .client.ipAddress,
     asn: .client.geographicalContext.asn,
     ua: .client.userAgent.rawUserAgent}]' \
  "$ENGAGEMENT_DIR/ir/reports/okta_systemlog_${USER_ID}.json" \
  > "$ENGAGEMENT_DIR/ir/evidence/push_fatigue_${USER_ID}.json"
```

**Evidence**: Filtered push-event JSON and the cluster summary as
`ir_evidence` with IPs cross-referenced against the 30-day ASN baseline.

**False positives**: Broken-authenticator-app retries. Three
discriminators must all hold for benign: (a) IP across all `DENIED` and
the eventual `ALLOWED` is the same and matches the baseline ASN; (b) a
same-window helpdesk ticket exists mentioning push delivery; (c) the
user-agent across the cluster is stable and matches a known device. Any
one breaking → escalate.

### Step 4 — Session-cookie + token replay

**Purpose**: Detect AiTM session cookie theft (Evilginx, EvilProxy,
Modlishka) where the adversary captured an authenticated session via a
reverse proxy and replayed the cookie from a new device.

**Action**:
1. Filter SystemLog for `user.session.start` and
   `policy.evaluate_sign_on` over the window.
2. For each `user.session.start`, capture
   `client.device.deviceFingerprint`, `client.ipAddress`,
   `client.geographicalContext.asn`, `client.userAgent.rawUserAgent`.
3. Build the actor's fingerprint set from the 30-day baseline. A
   `user.session.start` inside the incident window with a fingerprint
   not in the baseline set is the candidate.
4. For each candidate, look for the same `sessionId` (or refreshed
   token chain) earlier in the SystemLog — token replay produces a new
   session_start without a corresponding fresh primary authentication.
5. Cross-check `policy.evaluate_sign_on`: `result=ALLOW` with a
   `deviceFingerprint` mismatch from prior sessions, paired with a
   `behaviors` block flagging `New Device` / `New Geo-Location`, is the
   AiTM signature.

**Evidence**: Filtered session + policy JSON as `ir_log`; fingerprint
baseline-vs-incident diff as `ir_evidence` with `sessionId` and
`published` cited.

**False positives**: Legitimate multi-device users (laptop + phone, or
laptop + new self-enrolled home machine). Tenant ref's
`traveling_user_pattern` lists frequent travelers and multi-device
users. A new-device session for a listed user still warrants L2 review
but should not advance to `verified` without further corroboration
(e.g., concurrent sessions from geographically incompatible IPs).

### Step 5 — Admin + API token review

**Purpose**: Detect persistence via admin role assignment (`T1098`) or
new API tokens (`T1098.001`). Either gives durable access that survives
session and credential rotations.

**Action**:
1. Pull admin assignments:
   `curl ".../api/v1/users?filter=type.id+eq+\"<super-admin-type-id>\""`.
   Diff against the tenant-ref super-admin list; new entries inside the
   window are candidates.
2. Cross-reference SystemLog `user.account.privilege.grant` and
   `group.user_membership.add` — these tell you who granted, when,
   from what IP.
3. Pull API tokens: `curl ".../api/v1/api/tokens"`. Diff against the
   tenant-ref `api_token_baseline`; window-new tokens are candidates.
4. Cross-reference SystemLog `system.api_token.create`. Non-admin users
   issuing API tokens is a serious signal — Okta normally restricts
   token issuance to admins, so non-admin creation means the user holds
   an undocumented admin role, which is itself a finding.

**Evidence**: Admin JSON, token JSON, privilege-grant slice as `ir_log`;
diff markdown as `ir_evidence` citing each new token's `id`, `name`,
`createdBy`, `lastUsed`.

**False positives**: Documented service-account tokens in
`api_token_baseline`. Token name matching baseline (`okta-sync-prod`,
`siem-ingest`) plus documented owner is benign. Generic names (`test`,
`api`, `temp`) with unexpected owner are persistence handles.

### Step 6 — Hybrid AD-Okta consistency drift

**Purpose**: Detect lateral persistence where the adversary modifies the
on-prem AD side (hybrid AD-Okta via the Okta AD agent) and lets directory
sync propagate the change into Okta. The Okta audit feed shows a sync
event, not a user modification — without cross-referencing AD, the
change looks benign.

**Action**:
1. Pull AD-side state from a domain-joined admin workstation:
   ```powershell
   Get-ADUser -Identity <samaccountname> -Properties manager,memberOf,enabled,whenChanged,pwdLastSet | ConvertTo-Json -Depth 4
   ```
2. Pull Okta state: `curl ".../api/v1/users/{id}"`.
3. Diff `manager`, `memberOf` / group memberships, `enabled` /
   `status`, and `pwdLastSet` / `passwordChanged`. Drift during the
   window is the signal.
4. Cross-check against `ad_sync_lag_window` — typical sync lag is
   15-30 minutes. Drift older than the documented lag with no matching
   ticket is adversarial.

**Evidence**: Paired AD + Okta JSON as `ir_log`; per-field drift table
as `ir_evidence` with the ticket-system query result (showing no
matching change ticket) cited inline.

**False positives**: Sync lag itself. If `whenChanged` (AD) is within
`ad_sync_lag_window` of `lastUpdated` (Okta), the drift is in-flight.
Re-pull both sides after the documented lag before flagging.

## MITRE Technique Mapping

| Step | Technique | Notes |
|------|-----------|-------|
| 2 | `T1556.006` | MFA bypass via factor enrollment / removal |
| 2 | `T1556` | Modify Authentication Process (broader parent) |
| 3 | `T1621` | MFA Request Generation (push fatigue) |
| 4 | `T1078.004` | Cloud Accounts — stolen session paths |
| 4 | `T1539` | Steal Web Session Cookie — AiTM replay specifically |
| 5 | `T1098` | Account Manipulation — admin role assignment |
| 5 | `T1098.001` | Additional Cloud Credentials — new API token |
| 6 | `T1556` | Modify Authentication Process via upstream AD |
| 6 | `T1078.004` | Cloud Accounts — drift-driven persistence |

CISA AA23-263A is the canonical reference for Scattered Spider Okta TTPs
(push fatigue, factor enrollment, session theft, helpdesk social
engineering). Verify pattern attribution against the advisory directly
before final report — automated fetches of the advisory page have
returned `403` during authoring, and the TTP set there is authoritative.

## Known-benign register additions

When the verifier confirms `false_positive` on an Okta finding, these
row shapes are eligible for promotion into the tenant ref's "Known
benign patterns" section (`_template-okta.md`):

- `documented_push_test` — quarterly MFA drills. Fields: drill name,
  start/end UTC, user scope.
- `factor_reset_helpdesk_pattern` — helpdesk-initiated resets with
  ticket IDs. Fields: helpdesk identity, ticket-system URL pattern,
  factor types covered.
- `api_token_baseline` — service-owned tokens. Fields: token name,
  owning service-account, scope set, last-rotated UTC.
- `traveling_user_pattern` — frequent travelers. Fields: user UPN,
  baseline ASN list, refresh interval.
- `ad_sync_lag_window` — documented directory-sync delay. Fields:
  forward (AD → Okta) lag, reverse where applicable, last verified UTC.

Promotion rules per `agent/rules/triage.md` rule 5: only an L3 verifier
who confirmed `false_positive` with cited counter-evidence may seed a
`mechanical: true` row.

## Disposition heuristics

L2 does NOT write disposition. These are heuristics for the
`confidence` and `severity_recommendation` fields in the handoff JSON;
the verifier owns the decision.

- Lean **verified**: new factor enrolled by a non-helpdesk actor + new
  session from a never-seen device fingerprint in the same hour +
  session-cookie replay signal (same `sessionId`, different
  fingerprint).
- Lean **false_positive**: every signal in steps 2-6 individually
  explained by a tenant-ref baseline entry plus a corresponding
  helpdesk ticket. Symmetric bar to `verified` — hand-wave explanations
  are `escalated`, not `false_positive`.
- Lean **downgraded**: push-fatigue fired but the user denied every
  challenge with no subsequent `ALLOWED` and no factor/session change.
  Technique attempted, not landed.
- Lean **escalated**: one or two checks positive, others inconclusive
  (e.g., factor enrollment with no session anomaly). Voting belongs in
  the verifier's skill, not here.

## Activity Log Convention

Every methodology step closes with an `vigil assess log` row. The
metadata fields below let the report-writer's FTS find Okta-specific
evidence without parsing the free-text body.

```bash
vigil assess log <agent-id> \
  "Okta step <N>: <step name> for <finding-slug>" \
  "<one-line action summary citing artifact IDs>" \
  "<one-line result summary>" \
  --actor-kind agent
```

`metadata_json` on the row carries:

- `tier: L2`
- `platform: okta`
- `step_number: 1|2|3|4|5|6`
- `okta_org: <org>.okta.com`
- `actor_id: <00u...>`
- `factor_enrolled: <factorType>` (step 2 only, when present)
- `push_fatigue_cluster_count: <int>` (step 3 only)
- `session_fingerprint_new: true|false` (step 4 only)
- `api_token_id: <id>` (step 5 only, when present)
- `ad_drift_fields: [manager|memberOf|enabled|...]` (step 6 only)
- `artifact_refs: [<id>, ...]`

## Output Contract

The L2 handoff JSON consumed by the verifier:

```json
{
  "agent_id": "<runtime-agent-id>",
  "agent_role": "okta-investigator",
  "phase": "investigate",
  "handoff_status": "ready",
  "finding_slug": "<from L1 handoff>",
  "skill_consumed": "okta-investigation",
  "platform": "okta",
  "okta_org": "<org>.okta.com",
  "actor": "<upn>",
  "actor_id": "<00u...>",
  "time_window_utc": ["<since>", "<until>"],
  "mitre_techniques_observed": ["T1621", "T1556.006", "T1539"],
  "severity_recommendation": "high",
  "confidence": "medium",
  "confidence_rationale": "<one sentence citing the corroborating signals>",
  "evidence_refs": [<artifact-id>, ...],
  "step_outcomes": {
    "step1_systemlog": {"events": <int>, "histogram_artifact": <id>},
    "step2_factors": {"new_factors": [...], "helpdesk_ticket": "<id|none>"},
    "step3_push_fatigue": {"clusters": <int>, "allowed_after_denied": true|false},
    "step4_session_replay": {"new_fingerprints": [...], "session_ids": [...]},
    "step5_admin_api_tokens": {"new_admins": [...], "new_tokens": [...]},
    "step6_ad_drift": {"drift_fields": [...], "within_sync_window": true|false}
  },
  "coverage_gaps": [
    "<e.g. tenant did not enable user.session.start for non-interactive flows; cannot confirm AiTM via session_start alone>"
  ],
  "cross_platform_correlation_notes": "<if M365 / AWS / Workspace artifacts already exist in the engagement, name them by ID and describe the chain>",
  "next_specialist": "verifier",
  "next_steps": [
    "Five-check verification on <finding-slug> with the step-outcomes above as primary evidence",
    "Devil's-advocate against tenant-ref `factor_reset_helpdesk_pattern` / `traveling_user_pattern` / `api_token_baseline`",
    "If verified: hand to ir-lead with proposals for `revoke_session`, `force_mfa_reenroll`, `revoke_api_token` per `incident-containment`"
  ],
  "rationale": "<one paragraph: which steps fired, what evidence corroborates, what the verifier should focus the five-check on first>"
}
```

## Closing Sequence

Run in order at the end of the L2 dispatch:

1. **Register every raw API response** as an `ir_log` artifact —
   SystemLog pull, factor list, token inventory, app assignments,
   policies, admin user list, AD `Get-ADUser` JSON:

   ```bash
   vigil assess artifact register \
     "$ENGAGEMENT_DIR/ir/reports/okta_systemlog_${USER_ID}.json" \
     --kind ir_log \
     --finding <finding-slug> \
     --agent-id <runtime-agent-id> \
     --sensitive
   ```

   `--sensitive` is mandatory — Okta SystemLog rows include source IPs,
   user-agents, and session identifiers that survive token rotation.

2. **Register every derived analysis file** as an `ir_evidence`
   artifact — event histogram, factor diff, push-fatigue clusters,
   fingerprint diff, admin/token diff, AD drift table. Each derived
   file embeds the `jq` or PowerShell command that produced it so
   another investigator can re-run.

3. **Log the closing handoff entry**:

   ```bash
   vigil assess log <agent-id> \
     "Okta L2 handoff for <finding-slug>" \
     "Pulled SystemLog/factors/tokens/policies across 30d window; ran all 6 steps; registered artifacts <id-list>" \
     "Handoff to verifier with severity_recommendation=<x> confidence=<y>" \
     --actor-kind agent
   ```

4. **Emit the handoff JSON** to `/tmp/handoff.json` and record it:

   ```bash
   vigil assess agent handoff --from-json /tmp/handoff.json
   ```

## Common Failure Modes

- **Filtering SystemLog only on `actor.id`** when the adversary pivoted
  through a service-account proxy or `impersonatedUser` flow. Pair the
  actor filter with at least one independent axis (`client.ipAddress`,
  `authenticationContext.externalSessionId`, `target[].id`).
- **Skipping step 6** because the SystemLog looks clean. Adversaries
  who own the AD side make Okta-side changes appear as benign syncs.
  Non-optional for hybrid tenants.
- **Confusing push-fatigue with broken-authenticator retries.** Check
  same-window helpdesk ticket + same-ASN sourcing before treating push
  spam as adversarial.
- **Treating `policy.evaluate_sign_on` `result=ALLOW` as definitive.**
  An adversary who replayed a stolen fingerprint produces a clean
  `ALLOW`. Corroborate with `sessionId` history.
- **Static SSWS token used as the API token.** Every call then appears
  as the issuing admin in SystemLog. Prefer OAuth service-app tokens;
  if legacy SSWS is forced, document the issuing identity in
  `coverage_gaps`.
- **Truncated SystemLog pulls** that stop at 1000 events because the
  operator forgot the `Link: rel="next"` loop.
- **Token body in artifacts.** Reference tokens by service-app name
  only. A leaked `OKTA_API_TOKEN` forces rotation and re-pull of every
  Okta artifact.
- **Not registering the AD-side JSON** because it came from PowerShell
  on a different workstation. Chain of custody requires every evidence
  input to land under `$ENGAGEMENT_DIR/ir/reports/`.

## Reference Block

- `agent/rules/triage.md` — disposition vocabulary, severity recompute,
  30-day look-back, MITRE on every finding, tenant-ref first, UTC.
- `agent/shared-constraints-blue.md` — authorization, read-only,
  artifact chain of custody, dispatch handoff schema.
- `agent/rules/ir-evidence.md` — attribution gates, multi-signal
  corroboration.
- `agent/skills/alert-triage/SKILL.md` — the L1 dispatch this skill
  consumes.
- `agent/skills/alert-fp-verification/SKILL.md` — the L3 verifier this
  skill hands forward to.
- `agent/skills/m365-signin-investigation/SKILL.md` — load when the
  Okta trail terminates with a SAML assertion into Entra.
- `agent/skills/aws-cloudtrail-investigation/SKILL.md` — load when the
  trail terminates with `AssumeRoleWithSAML` into AWS.
- `agent/skills/phishing-triage/SKILL.md` — load when an AiTM landing
  page targeted Okta sign-in directly.
- `agent/skills/incident-containment/SKILL.md` — L4 owns
  `revoke_session`, `force_mfa_reenroll`, `revoke_api_token`,
  `disable_account` for verified Okta findings.
- `agent/references/tenants/<customer>-okta.md` — operator-curated
  tenant ref with org URL, admin identities, baselines, helpdesk
  pattern, AD-sync lag, known-benign register.
- Okta SystemLog: `https://developer.okta.com/docs/reference/api/system-log/`
- Okta Users API: `https://developer.okta.com/docs/reference/api/users/`
- Okta Factors API: `https://developer.okta.com/docs/reference/api/factors/`
- Okta Policies API: `https://developer.okta.com/docs/reference/api/policy/`
- MITRE T1621: `https://attack.mitre.org/techniques/T1621/`
- MITRE T1556.006: `https://attack.mitre.org/techniques/T1556/006/`
- MITRE T1539: `https://attack.mitre.org/techniques/T1539/`
- CISA AA23-263A (verify directly; `403` from automated fetch):
  `https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-263a`
