---
name: m365-signin-investigation
description: L2 Microsoft 365 sign-in + audit log investigation. Entra Sign-In Logs (interactive + non-interactive + service principal + managed identity), AAD audit, UAL hunting, mailbox forensics, OAuth app audit, impossible-travel correlation, conditional access state.
origin: Vigil
---

# M365 Sign-In Investigation (L2)

L2 platform-investigator skill. Owns the audit pull, correlation, and
timeline reconstruction for any Microsoft 365 / Entra ID actor handed
down by L1. Does **not** own disposition (L3 `alert-fp-verification`) or
containment (L4 `ir-lead`). The job: produce a defensible timeline +
evidence set the verifier can rule on without re-pulling.

## When to Activate

- L1 `alert-triage` dispatches with `platform=m365` and category one of:
  `anomalous-sign-in`, `impossible-travel`, `suspicious-oauth-grant`,
  `mailbox-rule-created`, `bec`, `risky-user`, `risky-sign-in`.
- `phishing-triage` has confirmed credential entry on a Microsoft sign-in
  page and the post-auth scope is M365; the phishing skill hands the actor
  UPN, the click timestamp, and the lure URL.
- L4 `ir-lead` is about to propose token-revoke + disable-account on an
  Entra principal and needs UAL evidence in the finding before approval.
- `aws-cloudtrail-investigation` traced a federated SAML assertion back to
  Entra ID as the IdP and needs the Entra-side sign-in record to anchor
  the federation chain.
- `okta-investigation` ruled Okta out as the credential origin on an
  inbound SAML chain and the Entra-side direct sign-in becomes the new
  hypothesis.

This skill is for L2 investigation of M365 sign-in anomalies. L1 dispatch decisions belong to alert-triage, verification belongs to alert-fp-verification, and
post-incident reporting (report-generation owns that).

## Operating Rules

These constrain every action under this skill. They apply before any tenant
command runs.

**Always-active references:**

- `agent/rules/triage.md` — disposition vocabulary (rule 3), symmetric
  evidence bar (rule 4), 30-day look-back (rule 6), UTC discipline
  (rule 7), confidence labels (rule 9), MITRE technique requirement
  (rule 11), tenant-ref first (rule 12).
- `agent/shared-constraints-blue.md` — read-only-by-default (§2), artifact
  chain of custody (§3), UTC (§4), audit pipeline via `vigil assess
  host-exec` (§6), tenant scope (§7), confidence labels (§8), dispatch
  handoff conventions.
- `agent/rules/ir-evidence.md` — attribution gates, multi-signal
  corroboration definitions, evidence-file conventions.
- The tenant ref at `agent/references/tenants/<customer>-m365.md`
  (template: `_template-m365.md`). Halts the dispatch if missing —
  the tenant ref is what tells you which Super Admin to impersonate,
  which Graph application registration owns the audit-read scopes,
  which sign-in patterns are already documented as benign, and which
  conditional-access policies are in report-only mode by design.

**Read-only by default.** Every Graph PowerShell SDK call, every
Exchange Online call, every Defender Advanced Hunting query in this skill
is read-only. WRITE actions (token revoke, password reset, disable
account, OAuth grant removal) are L4 `incident-containment`'s job — not
this skill's. If the investigation surfaces an obvious containment lever
mid-pull, document it in the handoff and stop; do not silently rotate a
session on a maintenance-window timer.

**Four sign-in streams or it didn't happen.** Entra serves four
independent sign-in log categories (interactive user, non-interactive
user, service principal, managed identity). Attackers prefer the
non-interactive stream — that is where refresh-token replay shows up and
where MFA does not gate the session. Pulling only the interactive stream
misses 70-90% of post-compromise activity and produces a timeline that
"looks clean" until the verifier catches the gap. Pull all four. Always.

**UTC throughout.** Sign-in logs and UAL emit UTC by default; do not
convert mid-investigation. ISO-8601 with explicit `Z` is the only
acceptable timestamp format in evidence files and finding
`details.timeline` rows.

**Tenant-ref first.** Before the first Graph call runs, read the tenant
ref end to end. Skip this and you will misclassify a documented
maintenance-window service principal sign-in as adversarial, or treat a
known executive's frequent-travel pattern as impossible-travel.

## Tools

| Task | Tool | Why |
|---|---|---|
| Entra context check (which tenant, which admin am I signed in as) | `az account show`, `az ad signed-in-user show` | Read-only; confirms which tenant the host-exec is pointed at before any pull. |
| Interactive + non-interactive sign-in pull | Microsoft Graph PowerShell SDK `Get-MgAuditLogSignIn` | The canonical, paginated source; supports `-Filter` per stream and `-All` for full window pulls. |
| Service principal + managed identity sign-in pull | `Get-MgAuditLogSignIn -Filter "signInEventTypes/any(t:t eq 'servicePrincipal')"` / `"...'managedIdentity'"` | Entra exposes the four streams via the `signInEventTypes` filter; SP and MI are the streams attackers use for refresh-token replay and workload-identity abuse. |
| Directory audit (role changes, app-registration mutations, policy edits) | `Get-MgAuditLogDirectoryAudit` | Captures admin-plane mutations that sign-in logs do not. |
| Unified Audit Log hunt | Exchange Online `Search-UnifiedAuditLog -StartDate ... -EndDate ... -UserIds <upn>` | The cross-workload audit feed (SharePoint / OneDrive / Exchange / Teams / Azure AD admin events); requires `ExchangeOnlineManagement` PowerShell module. |
| Inbox rules per mailbox | `Get-InboxRule -Mailbox <upn>` | The classic T1564.008 "hide security alerts" persistence surface. |
| Mailbox forwarding / delivery settings | `Get-Mailbox <upn> \| Format-List ForwardingSmtpAddress,DeliverToMailboxAndForward,ForwardingAddress` | External auto-forward (T1114.003). |
| Mailbox folder permissions (delegated read) | `Get-MailboxFolderPermission "<upn>:\Inbox"` | T1098.002 / T1114 delegated read. |
| Auto-reply state | `Get-MailboxAutoReplyConfiguration -Identity <upn>` | OOF messages weaponized for vendor-pivot BEC. |
| OAuth grants and app-role assignments | `Get-MgOauth2PermissionGrant`, `Get-MgServicePrincipalAppRoleAssignedTo`, `Get-MgUserAppRoleAssignment` | T1098.001 — new high-risk grants mid-incident are the persistence-via-grant signal. |
| Conditional Access policy state | `Get-MgIdentityConditionalAccessPolicy` | Confirms which policies should have blocked the sign-in and whether they were in `report-only` vs `enabled` state. |
| Defender XDR Advanced Hunting (KQL over `AADSignInEventsBeta`, `IdentityLogonEvents`, `EmailEvents`, `CloudAppEvents`, `OAuthAppInfo`, `AppFileEvents`) | `curl` POST to `https://api.security.microsoft.com/api/advancedhunting/run` | The Defender-XDR superset of sign-in data with 30-day retention by default; KQL gives correlation in one query that takes multiple Graph round-trips. |
| Risky users / risky sign-ins | `Get-MgRiskyUser`, `Get-MgRiskDetection` | Entra ID Protection signals are the verifier's "another control fired" corroboration source. |
| SharePoint / OneDrive admin audit | `pnp/cli-microsoft365` (`m365 spo ...`) | Site-level activity that UAL summarizes but does not always detail. |
| Offline parse / correlate | `jq`, `python3` | All offline; no tenant calls, no host-exec wrapper required. |

Every tenant-facing command above runs through `vigil assess host-exec`
with `--phase investigate --scope-host <tenant-slug>` and a non-empty
`--intent`. Host-side `jq`/`python3` over a registered artifact do not
require the wrapper (see `agent/shared-constraints-blue.md` §6).

### Graph application-registration scopes required

These are the read-only scopes the engagement's Graph app registration
must hold (granted by the tenant admin to a documented enterprise app in
the tenant ref's setup section, not added ad-hoc):

```
AuditLog.Read.All            # Get-MgAuditLogSignIn, Get-MgAuditLogDirectoryAudit
Directory.Read.All           # users, groups, app registrations, service principals
SecurityEvents.Read.All      # Defender XDR alerts
ThreatHunting.Read.All       # Advanced Hunting API
IdentityRiskyUser.Read.All   # risky users / risk detections
IdentityRiskEvent.Read.All
Mail.ReadBasic.All           # mailbox metadata (no body content)
MailboxSettings.Read         # inbox rules, forwarding, auto-reply via Graph
Policy.Read.All              # conditional-access policies
Application.Read.All         # OAuth grants, app role assignments
```

Exchange Online (`Search-UnifiedAuditLog`, `Get-InboxRule`,
`Get-MailboxFolderPermission`) is not a Graph endpoint; it requires
`View-Only Audit Logs` (or `Audit Logs`) and `View-Only Recipients`
Exchange RBAC roles on the impersonating principal, plus
`ExchangeOnlineManagement` module installed.

The tenant ref's "Setup" section documents the exact app-registration
client ID, the certificate-thumbprint / managed-identity used for non-
interactive auth, and the Exchange role group the IR principal sits in.
Missing scopes surface as a `403 Forbidden` or `Authorization_RequestDenied`
on the first call — do not improvise scope grants mid-investigation;
return a `blocked` handoff naming the missing scope.

## Methodology

Seven sequential steps. Each step lists Purpose / Action / Evidence /
Common-FP. Do not skip a step because "the alert already shows X" — the
alert is a starting point, not the answer.

### 1. Hydrate actor identity

**Purpose.** An incident actor is rarely a single UPN. Aliases,
immutable IDs, on-prem-AD ObjectIDs, and guest principals surface under
different filter values; pulling sign-ins by the alert's UPN alone
misses the alias the attacker actually used.

**Action.** Two host-exec calls
(`--phase investigate --scope-host <tenant> --target-host <upn>`):

1. **Actor envelope** (`--tool az --technique IOC-ENRICH`):
   ```bash
   az ad user show --id "<upn>" --query "{upn:userPrincipalName,id:id,
     immutableId:onPremisesImmutableId,mail:mail,
     proxyAddresses:proxyAddresses,otherMails:otherMails}" -o json
   ```
   → `actor_envelope_<slug>.json`.

2. **30-day baseline** (`--tool pwsh --technique T1078.004`):
   ```powershell
   Get-MgAuditLogSignIn -All -Filter "userPrincipalName eq '<upn>'
     and createdDateTime ge $((Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ'))"
   ```
   → `signin_baseline_<slug>_30d.json`. Derive the ASN / country /
   device-ID histogram with `jq` — that is the comparison source for
   steps 2 and 3.

**Evidence.** `signin_baseline_<slug>_30d.json`,
`actor_envelope_<slug>.json`, one-line histogram of ASN / country / app
counts.

**Common-FP.** A globally-distributed executive with legitimate VPN +
hotel-Wi-Fi looks identical to a residential-proxy attacker at IP level.
A new corporate Intune-enrolled device with a fresh device ID can look
like a rogue device-trust grant. Resolve via `traveling_user_pattern`
and the recent Intune enrollment audit; do not call either compromise
without a second signal.

### 2. Four-stream sign-in pull

**Purpose.** Entra serves four sign-in categories per Microsoft's
documented architecture (https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins):

1. **Interactive user sign-ins** — a human typed credentials or completed
   an MFA challenge. `signInEventTypes/any(t:t eq 'interactiveUser')`.
2. **Non-interactive user sign-ins** — silent token refresh, refresh-
   token replay, FOCI client redemption. `signInEventTypes/any(t:t eq
   'nonInteractiveUser')`. **This is the stream attackers use most.**
3. **Service principal sign-ins** — first-party or third-party apps
   authenticating with client credentials. `signInEventTypes/any(t:t eq
   'servicePrincipal')`.
4. **Managed identity sign-ins** — Azure resources authenticating with
   their assigned managed identity. `signInEventTypes/any(t:t eq
   'managedIdentity')`.

A finding built off only the interactive stream is incomplete by
construction.

**Action.** Loop the four streams; one host-exec call per stream
(`--tool pwsh --technique T1078.004 --phase investigate --scope-host
<tenant> --target-host <upn>`):

```powershell
# per-stream filter, for STREAM in {interactiveUser, nonInteractiveUser, servicePrincipal, managedIdentity}
Get-MgAuditLogSignIn -All -Filter "signInEventTypes/any(t:t eq '<STREAM>')
  and userPrincipalName eq '<upn>'
  and createdDateTime ge <WINDOW_START> and createdDateTime le <WINDOW_END>"
```

Outputs → `$DIR/signin_<stream>_<slug>_<window>.json`. Register each as
`--kind ir_log`. For service-principal / managed-identity streams, the
`userPrincipalName` filter is inapplicable — filter on `appId` or
`appDisplayName eq '<value>'`. SP and MI streams are tenant-wide; narrow
to the apps of interest to keep the pull focused.

**Evidence.** Four registered `ir_log` artifacts (one per stream).

**Common-FP.** A legitimate background app (Outlook mobile, Teams
desktop, OneDrive sync) generates dozens to hundreds of
non-interactive sign-ins per day with no security significance. A
service principal scheduled by IT for a maintenance job at the same
hour every day is not adversarial. Diff against the tenant ref's
`service_principal_baseline` list before flagging any SP sign-in as
anomalous.

### 3. Impossible-travel correlation

**Purpose.** Two valid sign-ins from geographically distant locations
within a window narrower than commercial-flight ground-speed is physical
impossibility, which means at least one of the sign-ins is not the
claimed user. Velocity is the discriminator; threshold is 800 km/h
(commercial cruise speed cap on the ground; subsonic civil aviation max
~900 km/h).

**Action.** The detector is a deterministic, stdlib-only script at
`agent/scripts/m365/impossible_travel.py`. It reads Microsoft Graph
`signIn` JSON — a bare array, a Graph `{"value": [...]}` list-response
wrapper, or JSON Lines — from a file argument or stdin, groups events by
user, sorts each user's events by `createdDateTime`, and walks consecutive
geo-located pairs computing the haversine great-circle distance over the
time delta. It uses the real Graph v1.0 `signIn` field paths:

- **user** — `userPrincipalName` (always lowercase; falls back to `userId`)
- **time** — `createdDateTime` (ISO-8601, UTC, e.g. `2023-12-01T16:03:35Z`)
- **ip** — `ipAddress`
- **geo** — `location.geoCoordinates.latitude` / `.longitude`
- **place** — `location.city` / `location.countryOrRegion` (2-letter code)

It skips events with missing/null `geoCoordinates` (cannot place them — the
surrounding geo-located events still pair), guards zero/negative time deltas
(no division by zero), sorts away out-of-order timestamps, and flags any
pair whose required velocity exceeds `--threshold-kmh` (default **800**
km/h — the commercial-flight band; subsonic civil aviation tops out near
~900 km/h). Chain to `ioc-enrichment` for the ASN / MaxMind GeoIP overlay
(the Common-FP below) so a VPN-exit or CDN-PoP pair is not miscalled as
adversarial travel — the script reads the Entra-provided `geoCoordinates`
directly; ASN disambiguation is the enrichment layer on top.

Concatenate the four per-stream sign-in artifacts from step 2 into one
event set (`$DIR/signin_merged_<slug>_<window>.json` — a JSON array or the
Graph `value`-wrapped shape; both are accepted), then run the offline
correlation. The audit-pipeline wrapper standardizes it under host-exec and
yields the command-run-id the closing sequence registers against (the
wrapper is optional for offline parse over already-registered artifacts per
`agent/shared-constraints-blue.md` §6, but use it for chain of custody):

```bash
vigil assess host-exec --tool python3 --technique T1078.004 \
  --phase investigate --scope-host <tenant-slug> --target-host <upn> \
  --cwd "$ENGAGEMENT_DIR/../.." \
  --intent "impossible-travel velocity correlation for <upn>" \
  -- python3 scripts/m365/impossible_travel.py \
     "$DIR/signin_merged_<slug>_<window>.json" --json \
  > "$ENGAGEMENT_DIR/ir/evidence/impossible_travel_<slug>.jsonl"
```

`--json` emits one JSON object per flagged pair (JSON Lines) — it redirects
straight into the `.jsonl` evidence file; drop `--json` for a human-readable
table, and pass `--threshold-kmh <n>` to override the 800 km/h ceiling.
Register the JSONL with `--kind ir_evidence`. Each flagged pair carries:

```python
# core loop — the full script groups by user, sorts by time, skips missing geo
for prev, cur in zip(events, events[1:]):  # events: one user, time-sorted
    p = prev["location"]["geoCoordinates"]; c = cur["location"]["geoCoordinates"]
    d_km = haversine_km(p["latitude"], p["longitude"], c["latitude"], c["longitude"])
    dt_h = (parse_iso(cur["createdDateTime"]) - parse_iso(prev["createdDateTime"])).total_seconds() / 3600
    if dt_h > 0 and (v := d_km / dt_h) > 800:
        emit({"user": user, "from": prev["createdDateTime"], "to": cur["createdDateTime"],
              "from_ip": prev["ipAddress"], "to_ip": cur["ipAddress"],
              "from_city": p_city, "to_city": c_city,
              "from_country": p_country, "to_country": c_country,
              "km": round(d_km, 1), "hours": round(dt_h, 3), "kmh": round(v, 0)})
```

**Evidence.** `impossible_travel_<slug>.jsonl` with paired sign-in
timestamps + IPs + city/country geo + computed velocity (km, hours, km/h);
the ASN overlay comes from the `ioc-enrichment` chain. The verifier reads
this file directly during Check 1 (reachability).

**Common-FP.** A user on a commercial flight with onboard Wi-Fi
(satellite-routed; geolocates to the ground station, often a different
continent than the plane). A split-tunnel corporate VPN whose exit node
geolocates elsewhere than the user. A Cloudflare-routed / CDN-served
service whose IP geolocates to a Cloudflare PoP rather than the user's
device. Always rule out the VPN-exit / CDN-PoP hypothesis before
asserting impossible-travel as adversarial; check the ASN — corporate
VPN exits are typically AS owned by the customer's network provider,
CDN PoPs are AS13335 (Cloudflare), AS16509 (Amazon), AS15169 (Google).

### 4. OAuth grant + app-consent audit

**Purpose.** A new OAuth grant with `Mail.ReadWrite.All`,
`Files.ReadWrite.All`, or `MailboxSettings.ReadWrite` scopes issued
during the incident window is T1098.001 "Additional Cloud Credentials"
— persistence that survives password reset, MFA re-enrollment, and
session revocation. The grant ID is the persistence handle; revoking
the grant is the only way to evict.

**Action.** Two `pwsh` host-exec calls
(`--technique T1098.001 --phase investigate --scope-host <tenant>
--target-host <upn>`):

1. **Current grant state:**
   ```powershell
   $u = Get-MgUser -UserId '<upn>'
   Get-MgOauth2PermissionGrant -All -Filter "principalId eq '$($u.Id)'"
   Get-MgUserAppRoleAssignment -UserId $u.Id -All
   ```
   → `$DIR/oauth_grants_<slug>.json`.

2. **Grant-creation events in window** (directory audit):
   ```powershell
   Get-MgAuditLogDirectoryAudit -All -Filter "activityDateTime ge $WINDOW_START
     and activityDateTime le $WINDOW_END
     and (activityDisplayName eq 'Add app role assignment to service principal'
       or activityDisplayName eq 'Consent to application'
       or activityDisplayName eq 'Add OAuth2PermissionGrant')"
   ```
   → `$DIR/directory_audit_consent_<window>.json`.

Diff the current-state grants against the tenant ref's
`oauth_app_approved`. Any grant whose `clientId` is off-baseline, or
whose `scope` field carries a scope not approved for that app, is a
finding candidate.

**Evidence.** `oauth_grants_<slug>.json` (current state),
`directory_audit_consent_<window>.json` (the creation events),
`oauth_diff_<slug>.md` (the markdown derived diff with one line per
new grant: clientId, displayName, scopes, principalId, consent type,
consenting actor).

**Common-FP.** An IT-approved app rolled out same-week as the incident.
This is only acceptable as a false-positive citation if the app
appears in the tenant ref's `oauth_app_approved` list with a matching
rollout-ticket reference. A new grant whose ticket-citation does not
match the rollout window stays a finding.

### 5. Mailbox forensics

**Purpose.** Three independent persistence surfaces live on a mailbox;
attackers reach for them in the order below because each survives a
different remediation step. Skipping any one of them produces a
remediation that "looks complete" but leaves the persistence in place.

**Action.** Three host-exec calls (each `--tool pwsh --phase investigate
--scope-host <tenant> --target-host <upn>`; each first runs
`Connect-ExchangeOnline -AppId <app-id> -CertificateThumbprint <thumb>
-Organization <tenant>.onmicrosoft.com`). Run all three; do not stop at
the first hit.

**5a. Inbox rules** (T1564.008 / T1114.003) → `inbox_rules_<slug>.json`:
```powershell
Get-InboxRule -Mailbox '<upn>' |
  Select Name,Enabled,Priority,Description,From,SubjectContainsWords,
         BodyContainsWords,MoveToFolder,DeleteMessage,MarkAsRead,
         ForwardTo,ForwardAsAttachmentTo,RedirectTo,StopProcessingRules
```
Adversarial patterns: rules moving messages matching `phish*|security|
microsoft|IT|helpdesk|wire|invoice|payment|payroll|bank` to RSS Feeds /
Junk Email / Conversation History / Deleted Items; `DeleteMessage=$true`;
external `ForwardTo` / `RedirectTo`; cryptic single-character names
(`.`, `..`, ` `, `~`).

**5b. Mailbox forwarding + delivery settings** (T1114.003) →
`mailbox_settings_<slug>.json`:
```powershell
Get-Mailbox -Identity '<upn>' |
  Select UserPrincipalName,ForwardingSmtpAddress,ForwardingAddress,
         DeliverToMailboxAndForward,GrantSendOnBehalfTo,WhenChangedUTC
Get-MailboxAutoReplyConfiguration -Identity '<upn>'
```
Adversarial pattern: `ForwardingSmtpAddress` to an external domain with
`DeliverToMailboxAndForward=$false` (silent exfiltration — the user
never sees the forwarded mail).

**5c. Delegated mailbox / folder permissions** (T1098.002) →
`mailbox_permissions_<slug>.json`:
```powershell
Get-MailboxFolderPermission '<upn>'
Get-MailboxFolderPermission '<upn>:\Inbox'
Get-MailboxPermission -Identity '<upn>' |
  Where-Object { $_.User -notlike 'NT AUTHORITY\SELF' }
```
Adversarial pattern: `FullAccess` / `SendAs` / `Reviewer`+ granted to an
account not in the tenant ref's `inbox_delegate_pattern`, within the
incident window.

**Evidence.** `inbox_rules_<slug>.json`, `mailbox_settings_<slug>.json`,
`mailbox_permissions_<slug>.json`. Plus a derived
`mailbox_forensics_<slug>.md` that calls out the adversarial pattern
hits and cites the source files + line numbers.

**Common-FP.** A user's own forwarding to a personal Gmail / iCloud /
Outlook.com address for convenience. This is a policy violation, not an
adversarial action — document it, but the disposition for IR purposes
stays `false_positive` (the IR scope is "did an attacker do this", not
"did the user violate AUP"). The AUP-violation discovery routes to HR /
compliance separately via the report-writer's policy-violation
annotation.

### 6. Conditional Access state

**Purpose.** Confirm whether the controls that should have prevented the
adversarial sign-in actually fired, or whether the policy was in
`report-only` / `disabled` and silently failed. The verifier's Check 3
(config gating) reads this evidence directly.

**Action.** Pull the catalog
(`--tool pwsh --technique CONFIG-AUDIT --phase investigate
--scope-host <tenant>`):
```powershell
Get-MgIdentityConditionalAccessPolicy -All |
  Select DisplayName,State,Id,CreatedDateTime,ModifiedDateTime,
         Conditions,GrantControls,SessionControls
```
→ `$DIR/ca_policies.json`. Then extract the alerting sign-in's verdict:
```bash
jq '.value[] | select(.id == "<sign-in-id>") | .appliedConditionalAccessPolicies' \
   "$DIR/signin_interactiveUser_${SLUG}_*.json" \
   > "$ENGAGEMENT_DIR/ir/evidence/ca_applied_${SLUG}_${SIGNIN_ID}.json"
```

For each policy in the applied list, the `result` field tells the story:

- `success` — policy fired and the user satisfied the grant (MFA, compliant
  device, etc.).
- `failure` — policy fired and the user failed; access was blocked.
- `notApplied` — policy did not apply (the user / app / location / risk
  did not match the policy's conditions).
- `notEnabled` — the policy is in `disabled` state.
- `unknown` / `unknownFutureValue` — telemetry incomplete; investigate the
  policy's `state` directly.

`reportOnlyXxx` variants (`reportOnlySuccess`, `reportOnlyFailure`, etc.)
mean the policy was in `enabledForReportingButNotEnforced` state — the
verdict was computed but **not enforced**. The sign-in succeeded
regardless of the verdict. This is by design when staging a new policy,
but an attacker sign-in that "would have been blocked" in report-only is
the policy-gap finding.

**Evidence.** `ca_policies.json` (tenant-wide policy catalog),
`ca_applied_<slug>_<signin-id>.json` (the applied-policy verdict on the
specific sign-in), one-line evidence statement per policy: "Policy
`<displayName>` (id `<id>`) state=`<state>` verdict=`<result>` on
sign-in <id>".

**Common-FP.** A CA policy is in `report-only` mode by design — it is
being staged and the tenant ref's `ca_policy_expected_fail` register
documents the staging. The verifier reads this register during Check 3;
do not raise a finding on the report-only verdict alone if the policy is
in the documented-staging list.

### 7. UAL hunt window

**Purpose.** The Unified Audit Log is the cross-workload feed (Exchange,
SharePoint, OneDrive, Teams, Azure AD admin, Defender). Sign-in logs and
directory audit do not capture file downloads from sensitive sites, PIM
role activations, or `Set-Mailbox` / `Add-MailboxPermission` admin
mutations — UAL does. A timeline without the UAL pull is missing the
lateral-movement and persistence-enumeration evidence.

**Action.** One host-exec call (`--tool pwsh --technique AUDIT-PULL
--phase investigate --scope-host <tenant> --target-host <upn>`) over a
paginated session — `Search-UnifiedAuditLog` caps at 5000 results per
call and silently truncates without `SessionId` + `SessionCommand
ReturnLargeSet`:

```powershell
$session = [guid]::NewGuid().ToString(); $all = @()
do {
  $b = Search-UnifiedAuditLog -StartDate '<WINDOW_START>' -EndDate '<WINDOW_END>' `
                              -UserIds '<upn>','<alias1>','<alias2>' `
                              -ResultSize 5000 -SessionId $session -SessionCommand ReturnLargeSet
  if ($b) { $all += $b }
} while ($b -and $b.Count -eq 5000)
$all | ConvertTo-Json -Depth 10
```
→ `$DIR/ual_<slug>_<window>.json`. UAL's filterable dimensions are
`RecordType` and `Operations`. Adversarial operations to grep:

| Operation | Why it matters |
|---|---|
| `New-InboxRule`, `Set-InboxRule`, `Enable-InboxRule` | Inbox-rule persistence (T1564.008 / T1114.003) — even if the rule was later deleted, UAL retains the create. |
| `Add-MailboxPermission`, `Set-MailboxFolderPermission`, `Add-RecipientPermission` | Delegated access grants (T1098.002). |
| `Set-Mailbox` with `ForwardingSmtpAddress` | External auto-forward toggle (T1114.003). |
| `Add-MgOauth2PermissionGrant`, `Consent to application` | OAuth persistence (T1098.001) — UAL captures consent events the directory audit also captures, but UAL aggregates them with the user's other activity for timeline construction. |
| `Add member to role`, `Add member to role completed (PIM activation)` | Admin-role activation. |
| `FileDownloaded`, `FileSyncDownloadedFull`, `FileAccessed` (SharePoint / OneDrive) | Data staging / exfiltration. |
| `MailItemsAccessed` (mailbox audit) | Read-access to mailbox items by the actor or a delegate. |
| `Send` (mail-send) | Outbound mail the actor sent — invoice fraud, vendor pivot. |
| `Update user`, `Reset user password` | Account-takeover follow-on. |

**Evidence.** `ual_<slug>_<window>.json` (raw),
`ual_findings_<slug>.md` (derived markdown with the adversarial-
operation hits, each one citing the UAL record's `Id`, `CreationDate`,
`UserId`, `Operation`, `ClientIP`, and `AuditData` summary).

**Common-FP.** Helpdesk-initiated `Add-MailboxPermission` /
`Set-Mailbox` mutations tied to a ticket ID; PIM role activations by
the user's own documented PIM-eligible role assignment. The
tenant ref's `helpdesk_action_register` and `pim_eligible_assignments`
sections are the citation sources.

## MITRE Technique Mapping

| Technique | When to assign | Source evidence |
|---|---|---|
| [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) | Sign-in succeeded with valid credentials from a new ASN / country outside the user's 30-day baseline | Step 1 baseline + Step 2 four-stream sign-in pull |
| [T1098.001 Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/) | New OAuth grant or app-role assignment created within incident window with scopes not on the approved list | Step 4 OAuth audit + directory audit consent events |
| [T1098.005 Device Registration](https://attack.mitre.org/techniques/T1098/005/) | A new device registered against the actor during the incident window with `deviceTrustType` in the sign-in record matching the registration | Step 2 sign-in `deviceDetail` + directory audit `Add device` |
| [T1114.001 Local Email Collection](https://attack.mitre.org/techniques/T1114/001/) | Actor accessed mailbox items via Graph / EWS / IMAP with read access to message bodies | Step 7 UAL `MailItemsAccessed` |
| [T1114.002 Remote Email Collection](https://attack.mitre.org/techniques/T1114/002/) | Delegate read permission granted within window + delegate-account UAL `MailItemsAccessed` | Step 5c delegated permission + Step 7 UAL |
| [T1114.003 Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/) | Inbox rule with `ForwardTo` / `RedirectTo` external OR mailbox-level `ForwardingSmtpAddress` populated to external | Step 5a inbox rules + Step 5b mailbox forwarding |
| [T1564.008 Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008/) | Inbox rule moving security-keyword messages to RSS Feeds / Junk / Deleted / Conversation History | Step 5a inbox rules |
| [T1556.006 MFA Authentication Process](https://attack.mitre.org/techniques/T1556/006/) | Non-interactive sign-in from new ASN with no preceding interactive sign-in from that ASN (refresh-token / session-cookie replay) | Step 2 four-stream merge + step 3 velocity calc |
| [T1621 MFA Request Generation](https://attack.mitre.org/techniques/T1621/) | High-volume MFA challenges in `signInDetails.authenticationDetails` over a short window (push-fatigue / MFA bombing); cross-skill to `okta-investigation` if Okta is the IdP rather than Entra direct | Step 2 sign-in `authenticationDetails` |

`details.mitre_techniques` carries the array of assigned technique
IDs on the finding. Severity follows `agent/rules/triage.md` rule 2 —
the MITRE technique determines the impact ceiling, not the SIEM rule's
authored severity hint.

## Known-benign register additions (`_template-m365.md`)

The tenant ref's "Known benign patterns" section is the verifier's Check
5 citation source. When a benign pattern surfaces that is not yet on the
register, flag it in the handoff as a `tenant_ref_update` candidate.

| Register key | Purpose | Schema fields |
|---|---|---|
| `ca_policy_expected_fail` | CA policies in `report-only` by design | `policy_id, policy_displayName, state, since_date, ticket_ref` |
| `traveling_user_pattern` | Known frequent travelers | `upn, allowed_countries[], allowed_asns[], confirmation_source` |
| `service_principal_baseline` | First-party + approved third-party app sign-ins | `appId, displayName, expected_signin_rate, expected_source_subnets[]` |
| `oauth_app_approved` | Sanctioned apps with grant scopes | `clientId, displayName, approved_scopes[], rollout_ticket, approving_admin_upn` |
| `inbox_rule_user_owned` | User-created filing rules | `upn, rule_name, rule_description, user_confirmation_date` |
| `helpdesk_action_register` | Ticketed mailbox / user mutations | `actor_upn, ticket_id, action, target_upn, date` |
| `pim_eligible_assignments` | PIM-eligible role assignments | `upn, role, scope, assigned_date` |
| `inbox_delegate_pattern` | Documented mailbox delegates | `mailbox_upn, delegate_upns[], permission_level, justification` |

The tenant ref's "Setup" section additionally documents: Graph
app-registration client ID, certificate thumbprint or workload identity,
Exchange role group membership, tenant ID, Defender XDR API tenant URL,
and the Super Admin break-glass account.

## Disposition heuristics

L2 proposes; L3 `alert-fp-verification` decides. Propose alongside
confidence so the verifier has a starting position.

- **`confirmed` (high)** — adversarial OAuth grant + post-grant token use
  against Mail / Files, **OR** impossible-travel > 800 km/h + new
  inbox rule matching adversarial keywords, **OR** token-replay
  (non-interactive sign-in from new ASN with no preceding interactive
  from that ASN) + a downstream UAL action (`MailItemsAccessed` /
  `Send` / `FileDownloaded`). Two independent signals; reproduction
  available.
- **`confirmed` (medium)** — one strong adversarial primitive (new
  high-risk OAuth grant, new external auto-forward, adversarial inbox
  rule) without yet-reproduced post-grant action.
- **`false_positive`** — sign-in matches tenant ref's
  `traveling_user_pattern` + zero rule / grant / forwarding artifacts
  + ASN allowlist hit. Citation must name the tenant-ref section and
  the matched fields.
- **`downgraded`** — credential-replay attempt **blocked** by CA
  policy verdict `failure`; primitive confirmed but proved impact
  narrows to "failed authentication attempt."
- **`disputed`** — single anomalous signal (e.g., one risky sign-in
  flagged by Identity Protection) without corroborating action, rule,
  grant, or forwarding artifact.

Confidence rationale is one sentence — "IP outside 30-day ASN baseline +
velocity 1247 km/h + new inbox rule moving `microsoft|security` to RSS
Feeds" qualifies; "looks suspicious" does not.

## Activity Log Convention

Every step outcome and every pull lands as an `vigil assess log` entry.
CLI signature (verified at `src/vigil_cli/blue.py:383`):

```
vigil assess log <agent> <title> <action> <result> --actor-kind agent
```

Per-step titles: `m365-step-<N>-<short-name>` —
`identity-hydrate`, `four-stream-pull`, `impossible-travel`,
`oauth-audit`, `mailbox-forensics`, `ca-state`, `ual-hunt`. Action is one
of `pull | correlate | register | handoff | block`. Result is a single
line summarizing the outcome.

Standard `metadata_json` shape:

```json
{
  "tier": "L2",
  "alert_external_id": "<source-system-id>",
  "platform": "m365",
  "skill_loaded": "m365-signin-investigation",
  "disposition": "confirmed|false_positive|downgraded|disputed|pending_runtime_proof",
  "confidence": "high|medium|low",
  "confidence_rationale": "<one-line>",
  "mitre_techniques": ["T1078.004", "T1098.001"],
  "actor_upn": "<upn>",
  "actor_object_id": "<guid>",
  "actor_aliases": ["<alias>", "..."],
  "time_window_utc": ["<iso-start>", "<iso-end>"],
  "ca_policies_evaluated": ["..."],
  "ca_policies_report_only_only": ["..."],
  "oauth_grants_new": [{"clientId": "...", "scopes": ["..."], "consent_time": "..."}],
  "inbox_rules_new": [{"name": "...", "forwardTo": "...", "moveToFolder": "..."}],
  "external_forwarding": {"set": true, "address": "...", "deliver_to_mailbox": false},
  "impossible_travel_velocity_kmh": 1247,
  "impossible_travel_pair": ["<signin-id-a>", "<signin-id-b>"],
  "ual_adversarial_ops": ["MailItemsAccessed", "New-InboxRule"],
  "evidence_refs": ["<artifact-id>", "..."]
}
```

## Output Contract

Handoff JSON back to the dispatcher. Artifact IDs only (paths are not
citable across dispatches).

```json
{
  "skill": "m365-signin-investigation",
  "finding_slug": "<slug>",
  "tier": "L2",
  "platform": "m365",
  "actor": {"upn": "user@<tenant>.onmicrosoft.com", "objectId": "<guid>", "aliases": ["..."]},
  "time_window_utc": ["<iso-start>", "<iso-end>"],
  "proposed_disposition": "confirmed",
  "confidence": "high",
  "confidence_rationale": "...",
  "mitre_techniques": ["T1078.004", "T1098.001", "T1564.008"],
  "evidence_refs": ["<artifact-id-1>", "<artifact-id-2>", "..."],
  "timeline": [
    {"t": "<iso>", "event": "<short description>", "evidence_ref": "<artifact-id>"}
  ],
  "coverage_gaps": ["<gap with proposed follow-up>"],
  "containment_proposed": [
    {"action": "revoke|disable|reset|remove", "target": "<specific principal/grant/rule>", "rollback": "<reverse action>"}
  ],
  "next_specialist": "verifier"
}
```

`containment_proposed` is **proposed** — L4 `incident-containment` runs
the WRITE actions; this skill does not.

## Closing Sequence

Sequential. Do not declare the dispatch complete until all five land.

1. **Register every raw pull as `ir_log`.** Sign-in JSON per stream,
   directory audit JSON, OAuth grants JSON, mailbox settings JSON,
   inbox rules JSON, mailbox permissions JSON, UAL JSON, CA policies
   JSON. Mailbox-content pulls (`Search-UnifiedAuditLog` returning subject
   lines, `MailItemsAccessed` detail) remain fully indexed with hash + linkage:

   ```bash
   vigil assess artifact register "$DIR/<file>.json" \
     --kind ir_log --finding <finding-slug> \
     --agent-id <agent-id> --command-run-id <run-id>
   ```

2. **Register derived evidence as `ir_evidence`.** Impossible-travel
   JSONL, OAuth diff markdown, mailbox-forensics markdown, UAL findings
   markdown, CA applied verdict JSON.

3. **Mark scratch on transient working notes** (failed-pagination
   retries, exploratory jq, replaced draft markdown):

   ```bash
   vigil assess artifact mark-scratch --under notes/scratch/
   ```

4. **Log the handoff entry.**

   ```bash
   vigil assess log <agent-name> "m365-signin-handoff" handoff \
     "<one-line summary: streams pulled, velocity, new grants, new rules, proposed disposition + mitre>" \
     --actor-kind agent
   ```

5. **Emit the handoff JSON** to
   `$ENGAGEMENT_DIR/handoffs/<dispatch-id>.json` and exit with
   `vigil assess agent handoff --from-json <path>`.

If any step blocks (missing scope, missing tenant ref, missing Exchange
role group, missing certificate), emit a `blocked` handoff naming the
exact missing component. Do not improvise scope grants or admin-action
substitutions.

## Common Failure Modes

Format: observation → why it is wrong → correct approach.

**M1. Pulling only interactive sign-ins.** Attackers prefer non-
interactive (refresh-token replay) because MFA does not gate it. A
finding built off the interactive stream alone misses 70-90% of
post-compromise activity. **Correct:** all four streams, every time
(Step 2 is non-negotiable).

**M2. Trusting `signInActivity.lastSignInDateTime` as ground truth.**
Entra's cached summary lags real-time and excludes some streams.
**Correct:** `Get-MgAuditLogSignIn` filtered on actor + window.

**M3. UAL `-UserIds` filter too narrow.** Activity recorded under alias
UPNs is missed when filtering only the primary UPN. **Correct:** step 1
resolves all aliases; step 7's filter passes the full list.

**M4. Skipping the OAuth-grant diff.** A new grant looks alarming
in isolation; many are same-week rollouts. **Correct:** diff against
`oauth_app_approved` before raising. The handoff's `oauth_grants_new`
carries only off-baseline grants.

**M5. Confusing `report-only` CA policy with `enabled`.** Report-only
computes a verdict but does not enforce. A `reportOnlyFailure` on the
sign-in record means the user got through regardless. **Correct:** read
the policy's `state` directly; only `enabled` enforces.

**M6. Treating Defender Advanced Hunting as a Graph replacement.**
`AADSignInEventsBeta` is a Defender-side denormalization with 30-day
retention and a schema marked Beta. **Correct:** use it for correlation
hunts; the canonical sign-in source for the timeline is Graph
`Get-MgAuditLogSignIn`.

**M7. UAL without `SessionId` + `ReturnLargeSet`.** A single call caps
at 5000 results and silently truncates. **Correct:** the paginated loop
in step 7 is mandatory for any active window.

**M8. Impossible-travel calc on the interactive stream only.** The
adversarial signal is a **non-interactive** sign-in from country B
shortly after an **interactive** sign-in from country A. **Correct:**
step 3 merges all four streams; the pair-flag is the cross-stream pair.

**M9. Mailbox forensics that stop at `Get-InboxRule`.** Inbox rules,
mailbox-level forwarding, and folder/mailbox permissions are three
independent persistence surfaces. **Correct:** all three sub-checks of
step 5, every time.

**M10. Impossible-travel without ASN check.** Two Cloudflare or
corporate-VPN exits in different countries are CDN / network policy,
not adversarial travel. **Correct:** velocity is necessary but not
sufficient; ASN disambiguates.

**M11. Skipping the tenant ref because "it's standard."** Standard
tenants have report-only-staged CA policies, traveling execs,
sanctioned third-party Mail-reader apps, and helpdesk-initiated rule
patterns. **Correct:** rule 12 of `agent/rules/triage.md` — tenant ref
first, always.

**M12. Wrong `--target-host` on host-exec.** `--target-host` is the
**investigation target**, not the IR principal. Conflating them
produces audit rows that look like the IR principal is the suspect.
**Correct:** `--target-host <upn>` is the actor under investigation.

## Reference Block

**Sibling skills:**

- `agent/skills/alert-triage/SKILL.md` — L1 dispatcher (routes
  `platform=m365` here).
- `agent/skills/phishing-triage/SKILL.md` — origin-email skill; hands
  off credential-entry timestamp + lure URL.
- `agent/skills/ioc-enrichment/SKILL.md` — IP / ASN / user-agent
  enrichment (steps 1 and 3).
- `agent/skills/alert-fp-verification/SKILL.md` — L3 verifier
  (destination of this skill's handoff).
- `agent/skills/incident-containment/SKILL.md` — L4 containment owner;
  runs `Revoke-MgUserSignInSession`, `Remove-MgOauth2PermissionGrant`,
  `Disable-MgUser`, `Remove-InboxRule`, `Set-Mailbox
  -ForwardingSmtpAddress $null` only after L3 verification + operator
  approval.

**Cross-cloud / cross-IdP pivots:**

- `agent/skills/okta-investigation/SKILL.md` — SAML from Okta as
  the credential origin into M365.
- `agent/skills/aws-cloudtrail-investigation/SKILL.md` — federated
  SAML from Entra ID into AWS STS.

**Always-active rules:** `agent/rules/triage.md`,
`agent/shared-constraints-blue.md`, `agent/rules/ir-evidence.md`,
`agent/rules/adversarial-mindset.md`, `agent/operator-core-blue.md`.

**Tenant ref:** `agent/references/tenants/<customer>-m365.md`
(template `_template-m365.md`).

**External documentation:**

- MITRE ATT&CK T1078.004 / T1098.001 / T1098.005 / T1114.001-003 /
  T1556.006 / T1564.008 / T1621 — https://attack.mitre.org/techniques/
- Entra sign-in concept ("four streams"):
  https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
- Microsoft Graph PowerShell SDK:
  https://learn.microsoft.com/en-us/powershell/microsoftgraph/
- Exchange Online PowerShell (`Search-UnifiedAuditLog`, `Get-InboxRule`,
  `Get-Mailbox`, `Get-MailboxFolderPermission`):
  https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell
- Defender XDR Advanced Hunting tables:
  https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
- Conditional Access policy states:
  https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies
