# <CUSTOMER> — Microsoft 365 / Entra ID Tenant Reference

> **USE THIS AS A SCAFFOLD — DO NOT DISPATCH AGAINST IT AS-IS.**
>
> Produced by `aith blue tenant init --customer <slug> --platform m365`,
> which writes to `agent/references/tenants/<slug>-m365.md` (per
> `PLATFORM_TO_TENANT_SUFFIX["m365"] = "m365"` in
> `src/ai_threat_hunting_cli/blue.py`).
>
> Before this file is loaded into a real engagement:
>
> 1. Replace every `<PLACEHOLDER>` (search for `<`). Remaining placeholders
>    cause the L1 `alert-triage-specialist` to halt with a `blocked`
>    handoff.
> 2. Populate the "Known benign patterns" register. Empty/placeholder rows
>    mean L1 cannot auto-close anything — every alert escalates to L2.
>    Promote rows from L3-verified `false_positive` findings only
>    (`agent/rules/triage.md` rule 5).
> 3. The tenant ref is operator-curated and authoritative. If the tenant
>    deviates, update the ref first, then re-dispatch.
>
> Platform-neutral sections (identity, on-call, change log, OOS artifacts)
> are mirrored across the `_template-<p>.md` family. Keep structure stable
> so cross-platform diffs stay readable.

Operator context for Microsoft 365 / Entra ID alert investigations on the
`<tenant-primary-domain>` tenant. Load this before running any Graph,
Exchange Online, or Defender command so you do not spend time
rediscovering config.

---

## Tenant Identity

| Field | Value |
|---|---|
| Primary domain | `<tenant-primary-domain>` |
| Tenant default `.onmicrosoft.com` | `<tenant>.onmicrosoft.com` |
| Verified domains | `<verified-domain-1>`, `<verified-domain-2>` (or `none`) |
| `tenantId` (GUID) | `<00000000-0000-0000-0000-000000000000>` |
| Organization name | `<CUSTOMER>` |
| Tenant created | `<YYYY-MM-DD>` |
| Total members (non-guest) | `<count>` (as of `<YYYY-MM-DD>`) |
| Total guest accounts (`#EXT#`) | `<count>` |
| Admin secondary email | `<admin-recovery-email>` |
| Org phone | `<+E.164-org-phone>` |

---

## Tool Configuration

### Azure CLI

```
Binary:    <path-to-az-binary>
Profile:   ~/.azure/
Signed-in: <admin-upn@tenant>  (tenant: <tenantId>)
```

`az account show --output json` to confirm tenant and subscription
context before any command. Investigator subscription scope (read-only):
`<subscription-id>` (`<subscription-name>`).

### Microsoft Graph PowerShell SDK

```
Module:    Microsoft.Graph (>= 2.x)
Connect:   Connect-MgGraph -TenantId <tenantId> -Scopes <scope-list>
Auth:      <interactive | client-credential app registration>
```

App registration used for unattended Graph pulls:

```
App display name: <ir-graph-app-name>
Application (client) ID: <00000000-0000-0000-0000-000000000000>
Object ID (servicePrincipal): <00000000-0000-0000-0000-000000000000>
Cert thumbprint / secret ref: <cert-thumbprint OR vault-secret-location>
```

### Exchange Online Management

```
Module:    ExchangeOnlineManagement
Connect:   Connect-ExchangeOnline -UserPrincipalName <admin-upn@tenant>
```

### CLI for Microsoft 365 (PnP)

```
Binary:   <path-to-m365-cli>
Profile:  m365 status   # confirms signed-in identity + tenant
```

### Defender XDR Advanced Hunting (REST)

```
Endpoint: https://api.security.microsoft.com/api/advancedhunting/run
Auth:     OAuth2 bearer (app registration above; scope `ThreatHunting.Read.All`)
```

---

## App Registration Scope Reality

The investigator app registration `<ir-graph-app-name>` is consented for
the following **application** scopes (admin consent required). **The
operator must verify each row against Entra → App registrations →
API permissions after `tenant init`.** Drift here is the most common
cause of Graph 403s during incidents.

| Scope | Status | Notes |
|---|---|---|
| `AuditLog.Read.All` | `<verified ✅ / not granted ❌>` | Sign-in logs, audit logs via Graph `/auditLogs/*` |
| `Directory.Read.All` | `<verified ✅ / not granted ❌>` | User, group, role, service principal lookups |
| `SecurityEvents.Read.All` | `<verified ✅ / not granted ❌>` | Defender for Cloud Apps / legacy Security API alerts |
| `ThreatHunting.Read.All` | `<verified ✅ / not granted ❌>` | Defender XDR Advanced Hunting (KQL) |
| `Mail.ReadBasic.All` | `<verified ✅ / not granted ❌>` | Mailbox header / metadata reads (no body) |
| `MailboxSettings.Read` | `<verified ✅ / not granted ❌>` | Inbox rules, forwarding, OOO settings |
| `Policy.Read.All` | `<verified ✅ / not granted ❌>` | Conditional Access policy enumeration |
| `IdentityRiskyUser.Read.All` | `<verified ✅ / not granted ❌>` | Entra ID Protection risk reads |

Write scopes (`Mail.ReadWrite`, `Directory.ReadWrite.All`, etc.) are
intentionally **not** in the IR app — IR here is read-only by design.
For ambiguous 403s, decode the bearer token at <https://jwt.ms> and
inspect the `roles` claim; missing `roles` for the expected scope means
admin consent did not propagate.

---

## Critical Identities

### Global Administrators (Entra role: Global Administrator)

| UPN | objectId | Name | Notes |
|---|---|---|---|
| `<ga-1@tenant>` | `<00000000-…>` | `<Full Name>` | `<role / tenure / MFA enforced / hardware FIDO2>` |
| `<ga-2@tenant>` | `<00000000-…>` | `<Full Name>` | `<role / tenure / MFA enforced / hardware FIDO2>` |

### Privileged Identity Management (PIM) eligible roles

| Role | Eligible principals | Activation requires MFA? | Max activation window |
|---|---|---|---|
| Global Administrator | `<list-of-eligible-upns>` | `<yes/no>` | `<hours>` |
| Privileged Authentication Administrator | `<list>` | `<yes/no>` | `<hours>` |
| Conditional Access Administrator | `<list>` | `<yes/no>` | `<hours>` |
| Application Administrator | `<list>` | `<yes/no>` | `<hours>` |
| Cloud Application Administrator | `<list>` | `<yes/no>` | `<hours>` |

### Break-glass accounts

| UPN | Storage location of credentials | Last rotation | Excluded from CA |
|---|---|---|---|
| `<breakglass-1@tenant.onmicrosoft.com>` | `<password manager / safe / vault reference>` | `<YYYY-MM-DD>` | `<yes — list policies excluding it>` |
| `<breakglass-2@tenant.onmicrosoft.com>` | `<location>` | `<YYYY-MM-DD>` | `<yes>` |

Break-glass accounts are cloud-only (no on-prem AD sync), excluded from
all Conditional Access policies, and protected by hardware FIDO2 keys
stored offline. Sign-in from a break-glass account during an incident is
**a documented event the IR operator triggers**, not adversarial
activity. Cross-check against the change log before treating them as
findings.

### Service principals / enterprise apps with privileged Graph scopes

| App display name | Application ID | Owner team | Privileged scopes |
|---|---|---|---|
| `<sp-1>` | `<00000000-…>` | `<owner team>` | `<e.g. Mail.Read, Directory.Read.All>` |
| `<sp-2>` | `<00000000-…>` | `<owner team>` | `<scopes>` |

---

## Conditional Access posture (IR program defaults — verify before use)

These are the CA policies the IR program assumes exist. **Mark each row
verified once the operator has confirmed it in the Entra portal for this
tenant.**

- `<policy-1-name>` — Require MFA for all admins (assigned: `<role list>`)
- `<policy-2-name>` — Block legacy authentication (assigned: All users)
- `<policy-3-name>` — Require compliant device for privileged roles
- `<policy-4-name>` — Block sign-in from named risky locations
- `<policy-5-name>` — Require MFA for guest invitations

If a policy is required for an investigation but is not in place, log
the gap as a coverage deferral on the engagement rather than asking the
operator to create one mid-incident.

---

## Key Personnel

| UPN | objectId | Name | Role | Notes |
|---|---|---|---|---|
| `<personnel-upn-1>` | `<00000000-…>` | `<Full Name>` | `<role>` | `<MFA, last sign-in, group memberships>` |
| `<personnel-upn-2>` | `<00000000-…>` | `<Full Name>` | `<role>` | `<MFA, last sign-in, group memberships>` |

`<count>` total users. Pull the full list with:

```powershell
Get-MgUser -All -Property Id,UserPrincipalName,DisplayName,AccountEnabled,UserType,SignInActivity |
  Select-Object Id,UserPrincipalName,DisplayName,AccountEnabled,UserType,@{n='LastSignIn';e={$_.SignInActivity.LastSignInDateTime}}
```

---

## MFA Posture

| Field | Value |
|---|---|
| Per-user MFA enforced? | `<yes / no — superseded by CA>` |
| Security Defaults enabled? | `<yes / no>` |
| MFA required for all admins (CA)? | `<yes / no>` |
| Hardware FIDO2 required for break-glass? | `<yes / no>` |
| Authentication methods policy | `<list allowed methods: FIDO2, Authenticator, SMS, voice, TAP>` |
| Known exception list | `<UPNs or groups exempted from MFA, with rationale>` |
| Known posture gaps | `<list>` |

Posture gaps here are *known conditions, not findings unique to a
specific alert*. Document them in the IR report posture section but do
not let them drive an alert's disposition by themselves.

---

## Known benign patterns (false-positive register)

> **The L1 `alert-triage-specialist` reads this table to decide whether an
> alert may be auto-closed without an L2 pull.** Schema is fixed — do not
> rename columns; the consumers (`agent/skills/alert-triage/SKILL.md`
> Mechanical-FP screen and the `alert-triage-specialist` agent prompt)
> match on these exact field names.

Column schema:

| pattern_id | actor | action_verb | time_pattern | source_signal | mechanical | rationale |
|---|---|---|---|---|---|---|

Conventions follow `_template-gws.md`. Highlights:

- `pattern_id` — short kebab-case slug, unique within this file.
- `actor` — explicit UPN or service principal appId. Wildcards
  (`*@<tenant>`) are NOT mechanical-eligible.
- `action_verb` — Defender / sign-in / audit native event name (e.g.
  `UserLoggedIn`, `Add OAuth2PermissionGrant`, `New-InboxRule`).
- `time_pattern` — concrete schedule (e.g.
  `every Tuesday 02:00 UTC ± 5 minutes`).
- `source_signal` — Defender / Sentinel / Sign-in rule identity.
- `mechanical` — `true` when L1 may auto-close.
- `rationale` — one sentence + citation of the L3 finding that promoted
  the entry.

Example rows — **replace with real entries before use; remove or comment
out the examples once real entries exist**:

| pattern_id | actor | action_verb | time_pattern | source_signal | mechanical | rationale |
|---|---|---|---|---|---|---|
| `<ca-policy-expected-fail>` | `<service-account@tenant>` | `User sign-in failed - CA policy` | `business hours, weekdays only` | `defender-xdr / Sign-in failure / rule-id <rid>` | `true` | `Service account intentionally blocked by CA policy "Block service accounts from interactive sign-in"; promoted from finding <slug>` |
| `<traveling-user-pattern>` | `<sales-vp@tenant>` | `Atypical travel` | `monthly EMEA → US round-trip week 1 of month` | `entra-id-protection / Atypical travel / rule-id <rid>` | `false` | `Documented travel pattern; L2 must verify city pair each time, NEVER auto-close` |
| `<oauth-app-approved>` | `<expense-app-sp>` | `Consent to application` | `any (one-shot consent expected once per upgrade)` | `defender-xdr / Suspicious OAuth consent / rule-id <rid>` | `true` | `Approved OAuth integration; appId pinned in row; consent re-prompts on app version upgrade` |
| `<transport-rule-documented>` | `<exchange-admin@tenant>` | `New-TransportRule` | `change window 1st Sat of month 06:00-10:00 UTC` | `purview / Exchange admin audit / rule-id <rid>` | `true` | `Documented mail-flow change window; cross-check ticket ID in audit description` |
| `<inbox-rule-user-owned>` | `<wildcard — see note>` | `New-InboxRule` | `any` | `defender-xdr / Suspicious inbox rule / rule-id <rid>` | `false` | `Users create their own inbox rules; L2 verifies rule target + content keywords each time` |
| `<service-principal-baseline>` | `<svc-backup-sp>` | `Add service principal` | `any (one-shot at app onboarding)` | `defender-xdr / Service principal added / rule-id <rid>` | `false` | `Manual review — backup SP onboarding is rare; confirm change ticket exists before closing` |

**Promotion rule** — only an L3 verifier who has confirmed
`false_positive` with cited evidence may seed a new mechanical row. New
`mechanical: false` rows can be added by the IR lead with a one-paragraph
rationale. Record changes in the **Tenant change log reference** below
and reference this file in the commit message.

---

## Common IR pull commands for this tenant

> Placeholders only — replace before running. UTC timestamps; look-back is
> 30 days from earliest plausible trigger (`agent/rules/triage.md` rule 6).

```powershell
# Sign-in logs for a specific user (Graph)
Get-MgAuditLogSignIn -Filter "userPrincipalName eq '<upn>'" -All |
  Select-Object CreatedDateTime,UserPrincipalName,IpAddress,ClientAppUsed,AppDisplayName,Status,RiskLevelDuringSignIn,Location

# Unified audit log search (Exchange Online + Entra + SharePoint)
Search-UnifiedAuditLog -StartDate <utc> -EndDate <utc> -UserIds <upn> -ResultSize 5000 |
  Select-Object CreationDate,UserIds,Operations,ResultStatus,AuditData

# Mailbox inbox rules (look for forwarding / delete / move-to-junk)
Get-InboxRule -Mailbox <upn> | Select-Object Name,Enabled,Priority,ForwardTo,ForwardAsAttachmentTo,RedirectTo,DeleteMessage,MoveToFolder

# OAuth2 permission grants (delegated consents on user account)
Get-MgOauth2PermissionGrant -Filter "principalId eq '<userObjectId>'" |
  Select-Object Id,ClientId,ConsentType,Scope,ResourceId

# Forwarding settings on the mailbox itself
Get-Mailbox <upn> | Select-Object UserPrincipalName,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward

# Conditional Access policies in effect
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName,State,Conditions,GrantControls
```

```kql
// Defender XDR Advanced Hunting — sign-in events for a user (30 days)
IdentityLogonEvents
| where AccountUpn == "<upn>"
| where Timestamp > ago(30d)
| project Timestamp, ActionType, LogonType, IPAddress, DeviceName, Application, AccountUpn, ISP, Location
| order by Timestamp desc
```

---

## On-call calendar reference

| Field | Value |
|---|---|
| On-call rotation tool | `<PagerDuty / Opsgenie / Teams shifts / other>` |
| Lookup URL | `<URL to on-call schedule>` |
| Look-up SLA | `<seconds to identify on-call for a given UTC timestamp>` |

The L3 verifier's devil's-advocate step (`alert-fp-verification` Check 5)
requires identifying who was on-call during the alert's time window.

---

## Vendor maintenance windows reference

| Source | URL | Notes |
|---|---|---|
| Microsoft 365 Service Health | https://portal.office.com/servicestatus | Cross-check before treating an outage-coincident anomaly as adversarial |
| Azure Status | https://status.azure.com | AAD / Entra incidents look like sign-in anomalies |
| Tenant-specific maintenance bulletin | `<internal URL or change ticket project>` | Includes CA cutovers, OAuth re-consents, tenant rebrand windows |
| Identity provider status (if federated) | `<URL>` | ADFS / on-prem federation breaks present as sign-in failures |

---

## Tenant change log reference

| Source | URL | Notes |
|---|---|---|
| Tenant config change tickets | `<Jira project URL / change ticketing>` | Every role assignment, CA policy edit, app registration, OAuth consent should be tracked |
| Entra audit logs | `Get-MgAuditLogDirectoryAudit` | Source of truth for directory changes |
| Unified audit log | `Search-UnifiedAuditLog` | Cross-workload audit (Exchange, SharePoint, Teams, AAD) |
| This file's git history | `git log -- agent/references/tenants/<customer>-m365.md` | Tenant ref changes themselves are part of the change log |

---

## Recent red team / authorized testing windows

> **Update this section at engagement start.** Empty or stale entries here
> are how the L3 verifier accidentally promotes a red-team artifact to a
> real finding during the devil's-advocate step.

| Start (UTC) | End (UTC) | Scope | Authorization reference |
|---|---|---|---|
| `<YYYY-MM-DDTHH:MM:SSZ>` | `<YYYY-MM-DDTHH:MM:SSZ>` | `<accounts / hosts / scopes>` | `<authorization letter / Jira ticket / RoE doc>` |

If no authorized testing is active during the engagement window, write a
single row with both timestamps set to the engagement start and
`scope: none`.

---

## Out-of-scope artifacts

- **Cross-tenant guest accounts** — guests with UPN suffix `#EXT#@<other-tenant>.onmicrosoft.com`
  whose home tenant is owned by a partner. Metadata is in scope; mailbox
  content peeks require the home tenant's authorization.
- **Cross-tenant B2B applications** — apps consented from partner
  tenants visible in this tenant's enterprise apps list but owned
  elsewhere.
- **Partner / managed-customer identities** — `<list any UPNs this
  tenant hosts but does not own>`.
- **Personal Outlook / Hotmail addresses in mail traffic** — out of
  scope for content; metadata in scope.
- **Cross-tenant Azure subscriptions** — `<subscription IDs visible
  from this tenant but owned elsewhere>`.
- **Tenant secrets** — app secrets, certificate private keys,
  break-glass passwords. This file references them by *location* only.

---

## Previous engagements

| Date | Key | Type | Status |
|---|---|---|---|
| `<YYYY-MM-DD>` | `<engagement-key>` | `<M365 IR / phishing / ATO / consent grant abuse>` | `<Complete — benign / Complete — verified / In progress>` |

Engagement artifacts live at `agent/engagements/<key>/` under the install
root.

---

## Template provenance

- Source: `agent/references/tenants/_template-m365.md`; modeled on
  `agent/references/tenants/_template-gws.md` for cross-platform parity.
- Alias: `aith blue tenant init --platform m365` writes to
  `<customer>-m365.md` per `PLATFORM_TO_TENANT_SUFFIX["m365"] = "m365"`.
- Consumers: `agent/skills/alert-triage/SKILL.md`,
  `agent/agents/alert-triage-specialist.md`,
  `agent/skills/m365-signin-investigation/SKILL.md`,
  `agent/skills/phishing-triage/SKILL.md`,
  `agent/skills/alert-fp-verification/SKILL.md`. Keep section names stable.
