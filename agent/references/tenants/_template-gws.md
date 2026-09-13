---
description: Scaffold tenant reference for Google Workspace alert investigations (GAM/gcloud IR context)
skill: google-workspaces
---

# <CUSTOMER> — Google Workspace Tenant Reference

> **USE THIS AS A SCAFFOLD — DO NOT DISPATCH AGAINST IT AS-IS.**
>
> Produced by `vigil blue tenant init --customer <slug> --platform gws`,
> which writes to `agent/references/tenants/<slug>-workspace.md` (the
> `gws → workspace` alias from `PLATFORM_TO_TENANT_SUFFIX` in
> `src/vigil_cli/blue.py`).
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
> are mirrored across future `_template-<p>.md` files. Keep structure
> stable so cross-platform diffs stay readable.

Operator context for Workspace alert investigations on the
`<tenant-domain>` tenant. Load this before running any GAM or gcloud
command so you do not spend time rediscovering config.

---

## Tenant Identity

| Field | Value |
|---|---|
| Primary domain | `<tenant-domain>` |
| Alias domains | `<alias-domain-1>`, `<alias-domain-2>` (or `none`) |
| Customer ID | `<C-prefixed-customer-id>` (bare form used in API paths: `<bare-customer-id>`) |
| Organization name | `<CUSTOMER>` |
| Tenant created | `<YYYY-MM-DD>` |
| Total users | `<count>` (as of `<YYYY-MM-DD>`) |
| Admin secondary email | `<admin-recovery-email>` |
| Org phone | `<+E.164-org-phone>` |

---

## Tool Configuration

### GAM

```
Binary:      <path-to-gam-binary>          (shell alias: gam)
Config dir:  ~/.gam/
Config file: ~/.gam/gam.cfg
admin_email: <super-admin@tenant-domain>   (Super Admin; used for DWD impersonation)
```

**GCP project: `<gam-gcp-project-id>`** — this is the project that owns the
GAM service account and the DWD entry. Document any *additional* GCP
projects visible in the console that do NOT have a service account so
operators don't chase them during incidents.

Service account (credentials reference — **do not paste the key body**):
```
SA email:     <sa-email>@<gcp-project>.iam.gserviceaccount.com
SA client_id: <numeric-sa-client-id>     (numeric ID used in the DWD entry)
SA key:       ~/.gam/oauth2service.json   (env var: GAM_OAUTHSERVICE_JSON if overridden)
```

### gcloud

```
Binary:  <path-to-gcloud>
ADC:     <adc-principal@tenant-domain> (authenticated)
```

gcloud ADC works for Admin Reports and Directory API pulls. **Alert Center
work goes through GAM** — `apps.alerts` is restricted to allowlisted OAuth
clients and gcloud's ADC client is not on that list.

---

## DWD Scope Reality

The DWD entry in Admin Console authorizes the following scopes for SA
client_id `<numeric-sa-client-id>`. **The operator must verify each row
against the live Admin Console after `tenant init`** — DWD drift is the
single most common cause of GAM preflight false negatives.

| Scope | Status | Notes |
|---|---|---|
| `https://www.googleapis.com/auth/apps.alerts` | `<verified ✅ / not in DWD ❌>` | Alert Center pulls via `gam print alerts` / `gam info alert` |
| `https://www.googleapis.com/auth/admin.reports.audit.readonly` | `<verified ✅ / not in DWD ❌>` | Sign-in audit, admin audit, drive audit, etc. (Admin Reports API) |
| `https://www.googleapis.com/auth/admin.directory.user.readonly` | `<verified ✅ / not in DWD ❌>` | User lookups, group membership, MFA enrollment |
| `https://www.googleapis.com/auth/gmail.readonly` | `<verified ✅ / not in DWD ❌>` | Message bodies, headers, attachments |
| `https://www.googleapis.com/auth/gmail.settings.basic` | `<verified ✅ / not in DWD ❌>` | Filters, forwarding, vacation |
| `https://www.googleapis.com/auth/gmail.settings.sharing` | `<verified ✅ / not in DWD ❌>` | IMAP/POP, sendas, delegation |
| `https://www.googleapis.com/auth/drive.readonly` | `<verified ✅ / not in DWD ❌>` | Drive audit content peeks (read-only) |
| `https://www.googleapis.com/auth/calendar.readonly` | `<verified ✅ / not in DWD ❌>` | Calendar audit, sharing surface inspection |

`gmail.modify` (and other write scopes) are intentionally **not** in the
IR DWD set — IR here is read-only by design. If GAM preflight reports
`Gmail API Service/App not enabled` it is probably probing `gmail.modify`,
not `gmail.readonly`; use a targeted scope check:

```bash
gam user <target@tenant-domain> check serviceaccount scopes "https://www.googleapis.com/auth/gmail.readonly"
```

For ambiguous cases, perform a scoped DWD token probe with the service-account
key and record the exact requested scope and API response.

---

## Critical Identities

### Super admins

| Email | Name | Notes |
|---|---|---|
| `<super-admin-1@tenant-domain>` | `<Full Name>` | `<role / tenure / MFA enforced>` |
| `<super-admin-2@tenant-domain>` | `<Full Name>` | `<role / tenure / MFA enforced>` |

### Break-glass account

| Email | Storage location of credentials | Last rotation |
|---|---|---|
| `<breakglass@tenant-domain>` | `<password manager / safe / vault reference>` | `<YYYY-MM-DD>` |

The break-glass account is exempt from MFA enforcement by policy — this is
expected. Sign-in from the break-glass account during an incident is **a
documented event the IR operator triggers**, not adversarial activity.
Cross-check break-glass sign-ins against the change log before treating
them as findings.

### Service accounts

| Identity | Purpose | Notes |
|---|---|---|
| `<svc-account-1@tenant-domain>` | `<integration name>` | `<scopes / OAuth client id / owner team>` |
| `<svc-account-2@tenant-domain>` | `<integration name>` | `<scopes / OAuth client id / owner team>` |

### Delegated admins

| Email | Role bundle | Notes |
|---|---|---|
| `<delegated-admin-1@tenant-domain>` | `<role bundle>` | `<MFA, last login, scope>` |

---

## Domain-wide delegation scopes (IR program defaults — verify before use)

These are the scopes the IR program assumes exist in DWD. **Mark each row
verified once the operator has confirmed it in Admin Console for this
tenant.** Operators must not assume a scope is granted just because it is
listed here.

- `https://www.googleapis.com/auth/admin.reports.audit.readonly` — sign-in
  audit, admin audit, drive audit, gmail audit, calendar audit
- `https://www.googleapis.com/auth/admin.directory.user.readonly` — user,
  group, 2SV state
- `https://www.googleapis.com/auth/gmail.readonly` — message bodies for
  L2 evidence ladder
- `https://www.googleapis.com/auth/gmail.settings.basic` — filters /
  forwarding / vacation
- `https://www.googleapis.com/auth/gmail.settings.sharing` — IMAP/POP,
  sendas, delegation
- `https://www.googleapis.com/auth/apps.alerts` — Alert Center read
- `https://www.googleapis.com/auth/drive.readonly` — drive audit content
  peeks
- `https://www.googleapis.com/auth/calendar.readonly` — calendar audit,
  sharing surface

If a scope is required for a specific investigation but is not granted,
log the gap as a coverage deferral on the engagement rather than expanding
DWD mid-incident.

---

## Key Personnel

| Email | Name | Role | Notes |
|---|---|---|---|
| `<personnel-email-1>` | `<Full Name>` | `<role>` | `<MFA, last login, group memberships>` |
| `<personnel-email-2>` | `<Full Name>` | `<role>` | `<MFA, last login, group memberships>` |

`<count>` total users. Pull the full list with:

```bash
gam print users fields primaryEmail,name.fullName,isAdmin,lastLoginTime,isEnrolledIn2Sv,suspended
```

---

## MFA Posture

| Field | Value |
|---|---|
| 2SV enforced org-wide? | `<yes / no — voluntary enrollment>` |
| Enforcement OU exceptions | `<list OUs without enforcement, or "none">` |
| Hardware security keys required? | `<yes / no / role-specific>` |
| Known posture gaps | `<list>` |

Posture gaps documented here are *known conditions, not findings unique to
a specific alert*. They still belong in the IR report's posture section
but should not drive an alert's disposition by themselves.

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

Conventions:

- `pattern_id` — short kebab-case slug, unique within this file (used in
  the structured counter-check citation, e.g. `Mechanical FP — matches tenant-ref pattern
  <pattern_id>`).
- `actor` — explicit identity (e.g.
  `vendor-sync@<tenant-domain>`). Wildcards (`*@<tenant-domain>`) are NOT
  mechanical-eligible — L1 will treat them as escalation cues.
- `action_verb` — the platform's native event name (e.g.
  `oauth_grant`, `mailbox_rule_add`, `signin_anomaly`). "Similar" verbs
  do not match — be exact.
- `time_pattern` — concrete schedule (e.g.
  `every Tuesday 02:00 UTC ± 5 minutes`). "Approximately during business
  hours" is NOT a documented schedule and disqualifies the row from
  mechanical auto-close.
- `source_signal` — SIEM/alert-center rule identity (e.g.
  `gws-alert-center / Suspicious sign-in / rule-id 0001`).
- `mechanical` — `true` when L1 may auto-close on a match (all five
  alert-triage screen conditions still apply); `false` when the entry
  explains a recurring legitimate signal that L2 still has to review
  manually each time.
- `rationale` — one sentence explaining why this pattern is benign and
  citing the original L3-verified finding (slug or engagement key) if the
  pattern was promoted from a prior finding.

Example rows — **replace with real entries before use; remove or comment
out the examples once real entries exist**:

| pattern_id | actor | action_verb | time_pattern | source_signal | mechanical | rationale |
|---|---|---|---|---|---|---|
| `<vendor-sync-nightly>` | `<vendor-sync@tenant-domain>` | `oauth_token_refresh` | `nightly 02:00 UTC ± 10 min` | `gws-alert-center / OAuth token refresh / rule-id <rid>` | `true` | `<vendor> integration; promoted from finding <slug> after L3 verified benign` |
| `<admin-impersonation-test>` | `<super-admin-1@tenant-domain>` | `user_impersonation` | `quarterly drill week 1 of Mar/Jun/Sep/Dec, business hours` | `gws-alert-center / Admin impersonation / rule-id <rid>` | `true` | `Documented IR drill schedule; cross-check on-call calendar before auto-close` |
| `<personal-gmail-coresp>` | `<wildcard — see note>` | `external_email_received` | `any` | `gws-gmail / Potential employee spoofing / rule-id <rid>` | `false` | `Employees use personal Gmail for legitimate side correspondence; L2 must verify identity match each time, NEVER auto-close` |
| `<calendar-share-external>` | `<sales-team-shared-cal@tenant-domain>` | `calendar_share_external` | `business hours, weekdays only` | `gws-alert-center / External calendar share / rule-id <rid>` | `true` | `Sales team shares booking calendar externally as a documented business process` |
| `<break-glass-quarterly-test>` | `<breakglass@tenant-domain>` | `super_admin_signin` | `quarterly drill, see change log` | `gws-alert-center / Privileged signin / rule-id <rid>` | `false` | `Break-glass tests must be cross-checked against the change-log entry; never auto-close without the ticket id` |

**Promotion rule** — only an L3 verifier who has confirmed `false_positive`
with cited evidence may seed a new mechanical row. New `mechanical: false`
rows can be added by the IR lead with a one-paragraph rationale. Either way,
record the change in the **Tenant change log reference** below and reference
this file in the commit message so the diff is auditable.

---

## Common IR pull commands for this tenant

> Placeholders only — replace before running. UTC timestamps; look-back is
> 30 days from earliest plausible trigger (`agent/rules/triage.md` rule 6).

```bash
# Alert Center
gam print alerts > /tmp/alerts_all.csv
gam info alert <alertId>
gam create alertfeedback <alertId> notuseful      # only after L3 disposition

# Sign-in activity (30-day window via Admin Reports REST)
TOKEN=$(gcloud auth application-default print-access-token)
curl -s -G -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "startTime=$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ')" \
  --data-urlencode "maxResults=200" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/<user@tenant-domain>/applications/login" \
  | python3 -m json.tool

# Account / audit pulls
gam info user <user> fields primaryEmail,lastLoginTime,isEnrolledIn2Sv,isEnforcedIn2Sv,suspended,isMailboxSetup
gam report users user <user@tenant-domain> event login    start <YYYY-MM-DDTHH:MM:SSZ>
gam report users user <user@tenant-domain> event drive    start <YYYY-MM-DDTHH:MM:SSZ>
gam report users user <user@tenant-domain> event gmail    start <YYYY-MM-DDTHH:MM:SSZ>
gam report users user <user@tenant-domain> event calendar start <YYYY-MM-DDTHH:MM:SSZ>
gam report admin                                         start <YYYY-MM-DDTHH:MM:SSZ>

# Gmail content + hygiene (use max_to_print, not maxresults)
gam user <user> print messages query "from:<sender> after:<YYYY/MM/DD>" max_to_print 25 \
  headers "Subject,From,To,Date,Message-Id,Authentication-Results"
gam user <user> print messages query "rfc822msgid:<rfc2822-id>" max_to_print 1
gam user <user> show message <gmail-internal-hex-id> format full
gam user <user> show forwarding
gam user <user> show filters
gam user <user> show delegate
```

---

## On-call calendar reference

| Field | Value |
|---|---|
| On-call rotation tool | `<PagerDuty / Opsgenie / GCal / other>` |
| Lookup URL | `<URL to on-call schedule>` |
| Look-up SLA | `<seconds to identify on-call for a given UTC timestamp>` |

The L3 verifier's devil's-advocate step (`alert-fp-verification` Check 5)
requires identifying who was on-call during the alert's time window — use
this pointer rather than asking the operator out-of-band.

---

## Vendor maintenance windows reference

| Source | URL | Notes |
|---|---|---|
| Google Workspace Status Dashboard | https://www.google.com/appsstatus/dashboard/ | Cross-check before treating an outage-coincident anomaly as adversarial |
| Tenant-specific maintenance bulletin | `<internal URL or change ticket project>` | Includes scheduled OU moves, SSO cutovers, OAuth re-grants |
| Identity provider status (if federated) | `<URL>` | Federation breaks look like sign-in anomalies — check first |

---

## Tenant change log reference

| Source | URL | Notes |
|---|---|---|
| Tenant config change tickets | `<Jira project URL / change ticketing>` | Every OU move, role assignment, DWD scope add, OAuth grant approval should be tracked here |
| Admin console audit log | `gam report admin` | Source of truth for admin actions; cross-reference ticket IDs in audit event descriptions |
| This file's git history | `git log -- agent/references/tenants/<customer>-workspace.md` | Tenant ref changes themselves are part of the change log |

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
`scope: none`. This is explicit "no red team in flight" evidence the L3
verifier can cite.

---

## Out-of-scope artifacts

> Anything an investigator must NOT pull, register as evidence, or
> reference in a finding. Includes cross-tenant resources, partner orgs
> the customer brokers traffic for, and identities the customer manages
> on behalf of someone else.

- **Cross-tenant domains** — `<list partner domains the tenant federates
  with but does not own>`. Any data sourced from these domains is
  out-of-scope and must not be pulled into engagement artifacts.
- **Partner / managed-customer identities** — `<list any users this tenant
  hosts but does not own>`.
- **Personal Gmail addresses appearing in correspondence** — out-of-scope
  for content pulls; metadata (timestamp, message-id, recipient) is in
  scope.
- **Cross-tenant GCP projects** — `<list any projects visible from the
  tenant's GCP console that belong to other entities>`.
- **Tenant secrets** — passwords, OAuth keys, SA private keys. This file
  references them by *location*; the secrets themselves never enter
  engagement artifacts or findings.

---

## Previous engagements

| Date | Key | Type | Status |
|---|---|---|---|
| `<YYYY-MM-DD>` | `<engagement-key>` | `<Workspace IR / phishing / ATO>` | `<Complete — benign / Complete — verified / In progress>` |

Engagement artifacts live at `agent/engagements/<key>/` under the install
root.

---

## Template provenance

- Source: `agent/references/tenants/_template-gws.md`; this tracked synthetic
  template is the public contract. Customer-populated references remain local-only.
- Alias: `vigil blue tenant init --platform gws` writes to
  `<customer>-workspace.md` per `PLATFORM_TO_TENANT_SUFFIX["gws"] = "workspace"`.
- Consumers: `agent/skills/alert-triage/SKILL.md`,
  `agent/agents/alert-triage-specialist.md`,
  `agent/skills/google-workspaces/SKILL.md`,
  `agent/skills/alert-fp-verification/SKILL.md`. Keep section names stable.
