---
description: Scaffold tenant reference for Okta org alert investigations (Okta API token scopes and admin role context)
skill: okta-investigation
---

# <CUSTOMER> — Okta Tenant Reference

> **USE THIS AS A SCAFFOLD — DO NOT DISPATCH AGAINST IT AS-IS.**
>
> Produced by `vigil blue tenant init --customer <slug> --platform okta`,
> which writes to `agent/references/tenants/<slug>-okta.md` (per
> `PLATFORM_TO_TENANT_SUFFIX["okta"] = "okta"` in
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
> are mirrored across the `_template-<p>.md` family. Keep structure stable
> so cross-platform diffs stay readable.

Operator context for Okta alert investigations on the `<okta-org>` org.
Load this before running any Okta API call so you do not spend time
rediscovering token scopes and admin role assignments.

---

## Tenant Identity

| Field | Value |
|---|---|
| Org URL | `https://<okta-org>.okta.com` |
| Custom domain (if any) | `https://<vanity-domain>` |
| Org ID | `<00oxxxxxxxxxxxxxxxxx>` |
| Org subdomain | `<okta-org>` |
| Organization name | `<CUSTOMER>` |
| Cell / region | `<US / EMEA / APAC / Preview / OK1...>` |
| Tenant created | `<YYYY-MM-DD>` |
| Total users (active) | `<count>` (as of `<YYYY-MM-DD>`) |
| Total apps assigned | `<count>` |
| Admin secondary email | `<admin-recovery-email>` |
| Org phone | `<+E.164-org-phone>` |

---

## Tool Configuration

### API token (legacy SSWS)

```
Token storage: $OKTA_API_TOKEN environment variable (operator-managed; NEVER committed)
Created by:    <admin login (UPN form)>
Token name:    <ir-token-name>
Token created: <YYYY-MM-DD>
Last rotated:  <YYYY-MM-DD>
Scope:         Inherits creator's admin role (per-user, not per-token)
```

Header form for every call:

```
Authorization: SSWS $OKTA_API_TOKEN
```

### OAuth-scoped service app (preferred over SSWS where supported)

```
App name:    <ir-service-app-name>
Client ID:   <00oxxxxxxxxxxxxxxxxx>
Auth:        Private-key JWT (key thumbprint <...>, stored in <vault location>)
Scopes:      okta.users.read, okta.logs.read, okta.policies.read,
             okta.apps.read, okta.factors.read, okta.groups.read
```

### Endpoint

```
Base URL: https://<okta-org>.okta.com/api/v1
```

`api.okta.com` is NOT the right base — every API call goes through the
org-specific subdomain. If you see `400 Bad Request — invalid host`,
the wrong base URL is the cause.

---

## API token + service-app scope reality

The IR token / service app is authorized for the following scopes.
**The operator must verify each row against the live Okta admin console
after `tenant init`.** Drift here is the most common cause of 403s
mid-incident.

### SSWS token (per-user admin role)

The SSWS token inherits the creator's admin role. List the creator's
admin role assignments in the next subsection — those determine what
the token can read.

| Surface | Status | Notes |
|---|---|---|
| System Log (`/api/v1/logs`) | `<verified ✅ / 403 ❌>` | Authoritative audit feed |
| Users (`/api/v1/users`) | `<verified ✅ / 403 ❌>` | User lookup, factors, group membership |
| Apps (`/api/v1/apps`) | `<verified ✅ / 403 ❌>` | Assigned apps, OAuth grants |
| Policies (`/api/v1/policies`) | `<verified ✅ / 403 ❌>` | Sign-on, MFA enrollment, password policies |
| API tokens (`/api/v1/api/tokens`) | `<verified ✅ / 403 ❌>` | Read other admin SSWS tokens (super admin only) |

### OAuth service-app scopes

| Scope | Status | Notes |
|---|---|---|
| `okta.users.read` | `<verified ✅ / not granted ❌>` | User reads |
| `okta.logs.read` | `<verified ✅ / not granted ❌>` | System Log reads |
| `okta.policies.read` | `<verified ✅ / not granted ❌>` | Policy reads |
| `okta.apps.read` | `<verified ✅ / not granted ❌>` | App enumeration |
| `okta.factors.read` | `<verified ✅ / not granted ❌>` | Factor lookups |
| `okta.groups.read` | `<verified ✅ / not granted ❌>` | Group reads |

Write scopes (`okta.users.manage`, `okta.policies.manage`, etc.) are
intentionally **not** granted — IR here is read-only by design.

---

## Critical Identities

### Super admins

| Login (UPN form) | userId | Name | Notes |
|---|---|---|---|
| `<super-admin-1>` | `<00u1xxxxxxxxxxxxxx>` | `<Full Name>` | `<role / tenure / MFA enforced / hardware FIDO2>` |
| `<super-admin-2>` | `<00u1xxxxxxxxxxxxxx>` | `<Full Name>` | `<role / tenure / MFA enforced / hardware FIDO2>` |

### Admin role assignments

| Login | userId | Role | Scope (org-wide / group-scoped) |
|---|---|---|---|
| `<admin-1>` | `<00u1...>` | `Super Administrator` | org-wide |
| `<admin-2>` | `<00u1...>` | `Org Administrator` | org-wide |
| `<admin-3>` | `<00u1...>` | `App Administrator` | scoped to apps `<app-1>, <app-2>` |
| `<admin-4>` | `<00u1...>` | `Help Desk Administrator` | scoped to group `<helpdesk-targets>` |
| `<admin-5>` | `<00u1...>` | `Read-Only Administrator` | org-wide |
| `<admin-6>` | `<00u1...>` | `MFA Administrator` | org-wide |
| `<admin-7>` | `<00u1...>` | `Factor Administrator` | org-wide |

### Break-glass account

| Login | userId | Storage location of credentials | Last rotation |
|---|---|---|---|
| `<breakglass@<okta-org>.okta.com>` | `<00u1...>` | `<password manager / safe / vault reference>` | `<YYYY-MM-DD>` |

Break-glass account is excluded from MFA enrollment policy and has a
hardware FIDO2 factor stored offline. Sign-in during an incident is **a
documented event the IR operator triggers**.

### Service-account users

| Login | userId | Purpose | Notes |
|---|---|---|---|
| `<svc-1>` | `<00u1...>` | `<integration>` | `<API token holder / scoped role>` |
| `<svc-2>` | `<00u1...>` | `<integration>` | `<scopes>` |

---

## MFA Posture

| Field | Value |
|---|---|
| Allowed factor types | `<FIDO2 (WebAuthn), Okta Verify push, Okta Verify TOTP, Google Authenticator, SMS, voice, email>` |
| Allowed factor types for admins | `<FIDO2 + Okta Verify push only — phishing-resistant required>` |
| MFA enrollment policy | `<policy-name>` (assigned to `<group>`, factor types `<list>`) |
| MFA policy (sign-on) | `<policy-name>` (assigned to `<group>`, factor prompts every `<duration>`) |
| FastPass enabled? | `<yes / no>` |
| Hardware FIDO2 required for super admins? | `<yes / no>` |
| Known exception list | `<logins or groups exempted from MFA, with rationale>` |
| Known posture gaps | `<list>` |

SMS / voice factors should be disabled for admins — flag any admin row
above with `Notes: SMS factor enrolled` for follow-up.

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
- `actor` — explicit Okta `actor.id` (`00u…`) or login. Wildcards
  (`*@<okta-org>.okta.com`) are NOT mechanical-eligible.
- `action_verb` — System Log `eventType` exactly (e.g.
  `user.session.start`, `user.mfa.factor.deactivate`,
  `system.api_token.create`).
- `time_pattern` — concrete schedule.
- `source_signal` — System Log rule, ThreatInsight, or SIEM rule ID.
- `mechanical` — `true` when L1 may auto-close.
- `rationale` — one sentence + citation of the L3 finding that promoted
  the entry.

Example rows — **replace with real entries before use; remove or comment
out the examples once real entries exist**:

| pattern_id | actor | action_verb | time_pattern | source_signal | mechanical | rationale |
|---|---|---|---|---|---|---|
| `<documented-push-test>` | `<00u1adminxxxxxxxxxx>` | `user.authentication.auth_via_mfa` | `quarterly drill week 1 of Mar/Jun/Sep/Dec, business hours` | `okta-threatinsight / Suspicious MFA push / rule-id <rid>` | `true` | `Documented MFA fatigue drill; cross-check on-call calendar before auto-close; promoted from finding <slug>` |
| `<factor-reset-helpdesk-pattern>` | `<00u1helpdesk-xxx>` | `user.mfa.factor.reset_all` | `business hours, weekdays only` | `okta-system-log / Admin factor reset / rule-id <rid>` | `false` | `Help-desk resets factors as part of normal onboarding/offboarding; L2 verifies ticket ID each time` |
| `<api-token-baseline>` | `<00u1svc-siemxxxxx>` | `system.api_token.create` | `annually, last week of January` | `okta-system-log / API token created / rule-id <rid>` | `true` | `SIEM integration token rotation; service account pinned; annual schedule documented` |
| `<traveling-user-pattern>` | `<00u1sales-vp-xxx>` | `user.session.start` (new geo) | `monthly EMEA → US round-trip week 1 of month` | `okta-threatinsight / New geo location / rule-id <rid>` | `false` | `Documented travel pattern; L2 verifies city pair each time, NEVER auto-close` |
| `<ad-sync-lag-window>` | `<00u1ad-agent-xxxx>` | `user.lifecycle.update` | `business hours, weekdays, sync cadence` | `okta-system-log / Bulk user update / rule-id <rid>` | `true` | `On-prem AD → Okta sync; recurring lifecycle updates from AD agent identity; promoted from finding <slug>` |

**Promotion rule** — only an L3 verifier who has confirmed
`false_positive` with cited evidence may seed a new mechanical row. New
`mechanical: false` rows can be added by the IR lead with a one-paragraph
rationale. Record changes in the **Tenant change log reference** below.

---

## Common IR pull commands for this tenant

> Placeholders only — replace before running. UTC timestamps; look-back is
> 30 days from earliest plausible trigger (`agent/rules/triage.md` rule 6).

```bash
# System Log — events for a specific actor (paginated; follow next-link header)
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "https://<okta-org>.okta.com/api/v1/logs?since=<YYYY-MM-DDTHH:MM:SSZ>&filter=actor.id+eq+%22<00u1...>%22&limit=1000"

# Factors enrolled by a user
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "https://<okta-org>.okta.com/api/v1/users/<00u1...>/factors"

# All admin SSWS tokens (super admin only)
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "https://<okta-org>.okta.com/api/v1/api/tokens"

# Sign-on / MFA enrollment policies
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "https://<okta-org>.okta.com/api/v1/policies?type=MFA_ENROLL"
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "https://<okta-org>.okta.com/api/v1/policies?type=OKTA_SIGN_ON"

# Apps with active assignments to the actor
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "https://<okta-org>.okta.com/api/v1/apps?filter=user.id+eq+%22<00u1...>%22"

# Active sessions for a user (use to gather evidence before kill)
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "https://<okta-org>.okta.com/api/v1/users/<00u1...>/sessions"
```

Always `+filter=` URL-encode the equality operator (`eq`) and surrounding
quotes — the Okta filter parser rejects unquoted IDs even when they
contain only alphanumerics.

---

## On-call calendar reference

| Field | Value |
|---|---|
| On-call rotation tool | `<PagerDuty / Opsgenie / GCal / other>` |
| Lookup URL | `<URL to on-call schedule>` |
| Look-up SLA | `<seconds to identify on-call for a given UTC timestamp>` |

The L3 verifier's devil's-advocate step (`alert-fp-verification` Check 5)
requires identifying who was on-call during the alert's time window.

---

## Vendor maintenance windows reference

| Source | URL | Notes |
|---|---|---|
| Okta Trust (status) | https://trust.okta.com | Cross-check before treating an auth-failure spike as adversarial |
| Tenant-specific maintenance bulletin | `<internal URL or change ticket project>` | Includes SSO cutovers, factor policy edits, app rebrands |
| Identity provider status (if federated) | `<URL>` | Upstream SAML / AD agent breaks present as sign-on failures |

---

## Tenant change log reference

| Source | URL | Notes |
|---|---|---|
| Okta change tickets | `<Jira project URL / change ticketing>` | Admin role assignments, policy edits, app config changes |
| Okta System Log | `/api/v1/logs?filter=eventType+sw+%22system%22` | Source of truth for admin actions |
| This file's git history | `git log -- agent/references/tenants/<customer>-okta.md` | Tenant ref changes themselves are part of the change log |

---

## Recent red team / authorized testing windows

> **Update this section at engagement start.** Empty or stale entries here
> are how the L3 verifier accidentally promotes a red-team artifact to a
> real finding during the devil's-advocate step.

| Start (UTC) | End (UTC) | Scope | Authorization reference |
|---|---|---|---|
| `<YYYY-MM-DDTHH:MM:SSZ>` | `<YYYY-MM-DDTHH:MM:SSZ>` | `<users / apps / factors in scope>` | `<authorization letter / Jira ticket / RoE doc>` |

If no authorized testing is active during the engagement window, write a
single row with both timestamps set to the engagement start and
`scope: none`.

---

## Out-of-scope artifacts

- **Cross-org Okta tenants** — `<list any related orgs (sandbox /
  preview) the operator can access but are not in scope>`.
- **Partner / managed-customer identities** — `<list any users this org
  hosts but does not own>`.
- **Personal email addresses appearing in factor email channels** —
  out of scope for content; metadata in scope.
- **Upstream IdPs (Azure AD / on-prem AD)** — federation source identity
  belongs to the upstream tenant's investigation; Okta-side metadata is
  in scope.
- **Tenant secrets** — SSWS tokens, private-key JWT signing keys,
  break-glass passwords. This file references them by *location*; the
  secrets themselves never enter engagement artifacts.

---

## Previous engagements

| Date | Key | Type | Status |
|---|---|---|---|
| `<YYYY-MM-DD>` | `<engagement-key>` | `<Okta IR / MFA bypass / session theft / token abuse>` | `<Complete — benign / Complete — verified / In progress>` |

Engagement artifacts live at `agent/engagements/<key>/` under the install
root.

---

## Template provenance

- Source: `agent/references/tenants/_template-okta.md`; modeled on
  `agent/references/tenants/_template-gws.md` for cross-platform parity.
- Alias: `vigil blue tenant init --platform okta` writes to
  `<customer>-okta.md` per `PLATFORM_TO_TENANT_SUFFIX["okta"] = "okta"`.
- Consumers: `agent/skills/alert-triage/SKILL.md`,
  `agent/agents/alert-triage-specialist.md`,
  `agent/skills/okta-investigation/SKILL.md`,
  `agent/skills/alert-fp-verification/SKILL.md`. Keep section names stable.
