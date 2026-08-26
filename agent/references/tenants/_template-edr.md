---
description: Scaffold tenant reference for EDR fleet alert investigations (MDE, CrowdStrike Falcon, SentinelOne)
skill: edr-alert-triage
---

# <CUSTOMER> — EDR Tenant Reference

> **USE THIS AS A SCAFFOLD — DO NOT DISPATCH AGAINST IT AS-IS.**
>
> Produced by `vigil blue tenant init --customer <slug> --platform edr`,
> which writes to `agent/references/tenants/<slug>-edr.md` (per
> `PLATFORM_TO_TENANT_SUFFIX["edr"] = "edr"` in
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
> 4. **Mark the deployed vendor.** This template covers MDE, CrowdStrike
>    Falcon, and SentinelOne; only one is normally deployed. Mark unused
>    vendors `N/A` rather than deleting their sections so cross-platform
>    diffs stay stable.
>
> Platform-neutral sections (identity, on-call, change log, OOS artifacts)
> are mirrored across the `_template-<p>.md` family. Keep structure stable
> so cross-platform diffs stay readable.

Operator context for EDR alert investigations on the `<CUSTOMER>` fleet.
EDR identities are *device-side*; user identity is whoever was logged
in. Cross-reference to the relevant identity-platform tenant ref
(`<customer>-m365.md`, `<customer>-okta.md`, etc.) for user lookups.

---

## Tenant Identity

| Field | Value |
|---|---|
| Deployed EDR vendor (primary) | `<MDE / CrowdStrike / SentinelOne>` |
| Secondary / legacy EDR (if any) | `<vendor>` or `N/A` |
| Total managed endpoints | `<count>` (as of `<YYYY-MM-DD>`) |
| Linked identity platform | `<m365 / okta / gws / aws-sso>` — see `<customer>-<platform>.md` |
| Organization name | `<CUSTOMER>` |
| Admin secondary email | `<admin-recovery-email>` |
| Org phone | `<+E.164-org-phone>` |

### Vendor-specific tenant identifiers

#### Microsoft Defender for Endpoint

```
Tenant ID:      <00000000-0000-0000-0000-000000000000>  (shared with M365 tenant ref)
Geo:            <US / EU / UK>
API base URL:   https://api.security.microsoft.com   (or https://api.securitycenter.microsoft.com for legacy)
Onboarding pkg: <SCCM / Intune / GPO script / manual>
```

#### CrowdStrike Falcon

```
CID:            <00000000000000000000000000000000-XX>
Cloud:          <us-1 / us-2 / eu-1 / us-gov-1>
API base URL:   https://api.<cloud>.crowdstrike.com
Console URL:    https://falcon.<cloud>.crowdstrike.com
```

#### SentinelOne

```
Site / Account: <site-id>, <account-id>
Region URL:     https://<region>.sentinelone.net
API base URL:   https://<region>.sentinelone.net/web/api/v2.1
```

Mark `N/A` for any vendor not deployed.

---

## Tool Configuration

### Microsoft Defender for Endpoint

```
On-host CLI:    mdatp                                        (macOS / Linux endpoints)
Cloud CLI:      Microsoft Graph PowerShell SDK, Defender XDR Advanced Hunting via REST
Auth:           OAuth2 bearer, app registration <ir-graph-app-name> (see m365 tenant ref)
Required scope: ThreatHunting.Read.All, DeviceManagementManagedDevices.Read.All
```

### CrowdStrike Falcon

```
Python SDK:     falconpy (pip install crowdstrike-falconpy)
Auth:           OAuth2 client-credentials grant
Client ID:      <ir-falcon-client-id>
Secret:         <vault location — NEVER committed>
Scopes:         hosts:read, detects:read, incidents:read, real-time-response:read,
                event-streams:read, sensor-update-policies:read
```

### SentinelOne

```
API token:      $S1_API_TOKEN environment variable (operator-managed; NEVER committed)
Scoped to:      <site-id> (site-scoped, NOT account-scoped — narrower blast radius)
Header form:    Authorization: ApiToken $S1_API_TOKEN
```

Mark unused tooling `N/A`; do not delete the block so cross-platform
diffs stay stable.

---

## EDR RBAC + console scope reality

The investigator role is authorized for the following permissions per
vendor. **The operator must verify each row against the live console
after `tenant init`.** Drift here is the most common cause of 403s
mid-incident.

### MDE roles (RBAC)

| Role | Status | Notes |
|---|---|---|
| `Security Reader` | `<verified ✅ / not assigned ❌>` | Read-only access to alerts, devices, hunting |
| `Security Operator` | `<verified ✅ / not assigned ❌>` | Read + investigation actions; no settings change |
| `Live Response (Basic)` | `<verified ✅ / not assigned ❌>` | Limited shell on isolated devices |
| `Live Response (Advanced)` | `<verified ✅ / not assigned ❌>` | Full shell; gated behind separate auth challenge |

### CrowdStrike Falcon role groups

| Role group | Status | Notes |
|---|---|---|
| `Endpoint Manager - Read Only` | `<verified ✅ / not assigned ❌>` | Hosts + detections read |
| `Investigator` | `<verified ✅ / not assigned ❌>` | Detections, incidents, event search |
| `RTR Read Only` | `<verified ✅ / not assigned ❌>` | RTR session metadata only |
| `RTR Active Responder` | `<verified ✅ / not assigned ❌>` | RTR shell, file-get, kill-process |
| `RTR Administrator` | `<verified ✅ / not assigned ❌>` | RTR + put files + custom scripts |

### SentinelOne RBAC

| Role | Status | Scope |
|---|---|---|
| `Viewer` | `<verified ✅ / not assigned ❌>` | site-scoped read |
| `IR Team` | `<verified ✅ / not assigned ❌>` | Investigation, mitigation actions |
| `Admin` | `<verified ✅ / not assigned ❌>` | Full site / account admin |

Write actions (uninstall agent, change exclusion, push custom rule) are
intentionally **not** granted to the investigator role — IR here is
read-only by default. Remote-shell capabilities (RTR, Live Response,
Remote Ops Shell) are tracked separately because they carry write
power even when authored as "investigation".

---

## Critical Identities

### EDR console administrators

| Console / vendor | Login | Name | Role | Notes |
|---|---|---|---|---|
| MDE | `<admin-upn>` | `<Full Name>` | `Global Admin` (Entra) → MDE inherited | MFA hardware FIDO2 |
| CrowdStrike | `<admin-email>` | `<Full Name>` | `Falcon Administrator` | MFA via Falcon Identity |
| SentinelOne | `<admin-email>` | `<Full Name>` | `Account Admin` | MFA SSO-enforced |

### Agent install / uninstall principals

| Vendor | Principal / mechanism | Notes |
|---|---|---|
| MDE | `<Intune service principal>` / `<SCCM service account>` | Onboarding script signed by Microsoft cert |
| CrowdStrike | `<deploy-svc-account>` | Install via `WindowsSensor.exe` MSI; CID embedded |
| SentinelOne | `<deploy-svc-account>` | Install token rotated `<cadence>` |

Unauthorized uninstall is an indicator of compromise by definition —
cross-check against the change log for an authorized retirement ticket.

### Live Response analysts (remote shell)

| Vendor | Analyst | Notes |
|---|---|---|
| MDE | `<analyst-upn>` | Live Response Advanced; MFA hardware FIDO2 |
| CrowdStrike | `<analyst-email>` | RTR Active Responder |
| SentinelOne | `<analyst-email>` | Remote Ops Shell |

Every RTR / Live Response / Remote Ops session is a tracked event. L2
investigations cross-reference sessions to change-management tickets.

---

## MFA Posture

| Field | Value |
|---|---|
| Console admin MFA enforced? | `<yes — list per vendor>` |
| Hardware FIDO2 required for Live Response / RTR? | `<yes / no>` |
| Step-up MFA on shell session start? | `<yes / no>` |
| RTR / Live Response session timeout | `<minutes>` |
| Known posture gaps | `<list>` |

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
- `actor` — explicit device identity (`DeviceId`, `aid`, or `agentUuid`)
  OR explicit signed-publisher when the alert is signature-based.
  Wildcards (`*-build-host`) are NOT mechanical-eligible.
- `action_verb` — vendor-native event name (e.g.
  `ProcessRollup2`, `DeviceProcessEvents` action, S1
  `Threats` indicator). "Similar" verbs do not match.
- `time_pattern` — concrete schedule.
- `source_signal` — Defender XDR alert title + ID, Falcon detection
  pattern, S1 detection rule ID.
- `mechanical` — `true` when L1 may auto-close.
- `rationale` — one sentence + citation of the L3 finding that promoted
  the entry.

Example rows — **replace with real entries before use; remove or comment
out the examples once real entries exist**:

| pattern_id | actor | action_verb | time_pattern | source_signal | mechanical | rationale |
|---|---|---|---|---|---|---|
| `<documented-admin-lolbin>` | `<DeviceId:0123abc...>` (jump host) | `Suspicious PowerShell parent chain` | `weekdays 14:00-22:00 UTC, IT patching window` | `mde / Suspicious PowerShell parent / rule-id <rid>` | `true` | `Documented IT patching jump host; promoted from finding <slug>` |
| `<dev-tool-path-allowlist>` | `<aid:falcon-host-xyz>` (engineering laptops) | `Suspicious script interpreter` | `any (developer workstations)` | `falcon / Suspicious interpreter / pattern-id <pid>` | `false` | `Dev tools (python, node, ts-node) trip this; L2 verifies host is in engineering group, NEVER auto-close` |
| `<vendor-av-quarantine-pattern>` | `<agentUuid:...>` (file servers) | `File quarantined` | `nightly 02:00-04:00 UTC scheduled scan` | `s1 / Static AI / rule-id <rid>` | `true` | `Scheduled scan quarantines stale signatures on file servers; promoted from finding <slug>` |
| `<pua-dev-machines>` | `<DeviceId:eng-laptop-...>` | `PUA detected` | `any (engineering laptops)` | `mde / PUA detection / rule-id <rid>` | `false` | `Engineers install pentest / red-team tooling on dev laptops; L2 verifies tool vs target host` |
| `<vendor-telemetry-baseline>` | `<aid:datadog-agent-host>` | `Persistent service installation` | `change window 1st Sat of month` | `falcon / Service installation / pattern-id <pid>` | `true` | `Datadog agent updates create new services on patch days; promoted from finding <slug>` |

**Promotion rule** — only an L3 verifier who has confirmed
`false_positive` with cited evidence may seed a new mechanical row. New
`mechanical: false` rows can be added by the IR lead with a one-paragraph
rationale. Record changes in the **Tenant change log reference** below.

---

## Common IR pull commands for this tenant

> Placeholders only — replace before running. UTC timestamps; look-back is
> 30 days from earliest plausible trigger (`agent/rules/triage.md` rule 6).

### MDE — Defender XDR Advanced Hunting

```kql
// Process tree for a device over 30 days
DeviceProcessEvents
| where DeviceId == "<DeviceId>"
| where Timestamp > ago(30d)
| project Timestamp, ProcessId, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountUpn, AccountDomain
| order by Timestamp desc
```

### CrowdStrike Falcon — falconpy

```python
# Event search over the streaming feed (FQL)
from falconpy import EventStreams
es = EventStreams(client_id=os.environ["FALCON_CLIENT_ID"],
                  client_secret=os.environ["FALCON_CLIENT_SECRET"])
events = es.event_search(filter='event_simpleName: "ProcessRollup2" + aid: "<aid>"',
                         limit=100)
print(events)
```

```python
# Detection details (REST via falconpy.Detects)
from falconpy import Detects
d = Detects(client_id=..., client_secret=...).get_detect_summaries(ids=["<detection-id>"])
```

### SentinelOne — REST

```bash
# Deep Visibility event query (queryId from a saved hunt or fresh /init query)
curl -s -H "Authorization: ApiToken $S1_API_TOKEN" \
  "https://<region>.sentinelone.net/web/api/v2.1/dv/events?queryId=<queryId>&limit=1000"

# Threats / detections for an agent
curl -s -H "Authorization: ApiToken $S1_API_TOKEN" \
  "https://<region>.sentinelone.net/web/api/v2.1/threats?agentIds=<agentUuid>&limit=200"

# Agent metadata + last-seen
curl -s -H "Authorization: ApiToken $S1_API_TOKEN" \
  "https://<region>.sentinelone.net/web/api/v2.1/agents?ids=<agentUuid>"
```

When the actor is a logged-in user (most process-tree alerts), pivot
to the identity-platform tenant ref for the user's recent sign-in
context.

---

## On-call calendar reference

| Field | Value |
|---|---|
| On-call rotation tool | `<PagerDuty / Opsgenie / Teams shifts / other>` |
| Lookup URL | `<URL to on-call schedule>` |
| Look-up SLA | `<seconds to identify on-call for a given UTC timestamp>` |

---

## Vendor maintenance windows reference

| Source | URL | Notes |
|---|---|---|
| MDE service health | https://portal.office.com/servicestatus | Defender XDR ingestion lags can mimic gaps |
| CrowdStrike status | https://status.crowdstrike.com | Sensor channel-file rollouts can produce noisy detections |
| SentinelOne status | https://status.sentinelone.com | Agent update windows can spike "service install" detections |
| Tenant-specific maintenance bulletin | `<internal URL or change ticket project>` | Includes mass patching, image deploys, fleet rebuilds |

---

## Tenant change log reference

| Source | URL | Notes |
|---|---|---|
| EDR change tickets | `<Jira project URL / change ticketing>` | Policy edits, exclusion adds, group moves, uninstalls |
| MDM / patching log | `<Intune / Jamf / SCCM / Tanium console>` | Scheduled patches that trip detections |
| This file's git history | `git log -- agent/references/tenants/<customer>-edr.md` | Tenant ref changes themselves are part of the change log |

---

## Recent red team / authorized testing windows

> **Update this section at engagement start.** Empty or stale entries here
> are how the L3 verifier accidentally promotes a red-team artifact to a
> real finding during the devil's-advocate step.

| Start (UTC) | End (UTC) | Scope | Authorization reference |
|---|---|---|---|
| `<YYYY-MM-DDTHH:MM:SSZ>` | `<YYYY-MM-DDTHH:MM:SSZ>` | `<hosts / device groups / tooling in scope>` | `<authorization letter / Jira ticket / RoE doc>` |

If no authorized testing is active during the engagement window, write a
single row with both timestamps set to the engagement start and
`scope: none`.

---

## Out-of-scope artifacts

- **BYOD personal devices** — devices not enrolled in MDM/EDR but
  appearing in logs (e.g., personal phone retrieving Outlook over
  modern auth). Telemetry from such devices is out of scope.
- **Partner / managed-customer endpoints** — `<list any tenants whose
  devices are enrolled here under MSP arrangements>`.
- **Air-gapped / classified fleets** — `<list any device groups that
  are out of IR scope by regulation>`.
- **Tenant secrets** — Falcon API secret, SentinelOne API token, MDE
  app secret, RTR session tokens. This file references them by
  *location*; the secrets themselves never enter engagement artifacts.

---

## Previous engagements

| Date | Key | Type | Status |
|---|---|---|---|
| `<YYYY-MM-DD>` | `<engagement-key>` | `<EDR triage / suspicious binary / RTR live response / lateral movement>` | `<Complete — benign / Complete — verified / In progress>` |

Engagement artifacts live at `agent/engagements/<key>/` under the install
root.

---

## Template provenance

- Source: `agent/references/tenants/_template-edr.md`; modeled on
  `agent/references/tenants/_template-gws.md` for cross-platform parity.
- Alias: `vigil blue tenant init --platform edr` writes to
  `<customer>-edr.md` per `PLATFORM_TO_TENANT_SUFFIX["edr"] = "edr"`.
- Consumers: `agent/skills/alert-triage/SKILL.md`,
  `agent/agents/alert-triage-specialist.md`,
  `agent/skills/edr-alert-triage/SKILL.md`,
  `agent/skills/alert-fp-verification/SKILL.md`. Keep section names stable.
