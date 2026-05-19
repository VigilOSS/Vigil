---
name: edr-alert-triage
description: L2 EDR alert context expansion across Defender for Endpoint, CrowdStrike Falcon, and SentinelOne. Process tree, network correlation, file/registry activity, TI cross-ref, persistence checks.
origin: AI Threat Hunting
---

# EDR Alert Triage (L2)

L2 platform investigation for endpoint-detection-and-response alerts across
Microsoft Defender for Endpoint (MDE), CrowdStrike Falcon, and SentinelOne
Singularity. The skill expands an L1-dispatched EDR alert into a
process-tree-plus-network-plus-persistence picture, cross-references threat
intel, runs vendor-specific FP gates, and hands off to L3 / L4.

## When to Activate

- L1 `alert-triage` dispatched with `platform=edr-mde`, `platform=edr-cs`,
  or `platform=edr-s1`. The dispatch handoff names this skill and carries
  the alert paste artifact + initial MITRE technique seed.
- An L2 platform investigation in flight needs host-side process tree
  context before disposition (e.g., an `aws-cloudtrail` finding surfaces a
  workstation IP that triggered EDR alerts in the same window).
- `network-threat-hunt` needs origin host context for C2 traffic — the
  network signal alone can't attribute process-level intent.

This skill does NOT triage L1 alerts. A fresh alert body with no L1
dispatch halts and re-routes to `alert-triage` first.

## Always-active references

- `agent/rules/triage.md` — disposition vocabulary, severity recompute
  (rule 2), symmetric evidence bar (rule 4), MITRE on every finding
  (rule 11), tenant-ref-first (rule 12).
- `agent/shared-constraints-blue.md` — authorization scope, read-only,
  artifact chain of custody, UTC discipline, host-exec audit envelope
  (§6), cross-tenant prohibition (§7).
- `agent/rules/ir-evidence.md` — attribution gate; an EDR ML score is one
  signal, not two — corroboration requires telemetry from a different
  table or sensor.
- The tenant ref named in `scope.json:tenant_reference_paths[]` — the
  `_template-edr.md` derivative (e.g., `acme-edr.md`) documenting
  admin scripts, PUA-tolerant dev machines, vendor telemetry baselines,
  internal-binary hashes. Missing → `blocked` handoff per `triage.md`
  rule 12.

## Tools

All target-facing queries (Advanced Hunting, Falcon FQL, Deep Visibility,
VT) go through `aith assess host-exec` with `--technique IOC-ENRICH` (TI)
or `--technique TRIAGE-PULL` (vendor audit). The audit pipeline records
the full envelope so the verifier can cite the exact query.

### Cross-vendor (shared)

| Tool | What it covers | Notes |
|------|----------------|-------|
| `curl` against VirusTotal v3 | File-hash / IP / domain reputation | `VT_API_KEY` env var; chain to `agent/skills/ioc-enrichment/SKILL.md` for the full enrichment loop |
| `shasum -a 256` | Compute SHA256 over locally-saved binaries (when MDE/CS/S1 provided a download link the audit pulled) | Offline; no host-exec needed when run over an already-registered artifact |
| `jq` | Parse the JSON returned by all three vendor APIs | Offline; pure filter |
| `python3` | Offline correlation across vendor exports (process-tree merge, time-window intersection, persistence-inventory diff) | Offline; pure stdlib unless the operator allowlists requests/pandas |

### Microsoft Defender for Endpoint (MDE)

| Tool | What it covers | Notes |
|------|----------------|-------|
| Advanced Hunting KQL via Graph | Query against `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents`, `DeviceLogonEvents` | `POST https://api.security.microsoft.com/api/advancedhunting/run` with body `{ "Query": "<KQL>" }`; OAuth token in `MDE_TOKEN` env var |
| Machine lookup | Device ID, OS, last-seen, exposure score | `GET /api/machines/{id}` |
| Live Response (containment, L4 only) | Run-script / get-file on the host | Graph API; out of scope for L2 — record as an L4-required step |
| Isolation (containment, L4 only) | `POST /api/machines/{id}/isolate` | L4 / `incident-containment` skill — do NOT call from L2 |

Key MDE tables: `DeviceProcessEvents` (exec + parent + cmdline + integrity
+ signer), `DeviceNetworkEvents` (outbound + process), `DeviceFileEvents`
(create/modify/delete + process), `DeviceRegistryEvents` (key set/delete +
process), `DeviceImageLoadEvents` (DLL sideloading), `DeviceLogonEvents`
(interactive / network / remote-interactive).

### CrowdStrike Falcon

| Tool | What it covers | Notes |
|------|----------------|-------|
| Event Search via FQL (Falcon Query Language) | Query against telemetry events (ProcessRollup2, NetworkConnectIP4, FileWriteFinal, RegistrySetValueOperation, DnsRequest, UserLogon) | `falconpy` Python SDK (`from falconpy import EventStreams`) or REST against `/fwmgr/queries/events/v1`; `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET` env vars |
| Host enumeration | Device AID, hostname, OS, sensor version, OverWatch tags | `Hosts: QueryDevicesByFilter` |
| Real Time Response (RTR, L4 only) | Live host queries — `ls`, `ps`, `reg query`, custom scripts | `Hosts: PerformActionV2`; L4 / containment only |
| Isolation (L4 only) | `Hosts: PerformActionV2` with `action_name=contain` | L4 / `incident-containment` — do NOT call from L2 |

Key Falcon events: `ProcessRollup2` (rolled-up process tree row),
`NetworkConnectIP4` (outbound IP + process), `FileWriteFinal` (dedup'd
file write), `RegistrySetValueOperation`, `DnsRequest` (DNS + process),
`UserLogon` (logon + logon type).

### SentinelOne Singularity

| Tool | What it covers | Notes |
|------|----------------|-------|
| Deep Visibility (DV) query | DV DSL queries across endpoint telemetry — `EventTypes`, `SrcProcImagePath`, `TgtProcCmdLine`, `DstIP`, `EventType`, etc. | `POST /web/api/v2.1/dv/events` with the DV filter object; `S1_API_TOKEN` env var |
| Storyline | Auto-correlated event chain S1 assembles per-incident | `GET /web/api/v2.1/dv/query/by-storyline-id?storylineId=<id>` |
| Agent lookup | UUID, hostname, OS, group, last-active | `GET /web/api/v2.1/agents` |
| Isolation (L4 only) | `POST /web/api/v2.1/agents/actions/disconnect` | L4 / `incident-containment` — do NOT call from L2 |

Key S1 DV `EventType` filters: `Process Creation`, `IP Connect` /
`IP Listen`, `File Creation` / `Modification` / `Deletion`, `Registry
Key Create` / `Value Modified`, `DNS Resolved`, `Logon`/`Logoff`.

## Methodology

### Step 1 — Process-tree expansion

Pull the alerting PID + ancestors (5 generations) + immediate children
(3 generations). Without the chain you cannot distinguish a benign admin
LOLBin invocation from living-off-the-land attacks.

**MDE (KQL):**

```kql
DeviceProcessEvents
| where DeviceId == "<device-id>"
| where Timestamp between (datetime(<start>) .. datetime(<end>))
| project Timestamp, ProcessId, InitiatingProcessId, InitiatingProcessFileName,
          FileName, ProcessCommandLine, InitiatingProcessCommandLine,
          ProcessIntegrityLevel, ProcessTokenElevation, SHA256,
          InitiatingProcessSHA256, AccountName, AccountDomain
| order by Timestamp asc
```

Walk parents by joining `InitiatingProcessId` → `ProcessId` of an earlier row.
Repeat 5 generations or until the chain hits `wininit.exe` / `services.exe`
/ `explorer.exe` (root). Walk children by joining `ProcessId` → other rows'
`InitiatingProcessId`.

**Falcon (FQL via Event Search):**

```
event_simpleName:ProcessRollup2 +aid:<device-aid>
+timestamp:>=<start_epoch_ms> +timestamp:<=<end_epoch_ms>
```

Then for each returned row, follow `ParentProcessId` recursively. Falcon
emits a `tree_id` on related events — use it to bound the join.

**SentinelOne (DV):**

```json
{
  "fromDate": "<start>",
  "toDate": "<end>",
  "filter": "AgentUuid = '<uuid>' AND EventType = 'Process Creation'"
}
```

S1's Storyline auto-correlation often pre-builds the tree for you — pull
`storylineId` from the alert and run `query/by-storyline-id` first; only
fall back to the DV walk if Storyline is incomplete.

**Purpose** — identify execution chain (LOLBin? unsigned binary? renamed
system tool? unexpected parent?).

**Evidence** — process tree as JSON (`kind=ir_evidence`). Per node: PID,
parent PID, image path, command line, SHA256, signer, integrity, user.

**Common FP** — admin scripts spawning multiple LOLBins (PSReadLine,
dotnet build chains, MSI installers). Chains matching
`documented_admin_lolbin` (parent = scheduled task → cmd → powershell →
known-good script path) are benign-in-context.

### Step 2 — Network correlation

Pull all network connections originating from the process tree (every PID
captured in Step 1) within a ±15 minute window around the alerting process
exec. Cross-link to `agent/skills/ioc-enrichment/SKILL.md` for destination
reputation — every external IP and resolved domain gets a reputation pull.

**MDE:**

```kql
DeviceNetworkEvents
| where DeviceId == "<device-id>"
| where Timestamp between (datetime(<start-15m>) .. datetime(<end+15m>))
| where InitiatingProcessId in (<pid-list-from-step-1>)
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, Protocol,
          InitiatingProcessFileName, InitiatingProcessId,
          InitiatingProcessSHA256, ActionType
```

**Falcon:**

```
event_simpleName:NetworkConnectIP4 +aid:<aid> +TargetProcessId:[<pid>,<pid>,...]
```

Pair with `DnsRequest` to resolve the domain side of each connect.

**SentinelOne:**

```
EventType IN ('IP Connect','IP Listen','DNS Resolved')
AND AgentUuid = '<uuid>'
AND SrcProcPid IN (<pid-list>)
```

**Purpose** — confirm C2 or data-egress. A suspicious process tree without
an outbound channel is a weaker case than one with confirmed C2.

**Evidence** — destination IP / port / domain, ASN, country, reputation
(VT malicious_count, AbuseIPDB confidence). Save network dump as artifact;
per-IOC intel via `ioc-enrichment`.

**Common FP** — monitoring agents calling home (Defender →
wd-prod-\*.cloudapp.azure.com, Falcon → ts01-b.cloudsink.net, S1 →
trust.sentinelone.net, MDM → Intune endpoints). Match
`vendor_telemetry_baseline` before treating as adversarial.

### Step 3 — File and registry activity

Pull file writes and registry modifications attributed to any PID in the
process tree, focused on the high-signal locations:

- **Files**: `%Temp%`, `%AppData%\Local`, `%AppData%\Roaming`,
  `\Users\Public\`, `\ProgramData\`, `\Windows\Tasks\`, `\Windows\System32\drivers\`
- **Registry persistence**:
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `\RunOnce`
  - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `\RunOnce`
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*` (IFEO injection)
  - `HKLM\SYSTEM\CurrentControlSet\Services\*` (service create / start config)
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` (Startup folder redirection)
  - `HKLM\SOFTWARE\Classes\*\shell\open\command` (file-type-association hijack)

**MDE:**

```kql
union
  (DeviceFileEvents | where DeviceId == "<id>"
   | where InitiatingProcessId in (<pid-list>)
   | where FolderPath has_any ("\\Temp\\", "\\AppData\\Local\\", "\\Public\\",
                                "\\ProgramData\\", "\\Tasks\\", "\\drivers\\")),
  (DeviceRegistryEvents | where DeviceId == "<id>"
   | where InitiatingProcessId in (<pid-list>)
   | where RegistryKey has_any ("\\CurrentVersion\\Run", "Image File Execution Options",
                                 "\\Services\\", "shell\\open\\command"))
| order by Timestamp asc
```

**Falcon:** combine `FileWriteFinal` + `RegistrySetValueOperation` filters
on the PID list.

**SentinelOne:** DV with `EventType IN ('File Creation','File Modification',
'Registry Key Create','Registry Value Modified')` filtered by `SrcProcPid`.

**Purpose** — detect persistence creation, payload staging,
defense-evasion key writes.

**MITRE mappings**: T1547.001 (Run Keys), T1546.012 (IFEO Injection),
T1543.003 (Windows Service), T1546.001 (File Association), T1574.002
(DLL Side-Loading — when writes land next to a known binary).

**Evidence** — file + registry write inventory with full path and
timestamp (`kind=ir_evidence`).

**Common FP** — installer activity from documented deployment windows
(SCCM / Intune / patch cycle). Match `documented_install_windows`.

### Step 4 — Persistence sweep

Run a broader sweep for the four canonical persistence mechanisms even
when Step 3 didn't surface them inline:

- **Scheduled tasks** — `schtasks.exe /create` exec, registry writes to
  `HKLM\...\Schedule\TaskCache\Tasks\*`, files under `\Windows\Tasks\`.
- **Services** — `sc.exe create` exec, registry writes to
  `HKLM\SYSTEM\CurrentControlSet\Services\<name>` (`ImagePath`, `ServiceDll`,
  `Start`).
- **Drivers** — `.sys` writes to `\Windows\System32\drivers\` plus service
  create with `Type=0x1`. Signed-but-malicious driver loads (BYOVD) are a
  real vector — cross-check SHA256 against the LOL drivers list.
- **WMI subscriptions** — `__EventFilter` / `__EventConsumer` /
  `__FilterToConsumerBinding`. MDE surfaces as registry ops against
  `HKLM\SOFTWARE\Microsoft\Wbem\CIMOM\*`; Falcon emits `WmiCreateProcess`;
  S1 surfaces under `EventType = 'WMI Activity'`.

**MITRE**: T1053.005, T1543.003, T1546.003, T1547 parent.

**Evidence** — inventory of scheduled tasks, services, driver loads, WMI
subscriptions created in window, with PID + SHA256 attribution.

**Common FP** — Tenable / Qualys vulnerability-scan tasks, IT-deployed
management agents (BigFix, SCCM, JAMF), backup-agent service creates.
Match `documented_service_install_baseline`.

### Step 5 — TI cross-reference

Every external SHA256 (Steps 1, 3, 4) and every external IP / domain
(Step 2) chains to `agent/skills/ioc-enrichment/SKILL.md`. Don't
re-implement enrichment here; hand the IOC list to that skill and
consume the recorded intel.

Before enriching, query `intel_*` for prior incident context — a hash or
IP flagged in a previous engagement (cross-tenant `intel-note` per
`triage.md` rule 8) is high-signal for severity.

```bash
aith assess list-intel dns-record --q "<ip>" --json | jq '.[]'
aith assess list-intel note --q "<sha256>" --json | jq '.[]'
```

**Evidence** — VT verdict (`malicious_count` / `total_engines`,
last-analysis date), AbuseIPDB confidence, prior `intel_*` rows linked
via `link-finding`. Every reputation citation carries `last_verified_utc`.

**Common FP** — low-prevalence custom internal tool: VT shows 0/91 but
`times_submitted=1` and `first_seen=<recent>` — one-off, not malware.
Match `documented_internal_binaries`.

### Step 6 — Vendor-specific FP gates

Each vendor has a small set of recurring false-positive shapes the L2
must screen before raising severity above what L1 emitted. These gates
are NOT mechanical-FP auto-closes (L1's domain) — they are L2
investigator judgment calls applied AFTER the audit pull.

#### MDE-specific gates

- **PUA on developer tools** — Sysinternals (`PsExec.exe`, `procdump.exe`,
  `procmon.exe`), legitimate red-team utilities on documented pentest VMs.
  Check `pua_dev_machines` in the tenant ref; dev-tagged → downgrade.
- **LOLBin alerts on documented admin scripts** — `powershell.exe
  -EncodedCommand`, `certutil.exe -decode`, `bitsadmin.exe /transfer`,
  `regsvr32.exe /s /u /i:`. Check `documented_admin_lolbin`.
- **Behavior:\* detect on packed legit installers** — NSIS / InstallShield
  / Inno trigger MDE's behavioral engine. Combined with no Step 2 C2, no
  Step 4 persistence, no Step 5 adversarial TI → heuristic noise.
- **`DefenderAvIcon` cloud-blocked** on niche enterprise software — MAPS
  cloud bumped a low-prevalence internal build to malicious.

#### CrowdStrike-specific gates

- **ML detect on packed legit installers** — Falcon NGAV ML scores packed
  installers moderate-to-high; corroborate with Step 2 / Step 4 before
  treating as adversarial.
- **OverWatch annotations** — Falcon's human-analyst layer may have
  already graded the alert. Read OverWatch comments first; a benign
  OverWatch verdict is L3-equivalent evidence. Register the annotation
  as an artifact.
- **Storyline aggregation noise** — Storylines pull benign helper events
  (browser sync, agent heartbeat) into the adversarial chain. Storyline
  event count is NOT a severity multiplier — count distinct
  high-confidence telemetry types.

#### SentinelOne-specific gates

- **Static AI engine FP** on packed legit binaries —
  `confidenceLevel=suspicious` (NOT `malicious`). Single-signal anomaly;
  does not justify above-`medium` severity alone.
- **Behavioral AI threat with `confidenceLevel=suspicious`** — same
  treatment; the `suspicious` band is "needs human eyes," not a positive
  identification. Downgrade unless corroborated by Step 2/3/4/5.
- **Storyline auto-correlation noise** — S1 Storyline groups by process
  lineage and includes benign helpers. Same as Falcon: count distinct
  adversarial signals, not total Storyline events.

### MITRE Technique Mapping (curated)

The seed list L1 emitted on the dispatch handoff is starter-grade. Refine
it here based on what the audit pull surfaced. Common technique families
for EDR alerts:

- **TA0007 Discovery**
  - `T1057` Process Discovery
  - `T1082` System Information Discovery
  - `T1087.001` / `T1087.002` Account Discovery (local / domain)
  - `T1018` Remote System Discovery
- **TA0003 Persistence**
  - `T1547.001` Registry Run Keys / Startup Folder
  - `T1543.003` Windows Service
  - `T1053.005` Scheduled Task
  - `T1546.003` WMI Event Subscription
  - `T1546.012` Image File Execution Options Injection
- **TA0005 Defense Evasion**
  - `T1027` Obfuscated Files or Information
  - `T1036.005` Masquerading (Match Legitimate Name or Location)
  - `T1218` System Binary Proxy Execution (rundll32, regsvr32, mshta, etc.)
  - `T1562.001` Disable or Modify Tools
  - `T1055` Process Injection
- **TA0011 Command and Control**
  - `T1071.001` Web Protocols (chain to `network-threat-hunt` for full hunt)
  - `T1071.004` DNS
  - `T1572` Protocol Tunneling

`triage.md` rule 11 forbids leaving `details_json.mitre_techniques`
empty. Default fallback when nothing better fits: `T1059` (Command and
Scripting Interpreter, parent) — almost every EDR alert chains through
a script-host process.

## Known-benign register additions (for `_template-edr.md`)

The tenant ref derived from `_template-edr.md` should enumerate:

- `documented_admin_lolbin` — admin scripts that legitimately use LOLBins
  (parent path + script hash + schedule + actor identity)
- `dev_tool_path_allowlist` — Sysinternals / red-team / dev-VM paths
  where PUA detects are expected
- `vendor_av_quarantine_pattern` — PUA hashes the customer has accepted
  as benign-in-context
- `pua_dev_machines` — device IDs tagged as developer workstations
- `vendor_telemetry_baseline` — EDR / SIEM / MDM agent outbound
  destinations (per vendor, per region) for Step 2 discount
- `documented_internal_binaries` — SHA256 of in-house tools (low-
  prevalence FP shape)
- `documented_install_windows` — software-deployment schedules (SCCM /
  Intune / JAMF) for Step 3 discount
- `documented_service_install_baseline` — IT-routine services and tasks
  for Step 4 discount

## Disposition heuristics

Map Step 1-6 evidence into a `triage.md` rule 3 disposition. The verifier
confirms; L2 seeds honestly.

| Disposition | Evidence shape |
|-------------|----------------|
| `verified` | Unsigned-binary + LOLBin chain + Step 2 C2 with adversarial TI + Step 4 persistence. Multi-signal corroboration. |
| `false_positive` | Every signal explained by tenant baseline: chain matches `documented_admin_lolbin`, destinations match `vendor_telemetry_baseline`, no Step 4 persistence, no Step 5 adversarial TI. |
| `downgraded` | Single suspicious indicator without corroboration: LOLBin alone, OR S1 `confidenceLevel=suspicious` only, OR ML-detect on packed installer with clean Step 2-5. |
| `escalated` | Vendor `confidenceLevel=suspicious` only AND tenant ref doesn't cover the pattern, OR the chain crosses into another EDR's host — L3 voting needed. |

L2 severity recompute: take the L1 ceiling, confirm or downgrade based on
Step 6 outcomes. Raising above L1 ceiling requires verifier confirmation.

## Activity Log Convention

Every L2 EDR triage pass produces activity entries via `aith assess log`.
`metadata_json` carries vendor-specific identifiers so FTS and the
verifier can join across activity entries and audit pulls:

```json
{
  "tier": "L2",
  "finding_slug": "<slug>",
  "platform": "edr-mde | edr-cs | edr-s1",
  "mde_device_id": "<guid>",
  "cs_device_aid": "<aid>",
  "s1_agent_uuid": "<uuid>",
  "alert_external_id": "<from L1 dispatch>",
  "process_tree_node_count": <int>,
  "network_connections_correlated": <int>,
  "persistence_mechanisms_found": <int>,
  "iocs_enriched": <int>,
  "vendor_fp_gates_triggered": ["<gate-name>", "..."],
  "disposition_proposed": "verified | false_positive | downgraded | escalated"
}
```

Only the field matching the alert's actual vendor is populated; the
other two stay null. The cross-vendor identifiers exist so that if an
incident touches multiple EDR stacks on different hosts, the queries
join cleanly.

## Output Contract

Standard L2 → L3 handoff per the `shared-constraints-blue.md` dispatch
schema. Required fields, EDR-specific:

```json
{
  "agent_id": "<runtime-agent-id>",
  "agent_role": "edr-triage-specialist",
  "phase": "investigation",
  "handoff_status": "ready",
  "finding_slug": "<updated by record-finding/update-finding>",
  "skill_to_load": "alert-fp-verification",
  "platform": "edr-mde | edr-cs | edr-s1",
  "alert_external_id": "<from L1>",
  "actor": "<account or device identity from process tree>",
  "target": "<device ID + any cross-host targets>",
  "time_window_utc": ["<start>", "<end>"],
  "mitre_techniques": ["<refined list from Step 6>"],
  "severity": "<L2-recomputed>",
  "confidence": "low | medium | high",
  "confidence_rationale": "<one sentence: which corroborating sources>",
  "disposition_proposed": "verified | false_positive | downgraded | escalated",
  "tenant_ref_paths_consulted": ["agent/references/tenants/<customer>-edr.md"],
  "evidence_refs": [<artifact-ids: process-tree dump, network correlation dump, persistence inventory, IOC dumps, OverWatch annotation export>],
  "vendor_fp_gates_outcome": {"<gate>": "<hit | miss | n/a>"},
  "next_specialist": "verifier",
  "next_steps": [
    "Verifier Check 1: confirm process tree completeness across 5 generations",
    "Verifier Check 2: confirm IOC reputation citations include last_verified_utc",
    "Verifier Check 3: re-run vendor-specific FP gates against current tenant ref"
  ],
  "coverage_gaps": ["<missing-vendor-api-token>", "<gap-in-tenant-ref>"],
  "rationale": "<one paragraph: what the audit pull surfaced, why this disposition>"
}
```

## Closing Sequence

1. **Register hunting-query exports, process-tree dumps, persistence
   inventories** as `ir_log` (raw audit pulls):

   ```bash
   aith assess artifact register \
     "$ENGAGEMENT_DIR/ir/evidence/edr-process-tree-<slug>.json" \
     --kind ir_log --finding <slug> --agent-id <runtime-agent-id> --sensitive
   ```

   `--sensitive` is mandatory — process trees and network dumps carry
   usernames, internal hostnames, source IPs, command-line args.

2. **Derived evidence** (correlation diagram, Storyline snapshot,
   persistence inventory, IOC reputation summary) as `ir_evidence`:

   ```bash
   aith assess artifact register \
     "$ENGAGEMENT_DIR/ir/evidence/edr-persistence-inventory-<slug>.md" \
     --kind ir_evidence --finding <slug> --agent-id <runtime-agent-id>
   ```

3. **Scratch** on transient working notes (raw KQL/FQL/DV drafts,
   intermediate jq pipelines):

   ```bash
   aith assess artifact register \
     "$ENGAGEMENT_DIR/scratch/edr-kql-draft-<slug>.kql" \
     --kind scratch --finding <slug>
   ```

4. **Record the triage activity entry** (use `aith assess log`):

   ```bash
   aith assess log <runtime-agent-id> \
     "edr-handoff" "handoff" \
     "Triaged <platform> alert <alert_external_id> for device <device-id>; pulled process tree (<N> nodes, <G> generations), correlated <M> network connections, found <P> persistence mechanisms, enriched <I> IOCs; FP gates: <summary>; proposed <disposition>" \
     --actor-kind agent
   ```

5. **Emit the handoff JSON**:

   ```bash
   aith assess agent handoff --from-json /tmp/handoff.json
   ```

## Common Failure Modes

- **Querying only the alerting process** — missing the parent chain
  collapses the basic question. Always pull 5 generations up and 3
  down. A "single-process alert" disposition without the chain is
  verifier-rejected.
- **Failing to correlate across vendors when a host has multiple
  agents** — workstations with MDE + Falcon (or S1 + an MDR overlay)
  emit parallel alerts. Treat them as one incident and merge process
  trees.
- **Treating EDR ML score as ground truth** — ML is one signal.
  Corroborate via Step 2/3/4/5. A finding whose only adversarial
  signal is the vendor ML score is `downgraded` by default.
- **Missing the OverWatch annotation on CrowdStrike** — Falcon's
  human-analyst layer may have already graded the alert. Skipping it
  skips L3-equivalent evidence.
- **Acting on SentinelOne `confidenceLevel=suspicious` without
  escalating** — `suspicious` is the vendor's "needs human eyes" band,
  not a positive identification. Default to `downgraded` / `escalated`.
- **Skipping `vendor_telemetry_baseline` in Step 2** — the EDR's own
  telemetry endpoints (or MDM / SIEM forwarder) routinely trigger
  "outbound to unfamiliar IP" alerts; check the baseline first.
- **Hardcoding vendor API tokens in commands** — `MDE_TOKEN`,
  `FALCON_CLIENT_SECRET`, `S1_API_TOKEN` live in env vars sourced from
  the secrets file; the audited `--intent` field never carries tokens.
- **Calling Live Response / RTR / S1 disconnect from L2** — those are
  L4 containment actions. L2 is read-only; routing those calls breaks
  the authorization scope.

## Reference Block

- `agent/rules/triage.md` — disposition vocabulary, severity recompute,
  symmetric evidence bar, MITRE rule, tenant-ref-first.
- `agent/shared-constraints-blue.md` — host-exec audit envelope (§6),
  cross-tenant prohibition (§7), artifact chain of custody (§3),
  read-only L2 (§1).
- `agent/rules/ir-evidence.md` — attribution gate; cross-source
  corroboration definition consumed by Step 5 and Step 6.
- `agent/skills/alert-triage/SKILL.md` — L1 dispatcher whose handoff
  seeds this skill.
- `agent/skills/ioc-enrichment/SKILL.md` — Step 5 TI cross-reference;
  this skill calls it for every external IP / domain / hash.
- `agent/skills/incident-containment/SKILL.md` — L4 consumer; host
  isolation per vendor (MDE `/machines/{id}/isolate`, Falcon
  `PerformActionV2 action_name=contain`, S1 `agents/actions/disconnect`).
  DO NOT call from this skill.
- `agent/skills/network-threat-hunt/SKILL.md` — parallel P2 skill;
  consumes this skill's process tree as origin context.
- `agent/skills/cobalt-strike-analysis/SKILL.md` — chain when Step 2
  flags Cobalt Strike infrastructure or Step 3 surfaces a beacon binary.
- `agent/skills/container-escape-detection/SKILL.md` — adjacent EDR-class
  telemetry skill; cite when the host is itself a container host.
- `agent/skills/alert-fp-verification/SKILL.md` — L3 verifier this
  skill hands off to; the five checks cite artifacts registered here.
- `agent/references/tenants/_template-edr.md` (and per-customer
  derivatives) — drives Step 1-6 FP screening via
  `documented_admin_lolbin`, `vendor_telemetry_baseline`,
  `pua_dev_machines`, `documented_internal_binaries`, etc.
- MDE Advanced Hunting schema:
  https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
- MITRE D3FEND (ATT&CK ↔ EDR-class telemetry): https://d3fend.mitre.org/
