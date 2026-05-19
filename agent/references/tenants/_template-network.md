# <CUSTOMER> — Network / Perimeter Tenant Reference

> **USE THIS AS A SCAFFOLD — DO NOT DISPATCH AGAINST IT AS-IS.**
>
> Produced by `aith blue tenant init --customer <slug> --platform network`,
> which writes to `agent/references/tenants/<slug>-network.md` (per
> `PLATFORM_TO_TENANT_SUFFIX["network"] = "network"` in
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

Operator context for network-plane alert investigations (firewall,
proxy, SIEM, DNS, beacon hunting) on the `<CUSTOMER>` perimeter. The
network plane has no user identity natively — actors are IPs, hostnames,
MACs, and NetFlow exporter IDs. Pivot to an identity-platform tenant
ref via DHCP / 802.1X / VPN session mapping when a user attribution is
needed.

---

## Tenant Identity

| Field | Value |
|---|---|
| Organization name | `<CUSTOMER>` |
| Sites / locations | `<HQ, DC1, DC2, branch-N>` |
| Primary internal IP space | `<10.0.0.0/8, 172.16.0.0/12>` |
| Primary external (egress) IP space | `<a.b.c.d/29, e.f.g.h/28>` |
| External DNS authoritative for | `<corp.tld>` |
| Internal DNS resolvers | `<10.0.0.53, 10.0.0.54>` |
| Time servers (NTP) | `<10.0.0.123, time.cloudflare.com>` |
| Admin secondary email | `<admin-recovery-email>` |
| Org phone | `<+E.164-org-phone>` |

---

## Tool Configuration

### SIEM

```
SIEM platform:   <Splunk / Elastic / Microsoft Sentinel / Chronicle>
Console URL:     <https://...>
Search head URL: <https://...>
Indexes / tables:
  - <index=fw>      firewall logs
  - <index=proxy>   web proxy logs
  - <index=dns>     DNS query logs
  - <index=netflow> NetFlow / IPFIX
  - <index=ids>     IDS/IPS alerts
Retention:       <hot 30d / warm 90d / cold 1y>
```

REST entry points:

```
Splunk:   curl -k -u <user>:<pass> https://<sh>:8089/services/search/jobs/...
Elastic:  curl -H "Authorization: ApiKey $ES_API_KEY" https://<es>:9200/_search
Sentinel: az monitor log-analytics query --workspace <ws-id> --analytics-query '<KQL>'
```

### Firewall

```
Primary vendor: <Palo Alto / FortiGate / Cisco Firepower / Check Point>
Console URL:    <https://...>
HA model:       <Active/Active / Active/Passive>
Log export:     <syslog → SIEM / vendor cloud>
```

Per-vendor admin tooling:

```
PAN:        pan-python (panxapi) against Panorama; REST API key in vault
FortiGate:  FortiGate REST; api-user token in vault
Firepower:  fmcapi / Firepower Management Center REST
```

### Web proxy / Secure Web Gateway

```
Vendor:        <Zscaler / Netskope / Forcepoint / Squid>
Log feed:      <NSS / cloud log streaming → SIEM>
Policy author: <admin group>
```

### DNS

```
Resolver fleet:        <Infoblox / BIND / Windows DNS / Pi-hole-style>
RPZ feeds:             <Spamhaus / Quad9 / custom>
Passive-DNS retention: <days>
DNS sinkhole IP:       <10.x.x.x>
```

### Packet / beacon / forensic tooling

```
Zeek (Corelight):  <sensor list, retention window>
RITA:              <DB host, refresh cadence>
tshark / Wireshark: <on-demand, on jump-host>
```

### Standalone CLIs

```
dig:       <path-to-dig>
whois:     <path-to-whois>
```

---

## Console + API scope reality

The investigator role is authorized for the following permissions per
console. **The operator must verify each row against the live console
after `tenant init`.** Drift here is the most common cause of denied
queries mid-incident.

| Console | Role | Status | Notes |
|---|---|---|---|
| `<SIEM>` | `<ir-read-role>` | `<verified ✅ / not assigned ❌>` | Read-only across all in-scope indexes |
| `<Firewall (PAN)>` | `Superreader` | `<verified ✅ / not assigned ❌>` | Read-only Panorama + every managed firewall |
| `<Firewall (Forti)>` | `<read-only profile>` | `<verified ✅ / not assigned ❌>` | Per-VDOM read |
| `<Proxy (Zscaler)>` | `<viewer + analyst>` | `<verified ✅ / not assigned ❌>` | Logs + policy read; no policy edit |
| `<DNS (Infoblox)>` | `<read-only>` | `<verified ✅ / not assigned ❌>` | DNS + IPAM read; RPZ read |

Write actions (firewall rule edit, proxy policy push, DNS RPZ add) are
intentionally **not** granted — IR here is read-only by default.
Out-of-band admin access via management network is documented in the
on-call escalation runbook.

---

## Critical Identities

### SIEM administrators

| Login | Name | Role | Notes |
|---|---|---|---|
| `<siem-admin-1>` | `<Full Name>` | `Admin` | MFA enforced |
| `<siem-admin-2>` | `<Full Name>` | `Power User` | MFA enforced |

### Firewall administrators (per vendor)

| Vendor | Login | Name | Role | Notes |
|---|---|---|---|---|
| PAN | `<pan-admin-1>` | `<Full Name>` | `superuser` | MFA enforced; jump-host required |
| FortiGate | `<forti-admin-1>` | `<Full Name>` | `super_admin` | MFA enforced; OOB only |

### Proxy administrators

| Login | Name | Role | Notes |
|---|---|---|---|
| `<proxy-admin-1>` | `<Full Name>` | `<Super Admin>` | MFA enforced |

### DNS RPZ owner

| Login | Name | Role | Notes |
|---|---|---|---|
| `<dns-owner-1>` | `<Full Name>` | `RPZ Author` | Adds / removes blocklist entries; on-call rotation |

### Break-glass / out-of-band admin

| Mechanism | Storage location | Last rotation |
|---|---|---|
| Management-network jump host root | `<password manager / safe / vault reference>` | `<YYYY-MM-DD>` |
| Console-port physical access | `<datacenter procedure ref>` | `<YYYY-MM-DD>` |

---

## Network identity mapping (asset → user pivot)

Network alerts carry no user identity. To attribute an internal IP to
a user, pivot via:

| Mapping source | Lookup form | Notes |
|---|---|---|
| DHCP lease history | `<DHCP server / IPAM>` | Retention `<days>` |
| 802.1X RADIUS | `<RADIUS server>` | Authoritative for wired/wireless EAP sessions |
| VPN session log | `<VPN concentrator>` | Authoritative for remote-access sessions |
| Identity-aware proxy | `<Zscaler ZIA / Cloudflare Access>` | Identity-platform tied (see `<customer>-<idp>.md`) |

Time-bound the lookup to the alert's `time_window_utc` — DHCP leases
reuse, and an IP at 14:00 UTC may belong to a different user at
14:05 UTC.

---

## MFA Posture

| Field | Value |
|---|---|
| SIEM console MFA enforced? | `<yes / no>` |
| Firewall admin MFA enforced (per vendor)? | `<yes / no, per row>` |
| Proxy admin MFA enforced? | `<yes / no>` |
| Out-of-band admin requires hardware MFA? | `<yes / no>` |
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
- `actor` — explicit src IP, internal hostname, or NetFlow exporter ID.
  CIDR-ranges (`10.0.0.0/24`) are NOT mechanical-eligible — they are
  by definition wildcards.
- `action_verb` — IDS signature name, firewall threat ID, proxy
  category violation, RITA beacon-tag, DNS-FW alert exactly.
- `time_pattern` — concrete schedule.
- `source_signal` — SIEM rule + ID, IDS signature + revision, RPZ
  feed name + rule.
- `mechanical` — `true` when L1 may auto-close.
- `rationale` — one sentence + citation of the L3 finding that promoted
  the entry.

Example rows — **replace with real entries before use; remove or comment
out the examples once real entries exist**:

| pattern_id | actor | action_verb | time_pattern | source_signal | mechanical | rationale |
|---|---|---|---|---|---|---|
| `<documented-outbound-jobs>` | `<10.0.5.42>` (build server) | `Outbound TLS to github.com:443` | `every 10 minutes (CI pull cadence)` | `pan-threat / Suspicious outbound / rule-id <rid>` | `true` | `CI build server polling GitHub; promoted from finding <slug>` |
| `<internal-ja3-baseline>` | `<10.0.10.0/24>` (engineering subnet) | `JA3 hash <abc...> not seen before` | `any` | `zeek / JA3-anomaly / rule-id <rid>` | `false` | `Engineering machines run many TLS-stack tools (curl variants, language SDKs); L2 verifies destination, not auto-close` |
| `<dns-high-entropy-allowlist>` | `<*.cloudfront.net, *.akamaihd.net, *.cdn.cloudflare.net>` | `High-entropy domain` | `any` | `dns-fw / DGA-like / rule-id <rid>` | `true` | `Known CDN naming patterns trigger DGA heuristic; promoted from finding <slug>` |
| `<partner-vpn-egress>` | `<198.51.100.42>` (partner VPN concentrator) | `Outbound to suspicious geo` | `business hours, weekdays only` | `fw-threat / Suspicious geo / rule-id <rid>` | `true` | `Partner VPN tunnel; geo destination is the partner's HQ; promoted from finding <slug>` |
| `<siem-query-baseline>` | `<siem-search-head IP>` | `Suspicious outbound API call` | `continuous (data export jobs)` | `proxy / API endpoint access / rule-id <rid>` | `false` | `SIEM data-export jobs hit external SaaS APIs; L2 verifies destination matches export config, not auto-close` |

**Promotion rule** — only an L3 verifier who has confirmed
`false_positive` with cited evidence may seed a new mechanical row. New
`mechanical: false` rows can be added by the IR lead with a one-paragraph
rationale. Record changes in the **Tenant change log reference** below.

---

## Common IR pull commands for this tenant

> Placeholders only — replace before running. UTC timestamps; look-back is
> 30 days from earliest plausible trigger (`agent/rules/triage.md` rule 6).

### Splunk (firewall traffic for a host, 30-day window)

```spl
index=fw earliest=-30d@d latest=now src=<ip>
| stats count by dest_ip, dest_port, app
| sort -count
```

### Microsoft Sentinel (KQL — equivalent against `CommonSecurityLog`)

```kql
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where SourceIP == "<ip>"
| summarize count() by DestinationIP, DestinationPort, ApplicationProtocol
| order by count_ desc
```

### Beacon hunting with RITA

```bash
# Show beacons with score >= 0.8 from a Zeek DB
rita show-beacons <zeek-db-name> -H | awk '$3 >= 0.8'
```

### DNS pivot (suspected DGA / sinkhole check)

```bash
dig @<resolver> +trace <suspected-dga.example>
whois <suspected-dga.example>
```

### Packet slice (post-Zeek, on jump-host)

```bash
tshark -r <capture.pcap> -Y "ip.addr==<ip> and tcp.port==443" -T fields \
  -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e tls.handshake.extensions_server_name
```

When the actor is an internal IP, always pivot to the identity-platform
tenant ref (DHCP/802.1X/VPN mapping above) before attributing the
behavior to a user.

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
| SIEM vendor status | `<https://status.splunk.com / status.elastic.co / Azure status>` | Search lag can mimic missing events |
| Firewall vendor status | `<vendor URL>` | Content / threat-feed pushes generate detection bursts |
| Proxy vendor status | `<vendor URL>` | Category-feed updates re-categorize benign sites |
| ISP / transit status | `<carrier URL>` | Egress path changes look like new exfil patterns |
| Tenant-specific maintenance bulletin | `<internal URL or change ticket project>` | Maintenance windows, RPZ rebuilds, BGP cutovers |

---

## Tenant change log reference

| Source | URL | Notes |
|---|---|---|
| Network change tickets | `<Jira project URL / change ticketing>` | Firewall edits, RPZ edits, BGP changes, VLAN moves |
| Firewall config audit | `<vendor audit log>` | Source of truth for ACL changes |
| Proxy policy audit | `<vendor audit log>` | Source of truth for category / rule edits |
| This file's git history | `git log -- agent/references/tenants/<customer>-network.md` | Tenant ref changes themselves are part of the change log |

---

## Recent red team / authorized testing windows

> **Update this section at engagement start.** Empty or stale entries here
> are how the L3 verifier accidentally promotes a red-team artifact to a
> real finding during the devil's-advocate step.

| Start (UTC) | End (UTC) | Scope | Authorization reference |
|---|---|---|---|
| `<YYYY-MM-DDTHH:MM:SSZ>` | `<YYYY-MM-DDTHH:MM:SSZ>` | `<source IPs / target subnets / techniques>` | `<authorization letter / Jira ticket / RoE doc>` |

If no authorized testing is active during the engagement window, write a
single row with both timestamps set to the engagement start and
`scope: none`.

---

## Out-of-scope artifacts

- **Partner traffic transiting our perimeter** — `<list partner ASNs /
  prefixes the tenant brokers traffic for>`. Metadata only; content
  out of scope.
- **Guest Wi-Fi / segmented networks not in the IR scope** — `<list
  SSIDs / VLANs / IP ranges>`.
- **ISP / transit telemetry** — flow data the carrier holds is not
  ours to pull without legal coordination.
- **Personal devices on BYOD VLANs** — captured by perimeter logs but
  out of scope for endpoint-side follow-up.
- **Tenant secrets** — firewall admin credentials, SIEM tokens, proxy
  API keys, RPZ feed credentials. This file references them by
  *location*; the secrets themselves never enter engagement artifacts.

---

## Previous engagements

| Date | Key | Type | Status |
|---|---|---|---|
| `<YYYY-MM-DD>` | `<engagement-key>` | `<network IR / beacon hunt / DNS exfil / firewall ACL audit>` | `<Complete — benign / Complete — verified / In progress>` |

Engagement artifacts live at `agent/engagements/<key>/` under the install
root.

---

## Template provenance

- Source: `agent/references/tenants/_template-network.md`; modeled on
  `agent/references/tenants/_template-gws.md` for cross-platform parity.
- Alias: `aith blue tenant init --platform network` writes to
  `<customer>-network.md` per `PLATFORM_TO_TENANT_SUFFIX["network"] = "network"`.
- Consumers: `agent/skills/alert-triage/SKILL.md`,
  `agent/agents/alert-triage-specialist.md`,
  `agent/skills/network-threat-hunt/SKILL.md`,
  `agent/skills/alert-fp-verification/SKILL.md`. Keep section names stable.
