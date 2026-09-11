---
name: network-threat-hunt
description: L2 network-plane threat hunt. SIEM alert triage (Splunk/Elastic/Sentinel), firewall + proxy log parsing (PAN/FortiGate/Zscaler), DNS sinkhole coordination, TI feed matching, beaconing detection (RITA), JA3 TLS fingerprint correlation.
origin: Vigil
---

# Network Threat Hunt (L2)

## When to Activate

- L1 `alert-triage` dispatched with `platform=network` (sub-tags
  `network-siem`, `network-fw`, `network-proxy`) for beaconing, DNS
  tunnel, exfil, JA3 anomaly, lateral movement, or unfamiliar-egress.
- `edr-alert-triage` surfaced C2 traffic and needs the network plane
  scoped — flow records, firewall sessions, proxy URLs — to confirm
  the channel and find peer-hosts sharing it.
- L4 `ir-lead` needs blocklist scoping before a firewall-block
  containment proposal; this skill's closing sequence emits the IOC
  bundle the proposal cites.
- An IOC pivot (destination IP, JA3 hash, DNS domain) from
  `ioc-enrichment` needs internal-host blast-radius before any
  host-level action.

L2 pulls telemetry (SIEM, REST firewall/proxy APIs, Zeek over saved
pcap, RITA). L2 does NOT change device state — firewall commit, DNS
sinkhole, policy push go through `incident-containment` with operator
approval.

## Always-active references

- `agent/rules/triage.md` — disposition vocabulary, severity recompute
  (rule 2), 30-day look-back (rule 6), tenant-ref-first (rule 12),
  MITRE on every finding (rule 11).
- `agent/shared-constraints-blue.md` — read-only by default, artifact
  chain of custody, UTC discipline, dispatch handoff schema.
- `agent/rules/ir-evidence.md` — attribution gate; a destination IP in
  a firewall log is not attributed to an actor until cross-sourced
  with EDR `DeviceLogonEvents` or proxy username.
- Tenant ref in `scope.json:tenant_reference_paths[]` — customer
  "Known benign patterns" register (documented outbound jobs, baseline
  JA3 set, partner VPN egress, DNS allowlist). Missing tenant ref →
  `blocked` handoff (`triage.md` rule 12).

## Operating Rules

**Read-only by default.** SIEM searches, REST pulls, Zeek/RITA runs,
pcap captures — all read-only. No firewall commit, DNS zone edit, or
proxy policy change. Containment actions go through
`incident-containment` with explicit operator approval.

**Chain of custody.** Raw pulls land under `$ENGAGEMENT_DIR/ir/net/`
with predictable names (`<feed>_<src_ip>_<window>.json|csv|pcap`); SHA-
256 every file (`/usr/bin/shasum -a 256 ir/net/* > ir/net/SHA256SUMS.txt`).
Derived analysis (beacon list, JA3 matrix, DNS scores) lands under
`ir/evidence/network/` with the source-file path and exact query
embedded.

**UTC throughout.** Firewall, SIEM, Zeek `ts`, and pcap timestamps are
UTC. Convert to user-local only in narrative for human readers.

**30-day look-back minimum** (`triage.md` rule 6). Beaconing tools tune
to evade short windows. Retention shorter than 30 days is a coverage
gap — document in `coverage_gaps[]`, do NOT silently truncate.

**Tenant ref before alarm.** Every signal cross-checks against the
known-benign register first (documented outbound jobs, baseline JA3
set, partner VPN egress, DNS allowlist). Elimination is by reference,
not intuition.

**Host commands via `vigil assess host-exec`.** Zeek, `dig`, `whois`,
`python3` entropy, RITA — all wrapped so the run is logged, hashed, and
attributable. Direct shell outside the runner is forbidden.

**Stay in scope** (`triage.md` rule 8). Cross-tenant logs and unrelated
IOCs do not enter this engagement's evidence tree.

## Tools

### Backend / orchestration

- `vigil assess resume-brief` — hydrate engagement state first on
  continuation.
- `vigil assess finding record <agent-name> <finding-json> --agent-id <your-agent_id>` — draft or
  update findings.
- `vigil assess host-exec` — wrap every host command (tshark, dig,
  whois, python entropy, RITA, Zeek).
- `vigil assess artifact register` — raw exports/pcap/RITA snapshots as
  `--kind ir_log`; derived analysis (beacon CSV, JA3 matrix, DNS
  scoring) as `--kind ir_evidence`.
- `vigil assess artifact mark-scratch` — transient notes under
  `notes/scratch/`.
- `vigil assess log` — activity row with `--metadata-inline` carrying
  network fields (see Activity Log Convention).
- `vigil assess agent handoff --from-json <path>` — close dispatch.

### SIEMs

| Platform | Access |
|---|---|
| Splunk | `services/search/jobs/export?output_mode=json&search=<spl>` via `curl` (Bearer from `splunk login`), or `splunk` CLI locally. Use `search/jobs` (POST) + `results` for long-running, `export` for streaming. |
| Elastic / ECS | `curl` `<es>/_search` with Lucene or KQL (`logs-*`, `network-*`). ECS fields: `source.ip`, `destination.ip`, `network.transport`, `tls.client.ja3`, `dns.question.name`. Auth via API key or basic. |
| Microsoft Sentinel | KQL via Log Analytics REST `api.loganalytics.io/v1/workspaces/<id>/query`. Tables: `CommonSecurityLog`, `DnsEvents`, `SecurityEvent`, `OfficeActivity`, `AzureDiagnostics`. Bearer via `az account get-access-token --resource=https://api.loganalytics.io`. |

### Firewalls / proxies

| Vendor | Access |
|---|---|
| Palo Alto PAN-OS | `pan-python` library (`pan.xapi`, real OSS pkg, `pip install pan-python`), or REST `/api?type=op&cmd=<show log traffic ...>`. API key via `/api?type=keygen`. |
| FortiGate | REST `/api/v2/monitor/log/...` or FortiAnalyzer REST `/jsonrpc`. Vendor CLI is sparse — prefer REST. |
| Zscaler | NSS feed (syslog forwarder) or REST `nss-feeds`. Verify per-tenant whether the SaaS API is wired up; in many tenants only NSS is. Use `curl` against REST. |

### Beaconing, packet, DNS, threat intel

- `rita` (Active Countermeasures, real OSS) — `rita import <zeek-log-dir>`,
  `rita show-beacons <db>`, `rita show-long-connections <db>`.
- `zeek` over pcap → `conn.log`, `dns.log`, `ssl.log`, `http.log`;
  `zeek-cut` extracts named fields.
- `tshark` for pcap slicing and JA3 extraction
  (`tshark -r <pcap> -Y "tls.handshake.type==1" -T fields -e tls.handshake.ja3`).
- `dig` / `whois` for DNS resolution and domain age; `python3` for
  Shannon entropy and inter-arrival CV.
- TI verification (MISP, OTX, VT) — chain through
  `agent/skills/ioc-enrichment/SKILL.md`, do not reimplement here.

## Methodology

Six steps. Each names its **purpose**, the **evidence** it produces,
and the **false-positive class** it must eliminate.

### Step 1 — Define the network window and evidence universe

**Purpose.** Establish what telemetry is available and over what
window before any analytic. Skipping this step makes downstream queries
either hit the wrong index or silently miss data outside retention.

**Actions.**

- Extend the L1 handoff's `time_window_utc` backward 30 days
  (`triage.md` rule 6). Store as `[T-30d, trigger_end]` in
  `details.network_window_utc`.
- For each implicated `src_ip`/`src_subnet`, dump firewall + proxy
  slice for that window via SIEM. Example SPL:

  ```spl
  index=firewall src_ip=10.42.0.18 earliest=-30d@d
  | fields _time, src_ip, dest_ip, dest_port, transport, bytes_out, bytes_in, app, user
  | outputlookup append=true network_window_10.42.0.18.csv
  ```

  Run through `vigil assess host-exec`; redirect result to
  `$ENGAGEMENT_DIR/ir/net/fw_<src_ip>_<window>.csv` and register it.
- SIEM is authority when no pcap exists; dump pcap from Arkime/Moloch/
  full-packet tap for forensic confirmation when available.

**Evidence.** `fw_<src_ip>_<window>.csv`,
`proxy_<src_ip>_<window>.csv`, optional `pcap_<src_ip>_<window>.pcap`.
Record byte count, flow count, retention window in
`details.coverage`.

**False-positive class.** Retention < 30 days hides long-jitter
beacons. Document in `coverage_gaps[]`, do not pretend the window is
intact.

### Step 2 — Beaconing detection (RITA-style or hand-rolled CV)

**Purpose.** Surface candidate C2 channels by the timing signature
adversaries cannot fully hide.

**Signature.** Coefficient of variation
(`cv = stddev(interval) / mean(interval)`) on inter-arrival times
**< 0.05** AND payload-size CV **< 0.05** is a beacon. RITA's default
score combines both with a threshold around 0.7 (RITA "score") which
maps to roughly the same regime.

**Actions.**

- If Zeek logs are loaded into RITA:

  ```bash
  vigil assess host-exec --tool rita --intent "show human-readable beacon candidates" \
    --technique T1071 --phase investigate --scope-host <customer-slug> \
    -- rita show-beacons <db-name> --human
  # writes top beacons by score; save the full machine-readable form:
  vigil assess host-exec --tool rita --intent "export beacon candidates" \
    --technique T1071 --phase investigate --scope-host <customer-slug> \
    -- rita show-beacons <db-name> --no-header > \
      "$ENGAGEMENT_DIR/ir/evidence/network/beacons_<db>.tsv"
  ```

- Hand-rolled SPL (use when no Zeek pipeline exists):

  ```spl
  index=firewall src_ip=10.42.0.18 earliest=-30d@d
  | sort 0 _time
  | streamstats current=f window=2 last(_time) as prev_time by src_ip, dest_ip, dest_port
  | eval interval = _time - prev_time
  | stats avg(interval) as mean_iat stdev(interval) as sd_iat
          avg(bytes_out) as mean_bo stdev(bytes_out) as sd_bo
          count as n by src_ip, dest_ip, dest_port
  | eval cv_iat = sd_iat / mean_iat, cv_bo = sd_bo / mean_bo
  | where n > 30 AND cv_iat < 0.05 AND cv_bo < 0.05
  | sort cv_iat
  ```

- Sentinel KQL equivalent uses `CommonSecurityLog` with `prev()` over
  `(SourceIP, DestinationIP, DestinationPort)` to compute `iat`, then
  `summarize` with the same `cv_iat < 0.05 and cv_bo < 0.05 and n > 30`
  filter.

**MITRE.** T1071.001 (Web Protocols), T1071.004 (DNS), T1573 (Encrypted
Channel) when the channel is HTTPS.

**Evidence to register.** Paired `<src_ip, dest_ip, dest_port>` rows
with `cv_iat`, `cv_bo`, `n`, mean interval. Save as
`ir/evidence/network/beacons_<src_ip>.tsv` (`--kind ir_evidence`).

**False-positive class to eliminate.** `documented_outbound_jobs` in the
tenant ref — backup-to-S3 every 5 minutes, update-server pings every 60
seconds, monitoring agents posting metrics on a fixed cadence. These
produce textbook beacons. Eliminate by matching the
`<src_ip, dest_fqdn|dest_ip, dest_port, cadence_seconds>` quadruple
against the register entry; partial match (e.g., right destination,
wrong cadence) escalates rather than auto-closes.

### Step 3 — DNS analysis (entropy, TXT exfil, sinkhole coordination)

**Purpose.** Identify DNS-based C2 (DGA, low-and-slow tunnels) and
exfiltration via TXT records.

**Three checks, run in order.**

1. **Shannon entropy on FQDN labels** — > 3.5 bits/char on the
   leftmost label is a DGA signature.

   ```bash
vigil assess host-exec --tool python3 --intent "score DNS label entropy" \
  --technique T1568.002 --phase investigate --scope-host <customer-slug> -- python3 - <<'PY'
   import math, collections, sys
   for line in sys.stdin:
       fqdn = line.strip().lower()
       label = fqdn.split('.')[0]
       if not label:
           continue
       c = collections.Counter(label)
       L = len(label)
       H = -sum((n/L) * math.log2(n/L) for n in c.values())
       if H > 3.5:
           print(f"{H:.3f}\t{fqdn}")
   PY
   ```

   Pipe Zeek `dns.log` query field in:
   `zeek-cut query < dns.log | python3 entropy.py > high_entropy.tsv`.

2. **TXT-record exfil** — TXT queries to an uncommon parent domain with
   response payloads > 100 chars, sustained over the window. SPL:

   ```spl
   index=dns query_type=TXT
   | eval parent=mvindex(split(query,"."),-2)+"."+mvindex(split(query,"."),-1)
   | stats count(eval(len(answer)>100)) as long_txt count as total by parent
   | where long_txt > 5 AND long_txt/total > 0.3
   ```

3. **Sinkhole coordination check** — before recommending any DNS
   sinkhole, cross-ref the candidate domain against MISP / OTX / VT via
   `agent/skills/ioc-enrichment/SKILL.md`. A sinkhole proposal that
   collides with a sandbox that the corporate EDR vendor is already
   sinkholing produces conflicting telemetry — `incident-containment`
   needs the conflict surfaced in the proposal.

**MITRE.** T1568.002 (DGA), T1071.004 (DNS C2), T1048.003 (Exfil over
Unencrypted/Obfuscated Non-C2 Protocol) when the TXT-exfil pattern
holds, T1572 (Protocol Tunneling) when the DNS channel is carrying a
general-purpose tunnel rather than plain C2 beacons.

**False-positive class to eliminate.**
`dns_high_entropy_allowlist` in the tenant ref — Akamai/AWS service
names that look DGA-like (S3 region routing, CloudFront cache-busted
hostnames), DKIM/DMARC `_dkim`/`_dmarc` selectors, Microsoft 365
autodiscover. Match by registered-domain (eTLD+1) before flagging.

For deeper DNS-tunnel-specific analysis (slow-drip, short-label,
character-set chi-squared), chain to
`agent/skills/dns-tunneling-detection/SKILL.md` rather than duplicating
its tiered methodology here.

### Step 4 — TLS fingerprint correlation (JA3 / JA3S)

**Purpose.** Identify C2 channels whose TLS client fingerprint diverges
from the corporate baseline, including tunnels that wrap themselves in
HTTPS to defeat content inspection.

**Source.** Zeek `ssl.log` (`ja3` field) or Sentinel
`tls.client.ja3`/`tls.server.ja3s` field. If neither is enabled, extract
from saved pcap:

```bash
vigil assess host-exec --tool tshark --intent "extract JA3 client fingerprints" \
  --technique T1573 --phase investigate --scope-host <customer-slug> -- tshark -r capture.pcap \
  -Y "tls.handshake.type==1" \
  -T fields -e ip.src -e ip.dst -e tls.handshake.ja3 \
  > ja3_extract.tsv
```

**Signature.** Uncommon JA3 from an internal host — uncommon relative
to the tenant's `internal_jaX_baseline`, not a global frequency table.
Cross-ref against practitioner-maintained lists on GitHub
(`salesforce/ja3`, `trisulnsm/trisul-scripts`) for known-malicious
matches; the original `ja3er.com` is dead.

**Correlation matrix.** Pivot to `(src_ip × ja3_hash)`; non-baseline
cells with `count > 0` are the hunting set. Save as
`ir/evidence/network/ja3_matrix_<window>.csv`.

**MITRE.** T1573, T1071.001 when JA3 ties to HTTP-layer C2; T1572
(Protocol Tunneling) when the TLS channel is wrapping a tunnel rather
than a direct C2 session.

**False-positive class.** `internal_jaX_baseline` — corp-managed
clients, legacy OpenSSL, Java tooling. Match by hash AND
`client_class` (workstation vs server) — a baseline-server JA3
appearing on a workstation is itself a signal even if the hash is
"known."

### Step 5 — Lateral movement (east-west flow analysis)

**Purpose.** Identify post-compromise lateral movement on RPC, SMB,
RDP, WinRM. A confirmed external C2 without a lateral check leaves the
operator blind to where the adversary went after initial access.

**Actions.**

- East-west SPL for RPC/SMB/RDP/WinRM:

  ```spl
  index=firewall src=10.0.0.0/8 dest=10.0.0.0/8
    dest_port IN (135,445,3389,5985,5986,5722)
  | stats count, values(user) as users,
          earliest(_time) as first, latest(_time) as last
          by src, dest, dest_port
  | where count > 5
  | sort -count
  ```

- Cross-source with EDR `DeviceLogonEvents` (Defender advanced
  hunting) or CrowdStrike `UserLogonAttempt`. Chain to
  `agent/skills/edr-alert-triage/SKILL.md` — this skill records the
  network flow, EDR records the resulting logon
  and the process that initiated it.

**MITRE.** T1021.001 (Remote Desktop), T1021.002 (SMB/Windows Admin
Shares), T1021.006 (WinRM), T1021 (Remote Services) as the parent.

**Evidence to register.** Flow matrix per
`<src_host, dest_host, dest_port>` with first/last timestamps and the
user attribution from the firewall. Cross-source rows live in the EDR
handoff, not this finding — link by `correlation_id`.

**False-positive class to eliminate.** IT admin tooling — jump hosts,
Ansible / SCCM / Intune push, vulnerability scanners (Nessus, Qualys)
whose by-design behavior is to fan out RDP/SMB across the fleet.
Tenant-ref `partner_vpn_egress` covers partner contractors whose
inbound source IPs land inside RFC1918 after IPsec termination.

### Step 6 — Proxy-level URL hunt

**Purpose.** Catch C2 and exfiltration that lives in HTTP/S content —
unusual User-Agents, application/octet-stream POSTs, exfil to
recently-registered domains, downloads from unusual TLDs.

**Actions.**

- Proxy filter for large `application/octet-stream` POSTs:

  ```spl
  index=proxy method=POST content_type="application/octet-stream"
  | where bytes_out > 100000
  | stats sum(bytes_out) as total_out, count by user, dest_host
  | sort -total_out
  ```

- WHOIS age on every destination not in the tenant allowlist —
  `vigil assess host-exec --tool whois --intent "lookup domain age" --technique T1583 --phase investigate --scope-host <customer-slug> -- whois <domain>`
  and extract creation date.
  Domains < 30 days old warrant investigation independent of other
  signal.
- User-Agent anomaly: UAs not in the corporate-image baseline that
  POST to external destinations.
- Unusual TLD: outbound to `.top`, `.xyz`, `.club`, `.work`, `.zip`,
  `.mov`, and other consistently-abused TLDs — combine with WHOIS age,
  never standalone.

**MITRE.** T1071.001 (Web Protocols), T1567 (Exfil Over Web Service),
T1567.002 (Exfil to Cloud Storage) when the destination is a
cloud-storage SaaS the tenant does not use; T1071.002 (File Transfer
Protocols) or T1071.003 (Mail Protocols) when the proxy content is
FTP/SMTP-shaped rather than HTTP(S); T1090 (Proxy) when traffic routes
through a chained or anonymizing proxy the tenant does not operate.

**False-positive class to eliminate.** Legitimate SaaS onboarded
recently — a new vendor app the procurement team approved last week
shows up exactly like a fresh-WHOIS exfil destination. The tenant ref
maintains a `recently_onboarded_saas` list specifically for this.

## Tenant-Ref Known-Benign Register Additions

Mirrored in `_template-network.md`; populate on every engagement.

- `documented_outbound_jobs` — backup-to-S3, update-server pings,
  monitoring-agent metrics, scheduled API egress. Required fields:
  `src_subnet`, `dest_fqdn`, `dest_port`, `cadence_seconds`,
  `mechanical: true|false`.
- `internal_jaX_baseline` — JA3 hashes from corp-managed clients by
  `client_class` (workstation/server/build-agent/mobile), with
  `prevalence` and `last_seen_utc`.
- `dns_high_entropy_allowlist` — legitimate CDN/cloud names by
  registered domain (eTLD+1). Match logic in Step 3 is eTLD+1.
- `partner_vpn_egress` — partner subnets whose east-west-looking
  traffic is partner inbound post-IPsec.
- `siem_query_baseline` — noisy saved searches; do not auto-dispose,
  walk full Step 2/3/4 before any kill.
- `recently_onboarded_saas` — vendor apps onboarded within 60 days
  whose fresh-WHOIS would otherwise pattern-match Step 6 exfil.

## Disposition Heuristics

The L2 disposition feeds the verifier's five-check. Pick from
`triage.md` rule 3 vocabulary only.

- `confirmed` — beaconing signature (Step 2, CV < 0.05) **and**
  unusual JA3 (Step 4, outside baseline) **and** DNS or destination
  flagged by TI feeds (Step 3 / IOC enrichment). All three signals
  independently corroborated.
- `false_positive` — every signal observed lands in a tenant-ref
  known-benign register entry, AND the register entry is
  `mechanical: true`, AND the actor/cadence/destination matches
  exactly (not "approximately").
- `downgraded` — single beaconing signature without payload-size
  anomaly, or unusual JA3 without DNS/TI corroboration. Keep the
  finding open at lower severity; do not close.
- `disputed` — partial signal that needs endpoint corroboration.
  Chain to `agent/skills/edr-alert-triage/SKILL.md` with the
  implicated `src_ip` → `src_host` mapping; record the EDR finding
  slug as a sibling in `details.cross_skill_correlation_ids[]`.

## Activity Log Convention

Every `vigil assess log` call in this skill carries `--metadata-inline`
shaped with the network fields below. The backend FTS indexes these
keys so the verifier can locate evidence without re-reading the raw
exports.

```json
{
  "tier": "L2",
  "platform": "network",
  "sub_platform": "siem|fw|proxy|dns|tls",
  "src_ip": "10.42.0.18",
  "dst_ip_list": ["203.0.113.42", "198.51.100.7"],
  "dst_fqdn_list": ["api.evil.example", "cdn.evil.example"],
  "ja3_hash": "769,4865-4866-...,0-23-65281-10-11-35,29-23-24,0",
  "beacon_cv": 0.027,
  "beacon_n": 412,
  "dns_entropy_max": 4.21,
  "siem_query_id": "<rule-or-saved-search-id>",
  "siem_window_utc": ["2026-04-19T00:00:00Z", "2026-05-19T00:00:00Z"],
  "step_id": "step-2-beacon|step-3-dns|step-4-ja3|step-5-lateral|step-6-proxy",
  "disposition_progress": "candidate|confirmed|eliminated"
}
```

Always use `vigil assess log` (one word verb). A mistyped verb produces
a help banner and no activity row — the operator's audit will show a
silent gap.

## Output Contract — Handoff Template

```json
{
  "agent_id": "<runtime-agent-id from dispatch banner>",
  "agent_role": "network-threat-hunt-specialist",
  "phase": "investigation",
  "handoff_status": "ready",
  "finding_slug": "<from finding record>",
  "skill_completed": "network-threat-hunt",
  "platform": "network",
  "sub_platform": "siem|fw|proxy|dns|tls|mixed",
  "src_ip": "10.42.0.18",
  "dst_ip_list": ["203.0.113.42"],
  "dst_fqdn_list": ["api.evil.example"],
  "ja3_hash_list": ["..."],
  "time_window_utc": ["2026-04-19T00:00:00Z", "2026-05-19T00:00:00Z"],
  "mitre_techniques": ["T1071.001", "T1573", "T1071.004"],
  "severity": "high",
  "confidence": "medium",
  "confidence_rationale": "Three independent network signals; no endpoint corroboration yet.",
  "tenant_ref_paths_consulted": [
    "agent/references/tenants/<customer>-network.md"
  ],
  "tenant_ref_eliminations": [
    {"register": "documented_outbound_jobs", "outcome": "miss"},
    {"register": "internal_jaX_baseline", "outcome": "miss"},
    {"register": "dns_high_entropy_allowlist", "outcome": "miss"}
  ],
  "evidence_refs": ["<artifact-id-fw-csv>", "<artifact-id-beacons-tsv>", "<artifact-id-ja3-matrix>", "<artifact-id-dns-entropy>"],
  "next_specialist": "edr-alert-triage | ioc-enrichment | incident-containment | verifier",
  "next_steps": [
    "Pivot to EDR for process tree on src_host(s) mapped from src_ip",
    "Enrich dst_ip / dst_fqdn / ja3_hash via ioc-enrichment",
    "If verified, draft firewall-block proposal via incident-containment"
  ],
  "coverage_gaps": ["Firewall retention only 14d — true T-30 window unavailable"],
  "cross_platform_correlation_notes": "EDR sibling finding slug: <slug>",
  "rationale": "<paragraph: why this disposition, what verifier checks first, what operator authorizes>"
}
```

## Closing Sequence

1. **Register raw exports, RITA snapshots, pcap** as `--kind ir_log`:

   ```bash
   for f in "$ENGAGEMENT_DIR/ir/net/"*.{csv,json,pcap}; do
     [ -f "$f" ] || continue
     vigil assess artifact register "$f" \
       --kind ir_log --finding <slug> --agent-id <runtime-agent-id>
   done
   ```

2. **Register derived evidence** (beacon list, JA3 matrix, DNS scores,
   lateral flow matrix) as `--kind ir_evidence` against
   `$ENGAGEMENT_DIR/ir/evidence/network/`.

3. **Mark transient notes as scratch:**
   `vigil assess artifact mark-scratch --under "$ENGAGEMENT_DIR/notes/scratch/"`.

4. **Record the activity entry** (verb is `log`, one word):

   ```bash
   vigil assess log <runtime-agent-id> \
     "network-handoff" \
     "Ran 6-step network hunt: window, beacon, DNS, JA3, lateral, proxy" \
     "Handoff to <next_specialist>" \
     --actor-kind agent \
     --metadata-file /tmp/network_metadata.json
   ```

5. **Emit the handoff JSON:**
   `vigil assess agent handoff --from-json /tmp/network_handoff.json`.

## Common Failure Modes

- **Beacon CV threshold too tight.** `cv < 0.05` misses jittered
  beacons randomizing intervals ±20%. Second-pass at `cv < 0.20`
  filtered to non-baseline destinations before concluding "no beacon."
- **Trusting JA3 hash alone.** Adversaries rotate JA3 by swapping TLS
  libraries. A JA3 finding stands only when corroborated by Step 2 or
  Step 3 — pivot, do not anchor.
- **DNS entropy threshold too coarse.** > 3.5 catches obvious DGA but
  misses deliberate-pattern C2 (`api1.example.com`, `api2.example.com`)
  where each label is low-entropy but parent-domain cardinality is the
  signal. Cross with uniqueness ratio from `dns-tunneling-detection`.
- **Pulling only outbound when inbound shows the lateral hop.** Step 5
  is mandatory even when Step 2 returned a clean outbound finding.
- **Treating `documented_outbound_jobs` as immutable.** Adversaries
  piggyback on the schedule — match all four fields
  (`src_subnet`, `dest_fqdn|dest_ip`, `dest_port`, `cadence_seconds`),
  not just cadence + source.
- **Skipping `host-exec` for "trivial" commands.** `dig`/`whois`
  outside `vigil assess host-exec` produces no activity row and no
  hash — the verifier cannot reproduce it.
- **Mistyped activity verb.** The verb is `vigil assess log`. Any other
  shape returns a help banner and writes nothing.

## Reference Block

- `agent/skills/alert-triage/SKILL.md` — L1 dispatch producer.
- `agent/skills/edr-alert-triage/SKILL.md` — origin-host pivot; use when
  Step 5 needs endpoint corroboration.
- `agent/skills/dns-tunneling-detection/SKILL.md` — deeper DNS-tunnel
  analysis (slow-drip, short-label, charset chi-squared) for Step 3
  candidates.
- `agent/skills/ioc-enrichment/SKILL.md` — IOC verification for Step 3
  sinkhole coordination and Step 6 destination enrichment.
- `agent/skills/incident-containment/SKILL.md` — firewall block, DNS
  sinkhole, proxy-policy proposals; cites this skill's IOC bundle.
- `agent/rules/triage.md` and `agent/shared-constraints-blue.md` —
  disposition vocabulary, severity, look-back, handoff schema.
- RITA: https://github.com/activecm/rita
- Sentinel KQL: https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/
- Elastic ECS: https://www.elastic.co/guide/en/ecs/current/index.html
- pan-python: https://github.com/kevinsteves/pan-python
- Zeek: https://docs.zeek.org/en/master/script-reference/log-files.html
