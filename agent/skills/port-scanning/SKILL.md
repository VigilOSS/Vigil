---
name: port-scanning
description: Discover open ports, running services, and their versions on a target
origin: Vigil
---

# Port Scanning

> **`vigil assess kali` audit flags:** use `--technique RECON` (port and service enumeration against in-scope hosts is canonical reconnaissance).

## When to Activate

- Initial recon of new target, need to discover services before vuln testing
- Verifying firewall rules, new IP discovered

## Tools

`nmap` (primary), `nc` (quick checks/banner grab)

## Methodology

### 1. Profile selection — pick before invoking nmap

Default `-T4` is *not* safe for shared infrastructure. Pick the profile from the target shape
returned by wafw00f and the engagement scope, not from habit. A follow-up nmap pass at the
cautious-tier profile (CDN-fronted / WAF-protected / rate-limited regulated targets) routinely
surfaces signal that an aggressive `-T4` default misses: TLS SAN expansion (staging / internal
subdomains), rDNS vendor identification (CDN / SaaS edge ownership), per-host WAF tier mapping,
edge-auth identifiers, and dense API-cluster footprints invisible to every other tool. That
depth comes from the rate calibration, not from extra scripts.

| Target shape | nmap timing flags | Notes |
|---|---|---|
| Lab / unrestricted CTF | `-T4` | Default speed, no rate limit. Only safe in dedicated labs. |
| Bug bounty (residential / SMB infra) | `-T3 --max-rate 500 --max-retries 2` | Drop default `-T4`; shared infra is the common case. |
| Cautious tier — CDN-fronted / WAF-protected / regulated | `-T3 --max-rate 200 --max-retries 2 --host-timeout 300s` | Enterprise CDN / WAF fronts. The `--host-timeout` is the trap addressed under "Per-host port-data presence assertion" below. |
| Hardened cautious tier (bot-management / aggressive WAF) | `-T3 --max-rate 100 --max-retries 2 --host-timeout 600s` | Tighter rate, longer per-host budget; bot-management blocks at the edge. |
| Multi-host batch | `-iL <hosts.txt>` + the matching rate profile | The per-batch port-data assertion catches host-timeout failures across hosts. |

When in doubt, run wafw00f first (`agent/references/tools/recon/wafw00f.md` "WAF-tier rate
adjustment table") and pick the profile that matches the WAF tier. The canonical
per-target rate calibration table lives in `agent/operator-core.md` "Recon Dispatch
Resource Policy" — the values in this section pull from that table.

### 2. Quick Initial Scan
```bash
vigil assess kali nmap-scan --target TARGET \
  --ports top-1000 --scripts safe \
  --extra-args "-Pn -T3 --max-rate 200 --max-retries 2 --host-timeout 300s" \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_initial \
  --technique RECON --intent "initial top-1000 + safe scripts at cautious rate (CDN/WAF-fronted)" \
  --probe-kind fingerprint --phase recon --timeout 900
# -Pn: skip host discovery (required when ICMP is blocked by firewall)
```

### 3. Full TCP Scan
```bash
vigil assess kali nmap-scan --target TARGET --ports full \
  --extra-args "-Pn -T3 --max-rate 200" \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_full_tcp \
  --technique RECON --intent "full-port TCP at cautious rate (CDN/WAF-fronted)" \
  --probe-kind fingerprint --phase recon --timeout 1800
# Speed optimization: discover ports first, then deep scan.
# Uses the default -sT (TCP connect) scan — do NOT switch to -sS here: raw SYN
# probes are dropped by Docker's userland NAT and silently return 0-open.
vigil assess kali nmap-scan --target TARGET --ports full \
  --extra-args "-Pn -T3 --min-rate 500" \
  -oA /engagements/$ENGAGEMENT_KEY/scans/ports_only \
  --technique RECON --intent "ports-only sweep before targeted -sV" \
  --probe-kind fingerprint --phase recon --timeout 1800
PORTS=$(grep -oE '[0-9]+/open' /engagements/$ENGAGEMENT_KEY/scans/ports_only.gnmap | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
vigil assess kali nmap-scan --target TARGET --ports "$PORTS" --scan-type sV \
  --extra-args "-Pn -sC -T3" \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_targeted \
  --technique RECON --intent "service detection on discovered open ports" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

### 4. Multi-host batch (`-iL`)

For multi-host scope, run nmap with a host list (one host per line) and the matching rate
profile. The per-host port-data assertion below catches host-timeout failures across the
batch:

```bash
vigil assess kali nmap-scan --target placeholder \
  -iL /engagements/$ENGAGEMENT_KEY/scans/in_scope_hosts.txt \
  --ports top-1000 --scripts safe \
  --extra-args "-Pn -T3 --max-rate 200 --max-retries 2 --host-timeout 300s" \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_batch \
  --technique RECON --intent "multi-host nmap batch at cautious rate (CDN/WAF-fronted)" \
  --probe-kind fingerprint --phase recon --timeout 3600
```

Run each sweep synchronously — one blocking `vigil assess kali <verb> … --timeout N` at a time. Specialists do NOT background target traffic or use `vigil assess kali job start` (operator-only; see `agent/shared-constraints.md` §2); a long sweep is handled by a generous `--timeout`. Never use broad `pkill`/`killall` (e.g. `pkill -f nmap`) — it stomps sibling agents' processes in the shared runtime. See
`agent/references/runtime-guides/kali-cli.md` "Process cleanup discipline" for the full
pattern.

### 5. Process consolidation

Use `-iL hosts.txt` rather than N parallel `nmap host` invocations. Nmap's parallelism is internal: `--max-parallelism`, `--min-parallelism`, and `-T<n>` tune host-and-port concurrency without spawning extra processes. Per-host loops amplify CPU without proportional speedup and create N audit rows that compete for the same network budget.

Split-by-profile parallel sweeps are allowed up to the runtime-tier cap (Standard 2 / Heavy 4 / Comfortable 8 — read `vigil runtime resources`) when two disjoint scan profiles run against the same host list. If you need to split work across specialists for context-window reasons, split the host list into N files and run one `-iL` per specialist — never N per-host invocations.

The trait-row table that drives the cap lives in `agent/references/recon/rate-calibration.md`; tier-pick prose is in `agent/references/runtime-guides/dispatch-resource-policy.md` "Recon Dispatch Resource Policy".

### 6. Per-host port-data presence assertion (mandatory before declaring batch complete)

The naive "did it finish?" gates lie. `grep -c '</nmaprun>' *.xml` shows clean closure even
when host-timeout fired mid-flight with zero port data captured — XML closure means the
nmap binary exited normally, not that every host scan finished. `grep -c "Nmap scan
report for $host"` returns 1 even when the host scan started and timed out before any
port data was captured.

The actual coverage gate is **per-host port-data presence**. Run both layers before
declaring a batch complete:

```bash
# Layer 1 — text output (port-data presence)
for f in /engagements/$ENGAGEMENT_KEY/scans/*.nmap; do
  hostname=$(basename "$f" .nmap)
  open_ports=$(grep -cE '^[0-9]+/(tcp|udp).*open' "$f")
  finished=$(grep -c "Nmap done" "$f")
  if [ "$open_ports" -eq 0 ] && [ "$finished" -eq 0 ]; then
    echo "GAP: $hostname (scan started but timed out — port data empty)"
  fi
done

# Layer 2 — XML host-status (xmllint XPath)
for f in /engagements/$ENGAGEMENT_KEY/scans/*.xml; do
  port_bytes=$(xmllint --xpath '//host[@status="up"]/ports' "$f" 2>/dev/null | wc -c)
  [ "$port_bytes" -eq 0 ] && echo "GAP: $f — host up but zero port data (host-timeout fired)"
done
```

Hosts that the assertion flags as gaps fall into two categories:

1. **Local rate / WAF intercept** — re-queue the host at the slower retry profile:
   `-T2 --host-timeout 1500-1800s` (or `-sT` if upstream filtering rejects SYN scans):
   ```bash
   vigil assess kali nmap-scan --target $hostname --ports top-1000 \
     --extra-args "-Pn -sT -T2 --max-retries 3 --host-timeout 1800s" \
     -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_retry_$hostname \
     --technique RECON --intent "slow retry on host-timeout flagged by port-data assertion" \
     --probe-kind fingerprint --phase recon --timeout 2400
   ```
2. **Upstream filtering kill-evidence** — if the slower retry STILL hits host-timeout with
   zero port data, that's defensible kill-evidence. Record an intel-note documenting the
   upstream filtering before moving on. When this pattern recurs across multiple origin
   hosts in the same scope, each one needs its own intel-note so the report can show the
   filtered surface explicitly:

   ```bash
   cat > /tmp/intel-upstream-filter.json <<EOF
   {
     "title": "Upstream filtering on www.secure.example.gov — nmap port-data empty after slow retry",
     "body": "nmap -T2 -sT --host-timeout 1800s returned 0 open ports / 0 reported. Layer 2 xmllint port-data assertion confirmed host marked up with empty <ports> element. This is upstream filtering (CDN edge or load balancer ACL), not local rate limit. Documented as kill-evidence for Phase 1 coverage gate.",
     "category": "infrastructure"
   }
   EOF
   vigil assess intel record note /tmp/intel-upstream-filter.json
   ```

Do NOT declare a batch complete until every flagged host either passes the assertion on
retry or has a recorded kill-evidence intel-note. The recon-specialist's pre-output
self-check fails loudly when this gate is skipped.

### 7. TLS SAN extraction

The TLS-grab side of nmap captures certificate metadata that surfaces adjacent hosts no
other tool sees. Extract SAN hosts after the scan completes:

```bash
grep -oE 'DNS:[^ ,]+' /engagements/$ENGAGEMENT_KEY/scans/nmap_initial.nmap | \
  sed 's/DNS://' | sort -u > /engagements/$ENGAGEMENT_KEY/scans/nmap_san_hosts.txt
```

Feed `nmap_san_hosts.txt` back into subdomain-enumeration / httpx — TLS SAN extraction
commonly surfaces staging / internal subdomains that don't appear in passive sources.
Feed these back through dnsx for live-host confirmation.

### 7a. Multi-time DNS resolution (split-VIP detection)

Single-resolution DNS misses split-VIP load-balanced clusters; the resolver's first
answer for a load-balanced name represents one path through the cluster, not the
cluster as a whole. The cross-host TLS / SAN / vhost methodology in
`agent/skills/web-recon/SKILL.md` "TLS / SAN / vhost cross-host" carries the
load-bearing recipe — port-scanning runs the same probe before declaring the host
list complete, because each unique IP discovered may serve a different banner /
cert / open-port set on subsequent nmap runs.

```bash
vigil assess kali exec --technique RECON --intent "multi-time DNS resolution — detect split-VIP load-balanced clusters" \
  --probe-kind fingerprint --phase recon --timeout 600 -- bash -c '
  for i in 1 2 3 4 5; do dig +short TARGET_HOST A; sleep 60; done | sort -u
'
```

Five samples spaced 60s apart land close to most rotation TTLs (30-300s). Two or
more unique IPs across the sample set indicates split-VIP — capture each IP's nmap
banner separately (`nmap -Pn <ip> -p 443 --script=ssl-cert`) because cluster IPs
sometimes carry different certs and different open-port sets. Full mechanics
including the cross-host SAN collision counter live in
`agent/references/tools/recon/openssl-sans.md`.

### 8. rDNS extraction

Reverse DNS reveals shared / CDN-fronted infrastructure ownership. Extract from the nmap
greppable output:

```bash
# rDNS from nmap -oG output (gnmap)
grep -oE 'Host: [0-9.]+ \([^)]+\)' /engagements/$ENGAGEMENT_KEY/scans/nmap_initial.gnmap \
  | sed -E 's/Host: ([0-9.]+) \(([^)]+)\)/\1\t\2/' \
  | sort -u > /engagements/$ENGAGEMENT_KEY/scans/nmap_rdns.tsv

# Standalone rDNS pass for hosts that need cleaner output
vigil assess kali exec --technique RECON --intent "rDNS sweep for vendor identification" \
  --probe-kind fingerprint --phase recon --timeout 300 -- \
  bash -c 'while read ip; do printf "%s\t" "$ip"; dig -x "$ip" +short; done \
    < /engagements/$ENGAGEMENT_KEY/scans/in_scope_ips.txt \
    > /engagements/$ENGAGEMENT_KEY/scans/rdns.tsv'
```

rDNS that resolves to a third-party vendor or CDN domain (CDN provider domains,
notification SaaS, edge platforms, etc.) recasts the host as a CDN/SaaS edge rather
than a primary target. The testing approach changes once you know — vendor edges
typically have their own disclosure scope, and origin-server vulns probed through
the edge often produce false positives.

### 9. Service Detection
```bash
vigil assess kali nmap-scan --target TARGET --ports "PORT1,PORT2" --scan-type sV \
  --extra-args "--version-intensity 5" \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_versions \
  --technique RECON --intent "deep version detection on suspect ports" \
  --probe-kind fingerprint --phase recon --timeout 600

# Banner grab via vigil assess kali exec (audit-pipeline-respecting)
vigil assess kali exec --technique RECON --intent "nc banner grab" \
  --probe-kind fingerprint --phase recon --timeout 60 -- \
  bash -c 'printf "\n" | nc -nv TARGET PORT 2>&1 | head -5'
```

### 10. Script Scanning
```bash
vigil assess kali nmap-scan --target TARGET --scripts vuln \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_vuln \
  --technique RECON --intent "vuln NSE category" \
  --probe-kind payload --phase recon --timeout 1800
vigil assess kali nmap-scan --target TARGET --scripts http-enum --ports 80,443 \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_http_enum \
  --technique RECON --intent "http-enum NSE on web ports" \
  --probe-kind fingerprint --phase recon --timeout 600
vigil assess kali nmap-scan --target TARGET --scripts smb-enum-shares,smb-enum-users --ports 445 \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_smb_enum \
  --technique RECON --intent "SMB enumeration NSE" \
  --probe-kind fingerprint --phase recon --timeout 600
vigil assess kali nmap-scan --target TARGET --scripts ftp-anon --ports 21 \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_ftp_anon \
  --technique RECON --intent "FTP anonymous-login check" \
  --probe-kind fingerprint --phase recon --timeout 300
vigil assess kali nmap-scan --target TARGET --scripts ssh-auth-methods --ports 22 \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_ssh \
  --technique RECON --intent "SSH auth-methods enumeration" \
  --probe-kind fingerprint --phase recon --timeout 300
```

### 11. UDP Scan
```bash
vigil assess kali nmap-scan --target TARGET --scan-type sU --ports top-100 \
  --extra-args "-T3 --max-retries 2" \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_udp \
  --technique RECON --intent "top-100 UDP sweep" \
  --probe-kind fingerprint --phase recon --timeout 1800
vigil assess kali nmap-scan --target TARGET --ports 53,67,68,69,123,161,162,500,514,1900 --scan-type sU \
  --extra-args "-T3" \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_udp_targeted \
  --technique RECON --intent "targeted UDP service ports" \
  --probe-kind fingerprint --phase recon --timeout 900
```

### 12. Firewall Evasion (when standard scans blocked)
```bash
# Fragment packets / decoy / slow / source-port — pass via --extra-args
vigil assess kali nmap-scan --target TARGET --ports PORT \
  --extra-args "-f -sV" \
  --technique RECON --intent "fragmented packets evasion" \
  --probe-kind fingerprint --phase recon --timeout 600 \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_evasion_fragment
vigil assess kali nmap-scan --target TARGET --ports PORT \
  --extra-args "-D RND:5 -sV" \
  --technique RECON --intent "decoy scan evasion" \
  --probe-kind fingerprint --phase recon --timeout 600 \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_evasion_decoy
vigil assess kali nmap-scan --target TARGET --ports PORT \
  --extra-args "--source-port 53 -sV" \
  --technique RECON --intent "source-port 53 evasion" \
  --probe-kind fingerprint --phase recon --timeout 600 \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_evasion_srcport
```

### 13. Output Parsing
```bash
grep -oE '[0-9]+/open/tcp//[^ ]+' /engagements/$ENGAGEMENT_KEY/scans/nmap_initial.gnmap
grep "open" /engagements/$ENGAGEMENT_KEY/scans/nmap_targeted.txt | grep -v "filtered"
```

## Common Port Reference

| Port | Service | Notes |
|------|---------|-------|
| 21 | FTP | Anonymous login |
| 22 | SSH | Version, auth methods |
| 25 | SMTP | Open relay, user enum |
| 53 | DNS | Zone transfer |
| 80/443 | HTTP/S | Web app testing |
| 139/445 | SMB | Shares, null sessions |
| 1433 | MSSQL | Default creds, xp_cmdshell |
| 3306 | MySQL | Remote auth, UDF |
| 5432 | PostgreSQL | COPY TO PROGRAM |
| 3389 | RDP | Brute-force, BlueKeep |
| 5900 | VNC | Auth bypass, no-password |
| 6379 | Redis | Often unauthenticated |
| 8080 | HTTP alt | Management panels |
| 27017 | MongoDB | Often unauthenticated |

## What to Record

- Open ports with service names and versions
- OS detection results if available
- Notable NSE script output (vulns, default creds, misconfigs)
- TLS SAN hosts extracted from the nmap output (record as recon intel for downstream re-feed)
- rDNS vendor identification for shared / CDN-fronted hosts
- Filtered ports worth retesting after gaining access
- Per-host port-data assertion result — every host either passes or has a recorded
  kill-evidence intel-note
- Non-web services to hand off for deeper testing

## Output Contract

The skill produces these structured sections in the recon-specialist's return payload.
Backend writes (`finding record`, `intel record`, `record-surface`) are the durable
record; this contract names what each markdown section should hold so downstream
specialists can parse the output consistently.

| Section | Holds |
|---|---|
| `#### Summary` | One-paragraph headline: hosts scanned, profile chosen, open-port total, port-data-assertion pass/fail count. |
| `#### Open Services` | Per-host table of `host : port/proto : service : version : NSE notes`. The canonical port-and-service inventory feeding `record-surface` for non-web services and dispatch decisions for follow-on testing. |
| `#### Findings` | Decisive findings already proved by the scan (default-creds via NSE, anonymous FTP, well-known-vuln NSE hit). Each must also be recorded via `vigil assess finding record`. |
| `#### Surface Candidates` | Non-web services that warrant deeper triage (Redis, Elasticsearch, Docker API, MongoDB, exposed RDP, etc.) — each surfaced via `vigil assess record-surface`. |
| `#### Intelligence` | TLS SAN hosts surfaced from `ssl-cert` NSE, rDNS vendor identification for shared / CDN-fronted IPs, OS detection output, banner anomalies. Each row landed via `vigil assess intel record <type>`. |
| `#### Coverage Gaps` | Every host the per-host port-data assertion flagged as a gap and the disposition (re-queued at slower retry profile, recorded as upstream-filtering kill-evidence, deferred). UDP coverage gaps. Hosts that hit the host-timeout. The operator uses this section to decide whether to re-dispatch a slower retry pass. |

## Extended Resources

- `agent/references/runtime-guides/dispatch-resource-policy.md` "Recon Dispatch Resource Policy" — canonical per-target rate calibration table (cautious tier, CDN-fronted, WAF-protected, vendor SaaS, origin)
- `agent/references/tools/recon/nmap.md` — nmap flags, scan types, NSE scripts, output formats, the cautious-tier profile, TLS SAN extraction, rDNS, multi-host `-iL`, the XML-closure trap and the correct port-data presence gate, and the "one process beats N processes" mechanism
