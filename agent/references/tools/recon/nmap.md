# nmap

**Purpose:** Port/service discovery and enumeration
For live engagement targets, run Nmap via `aith assess kali nmap-scan` (typed verb, audit-flag-aware).
Run `aith assess kali nmap-scan --help` for the live flag set, or `aith assess contract kali nmap-scan` for the canonical schema and example payload.

## Discovery Scans

Run all discovery scans via `aith assess kali nmap-scan` — the typed verb passes audit flags and writes the coverage row. Pass the required audit flags (`--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout`) per `shared-constraints.md §2`. See `agent/skills/kali-exec/SKILL.md` "Examples per verb" for complete invocation profiles.

Flag reference (used inside the wrapper):

**Quick (with host discovery skip):** `--flags "-sV -sC -Pn -T4"`
**Full port scan:** `--flags "-sV -sC -Pn -T4 -p-"`
**Top 1000 ports (default):** `--flags "-sV -sC -Pn"`
**Specific ports:** `--ports 80,443,8080,8443` (typed flag) or `--flags "-p 80,443,8080,8443"`
**UDP top ports:** `--flags "-sU --top-ports 50 -Pn"`

`-Pn` is required when ICMP is blocked by firewall (common in lab/engagement environments).

## Profile selection — pick before running, not after the timeout fires

Default `-T4` is *not* the right choice for shared infrastructure. Pick the timing flags
from the WAF tier and the engagement scope. `agent/skills/port-scanning/SKILL.md` carries
the full table; the load-bearing entries:

- **Lab / unrestricted CTF** → `-T4`. Default speed, no rate cap.
- **Bug bounty (residential / SMB infra)** → `-T3 --max-rate 500 --max-retries 2`. Drop
  default `-T4`; shared infra is the common case.
- **Cautious tier — CDN-fronted / WAF-protected / regulated** → `-T3 --max-rate 200
  --max-retries 2 --host-timeout 300s`. Enterprise CDN / WAF fronts. The `--host-timeout`
  is the trap documented under "XML-closure trap" below.
- **Hardened cautious tier (bot-management / aggressive WAF)** → `-T3 --max-rate 100
  --max-retries 2 --host-timeout 600s`. Tighter rate, longer per-host budget;
  bot-management blocks at the edge.
- **Multi-host batch** → `-iL <hosts.txt>` with the matching rate profile. Pair with the
  per-host port-data presence assertion to catch host-timeout failures across hosts.

A follow-up nmap pass at the cautious-tier profile routinely surfaces signal that an
aggressive `-T4` default misses: TLS SAN expansion (staging / internal subdomains),
rDNS vendor identification (CDN / SaaS edge ownership), per-host WAF tier mapping,
edge-auth identifiers, and dense API-cluster footprints invisible to every other tool.
The depth comes from the rate calibration — the default `-T4` profile trips the rate
limit and leaves the SAN/rDNS data uncaptured.

The canonical per-target rate calibration table lives in
`agent/operator-core.md` "Recon Dispatch Resource Policy" — the values above pull from
that table. The same policy section caps concurrent nmap processes at 1 per dispatch
(consolidate via `-iL`, see "Why one process beats N processes" below).

## Why one process beats N processes

Prefer one nmap process scanning multiple hosts via `-iL hosts.txt` over N parallel
`nmap host` invocations. Nmap's parallelism is **internal** — `--max-parallelism`,
`--min-parallelism`, and the `-T<n>` template tune host-and-port concurrency without
spawning extra processes. Spawning N nmap processes amplifies host CPU per port without
proportional speedup, and creates N audit rows that look like progress while actually
competing for the same network/CPU budget.

The full mechanism (and the 2-process concurrency cap that the operator enforces across
specialists) is documented in `agent/skills/port-scanning/SKILL.md` "Process consolidation".

## TLS SAN extraction

The TLS-grab output that nmap captures during `-sV` against TLS-bearing ports carries
certificate metadata that surfaces adjacent hosts no other tool sees. Extract SAN hosts
after the scan completes:

```bash
grep -oE 'DNS:[^ ,]+' nmap_initial.nmap | sed 's/DNS://' | sort -u > nmap_san_hosts.txt
```

Feed `nmap_san_hosts.txt` back into subdomain-enumeration / httpx — TLS SANs routinely
surface staging hosts and adjacent services that passive sources miss.

## rDNS extraction

Reverse DNS reveals shared / CDN-fronted infrastructure ownership. Extract from the nmap
greppable output:

```bash
grep -oE 'Host: [0-9.]+ \([^)]+\)' nmap_initial.gnmap \
  | sed -E 's/Host: ([0-9.]+) \(([^)]+)\)/\1\t\2/' \
  | sort -u > nmap_rdns.tsv
```

When rDNS resolves to a third-party vendor or CDN domain, the host is a CDN/SaaS edge
rather than a primary target — the testing approach changes once you know. Vendor edges
typically have their own disclosure scope, and origin-server vulns probed through the
edge often produce false positives.

## Multi-host batch (`-iL`)

Run via `aith assess kali nmap-scan` with `-iL` passed through `--extra-args` or the typed `--input-file` flag so the audit row records the batch and the scan stays inside the runtime:

```bash
aith assess kali nmap-scan \
  --target placeholder \
  -iL /engagements/$ENGAGEMENT_KEY/scans/hosts.txt \
  --ports top-1000 --service-detection \
  --max-rate 200 --max-retries 2 \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_batch \
  --technique RECON --intent "cautious-tier multi-host batch" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

Always pair `-iL` with the per-host port-data presence assertion — a single batch can
contain a mix of hosts that pass and hosts that hit `--host-timeout`, and the naive "did
the binary finish?" gate cannot tell the two apart.

## XML-closure trap and the correct port-data presence gate

`grep -c '</nmaprun>' *.xml` shows clean closure even when host-timeout fires mid-flight
with zero port data captured. **XML closure means the nmap binary exited normally, NOT
that every host scan finished.** `grep -c "Nmap scan report for $host"` returns 1 even
when the host scan started and timed out before any port data was captured.

Use the port-data presence check, not XML closure or scan-report line. Two layers, both
required before declaring a batch complete:

```bash
# Layer 1 — text output (port-data presence)
for f in scans/*.nmap; do
  hostname=$(basename "$f" .nmap)
  open_ports=$(grep -cE '^[0-9]+/(tcp|udp).*open' "$f")
  finished=$(grep -c "Nmap done" "$f")
  if [ "$open_ports" -eq 0 ] && [ "$finished" -eq 0 ]; then
    echo "GAP: $hostname (scan started but timed out — port data empty)"
  fi
done

# Layer 2 — XML host-status (xmllint XPath)
for f in scans/*.xml; do
  port_bytes=$(xmllint --xpath '//host[@status="up"]/ports' "$f" 2>/dev/null | wc -c)
  [ "$port_bytes" -eq 0 ] && echo "GAP: $f — host up but zero port data (host-timeout fired)"
done
```

Hosts the assertion flags fall into two categories:

1. **Local rate / WAF intercept** — re-queue at the slower retry profile
   (`-T2 --host-timeout 1500-1800s`, or `-sT` if upstream filtering rejects SYN).
2. **Upstream filtering kill-evidence** — if the slower retry STILL hits host-timeout
   with zero port data, that's defensible kill-evidence. Record an intel-note documenting
   the upstream filtering before moving on. When this pattern recurs across multiple
   origin hosts in the same scope, each one needs its own intel-note so the report can
   show the filtered surface explicitly.

The full mandatory assertion + intel-note recipe lives in
`agent/skills/port-scanning/SKILL.md` "Per-host port-data presence assertion".

## Scan Types

Pass scan-type flags through `--extra-args` on the `aith assess kali nmap-scan` typed verb, or use `aith assess kali exec -- nmap ...` when building a complex pipeline not covered by the typed verb. Audit flags are required on both paths.

**SYN scan (default, needs root):** `-sS` (stealthy, half-open)
**TCP connect (no root):** `-sT` (full handshake, logged)
**Version detection:** `-sV` with `--version-intensity 5` (0=light, 9=deep)
**OS detection (needs root):** `-O`
**Aggressive:** `-A` (combines -O, -sV, -sC, --traceroute)

## NSE Scripts

**Default scripts:** `-sC` (same as `--script=default`)
**Vuln category:** `--script=vuln`
**Specific script:** `--script=http-enum`
**Script args:** `--script-args='http-enum.basepath=/api/'`

Common categories: `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`

## Speed & Evasion

**Timing:** `-T0` (paranoid) to `-T5` (insane). Default: `-T3`
**Min rate:** `--min-rate 1000`
**Max retries:** `--max-retries 2`
**Fragment packets:** `-f`
**Source port spoof:** `--source-port 53`

## Output

`-oN file.txt` — normal text
`-oX file.xml` — XML (for parsing)
`-oG file.gnmap` — greppable
`-oA basename` — all formats at once

## Common Port Quick Reference

| Port | Service | Notes |
|------|---------|-------|
| 21 | FTP | Check anonymous login |
| 22 | SSH | Version → CVE check |
| 25 | SMTP | Open relay check |
| 53 | DNS | Zone transfer |
| 80/443 | HTTP/HTTPS | Web application |
| 139/445 | SMB | EternalBlue, null session |
| 3306 | MySQL | Remote auth |
| 3389 | RDP | BlueKeep, NLA check |
| 5432 | PostgreSQL | Remote auth |
| 8080/8443 | HTTP alt | Admin panels |
