---
name: port-scanning
description: Discover open ports, running services, and their versions on a target
origin: Vigil
---

# Port Scanning

> **`vigil assess kali` audit flags:** use `--technique RECON` (port and service enumeration against in-scope hosts is canonical reconnaissance).

## When to Activate

- New in-scope hosts or IPs need a service inventory before vulnerability testing.

Typed verb: `vigil assess kali nmap-scan` (`--ports`, `--scripts`, `--service-detection`,
`--os-detection`, `--max-rate`, `--max-retries`, `--host-timeout`, `-iL`, `-oA`; the rest via
`--extra-args`, whose value must use the `=` form when it starts with a dash, e.g.
`--extra-args=-T3`). SAN and rDNS extraction, raw-packet limits, the XML-closure trap:
`agent/references/tools/recon/nmap.md`. A sweep that will not finish inside the `--timeout` ceiling (`agent/shared-constraints.md` §2) splits by host list or port range across calls; one that cannot be split goes to the operator as a `kali job` in `next_steps`.
Container paths are `/engagements/$ENGAGEMENT_KEY/...`; host-side shell (grep, loops) uses
`$DIR/...` (`agent/shared-constraints.md` §11).

## 1. Profile selection — pick before invoking nmap

`-T4` is not safe for shared infrastructure. Take the nmap profile from the row of
`agent/references/recon/rate-calibration.md` that the wafw00f result picks
(`agent/references/tools/recon/wafw00f.md` "WAF-tier rate adjustment table"). A cautious-tier pass routinely surfaces what `-T4` misses — SAN expansion, rDNS vendor
identification, per-host WAF tiers, dense API clusters — because of the rate, not extra scripts.

The default scan type is `-sT` (connect). Never switch to `-sS`: raw SYN probes are dropped by
Docker's userland NAT and return 0-open. `--scan-type sV` would replace `-sT` with nmap's root
default (SYN), so enable versions with `--service-detection` instead.

## 2. Canonical runs

```bash
# Initial
vigil assess kali nmap-scan --target TARGET --ports top-1000 --scripts safe \
  --max-rate 100 --max-retries 2 --host-timeout 300s --extra-args "-Pn -T3" \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_initial \
  --technique RECON --intent "initial top-1000 + safe scripts, Cloud-fronted row" \
  --probe-kind fingerprint --phase recon --timeout 600

# Two-pass full TCP: ports first, then service detection on what is open
vigil assess kali nmap-scan --target TARGET --ports full --max-rate 100 --extra-args "-Pn -T3" \
  -oA /engagements/$ENGAGEMENT_KEY/scans/ports_only \
  --technique RECON --intent "full-port sweep" --probe-kind fingerprint --phase recon --timeout 600
PORTS=$(grep -oE '[0-9]+/open' "$DIR/scans/ports_only.gnmap" | cut -d/ -f1 | paste -sd, -)
vigil assess kali nmap-scan --target TARGET --ports "$PORTS" --service-detection \
  --extra-args "-Pn -sC -T3" -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_targeted \
  --technique RECON --intent "service detection on open ports" \
  --probe-kind fingerprint --phase recon --timeout 600

# Multi-host: one -iL process (no --target)
vigil assess kali nmap-scan -iL /engagements/$ENGAGEMENT_KEY/scans/in_scope_hosts.txt \
  --ports top-1000 --scripts safe --max-rate 100 --max-retries 2 --host-timeout 300s \
  --extra-args "-Pn -T3" -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_batch \
  --technique RECON --intent "multi-host batch, Cloud-fronted row" \
  --probe-kind fingerprint --phase recon --timeout 600
```

## 3. Process consolidation

One `-iL` process beats N per-host invocations: nmap parallelises internally
(`--min/--max-parallelism`, `-T`), while per-host loops add CPU, audit rows and contention without
speed. Split-by-profile parallel sweeps are allowed up to the runtime-tier cap (Standard 2 / Heavy
4 / Comfortable 8, `vigil runtime resources`; trait table in
`agent/references/recon/rate-calibration.md`). To split across specialists, split the host list.

## 4. Per-host port-data presence assertion (mandatory before declaring a batch complete)

XML closure (`</nmaprun>`) and a "Nmap scan report for" line both appear when a host timed out
with no port data. The gate is port-data presence per host: run both layers in
`agent/references/tools/recon/nmap.md` "XML-closure trap and the correct port-data presence gate"
against `$DIR/scans`. Each flagged host is either:

1. **Local rate or WAF intercept** — re-queue it alone at
   `--max-retries 3 --host-timeout 540s --extra-args "-Pn -T2"` (still `-sT`) with `--timeout 600`,
   so nmap closes the host before the call ceiling; or
2. **Upstream filtering kill-evidence** — the slow retry still returns zero port data. Record one
   intel note per host (`vigil assess intel record note <file>`; shape via
   `vigil assess contract intel record`) naming the retry profile and the empty `<ports>` result,
   so the report shows the filtered surface.

Do not declare a batch complete until every flagged host passes on retry or has its note; the
recon-specialist's pre-output self-check fails when this gate is skipped.

## 5. Adjacent hosts and ownership

- **TLS SANs** from the scan output and **rDNS** from `-oG` (extraction in `nmap.md`) surface
  staging and internal names. Newly found hosts are intel until admitted to scope
  (`agent/shared-constraints.md` §1, `vigil assess scope explain <host>`); only then feed them to
  dnsx/httpx or the next nmap run.
- **Split-VIP clusters:** before declaring the host list complete, sample DNS several times
  (`agent/skills/tls-vhost-correlation/SKILL.md`; collision counter in
  `agent/references/tools/recon/openssl-sans.md`); each distinct IP may serve a different cert and
  port set.
- **rDNS to a CDN or SaaS vendor** recasts the host as a vendor edge: it often has its own
  disclosure scope, and origin-server vulnerabilities probed through it produce false positives.

## 6. Further passes

NSE categories (`http-enum`, `smb-enum-*`, `ftp-anon`, `ssh-auth-methods`; only the `intrusive`
and `brute` categories need `--destructive`; read-only `vuln` checks do not), deep version
detection (`--extra-args=--version-intensity=5`), UDP
(`--scan-type sU --ports top-100`, slow; targeted service ports first), and banner grabs via
`vigil assess kali exec … -- bash -c 'printf "\n" | nc -nv HOST PORT'`. Packet-level evasion
(`-f`, source port, decoys) needs raw packets and usually exceeds the ROE (`nmap.md`).

## What to Record

Open ports with services and versions, OS detection, notable NSE output, SAN hosts and rDNS vendor
identification as intel, filtered ports worth retesting later, the assertion result per host, and
non-web services to hand off.

## Output Contract

The skill produces these structured sections in the recon-specialist's return payload. Backend
writes (`finding record`, `intel record`, `record-surface`) are the durable record; this contract
names what each markdown section holds so downstream specialists parse it consistently.

| Section | Holds |
|---|---|
| `#### Summary` | Hosts scanned, profile chosen, open-port total, assertion pass/fail count. |
| `#### Open Services` | Per-host `host : port/proto : service : version : NSE notes`; the inventory feeding `record-surface` and follow-on dispatch. |
| `#### Findings` | Findings the scan already proves (default creds via NSE, anonymous FTP, a well-known-vuln NSE hit), each recorded via `vigil assess finding record`. |
| `#### Surface Candidates` | Non-web services warranting triage (Redis, Elasticsearch, Docker API, MongoDB, exposed RDP), each via `vigil assess record-surface`. |
| `#### Intelligence` | SAN hosts, rDNS vendor identification, OS detection, banner anomalies, each via `vigil assess intel record <type>`. |
| `#### Coverage Gaps` | Every host the assertion flagged and its disposition (slow retry, upstream-filtering note, deferred), UDP gaps, host timeouts. The operator decides re-dispatch from this. |
