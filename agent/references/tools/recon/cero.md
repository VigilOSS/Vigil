---
description: cero TLS SAN scraper (Phase 3); DEFAULT = cero against the A-record IPs of RESOLVED origin/staging hosts (few distinct IPs, Docker-safe); whole-asnmap-CIDR sweeps are a gated escalation (Docker per-dest-IP proxy hazard); wrapper target flags (--target, -l, --only-domains)
skill: subdomain-enumeration
---

# cero

TLS SAN scraper, run as `vigil assess kali cero` (`vigil assess contract kali cero`). It catches
names from private-CA certs that never reach CT logs, on TLS-handshakable internet-facing IPs.

**Wrapper flags.** The target is `--target`/`--domain` (one host, IP or CIDR) or `-l` (a file
piped to cero on stdin). The wrapper does not bind `-d`: cero's own `-d` is a toggle that keeps only
valid domain names, exposed as `--only-domains`. `-t` is cero's per-host handshake timeout in
seconds, not a thread count.

## Default: resolved origin/staging IPs

Scrape SANs off the A-record IPs of hosts you already resolved (`origin.*`, `*-origin`,
`staging.*`, `dev.*`, `internal.*`): a small, de-duplicated set of destination IPs. A CIDR or an
asnmap CIDR file expands to thousands of distinct destination IPs, which wedges the Docker Desktop
userspace proxy (`agent/references/runtime-guides/docker-desktop-network-hazards.md`). The danger
knob is distinct destination IPs; concurrency and rate do not rescue a large fan-out. The verb
counts the distinct IPs in its input and WARNs on Docker Desktop when the count is too large.

```bash
vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/origin_hosts.txt \
  -a -resp-only -silent -o /engagements/$ENGAGEMENT_KEY/scans/origin_ips_raw.txt \
  --technique RECON --intent "resolve origin/staging hosts to A-records for cero SAN scrape" \
  --probe-kind baseline --phase recon --timeout 300
sort -u "$DIR/scans/origin_ips_raw.txt" > "$DIR/scans/origin_ips.txt"
vigil assess kali cero -l /engagements/$ENGAGEMENT_KEY/scans/origin_ips.txt \
  -p 443,8443,9443 -c 100 -t 4 -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans.txt \
  --technique OSINT --intent "TLS SAN scrape across resolved origin/staging IPs" \
  --probe-kind fingerprint --phase recon --timeout 600
```

Lower `-c` to 50 on rate-sensitive targets. Add ports the target advertises (nmap or httpx
output) beyond the 443,8443 default.

## Whole-CIDR sweep — gated escalation only

Feed a CIDR (`--target <cidr>` or a CIDR file via `-l`) only when both gates pass:

1. **asnmap confirms the netblock is target-owned and non-cloud.** A CDN/cloud range (Akamai,
   Cloudflare, Fastly, AWS, GCP, Azure) returns the provider's shared-fleet SANs and still carries
   the Docker hazard.
2. **The runtime is not Docker Desktop.** `kali cero` always runs in the container, so on macOS or
   Windows Docker Desktop a whole-CIDR sweep fans out through the userspace proxy.

Raise `-c` to 200 only for a large (>1000 IP) sweep on the bursty-OK profile, under both gates.

cero and `httpx -tls-grab` produce different SAN sets (httpx reads already-live HTTP hosts, cero
handshakes the IP list), so run both; `tlsx.md` covers the structured-JSON and JARM/JA3 variant.
