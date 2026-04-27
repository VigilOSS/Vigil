# cero

**Purpose:** TLS Subject Alternative Name (SAN) scraper — opens TLS handshakes against domains or CIDRs and extracts SAN fields from the cert. Catches subdomains that never appear in CT logs because they were issued by a private CA but TLS-handshakable on internet-exposed IPs.

For live engagement targets, run cero via `aith assess kali cero` (typed verb, audit-flag-aware).

**Where it lives:** `/usr/local/bin/cero` in `runtime-full` (`go install github.com/glebarez/cero@latest` — see `agent/docker/runtime-full/Dockerfile`).

## Resource-safe invocation (Phase 3 TLS SAN feedback loop)

The high-value pattern is asnmap → cero. Feed an asnmap-derived CIDR range into cero with default ports and concurrency=100; the runtime image ships these defaults.

```bash
aith assess kali cero -d /engagements/$ENGAGEMENT_KEY/scans/target_cidrs.txt \
  -p 443,8443,9443 -c 100 -t 4 \
  -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans.txt \
  --technique OSINT --intent "TLS SAN scrape across asnmap-derived CIDRs" \
  --probe-kind fingerprint --phase recon --timeout 600
```

Lower concurrency to 50 against rate-sensitive targets; raise to 200 only when sweeping large CIDRs (>1000 IPs) on the bursty-OK profile.

## When to use vs. alternatives

- **vs. CT-log scraping (subfinder Censys/crt.sh modules):** cero catches private-CA certs that never publish to CT. Both feed the same merged sub list — they are complementary, not alternatives.
- **vs. httpx `-tls-grab`:** httpx grabs TLS off existing live HTTP hosts; cero brute-handshakes a CIDR. Run both — they produce different SAN sets.

## Cross-reference

- Comparison matrix and CIDR-feed pattern: `agent/references/tools/recon/subdomain-enumeration-tools.md`.
- Phase 3 in the staged composition: `agent/skills/subdomain-enumeration/SKILL.md`.
