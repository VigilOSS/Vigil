---
description: TLS SAN scraper (Phase 3); asnmap → cero CIDR-feed pattern
skill: subdomain-enumeration
---

# cero

**Purpose:** TLS Subject Alternative Name (SAN) scraper — opens TLS handshakes against domains or CIDRs and extracts SAN fields from the cert. Catches subdomains that never appear in CT logs because they were issued by a private CA but TLS-handshakable on internet-exposed IPs.

For live engagement targets, run cero via `vigil assess kali cero` (typed verb, audit-flag-aware).

**Where it lives:** `/usr/local/bin/cero` in `runtime-full` (`go install github.com/glebarez/cero@latest` — see `agent/docker/runtime-full/Dockerfile`).

## Wrapper flag mapping (read first)

The typed wrapper exposes targets via `--target` / `--domain` (single domain or CIDR) and `-l` / `--input-list` (file of domains/CIDRs piped to cero on stdin). The wrapper does **not** bind argparse `-d` to the target argument because cero's native `-d` flag is a toggle (filter results to valid domain names only), not a target argument. The toggle is exposed as `--only-domains`. Reach for `-l` whenever your target list is in a file; reach for `--target` for a single ad-hoc host.

## Resource-safe invocation (Phase 3 TLS SAN feedback loop)

The high-value pattern is asnmap → cero. Feed an asnmap-derived CIDR file into cero with default ports and concurrency=100; the runtime image ships these defaults.

```bash
# File-input form (asnmap → cero feedback loop)
vigil assess kali cero -l /engagements/$ENGAGEMENT_KEY/scans/target_cidrs.txt \
  -p 443,8443,9443 -c 100 -t 4 \
  -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans.txt \
  --technique OSINT --intent "TLS SAN scrape across asnmap-derived CIDRs" \
  --probe-kind fingerprint --phase recon --timeout 600

# Single-target form
vigil assess kali cero --target 198.51.100.0/24 \
  -p 443,8443,9443 -c 100 -t 4 \
  -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans_single.txt \
  --technique OSINT --intent "TLS SAN scrape on single CIDR" \
  --probe-kind fingerprint --phase recon --timeout 600

# --only-domains toggle (cero -d): filter results to valid domain names
vigil assess kali cero -l /engagements/$ENGAGEMENT_KEY/scans/target_cidrs.txt \
  --only-domains -p 443 \
  -o /engagements/$ENGAGEMENT_KEY/scans/cero_domain_sans.txt \
  --technique OSINT --intent "TLS SAN scrape, domain-name results only" \
  --probe-kind fingerprint --phase recon --timeout 600
```

Lower concurrency to 50 against rate-sensitive targets; raise to 200 only when sweeping large CIDRs (>1000 IPs) on the bursty-OK profile.

## When to use vs. alternatives

- **vs. CT-log scraping (subfinder Censys/crt.sh modules):** cero catches private-CA certs that never publish to CT. Both feed the same merged sub list — they are complementary, not alternatives.
- **vs. httpx `-tls-grab`:** httpx grabs TLS off existing live HTTP hosts; cero brute-handshakes a CIDR. Run both — they produce different SAN sets.

## Cross-reference

- Comparison matrix and CIDR-feed pattern: `agent/references/tools/recon/subdomain-enumeration-tools.md`.
- Phase 3 in the staged composition: `agent/skills/subdomain-enumeration/SKILL.md`.
