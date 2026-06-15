---
description: TLS SAN scraper (Phase 3); DEFAULT = cero against the A-record IPs of RESOLVED origin/staging hosts (few distinct IPs, Docker-safe); whole-asnmap-CIDR sweeps are a gated escalation (Docker per-dest-IP proxy hazard)
skill: subdomain-enumeration
---

# cero

**Purpose:** TLS Subject Alternative Name (SAN) scraper — opens TLS handshakes against domains or CIDRs and extracts SAN fields from the cert. Catches subdomains that never appear in CT logs because they were issued by a private CA but TLS-handshakable on internet-exposed IPs.

For live engagement targets, run cero via `vigil assess kali cero` (typed verb, audit-flag-aware).

**Where it lives:** `/usr/local/bin/cero` in `runtime-full` (`go install github.com/glebarez/cero@latest` — see `agent/docker/runtime-full/Dockerfile`).

## Wrapper flag mapping (read first)

The typed wrapper exposes targets via `--target` / `--domain` (single domain or CIDR) and `-l` / `--input-list` (file of domains/CIDRs piped to cero on stdin). The wrapper does **not** bind argparse `-d` to the target argument because cero's native `-d` flag is a toggle (filter results to valid domain names only), not a target argument. The toggle is exposed as `--only-domains`. Reach for `-l` whenever your target list is in a file; reach for `--target` for a single ad-hoc host.

## Resource-safe invocation (Phase 3 TLS SAN feedback loop)

**DEFAULT: cero against the resolved origin/staging A-record IPs — not whole CIDRs.**
The high-value, Docker-safe pattern is to scrape SANs off the **A-record IPs of the hosts you
already resolved** (`origin.*`, `*-origin`, `staging.*`, `dev.*`, `internal.*`), which is a **small,
de-duplicated IP list** — a handful of distinct destination IPs. Whole-CIDR sweeps are an
explicitly-gated **escalation**, not the default, because feeding a CIDR (or an asnmap-derived CIDR
file) to cero expands to **thousands of distinct destination IPs**, which is the Docker Desktop
per-destination-IP proxy wedge (I-001 — see
`agent/references/runtime-guides/docker-desktop-network-hazards.md`). The danger knob is **distinct
destination IPs, not concurrency or rate**.

```bash
# DEFAULT — resolve origin/staging candidate hosts to A-records, dedup the IPs, feed ONLY those IPs.
# Step 1: resolve to A-records (IPs only).
vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/origin_hosts.txt \
  -a -resp-only -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/origin_ips.txt \
  --technique RECON --intent "resolve origin/staging hosts to A-records for cero SAN scrape" \
  --probe-kind baseline --phase recon --timeout 300
# (dedup origin_ips.txt to distinct IPs before feeding cero)

# Step 2: cero against the small resolved-IP list (few distinct dest IPs — Docker-safe).
vigil assess kali cero -l /engagements/$ENGAGEMENT_KEY/scans/origin_ips.txt \
  -p 443,8443,9443 -c 100 -t 4 \
  -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans.txt \
  --technique OSINT --intent "TLS SAN scrape across resolved origin/staging IPs" \
  --probe-kind fingerprint --phase recon --timeout 600

# Single-target form (one ad-hoc resolved origin IP)
vigil assess kali cero --target 198.51.100.10 \
  -p 443,8443,9443 -c 100 -t 4 \
  -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans_single.txt \
  --technique OSINT --intent "TLS SAN scrape on single resolved origin IP" \
  --probe-kind fingerprint --phase recon --timeout 600

# --only-domains toggle (cero -d): filter results to valid domain names
vigil assess kali cero -l /engagements/$ENGAGEMENT_KEY/scans/origin_ips.txt \
  --only-domains -p 443 \
  -o /engagements/$ENGAGEMENT_KEY/scans/cero_domain_sans.txt \
  --technique OSINT --intent "TLS SAN scrape, domain-name results only" \
  --probe-kind fingerprint --phase recon --timeout 600
```

Lower concurrency to 50 against rate-sensitive targets. (Concurrency tunes throughput per IP; it does
**not** rescue you from a large-distinct-dest-IP fan-out — that is governed by the IP count, below.)

### Whole-CIDR sweep — gated escalation only

Feeding a CIDR or an asnmap-derived CIDR file to cero is an **escalation**, allowed **only** after
both gates pass:

1. **asnmap confirms the netblock is target-OWNED and NON-CLOUD** — not an Akamai / Cloudflare /
   Fastly / AWS / GCP / Azure announced range. Use asnmap to *confirm a non-cloud netblock is worth a
   broader sweep*, not as the primary cero feed. A CDN/cloud CIDR sweep is wasted breadth (the SANs
   belong to the provider's shared fleet) **and** the Docker hazard.
2. **Runtime is NOT macOS/Windows Docker Desktop, or the sweep is routed to the host path.** A
   whole-CIDR cero on Docker Desktop fans out to thousands of distinct destination IPs and wedges
   `com.docker.backend` (I-001). On a dedicated/non-Docker-Desktop runtime or via the audited host
   path it is fine.

```bash
# ESCALATION (gated): whole-CIDR cero on a confirmed non-cloud, target-owned netblock,
# on a runtime where the Docker per-dest-IP hazard does not apply (or via the host path).
vigil assess kali cero -l /engagements/$ENGAGEMENT_KEY/scans/confirmed_noncloud_cidrs.txt \
  -p 443,8443,9443 -c 100 -t 4 \
  -o /engagements/$ENGAGEMENT_KEY/scans/cero_cidr_sans.txt \
  --technique OSINT --intent "TLS SAN scrape across confirmed non-cloud asnmap CIDRs (escalation)" \
  --probe-kind fingerprint --phase recon --timeout 600
```

Raise concurrency to 200 only when sweeping large CIDRs (>1000 IPs) on the bursty-OK profile **and**
only under the escalation gates above.

## When to use vs. alternatives

- **vs. CT-log scraping (subfinder Censys/crt.sh modules):** cero catches private-CA certs that never publish to CT. Both feed the same merged sub list — they are complementary, not alternatives.
- **vs. httpx `-tls-grab`:** httpx grabs TLS off existing live HTTP hosts; cero brute-handshakes a CIDR. Run both — they produce different SAN sets.

## Cross-reference

- Docker Desktop per-destination-IP proxy hazard (why resolved-origin-IPs is the default and whole-CIDR is gated): `agent/references/runtime-guides/docker-desktop-network-hazards.md`.
- Resolving origin/staging hosts to A-records to feed cero: `agent/references/tools/recon/dnsx.md` (`-a -resp-only`).
- Comparison matrix and CIDR-feed pattern: `agent/references/tools/recon/subdomain-enumeration-tools.md`.
- Phase 3 in the staged composition: `agent/skills/subdomain-enumeration/SKILL.md`.
