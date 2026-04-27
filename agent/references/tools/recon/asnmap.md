# asnmap

**Purpose:** ASN → CIDR mapper. Takes a domain or org name, looks up the owning ASN(s), and emits the IP ranges those ASNs announce. The cero feed for the Phase 3 TLS SAN sweep.

For live engagement targets, run asnmap via `aith assess kali asnmap` (typed verb, audit-flag-aware).

**Where it lives:** `/usr/local/bin/asnmap` in `runtime-full` (`go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest` — see `agent/docker/runtime-full/Dockerfile`).

## Resource-safe invocation

asnmap is network-bound (queries ProjectDiscovery's ASN service) and very low CPU/RAM. No tier-specific tuning is needed.

```bash
# Resolve from a domain
aith assess kali asnmap -d target.example -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/target_cidrs.txt \
  --technique OSINT --intent "ASN → CIDR mapping for target.example" \
  --probe-kind fingerprint --phase recon --timeout 300

# Resolve from an org name (when the apex is fronted and ASN lookup off the IP fails)
aith assess kali asnmap -org "Target Corporation" -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/target_org_cidrs.txt \
  --technique OSINT --intent "ASN → CIDR mapping by org name" \
  --probe-kind fingerprint --phase recon --timeout 300
```

## When to use vs. alternatives

- **vs. whois/RDAP scraping:** asnmap aggregates BGP announcement data from multiple sources, so it catches announced-but-undocumented prefixes that whois misses.
- **vs. manual `dig +short` chains:** asnmap is a single audited call; manual chains are not auditable through `list-command-runs`.

## Cross-reference

- CIDR-feed pattern (asnmap → cero): `agent/references/tools/recon/subdomain-enumeration-tools.md` "cero — CIDR-feed pattern".
- Phase 3 in the staged composition: `agent/skills/subdomain-enumeration/SKILL.md`.
