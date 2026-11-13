---
description: asnmap ASN/org to CIDR mapping — PDCP_API_KEY gate (empty output without it), keyless whois.cymru.com/RADB/RDAP fallbacks, and its role confirming a non-cloud netblock for the gated cero CIDR sweep
skill: subdomain-enumeration
---

# asnmap

ASN/domain/org to CIDR mapper, run as `vigil assess kali asnmap` (flags and example:
`vigil assess contract kali asnmap`).

**PDCP key.** Without `PDCP_API_KEY` asnmap exits 0 with empty output, which reads exactly like
"this ASN announces nothing" and silently empties the downstream feed. The verb detects the
missing key and fails; `--allow-no-key` overrides. To provision it, take a free key from
`cloud.projectdiscovery.io`, set `PDCP_API_KEY=...` in `<install>/.env`, and re-run
`vigil runtime start`.

**Keyless fallbacks** (`whois`, `dig` and `curl` are in the runtime image; run them under
`vigil assess kali exec`):

- Team Cymru: `whois -h whois.cymru.com " -v <ip>"` maps IP to ASN and prefix.
- RADB: `whois -h whois.radb.net '!gAS<asn-number>'` expands an ASN to its announced prefixes.
- RDAP: `curl -s https://rdap.arin.net/registry/ip/<ip>` gives the registered CIDR.

Use `-org "<name>"` when the apex is CDN-fronted and the ASN lookup off its IP returns the CDN.
asnmap output is the confirmation that a netblock is target-owned and non-cloud before the gated
whole-CIDR cero sweep (`cero.md` "Whole-CIDR sweep — gated escalation only"), not the default cero
feed.
