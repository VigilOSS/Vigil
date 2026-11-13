---
description: tlsx bulk TLS certificate harvester — SAN/CN harvest to expand the subdomain set (private-CA certs CT logs miss), issuer/org + JARM/JA3 for cert pivoting, the Docker per-dest-IP fan-out hazard on CIDR input
skill: subdomain-enumeration
---

# tlsx

Run as `vigil assess kali tlsx`. Inputs, the default SAN+CN profile, field and fingerprint flags,
and its raw-TLS (no attribution header) posture: `vigil assess contract kali tlsx`. Use
`--technique RECON` for the SAN/CN harvest and `--technique OSINT` for issuer/fingerprint
pivoting.

**Docker per-destination-IP hazard.** A whole CIDR or an asnmap CIDR file fans out to thousands of
distinct destination IPs and wedges the Docker Desktop userspace proxy. Feed the resolved A-record
IPs of origin/staging hosts by default; a whole-CIDR sweep is the gated escalation in `cero.md`
("Whole-CIDR sweep — gated escalation only"), with the mechanism in
`agent/references/runtime-guides/docker-desktop-network-hazards.md`.

**Harvest, expand, pivot.**

1. Harvest SAN/CN off live hosts or resolved origin IPs (the default profile).
2. Merge the names into the candidate set, then re-resolve with `vigil assess kali dnsx` and
   re-probe liveness; scope admission applies as for any discovered name.
3. On a high-value origin pull `-cert -jarm`, then look for other in-scope hosts with the same
   issuer or fingerprint: a shared appliance, or a shared origin behind a CDN.

tlsx handshakes a host/IP list independently of HTTP liveness; `httpx -tls-grab` reads only
already-live HTTP hosts. tlsx and cero return overlapping but different name sets, and only tlsx
gives JARM/JA3.
