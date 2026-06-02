---
name: tls-vhost-correlation
description: Cross-host TLS / SAN / vhost correlation — split-VIP detection, shared multi-tenant cert detection, vhost-cert mismatch detection
origin: Vigil
---

# TLS / vhost Cross-Host Correlation

## Identity

Cross-host TLS analysis. Per-host TLS-grab tools (httpx `-tls-grab`, nmap `ssl-cert`) record
SANs **per host** — they cannot tell you that two hosts share a multi-tenant cert, that a
single name resolves to a load-balanced cluster of distinct origins, or that a host serves
a default cert whose SANs reveal adjacent attack surface. Those three signals — shared
cert, split-VIP, vhost-cert mismatch — only surface from a cross-host pass over the SAN
sets.

## When to Activate

- Recon-pass output flagged a CDN-fronted, multi-tenant, or load-balanced shape (any major
  CDN/edge in wafw00f, httpx `-tls-grab` showing a SAN list spanning multiple tenants,
  rDNS resolving the host to a known shared platform).
- Multiple in-scope hosts share an apex domain or sit on the same edge — collision
  analysis and split-VIP detection often expose tenant identities or staging hosts that
  passive sources missed.
- Before leaving Phase 1, when the per-host TLS-grab from `web-recon` Step 8 surfaced any
  SAN list larger than the host's own canonical name (the host serves a cert for *other*
  names — a shared-cert or default-cert signal).

Skip this skill when the in-scope target is a single non-shared host with no CDN, no
multi-tenant signals, and no vendor-edge fingerprint — the methodology has nothing to
correlate against.

## Methodology

This skill runs **after** the per-host TLS-grab in `web-recon` Step 8 (and the SAN
extraction inside `nmap`/`httpx` from steps 1-2) has populated each host's SAN set. The
three sub-procedures compose: multi-time DNS feeds the per-IP probe loop, the per-IP
probes feed the per-host SAN store, and the cross-host SAN collision counter consumes the
combined store.

The detailed recipes — per-host SAN extraction loop, the cross-host collision counter,
vhost-cert match check, and the dnsx confirmation pass — live in
`agent/references/tools/recon/openssl-sans.md`. The three sub-steps below are the
methodology summary; mechanics live in the recipe.

### Multi-time DNS resolution (split-VIP detection)

```bash
vigil assess kali exec --technique RECON --intent "multi-time DNS resolution — detect split-VIP load-balanced clusters" \
  --probe-kind fingerprint --phase recon --timeout 600 -- bash -c '
  for i in 1 2 3 4 5; do dig +short TARGET_HOST A; sleep 60; done | sort -u
'
```

A single DNS lookup misses split-VIP load-balanced clusters — when a name resolves to a
different IP across multiple resolutions, each unique IP can be probed independently and
may serve different content / different cert / different rate-limit policy. Five samples
spaced 60s apart land close to most rotation TTLs (30-300s) without burning host wall
time. Two or more unique IPs across the sample set indicates split-VIP; capture each IP's
cert via `openssl s_client -connect <ip>:443 -servername <hostname>` because different
cluster IPs sometimes carry different certs.

### Cross-host SAN collision detection

Loop `openssl s_client` across the in-scope host list, extract each cert's SAN set, and
count how many hosts share each SAN entry:

```bash
for h in $HOSTS; do
  echo | timeout 10 openssl s_client -connect "$h:443" -servername "$h" 2>/dev/null \
    | openssl x509 -noout -ext subjectAltName \
    | grep -oE 'DNS:[^,]+' | sort -u
done | sort | uniq -c | sort -rn
```

A SAN that appears in two or more hosts' certs indicates a shared multi-tenant cert (one
cert serving multiple tenant SANs) — a tenant-identity disclosure surface and a
vhost-routing hint. The full collision-counter script lives in `openssl-sans.md` step 2;
high-count entries are recorded as intel-notes and fed back as Phase 1a subdomain
expansion seeds.

### vhost-cert mismatch detection

For each in-scope host, compare the served cert's CN (and SAN list) against the requested
hostname. Mismatches indicate a shared frontend serving a non-matching default cert — a
frontend-misconfiguration signal that can leak adjacent tenant identities, plus the cert's
actual CN / SANs are adjacent attack surface (record each as a follow-up subdomain
candidate). Recipe: `openssl-sans.md` step 3.

## Required Behavior

- Run all three sub-procedures together when the shared-frontend trigger fires —
  collision detection without split-VIP misses load-balanced cluster cert variation, and
  vhost-cert mismatch without collision detection misses the systemic-default-cert
  pattern.
- Record collisions and mismatches as durable intel-notes via
  `vigil assess record-intel note <intel-json>`; SAN-discovered subdomains feed Phase 1a
  via `vigil assess ingest-endpoints` so they enter the work buffer.
- Keep target-facing execution in `vigil assess kali ...` — host-side `openssl` /
  `dig` bypasses the audit pipeline that downstream specialists rely on.

## Output Contract

This skill is owned by recon-specialist as a sub-procedure of the Phase 1 web-recon pass.
Outputs feed into the recon-specialist's normal output structure:

| Section | Holds |
|---|---|
| `#### Intelligence` | One `intel-note` per detected collision (count >= 2 entry), per detected vhost-cert mismatch, and per split-VIP cluster. Each note carries the host(s), the shared SAN, and the inferred relationship (shared multi-tenant cert / default cert / load-balanced split-VIP). |
| `#### Surface Candidates` | Each new host name surfaced from a SAN collision or a vhost-cert CN mismatch becomes a follow-on subdomain seed; record via `vigil assess record-surface` so the operator can re-feed Phase 1a. |
| `#### Coverage Gaps` | When the shared-frontend trigger never fired (single non-shared host, no CDN, no multi-tenant signals), declare "no shared-frontend signal — TLS/vhost cross-host correlation skipped" with the rationale. When the trigger fired but a sub-procedure could not run (openssl missing in runtime, host unreachable), declare which sub-procedure was blocked and why. |

## Extended Resources

- `agent/references/tools/recon/openssl-sans.md` — per-host TLS SAN extraction (openssl
  s_client + x509 -ext subjectAltName), cross-host SAN collision counter, vhost / cert
  mismatch detection, multi-time DNS resolution loop, dnsx live-host confirmation.
- `agent/skills/web-recon/SKILL.md` — Step 8 per-host TLS-grab feeds this skill; this
  skill is the cross-host follow-up when shared-frontend signals fire.
- `agent/skills/subdomain-enumeration/SKILL.md` — SAN-discovered subdomains land back here
  for active-resolution + live-host confirmation.
