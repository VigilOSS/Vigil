---
description: "Pexip Infinity admin-API deep-enum: namespace probe list, anonymous-vs-default-admin-vs-credentialed reachability triad, configuration-leak chain seeds"
skill: vendor-platform-enum
source: Custom — compiled from the Pexip Infinity admin-API documentation and management-plane research.
---

# Pexip Infinity Admin API — Deep-Enum Payloads

> Source: Custom — compiled from the Pexip Infinity admin-API documentation and management-plane research.

Use these payloads after `vendor-platform-enum/SKILL.md` triggers on a Pexip Infinity fingerprint. The admin API at `/api/admin/configuration/v1/<namespace>/` exposes the deployment's configuration; mis-set front-end auth (or an exposed management VLAN) lets anonymous or default-credential callers read or modify it.

## Namespace probe list

Each namespace is an independent permission decision. Probe all of them — a deployment that authenticates `/conferencing_node` may still expose `/upgrade_package` because the per-namespace ACL was missed.

```
conference, conferencing_node, worker_vm, system_location,
mssip_proxy, h323_gatekeeper, sip_proxy, static_route,
gms_access_token, automatic_participant, end_user, event_sink,
external_participant, gateway_routing_rule, global_configuration,
media_server, policy_server, recurring_conference, registration,
role, sso_profile, syslog_server, snmp_network_management_system,
system_tuneable, tls_certificate, ldap_role, ldap_sync_source,
upgrade_package, web_app_alias, ssh_authorized_key,
managed_certificate, dns_server, ntp_server, http_proxy
```

For each namespace, send:

```bash
vigil assess kali exec --technique INFO-DISCLOSURE \
  --intent "Pexip admin-API namespace probe (anonymous reachability test)" \
  --probe-kind payload --phase recon --timeout 20 -- \
  curl -sS 'https://TARGET/api/admin/configuration/v1/<namespace>/?limit=1' \
    -H 'Accept: application/json'
```

A 200 with a `meta.total_count` field and a `objects[]` array is anonymous-readable.

## Three reachability profiles

Probe each namespace under three conditions and record each response code:

1. **Anonymous** — no `Authorization` header. A 200 here is the high-impact finding (no-auth on the admin plane).
2. **Default-admin guess** (operator-gated):
   - `Authorization: Basic YWRtaW46YWRtaW4=` (admin:admin)
   - `Authorization: Basic YWRtaW46cGV4aXA=` (admin:pexip)
   - `Authorization: Basic YWRtaW46UGFzc3dvcmQx` (admin:Password1)
   A 200 here is a separate finding (default credentials, not no-auth).
3. **Operator-supplied credentials** — only when scope explicitly permits credentialed testing. Distinguishes "low-priv operator can read" from "anonymous can read".

## High-impact namespaces (read first)

Some namespaces leak more than others. Read these first when the anonymous probe returns 200:

| Namespace | What it leaks |
|---|---|
| `conferencing_node` | Per-node FQDN, IP, TLS cert fingerprint, system_location reference, deployment role (proxy / transcoding / management). The full topology of the conferencing plane. |
| `worker_vm` | Worker-VM hostnames, IP addresses, hypervisor fingerprint. |
| `system_location` | DNS server, NTP server, syslog server, HTTP proxy, MTU per location. Each is an internal-IP or internal-DNS leak. |
| `tls_certificate` | Per-cert subject, SAN, issuer, expiry, fingerprint. Reveals the cert chain even when the front-end TLS endpoint masks it. |
| `event_sink` | External monitoring URL + bearer token (if exposed). The token is an immediate credential leak. |
| `sso_profile` | SSO IdP metadata URL, certificate, entity ID. Reveals the federation configuration. |
| `ldap_sync_source` | Bind DN, base DN, server URL, sync schedule. The bind credentials are usually masked but the schema map is not. |
| `upgrade_package` | Pending upgrade version + signature. Reveals current platform version (drives CVE-match intel). |
| `ssh_authorized_key` | Public keys with operator usernames. Authorized-keys names alone are intel; if any private-key blob is exposed, that is a credential leak. |
| `gms_access_token` | Management-server access tokens. Immediate credential leak. |

## Configuration-leak chain

A single leaked `conferencing_node` row seeds adjacent reads:

- `system_location` reference → `/api/admin/configuration/v1/system_location/<id>/` → DNS / NTP / syslog server addresses.
- TLS cert fingerprint + SAN → cross-feed into subdomain-enumeration (the cert SANs are subdomain hints).
- Worker-VM count + role → infrastructure intel for downstream Phase 5 hypotheses.

Walk each adjacent read in the same dispatch — the chain is the high-severity finding, not the per-namespace primitive.

## Status / version probe

`GET /api/admin/status/v1/version` returns the platform version when the status namespace is exposed:

```json
{"version-id": "31.1.1.62820.0", "pseudo-version": "..."}
```

Version intel feeds CVE-match in osint-recon — record under `vigil assess record-intel tech-component` with the resolved version string.

## Bounded-vs-systemic IDOR test

Pexip uses sequential integer IDs in object URLs (`/api/admin/configuration/v1/conferencing_node/1/`, `.../2/`). Walk the ID space via `vigil assess kali exec` so the sweep lands in the audit pipeline:

```bash
vigil assess kali exec --technique IDOR \
  --intent "Pexip conferencing_node IDOR boundedness sweep, IDs 1-10" \
  --probe-kind payload --phase consume-test --timeout 60 -- \
  bash -c '
    for id in 1 2 3 4 5 6 7 8 9 10; do
      curl -sS "https://TARGET/api/admin/configuration/v1/conferencing_node/$id/" \
        -o /dev/null -w "%{http_code} $id\n"
    done
  '
```

- **Bounded** — only the current object's IDs return 200; non-existent IDs return 404. The leak is the namespace's current contents.
- **Systemic** — every ID returns 200 with a different object. The namespace is fully enumerable by ID.

## Rate-limit discipline

Pexip's management plane runs on lower-spec hardware than the conferencing plane — the admin API is not designed to handle bulk reads. Default to 1 request / 500ms (2 RPS); drop to 1 request / 1500ms on the first 5xx or `Retry-After`. A management-plane DoS is a real risk; the deep-enum dispatch must stop and re-queue at the slower rate the moment a 5xx appears.
