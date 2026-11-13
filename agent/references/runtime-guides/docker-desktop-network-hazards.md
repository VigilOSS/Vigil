---
description: macOS/Windows Docker Desktop userspace network proxy (com.docker.backend) tracks NAT/socket state PER DISTINCT DESTINATION IP — so a DNS brute against a large resolver list (~15k IPs) wedges the VM regardless of qps. The danger knob is distinct destination IPs, NOT query rate. Safe envelope (≤~50 distinct dest IPs in-container; small validated resolver tier) and the host-execution escape hatch for large resolver sets.
skill: subdomain-enumeration
---

# Docker Desktop Network Hazards — the per-destination-IP proxy wedge

On macOS/Windows Docker Desktop, the danger knob for network-heavy recon is the number of distinct
destination IPs, not the query rate. Docker Desktop routes every container packet through a
host-side userspace proxy (`com.docker.backend`) that keeps NAT/socket state per destination IP.
A flood to a handful of IPs is cheap. A modest rate spread across thousands of IPs blows up that
state table, pins `com.docker.backend` CPU and takes the Docker daemon down, however slow the
rate. Native Linux and remote Docker have no such proxy, so none of this applies there.

## What it looks like

A `puredns` brute pointed at a 15,487-IP community resolver list (the full `trickest/resolvers`)
drove the host 1-minute load to about 112 and `com.docker.backend` to about 1081% CPU. The daemon
went down and both in-container work and `docker exec` stalled until Docker Desktop was restarted.
`docker exec` rides the same proxy, so a `docker exec` completion poll in an `until` loop hangs
with no timeout once the proxy wedges. Use host-side bind-mounted `.done` markers instead.

The same pathology hits any wide fan-out:

- bulk `httpx` liveness over thousands of hosts at `-threads 60`
- `cero` / TLS-SAN over a whole CIDR (`agent/references/tools/recon/cero.md`)
- nmap or asnmap CIDR sweeps

Lowering `--rate-limit` or `-threads` is a host-NIC concern and does not rescue a large distinct-IP
fan-out. "A large resolver list with per-resolver rate limiting is safe" is false on Docker
Desktop.

## The safe envelope

Before any DNS-heavy or wide fan-out op, count the distinct destination IPs it will touch
(resolver-list lines, CIDR size, host-list length).

**In-container on Docker Desktop:**

- Point DNS ops at a small validated resolver tier of about 50 distinct IPs at most. The
  in-container guard warns above `VIGIL_RESOLVER_IP_CAP` (default 50). A curated anycast set of
  16–40 IPs stays under the cap and also out-performs a large "alive" public list, because
  resolver quality under load governs throughput.
- Keep bulk `httpx` liveness at about `-threads 25`.
- Point `cero` at resolved origin IPs rather than whole CIDRs. A whole-CIDR or large host-list
  expansion is an escalation, not a default.
- Run one heavy network op at a time, because overlapping fan-outs trip the wedge sooner.

**On the host (for large sets):** with no userspace proxy in the path, thousands of resolvers are
fine, and much faster. Route the DNS-heavy tools (`massdns`, `puredns`, `dnsx`, `subfinder`,
`shuffledns`, `alterx`) and bulk-liveness `httpx` through the audited host path. Target HTTP,
exploit and authenticated traffic stay in the container. `vigil assess recon --runtime auto` (the
default) selects the host path on Docker Desktop. Standalone `dns-discovery` / `web-discovery`
need `--runtime host` (or `VIGIL_RECON_RUNTIME=host|auto`). Anything else goes through `vigil
assess host-exec`.

## Cross-references

- `agent/skills/subdomain-enumeration/SKILL.md` "Host-CPU note": the in-skill rule.
- `agent/references/tools/recon/puredns.md` and `dnsx.md`: `--rate-limit` is total qps, not per
  resolver.
- `agent/references/recon/rate-calibration.md`: the DNS-brute rate column.
