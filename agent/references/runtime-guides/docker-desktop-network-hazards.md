---
description: macOS/Windows Docker Desktop userspace network proxy (com.docker.backend) tracks NAT/socket state PER DISTINCT DESTINATION IP — so a DNS brute against a large resolver list (~15k IPs) wedges the VM regardless of qps. The danger knob is distinct destination IPs, NOT query rate. Safe envelope (≤~50 distinct dest IPs in-container; small validated resolver tier) and the host-execution escape hatch for large resolver sets.
skill: subdomain-enumeration
---

# Docker Desktop Network Hazards — the per-destination-IP proxy wedge

> **The one rule:** on macOS/Windows Docker Desktop the danger knob for
> network-heavy recon is the **number of distinct destination IPs**, not the
> query rate (qps). A DNS brute that fans out to a large resolver list wedges the
> Docker VM **regardless of how slow you set the rate**. Keep in-container DNS ops
> pointed at **≤~50 distinct resolver IPs**; route large resolver sets to the host.

## The mechanism

On native Linux (and remote/CI Docker), the container shares the host kernel's
network namespace path and packets egress directly — there is no userspace proxy
in the hot path. **Docker Desktop on macOS and Windows is different.** It runs the
container inside a lightweight Linux VM and routes **every container packet through
a host-side userspace network proxy** (`com.docker.backend`). That proxy maintains
**NAT/socket state per distinct destination IP**.

The cost is therefore driven by **how many distinct destination IPs** the
container is talking to, because each one is a tracked NAT/socket entry in
`com.docker.backend`. A flood of packets to a *handful* of destination IPs is
cheap (few proxy entries, reused). A *moderate* packet rate spread across
*thousands* of distinct destination IPs is **expensive** — it blows up the proxy's
per-destination state table, pins `com.docker.backend` CPU, and saturates the VM's
net stack until the Docker daemon itself becomes unresponsive.

This is why the usual "just lower the rate" intuition fails here: **rate is the
wrong knob.** You can set the DNS brute to a crawl and still wedge the host if the
resolver list is large, because each resolver is a distinct destination IP and the
proxy must track all of them concurrently.

## The incident (I-001) — what this looks like when it goes wrong

A `puredns` brute was pointed at a community resolver list of **15,487 distinct
resolver IPs** (e.g. the full `trickest/resolvers` list). That fanned every brute
query across ~15k distinct destination IPs. The host-side `com.docker.backend`
userspace proxy saturated on per-destination NAT tracking:

- host 1-minute load average climbed to **~112**,
- `com.docker.backend` pinned at **~1081% CPU**,
- the Docker daemon went down; in-container work and `docker exec` both stalled.

**The qps was not the killer — the resolver-IP count was.** Resolution required a
Docker Desktop restart. (A related failure, I-012: because `docker exec` rides the
*same* proxy, a wedged proxy also stalls any `docker exec`-based completion poller
with no timeout — never poll for completion via `docker exec` in an `until` loop;
use host-side bind-mounted `.done` markers instead.)

The same per-destination-IP pathology is **not DNS-specific**. Any in-container op
that fans out to many distinct destination IPs hits it:

- **`httpx` over a large host list at high concurrency** — bulk liveness over
  thousands of hosts at `-threads 60` re-triggered the spike (I-007). Cap bulk
  liveness at `-threads ~25` in-container or run it on the host.
- **`cero` / TLS-SAN against a whole CIDR** — a `/16`-class sweep is thousands of
  distinct destination IPs. Prefer cero against the **resolved origin A-record IPs**
  (few distinct IPs), not whole asnmap CIDRs — see
  `agent/references/tools/recon/cero.md`.
- **`nmap` / asnmap CIDR sweeps** — same shape; many distinct dest IPs.

## The danger knob is distinct destination IPs, not qps

Restate, because it is the whole point and it is counter-intuitive:

| Knob | In-container Docker Desktop impact |
|---|---|
| **Distinct destination IPs** (resolver-list size, CIDR breadth, host-list size) | **Dominant.** Each distinct dest IP is a tracked NAT/socket entry; thousands of them wedge `com.docker.backend`. |
| Query/packet rate (qps, `--rate-limit`, `-threads`) | Secondary — a *host-NIC* concern. It matters, but lowering it does **not** rescue you from a large-distinct-dest-IP fan-out. |

So the contradictory-sounding folklore "a large resolver list with per-resolver
rate-limiting is safe" is **false on Docker Desktop**: the large list is exactly
the hazard, independent of the rate.

## The safe envelope

**In-container (macOS/Windows Docker Desktop):**

- Keep DNS ops pointed at a **small validated resolver tier** — **≤~50 distinct
  resolver IPs**. A curated premium-anycast set (~16–40 IPs) both stays under the
  cap *and* gives better bulk throughput than a large "alive" public list (resolver
  *quality* under load governs throughput, not count).
- Keep bulk `httpx` liveness at **`-threads ~25`** in-container.
- Keep `cero` pointed at **resolved origin IPs**, not whole CIDRs; treat any
  whole-CIDR / large-host-list expansion as an escalation, not a default.
- Serialize network-heavy ops (one heavy net op at a time) — a wedge is easier to
  trip when two large fan-outs overlap.

**On the host (the escape hatch for large sets):**

- There is **no userspace proxy** in the host path, so the per-destination-IP
  ceiling does not apply. A large resolver list (thousands of IPs) is fine **on
  the host** — it is also dramatically faster (no proxy hop).
- Route DNS-heavy tools (`massdns`/`puredns`/`dnsx`/`subfinder`/`shuffledns`/
  `alterx`) and bulk-liveness `httpx` through the **audited host-execution path**;
  keep target HTTP / exploit / auth'd traffic **in the isolated container**.
- The audited host path runs through `vigil assess host-exec` (and, where wired,
  the auto-host-select on the composed `dns-discovery` / `web-discovery` verbs on
  macOS Docker Desktop), so the audit fields are retained.

**Native Linux / remote Docker:** this hazard is a **transparent no-op** — there is
no `com.docker.backend` proxy, so large resolver sets in-container are fine and the
host-routing guidance does not apply. Any code-side guard should detect the runtime
(macOS Docker Desktop vs. native/remote) and only engage on Docker Desktop.

## Quick checklist before any DNS-heavy / wide-fan-out op

1. **Count distinct destination IPs** the op will touch (resolver-list lines,
   CIDR size, host-list length). Not the qps — the **distinct dest IP count**.
2. If **>~50** distinct dest IPs **and** runtime is macOS/Windows Docker Desktop →
   **route to the host path** (or trim to the small validated tier).
3. If **≤~50** distinct dest IPs → safe in-container; still pace the rate for
   resolver fair-use / host-NIC headroom.
4. **Never** poll for completion with `docker exec` in an `until` loop — it rides
   the same proxy and will hang if the proxy wedges (I-012). Use host-side `.done`
   file markers.

## Cross-references

- `agent/skills/subdomain-enumeration/SKILL.md` "Host-CPU note" / "Docker-resource-safe
  profiles" — the in-skill mechanics and the resolver-IP cap near the `puredns -r`
  examples. The host-execution path for DNS-heavy recon (the escape hatch this guide
  routes large resolver sets to) is the host-routing layer the composed
  `dns-discovery` / `web-discovery` verbs auto-select on macOS (pass `--runtime host`
  to force it; `--runtime auto` is the default).
- `agent/references/tools/recon/puredns.md` and
  `agent/references/tools/recon/dnsx.md` — DNS-brute/resolve mechanics; the
  `--rate-limit` knob is **total qps** (not per-resolver), and is the *secondary*
  knob here.
- `agent/references/tools/recon/cero.md` — the resolved-origin-IP-vs-whole-CIDR
  decision (the cero instance of this same hazard).
- `agent/references/recon/rate-calibration.md` — the DNS-brute rate column is
  governed by resolver fair-use + runtime network capacity (this hazard), distinct
  from the genuine per-target-politeness columns.
- `agent/references/runtime-guides/cdn-ip-blocking.md` — unrelated network concern
  (our egress IP on a CDN reputation list), not the Docker proxy.
