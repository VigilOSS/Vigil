---
description: Subdomain-enumeration tool roles (subfinder/bbot/cero/alterx/puredns/dnsx/tlsx) with RAM and key needs, the per-profile puredns/dnsx flag sets, resolver-pool rate reality, and how to read a dns-discovery query-budget or per-resolver-qps WARN
skill: subdomain-enumeration
---

# Subdomain Enumeration Tooling

Decisions and bound rules live in `agent/skills/subdomain-enumeration/SKILL.md`; stage commands in
`agent/references/recon/subdomain-enum-manual-stages.md`; rate values in
`agent/references/recon/rate-calibration.md` (DNS-brute column and the runtime-tier matrix). This
file is the tool choice, the profile flag sets, and how to read the budget WARNs.

## Tool roles

| Tool | Stage | Memory during a run | Key | Tool reference |
|------|-------|---------------------|-----|----------------|
| `subfinder` | Phase 0 passive aggregator | single-digit MB | optional, fail-open | `subfinder.md` (key setup and which keys pay) |
| `bbot` | Phase 0 passive mop-up | 200-500 MB | optional | `bbot.md` (output is unreliable; harvest and validate) |
| `alterx` | Phase 2 permutation generator | low | none | `alterx.md` |
| `puredns` | Phase 1/2 brute and wildcard-aware resolve | ~500 MB at 5000 qps | none (resolver list) | `puredns.md` |
| `shuffledns` | fallback brute when puredns cannot run | lower than puredns | none | `shuffledns.md` |
| `dnsx` | Phase 3 resolution and record enrichment | ~150 MB | none | `dnsx.md` |
| `tlsx` / `cero` | Phase 3 TLS SAN harvest | ~100 MB (cero at `-c 100`) | none | `tlsx.md`, `cero.md` |
| `asnmap` | ASN to CIDR, feeds the gated cero escalation | low | `PDCP_API_KEY` required | `asnmap.md` |

## Resource profiles and rate reality

A DNS brute queries the public-resolver pool (`-r`), not the target, so the rate protects
resolver fair-use and local runtime networking. `--rate-limit` / `--dns-rate` is total qps across
the pool, not per resolver. Take the rate for each profile from `rate-calibration.md`; the other
flags each profile carries:

| Profile | puredns | dnsx typed verb | Use when |
|---|---|---|---|
| `polite-CDN-fronted-target` (default for unknown targets) | `--rate-limit <row> --wildcard-tests 30` | `--dnsx-profile polite-cdn` (the default) | CDN/WAF-fronted, regulated, household brand, wildcard returning canonical CNAMEs |
| `polite-residential` | `--rate-limit <row> --wildcard-batch 100000` | `--dnsx-profile polite-residential` | assessed SMB/residential target, no CDN signal |
| `bursty-OK` | `--rate-limit <row>` | `--dnsx-profile bursty-ok` | dedicated resolver pool that holds up under bulk load, single-engagement runtime, operator note in `--intent` |

`vigil assess kali dnsx --help` prints the `-rl`/`-t`/`-retry`/`-timeout` each dnsx profile sets.

- Past ~8-10k qps on a large (>100) pool, upstream resolvers throttle per source IP and the
  failures look like wildcard misses rather than rate errors.
- When the target is its own resolver (you point `-r` at the target's NS), the cap protects the
  target's authoritative server; that is the one case where the brute rate is target politeness.
- When the target's authoritative DNS is rate-limited at the apex, drop the cap to 1000-2000 qps;
  otherwise puredns takes the resolvers' full bandwidth without protecting them.
- massdns and dnsx packet rates load the host network stack outside the container's `--cpus`
  limit; on Docker Desktop the crash knob is distinct destination IPs, not qps (the skill's
  "Host-CPU note"; `agent/references/runtime-guides/docker-desktop-network-hazards.md`).

**Reading the budget WARNs.** `vigil assess dns-discovery` estimates
`wordlist_lines × target_count` (plus wildcard tests and productive-parent re-brutes) and WARNs
above `--query-budget` (default 5,000,000). It derives per-resolver qps as
`--dns-rate ÷ healthy resolvers` and WARNs above `--per-resolver-qps` (default 1500). Both are
advisory: trim `--wordlist-head`, the target set, or the rate before launching, and log the call.
