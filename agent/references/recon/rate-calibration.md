---
description: Per-target rate calibration table (Cloud-fronted, Origin, WAF-protected, High-friction, Vendor SaaS, Lab / CTF) plus the runtime-tier × DNS-profile matrix and the concurrent-nmap-procs cap. Recon-class roles load it on first use, before bounded per-host probes
---

# Per-Target Rate Calibration Table

Operators set per-target rate calibration before dispatch, and recon-class roles
(recon-specialist, surface-collector, osint-analyst) load this table on first use, before bounded
per-host probes (nmap, directory fuzz, nuclei); other roles load it when a dispatch points here.
This table is the one source for these values. Vendor names are trait-match examples: pick the row
on the trait, not the brand.

Pick the row from the wafw00f result first (`agent/references/tools/recon/wafw00f.md` maps each
result to a row), then from the hosting trait. The tier-picking and step-down procedure is in
`agent/references/runtime-guides/dispatch-resource-policy.md` "Picking a tier".

## Trait-row table

| Target trait | nmap profile | dir-fuzz rate | nuclei | DNS brute† (puredns rl) | concurrent nmap procs |
|---|---|---|---|---|---|
| Cloud-fronted (any major CDN/edge — examples: Cloudflare, Akamai, Fastly, CloudFront) | `-T3 --max-rate 100` | 50–100 req/s | `--rate-limit 100-150 -bs 25 -c 25` | 800 (cautious resolver-load) | runtime-tier (Standard 2 / Heavy 4 / Comfortable 8) |
| Origin / single-server (no CDN, no WAF) | `-T2 --max-rate 30` | 5–10 req/s | `--rate-limit 30 -bs 10 -c 10` | 2500 (moderate resolver-load) | runtime-tier (Standard 2 / Heavy 4 / Comfortable 8) |
| WAF-protected (any vendor WAF tier — Cloudflare WAF, Akamai App & API, F5 ASM, AWS WAF, Imperva) | `-T2 --max-rate 30` | 1–3 req/s | `--rate-limit 30 -bs 10 -c 10` | 800 (cautious resolver-load) | runtime-tier (Standard 2 / Heavy 4 / Comfortable 8) |
| High-friction policy / regulated (`.gov`, `.mil`, finance, healthcare) | `-T2 --max-rate 50 --host-timeout 540s` | ≤2 req/s | `--rate-limit 30 -bs 10 -c 10` | 800 (cautious resolver-load) | runtime-tier (Standard 2 / Heavy 4 / Comfortable 8) |
| Vendor SaaS (e.g., Salesforce, ServiceNow, StatusPage, Auth0, Okta) | `-T3 --max-rate 60` | 20 req/s | `--rate-limit 60 -bs 15 -c 15` | 800 (cautious resolver-load) | runtime-tier (Standard 2 / Heavy 4 / Comfortable 8) |
| Lab / CTF (a dedicated target the ROE explicitly clears for aggressive rates) | `-T4` | `-t 40`, no rate cap | `--rate-limit 150 -c 25` | per runtime tier | runtime-tier (Standard 2 / Heavy 4 / Comfortable 8) |

- **nmap** on every row except Lab / CTF also takes `--max-retries 2` and a `--host-timeout`
  (300s unless the row sets one; 600s behind bot management). A host that hits the timeout returns
  no port data, which the presence assertion in `agent/skills/port-scanning/SKILL.md` §4 catches.
- **dir-fuzz rate** is the request-per-second ceiling for every HTTP tool that walks paths or
  parameters on the target: ffuf `-rate`, feroxbuster `--rate-limit` (per directory scan, so pair
  it with `--scan-limit 1`; `agent/references/tools/fuzzing/feroxbuster.md`), and httpx `-rl` on a
  multi-path probe. Keep threads at or below the rate.
- A WAF of any tier, including a generic rule-set WAF, takes the WAF-protected row.

† **The DNS-brute column is resolver load and runtime capacity, not target politeness.** The
nmap, dir-fuzz and nuclei columns hit the target directly and are per-target politeness. A
`puredns`/`shuffledns`/`massdns` brute fans out to the public-resolver pool, so the target's
authoritative NS sees only a diluted, cached-NXDOMAIN trickle. The `puredns rl` ceiling is bounded by
public-resolver fair-use and per-resolver limits, and by local runtime network capacity (the Docker
Desktop userspace proxy and host NIC, where the dominant knob is the count of distinct resolver IPs,
not qps; `agent/references/runtime-guides/docker-desktop-network-hazards.md`). The number is total
qps across the whole pool, not per resolver. The trusted validation pool takes
`--rate-limit-trusted 200`, also a total across that pool. The CDN/WAF/regulated/Vendor-SaaS rows stay cautious for
resolver fair-use and Docker NAT pressure, not because the target's DNS is delicate. Only a brute
aimed directly at the target's own authoritative NS (no public pool) makes the rate a
target-politeness concern.

## DNS-brute profile × runtime tier matrix

The profile names match `agent/skills/subdomain-enumeration/SKILL.md` "Docker-resource-safe
profiles" and the dnsx-wrapper keys; per the footnote they are cautious / moderate / bursty
resolver-load tiers, not target politeness. Available profiles per runtime tier (`vigil runtime
resources` shows the active tier):

| Runtime tier | `polite-CDN-fronted-target` (cautious 800) | `polite-residential` (2500) | `bursty-OK` (5000) |
|---|---|---|---|
| Standard | available | available | NOT available |
| Heavy | available | available | available (opt-in via `--intent`) |
| Comfortable | available | available | available (default-eligible for trait rows that allow it) |

`bursty-OK` is never the matrix default; selection requires an explicit operator
note in `--intent`.

## Concurrent nmap procs cap

The "concurrent nmap procs" column scales with the runtime tier: Standard = 2, Heavy = 4,
Comfortable = 8. Prefer one `nmap -iL hosts.txt` over N parallel per-host runs
(`agent/skills/port-scanning/SKILL.md` "Process consolidation"); the cap governs split-by-profile
parallel sweeps when consolidation is impractical.

## Tier selection and step-down

Tier-pick and step-down rules live in
`agent/references/runtime-guides/dispatch-resource-policy.md` "Recon Dispatch Resource Policy":
this file is the data, that one the procedure for picking and adjusting a row mid-engagement.
