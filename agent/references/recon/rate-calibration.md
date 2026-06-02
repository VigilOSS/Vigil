# Per-Target Rate Calibration Table

Operators set per-target rate calibration before dispatch; recon-class specialists
pull values from this table rather than guessing. Vendor names appear as
**trait-match examples**, not canonical categories — pick the row on the trait,
not the brand.

This file was extracted from `agent/shared-constraints.md` §14 to keep the
first-load specialist constraints lighter — the rate-calibration table is only
load-bearing for recon-class roles (recon-specialist, surface-collector,
osint-analyst when running active enumeration). Other specialists do not need
this table loaded on every dispatch.

## Trait-row table

| Target trait | nmap profile | dir-fuzz rate | nuclei | DNS brute (puredns rl) | concurrent nmap procs |
|---|---|---|---|---|---|
| Cloud-fronted (any major CDN/edge — examples: Cloudflare, Akamai, Fastly, CloudFront) | `-T3 --max-rate 100` | 50–100 req/s | `--rate-limit 100-150 -bs 25 -c 25` | 800 (polite-CDN-fronted-target) | runtime-tier (Standard 2 / Heavy 4 / Comfortable 8) |
| Origin / single-server (no CDN, no WAF) | `-T2 --max-rate 30` | 5–10 req/s | `--rate-limit 30 -bs 10 -c 10` | 2500 (polite-residential) | runtime-tier (Standard 2 / Heavy 4 / Comfortable 8) |
| WAF-protected (any vendor WAF tier — Cloudflare WAF, Akamai App & API, F5 ASM, AWS WAF, Imperva) | `-T2 --max-rate 30` | 1–3 req/s | `--rate-limit 30 -bs 10 -c 10` | 800 (polite-CDN-fronted-target) | runtime-tier (Standard 2 / Heavy 4 / Comfortable 8) |
| High-friction policy / regulated (`.gov`, `.mil`, finance, healthcare) | `-T2 --max-rate 50 --host-timeout 1500s` | ≤2 req/s | `--rate-limit 30 -bs 10 -c 10` | 800 (polite-CDN-fronted-target) | runtime-tier (Standard 2 / Heavy 4 / Comfortable 8) |
| Vendor SaaS (e.g., Salesforce, ServiceNow, StatusPage, Auth0, Okta) | `-T3 --max-rate 60` | 20 req/s | `--rate-limit 60 -bs 15 -c 15` | 800 (polite-CDN-fronted-target — vendor-controlled DNS, lower rate) | runtime-tier (Standard 2 / Heavy 4 / Comfortable 8) |

## DNS-brute profile × runtime tier matrix

The DNS-brute column matches the canonical SKILL profile names in
`agent/skills/subdomain-enumeration/SKILL.md` "Docker-resource-safe profiles".
Available profiles per runtime tier (read `vigil runtime resources` to confirm
the active tier):

| Runtime tier | `polite-CDN-fronted-target` (cautious 800) | `polite-residential` (2500) | `bursty-OK` (5000) |
|---|---|---|---|
| Standard | available | available | NOT available |
| Heavy | available | available | available (opt-in via `--intent`) |
| Comfortable | available | available | available (default-eligible for trait rows that allow it) |

`bursty-OK` is never the matrix default; selection requires an explicit operator
note in `--intent`.

## Concurrent nmap procs cap

The "concurrent nmap procs" column scales with the runtime tier: Standard = 2,
Heavy = 4, Comfortable = 8. Consolidation is the rule — prefer one
`nmap -iL hosts.txt` over N parallel `nmap host` invocations (see
`agent/skills/port-scanning/SKILL.md` "Process consolidation"); the cap governs
split-by-profile parallel sweeps when consolidation is genuinely impractical.

## Tier selection and step-down

Tier-pick prose and step-down rules live in `agent/operator-core.md` "Recon
Dispatch Resource Policy". This file is the data; that file is the procedure
for picking and adjusting a row mid-engagement.
