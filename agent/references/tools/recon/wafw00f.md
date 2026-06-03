---
description: WAF identification and fingerprinting
---

# wafw00f

**Purpose:** Web Application Firewall identification and fingerprinting.
For live engagement targets, run wafw00f via `vigil assess kali wafw00f` (typed verb, audit-flag-aware).

## Run FIRST in the recon sequence

`wafw00f` is the first tool in the `wafw00f → nmap → httpx → whatweb → nuclei → ffuf →
(nikto IF triggered)` mandatory recon order, because the WAF tier it identifies drives the
rate-limit choice for every later tool. Running nmap, httpx, ffuf, or nuclei before
wafw00f means picking a rate profile blind — the common consequence is tripping the WAF
early and either getting rate-limited for the rest of the engagement or losing port-scan
data to host-timeout retries.

The recon-specialist's pre-output self-check requires a wafw00f run for every live
in-scope host with the WAF tier recorded. Skip-or-defer is not a supported mode.

## Basic Usage

Run all target-facing wafw00f probes via `vigil assess kali wafw00f` — the typed verb passes audit flags and writes the coverage row. Pass the required audit flags (`--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout`) per `shared-constraints.md §2`. See `agent/skills/kali-exec/SKILL.md` "Examples per verb — kali wafw00f" for a complete annotated invocation.

Flag reference (used inside `vigil assess kali wafw00f`):

**Single target:** `vigil assess kali wafw00f https://target --technique DISCOVERY --intent "WAF identification" --probe-kind fingerprint --phase recon --timeout 300`
**Verbose:** pass `-v` via `--extra-args`
**Test all WAFs (not just first match):** `-a` (via `--extra-args`)
**Multi-host batch from file:** `--input-list /engagements/$ENGAGEMENT_KEY/scans/live_hosts.txt` (typed flag)
**List all detectable WAFs:** `vigil assess kali exec --technique HEALTH --intent "wafw00f list WAFs" --probe-kind fingerprint --phase recon --timeout 30 -- wafw00f -l`
**Custom headers:** `--extra-args "-H 'Cookie: session=abc'"`
**Proxy:** `--extra-args "-p http://127.0.0.1:8080"`
**Output (CSV):** `-o /engagements/$ENGAGEMENT_KEY/scans/wafw00f_results.csv` (via `--extra-args`)

Note: wafw00f outputs CSV format with `-o`. It does not support `-f json`. For JSON,
parse CSV output or capture stdout.

## Multi-host batch invocation (canonical)

```bash
vigil assess kali wafw00f --input-list /engagements/$ENGAGEMENT_KEY/scans/live_hosts.txt \
  --extra-args "-a -o /engagements/$ENGAGEMENT_KEY/scans/wafw00f_results.csv" \
  --technique RECON --intent "WAF tier sweep across in-scope live hosts" \
  --probe-kind fingerprint --phase recon --timeout 1200
```

Drive nmap/httpx/ffuf/nuclei rate decisions per host from the CSV output. Don't average
the WAF tier across the batch — CDN-fronted hosts and bare-origin hosts in the same
scope need different rate profiles.

## WAF-tier rate adjustment table

Map the wafw00f finding to a rate profile for every later tool. The categories below are
load-bearing — a profile mismatch costs the engagement either coverage (host-timeout) or
the rest of the engagement (WAF lockout).

| WAF tier (wafw00f finding) | nmap | httpx | ffuf | nuclei |
|---|---|---|---|---|
| **No WAF detected** | `-T4` (default) | default rate | `-t 40` (default) | `-rate-limit 150 -c 25` |
| **Basic WAF** (generic rule-set tier) | `-T3 --max-rate 500 --max-retries 2` | `-rl 100` | `-t 20 -rate 50` | `-rate-limit 100 -c 20` |
| **CDN-fronted (any major CDN / edge platform)** | `-T3 --max-rate 200 --max-retries 2 --host-timeout 300s` | `-rl 50 -timeout 10` | `-t 10 -rate 25` | `-rate-limit 75 -c 15 -bs 15` |
| **WAF-protected (enterprise WAF tier)** or **cautious-tier profile (high-friction policy / regulated targets)** | `-T3 --max-rate 100 --max-retries 2 --host-timeout 600s` | `-rl 25 -timeout 15` | `-t 5 -rate 10` | `-rate-limit 25 -c 10 -bs 10` |

The cautious-tier row is what hardened policy / regulated targets typically need —
anything more aggressive produces silent host-timeout failures for nmap and intercepted
HTTP probes for httpx/ffuf/nuclei. The canonical per-target rate calibration table
(with vendor examples for each trait) lives in `agent/operator-core.md` "Recon Dispatch
Resource Policy".

## Operational notes

- Re-run wafw00f when scope expands (new subdomain via TLS SAN extraction or
  subdomain-enumeration). The new host may sit behind a different WAF tier than the
  apex — rate the new host on its own findings.
- `wafw00f` itself is rate-aware enough at default settings; do not bypass it with
  custom raw-curl probes for WAF detection because the resulting rate-limit profile
  will be guesswork instead of evidence.
- Cross-reference the cautious-tier rate profile in `agent/references/tools/recon/nikto.md`
  ("Pause and rate control" + the cautious-tier profile section) — nikto is conditional,
  but when it fires on a cautious-tier target the same rate constraints apply.

**Why it matters:** Identify which WAF is in use BEFORE attempting bypass payloads.
Different WAFs require different evasion techniques (see tamper scripts in sqlmap.md and
encoder chains in wfuzz.md). Testing blind wastes time and may trigger rate limiting or
IP bans.
