---
description: Template-based vulnerability scanning (CVEs, misconfigs, exposures)
skill: nuclei-scanning
---

# nuclei

**Purpose:** Vulnerability scanning with community templates
For live engagement targets, run `nuclei` via `vigil assess kali nuclei` (typed verb, audit-flag-aware).

Per-target rate calibration: `agent/operator-core.md` "Recon Dispatch Resource Policy". Pull `--rate-limit / -bs / -c` from the matching trait row before running broad sweeps.

Run all nuclei probes via `vigil assess kali nuclei` — the typed verb passes audit flags and writes the coverage row. Pass the required audit flags (`--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout`) per `shared-constraints.md §2`. See `agent/skills/kali-exec/SKILL.md` "Examples per verb — kali nuclei" for complete invocation profiles with OOB configuration.

## Basic Scanning

Flag reference (used inside `vigil assess kali nuclei`):

**Single target:** `-u https://target`
**Multiple targets:** `-l /engagements/$ENGAGEMENT_KEY/scans/targets.txt`
**By severity:** `-severity critical,high`
**By tag:** `-tags cve,rce,misconfig`
**Exclude tags:** `-exclude-tags dos,fuzz,intrusive,brute-force` — the canonical politeness/safety exclusion set. The `vigil assess kali nuclei` wrapper **injects this set by default** when you do not pass your own `-exclude-tags`/`-etags`, so broad sweeps never fire DoS/fuzz/intrusive/brute-force templates against production-like in-scope targets (CR-27). Passing your own `-exclude-tags` overrides it verbatim (no merge).

## Template Selection

**Specific template:** `-t http/cves/2021/CVE-2021-44228.yaml`
**Template directory:** `-t /custom/templates/`
**Auto-scan (tech-based):** `-as` (detects tech stack, runs matching templates)
**List templates:** `vigil assess kali exec --technique HEALTH --intent "nuclei template list" --probe-kind fingerprint --phase recon --timeout 30 -- nuclei -tl`
**Workflows:** `-w http/workflows/wordpress-workflow.yaml`

Note: Template paths use protocol prefix (e.g., `http/cves/`, `dns/`, `network/`).

## Auth & Headers

**Custom header:** `-header "Cookie: session=abc"`
**Header from file:** `-header-file headers.txt`
**Proxy through Burp:** `-proxy http://127.0.0.1:8080`

## OOB Callbacks

OOB callbacks use the shared interactsh infrastructure — agents do not pass raw interactsh URLs directly. Instead:
1. `vigil oob status --json` — confirm `server=true`, `frpc=true`.
2. `vigil oob client start <name> --engagement <key> --agent <role>` — start the listener client.
3. Pass the configured OOB server domain (`domain` from step 1, e.g. `oob.example.com`) as `-interactsh-url <domain>` so nuclei's own per-template callbacks land on the shared listener. Nuclei appends its own unique id per probe; `vigil oob poll` extracts that label.
4. `vigil oob poll --client <name>` — correlate probe<->callback after probes fire; a matched row is the confirmed hit. `vigil oob client logs <name> --lines 80` is a raw listener tail for infra debugging only, not a correlation source.

**Disable interactsh (when OOB unavailable):** `-no-interactsh`

## Rate Limiting & Performance

**Rate limit:** `-rate-limit 100` (requests/second)
**Concurrency:** `-c 25` (template concurrency)
**Bulk size:** `-bs 25` (hosts per template)
**Timeout:** `-timeout 10`
**Retries:** `-retries 2`
**Stats display:** `-stats`

## Output

**Text:** `-o /engagements/$ENGAGEMENT_KEY/scans/nuclei_results.txt`
**JSON Lines:** `-jsonl -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_results.jsonl`
**Markdown:** `-me /engagements/$ENGAGEMENT_KEY/scans/nuclei_md/` (markdown export)

Always write output to `/engagements/$ENGAGEMENT_KEY/scans/` — writing to `/tmp` loses artifacts on container recreate.

## Template Management

**Update templates:** `vigil assess kali exec --technique HEALTH --intent "nuclei template update" --probe-kind fingerprint --phase recon --timeout 120 -- nuclei -ut`
**Custom template directory:** `-td /path/to/templates/` (override default template location)

## Triage Rules

From the nuclei-scanning skill — apply these to results:
- **Critical/High:** Validate manually, record as findings if confirmed
- **Medium/Low:** Intelligence — inform testing priorities
- **Info:** Tech stack enrichment for recon data
