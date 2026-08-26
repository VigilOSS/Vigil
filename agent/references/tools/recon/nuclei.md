---
description: Template-based vulnerability scanning (CVEs, misconfigs, exposures)
skill: nuclei-scanning
---

# nuclei

**Purpose:** Vulnerability scanning with community templates
For live engagement targets, run `nuclei` via `vigil assess kali nuclei` (typed verb, audit-flag-aware).

Per-target rate calibration: `agent/references/runtime-guides/dispatch-resource-policy.md` "Recon Dispatch Resource Policy". Pull `--rate-limit / -bs / -c` from the matching trait row before running broad sweeps.

Run all nuclei probes via `vigil assess kali nuclei` — the typed verb passes audit flags and writes the coverage row. Pass the required audit flags (`--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout`) per `shared-constraints.md §2`. Use `vigil assess contract kali nuclei` for the current invocation profiles and wrapper-owned OOB policy.

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

OOB callbacks use the persisted Vigil tenant route. The operator first checks the output of
`vigil oob status --json` for `server=true`, `frpc=true`, `route_matches=true`, and a resolving
tenant domain. Then run the typed verb with `--oob-mode vigil`; the wrapper supplies that tenant
domain to Nuclei and rejects raw `-interactsh-url` / `-interactsh-server` flags so ambient
configuration cannot redirect callbacks. Nuclei's own JSONL finding is the correlation source for Nuclei-managed callback IDs.
Operator-provisioned `vigil oob client` + `mint` + `poll` remains the path for manual callback
probes; a separate Vigil client does not replace Nuclei's internal callback tracking.

**Disable interactsh:** omit the flag or pass `--oob-mode none` (the default). Use
`--oob-mode public` only for an explicit public-Interactsh data-egress decision.

## Rate Limiting & Performance

**Rate limit:** `-rate-limit 100` (requests/second)
**Concurrency:** `-c 25` (template concurrency)
**Bulk size:** `-bs 25` (hosts per template)
**Timeout:** `-timeout 10`
**Retries:** `-retries 2`
**Stats display:** `-stats`

### WAF resilience (typed flags)

- **`-mhe 50` (max-host-error) is injected by default.** nuclei's own default (~30) makes it
  ABANDON a host after that many errors — a WAF's 403 storm hits it in seconds, silently killing
  template coverage on exactly the hardest hosts. The raised default keeps the sweep on-host; raise
  it further on heavily-WAF'd targets (confirm `-mhe 0` semantics with `vigil assess kali tool-help nuclei`).
- **`-random-agent`** rotates the User-Agent so a UA-based scanner block does not drop every request.
- **`-H "<header>"`** (repeatable) sends browser-like headers past edge UA/header filters.
- **Lead with explicit `-t` template paths.** `-as` (automatic) keys off tech fingerprinting, which a
  CDN/WAF defeats, so it under-fires alone — treat `-as` as additive, not the primary template source.

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
