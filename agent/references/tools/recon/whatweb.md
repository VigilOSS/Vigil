# whatweb

**Purpose:** Web technology fingerprinting
For live engagement targets, run WhatWeb via `aith assess kali whatweb` (typed verb, audit-flag-aware).

## Basic Usage

Run all target-facing whatweb probes via `aith assess kali whatweb` — the typed verb passes audit flags and writes the coverage row. Pass the required audit flags (`--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout`) per `shared-constraints.md §2`. See `agent/skills/kali-exec/SKILL.md` "Examples per verb — kali whatweb" for a complete annotated invocation.

Flag reference (used inside `aith assess kali whatweb`):

**Basic (passive, aggression 1):** `aith assess kali whatweb https://target --technique DISCOVERY --intent "passive tech fingerprint" --probe-kind fingerprint --phase recon --timeout 300`
**Aggressive (aggression 3):** pass `-a 3` via `--extra-args`
**Multiple targets:** `--input-file /engagements/$ENGAGEMENT_KEY/scans/targets.txt` (via `--extra-args`)
**Verbose:** `--extra-args "-v"`

## Aggression Levels

| Level | Name | Description |
|-------|------|-------------|
| 1 | Stealthy | One HTTP request per target (default) |
| 2 | Unused | Reserved |
| 3 | Aggressive | Multiple requests, triggers additional tests |
| 4 | Heavy | Many requests, tests all plugins |

Use level 1 for initial fingerprinting, level 3 for deeper tech stack analysis.

## Auth & Headers

**Cookie:** `whatweb --cookie "session=abc123" https://target`
**Custom User-Agent:** `whatweb --user-agent "Mozilla/5.0" https://target`
**Custom header:** `whatweb --header "Authorization: Bearer token" https://target`
**Proxy:** `whatweb --proxy http://127.0.0.1:8080 https://target`

## Plugins

**List all plugins:** `whatweb --list-plugins`
**Run specific plugins:** `whatweb --plugins Apache,PHP,jQuery https://target`

## Output

Flag reference for output (pass via `--extra-args` or as direct flag to `aith assess kali whatweb`):

**JSON:** `--log-json /engagements/$ENGAGEMENT_KEY/scans/whatweb_results.json`
**Brief (one-liner per target):** `--log-brief /engagements/$ENGAGEMENT_KEY/scans/whatweb_brief.txt`
**Verbose log:** `--log-verbose /engagements/$ENGAGEMENT_KEY/scans/whatweb_verbose.txt`
**XML:** `--log-xml /engagements/$ENGAGEMENT_KEY/scans/whatweb_results.xml`

Always write output to `/engagements/$ENGAGEMENT_KEY/scans/` — writing to `/tmp` loses artifacts on container recreate.

## Tuning

**Wait between requests:** `--extra-args "--wait 0.5"`
**Max threads:** `--extra-args "--max-threads 10"`

**Pipeline usage:** Run whatweb after `aith assess kali httpx` confirms live hosts. Its plugin-based fingerprinting provides deeper tech detection than httpx's built-in `-tech-detect`, including specific version numbers and framework details.
