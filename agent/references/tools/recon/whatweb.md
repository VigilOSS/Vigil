# whatweb

**Purpose:** Web technology fingerprinting
For live engagement targets, run WhatWeb via `aith assess kali whatweb` (typed verb, audit-flag-aware).

## Basic Usage

**Basic (passive):** `whatweb https://target`
**Aggressive:** `whatweb -a 3 https://target`
**Multiple targets:** `whatweb --input-file=/engagements/$ENGAGEMENT_KEY/scans/targets.txt`
**Verbose:** `whatweb -v https://target`

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

**JSON:** `whatweb --log-json=results.json https://target`
**Brief (one-liner per target):** `whatweb --log-brief=results.txt https://target`
**Verbose log:** `whatweb --log-verbose=results.txt https://target`
**XML:** `whatweb --log-xml=results.xml https://target`
**Quiet (no banner):** `whatweb --color=never --quiet https://target`

## Tuning

**Wait between requests:** `whatweb --wait 0.5 https://target`
**Max threads:** `whatweb --max-threads 10 https://target`

**Pipeline usage:** Run whatweb after httpx confirms live hosts. Its plugin-based fingerprinting provides deeper tech detection than httpx's built-in `-tech-detect`, including specific version numbers and framework details.
