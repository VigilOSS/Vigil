---
description: HTTP probing, tech detection, live host confirmation
skill: web-recon
---

# httpx

**Purpose:** Fast multi-purpose HTTP toolkit — live host probing, tech detection, status codes, titles
For live engagement targets, run httpx via `vigil assess kali httpx` (typed verb, audit-flag-aware).

Per-target rate calibration (when probing in volume): `agent/references/runtime-guides/dispatch-resource-policy.md` "Recon Dispatch Resource Policy". Pull `-rl` and `-timeout` values from the matching trait row before running large batches.

## Probing

Run all target-facing httpx probes via `vigil assess kali httpx` — the typed verb passes audit flags and writes the coverage row. Pass the required audit flags (`--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout`) per `shared-constraints.md §2`. See `agent/skills/kali-exec/SKILL.md` "Examples per verb — kali httpx" for a complete annotated invocation.

Flag reference (used inside `vigil assess kali httpx`):

**Probe from file:** `-l /engagements/$ENGAGEMENT_KEY/scans/targets.txt -status-code -title -web-server -cl`
**Follow redirects:** `-follow-redirects`
**With path appended:** `-path /api/v1`
**Alt-port liveness (I-6):** `-ports 80,443,8080,8443` — httpx defaults to 80/443 only, so an
alt-port-only host (8080/8443/…) reads as dead and is never seeded/crawled unless you pass the
port list explicitly. Reach for this whenever a target's scope includes non-standard ports.

## Fingerprinting

Flag reference (used inside `vigil assess kali httpx`):

**Tech detection:** `-tech-detect`
**TLS certificate info:** `-tls-grab`
**CDN detection:** `-cdn`
**IP resolution:** `-ip`
**Favicon hash (Shodan matching):** `-favicon`
**Response hash:** `-hash md5`
**Screenshot:** `-screenshot`

## Filtering & Matching

**Match by status code:** `-mc 200,301,302,403`
**Filter by status code:** `-fc 404,503`
**Match by content type:** `-match-ct "text/html"`
**Filter by CDN:** `-filter-cdn cloudflare,akamai`

## Auth & Headers

**Custom header:** `-H "Cookie: session=abc"`
**Multiple headers:** `-H "Authorization: Bearer token" -H "X-Custom: value"`

## Rate Limiting & Performance

**Rate limit:** `-rate-limit 50` (requests per second)
**Threads:** `-threads 25`
**Timeout:** `-timeout 10`

## Output

**JSON output:** `-json -o /engagements/$ENGAGEMENT_KEY/scans/httpx_live.jsonl`
**CSV output:** `-csv -o /engagements/$ENGAGEMENT_KEY/scans/httpx_live.csv`
**Save response bodies:** `-store-response -store-response-dir /engagements/$ENGAGEMENT_KEY/scans/httpx_bodies`

Always write output to `/engagements/$ENGAGEMENT_KEY/scans/` — writing to `/tmp` loses artifacts on container recreate.

## Passthrough flags (`--extra-args`)

`--extra-args` shlex-splits a raw string and appends it to the argv after every typed flag above —
prefer a typed flag when one exists (it is validated at parse time and documented here); reach for
`--extra-args` only for the long tail below. Example: `--extra-args '-mr "(?i)internal"'`.

Common passthrough flags not yet typed on the wrapper:

- `-mr` / `-match-regex` — match response body/header against a regex.
- `-body` / `-d` — send a request body (e.g. for `-x POST`).
- `-method` / `-x` — HTTP method to use for the probe (default GET).
- `-json` field selection (e.g. `-irr` / `-include-response` to embed the response body in each JSON row) — spelling has shifted across httpx releases, so confirm it first (see below).

If you hit a flag that isn't typed and isn't in this list, check the live `-h` output first
(`vigil assess kali tool-help httpx`) rather than guessing — the installed httpx version is the
source of truth for exact spelling.

**Pipeline usage:** httpx is glue between subdomain enumeration and scanning. Write subfinder/puredns output to a file first, then pass it to `vigil assess kali httpx -l <file>` so each step has its own audit row and the coverage map stays truthful. Piping between tools in a single `kali exec` heredoc loses the per-tool audit rows.

Example two-step pattern:
```bash
# Step 1 — passive enum writes to file (vigil assess kali subfinder ...)
# Step 2 — httpx consumes the file
vigil assess kali httpx \
  -l /engagements/$ENGAGEMENT_KEY/scans/subs_resolved.txt \
  -status-code -title -tech-detect -tls-grab -json \
  -o /engagements/$ENGAGEMENT_KEY/scans/httpx_live.jsonl \
  --technique DISCOVERY --intent "live-host + tech confirm over resolved subs" \
  --probe-kind fingerprint --phase recon --timeout 1200
```
