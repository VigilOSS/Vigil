# httpx

**Purpose:** Fast multi-purpose HTTP toolkit — live host probing, tech detection, status codes, titles
For live engagement targets, run httpx via `aith assess kali httpx` (typed verb, audit-flag-aware).

Per-target rate calibration (when probing in volume): `agent/operator-core.md` "Recon Dispatch Resource Policy". Pull `-rl` and `-timeout` values from the matching trait row before running large batches.

## Probing

Run all target-facing httpx probes via `aith assess kali httpx` — the typed verb passes audit flags and writes the coverage row. Pass the required audit flags (`--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout`) per `shared-constraints.md §2`. See `agent/skills/kali-exec/SKILL.md` "Examples per verb — kali httpx" for a complete annotated invocation.

Flag reference (used inside `aith assess kali httpx`):

**Probe from file:** `-l /engagements/$ENGAGEMENT_KEY/scans/targets.txt -status-code -title -server -content-length`
**Follow redirects:** `-follow-redirects`
**With path appended:** `-path /api/v1`

## Fingerprinting

Flag reference (used inside `aith assess kali httpx`):

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

Always write output to `/engagements/$ENGAGEMENT_KEY/scans/` — writing to `/tmp` loses artifacts on container recreate.

**Pipeline usage:** httpx is glue between subdomain enumeration and scanning. Write subfinder/puredns output to a file first, then pass it to `aith assess kali httpx -l <file>` so each step has its own audit row and the coverage map stays truthful. Piping between tools in a single `kali exec` heredoc loses the per-tool audit rows.

Example two-step pattern:
```bash
# Step 1 — passive enum writes to file (aith assess kali subfinder ...)
# Step 2 — httpx consumes the file
aith assess kali httpx \
  -l /engagements/$ENGAGEMENT_KEY/scans/subs_resolved.txt \
  -status-code -title -tech-detect -tls-grab -json \
  -o /engagements/$ENGAGEMENT_KEY/scans/httpx_live.jsonl \
  --technique DISCOVERY --intent "live-host + tech confirm over resolved subs" \
  --probe-kind fingerprint --phase recon --timeout 1200
```
