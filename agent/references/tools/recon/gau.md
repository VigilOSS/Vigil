# gau (Get All URLs)

**Purpose:** Fetch known URLs from multiple archive sources (Wayback Machine, AlienVault OTX, Common Crawl, URLScan)
For live engagement targets, run gau via `aith assess kali gau` (typed verb, audit-flag-aware).

## Basic Usage

Run all gau probes via `aith assess kali gau` — the typed verb passes audit flags and writes the coverage row. Pass the required audit flags (`--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout`) per `shared-constraints.md §2`. See `agent/skills/kali-exec/SKILL.md` "Examples per verb — kali gau" for a complete annotated invocation.

Flag reference (used inside `aith assess kali gau`):

**Single domain:** `aith assess kali gau example.com --technique DISCOVERY --intent "historical URL harvest (passive)" --probe-kind fingerprint --phase collect --timeout 1800 -o /engagements/$ENGAGEMENT_KEY/scans/gau_example.txt`
**Include subdomains:** `--subs`
**With threads:** `--threads 5`
**Output to file:** `-o /engagements/$ENGAGEMENT_KEY/scans/gau_example.txt`
**Filter by extension:** `--blacklist png,jpg,gif,css,woff,svg`
**Specific providers:** `--providers wayback,otx,commoncrawl`
**Date range:** `--from 202301 --to 202412`

## Config

gau supports `~/.gau.toml` for persistent settings (API keys for OTX, custom providers).

## Pipeline Usage

Write gau output to a file first, then feed into downstream `aith assess kali` verbs. This keeps each tool's audit row separate and the coverage map truthful.

```bash
# Step 1 — collect historical URLs (passive, no target traffic)
aith assess kali gau example.com --subs --threads 5 \
  --providers wayback,otx,commoncrawl,urlscan \
  -o /engagements/$ENGAGEMENT_KEY/scans/gau_example.txt \
  --technique DISCOVERY --intent "historical URL harvest for example.com (passive)" \
  --probe-kind fingerprint --phase collect --timeout 1800

# Step 2 — filter parameterized URLs for downstream fuzzing (host-side post-processing)
grep "=" /engagements/$ENGAGEMENT_KEY/scans/gau_example.txt | sort -u \
  > /engagements/$ENGAGEMENT_KEY/scans/gau_params.txt

# Step 3 — confirm live URLs via aith assess kali httpx (separate audit row)
aith assess kali httpx \
  -l /engagements/$ENGAGEMENT_KEY/scans/gau_example.txt \
  -status-code -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/gau_live.jsonl \
  --technique DISCOVERY --intent "live-URL confirmation for gau harvest" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

gau queries 4 sources vs. waybackurls' 1 (Wayback only). Output often contains duplicates — pipe through `sort -u` before ingestion.
