# gau (Get All URLs)

**Purpose:** Fetch known URLs from multiple archive sources (Wayback Machine, AlienVault OTX, Common Crawl, URLScan).

**Recommended verb:** `vigil assess gau-endpoints` for the standard collection-and-ingest flow (cache-aware, runs gau and seats URLs into `work_items` in one shot). For body-fetch + secret extraction use `vigil assess gau-secrets`. For LinkFinder-style extraction over JS bundles use `vigil assess gau-js-endpoints`. Drop down to the typed `vigil assess kali gau` verb only for ad-hoc archive sweeps that do not need to feed the work buffer.

## Basic Usage

The `vigil assess kali gau` typed verb writes its own audit row and supports the standard required flags (`--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout`) per `shared-constraints.md §2`. The wrapper verbs above stamp these automatically.

Flag reference (used inside `vigil assess kali gau`):

**Single domain:** `vigil assess kali gau example.com --technique DISCOVERY --intent "historical URL harvest (passive)" --probe-kind fingerprint --phase collect --timeout 1800 -o /engagements/$ENGAGEMENT_KEY/scans/gau_example.txt`
**Include subdomains:** `--subs`
**With threads:** `--threads 5`
**Output to file:** `-o /engagements/$ENGAGEMENT_KEY/scans/gau_example.txt` (the typed verb translates `-o` to gau's actual `--o` long-flag form)
**Filter by extension:** `--blacklist png,jpg,gif,css,woff,svg`
**Specific providers:** `--providers wayback,otx,commoncrawl`
**Date range:** `--from 202301 --to 202412`

## Config

gau supports `~/.gau.toml` for persistent settings (API keys for OTX, custom providers).

## Pipeline Usage

The `gau-endpoints` / `gau-secrets` / `gau-js-endpoints` verbs already implement the
standard pipelines (collect → dedup → ingest, and collect → uro → httpx body capture →
trufflehog). Use the snippet below only when composing a one-off chain manually.

```bash
# Step 1 — collect historical URLs (passive, no target traffic)
vigil assess kali gau example.com --subs --threads 5 \
  --providers wayback,otx,commoncrawl,urlscan \
  -o /engagements/$ENGAGEMENT_KEY/scans/gau_example.txt \
  --technique DISCOVERY --intent "historical URL harvest for example.com (passive)" \
  --probe-kind fingerprint --phase collect --timeout 1800

# Step 2 — filter parameterized URLs for downstream fuzzing (host-side post-processing)
grep "=" /engagements/$ENGAGEMENT_KEY/scans/gau_example.txt | sort -u \
  > /engagements/$ENGAGEMENT_KEY/scans/gau_params.txt

# Step 3 — confirm live URLs via vigil assess kali httpx (separate audit row)
vigil assess kali httpx \
  -l /engagements/$ENGAGEMENT_KEY/scans/gau_example.txt \
  -status-code -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/gau_live.jsonl \
  --technique DISCOVERY --intent "live-URL confirmation for gau harvest" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

gau queries 4 sources vs. waybackurls' 1 (Wayback only). Output often contains duplicates — pipe through `sort -u` before ingestion.
