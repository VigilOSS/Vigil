# gau (Get All URLs)

**Purpose:** Fetch known URLs from multiple archive sources (Wayback Machine, AlienVault OTX, Common Crawl, URLScan)
For live engagement targets, run gau via `aith assess kali gau` (typed verb, audit-flag-aware).

## Basic Usage

**Single domain:** `gau target.example`
**Include subdomains:** `gau --subs target.example`
**With threads:** `gau target.example --threads 5`
**Output to file:** `gau target.example --o urls.txt`
**Filter by extension:** `gau target.example --blacklist png,jpg,gif,css,woff,svg`
**Specific providers:** `gau target.example --providers wayback,otx,commoncrawl`
**Date range:** `gau target.example --from 202301 --to 202412`
**From stdin:** `echo "target.example" | gau`

## Config

gau supports `~/.gau.toml` for persistent settings (API keys for OTX, custom providers).

## Pipeline Usage

Feed output into downstream tools:
- `gau target.example | grep "=" | sort -u` → parameterized URLs for fuzzing
- `gau target.example | httpx -silent -status-code` → verify which URLs are still live
- `gau target.example | grep "=" | sort -u | dalfox pipe` → XSS scanning
- `gau target.example | grep -iE "\.js$" | sort -u` → JS files for source analysis

gau queries 4 sources vs. waybackurls' 1 (Wayback only). Output often contains duplicates — pipe through `sort -u` before ingestion.
