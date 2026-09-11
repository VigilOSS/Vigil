---
description: Historical URL discovery (Wayback, OTX, Common Crawl, URLScan); `vigil assess gau endpoints` is the recommended wrapper (cache-aware, ingests in one shot), with `gau secrets` and `gau js-endpoints` for body capture and JS-extracted route recovery
skill: gau-triage
---

# gau (Get All URLs)

**Purpose:** Fetch known URLs from multiple archive sources (Wayback Machine, AlienVault OTX, Common Crawl, URLScan).

**Recommended verb:** `vigil assess gau endpoints` for the standard collection-and-ingest flow (cache-aware, runs gau and seats URLs into `work_items` in one shot). For body-fetch + secret extraction use `vigil assess gau secrets`. For route extraction over JS bundles use `vigil assess gau js-endpoints`. Drop down to the typed `vigil assess kali gau` verb only for ad-hoc archive sweeps that do not need to feed the work buffer.

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

## Passive: no attribution header, no program rate cap, no per-host scoping

gau makes **zero requests to the target** — it queries third-party archives
(Wayback, Common Crawl, OTX, URLScan). Two consequences:

- **Mandatory program-attribution headers do not apply.** A Bugcrowd
  `X-Bug-Bounty: BugCrowd-<username>` header (required on active traffic — see
  `agent/references/tools/recon/katana.md`) is irrelevant to gau because gau never
  contacts the in-scope host. The same is true of the program's request-rate cap
  (e.g. "max 5 req/s on automated tooling"): that governs traffic *to the target*,
  which gau does not generate. Only the archive providers' own quotas apply.
- **Scope filtering happens downstream, not at collection.** Feeding a
  wildcard-scoped root with `--subs` (`gau acme-telco.example --subs`) over-collects
  archived URLs for *every* subdomain of the root, including ones not explicitly
  in scope. That is acceptable for passive collection precisely because gau issues
  no target traffic — the collected corpus is filtered to scope at ingestion/triage
  (`vigil assess scope filter`, work-buffer classification) **before** any active
  tool probes it. Choose Katana's explicit `-fs fqdn` traversal when the active
  crawl must remain on exact seeds; passive breadth is not a reason to make the
  active crawler follow sibling hosts.
  - For roots where the program carves out specific OOS subdomains (e.g.
    `*.acme-telco.example` in scope but `appointments.acme-telco.example` out), still feed
    the root to gau for breadth; the carve-out is enforced when the active phase
    consumes the corpus, not here.

## Provider quotas — be deliberate on large multi-domain sweeps

URLScan and OTX are quota-sensitive (URLScan especially without an API key);
Wayback and Common Crawl tolerate the most volume. For a large `--list` sweep
across many roots with `--subs`, prefer `--providers wayback,commoncrawl,otx`
(drop `urlscan`) and keep `--threads` low (3–5). gau is resilient — if one
provider rate-limits, it continues with the others — but a giant sweep with all
four providers at high threads is the fastest way to burn a quota. gau reads
domains from stdin or `--list`; the raw binary (under `kali job start`) takes
domains on **stdin** (`cat roots.txt | gau --subs ...`), while the typed
`vigil assess kali gau` verb exposes `--list`.

## Config

gau supports `~/.gau.toml` for persistent settings (API keys for OTX, custom providers).

## Pipeline Usage

The `gau endpoints` / `gau secrets` / `gau js-endpoints` verbs already implement the
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
