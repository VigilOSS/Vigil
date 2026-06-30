---
name: directory-fuzzing
description: Discover hidden directories, files, and endpoints on a web server
origin: Vigil
---

# Directory Fuzzing

## When to Activate

- Web server identified, need hidden content discovery
- Looking for admin panels, backups, configs, API endpoints
- After identifying web technology (for targeted wordlists)

## Tools

`ffuf` (primary — parameter/vhost fuzzing), `feroxbuster` (recursive content discovery), `curl` (verification)

## Rate-of-Business (RoB) Calibration

A self-imposed "never enumerate" restriction is a **methodology choice, not a target fact.** Light, targeted, low-rate content-discovery of *known* protected resources (login panels, admin paths, API prefixes) is "identifying an indicator of vulnerability" under standard bug-bounty RoB definitions — it is not active exploitation. The honest constraint is three-dimensional:

| Dimension | Compliant | Non-compliant |
|---|---|---|
| **Rate** | `--rate 20` or below; respect 429 back-off | Unbounded `-t 200` against a production target |
| **Wordlist size** | Curated / targeted lists (`dirb/common.txt`, `raft-medium-directories.txt`, known-good tech-specific lists) | Raft-large or custom-brute against a production API |
| **Stop condition** | Stop on first sensitive-data response; do not harvest bulk PII | Running to exhaustion after a credential-bearing endpoint appears |

When a prior dispatch rejected or soft-capped a content-discovery run on RoB grounds without evidence of the above violations, **re-dispatch with the self-imposed restriction relaxed** before accepting a coverage gap or a downgraded severity. A "maybe gated" verdict from a never-run fuzz pass is not a finding disposition — it is a coverage gap.

See `agent/operator-core.md` "Recon Dispatch Resource Policy" for the per-target rate column and `agent/rules/hunting.md` for the RoB doctrine that governs what a "minimal testing" restriction actually bars.

## Methodology

### 1. Baseline Response
```bash
vigil assess kali exec --technique FUZZ --intent "baseline 404 fingerprint for filter calibration" \
  --probe-kind baseline --phase consume-test --timeout 30 -- \
  curl -s -o /dev/null -w "Code: %{http_code}, Size: %{size_download}" https://TARGET/nonexistent12345
```

### 2. Common Path Discovery
```bash
vigil assess kali ffuf \
  -u https://TARGET/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -fc 404 \
  -o /engagements/$ENGAGEMENT_KEY/scans/ffuf_common.json -of json \
  --technique FUZZ --intent "common path discovery (dirb/common wordlist)" \
  --probe-kind payload --phase consume-test --timeout 1800

# Auto-calibrate variant
vigil assess kali ffuf \
  -u https://TARGET/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -ac \
  -o /engagements/$ENGAGEMENT_KEY/scans/ffuf_common_ac.json -of json \
  --technique FUZZ --intent "common path discovery auto-calibrate" \
  --probe-kind payload --phase consume-test --timeout 1800
```

### 3. Extension Fuzzing
```bash
vigil assess kali ffuf \
  -u https://TARGET/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -e .php,.html,.js,.txt,.bak,.old,.conf,.xml,.json,.yml,.env,.log,.sql,.zip,.tar.gz \
  -ac \
  -o /engagements/$ENGAGEMENT_KEY/scans/ffuf_extensions.json -of json \
  --technique FUZZ --intent "extension fuzzing (common wordlist + generic extensions)" \
  --probe-kind payload --phase consume-test --timeout 1800
# Tech-specific extensions: PHP(.phps,.phtml,.inc) ASP(.aspx,.config) Java(.jsp,.do,.action)
```

### 4. Filter Tuning

Apply these flags on any `vigil assess kali ffuf` invocation to tune signal/noise:
```
-fc 404,403,301        # Status code filter
-fs 1234               # Response size filter
-fw 42 / -fl 10        # Word/line count filter
-mc 200,301,302,403    # Match only specific codes
```

### 5. Recursive Discovery
```bash
# feroxbuster for recursive content discovery (faster, auto-recurses, Rust-based)
vigil assess kali exec --technique FUZZ \
  --intent "recursive dir discovery (feroxbuster smart + auto-tune)" \
  --probe-kind payload --phase consume-test --timeout 1800 -- \
  feroxbuster -u https://TARGET -w /usr/share/wordlists/dirb/common.txt --smart --auto-tune \
    -d 3 -t 50 -o /engagements/$ENGAGEMENT_KEY/scans/ferox_results.txt

# feroxbuster with extensions
vigil assess kali exec --technique FUZZ \
  --intent "recursive dir discovery with extension variants" \
  --probe-kind payload --phase consume-test --timeout 1800 -- \
  feroxbuster -u https://TARGET -w /usr/share/wordlists/dirb/common.txt \
    -x php,html,js,txt,bak -d 2 --auto-tune

# ffuf for targeted sub-path fuzzing after feroxbuster finds interesting directories
vigil assess kali ffuf \
  -u https://TARGET/admin/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -ac \
  -o /engagements/$ENGAGEMENT_KEY/scans/ffuf_admin.json -of json \
  --technique FUZZ --intent "targeted sub-path fuzz under /admin/" \
  --probe-kind payload --phase consume-test --timeout 1800
```

Run each directory-fuzz sweep synchronously — one blocking `vigil assess kali <verb> …
--timeout N` at a time. Specialists do NOT background target traffic or use `vigil assess kali
job start` (operator-only; see `agent/shared-constraints.md` §2); a long sweep is handled by a
generous `--timeout`. Never use broad `pkill`/`killall` (e.g. `pkill -f ffuf`) — it stomps
sibling agents' processes in the shared runtime. See
`agent/references/runtime-guides/kali-cli.md` "Process cleanup discipline" for the full pattern.

### 6. Wordlist Escalation
```bash
# L1: /usr/share/wordlists/dirb/common.txt (~4,600)
# L2: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt (~20,000)
# L3: /usr/share/wordlists/dirbuster/directory-list-2.3-big.txt (~220,000)
# Specialized: /usr/share/seclists/Discovery/Web-Content/raft-medium-{directories,files}.txt
# API: /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```

### 7. Backup and Sensitive Files
```bash
vigil assess kali ffuf \
  -u https://TARGET/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e .bak,.old,.orig,.save,.swp,.tmp,~,.copy \
  -ac \
  -o /engagements/$ENGAGEMENT_KEY/scans/ffuf_backups.json -of json \
  --technique INFO-DISCLOSURE --intent "backup and sensitive file extension sweep" \
  --probe-kind payload --phase consume-test --timeout 1800

vigil assess kali exec --technique INFO-DISCLOSURE \
  --intent "sensitive file checklist (.env, .git, .htaccess, wp-config)" \
  --probe-kind fingerprint --phase consume-test --timeout 60 -- bash -c '
for f in .env .git/config .htaccess web.config wp-config.php .DS_Store; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$f")
  [ "$code" != "404" ] && echo "$f -> $code"
done
curl -s https://TARGET/.git/HEAD
curl -s https://TARGET/.svn/entries | head -5
'
```

### 8. SaaS API Namespace Fuzzing

SaaS platforms nest APIs under versioned/namespaced prefixes. Fuzz each known prefix separately:
```bash
# Discover API versions and namespaces
vigil assess kali exec --technique DISCOVERY \
  --intent "SaaS API namespace prefix enumeration" \
  --probe-kind fingerprint --phase consume-test --timeout 120 -- bash -c '
for prefix in /api/v1 /api/v2 /api/v3 /api/internal /api/admin /api/lotus /api/private \
  /sc/v1 /sc/v2 /admin/api /admin/api/v2 /rosetta/api /theming/api /wfm/api /qa/api \
  /sell/api /explore/api /embeddable/api /collaboration; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET$prefix" -u "$AUTH")
  [ "$code" != "404" ] && echo "$code $prefix"
done
'

# For each live prefix, fuzz endpoints
vigil assess kali ffuf \
  -u "https://TARGET/api/v2/FUZZ.json" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -ac \
  -o /engagements/$ENGAGEMENT_KEY/scans/ffuf_api_v2.json -of json \
  --technique DISCOVERY --intent "API endpoint fuzz under /api/v2/" \
  --probe-kind payload --phase consume-test --timeout 1800
```

**Header anomaly check:** On every non-404 response, inspect `Location`, `X-Served-By`, `Via`, `Server`, and any vendor-specific headers (e.g., `zendesk-service`, `x-envoy-decorator-operation`) for internal service names, K8s hostnames, or tenant-identifying data.

### 9. Virtual Host / Subdomain
```bash
vigil assess kali ffuf \
  -u https://TARGET \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.TARGET" \
  -ac \
  -o /engagements/$ENGAGEMENT_KEY/scans/ffuf_vhosts.json -of json \
  --technique DISCOVERY --intent "vhost/subdomain enumeration via Host header fuzzing" \
  --probe-kind payload --phase consume-test --timeout 1800
```

### 10. Triage, Output and Verification

Status/size filters (`-fc`, `-fs`, `-ac`) thin the noise but cannot catch a soft-200 that returns
a `200` with a custom-error body, or an admin page that differs only in size class from the bulk of
hits. After a sweep, rank the surviving results with `vigil assess anomaly-score` to surface the
genuine odd-ones-out. ffuf's JSON `results` carry `status`, `length`, `words`, `lines`, `url` —
exactly the oracle's fields (rename only the hyphenated `content-type`):

```bash
# Rank the ffuf hit set written by §2–§9 (e.g. ffuf_common.json):
jq '[.results[] | {url, status, length, words, lines, content_type: .["content-type"]}]' \
  /engagements/$ENGAGEMENT_KEY/scans/ffuf_common.json > /tmp/dir_pop.json
vigil assess anomaly-score /tmp/dir_pop.json --top 15
#   #1  score=4.17  status=200  len=8800  url=https://TARGET/admin   ← off-cluster: big body, unique title
#       ^ length_bucket=...  ^ title='admin login'  ^ words_bucket=...
```

The high-scoring paths are the ones that broke from the bulk response shape — an unusually large
body, a distinct title, a lone redirect, a rare status — i.e. the admin panels, debug pages, and
soft-200s worth manual review. A path's content-type or notable-headers (`set-cookie`,
`www-authenticate`, `location`) being rare in the set also lifts its score. Because the oracle
buckets sizes, near-identical boilerplate pages cluster and stop drowning the signal; it surfaces
category outliers, not byte-level deltas. Then verify the top hits by hand:

```bash
# Main output (embedded in every ffuf call above via -o / -of json)
# Verify a discovered path:
vigil assess kali exec --technique DISCOVERY \
  --intent "HEAD verification of discovered path" \
  --probe-kind fingerprint --phase consume-test --timeout 30 -- \
  curl -sI https://TARGET/discovered_path
```

## What to Record

- Discovered paths with status codes and response sizes
- Sensitive files found (.env, .git, backups, config)
- Admin/management interfaces discovered
- Wordlists used and filter/matcher settings
- Whether authenticated fuzzing was performed
- New endpoints to feed into work buffer via `vigil assess ingest-endpoints`

## Extended Resources

- `agent/operator-core.md` "Recon Dispatch Resource Policy" — canonical per-target rate calibration table; the dir-fuzz column drives `-rate / -t / --rate-limit` per trait row.
- `agent/references/tools/fuzzing/ffuf.md` — ffuf flags, filter/matcher options, wordlist selection
- `agent/references/tools/fuzzing/feroxbuster.md` — feroxbuster recursive scanning, auto-tune, smart mode
