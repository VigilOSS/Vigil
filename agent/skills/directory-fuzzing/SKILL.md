---
name: directory-fuzzing
description: Discover hidden directories, files, and endpoints on a web server
origin: AI Threat Hunting
---

# Directory Fuzzing

## When to Activate

- Web server identified, need hidden content discovery
- Looking for admin panels, backups, configs, API endpoints
- After identifying web technology (for targeted wordlists)

## Tools

`ffuf` (primary — parameter/vhost fuzzing), `feroxbuster` (recursive content discovery), `curl` (verification)

## Methodology

### 1. Baseline Response
```bash
curl -s -o /dev/null -w "Code: %{http_code}, Size: %{size_download}" https://TARGET/nonexistent12345
```

### 2. Common Path Discovery
```bash
ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 404
ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -ac  # Auto-calibrate
```

### 3. Extension Fuzzing
```bash
ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt \
  -e .php,.html,.js,.txt,.bak,.old,.conf,.xml,.json,.yml,.env,.log,.sql,.zip,.tar.gz
# Tech-specific: PHP(.phps,.phtml,.inc) ASP(.aspx,.config) Java(.jsp,.do,.action)
```

### 4. Filter Tuning
```bash
-fc 404,403,301        # Status code filter
-fs 1234               # Response size filter
-fw 42 / -fl 10        # Word/line count filter
-mc 200,301,302,403    # Match only specific codes
```

### 5. Recursive Discovery
```bash
# feroxbuster for recursive content discovery (faster, auto-recurses, Rust-based)
feroxbuster -u https://TARGET -w /usr/share/wordlists/dirb/common.txt --smart --auto-tune \
  -d 3 -t 50 -o /engagement/scans/ferox_results.txt

# feroxbuster with extensions
feroxbuster -u https://TARGET -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,js,txt,bak -d 2 --auto-tune

# ffuf for targeted sub-path fuzzing after feroxbuster finds interesting directories
ffuf -u https://TARGET/admin/FUZZ -w /usr/share/wordlists/dirb/common.txt -ac
```

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
ffuf -u https://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e .bak,.old,.orig,.save,.swp,.tmp,~,.copy
for f in .env .git/config .htaccess web.config wp-config.php .DS_Store; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$f")
  [ "$code" != "404" ] && echo "$f -> $code"
done
curl -s https://TARGET/.git/HEAD
curl -s https://TARGET/.svn/entries | head -5
```

### 8. SaaS API Namespace Fuzzing

SaaS platforms nest APIs under versioned/namespaced prefixes. Fuzz each known prefix separately:
```bash
# Discover API versions and namespaces
for prefix in /api/v1 /api/v2 /api/v3 /api/internal /api/admin /api/lotus /api/private \
  /sc/v1 /sc/v2 /admin/api /admin/api/v2 /rosetta/api /theming/api /wfm/api /qa/api \
  /sell/api /explore/api /embeddable/api /collaboration; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET$prefix" -u "$AUTH")
  [ "$code" != "404" ] && echo "$code $prefix"
done

# For each live prefix, fuzz endpoints
ffuf -u "https://TARGET/api/v2/FUZZ.json" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -ac
```

**Header anomaly check:** On every non-404 response, inspect `Location`, `X-Served-By`, `Via`, `Server`, and any vendor-specific headers (e.g., `zendesk-service`, `x-envoy-decorator-operation`) for internal service names, K8s hostnames, or tenant-identifying data.

### 9. Virtual Host / Subdomain
```bash
ffuf -u https://TARGET -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.TARGET" -ac
```

### 10. Output
```bash
ffuf -u https://TARGET/FUZZ -w wordlist.txt -ac -o /engagement/scans/dir_fuzz_results.json -of json
curl -sI https://TARGET/discovered_path  # Verify
```

## What to Record

- Discovered paths with status codes and response sizes
- Sensitive files found (.env, .git, backups, config)
- Admin/management interfaces discovered
- Wordlists used and filter/matcher settings
- Whether authenticated fuzzing was performed
- New endpoints to feed into work buffer via `assess.py ingest-endpoints`

## Extended Resources

- `agent/references/tools/fuzzing/ffuf.md` — ffuf flags, filter/matcher options, wordlist selection
- `agent/references/tools/fuzzing/feroxbuster.md` — feroxbuster recursive scanning, auto-tune, smart mode
