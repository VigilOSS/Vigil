---
description: URL brute-forcing with wordlists
skill: directory-fuzzing
---

# dirb

**Purpose:** Web directory brute-forcing with built-in wordlists
For live engagement targets, run dirb via `vigil assess kali exec --technique RECON --intent "<why>" --probe-kind fingerprint --phase <phase> --timeout <seconds> -- dirb ...` with the standard audit-flag set.

## Basic Usage

**Default wordlist (built-in):** `dirb https://target` (uses `/usr/share/dirb/wordlists/common.txt`)
**Custom wordlist:** `dirb https://target /path/to/wordlist.txt`
**Cookie auth:** `dirb https://target -c "session=abc123"`
**Custom User-Agent:** `dirb https://target -a "Mozilla/5.0"`
**Ignore specific codes:** `dirb https://target -N 403`
**Extensions:** `dirb https://target -X .php,.bak,.old`
**Recursive:** `dirb https://target -r` (disable with `-r` to skip)
**Delay (ms):** `dirb https://target -z 100`
**HTTP basic auth:** `dirb https://target -u user:pass`
**Proxy:** `dirb https://target -p http://127.0.0.1:8080`
**TLS skip:** `dirb https://target` (dirb accepts self-signed certs by default)
**Output:** `dirb https://target -o results.txt`

## Built-in Wordlists (Kali)

```
/usr/share/dirb/wordlists/common.txt         # default, small
/usr/share/dirb/wordlists/big.txt             # larger coverage
/usr/share/dirb/wordlists/vulns/*.txt         # vulnerability-specific (apache, iis, etc.)
/usr/share/dirb/wordlists/catala.txt          # non-English paths
```

## When to Use

dirb's advantage is zero-config: it bundles wordlists and works out of the box with `dirb URL`.
Use it when you want a quick first pass without specifying wordlists. For thorough or targeted
fuzzing, prefer ffuf (parameter/vhost) or feroxbuster (recursive content discovery).
