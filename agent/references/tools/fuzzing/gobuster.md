---
description: Directory/file, DNS, and vhost brute-forcing
skill: directory-fuzzing
---

# gobuster

**Purpose:** Directory, DNS, and vhost brute-forcing
For live engagement targets, run Gobuster via `vigil assess kali exec --technique RECON --intent "<why>" --probe-kind fingerprint --phase <phase> --timeout <seconds> -- gobuster ...` with the standard audit-flag set.
Long-running gobuster sweeps should use `vigil assess kali job start --technique RECON --intent "<why>" --probe-kind fingerprint --phase <phase> --timeout <seconds> -- gobuster ...` so they survive across calling-shell exit.

## Directory Mode

**Basic:** `gobuster dir -u https://target -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
**With extensions:** `gobuster dir -u https://target -w wordlist.txt -x php,html,txt`
**Status codes to include:** `-s "200,204,301,302,307"`
**Status codes to exclude:** `-b "404,403"`
**Cookie auth:** `-c "session=abc123"`
**Custom header:** `-H "Authorization: Bearer token"`
**TLS skip verification:** `-k`
**Proxy:** `--proxy http://127.0.0.1:8080`
**Delay between requests:** `--delay 100ms`
**Threads:** `-t 50`
**Output:** `-o results.txt`

## DNS Subdomain Mode

**Basic:** `gobuster dns -d target.example -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
**Show IPs:** `-i`
**Wildcard detection:** `--wildcard`

## Vhost Mode

**Basic:** `gobuster vhost -u https://target -w subdomains.txt`
**Append domain:** `--append-domain`

## S3 Bucket Enumeration

**S3 mode:** `gobuster s3 -w bucket-names.txt`

## When to Use

Use gobuster when: (1) you need DNS or S3 enumeration (ffuf/feroxbuster don't have these modes),
(2) you want non-recursive directory scanning (simpler output than feroxbuster), or (3) feroxbuster
is unavailable. For recursive content discovery, prefer feroxbuster. For parameter/vhost fuzzing,
prefer ffuf.
