# feroxbuster

**Purpose:** Fast, recursive content discovery (Rust-based replacement for gobuster/dirb)
For live engagement targets, run feroxbuster via `vigil assess kali exec --technique RECON --intent "<why>" --probe-kind fingerprint --phase <phase> --timeout <seconds> -- feroxbuster ...` with the standard audit-flag set.

## Basic Usage

**Basic scan:** `feroxbuster -u https://target -w /usr/share/wordlists/dirb/common.txt`
**Recursive (depth 3):** `feroxbuster -u https://target -w wordlist.txt -d 3`
**With extensions:** `feroxbuster -u https://target -w wordlist.txt -x php,html,js,txt,bak`
**Auto-tune (adjust speed):** `feroxbuster -u https://target -w wordlist.txt --auto-tune`
**Status code filter:** `feroxbuster -u https://target -w wordlist.txt -C 404,403`

## Auth & Headers

**Cookie:** `-b "session=abc123"`
**Custom header:** `-H "Authorization: Bearer token123"`
**TLS skip verification:** `-k` (critical for self-signed certs)

## Tuning

**Threads:** `-t 50`
**Rate limit:** `--rate-limit 100` (requests/second)
**Proxy through Burp:** `--proxy http://127.0.0.1:8080`
**Extract links from pages:** `--extract-links`
**Filter responses by regex:** `--filter-regex "logout|signout"`

## Output & Resume

**Text output:** `-o results.txt`
**JSON output:** `--json -o results.json`
**Resume interrupted scan:** `--resume-from ferox-STATE_FILE.state`

## Wordlist tier and cautious-tier rate guidance

The recon-mandatory minimum is the L1 wordlist
(`/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt`) plus
tech-extension variants — see `agent/skills/web-recon/SKILL.md` Step 5. Match the
`--rate-limit` and `-t` settings to the wafw00f-determined WAF tier (full table in
`agent/references/tools/recon/wafw00f.md` "WAF-tier rate adjustment table"; canonical
per-target calibration in `agent/operator-core.md` "Recon Dispatch Resource Policy"):

- **No WAF** → `-t 50` (default), no rate cap.
- **Basic WAF** → `-t 25 --rate-limit 50`.
- **CDN-fronted (any major CDN / edge platform)** → `-t 10 --rate-limit 25`.
- **Cautious tier (enterprise WAF / high-friction policy / regulated)** → `-t 5 --rate-limit 10`.

Run wafw00f BEFORE feroxbuster so the rate matches the WAF tier — the default `-t 50`
trips cautious-tier rate-limit profiles in seconds and locks the engagement out.

## When to Use

Prefer feroxbuster over gobuster/dirb for content discovery. It auto-recurses into found
directories, handles auto-calibration, and is faster. Use ffuf for parameter fuzzing,
vhost fuzzing, and targeted single-directory work.
