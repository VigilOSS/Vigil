# feroxbuster

**Purpose:** Fast, recursive content discovery (Rust-based replacement for gobuster/dirb)
For live engagement targets, run feroxbuster through the Kali MCP command-execution tool.

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

## When to Use

Prefer feroxbuster over gobuster/dirb for content discovery. It auto-recurses into found
directories, handles auto-calibration, and is faster. Use ffuf for parameter fuzzing,
vhost fuzzing, and targeted single-directory work.
