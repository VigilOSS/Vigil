# feroxbuster

**Purpose:** Fast, recursive content discovery (Rust-based replacement for gobuster/dirb)
For live engagement targets, run feroxbuster through the Kali MCP command-execution tool.

**Basic scan:** `feroxbuster -u https://target -w /usr/share/wordlists/dirb/common.txt`
**Recursive (depth 3):** `feroxbuster -u https://target -w wordlist.txt -d 3`
**With extensions:** `feroxbuster -u https://target -w wordlist.txt -x php,html,js,txt,bak`
**Smart mode (auto-filter):** `feroxbuster -u https://target -w wordlist.txt --smart`
**Auto-tune (adjust speed):** `feroxbuster -u https://target -w wordlist.txt --auto-tune`
**Status code filter:** `feroxbuster -u https://target -w wordlist.txt -C 404,403`
**Threads:** `-t 50`
**Output:** `-o results.txt` or `--json -o results.json`
**Rate limit:** `--rate-limit 100`
**Resume interrupted scan:** `--resume-from state.json`
**Collect links from pages:** `--collect-links`

**When to use:** Prefer feroxbuster over gobuster/dirb for content discovery. It auto-recurses into found directories, handles auto-calibration, and is significantly faster. Use ffuf for parameter fuzzing, vhost fuzzing, and targeted single-directory work.
