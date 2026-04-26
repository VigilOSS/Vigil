# wafw00f

**Purpose:** Web Application Firewall identification and fingerprinting
For live engagement targets, run wafw00f via `aith assess kali wafw00f` (typed verb, audit-flag-aware).

## Basic Usage

**Single target:** `wafw00f https://target`
**Verbose:** `wafw00f https://target -v`
**Test all WAFs (not just first match):** `wafw00f https://target -a`
**Scan from file:** `wafw00f -i targets.txt`
**List all detectable WAFs:** `wafw00f -l`
**Custom headers:** `wafw00f https://target -H "Cookie: session=abc"`
**Proxy:** `wafw00f https://target -p http://127.0.0.1:8080`
**Output (CSV):** `wafw00f https://target -o results.csv`

Note: wafw00f outputs CSV format with `-o`. It does not support `-f json`. For JSON, parse CSV output or capture stdout.

**Why it matters:** Identify which WAF is in use BEFORE attempting bypass payloads. Different WAFs require different evasion techniques (see tamper scripts in sqlmap.md and encoder chains in wfuzz.md). Testing blind wastes time and may trigger rate limiting or IP bans.
