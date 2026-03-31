# wafw00f

**Purpose:** Web Application Firewall identification and fingerprinting
For live engagement targets, run wafw00f through the Kali MCP command-execution tool.

**Basic scan:** `wafw00f https://target`
**Verbose:** `wafw00f https://target -v`
**List all detectable WAFs:** `wafw00f -l`
**Scan from file:** `wafw00f -i targets.txt`
**Output:** `wafw00f https://target -o results.json -f json`

**Why it matters:** Identify which WAF is in use BEFORE attempting bypass payloads. Different WAFs require different bypass techniques. Testing blind wastes time and may trigger rate limiting or IP bans.
