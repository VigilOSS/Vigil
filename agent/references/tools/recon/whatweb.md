# whatweb

**Purpose:** Web technology fingerprinting
For live engagement targets, run WhatWeb through the Kali MCP command-execution tool with `whatweb`.

**Basic:** `whatweb https://target`
**Aggressive:** `whatweb -a 3 https://target`
**Multiple targets:** `whatweb --input-file=/engagement/scans/targets.txt`
**Verbose:** `whatweb -v https://target`
**Output:** `--log-json=results.json`
