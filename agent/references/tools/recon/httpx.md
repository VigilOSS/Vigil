# httpx

**Purpose:** Fast multi-purpose HTTP toolkit — live host probing, tech detection, status codes, titles
For live engagement targets, run httpx through the Kali MCP command-execution tool.

**Probe single URL:** `echo "https://target" | httpx -silent -status-code -title -tech-detect`
**Probe from file:** `httpx -l targets.txt -silent -status-code -title -server -content-length`
**Follow redirects:** `httpx -l targets.txt -follow-redirects -silent`
**Tech detection:** `httpx -l targets.txt -tech-detect -silent`
**JSON output:** `httpx -l targets.txt -json -o results.json`
**Filter by status:** `httpx -l targets.txt -mc 200,301,302,403`
**Custom headers:** `httpx -l targets.txt -H "Cookie: session=abc"`
**Rate limit:** `-rate-limit 50` (requests per second)
**Threads:** `-threads 25`

**Pipeline usage:** httpx is glue between subdomain enumeration and scanning. Feed subfinder/puredns output into httpx to confirm live hosts before deeper testing.
