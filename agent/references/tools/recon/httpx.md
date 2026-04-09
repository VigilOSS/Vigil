# httpx

**Purpose:** Fast multi-purpose HTTP toolkit — live host probing, tech detection, status codes, titles
For live engagement targets, run httpx through the Kali MCP command-execution tool.

## Probing

**Probe single URL:** `echo "https://target" | httpx -silent -status-code -title -tech-detect`
**Probe from file:** `httpx -l targets.txt -silent -status-code -title -server -content-length`
**Follow redirects:** `httpx -l targets.txt -follow-redirects -silent`
**With path appended:** `httpx -l targets.txt -path /api/v1 -silent`

## Fingerprinting

**Tech detection:** `httpx -l targets.txt -tech-detect -silent`
**TLS certificate info:** `httpx -l targets.txt -tls-grab -silent`
**CDN detection:** `httpx -l targets.txt -cdn -silent`
**IP resolution:** `httpx -l targets.txt -ip -silent`
**Favicon hash (Shodan matching):** `httpx -l targets.txt -favicon -silent`
**Response hash:** `httpx -l targets.txt -hash md5 -silent`
**Screenshot:** `httpx -l targets.txt -screenshot -silent`

## Filtering & Matching

**Match by status code:** `-mc 200,301,302,403`
**Filter by status code:** `-fc 404,503`
**Match by content type:** `-match-ct "text/html"`
**Filter by CDN:** `-filter-cdn cloudflare,akamai`

## Auth & Headers

**Custom header:** `-H "Cookie: session=abc"`
**Multiple headers:** `-H "Authorization: Bearer token" -H "X-Custom: value"`

## Rate Limiting & Performance

**Rate limit:** `-rate-limit 50` (requests per second)
**Threads:** `-threads 25`
**Timeout:** `-timeout 10`

## Output

**JSON output:** `httpx -l targets.txt -json -o results.json`
**CSV output:** `httpx -l targets.txt -csv -o results.csv`

**Pipeline usage:** httpx is glue between subdomain enumeration and scanning. Feed subfinder/puredns output into httpx to confirm live hosts before deeper testing:
```
subfinder -d target.example -silent | dnsx -silent -a -resp-only | httpx -silent -status-code -title -tech-detect
```
