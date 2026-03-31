# gau (Get All URLs)

**Purpose:** Fetch known URLs from multiple archive sources (Wayback Machine, AlienVault OTX, Common Crawl, URLScan)
For live engagement targets, run gau through the Kali MCP command-execution tool.

**Basic:** `gau target.example`
**With threads:** `gau target.example --threads 5`
**Output to file:** `gau target.example --o urls.txt`
**Filter by extension:** `gau target.example --blacklist png,jpg,gif,css,woff,svg`
**Include subdomains:** `gau --subs target.example`
**Specific providers:** `gau target.example --providers wayback,otx,commoncrawl`

**Pipeline usage:** gau replaces waybackurls by querying 4x more sources. Feed output into:
- `dalfox pipe` for XSS scanning
- `grep "=" | sort -u` for parameterized URLs → parameter fuzzing
- Source analysis for JS endpoint extraction
- `httpx` to verify which discovered URLs are still live
