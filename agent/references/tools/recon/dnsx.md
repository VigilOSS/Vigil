# dnsx

**Purpose:** Fast multi-purpose DNS toolkit for bulk resolution and record enumeration
For live engagement targets, run dnsx through the Kali MCP command-execution tool.

**Resolve A records:** `cat subs.txt | dnsx -silent -a -resp`
**CNAME records:** `cat subs.txt | dnsx -silent -cname -resp`
**Multiple record types:** `cat subs.txt | dnsx -silent -a -aaaa -cname -mx -resp`
**Output:** `cat subs.txt | dnsx -silent -a -resp -o resolved.txt`
**JSON output:** `cat subs.txt | dnsx -silent -a -resp -json -o resolved.json`
**Rate limit:** `-rate-limit 300`
**Retry:** `-retry 2`
**Wildcard filtering:** `-wd target.example` (filter wildcard responses for a domain)

**Pipeline usage:** dnsx sits between subdomain discovery and HTTP probing. Use it to:
1. Validate which subdomains actually resolve (drop dead DNS)
2. Get CNAME records for subdomain takeover detection
3. Identify different IP ranges for infrastructure mapping
