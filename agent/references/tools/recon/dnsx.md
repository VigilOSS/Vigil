# dnsx

**Purpose:** Fast multi-purpose DNS toolkit for bulk resolution and record enumeration
For live engagement targets, run dnsx via `aith assess kali dnsx` (typed verb, audit-flag-aware).

## Record Resolution

**A records:** `cat subs.txt | dnsx -silent -a -resp`
**AAAA records:** `cat subs.txt | dnsx -silent -aaaa -resp`
**CNAME records:** `cat subs.txt | dnsx -silent -cname -resp`
**MX records:** `cat subs.txt | dnsx -silent -mx -resp`
**TXT records:** `cat subs.txt | dnsx -silent -txt -resp`
**NS records:** `cat subs.txt | dnsx -silent -ns -resp`
**SOA records:** `cat subs.txt | dnsx -silent -soa -resp`
**PTR (reverse DNS):** `echo "1.2.3.4" | dnsx -silent -ptr -resp`
**Multiple record types:** `cat subs.txt | dnsx -silent -a -aaaa -cname -mx -txt -resp`
**Response only (IPs):** `cat subs.txt | dnsx -silent -a -resp-only`

## Custom Resolvers

**Resolver file:** `cat subs.txt | dnsx -silent -a -resp -r resolvers.txt`
**Rate limit per resolver:** `cat subs.txt | dnsx -silent -a -resp -rl 10`

## Tuning

**Threads:** `cat subs.txt | dnsx -silent -a -resp -t 100`
**Rate limit:** `-rate-limit 300`
**Retry:** `-retry 2`
**Wildcard filtering:** `-wd target.example`

## Output

**Text:** `cat subs.txt | dnsx -silent -a -resp -o resolved.txt`
**JSON:** `cat subs.txt | dnsx -silent -a -resp -json -o resolved.json`

**Pipeline usage:** dnsx sits between subdomain discovery and HTTP probing:
1. Validate which subdomains actually resolve (drop dead DNS)
2. Get CNAME records for subdomain takeover detection
3. Identify different IP ranges for infrastructure mapping
4. Get TXT records for SPF/DKIM and sometimes exposed secrets
