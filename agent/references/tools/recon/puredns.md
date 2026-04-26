# puredns

**Purpose:** Fast domain resolver and DNS brute-forcer with accurate wildcard filtering
For live engagement targets, run puredns via `aith assess kali puredns` (typed verb, audit-flag-aware).

**Brute-force subdomains:** `puredns bruteforce wordlist.txt target.example -r resolvers.txt -w results.txt`
**Resolve a list:** `puredns resolve subdomains.txt -r resolvers.txt -w resolved.txt`
**Wildcard detection:** Built-in — automatically filters wildcard DNS responses
**Custom resolvers:** `-r resolvers.txt` (use trusted public resolvers to avoid false positives)
**Rate limit:** `--rate-limit 500`
**Threads:** `-t 100`

**Pipeline usage:** Use after subfinder (passive) to add active brute-force results. puredns handles wildcard domains correctly, which ffuf vhost fuzzing does not. Feed output into dnsx for record-type enrichment, then httpx for live host confirmation.

**Resolver list:** Use a curated list of reliable public resolvers. Community lists available at `github.com/trickest/resolvers`.
