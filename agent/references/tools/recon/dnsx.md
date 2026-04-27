# dnsx

**Purpose:** Fast multi-purpose DNS toolkit for bulk resolution and record enumeration
For live engagement targets, run dnsx via `aith assess kali dnsx` (typed verb, audit-flag-aware).

## NXDOMAIN / CPU-spike trap (read first)

`-resp -json` against brute-force wordlists emits a JSON record for every NXDOMAIN response, not just successful resolutions. On a 110k-entry wordlist with the typical 95-99% miss rate, that is 100k+ JSON serializations per pass — enough to saturate container CPU and force several pacing reductions before stabilizing. The rule is **lean on bulk, enrich on survivors**.

**Host-CPU and Docker-stability note.** DNS bruteforce is the dominant host-CPU and host-network spike in the engagement runtime — see `agent/skills/subdomain-enumeration/SKILL.md` "Host-CPU note" for the full mechanism. dnsx sends thousands of UDP queries per second; the host kernel's per-packet network-stack overhead is amplified well beyond what `--cpus` cgroup limits constrain (cgroup CPU limits the userland process, not the host's kernel networking path). Aggressive dnsx profiles have crashed Docker on standard laptop hardware. Default to the polite-residential or polite-CDN-fronted-target profile; reach for the bursty-OK ceiling only when the operator has explicitly opted in.

```bash
# Step 1 — lean brute (no -resp / no -json on bulk inputs)
aith assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/candidates.txt \
  -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/candidates_resolved.txt \
  --technique RECON --intent "bulk dnsx resolve (lean — no JSON, drop NXDOMAIN early)" \
  --probe-kind baseline --phase recon --timeout 1200

# Step 2 — enrich survivors only (smaller set, JSON safe here)
aith assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/candidates_resolved.txt \
  -resp -json -a -cname -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/dnsx_enriched.jsonl \
  --technique RECON --intent "enrich resolved survivors with A+CNAME JSON" \
  --probe-kind fingerprint --phase recon --timeout 600
```

For tight-RAM containers (Lab/CTF tier, `AITH_RUNTIME_MEMORY_GB=2`), wrap with `GOMAXPROCS=1 nice -n 10` to bound goroutine CPU usage:

```bash
aith assess kali exec -- env GOMAXPROCS=1 nice -n 10 \
  dnsx -l /engagements/$ENGAGEMENT_KEY/scans/candidates.txt \
  -rl 100 -t 20 -retry 3 -timeout 5 -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/dnsx_low.txt \
  --technique RECON --intent "tight-RAM dnsx profile (GOMAXPROCS=1 nice -n 10)" \
  --probe-kind baseline --phase recon --timeout 1800
```

## Rate-limit profiles

Match the dnsx flags to the runtime/target tier — see `agent/skills/subdomain-enumeration/SKILL.md` "Docker-resource-safe profiles" for selection guidance.

| Profile | Flags |
|---------|-------|
| polite-CDN-fronted-target (CDN-fronted / WAF-protected / regulated cautious tier) | `-rl 100 -t 20 -retry 3 -timeout 5` |
| polite-residential default (Standard runtime, public resolvers) | `-rl 300 -t 50 -retry 2` |
| bursty-OK (opt-in only — private resolver, no shared-infra constraints) | `-rl 500 -t 100` |

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
**JSON (enrich-only — see NXDOMAIN trap):** `cat survivors.txt | dnsx -silent -a -resp -json -o resolved.json`

**Pipeline usage:** dnsx sits between subdomain discovery and HTTP probing:
1. Validate which subdomains actually resolve (drop dead DNS — lean profile, no JSON).
2. Get CNAME records for subdomain takeover detection (enrichment pass, JSON safe).
3. Identify different IP ranges for infrastructure mapping.
4. Get TXT records for SPF/DKIM and sometimes exposed secrets.
