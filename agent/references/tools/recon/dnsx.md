# dnsx

**Purpose:** Fast multi-purpose DNS toolkit for bulk resolution and record enumeration
For live engagement targets, run dnsx via `aith assess kali dnsx` (typed verb, audit-flag-aware). The typed wrapper applies Docker-safe defaults: `--dnsx-profile polite-cdn`, `--resolver-profile public-tcp`, `-rl 100`, `-t 20`, `-retry 3`, and `-timeout 5` unless the operator chooses a more aggressive profile.

## NXDOMAIN / CPU-spike trap (read first)

`-resp -json` against brute-force wordlists emits a JSON record for every NXDOMAIN response, not just successful resolutions. On a 110k-entry wordlist with the typical 95-99% miss rate, that is 100k+ JSON serializations per pass — enough to saturate container CPU and force several pacing reductions before stabilizing. The rule is **lean on bulk, enrich on survivors**.

**Host-CPU and Docker-stability note.** DNS bruteforce is the dominant host-CPU and host-network spike in the engagement runtime — see `agent/skills/subdomain-enumeration/SKILL.md` "Host-CPU note" for the full mechanism. dnsx can send thousands of UDP queries per second; the host kernel's per-packet network-stack overhead is amplified well beyond what `--cpus` cgroup limits constrain (cgroup CPU limits the userland process, not the host's kernel networking path). Aggressive dnsx profiles have crashed Docker on standard laptop hardware. Keep the typed wrapper's `public-tcp` resolver profile unless there is a deliberate reason to use UDP resolvers. Reach for the `bursty-ok` ceiling only when the operator has explicitly opted in.

```bash
# Step 1 — lean brute (no -resp / no -json on bulk inputs)
aith assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/candidates.txt \
  --dnsx-profile polite-cdn --resolver-profile public-tcp -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/candidates_resolved.txt \
  --technique RECON --intent "bulk dnsx resolve (lean — no JSON, drop NXDOMAIN early)" \
  --probe-kind baseline --phase recon --timeout 1200

# Step 2 — enrich survivors only (smaller set, JSON safe here)
aith assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/candidates_resolved.txt \
  --dnsx-profile polite-cdn --resolver-profile public-tcp \
  -resp -json --allow-bulk-json -a -cname -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/dnsx_enriched.jsonl \
  --technique RECON --intent "enrich resolved survivors with A+CNAME JSON" \
  --probe-kind fingerprint --phase recon --timeout 600
```

For tight-RAM containers (Lab/CTF tier, `AITH_RUNTIME_MEMORY_GB=2`), wrap with `GOMAXPROCS=1 nice -n 10` to bound goroutine CPU usage:

```bash
aith assess kali exec --technique RECON \
  --intent "tight-RAM dnsx profile (GOMAXPROCS=1 nice -n 10)" \
  --probe-kind baseline --phase recon --timeout 1800 -- \
  env GOMAXPROCS=1 nice -n 10 \
  dnsx -l /engagements/$ENGAGEMENT_KEY/scans/candidates.txt \
  -rl 100 -t 20 -retry 3 -timeout 5 -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/dnsx_low.txt
```

## Rate-limit profiles

Match the dnsx flags to the runtime/target tier — see `agent/skills/subdomain-enumeration/SKILL.md` "Docker-resource-safe profiles" for selection guidance.

| Wrapper profile | Flags |
|---------|-------|
| `--dnsx-profile polite-cdn` (default; CDN-fronted / WAF-protected / regulated cautious tier) | `-rl 100 -t 20 -retry 3 -timeout 5` |
| `--dnsx-profile polite-residential` (Standard runtime, public resolvers after explicit assessment) | `-rl 300 -t 50 -retry 2 -timeout 5` |
| `--dnsx-profile bursty-ok` (opt-in only — private resolver, no shared-infra constraints) | `-rl 500 -t 100 -retry 2 -timeout 5` |

The typed wrapper rejects `-rl` / `-t` above `polite-residential` unless `--dnsx-profile bursty-ok` is passed, and rejects values above `bursty-ok` unless `--allow-unsafe-rate` is passed. Guarded flags such as `-rl`, `-t`, `-r`, `-w`, `-resp`, and `-json` must be passed as typed wrapper flags, not through `--extra-args`, so the safety checks cannot be bypassed. Common dnsx record/filter flags are typed (`-aaaa`, `-mx`, `-txt`, `-ns`, `-soa`, `-ptr`, `-asn`, `-cdn`, `-rcode`, `-wd`); use `--extra-args` for unmodeled flags that are not load/transport/bulk-response knobs.

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
**Rate limit:** `-rl 300`
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
