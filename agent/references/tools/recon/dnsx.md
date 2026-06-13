---
description: Bulk DNS resolution and record enumeration — NXDOMAIN/CPU spike pattern, two-step lean-then-enrich, `GOMAXPROCS=1 nice -n 10` profile, GeoDNS multi-region resolver pass, DNSSEC/AXFR probe-once-and-skip
skill: subdomain-enumeration
---

# dnsx

**Purpose:** Fast multi-purpose DNS toolkit for bulk resolution and record enumeration
For live engagement targets, run dnsx via `vigil assess kali dnsx` (typed verb, audit-flag-aware). The typed wrapper applies Docker-safe defaults: `--dnsx-profile polite-cdn`, `--resolver-profile public-tcp`, `-rl 100`, `-t 20`, `-retry 3`, and `-timeout 5` unless the operator chooses a more aggressive profile.

## NXDOMAIN / CPU-spike trap (read first)

`-resp -json` against brute-force wordlists emits a JSON record for every NXDOMAIN response, not just successful resolutions. On a 110k-entry wordlist with the typical 95-99% miss rate, that is 100k+ JSON serializations per pass — enough to saturate container CPU and force several pacing reductions before stabilizing. The rule is **lean on bulk, enrich on survivors**.

**Host-CPU and Docker-stability note.** DNS bruteforce is the dominant host-CPU and host-network spike in the engagement runtime — see `agent/skills/subdomain-enumeration/SKILL.md` "Host-CPU note" for the full mechanism. dnsx can send thousands of UDP queries per second; the host kernel's per-packet network-stack overhead is amplified well beyond what `--cpus` cgroup limits constrain (cgroup CPU limits the userland process, not the host's kernel networking path). Aggressive dnsx profiles have crashed Docker on standard laptop hardware. Keep the typed wrapper's `public-tcp` resolver profile unless there is a deliberate reason to use UDP resolvers. Reach for the `bursty-ok` ceiling only when the operator has explicitly opted in.

```bash
# Step 1 — lean brute (no -resp / no -json on bulk inputs)
vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/candidates.txt \
  --dnsx-profile polite-cdn --resolver-profile public-tcp -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/candidates_resolved.txt \
  --technique RECON --intent "bulk dnsx resolve (lean — no JSON, drop NXDOMAIN early)" \
  --probe-kind baseline --phase recon --timeout 1200

# Step 2 — enrich survivors only (smaller set, JSON safe here)
vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/candidates_resolved.txt \
  --dnsx-profile polite-cdn --resolver-profile public-tcp \
  -resp -json --allow-bulk-json -a -cname -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/dnsx_enriched.jsonl \
  --technique RECON --intent "enrich resolved survivors with A+CNAME JSON" \
  --probe-kind fingerprint --phase recon --timeout 600
```

For tight-RAM containers (Lab/CTF tier, `VIGIL_RUNTIME_MEMORY_GB=2`), wrap with `GOMAXPROCS=1 nice -n 10` to bound goroutine CPU usage:

```bash
vigil assess kali exec --technique RECON \
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
**Rate limit:** `cat subs.txt | dnsx -silent -a -resp -rl 10` (`-rl` is **total qps**, not per-resolver)

## GeoDNS multi-region resolver pass (dnsx mechanics)

Targets on a GeoDNS / GSLB provider return **geo-varying A/CNAME records** — the answer depends on
the *resolver's* geographic vantage, so a single-vantage resolve under-reports the surface. Re-resolve
the apex plus a sample of resolved hosts against resolvers in **2–3 distinct geographies** and **diff
the answer sets**; when records vary by region, record **each region's A/CNAME set as separate
surface** and feed the geo-specific IPs to the Phase-3 cero/cert grab.

This is the *time-invariant* complement to `openssl-sans.md` §4's multi-*time* re-resolution (which
varies time from a single vantage and catches round-robin/GSLB rotation but **not** geo-varying
records). Two mechanics for the geo pass:

```bash
# (1) Multi-region resolver set (dnsx) — point -r at resolvers in different geographies, diff outputs.
# dnsx has no EDNS-Client-Subnet flag, so region-pinned resolver files are the dnsx-native mechanism.
# Run once per region file, then diff the resolved sets.
cat apex_and_sample.txt | dnsx -silent -a -cname -resp -r resolvers_us.txt   -o resolved_us.txt
cat apex_and_sample.txt | dnsx -silent -a -cname -resp -r resolvers_eu.txt   -o resolved_eu.txt
cat apex_and_sample.txt | dnsx -silent -a -cname -resp -r resolvers_apac.txt -o resolved_apac.txt
# diff resolved_us/eu/apac → region-varying answers = GeoDNS surface

# (2) EDNS Client-Subnet via dig — spoof the source region in-band (no region-pinned resolver needed).
# This is a dig mechanism, NOT a dnsx flag; reach for it when you cannot source region-pinned resolvers.
dig +subnet=203.0.113.0/24 A apex   @1.1.1.1   # a US client subnet
dig +subnet=2.16.0.0/16   A apex   @1.1.1.1   # an EU client subnet
```

A small curated multi-region resolver set (e.g. Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9
`9.9.9.9`, plus a couple of region-pinned anycast resolvers) covers most cases — keep the **distinct
resolver-IP count small** so the multi-region pass stays under the Docker per-destination-IP ceiling
(`agent/references/runtime-guides/docker-desktop-network-hazards.md`). The `dig +subnet=` form avoids
adding distinct resolver IPs entirely (one resolver, spoofed client subnets).

## DNSSEC / AXFR — probe once, then skip

These are **cheap one-shot probes whose answer is almost always "no" — so probe each ONCE per zone,
record the result, and never re-probe.** Re-trying a refused AXFR or walking a non-NSEC zone is wasted
budget and noise.

**DNSSEC probe-once.** Get the authoritative NS (dnsx), then a single signed-record check (dig — dnsx
has **no** DNSSEC flag, so the DNSKEY/RRSIG presence check is dig-side):

```bash
# Authoritative NS + SOA (one shot each, dnsx-native).
cat apex.txt | dnsx -silent -ns -resp
cat apex.txt | dnsx -silent -soa -resp
# Single DNSSEC presence check (dig): DNSKEY / RRSIG on the apex.
dig +dnssec DNSKEY <apex> @<ns>                 # RRSIG present in the answer ⇒ zone is signed
```

Decision: **only** if RRSIG/NSEC records are present **and** the zone is **NSEC** (not NSEC3, which is
hashed) is zone-walking applicable — and even then NSEC-walking enumerates the whole zone, so treat it
as an explicit operator opt-in within the authorized-technique envelope. Otherwise log
`DNSSEC absent / NSEC3 — skip walk` and move on. **Do not re-probe.**

**AXFR probe-once.** dnsx has a native `-axfr` query (it queries AXFR against the zone's authoritative
NS); try the transfer **exactly once**:

```bash
# dnsx-native one-shot AXFR (near-universally REFUSED on internet zones).
cat apex.txt | dnsx -silent -axfr -resp
# dig fallback against a specific NS:
dig AXFR @<ns> <apex>
# or: nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=<apex> -p 53 <ns>
```

On the near-universal REFUSED/timeout, record `AXFR refused — skip` so no later step retries it. A
successful transfer is rare and high-value (dump the whole zone); a refusal is terminal — **skip, do
not retry.** Both the DNSSEC verdict and the AXFR verdict belong in the recorded recon facts as
explicit skip decisions, consistent with the skill's "one heavy enum op at a time" discipline.

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
