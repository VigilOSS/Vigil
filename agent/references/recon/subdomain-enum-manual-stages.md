---
description: Manual Phase 0-3 subdomain-enumeration stage recipes (subfinder, bbot, crt.sh/certspotter, puredns, alterx, merge, tlsx/httpx/cero/dnsx, de-noise, live filter, ingest) for tuning or replacing a stage of the composed recon verbs
skill: subdomain-enumeration
---

# Subdomain enumeration — manual stage recipes

Load this when a stage of `vigil assess recon` / `dns-discovery` / `web-discovery` has to be
run, tuned, or recommended by hand: a stage the composed verbs do not cover, a flag-by-flag
re-run, or reproducing what a checkpointed stage did. The decisions (profile, brute gating,
wildcard handling, bound rules) live in `agent/skills/subdomain-enumeration/SKILL.md`; this
file is the mechanics. Every target-facing command is a blocking `vigil assess kali` call with
`--timeout 600` or less (`agent/shared-constraints.md` §2); DNS-heavy passes and bulk httpx run
one after another, never stacked (the skill's "Host-CPU note"). A stage that will not finish
inside one call splits its input list across calls; one that still cannot fit (a full bbot
preset, a very large brute) is an operator-owned `kali job` you name in `next_steps`.

Paths inside `vigil assess kali` argv use `/engagements/$ENGAGEMENT_KEY/scans/`; host-side
shell (grep, awk, sort) uses `$DIR/scans/` for the same files (`agent/shared-constraints.md` §11). Profiles are the skill's
"Docker-resource-safe profiles" and their flag sets are in
`agent/references/tools/recon/subdomain-enumeration-tools.md`; the examples use
`polite-residential`, and `<profile rl>` is that profile's DNS-brute value in
`agent/references/recon/rate-calibration.md`.

## Phase 0 — passive (always on)

subfinder is non-recursive by default: `-recursive` saturated the Docker daemon on large
apexes (a 4,289-host fixture exhausted the health-check budget) and adds little over `-all`.
Keyed sources lift coverage substantially; key setup is `agent/references/tools/recon/subfinder.md`.

```bash
vigil assess kali subfinder -d target.example -all -t 20 -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  --technique RECON --intent "Phase 0 passive subdomain enum (non-recursive)" \
  --probe-kind fingerprint --phase recon --timeout 600
```

bbot is a passive mop-up, not a trusted breadth source: its excavate module emits false
hostnames, so harvest `DNS_NAME` events from `output.json` and DNS-validate them like every
other source (`agent/references/tools/recon/bbot.md`). The full `subdomain-enum` preset runs
15-30 minutes, so it is an operator `kali job` (operator form in `bbot.md`); the synchronous pass
narrows to a few passive modules:

```bash
vigil assess kali bbot -t target.example -m crt -m certspotter -m hackertarget -rf passive \
  -o /engagements/$ENGAGEMENT_KEY/scans/bbot_subs \
  --technique OSINT --intent "Phase 0 focused passive bbot pass" \
  --probe-kind fingerprint --phase recon --timeout 600
```

## Phase 0b — certificate transparency (always on)

crt.sh rate-limits aggressively and answers an empty 4-byte body under load, so retry with
backoff rather than trusting one empty response.

```bash
vigil assess kali exec --technique OSINT --intent "Phase 0b crt.sh CT harvest with backoff" \
  --probe-kind fingerprint --phase recon --timeout 600 -- bash -c '
for apex in $(cat /engagements/$ENGAGEMENT_KEY/scans/apexes.txt); do
  for attempt in 1 2 3; do
    out=$(curl -s "https://crt.sh/?q=%25.${apex}&output=json")
    [ "$(printf "%s" "$out" | wc -c)" -gt 8 ] && break
    sleep $((attempt * 5))
  done
  printf "%s" "$out" | jq -r ".[].name_value" 2>/dev/null
done | sed "s/^\*\.//" | sort -u >> /engagements/$ENGAGEMENT_KEY/scans/subs_ct.txt'
```

When crt.sh stays empty after backoff, use certspotter
(`https://api.certspotter.com/v1/issuances?domain=<apex>&include_subdomains=true&expand=dns_names`);
in one engagement that recovered 1,916 CT hosts while crt.sh was throttled.

## Phase 0c — GeoDNS, DNSSEC, AXFR (probe once)

The recipes are `agent/references/tools/recon/dnsx.md` "GeoDNS multi-region resolver pass"
and "DNSSEC / AXFR — probe once, then skip". Diff answer sets from 2-3 geographies (or
`dig +subnet=` ECS, which adds no destination IPs) and record each region's A/CNAME set as
separate surface. NSEC-walk only an NSEC (not NSEC3) zone. Record every skip.

## Phase 1 — active brute

`kali puredns` runs in the container, which cannot see the shipped host-side resolver lists under
`agent/scripts/assess/data/resolvers/`. Copy `premium-anycast.txt` and `trusted-anycast.txt` to
`$DIR/wordlists/` before a hand-run call (`dns-discovery --brute` stages them itself).

```bash
vigil assess kali puredns bruteforce \
  /usr/share/wordlists/n0kovo_subdomains_500k.txt target.example \
  -r /engagements/$ENGAGEMENT_KEY/wordlists/premium-anycast.txt \
  --resolvers-trusted /engagements/$ENGAGEMENT_KEY/wordlists/trusted-anycast.txt \
  --rate-limit <profile rl> --wildcard-batch 100000 --wildcard-tests 30 \
  -w /engagements/$ENGAGEMENT_KEY/scans/subs_brute.txt \
  --technique RECON --intent "Phase 1 active brute @ polite-residential (two-tier resolvers)" \
  --probe-kind fingerprint --phase recon --timeout 600

# Equivalent composed form: wildcard pre-strip, HEAD cap, convergence and budget WARN included.
vigil assess dns-discovery target.example --brute \
  --wordlist /usr/share/wordlists/n0kovo_subdomains_500k.txt --wordlist-head 500000 --runtime host
```

- The baked wordlist is n0kovo's huge list HEAD-capped to 500k labels at build time; finish
  with an assetnote best-dns-wordlist pass when budget allows. Never `sort` a frequency-ordered
  wordlist: the HEAD cap depends on that order.
- An operator-provisioned pool lives at `/engagements/$ENGAGEMENT_KEY/wordlists/resolvers.txt`.
  Validate it under bulk load first and keep in-container distinct resolver IPs under ~50,
  or route to the host. `agent/scripts/assess/data/resolvers/validated-trickest.txt` is an
  optional wide tier a maintainer refreshes with `agent/scripts/refresh_resolvers.py`
  (absent until refreshed); point `--resolvers <path>` at it for a large brute.
- `vigil assess dns-discovery --brute` injects both shipped lists by default; override with `--resolvers <file>` / `--resolvers-trusted <file>`, or pass `--no-default-resolvers` to manage the pool yourself (which leaves puredns's own self-discovered resolver set — and its uncapped dest-IP fan-out — in play).
- `--wildcard-batch 50000` on containers with 4 GB or less: puredns's wildcard dedup map
  truncates silently instead of failing with an OOM.

## Phase 1.5 — productive-parent recursion

Cluster resolved hosts by their 2nd/3rd-level parent; parents with at least 5 children
(excluding the apex, already-bruted parents and wildcard sinks) get the wordlist HEAD re-bruted
against them; feed new resolutions back into the convergence loop. `dns-discovery --brute`
does this (`--parent-min-children`, `--no-parent-recursion`).

## Phase 2 — permutation (estimate first)

A 1,000-sub input can produce 200k+ candidates; abort above 500k and narrow the input to
subdomains sharing an apex CNAME or staging/dev clusters. Resolve permutations through puredns
(wildcard-aware), never dnsx, because permutations have a high false-positive rate.

```bash
vigil assess kali alterx -l /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt -enrich -estimate \
  --technique RECON --intent "Phase 2 permutation estimate" --probe-kind fingerprint --phase recon --timeout 120
vigil assess kali alterx -l /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt -enrich -limit 100000 \
  -o /engagements/$ENGAGEMENT_KEY/scans/perms.txt \
  --technique RECON --intent "Phase 2 permutation candidates capped at 100k" --probe-kind fingerprint --phase recon --timeout 600
vigil assess kali puredns resolve /engagements/$ENGAGEMENT_KEY/scans/perms.txt \
  -r /engagements/$ENGAGEMENT_KEY/wordlists/premium-anycast.txt \
  --resolvers-trusted /engagements/$ENGAGEMENT_KEY/wordlists/trusted-anycast.txt \
  --rate-limit <profile rl> --wildcard-batch 100000 -w /engagements/$ENGAGEMENT_KEY/scans/perms_resolved.txt \
  --technique RECON --intent "Phase 2 permutation resolve" --probe-kind fingerprint --phase recon --timeout 600
```

## Phase 2.5 — merge

```bash
vigil assess kali exec --technique RECON --intent "Phase 2.5 merge of passive + brute + permutation outputs" \
  --probe-kind baseline --phase recon --timeout 60 -- bash -c '
  cat /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt /engagements/$ENGAGEMENT_KEY/scans/subs_ct.txt \
      /engagements/$ENGAGEMENT_KEY/scans/subs_brute.txt /engagements/$ENGAGEMENT_KEY/scans/perms_resolved.txt 2>/dev/null \
    | sort -u > /engagements/$ENGAGEMENT_KEY/scans/subs_merged.txt'
```

A phase that did not run leaves no file; the redirect skips it.

## Phase 3 — TLS SAN feedback

`tlsx` is the primary SAN harvester (lighter than `httpx -tls-grab`); use `httpx -tls-grab`
only when the HTTP status/title is wanted in the same pass, and `cero` on resolved origin IPs (a
confirmed non-cloud owned CIDR only under `cero.md`'s gates). Leave `-tech-detect` off bulk httpx:
it amplifies memory under cgroup pressure and triggered RC137 SIGKILLs on large merged lists.

```bash
vigil assess kali tlsx -l /engagements/$ENGAGEMENT_KEY/scans/subs_merged.txt -san -cn -resp-only -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/tlsx_sans.txt \
  --technique DISCOVERY --intent "Phase 3 TLS SAN harvest via tlsx" \
  --probe-kind fingerprint --phase recon --timeout 600
vigil assess kali httpx -l /engagements/$ENGAGEMENT_KEY/scans/subs_merged.txt \
  -tls-grab -status-code -title -json --extra-args=-tls-probe \
  -o /engagements/$ENGAGEMENT_KEY/scans/httpx_tls.jsonl \
  --technique DISCOVERY --intent "Phase 3 SAN harvest with HTTP status (no tech-detect)" \
  --probe-kind fingerprint --phase recon --timeout 600
vigil assess kali cero -l /engagements/$ENGAGEMENT_KEY/scans/origin_ips.txt -p 443,8443,9443 -c 100 -t 4 \
  -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans.txt \
  --technique OSINT --intent "Phase 3 TLS SAN scrape across resolved origin/staging IPs" --probe-kind fingerprint --phase recon --timeout 600
vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/subs_merged.txt \
  --dnsx-profile polite-cdn --resolver-profile public-tcp -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/dnsx_final.txt \
  --technique RECON --intent "Phase 3 final dnsx resolution (lean)" --probe-kind baseline --phase recon --timeout 600
```

`origin_ips.txt` is the de-duplicated A-record set of resolved origin/staging hosts
(`agent/references/tools/recon/cero.md` "Default: resolved origin/staging IPs"); a whole asnmap CIDR
sweep is the gated escalation in `cero.md` "Whole-CIDR sweep — gated escalation only".

Keep bulk dnsx lean (no `-json`/`-resp`); enrich survivors in a second pass
(`agent/references/tools/recon/dnsx.md` "NXDOMAIN / CPU-spike trap").

**SAN set as a primary source.** When a shared multi-tenant cert (a SAN appearing on two or
more hosts) or a vhost-cert mismatch is found, the cert's SANs are candidate subdomains in their
own right, often staging/internal tenants absent from CT. Extract them per host, merge, and
confirm with `dnsx -a -resp` (`agent/references/tools/recon/openssl-sans.md` steps 1, 2, 3 and 5);
`san_live.txt` then feeds `vigil assess ingest endpoints subdomain-enum`.

## Filter, verify, ingest

De-noise before httpx: passive/CT/PTR output inflates the list about tenfold with non-host
records, each costing a full httpx timeout. Order real apexes ahead of CDN-wildcard blocks so a
tar-pit block does not starve them (a 13k CDN-wildcard block timed httpx out before a later
4,818-host block in one fixture).

```bash
grep -viE '(^|\.)(_dmarc|_dkim|_domainkey|_acme-challenge)\.' "$DIR/scans/subs_merged.txt" \
  | grep -viE '(^|\.)(dhcp-|dha-[0-9]+-[0-9]+|dhpcile[0-9]+)' | grep -viE '(-laptop|-kw|-desktop)(\.|$)' \
  | grep -viE '^[0-9a-f]{2}-[0-9a-f]{2}-' | grep -viE '\.rev\.' \
  | sort -u > "$DIR/scans/subs_denoised.txt"

vigil assess kali httpx -l /engagements/$ENGAGEMENT_KEY/scans/subs_denoised.txt \
  -status-code -title -web-server -cl -follow-redirects --extra-args=-silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/subdomains_live.txt \
  --technique DISCOVERY --intent "live-host confirmation (status-only)" --probe-kind fingerprint --phase recon --timeout 600

awk '{print $1}' "$DIR/scans/subdomains_live.txt" | sort -u > "$DIR/scans/subs_live_only.txt"
vigil assess kali httpx -l /engagements/$ENGAGEMENT_KEY/scans/subs_live_only.txt -tech-detect -json --extra-args=-silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/subdomains_tech.jsonl \
  --technique DISCOVERY --intent "tech-detect on confirmed-live subset" --probe-kind fingerprint --phase recon --timeout 600

awk '{print $1}' "$DIR/scans/subdomains_live.txt" | sort -u | while IFS= read -r sub; do
  echo "GET https://$sub"
done | vigil assess ingest endpoints subdomain-enum
```

After ingestion the operator runs the reactive nuclei sweep against the new hosts
(`agent/skills/nuclei-scanning/SKILL.md` "Reactive Sweep Mode").
