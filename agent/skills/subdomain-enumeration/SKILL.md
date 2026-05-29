---
name: subdomain-enumeration
description: Subdomain discovery via subfinder, DNS brute-force, TLS SAN feedback, and resource-tier-aware staged composition
origin: AI Threat Hunting
---

# Subdomain Enumeration

> **`aith assess kali` audit flags:** use `--technique RECON` when actively probing in-scope DNS infrastructure (DNS brute-force, wildcard tests, zone transfers). Switch to `OSINT` for passive external-source lookups (certificate transparency logs, public archives, OSINT APIs).

## When to Activate

- Beginning of engagement when the `hosts` array in scope.json includes `*.domain` entries (e.g., `*.target.example`).
- Need to discover additional attack surface beyond the primary domain.
- **Phase 1a (first-class) when scope.json `hosts` contains `*.domain` entries** — dispatched BEFORE the parallel recon+source pass so live subdomains land in the endpoint inventory before downstream steps depend on them.
- After finding references to subdomains in JS/HTML source code.

## Tooling preflight

Before any active step, confirm every binary in the chain is reachable inside the runtime — puredns silently fails when massdns is missing (zero output, no error, exit code 0), and a dnsx fallback against a typical bruteforce wordlist will spike container CPU before stabilizing. Run the preflight once at the top of Phase 1a:

```bash
aith assess kali exec --technique HEALTH --intent "subdomain-enum tooling preflight" \
  --probe-kind fingerprint --phase recon --timeout 60 -- \
  which alterx asnmap bbot cero dnsx massdns puredns shuffledns subfinder
```

If any binary is missing, do NOT silently fall back — pause active enumeration and dispatch a runtime fix:

1. Confirm the runtime image tag is current (`aith runtime resources`).
2. If the image is current and the binary is still missing, the runtime image needs a rebuild — `agent/docker/runtime-full/Dockerfile` is the source of truth (see `agent/references/tools/recon/subdomain-enumeration-tools.md` for the canonical tier table).
3. Re-run the preflight after `aith runtime restart`.

The runtime image is heavy by design — every binary in the preflight list is already installed in `runtime-full`. A missing binary indicates image drift, not a tooling gap.

DNS resolution success-rate parallels the egress reputation problem: if every host resolves but no host responds with HTTP signal, run the egress reputation check first (`agent/references/runtime-guides/cdn-ip-blocking.md`) before assuming a tooling failure.

## Docker-resource-safe profiles

Subdomain enumeration is the highest-CPU-burst phase of recon. Docker's cgroup limits (`AITH_RUNTIME_MEMORY_GB` / `AITH_RUNTIME_CPUS` / `AITH_RUNTIME_PIDS_LIMIT` / `AITH_RUNTIME_SHM_SIZE` from `.env.example`) bound container userland, but a DNS-heavy profile against the wrong target tier can still saturate host-side Docker networking. Pick the profile by target shape, not by what the apex looks like — wildcards expand the surface and the rate calibration must match the surface, not the seed.

> **Serialize heavy ops on a shared runtime.** Run DNS-heavy passes (puredns/dnsx) and bulk
> `httpx` liveness **one at a time** — never stack a DNS brute and an httpx pass, or two httpx
> passes, concurrently. Even individually-gentle passes compose into a SIGKILL (RC137) under
> aggregate cgroup memory pressure (a solo httpx of 3,875 hosts ran clean; the same load with
> two siblings was killed). This is the skill-level expression of the operator's
> "one heavy enum op at a time" aggregate-concurrency rule (`agent/operator-core.md` → Recon
> Dispatch Resource Policy → Aggregate concurrency).

> **Host-CPU note.** DNS bruteforce is the dominant host-CPU and host-network spike in the engagement runtime. massdns and dnsx can send thousands of DNS packets per second; the host kernel's per-packet network-stack overhead is amplified well beyond what `--cpus` cgroup limits constrain (cgroup CPU limits the userland process, not the host's kernel networking path). Aggressive DNS profiles have crashed Docker on Standard-tier hardware. **The `aith assess kali dnsx` wrapper defaults to `--dnsx-profile polite-cdn --resolver-profile public-tcp`.** Step up to `polite-residential` only after assessing the target, and keep `bursty-OK` gated by runtime tier (see the matrix below). When in doubt, drop a tier.

Profiles and full tier rationale live in `agent/references/tools/recon/subdomain-enumeration-tools.md`; the three operational tiers below are the load-bearing settings, listed from most cautious (default for any unknown target) down to opt-in only.

> **polite-CDN-fronted-target profile** — anything CDN-fronted, behind an enterprise WAF, or in a high-friction policy / regulated category. Target authoritative DNS is rate-limited at the apex; aggressive bursts trigger DNS-tier blocks that persist beyond the engagement.
> - `puredns --rate-limit 800 --wildcard-tests 30`
> - `dnsx -rl 100 -t 20 -retry 3 -timeout 5`
> - Use when: scope target is fronted by a major CDN, has a wildcard DNS that returns canonical CNAMEs, or is a household-name brand.

> **polite-residential profile** — small-medium target, public resolvers, available on every runtime tier. Use it after explicit assessment when the target is not CDN/WAF-sensitive.
> - `puredns --rate-limit 2500 --wildcard-batch 100000`
> - `dnsx -rl 300 -t 50 -retry 2`
> - Use when: bug-bounty scope on residential/SMB infrastructure, shared resolver pool, no specific CDN signal.

> **bursty-OK profile (tier-gated)** — private resolver pool, no shared-infra constraints, target authoritative DNS is generous.
> - `puredns --rate-limit 5000`
> - `dnsx -rl 500 -t 100`
> - Use when: private CTF lab, dedicated resolver list (>100 healthy resolvers), single-engagement runtime.

### Runtime-tier rate ceilings

Read `aith runtime resources` to identify the active tier; the matrix below scales the
opt-up paths. Standard tier never picks `bursty-OK` (RAM pressure on puredns's
wildcard-filter dedup map produces silent truncation under heavy bursts on tight cgroups).

| Runtime tier | cautious (`polite-CDN-fronted-target`, 800) | residential (`polite-residential`, 2500) | bursty-OK (5000) |
|---|---|---|---|
| Standard (8 GB / 4 CPUs) | available | available | NOT available |
| Heavy | available | available | opt-in (pass the opt-in note in `--intent`) |
| Comfortable | available | available | default-available — pick when target shape allows |

When the runtime tier is tighter than Standard (e.g. `AITH_RUNTIME_MEMORY_GB=4`), drop the next tier down regardless of target shape — RAM pressure on puredns's wildcard-filter dedup map produces silent truncation, not a clean OOM.

## Phase 0/1/2/3 staged composition

Each phase compounds on the previous one. Stop at any phase when its bound rule fires (see "Bound rules" below). Cross-reference the verb invocations in `agent/skills/kali-exec/SKILL.md` "Subdomain enumeration: Phase A→D workflow" — this section describes operator-phase-flow ordering and resource shaping.

### Phase 0 — Passive enumeration (always-on)

`subfinder` aggregates 30+ public sources without sending traffic to the target. API keys lift coverage to ~90%+ — the worth-it free keys (SecurityTrails, Censys, VirusTotal, Shodan) are configured via `${SUBFINDER_*_API_KEY}` env vars in `.env.example`. Pair with chaos and github-subdomains (already wired into the bbot subdomain-enum preset) for the broadest passive sweep.

```bash
# NON-recursive by default. `-recursive` saturated the Docker daemon on large
# apexes (army.mil: 4,289 subs → docker-ps health-checks timed out) and adds
# little over `-all` on most targets. Reserve `-recursive` for a DEDICATED
# runtime; on a shared/Standard runtime keep it off.
aith assess kali subfinder -d target.example -all -t 20 -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  --technique RECON --intent "Phase 0 passive subdomain enum (non-recursive)" \
  --probe-kind fingerprint --phase recon --timeout 600
```

When budget allows the longer wall-clock, follow with bbot for deeper passive coverage (50+ sources):

```bash
aith assess kali bbot -t target.example -p subdomain-enum -rf passive \
  -o /engagements/$ENGAGEMENT_KEY/scans/bbot_subs \
  --technique OSINT --intent "Phase 0 deep passive enum (bbot subdomain-enum preset)" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

### Phase 0b — Certificate Transparency (always-on, first-class)

CT logs are a primary passive source, not an afterthought — in a real engagement CT
harvest added **+1,758 net-new** `.mil` hostnames over subfinder/bbot alone, and on
DNS-sink apexes (see Phase 1 wildcard gating) CT is the *only* source that cuts through the
noise. Run it on every engagement, in parallel-conceptually-but-serialized-on-shared-runtime
with Phase 0, before any active brute.

```bash
# Per-apex crt.sh query WITH backoff — crt.sh rate-limits aggressively and returns
# empty 4-byte bodies under load, so retry with backoff rather than trusting a single
# empty response. (Run via the audited host-exec / kali lane as configured.)
for apex in $(cat /engagements/$ENGAGEMENT_KEY/scans/apexes.txt); do
  for attempt in 1 2 3; do
    out=$(curl -s "https://crt.sh/?q=%25.${apex}&output=json")
    [ "$(printf '%s' "$out" | wc -c)" -gt 8 ] && break
    sleep $((attempt * 5))   # backoff: 5s, 10s, 15s
  done
  printf '%s' "$out" | jq -r '.[].name_value' 2>/dev/null
done | sed 's/^\*\.//' | sort -u >> /engagements/$ENGAGEMENT_KEY/scans/subs_ct.txt
```

**certspotter / alternate-CT fallback (when crt.sh blocks):** if crt.sh stays empty after
backoff, fall back to certspotter (`https://api.certspotter.com/v1/issuances?domain=<apex>&include_subdomains=true&expand=dns_names`)
or another CT aggregator. In the reference engagement this fallback recovered 1,916 CT hosts
once crt.sh was rate-limited. Merge `subs_ct.txt` into the Phase 2.5 union like any other source.

### Phase 1 — Active brute (gated by Phase 0 size, SKIP on DNS-sink apexes)

> **Detect wildcard / DNS-sink apexes BEFORE bruteforcing.** Resolve a handful of random
> nonexistent labels at the apex (e.g. `rande7x9.<apex>`); if they return a stable A/CNAME the
> apex is a wildcard *sink* (e.g. `af.mil`, `africom.mil` returned 12,386 raw → 8 real;
> MAC-shaped and `dhcp-*.rev` PTR floods). On a detected sink, **SKIP DNS brute and PTR
> entirely** and rely on CT (Phase 0b) + TLS SAN (Phase 3) — DNS-based discovery there is pure
> noise that burns the rate budget. Only bruteforce apexes that are NOT wildcard sinks.

`puredns bruteforce` runs the active brute pass through massdns with wildcard filtering. Apply the tier profile. For wildcard-heavy targets (apex returns a wildcard answer for nonexistent labels), keep `--wildcard-tests` at 30 so the filter probes more candidates per wildcard cluster.

```bash
# polite-residential default (Standard runtime, no specific CDN signal)
aith assess kali puredns bruteforce \
  /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt target.example \
  -r /engagements/$ENGAGEMENT_KEY/wordlists/resolvers.txt \
  --rate-limit 2500 --wildcard-batch 100000 --wildcard-tests 30 \
  -w /engagements/$ENGAGEMENT_KEY/scans/subs_brute.txt \
  --technique RECON --intent "Phase 1 active brute @ polite-residential rate" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

Skip Phase 1 entirely when Phase 0 returned >5000 unique subs or the target is a top-tier organization — passive sources have already saturated the namespace and permutation bursts add live hosts at <0.1% rate (see `subdomain-enumeration-tools.md` "When NOT to bruteforce").

Conversely, when Phase 0 returned **0 or fewer than 10 subs**, treat that as a signal that either the configured passive-source API keys are misconfigured (check `${SUBFINDER_*_API_KEY}` env vars) or the target genuinely has no public footprint. In both cases Phase 1 brute is the only signal source — run it, BUT cap it at the cautious-tier rate (`polite-CDN-fronted-target` / `puredns --rate-limit 800`) regardless of target shape, since the wordlist is the only signal and faster rates produce noise rather than coverage. Record the rationale via `aith assess log operator "Phase 0 returned <10 subs — Phase 1 brute @ cautious-tier as sole signal source" "<phase-0 count>" --actor-kind operator`.

### Phase 2 — Permutation (estimate-first)

`alterx` expands the known-subdomain set 10-100x using built-in patterns. Always run `-enrich -estimate` first to bound the expansion before generating candidates — a 1000-sub input with default patterns can produce 200k+ candidates, and a 5000-sub input can break 500k.

```bash
# Step 2a: estimate first to avoid 500k+ explosions
aith assess kali alterx -l /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  -enrich -estimate \
  --technique RECON --intent "Phase 2 permutation estimate (no candidate output)" \
  --probe-kind fingerprint --phase recon --timeout 120

# Step 2b: cap at 100k candidates
aith assess kali alterx -l /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  -enrich -limit 100000 \
  -o /engagements/$ENGAGEMENT_KEY/scans/perms.txt \
  --technique RECON --intent "Phase 2 permutation candidates capped at 100k" \
  --probe-kind fingerprint --phase recon --timeout 600

# Step 2c: resolve the permutation set through puredns (wildcard-aware)
aith assess kali puredns resolve /engagements/$ENGAGEMENT_KEY/scans/perms.txt \
  -r /engagements/$ENGAGEMENT_KEY/wordlists/resolvers.txt \
  --rate-limit 2500 --wildcard-batch 100000 \
  -w /engagements/$ENGAGEMENT_KEY/scans/perms_resolved.txt \
  --technique RECON --intent "Phase 2 permutation resolve through puredns" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

Abort Phase 2 if the estimate exceeds 500k candidates — narrow the input set first (focus on subdomains that share an apex CNAME or look like staging/dev clusters) instead of resolving a candidate set that will spend hours of runtime CPU for marginal yield.

If `perms_resolved.txt` is empty (alterx produced no expansions or every permutation fell into a wildcard sink), Phase 3 still runs — it consumes `subs_merged.txt` directly, which contains the Phase 0 + Phase 1 union below.

### Phase 2.5 — Merge intermediate outputs

Phase 3 reads from `subs_merged.txt`. Build it once, after Phase 2, by unioning the Phase 0 / Phase 1 / Phase 2 outputs:

```bash
aith assess kali exec --technique RECON \
  --intent "Phase 2.5 merge of passive + brute + permutation outputs" \
  --probe-kind baseline --phase recon --timeout 60 -- bash -c '
  cat /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
      /engagements/$ENGAGEMENT_KEY/scans/subs_brute.txt \
      /engagements/$ENGAGEMENT_KEY/scans/perms_resolved.txt 2>/dev/null \
    | sort -u > /engagements/$ENGAGEMENT_KEY/scans/subs_merged.txt
'
```

When a phase did not run (Phase 1 skipped, Phase 2 aborted), the missing file is silently skipped by the redirect and the merge still produces a valid union of the surviving phases.

### Phase 3 — TLS SAN feedback loop (always-on after 2)

`httpx -tls-grab` and `cero` extract Subject Alternative Names from TLS handshakes. Two complementary patterns:

1. **httpx with `-tls-grab` against the merged sub list** — emits SAN, issuer, validity, and JARM hash in the JSON output. Catches wildcards (`*.foo.target.example`) and shared-cert tenants.
2. **cero against asnmap-derived CIDR ranges** — TCP/TLS handshake on 443/8443/9443 across the target's owned CIDR. Catches subdomains that never appear in CT logs (private CAs, internal stages on internet-exposed IPs).

```bash
# httpx feedback loop — NO -tech-detect on this bulk pass. tech-detect amplifies
# httpx memory under cgroup pressure and was a SIGKILL (RC137) trigger on large
# merged lists. This pass only needs the SAN/TLS grab; tech-detect the confirmed-
# live subset later (Phase: Filter/verify/ingest), not the full merged set.
aith assess kali httpx -l /engagements/$ENGAGEMENT_KEY/scans/subs_merged.txt \
  -tls-grab -tls-probe -status-code -title -json \
  -o /engagements/$ENGAGEMENT_KEY/scans/httpx_tls.jsonl \
  --technique DISCOVERY --intent "Phase 3 TLS SAN harvest via httpx -tls-grab (status-only, no tech-detect)" \
  --probe-kind fingerprint --phase recon --timeout 1200

# asnmap → cero CIDR sweep
aith assess kali asnmap -d target.example -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/target_cidrs.txt \
  --technique OSINT --intent "Phase 3 ASN → CIDR mapping for cero feed" \
  --probe-kind fingerprint --phase recon --timeout 300

aith assess kali cero -l /engagements/$ENGAGEMENT_KEY/scans/target_cidrs.txt \
  -p 443,8443,9443 -c 100 -t 4 \
  -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans.txt \
  --technique OSINT --intent "Phase 3 TLS SAN scrape across owned CIDRs" \
  --probe-kind fingerprint --phase recon --timeout 600

# Final pass: dnsx resolves the merged set, drives live-host confirmation
aith assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/subs_merged.txt \
  --dnsx-profile polite-cdn --resolver-profile public-tcp -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/dnsx_final.txt \
  --technique RECON --intent "Phase 3 final dnsx resolution (lean — no JSON on bulk)" \
  --probe-kind baseline --phase recon --timeout 600
```

The lean dnsx invocation (no `-json`, no `-resp` on bulk inputs) is deliberate — see `agent/references/tools/recon/dnsx.md` for the NXDOMAIN/CPU spike pattern. Enrich survivors with a second JSON pass only after the merged set is filtered.

## TLS SAN extraction as a primary source

Phase 3 above treats TLS SAN extraction as a *feedback* step — applied after passive + active + permutation. That ordering is correct for greenfield enumeration on a new wildcard, but in two situations the SAN set is a *primary* source rather than a feedback loop:

1. **Cross-host SAN collision is signaling a shared multi-tenant cert.** When the
   web-recon TLS / SAN / vhost cross-host pass surfaces SAN entries that appear in two
   or more hosts' certs (the count >= 2 entries from
   `agent/references/tools/recon/openssl-sans.md` step 2), each SAN entry is a candidate
   subdomain even when no passive source records it — multi-tenant certs commonly
   embed staging / internal tenant SANs that never appear in CT logs.
2. **vhost-cert mismatch flags a frontend exposing a non-matching default cert.** When
   the cert's CN or first SAN does not match the requested hostname, the cert's actual
   CN / SANs are adjacent attack surface — the frontend serves the requested name but
   the cert proves the host is sitting on a shared edge whose default certificate
   covers a different name.

In both cases, treat the SAN set as a primary subdomain source and feed it through
`dnsx -resp` for live-host confirmation after SAN extraction:

```bash
# Per-host SAN extraction (full recipe in openssl-sans.md step 1)
aith assess kali exec --technique RECON \
  --intent "per-host TLS SAN extraction as primary subdomain source" \
  --probe-kind fingerprint --phase recon --timeout 300 -- bash -c '
  while read HOST; do
    OUT="/engagements/$ENGAGEMENT_KEY/scans/sans_${HOST}.txt"
    echo | timeout 10 openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null \
      | openssl x509 -noout -ext subjectAltName 2>/dev/null \
      | grep -oE "DNS:[^,]+" | sed "s/DNS://" | sort -u > "$OUT"
  done < /engagements/$ENGAGEMENT_KEY/scans/in_scope_hosts.txt
'

# Merge SAN-discovered names.
aith assess kali exec --technique RECON \
  --intent "merge SAN-discovered subdomains" \
  --probe-kind fingerprint --phase recon --timeout 300 -- bash -c '
  cat /engagements/$ENGAGEMENT_KEY/scans/sans_*.txt | sort -u \
    > /engagements/$ENGAGEMENT_KEY/scans/san_candidates.txt
'

# Confirm the SAN-discovered names through the typed dnsx verb.
aith assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/san_candidates.txt \
  --dnsx-profile polite-cdn --resolver-profile public-tcp \
  -a -resp -silent -o /engagements/$ENGAGEMENT_KEY/scans/san_live.txt \
  --technique RECON --intent "dnsx -resp confirmation of SAN-discovered subdomains" \
  --probe-kind fingerprint --phase recon --timeout 600
```

`san_live.txt` is the primary input to `aith assess ingest-endpoints "$ENGAGEMENT_DIR/cases.db" subdomain-enum` for this dispatch. The full openssl extraction loop, the cross-host collision counter, and the vhost-cert match check live in `agent/references/tools/recon/openssl-sans.md` — call into it from this section rather than duplicating mechanics here.

This section does NOT replace the Phase 3 TLS SAN feedback loop above; it sits alongside it. The Phase 3 loop is the breadth-first sweep across the merged sub list (post-Phase 0/1/2). The SAN-as-primary section fires when the cross-host signal is already strong (a shared multi-tenant cert was detected, or a vhost-cert mismatch was found), so the enumeration is depth-first against the cert's actual coverage set rather than breadth-first against the apex's enumerated subset.

## Bound rules

Stopping criteria are explicit because subdomain enumeration is the easiest place to burn a runtime budget on diminishing returns.

- **subfinder is non-recursive by default; `-recursive` is dedicated-runtime-only.** On a shared/Standard runtime never pass `-recursive` — it saturated the Docker daemon on large apexes (army.mil, 4,289 subs). On a dedicated runtime, if you do opt into recursion, cap depth ≤ 2 plus one feedback pass on discovered subs; further recursion produces marketing-tracker subs and stale CDN siblings that don't contribute to attack surface.
- **New-subdomain ratio < 5% of prior round.** When the marginal yield of a new round (additional permutations, deeper bbot modules, expanded wordlist) is under 5% of the cumulative count, stop. The remaining surface is below the cost-per-discovery threshold.
- **Wildcard ratio > 30% (detect EARLY, before brute).** When more than 30% of resolved hits land on the same wildcard answer (single A record, single CNAME), the apex is a wildcard sink and brute force is pure noise. Detect this up front with the random-label probe in Phase 1, not only mid-run. On a detected sink, route to **CT (Phase 0b) + TLS SAN / asnmap (Phase 3)** and skip DNS brute/PTR entirely — wildcard-fronted hosts still have unique certs, and CT/SAN are the sources that cut through the sink.
- **Permutation estimate > 500k candidates.** Abort Phase 2 and narrow the input set before resolving. A 500k+ candidate run costs ~30+ minutes of runtime CPU at polite-residential rates and produces sub-1% live-host yield.

When stopping early, record the rationale via `aith assess log operator "Subdomain enum bound rule fired" "<rule>" "<round-stats>" --actor-kind operator` so the audit trail explains the missing rounds instead of leaving an unexplained coverage gap.

## When bbot replaces the manual pipeline

bbot's `subdomain-enum` preset chains 50+ passive sources, CT, DNS aggregators, and security feeds in one invocation — for one-shot bug-bounty work or first-pass coverage on a new wildcard, it produces the same surface as the manual Phase 0+1+3 pipeline with less orchestration overhead. Reach for bbot when:

- The engagement is a single-pass coverage sweep (e.g. bug-bounty triage on a new asset).
- You need broad coverage and the runtime budget tolerates a 15-30 minute wall-clock.
- The target is unfamiliar — bbot's module breadth catches surfaces a manual pipeline might skip.

Reach for the manual pipeline when:

- You need surgical pacing (CDN-fronted target, rate-sensitive infrastructure).
- The pipeline integrates with custom orchestration (asnmap → cero feedback, alterx with engagement-specific patterns).
- You are extending coverage on an already-enumerated apex — bbot would re-run sources you've already exhausted.

The two are complementary, not exclusive. A common pattern is bbot first-pass for breadth, manual Phase 1+2+3 second-pass for depth on the highest-signal subs.

## Process-cleanup discipline

Run each subdomain scan **synchronously** (one blocking `aith assess kali <verb> … --timeout N`
at a time) — specialists do not background target traffic or use `kali job start` (operator-only;
see `agent/shared-constraints.md` §2). A long enum is handled by a generous `--timeout`, which
cascades SIGTERM→SIGKILL into the in-container PID on expiry, so no manual cleanup is needed.
Never use broad `pkill`/`killall` — it stomps sibling agents in the shared runtime. See
`agent/references/runtime-guides/kali-cli.md` "Process cleanup discipline" for the run-uuid
PID-file pattern when a mid-run kill is genuinely required.

## Filter, verify, and ingest

After staged enumeration, run the live-host filter pipeline before ingesting subdomains into the work buffer. Only verified live web entries enter the engagement pipeline.

```bash
# Stage 0: DE-NOISE before httpx. Passive/CT/PTR enumeration inflates the merged
# list ~10x with non-host artifacts that each cost a full httpx timeout for ~0
# yield. Drop DNS service records and PTR/workstation noise BEFORE probing, and
# order real apexes ahead of CDN-wildcard blocks so they aren't starved behind a
# tar-pit (e.g. a 13k Akamai-wildcard block timed out httpx before it reached
# navy.mil's 4,818 real subs).
grep -viE '(^|\.)(_dmarc|_dkim|_domainkey|_acme-challenge)\.' \
     /engagements/$ENGAGEMENT_KEY/scans/subs_merged.txt \
  | grep -viE '(^|\.)(dhcp-|dha-[0-9]+-[0-9]+|dhpcile[0-9]+)' \
  | grep -viE '(-laptop|-kw|-desktop)(\.|$)' \
  | grep -viE '^[0-9a-f]{2}-[0-9a-f]{2}-' \
  | grep -viE '\.rev\.' \
  | sort -u > /engagements/$ENGAGEMENT_KEY/scans/subs_denoised.txt

# Stage 1: HTTP probing with httpx — status-only on the bulk pass. NO -tech-detect
# here (it amplifies httpx memory under cgroup pressure → RC137 SIGKILL on large
# lists). tech-detect the confirmed-live subset in Stage 1b only.
aith assess kali httpx -l /engagements/$ENGAGEMENT_KEY/scans/subs_denoised.txt \
  -status-code -title -server -content-length -follow-redirects -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/subdomains_live.txt \
  --technique DISCOVERY --intent "live-host confirmation on de-noised sub list (status-only)" \
  --probe-kind fingerprint --phase recon --timeout 1200

# Stage 1b: tech-detect ONLY the confirmed-live subset (small, safe).
awk '{print $1}' /engagements/$ENGAGEMENT_KEY/scans/subdomains_live.txt | sort -u \
  > /engagements/$ENGAGEMENT_KEY/scans/subs_live_only.txt
aith assess kali httpx -l /engagements/$ENGAGEMENT_KEY/scans/subs_live_only.txt \
  -tech-detect -json -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/subdomains_tech.jsonl \
  --technique DISCOVERY --intent "tech-detect on confirmed-live subset only" \
  --probe-kind fingerprint --phase recon --timeout 600

# Stage 2: ingest verified live subs into the work buffer
awk '{print $1}' "$ENGAGEMENT_DIR/scans/subdomains_live.txt" | sort -u | while IFS= read -r sub; do
  echo "GET https://$sub"
done | aith assess ingest-endpoints "$ENGAGEMENT_DIR/cases.db" subdomain-enum
```

After ingestion, the operator triggers a reactive nuclei sweep against the newly-live subdomains — see `agent/skills/nuclei-scanning/SKILL.md` "Reactive Sweep Mode".

## What to Record

- **Total subdomains found** (passive + active + permutation + TLS SAN), broken down by source.
- **Live subdomains** with HTTP status codes.
- **Interesting subdomains**: staging, dev, admin, api, internal, test, beta.
- **Services** running on non-standard ports.
- **Source** of each subdomain (subfinder source, brute-force, alterx permutation, cero SAN, asnmap CIDR).
- Any subdomain pointing to **different infrastructure** (cloud, CDN, third-party).
- The hypothesis each interesting subdomain suggests: auth bypass, stale deployment, separate trust zone, or chain opportunity.
- Bound-rule firings: any phase that stopped early, the rule that fired, and the cumulative count at the firing.

## Extended Resources

- `agent/references/recon/rate-calibration.md` — canonical per-target rate calibration; the DNS-brute column gates puredns/shuffledns invocations. Tier-pick prose lives in `agent/operator-core.md` "Recon Dispatch Resource Policy".
- `agent/references/tools/recon/subdomain-enumeration-tools.md` — comparison matrix, API-key value-for-cost, puredns rate guidance, alterx permutation chain, cero CIDR-feed, bbot passive preset, when-not-to-bruteforce signals.
- `agent/skills/kali-exec/SKILL.md` — Phase A→D workflow with example invocations (kali-cli foundational skill).
- `agent/references/tools/recon/puredns.md` — massdns dependency, wildcard tuning, rate-limit ceilings.
- `agent/references/tools/recon/dnsx.md` — NXDOMAIN/CPU spike pattern, two-step brute-then-enrich, GOMAXPROCS profile.
- `agent/references/tools/recon/cero.md` — TLS SAN scraper post-asnmap CIDR feed.
- `agent/references/tools/recon/openssl-sans.md` — per-host TLS SAN extraction loop, cross-host SAN collision counter, vhost / cert mismatch detection, multi-time DNS resolution recipe; powers the "TLS SAN extraction as a primary source" section.
- `agent/references/tools/recon/alterx.md` — permutation generator with `{{sub}}/{{suffix}}` DSL.
- `agent/references/tools/recon/asnmap.md` — CIDR mapping by ASN, feeds cero.
- `agent/references/tools/recon/bbot.md` — multi-module passive preset.
- `agent/references/tools/recon/shuffledns.md` — lighter alternative to puredns.
- `agent/references/tools/recon/httpx.md` — HTTP probing and TLS-grab.
- `agent/references/subdomain-enumeration.md` — prioritization, sliding-window, and bound-rule companion doc.
