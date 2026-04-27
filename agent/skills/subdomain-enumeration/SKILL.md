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
aith assess kali exec -- which massdns puredns dnsx subfinder shuffledns alterx cero asnmap bbot \
  --technique RECON --intent "subdomain-enum tooling preflight" \
  --probe-kind fingerprint --phase recon --timeout 60
```

If any binary is missing, do NOT silently fall back — pause active enumeration and dispatch a runtime fix:

1. Confirm the runtime image tag is current (`aith runtime resources`).
2. If the image is current and the binary is still missing, the runtime image needs a rebuild — `agent/docker/runtime-full/Dockerfile` is the source of truth (see `agent/references/tools/recon/subdomain-enumeration-tools.md` for the canonical tier table).
3. Re-run the preflight after `aith runtime restart`.

The runtime image is heavy by design — every binary in the preflight list is already installed in `runtime-full`. A missing binary indicates image drift, not a tooling gap.

## Docker-resource-safe profiles

Subdomain enumeration is the highest-CPU-burst phase of recon. Docker's cgroup limits (`AITH_RUNTIME_MEMORY_GB` / `AITH_RUNTIME_CPUS` / `AITH_RUNTIME_PIDS_LIMIT` / `AITH_RUNTIME_SHM_SIZE` from `.env.example`) bound the burst, but a default rate-limit profile against the wrong target tier still saturates the runtime. Pick the profile by target shape, not by what the apex looks like — wildcards expand the surface and the rate calibration must match the surface, not the seed.

> **Host-CPU note.** DNS bruteforce is the dominant host-CPU and host-network spike in the engagement runtime. massdns sends thousands of UDP packets per second; the host kernel's per-packet network-stack overhead is amplified well beyond what `--cpus` cgroup limits constrain (cgroup CPU limits the userland process, not the host's kernel networking path). Aggressive DNS profiles have crashed Docker on standard laptop hardware. **Default to `polite-residential` everywhere.** Step up to `bursty-OK` only on private/lab resolvers AND with explicit operator opt-in (`--intent "bursty DNS — opted in by operator on private resolver"`). When in doubt, drop a tier.

Profiles and full tier rationale live in `agent/references/tools/recon/subdomain-enumeration-tools.md`; the three operational tiers below are the load-bearing settings, listed from most cautious (default for any unknown target) down to opt-in only.

> **polite-CDN-fronted-target profile** — anything CDN-fronted, behind an enterprise WAF, or in a high-friction policy / regulated category. Target authoritative DNS is rate-limited at the apex; aggressive bursts trigger DNS-tier blocks that persist beyond the engagement.
> - `puredns --rate-limit 800 --wildcard-tests 30`
> - `dnsx -rl 100 -t 20 -retry 3 -timeout 5`
> - Use when: scope target is fronted by a major CDN, has a wildcard DNS that returns canonical CNAMEs, or is a household-name brand.

> **polite-residential default** — small-medium target, public resolvers, Standard runtime tier (8 GB / 4 CPUs). **This is the default for any new engagement** — only step away from it after explicit assessment.
> - `puredns --rate-limit 2500 --wildcard-batch 100000`
> - `dnsx -rl 300 -t 50 -retry 2`
> - Use when: bug-bounty scope on residential/SMB infrastructure, shared resolver pool, no specific CDN signal.

> **bursty-OK profile (opt-in only)** — private resolver pool, no shared-infra constraints, target authoritative DNS is generous. **Operator opt-in required** — pass the opt-in note in `--intent` so the audit row records the explicit assessment.
> - `puredns --rate-limit 5000`
> - `dnsx -rl 500 -t 100`
> - Use when: private CTF lab, dedicated resolver list (>100 healthy resolvers), single-engagement runtime, AND the operator has explicitly opted in. Higher ceilings have crashed Docker on standard laptop hardware.

When the runtime tier is tighter than Standard (e.g. `AITH_RUNTIME_MEMORY_GB=4`), drop the next tier down regardless of target shape — RAM pressure on puredns's wildcard-filter dedup map produces silent truncation, not a clean OOM.

## Phase 0/1/2/3 staged composition

Each phase compounds on the previous one. Stop at any phase when its bound rule fires (see "Bound rules" below). Cross-reference the verb invocations in `agent/skills/kali-exec/SKILL.md` "Subdomain enumeration: Phase A→D workflow" — this section describes operator-phase-flow ordering and resource shaping.

### Phase 0 — Passive enumeration (always-on)

`subfinder` aggregates 30+ public sources without sending traffic to the target. API keys lift coverage to ~90%+ — the worth-it free keys (SecurityTrails, Censys, VirusTotal, Shodan) are configured via `${SUBFINDER_*_API_KEY}` env vars in `.env.example`. Pair with chaos and github-subdomains (already wired into the bbot subdomain-enum preset) for the broadest passive sweep.

```bash
aith assess kali subfinder -d target.example -all -recursive -t 30 \
  -o /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  --technique RECON --intent "Phase 0 passive subdomain enum" \
  --probe-kind fingerprint --phase recon --timeout 600
```

When budget allows the longer wall-clock, follow with bbot for deeper passive coverage (50+ sources):

```bash
aith assess kali bbot -t target.example -p subdomain-enum -rf passive \
  -o /engagements/$ENGAGEMENT_KEY/scans/bbot_subs \
  --technique OSINT --intent "Phase 0 deep passive enum (bbot subdomain-enum preset)" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

### Phase 1 — Active brute (gated by Phase 0 size)

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

### Phase 3 — TLS SAN feedback loop (always-on after 2)

`httpx -tls-grab` and `cero` extract Subject Alternative Names from TLS handshakes. Two complementary patterns:

1. **httpx with `-tls-grab` against the merged sub list** — emits SAN, issuer, validity, and JARM hash in the JSON output. Catches wildcards (`*.foo.target.example`) and shared-cert tenants.
2. **cero against asnmap-derived CIDR ranges** — TCP/TLS handshake on 443/8443/9443 across the target's owned CIDR. Catches subdomains that never appear in CT logs (private CAs, internal stages on internet-exposed IPs).

```bash
# httpx feedback loop
aith assess kali httpx -l /engagements/$ENGAGEMENT_KEY/scans/subs_all.txt \
  -tls-grab -tls-probe -tech-detect -status-code -title -json \
  -o /engagements/$ENGAGEMENT_KEY/scans/httpx_tls.jsonl \
  --technique DISCOVERY --intent "Phase 3 TLS SAN harvest via httpx -tls-grab" \
  --probe-kind fingerprint --phase recon --timeout 1200

# asnmap → cero CIDR sweep
aith assess kali asnmap -d target.example -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/target_cidrs.txt \
  --technique OSINT --intent "Phase 3 ASN → CIDR mapping for cero feed" \
  --probe-kind fingerprint --phase recon --timeout 300

aith assess kali cero -d /engagements/$ENGAGEMENT_KEY/scans/target_cidrs.txt \
  -p 443,8443,9443 -c 100 -t 4 \
  -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans.txt \
  --technique OSINT --intent "Phase 3 TLS SAN scrape across owned CIDRs" \
  --probe-kind fingerprint --phase recon --timeout 600

# Final pass: dnsx resolves the merged set, drives live-host confirmation
aith assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/subs_merged.txt \
  -a -cname -resp -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/dnsx_final.txt \
  --technique RECON --intent "Phase 3 final dnsx resolution (lean — no JSON on bulk)" \
  --probe-kind baseline --phase recon --timeout 600
```

The lean dnsx invocation (no `-json`, no `-resp` on bulk inputs) is deliberate — see `agent/references/tools/recon/dnsx.md` for the NXDOMAIN/CPU spike pattern. Enrich survivors with a second JSON pass only after the merged set is filtered.

## Bound rules

Stopping criteria are explicit because subdomain enumeration is the easiest place to burn a runtime budget on diminishing returns.

- **Recursion depth ≤ 2.** subfinder `-recursive` plus a feedback pass on discovered subs is enough; further recursion produces marketing-tracker subs and stale CDN siblings that don't contribute to attack surface.
- **New-subdomain ratio < 5% of prior round.** When the marginal yield of a new round (additional permutations, deeper bbot modules, expanded wordlist) is under 5% of the cumulative count, stop. The remaining surface is below the cost-per-discovery threshold.
- **Wildcard ratio > 30%.** When more than 30% of resolved hits land on the same wildcard answer (single A record, single CNAME), the apex is a wildcard sink and brute force is producing noise. Switch to the TLS SAN / asnmap path (Phase 3) — wildcard-fronted hosts still have unique certs.
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

When dispatching parallel subdomain scans, use `kali job start` lifecycle instead of background-and-pkill — broad pkill stomps on sibling agents in the shared runtime. See `agent/references/runtime-guides/kali-cli.md` "Process cleanup discipline" for the full pattern.

## Filter, verify, and ingest

After staged enumeration, run the live-host filter pipeline before ingesting subdomains into the work buffer. Only verified live web entries enter the engagement pipeline.

```bash
# Stage 1: HTTP probing with httpx
aith assess kali httpx -l /engagements/$ENGAGEMENT_KEY/scans/subs_all.txt \
  -status-code -title -tech-detect -server -content-length -follow-redirects -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/subdomains_live.txt \
  --technique DISCOVERY --intent "live-host confirmation on merged sub list" \
  --probe-kind fingerprint --phase recon --timeout 1200

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

- `agent/operator-core.md` "Recon Dispatch Resource Policy" — canonical per-target rate calibration table; the DNS-brute column gates puredns/shuffledns invocations.
- `agent/references/tools/recon/subdomain-enumeration-tools.md` — comparison matrix, API-key value-for-cost, puredns rate guidance, alterx permutation chain, cero CIDR-feed, bbot passive preset, when-not-to-bruteforce signals.
- `agent/skills/kali-exec/SKILL.md` — Phase A→D workflow with example invocations (kali-cli foundational skill).
- `agent/references/tools/recon/puredns.md` — massdns dependency, wildcard tuning, rate-limit ceilings.
- `agent/references/tools/recon/dnsx.md` — NXDOMAIN/CPU spike pattern, two-step brute-then-enrich, GOMAXPROCS profile.
- `agent/references/tools/recon/cero.md` — TLS SAN scraper post-asnmap CIDR feed.
- `agent/references/tools/recon/alterx.md` — permutation generator with `{{sub}}/{{suffix}}` DSL.
- `agent/references/tools/recon/asnmap.md` — CIDR mapping by ASN, feeds cero.
- `agent/references/tools/recon/bbot.md` — multi-module passive preset.
- `agent/references/tools/recon/shuffledns.md` — lighter alternative to puredns.
- `agent/references/tools/recon/httpx.md` — HTTP probing and TLS-grab.
- `agent/references/subdomain-enumeration.md` — prioritization, sliding-window, and bound-rule companion doc.
