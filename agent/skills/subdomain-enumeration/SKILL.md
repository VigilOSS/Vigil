---
name: subdomain-enumeration
description: Subdomain discovery via subfinder, DNS brute-force, TLS SAN feedback, and resource-tier-aware staged composition
origin: Vigil
---

# Subdomain Enumeration

> **`vigil assess kali` audit flags:** use `--technique RECON` when actively probing in-scope DNS infrastructure (DNS brute-force, wildcard tests, zone transfers). Switch to `OSINT` for passive external-source lookups (certificate transparency logs, public archives, OSINT APIs).

## When to Activate

- Beginning of engagement when the `hosts` array in scope.json includes `*.domain` entries (e.g., `*.target.example`).
- Need to discover additional attack surface beyond the primary domain.
- **Phase 1a (first-class) when scope.json `hosts` contains `*.domain` entries** — the **operator** runs the spine as the `vigil assess recon` job before the 1b recon+source pass; a specialist loads this skill to **assess** that job's output (bound rules, stop reasons, completeness) and recommend re-runs, not to execute the phases itself.
- After finding references to subdomains in JS/HTML source code.

> **Register out-of-scope carve-outs in `scope.json` `out_of_scope` before enumerating.** Wildcard expansion surfaces hosts the program excluded (telecom-PTR space, vendor apexes, carved-out subdomains). The `vigil assess recon` pipeline scope-filters the resolved set between the dns and web stages, so authoring the deny-list up front keeps bulk liveness/crawl off out-of-scope hosts. A carve-out added mid-run only applies on the next `--resume`.

## Tooling preflight

Before any active step, confirm every binary in the chain is reachable inside the runtime — puredns silently fails when massdns is missing (zero output, no error, exit code 0), and a dnsx fallback against a typical bruteforce wordlist will spike container CPU before stabilizing. Run the preflight once at the top of Phase 1a:

```bash
vigil assess kali exec --technique HEALTH --intent "subdomain-enum tooling preflight" \
  --probe-kind fingerprint --phase recon --timeout 60 -- \
  which alterx asnmap bbot cero dnsx github-subdomains massdns puredns shuffledns subfinder tlsx
```

`github-subdomains` (passive Phase 0 source) and `tlsx` (Phase 3 TLS-SAN harvester) are in the preflight set because they are part of the same enumeration chain — a missing one is image drift to fix, not a gap to route around. `github-subdomains` additionally reads a `GITHUB_TOKEN` from the runtime env at probe time (it mines GitHub code search); a missing token degrades that one source to a no-op, which is a configuration gap, not a tooling gap.

If any binary is missing, do NOT silently fall back — pause active enumeration and dispatch a runtime fix:

1. Confirm the runtime image tag is current (`vigil runtime resources`).
2. If the image is current and the binary is still missing, the runtime image needs a rebuild — `agent/docker/runtime-full/Dockerfile` is the source of truth (see `agent/references/tools/recon/subdomain-enumeration-tools.md` for the canonical tier table).
3. Re-run the preflight after `vigil runtime restart`.

The runtime image is heavy by design — every binary in the preflight list is already installed in `runtime-full`. A missing binary indicates image drift, not a tooling gap.

DNS resolution success-rate parallels the egress reputation problem: if every host resolves but no host responds with HTTP signal, run the egress reputation check first (`agent/references/runtime-guides/cdn-ip-blocking.md`) before assuming a tooling failure.

## Docker-resource-safe profiles

> **A DNS brute fans out to PUBLIC RESOLVERS, not to the target — so the rate
> ceiling is NOT a target-politeness lever.** A puredns/shuffledns/massdns brute
> sends every candidate query to the configured public-resolver pool (`-r`). The
> target's authoritative NS sees only a *diluted, cached-NXDOMAIN trickle* —
> resolvers absorb and cache the bulk of the misses, and only de-duplicated
> cache-fills reach the apex's NS. So the brute rate is bounded by **(a)
> public-resolver fair-use** (a too-hot pool gets you REFUSED/throttled by the
> resolver operators, not by the target) and **(b) local runtime network
> capacity** — on macOS Docker Desktop the per-packet userspace-proxy / host-NIC
> overhead, NOT the `--cpus` cgroup (see the Host-CPU note below and
> `agent/references/runtime-guides/docker-desktop-network-hazards.md`, CR-3). Read
> the `800/2500/5000` rate numbers below as **resolver-fair-use + runtime-network
> ceilings**, not as "don't anger the target's DNS." The genuine target-politeness
> levers live on the dir-fuzz / nuclei / nmap columns of
> `agent/references/recon/rate-calibration.md`, which DO hit the target directly —
> the DNS-brute column is governed by resolver load and runtime capacity instead.
> (The rare exception where the cap really does protect an authoritative server is
> when the target IS its own resolver / you point `-r` at the target's NS — don't.)

Subdomain enumeration is the highest-CPU-burst phase of recon. Docker's cgroup limits (`VIGIL_RUNTIME_MEMORY_GB` / `VIGIL_RUNTIME_CPUS` / `VIGIL_RUNTIME_PIDS_LIMIT` / `VIGIL_RUNTIME_SHM_SIZE` from `.env.example`) bound container userland, but a DNS-heavy profile against the wrong target tier can still saturate host-side Docker networking. Pick the profile by target shape, not by what the apex looks like — wildcards expand the surface and the rate calibration must match the surface, not the seed.

> **Route DNS-heavy passes to the HOST on macOS Docker Desktop.** The per-packet
> userspace-proxy overhead (not cgroup CPU) is what crashes Docker Desktop under a
> brute, and the danger knob is the count of **distinct resolver destination IPs**
> (>~50 in-container), not qps — see `docker-desktop-network-hazards.md` (CR-3).
> The composed `vigil assess dns-discovery` verb routes its DNS-heavy stages
> (subfinder/puredns/dnsx) to the audited host path when you pass `--runtime host`
> (or set `VIGIL_RECON_RUNTIME=host`; `VIGIL_RECON_RUNTIME=auto` platform-selects
> host on macOS Docker Desktop). Bare `--runtime auto` stays in-container for
> back-compat. The shipped premium-anycast brute tier (~40 IPs, below) stays under
> the in-container dest-IP ceiling; larger validated resolver lists go via the
> host route. Target HTTP/exploit work always stays in-container — only DNS recon
> is host-routed.

> **Serialize heavy ops on a shared runtime.** Run DNS-heavy passes (puredns/dnsx) and bulk
> `httpx` liveness **one at a time** — never stack a DNS brute and an httpx pass, or two httpx
> passes, concurrently. Even individually-gentle passes compose into a SIGKILL (RC137) under
> aggregate cgroup memory pressure (a solo httpx of 3,875 hosts ran clean; the same load with
> two siblings was killed). This is the skill-level expression of the operator's
> "one heavy enum op at a time" aggregate-concurrency rule (`agent/operator-core.md` → Recon
> Dispatch Resource Policy → Aggregate concurrency).

> **Host-CPU note.** DNS bruteforce is the dominant host-CPU and host-network spike in the engagement runtime. massdns and dnsx can send thousands of DNS packets per second; the host kernel's per-packet network-stack overhead is amplified well beyond what `--cpus` cgroup limits constrain (cgroup CPU limits the userland process, not the host's kernel networking path). Aggressive DNS profiles have crashed Docker on Standard-tier hardware. **The `vigil assess kali dnsx` wrapper defaults to `--dnsx-profile polite-cdn --resolver-profile public-tcp`.** Step up to `polite-residential` only after assessing the target, and keep `bursty-OK` gated by runtime tier (see the matrix below). When in doubt, drop a tier.

Profiles and full tier rationale live in `agent/references/tools/recon/subdomain-enumeration-tools.md`; the three operational tiers below are the load-bearing settings, listed from most cautious (default for any unknown target) down to opt-in only.

> **polite-CDN-fronted-target profile** — anything CDN-fronted, behind an enterprise WAF, or in a high-friction policy / regulated category. The reason to stay slow here is **resolver fair-use + Docker-proxy NAT pressure** (CR-2), NOT the target's authoritative DNS — a CDN-fronted apex sees only the diluted cached-NXDOMAIN trickle, but a hot brute through public resolvers gets *you* REFUSED-throttled and wedges the userspace proxy. The `800` is a resolver+runtime ceiling, not a target-politeness number.
> - `puredns --rate-limit 800 --wildcard-tests 30`
> - `dnsx -rl 100 -t 20 -retry 3 -timeout 5`
> - Use when: scope target is fronted by a major CDN, has a wildcard DNS that returns canonical CNAMEs, or is a household-name brand.

> **polite-residential profile** — small-medium target, public resolvers, available on every runtime tier. Use it after explicit assessment when the target is not CDN/WAF-sensitive. (The `2500` is again a resolver-pool + runtime ceiling, not a target-DNS number.)
> - `puredns --rate-limit 2500 --wildcard-batch 100000`
> - `dnsx -rl 300 -t 50 -retry 2`
> - Use when: bug-bounty scope on residential/SMB infrastructure, shared resolver pool, no specific CDN signal.

> **bursty-OK profile (tier-gated)** — dedicated/premium resolver pool that behaves under bulk load, no shared-infra constraints, generous local runtime network capacity.
> - `puredns --rate-limit 5000`
> - `dnsx -rl 500 -t 100`
> - Use when: private CTF lab, dedicated resolver list (premium-anycast or a validated pool that holds up under bulk load — see the two-tier resolver strategy in Phase 1), single-engagement runtime. On macOS Docker Desktop, run this tier via `--runtime host` so the resolver fan-out is not bounded by the in-container dest-IP ceiling.

> **Composed-verb rate knob.** `vigil assess dns-discovery --dns-rate <qps>` sets the puredns `--rate-limit` (TOTAL qps across the whole resolver pool, NOT per-resolver — CR-1; default 1500). The same resolver-load-not-target-politeness framing applies: pick `--dns-rate` against resolver fair-use + the per-resolver-qps advisory (see "Per-engagement DNS query budget" below), not against the target's apex.

### Runtime-tier rate ceilings

Read `vigil runtime resources` to identify the active tier; the matrix below scales the
opt-up paths. Standard tier never picks `bursty-OK` (RAM pressure on puredns's
wildcard-filter dedup map produces silent truncation under heavy bursts on tight cgroups).

| Runtime tier | cautious (`polite-CDN-fronted-target`, 800) | residential (`polite-residential`, 2500) | bursty-OK (5000) |
|---|---|---|---|
| Standard (8 GB / 4 CPUs) | available | available | NOT available |
| Heavy | available | available | opt-in (pass the opt-in note in `--intent`) |
| Comfortable | available | available | default-available — pick when target shape allows |

When the runtime tier is tighter than Standard (e.g. `VIGIL_RUNTIME_MEMORY_GB=4`), drop the next tier down regardless of target shape — RAM pressure on puredns's wildcard-filter dedup map produces silent truncation, not a clean OOM.

### Per-engagement DNS query budget

Choose brute scope against a **stated budget up front**, not by discovering the cost mid-run (CR-23). Two numbers, distinct from the total-qps tiers above:

- **Total planned DNS queries** — a brute fans out roughly `wordlist_lines × target_count` queries (plus wildcard tests and the productive-parent re-brutes). The composed verb estimates this before the brute and **WARNs** when it would exceed `--query-budget` (default 5,000,000) — it proceeds (advisory, never a hard block), but the WARN is your cue to trim the wordlist (`--wordlist-head`) or the target set before spending the budget.
- **Per-resolver qps** — derived as `--dns-rate ÷ healthy-resolver-count` (NOT a separate knob; `--dns-rate`/`--rate-limit` is TOTAL qps across the pool, CR-1). The verb WARNs when the derived per-resolver qps exceeds `--per-resolver-qps` (default 1500) so a small pool driven at a high total rate doesn't burn resolver fair-use. Lower `--dns-rate` or add resolvers.

Both are advisory WARNs surfaced by `vigil assess dns-discovery`, consistent with this skill's "guidance is a cue, not a CLI gate" posture. Size the brute against them before launching, and record the chosen scope-vs-budget call in the bound-rule audit log.

## Phase 0/1/2/3 staged composition

> **Composed pipeline shortcut.** `vigil assess dns-discovery <apex…>` is the
> **convergent** DNS spine: it loops the Phase-0/0b/1/1.5 DNS methods (subfinder
> passive + CT/crt.sh + optional puredns brute + productive-parent recursion) →
> merge + de-noise → per-parent wildcard pre-strip → dnsx-resolve, **repeating
> until two consecutive passes add zero net-new resolved hosts** (`--max-passes`,
> default 3; `--no-converge` for a single pass). `vigil assess web-discovery
> <resolved_hosts.txt>` runs the Phase-3 web side (de-noise → httpx liveness →
> auto-populate the `assessment_host_liveness` ledger → katana crawl → optional
> work-buffer ingest). Both expose every knob as a flag
> (`--recursive`, `--brute`, `--wordlist`/`--wordlist-head`/`--deep-tail`,
> `--resolvers`/`--resolvers-trusted`/`--no-default-resolvers`, `--dns-rate`,
> `--dnsx-profile`, `--runtime {auto,host,container}`, `--max-passes`/`--no-converge`,
> `--no-parent-recursion`/`--parent-min-children`, `--no-wildcard-strip`,
> `--query-budget`/`--per-resolver-qps`, opt-in `--js-host-mining`/`--bbot`,
> `--ports`, `--katana-depth`/`--katana-extra-args`, …) and bake in the safe
> defaults this skill documents (non-recursive subfinder, brute OFF, two-tier
> shipped resolvers, HEAD-capped wordlist, de-noised inputs, status-only bulk
> httpx, stdin-safe exec). On macOS Docker Desktop add `--runtime host` (or set
> `VIGIL_RECON_RUNTIME=host|auto`) so the DNS-heavy stages route to the audited
> host path and dodge the userspace-proxy wedge
> (`agent/references/runtime-guides/docker-desktop-network-hazards.md`). Use the
> verb for the mechanical pipe; the manual stages below remain the reference for
> tuning and for steps the verb doesn't cover.

> **Supervised one-shot — `vigil assess recon <apex…>`.** When a long DNS/brute
> pass would otherwise be a multi-minute blocking call (the failure mode that
> kills a halting subagent), the **operator** runs the whole spine as one
> supervised, resumable, pollable job instead: `vigil assess recon <apex…>`
> orchestrates `dns-discovery → web-discovery` as **checkpointed stages** (each
> stage's canonical artifact is its checkpoint; `--resume` restarts from the first
> incomplete stage, so a killed run re-runs cleanly with no redo and no orphans).
> It writes `scans/recon/recon-status.json` after every stage. With `--background`
> it spawns the pipeline as a **detached host job** and returns a job id
> immediately — poll `vigil assess recon-status [--job-id N]` (a read-only digest:
> per-stage state + counts + "% complete + what's next") instead of blocking. On
> macOS Docker Desktop the DNS-heavy stages are **enforced** host-side (a missing
> host binary fails the preflight rather than silently wedging the proxy, I-001);
> `--runtime container` forces isolation and bypasses the enforcement. Flags:
> `--brute`, `--no-crawl`, `--resume`, `--runtime {auto,host,container}`,
> `--stage-timeout`, `--background`.

Each phase compounds on the previous one. Stop at any phase when its bound rule fires (see "Bound rules" below). Cross-reference the verb invocations in `agent/skills/kali-exec/SKILL.md` "Subdomain enumeration: Phase A→D workflow" — this section describes operator-phase-flow ordering and resource shaping.

### Phase 0 — Passive enumeration (always-on)

`subfinder` aggregates 30+ public sources without sending traffic to the target. API keys lift coverage to ~90%+ — the worth-it free keys (SecurityTrails, Censys, VirusTotal, Shodan) are configured via `${SUBFINDER_*_API_KEY}` env vars in `.env.example`. Pair with chaos and github-subdomains (already wired into the bbot subdomain-enum preset) for the broadest passive sweep.

```bash
# NON-recursive by default. `-recursive` saturated the Docker daemon on large
# apexes (army.mil: 4,289 subs → docker-ps health-checks timed out) and adds
# little over `-all` on most targets. Reserve `-recursive` for a DEDICATED
# runtime; on a shared/Standard runtime keep it off.
vigil assess kali subfinder -d target.example -all -t 20 -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  --technique RECON --intent "Phase 0 passive subdomain enum (non-recursive)" \
  --probe-kind fingerprint --phase recon --timeout 600
```

When budget allows the longer wall-clock, follow with bbot for deeper passive coverage (50+ sources):

```bash
vigil assess kali bbot -t target.example -p subdomain-enum -rf passive \
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

### Phase 0c — GeoDNS multi-region + DNSSEC/AXFR probe-once (cheap one-shots, run before brute)

These are cheap, single-shot DNS probes that belong before/alongside the passive sources, not in the brute loop. The full dnsx/dig mechanics live in `agent/references/tools/recon/dnsx.md` ("GeoDNS multi-region resolver pass" and "DNSSEC / AXFR — probe once, then skip") — call into it rather than duplicating the recipes; the methodology is summarised here (CR-10).

- **GeoDNS / multi-region resolver pass.** Targets on a GeoDNS / GSLB provider return geo-varying A/CNAME records. Re-resolve the apex + a sample of resolved hosts against resolvers pinned to ≥2-3 distinct geographies (a small curated multi-region set — Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9 `9.9.9.9` plus a couple region-pinned anycast IPs — or use `dig +subnet=<client-subnet>` EDNS-Client-Subnet to spoof the source region) and **diff the answer sets**. When records vary by region, record each region's A/CNAME set as separate surface and feed the geo-specific origin IPs to the Phase 3 cero/cert grab. Keep the multi-region resolver-IP count small so the pass stays under the Docker per-destination-IP ceiling (`agent/references/runtime-guides/docker-desktop-network-hazards.md`, CR-3); the `dig +subnet=` form avoids the extra dest-IPs entirely.
- **DNSSEC probe-once.** One `dnsx -ns` to get the authoritative NS, then a single dig DNSKEY/RRSIG presence check (`dig +dnssec DNSKEY <apex> @<ns>` — dnsx has no DNSSEC flag). Only if RRSIG/NSEC records are present **and** the zone is **NSEC** (not NSEC3, which is hashed) is NSEC-walking applicable (`ldns-walk` / `nsec3walker`). Otherwise log `DNSSEC absent / NSEC3 — skip walk` and move on.
- **AXFR probe-once.** For each authoritative NS, one `dig AXFR @<ns> <apex>` (or nmap `--script dns-zone-transfer`). On the near-universal REFUSED/timeout, record `AXFR refused — skip` so no later step retries it.

Run each probe as a single audited `vigil assess kali` call so it cannot loop or spike DNS, and record the skip decision (DNSSEC absent / NSEC3 / AXFR refused) in the bound-rule audit log so a not-walked zone is an explicit, justified skip rather than a coverage gap (mirror the `vigil assess log operator` pattern used elsewhere in this skill).

### Phase 1 — Active brute (gated by Phase 0 size, SKIP on DNS-sink apexes)

> **Detect wildcard / DNS-sink parents BEFORE bruteforcing — probe each discovered
> parent, not only the apex.** Resolve a handful of random nonexistent labels (3 is
> the shipped default) against the apex AND against every discovered 2nd/3rd-level
> *parent cluster* (e.g. `rande7x9.<parent>`); if all the random labels return a
> stable A/CNAME, that parent is a wildcard *sink*. Apex-only probing misses
> non-apex sinks — `*.review.library.acme.example` (a wildcard *under* apex `library.acme.example`,
> incident I-010) is exactly the case an apex probe never catches, and apex-level
> sinks like `af.mil` / `africom.mil` (12,386 raw → 8 real; MAC-shaped and
> `dhcp-*.rev` PTR floods) are caught by the apex probe. **Pre-strip every
> brute/permutation candidate that falls under a detected wildcard parent before
> spending DNS** — don't rely only on puredns's post-resolution wildcard filter.
> On a fully-sunk apex, **SKIP DNS brute and PTR entirely** and rely on CT (Phase
> 0b) + TLS SAN (Phase 3) — DNS-based discovery there is pure noise that burns the
> rate budget. **Don't discard the detected wildcard environment — record it as a
> Phase-2 Host/SNI-fuzz surface** (the sink's `*` proves a vhost frontend that
> answers any name; fuzz `Host: FUZZ.<wildcard-parent>` / SNI against its origin in
> web-discovery instead of throwing DNS at it).
>
> The composed `vigil assess dns-discovery --brute` verb automates this: it probes
> each discovered parent (`_WILDCARD_PROBE_LABELS=3` random labels), strips
> candidates under detected sinks before the brute, and writes the sinks to
> `scans/dns-discovery/wildcard_parents.txt` as the Phase-2 Host/SNI-fuzz handoff.
> Disable the strip with `--no-wildcard-strip` only when you have a reason to brute
> into a known sink.

`puredns bruteforce` runs the active brute pass through massdns with wildcard filtering. Apply the tier profile. For wildcard-heavy targets (apex returns a wildcard answer for nonexistent labels), keep `--wildcard-tests` at 30 so the filter probes more candidates per wildcard cluster.

**Two-tier resolver strategy (CR-8/12/18) — brute `-r` many / validate `--resolvers-trusted` few.** The brute pass fans candidates out across a WIDE, behave-under-load resolver pool (`-r`), then cross-checks the survivors against a SMALL, high-trust pool (`--resolvers-trusted`) to kill false positives the wide pool let through. The two tiers ship in-repo:

- `-r` BRUTE tier → `agent/scripts/assess/data/resolvers/premium-anycast.txt` (~40 curated anycast IPs that hold up under bulk/concurrent load: Cloudflare/Google/Quad9/OpenDNS/AdGuard/… primary+secondary pairs).
- `--resolvers-trusted` VALIDATION tier → `agent/scripts/assess/data/resolvers/trusted-anycast.txt` (~12 IPs, the most reliable subset).

**Resolver QUALITY-under-load, not raw count, governs brute throughput — and single-query "alive" validation does NOT predict bulk behavior.** Engagement evidence (CR-18): ~40 premium anycast IPs sustained ~250-500 names/s at ~0% REFUSED, whereas ~1,349 single-query-"alive" public resolvers managed ~4 names/s at 38% REFUSED. A resolver that answers one probe can still collapse under a brute's concurrency, so default to the shipped premium-anycast tier and step up to a larger pool only after validating it under bulk load (not a single liveness ping). `vigil assess dns-discovery --brute` injects both shipped lists by default; override with `--resolvers <file>` / `--resolvers-trusted <file>`, or pass `--no-default-resolvers` to manage the pool yourself (which leaves puredns's own self-discovered resolver set — and its uncapped dest-IP fan-out — in play; see the CR-3 dest-IP ceiling).

**Wordlist: brute the HEAD, opt into the deep tail (CR-19).** Recommend a cert-derived brute list — **n0kovo_subdomains** — as the primary wordlist (CT-derived, frequency-ordered), with an assetnote best-dns-wordlist final pass. CT-derived / frequency-ordered huge lists (n0kovo, ~3M) keep the real labels in the **head** and CT-hash / one-off junk in the **tail**, so bruting only the head recovers nearly all real hosts at a fraction of the DNS spend. The composed verb brutes the first `--wordlist-head N` labels (default 500000) and opts into the full list with `--deep-tail`; it WARNs when it truncates so the drop is auditable. Don't `sort` an arbitrary `--wordlist` — sorting destroys the frequency order the HEAD cap depends on. The runtime image bakes this list **pre-capped to its first 500k labels** at `/usr/share/wordlists/n0kovo_subdomains_500k.txt` (the `huge` 3M list HEAD-capped at build time), so select it with `--wordlist /usr/share/wordlists/n0kovo_subdomains_500k.txt` and the `--wordlist-head` cap is already satisfied (a no-op on the baked file).

```bash
# polite-residential default (Standard runtime, no specific CDN signal),
# two-tier resolvers (shipped premium-anycast brute / trusted-anycast validate).
vigil assess kali puredns bruteforce \
  /usr/share/wordlists/n0kovo_subdomains_500k.txt target.example \
  -r agent/scripts/assess/data/resolvers/premium-anycast.txt \
  --resolvers-trusted agent/scripts/assess/data/resolvers/trusted-anycast.txt \
  --rate-limit 2500 --wildcard-batch 100000 --wildcard-tests 30 \
  -w /engagements/$ENGAGEMENT_KEY/scans/subs_brute.txt \
  --technique RECON --intent "Phase 1 active brute @ polite-residential rate (two-tier resolvers)" \
  --probe-kind fingerprint --phase recon --timeout 1800

# OR the composed verb — wildcard pre-strip + two-tier resolvers + HEAD cap +
# convergence + budget WARN baked in. On macOS Docker Desktop add --runtime host.
vigil assess dns-discovery target.example --brute \
  --wordlist /usr/share/wordlists/n0kovo_subdomains_500k.txt \
  --wordlist-head 500000 --runtime host
```

> **Resolver-list provisioning.** The shipped premium/trusted lists are the safe
> default. The skill's historical `/engagements/$ENGAGEMENT_KEY/wordlists/resolvers.txt`
> path is an operator-provisioned pool — if you point `-r` at a large public list,
> validate it under bulk load first (single-query liveness is not enough, CR-18)
> and keep the in-container distinct-resolver-IP count under the CR-3 ceiling, or
> route the brute to the host (`--runtime host`).

Skip Phase 1 entirely when Phase 0 returned >5000 unique subs or the target is a top-tier organization — passive sources have already saturated the namespace and permutation bursts add live hosts at <0.1% rate (see `subdomain-enumeration-tools.md` "When NOT to bruteforce").

Conversely, when Phase 0 returned **0 or fewer than 10 subs**, treat that as a signal that either the configured passive-source API keys are misconfigured (check `${SUBFINDER_*_API_KEY}` env vars) or the target genuinely has no public footprint. In both cases Phase 1 brute is the only signal source — run it, BUT cap it at the cautious-tier rate (`polite-CDN-fronted-target` / `puredns --rate-limit 800`) regardless of target shape, since the wordlist is the only signal and faster rates produce noise rather than coverage. Record the rationale via `vigil assess log operator "Phase 0 returned <10 subs — Phase 1 brute @ cautious-tier as sole signal source" "<phase-0 count>" --actor-kind operator`.

### Phase 1.5 — Productive-parent recursion (first-class enum axis)

A brute against the apex finds the *first* level of structure. Real targets nest deeper: once the apex brute resolves `a.origin.api.target.example` and `b.origin.api.target.example`, the parent `origin.api.target.example` is itself a productive namespace worth bruting directly. Make this a first-class axis, not an afterthought (CR-20):

1. **Cluster** the resolved hosts by their 2nd/3rd-level parent (the label sequence one level below the bruted apex).
2. **Select** parents with **>= N children** (default 5) as "productive", excluding the apex itself and any parent already fully bruted.
3. **Re-brute** the wordlist against each productive parent (skipping any flagged a wildcard sink by the per-parent probe above), then **re-resolve** the union.
4. **Feed the new resolutions back** into the convergence loop (below) so a freshly-discovered productive parent can itself spawn a deeper re-brute.

Pair the per-parent re-brute with the CR-19 HEAD cap so a parent count of M does not multiply DNS spend by M × full-list — brute the head against each productive parent. `vigil assess dns-discovery --brute` runs this automatically: after each resolve pass it clusters productive parents (`--parent-min-children`, default 5) and re-brutes the new ones in the next convergence pass; `--no-parent-recursion` turns the axis off.

### Convergence loop — discover → resolve until two consecutive zero-net-new passes (CR-6)

Subdomain discovery is iterative, not linear: each newly-resolved host can seed the host-mining / SAN / permutation / productive-parent axes, which surface more hosts to resolve. The canonical stop criterion is **two consecutive full passes that add zero net-new resolved hosts** (bounded by `--max-passes`, default 3) — run alongside the existing `<5%` marginal-yield bound rule, not instead of it. `vigil assess dns-discovery` is the iterating spine: it loops discover → merge → de-noise → wildcard-strip → dnsx-resolve → productive-parent recursion, folding each pass's resolved set back in as seeds, and stops on the two-zero-pass criterion or `--max-passes`. Use `--no-converge` for a single pass.

Two **opt-in** discovery axes extend the convergence loop's breadth (off by default — they add egress and noise, and harvested names are DNS-validated by the resolve pass before they count):

- **`--js-host-mining`** — mine in-scope hostnames from gau / web-archive (and katana-crawled JS) URLs, filter to the in-scope apexes, and feed them back into the resolve loop. JS/archive bodies routinely reference hosts that never appear in CT or passive sources.
- **`--bbot`** — bbot passive `subdomain-enum` mop-up. bbot output is unreliable (CR-24: the excavate module emits false hostnames), so harvested `DNS_NAME` events are merged **only after** the normal de-noise and **only counted after** the convergence resolve pass DNS-validates them — never trusted blindly.

### Phase 2 — Permutation (estimate-first)

`alterx` expands the known-subdomain set 10-100x using built-in patterns. Always run `-enrich -estimate` first to bound the expansion before generating candidates — a 1000-sub input with default patterns can produce 200k+ candidates, and a 5000-sub input can break 500k.

```bash
# Step 2a: estimate first to avoid 500k+ explosions
vigil assess kali alterx -l /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  -enrich -estimate \
  --technique RECON --intent "Phase 2 permutation estimate (no candidate output)" \
  --probe-kind fingerprint --phase recon --timeout 120

# Step 2b: cap at 100k candidates
vigil assess kali alterx -l /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  -enrich -limit 100000 \
  -o /engagements/$ENGAGEMENT_KEY/scans/perms.txt \
  --technique RECON --intent "Phase 2 permutation candidates capped at 100k" \
  --probe-kind fingerprint --phase recon --timeout 600

# Step 2c: resolve the permutation set through puredns (wildcard-aware).
# Same two-tier resolvers as Phase 1: premium-anycast brute / trusted-anycast validate.
vigil assess kali puredns resolve /engagements/$ENGAGEMENT_KEY/scans/perms.txt \
  -r agent/scripts/assess/data/resolvers/premium-anycast.txt \
  --resolvers-trusted agent/scripts/assess/data/resolvers/trusted-anycast.txt \
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
vigil assess kali exec --technique RECON \
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

Three complementary TLS-SAN harvesters extract Subject Alternative Names from the handshake — use `tlsx` as the **primary** SAN harvester over a host list because it is purpose-built for cert/SAN extraction (SAN + CN + issuer + JARM/JA3/JA4 at scale, lighter than `httpx -tls-grab`, which carries the full HTTP-probe weight). Keep `httpx -tls-grab` for the case where you already need the HTTP status/title in the same pass, and `cero` for the IP/CIDR-range sweep where there is no hostname list yet:

1. **tlsx against the merged sub list (primary SAN harvester)** — `tlsx -san -cn -silent` pulls every cert's SAN/CN set; `-resp-only` emits just the discovered names so the output feeds straight back into the resolve loop. Catches wildcards (`*.foo.target.example`) and shared-cert tenants that never appear in passive sources.
2. **httpx with `-tls-grab` against the merged sub list** — emits SAN, issuer, validity, and JARM hash *alongside* HTTP status/title in one JSON pass. Reach for it when you want the HTTP signal and the SAN grab together; otherwise `tlsx` is the cheaper SAN-only path.
3. **cero against asnmap-derived CIDR ranges** — TCP/TLS handshake on 443/8443/9443 across the target's owned CIDR. Catches subdomains that never appear in CT logs (private CAs, internal stages on internet-exposed IPs), where there is no hostname list to feed `tlsx`.

```bash
# tlsx SAN harvest — the primary, cheapest SAN-only feedback pass. -resp-only
# emits just the discovered SAN/CN names so they feed straight back into the
# resolve loop alongside the brute/permutation output.
vigil assess kali exec --technique DISCOVERY \
  --intent "Phase 3 TLS SAN harvest via tlsx (-san -cn, names-only)" \
  --probe-kind fingerprint --phase recon --timeout 1200 -- \
  tlsx -l /engagements/$ENGAGEMENT_KEY/scans/subs_merged.txt \
  -san -cn -resp-only -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/tlsx_sans.txt

# httpx feedback loop — NO -tech-detect on this bulk pass. tech-detect amplifies
# httpx memory under cgroup pressure and was a SIGKILL (RC137) trigger on large
# merged lists. This pass only needs the SAN/TLS grab; tech-detect the confirmed-
# live subset later (Phase: Filter/verify/ingest), not the full merged set.
vigil assess kali httpx -l /engagements/$ENGAGEMENT_KEY/scans/subs_merged.txt \
  -tls-grab -tls-probe -status-code -title -json \
  -o /engagements/$ENGAGEMENT_KEY/scans/httpx_tls.jsonl \
  --technique DISCOVERY --intent "Phase 3 TLS SAN harvest via httpx -tls-grab (status-only, no tech-detect)" \
  --probe-kind fingerprint --phase recon --timeout 1200

# asnmap → cero CIDR sweep
vigil assess kali asnmap -d target.example -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/target_cidrs.txt \
  --technique OSINT --intent "Phase 3 ASN → CIDR mapping for cero feed" \
  --probe-kind fingerprint --phase recon --timeout 300

vigil assess kali cero -l /engagements/$ENGAGEMENT_KEY/scans/target_cidrs.txt \
  -p 443,8443,9443 -c 100 -t 4 \
  -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans.txt \
  --technique OSINT --intent "Phase 3 TLS SAN scrape across owned CIDRs" \
  --probe-kind fingerprint --phase recon --timeout 600

# Final pass: dnsx resolves the merged set, drives live-host confirmation
vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/subs_merged.txt \
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
vigil assess kali exec --technique RECON \
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
vigil assess kali exec --technique RECON \
  --intent "merge SAN-discovered subdomains" \
  --probe-kind fingerprint --phase recon --timeout 300 -- bash -c '
  cat /engagements/$ENGAGEMENT_KEY/scans/sans_*.txt | sort -u \
    > /engagements/$ENGAGEMENT_KEY/scans/san_candidates.txt
'

# Confirm the SAN-discovered names through the typed dnsx verb.
vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/san_candidates.txt \
  --dnsx-profile polite-cdn --resolver-profile public-tcp \
  -a -resp -silent -o /engagements/$ENGAGEMENT_KEY/scans/san_live.txt \
  --technique RECON --intent "dnsx -resp confirmation of SAN-discovered subdomains" \
  --probe-kind fingerprint --phase recon --timeout 600
```

`san_live.txt` is the primary input to `vigil assess ingest endpoints subdomain-enum` for this dispatch. The full openssl extraction loop, the cross-host collision counter, and the vhost-cert match check live in `agent/references/tools/recon/openssl-sans.md` — call into it from this section rather than duplicating mechanics here.

This section does NOT replace the Phase 3 TLS SAN feedback loop above; it sits alongside it. The Phase 3 loop is the breadth-first sweep across the merged sub list (post-Phase 0/1/2). The SAN-as-primary section fires when the cross-host signal is already strong (a shared multi-tenant cert was detected, or a vhost-cert mismatch was found), so the enumeration is depth-first against the cert's actual coverage set rather than breadth-first against the apex's enumerated subset.

## Bound rules

Stopping criteria are explicit because subdomain enumeration is the easiest place to burn a runtime budget on diminishing returns.

- **subfinder is non-recursive by default; `-recursive` is dedicated-runtime-only.** On a shared/Standard runtime never pass `-recursive` — it saturated the Docker daemon on large apexes (army.mil, 4,289 subs). On a dedicated runtime, if you do opt into recursion, cap depth ≤ 2 plus one feedback pass on discovered subs; further recursion produces marketing-tracker subs and stale CDN siblings that don't contribute to attack surface.
- **Convergence: two consecutive passes add zero net-new resolved hosts.** The canonical stop criterion for the discover→resolve loop (CR-6). Run it alongside the `<5%` marginal-yield rule below, not instead of it. `vigil assess dns-discovery` enforces it (bounded by `--max-passes`, default 3); when driving the manual pipeline, stop re-running the host-mining / SAN / permutation / productive-parent axes once two full passes in a row add nothing new.
- **New-subdomain ratio < 5% of prior round.** When the marginal yield of a new round (additional permutations, deeper bbot modules, expanded wordlist) is under 5% of the cumulative count, stop. The remaining surface is below the cost-per-discovery threshold.
- **Wildcard ratio > 30% (detect EARLY, per discovered parent — not only the apex).** When more than 30% of a parent's resolved hits land on the same wildcard answer (single A record, single CNAME), that parent is a wildcard sink and brute force under it is pure noise. Detect this up front with the per-parent random-label probe in Phase 1 (probe each discovered parent cluster, not only the apex — `*.review.library.acme.example`-style non-apex sinks are invisible to apex-only probing), not only mid-run. On a detected sink, **pre-strip candidates under it before DNS spend**, route the apex to **CT (Phase 0b) + TLS SAN / asnmap (Phase 3)**, skip DNS brute/PTR under the sink — and **record the wildcard parent as a Phase-2 Host/SNI-fuzz surface** (`scans/dns-discovery/wildcard_parents.txt`) rather than discarding it. Wildcard-fronted hosts still have unique certs, and CT/SAN are the sources that cut through the sink.
- **Permutation estimate > 500k candidates.** Abort Phase 2 and narrow the input set before resolving. A 500k+ candidate run costs ~30+ minutes of runtime CPU at polite-residential rates and produces sub-1% live-host yield.
- **DNSSEC absent / NSEC3 zone, or AXFR refused — probe once, skip, never retry (CR-10).** A single DNSSEC presence check and a single AXFR attempt per authoritative NS (Phase 0c). On `DNSSEC absent`, an `NSEC3` (hashed) zone, or the near-universal AXFR `REFUSED`/timeout, record the skip and never re-probe — retrying a refused AXFR or walking a non-NSEC zone is wasted DNS spend.
- **DNS query budget exceeded (advisory WARN).** When the planned brute (`wordlist_lines × target_count`) would exceed `--query-budget`, or the derived per-resolver qps exceeds `--per-resolver-qps`, the verb WARNs (CR-23). It is a cue to trim scope (`--wordlist-head`, fewer targets) or lower `--dns-rate`/add resolvers before launching — not a hard block.

When stopping early — or recording a probe-once skip — log the rationale via `vigil assess log operator "Subdomain enum bound rule fired" "<rule>" "<round-stats>" --actor-kind operator` so the audit trail explains the missing rounds instead of leaving an unexplained coverage gap.

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

Run each subdomain scan **synchronously** (one blocking `vigil assess kali <verb> … --timeout N`
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
vigil assess kali httpx -l /engagements/$ENGAGEMENT_KEY/scans/subs_denoised.txt \
  -status-code -title -web-server -cl -follow-redirects --extra-args "-silent" \
  -o /engagements/$ENGAGEMENT_KEY/scans/subdomains_live.txt \
  --technique DISCOVERY --intent "live-host confirmation on de-noised sub list (status-only)" \
  --probe-kind fingerprint --phase recon --timeout 1200

# Stage 1b: tech-detect ONLY the confirmed-live subset (small, safe).
awk '{print $1}' /engagements/$ENGAGEMENT_KEY/scans/subdomains_live.txt | sort -u \
  > /engagements/$ENGAGEMENT_KEY/scans/subs_live_only.txt
vigil assess kali httpx -l /engagements/$ENGAGEMENT_KEY/scans/subs_live_only.txt \
  -tech-detect -json --extra-args "-silent" \
  -o /engagements/$ENGAGEMENT_KEY/scans/subdomains_tech.jsonl \
  --technique DISCOVERY --intent "tech-detect on confirmed-live subset only" \
  --probe-kind fingerprint --phase recon --timeout 600

# Stage 2: ingest verified live subs into the work buffer
awk '{print $1}' "$ENGAGEMENT_DIR/scans/subdomains_live.txt" | sort -u | while IFS= read -r sub; do
  echo "GET https://$sub"
done | vigil assess ingest endpoints subdomain-enum
```

After ingestion, the operator triggers a reactive nuclei sweep against the newly-live subdomains — see `agent/skills/nuclei-scanning/SKILL.md` "Reactive Sweep Mode".

## What to Record

- **Total subdomains found** (passive + active + permutation + TLS SAN), broken down by source.
- **Live subdomains** with HTTP status codes.
- **Interesting subdomains**: staging, dev, admin, api, internal, test, beta.
- **Services** running on non-standard ports.
- **Source** of each subdomain (subfinder source, brute-force, alterx permutation, productive-parent re-brute, cero SAN, asnmap CIDR, JS/archive host mining, bbot mop-up).
- Any subdomain pointing to **different infrastructure** (cloud, CDN, third-party).
- **Dangling CNAMEs are a takeover SCREENING signal, not a finding.** When a subdomain CNAMEs to a third-party resource that no longer serves it (S3 `NoSuchBucket`, a `d*.cloudfront.net` target with no A, `*.azurewebsites.net` / `*.trafficmanager.net` NXDOMAIN), record the dangling state as intel and hand the candidate on — but the signature alone is necessary-but-not-sufficient, so load `agent/skills/cloud-exposure/SKILL.md` (which owns the per-provider claimability rules and the prove-or-kill benign own-account claim, citing `agent/references/subdomain-takeover.md`) and confirm claimability there BEFORE anyone records a takeover finding. The bare signature is the #1 false-positive class for this bug type (one engagement saw 7 perfect-signature CloudFront candidates, all non-claimable false positives).
- The hypothesis each interesting subdomain suggests: auth bypass, stale deployment, separate trust zone, or chain opportunity.
- **Wildcard parents** detected (the Phase-2 Host/SNI-fuzz surface from `scans/dns-discovery/wildcard_parents.txt`) and the candidates stripped under them.
- **Productive parents** re-bruted (>= `--parent-min-children`) and the convergence outcome: how many passes ran, net-new per pass, and whether it stopped on the two-zero-pass criterion or `--max-passes`.
- **Probe-once skips** (CR-10): GeoDNS region-varying answer sets (each region's A/CNAME), DNSSEC absent / NSEC3, AXFR refused — recorded as explicit, justified skips.
- **DNS query budget**: planned-vs-budget queries and the per-resolver qps for the brute, plus any budget WARN that fired.
- Bound-rule firings: any phase that stopped early, the rule that fired, and the cumulative count at the firing.

## Extended Resources

- `agent/references/recon/rate-calibration.md` — canonical per-target rate calibration; the DNS-brute column gates puredns/shuffledns invocations. Tier-pick prose lives in `agent/references/runtime-guides/dispatch-resource-policy.md` "Recon Dispatch Resource Policy".
- `agent/references/tools/recon/subdomain-enumeration-tools.md` — comparison matrix, API-key value-for-cost, puredns rate guidance, alterx permutation chain, cero CIDR-feed, bbot passive preset, when-not-to-bruteforce signals.
- `agent/skills/kali-exec/SKILL.md` — Phase A→D workflow with example invocations (kali-cli foundational skill).
- `agent/references/tools/recon/puredns.md` — massdns dependency, wildcard tuning, rate-limit ceilings.
- `agent/references/tools/recon/dnsx.md` — NXDOMAIN/CPU spike pattern, two-step brute-then-enrich, GOMAXPROCS profile, GeoDNS multi-region resolver pass, and DNSSEC/AXFR probe-once-and-skip mechanics (powers Phase 0c).
- `agent/references/tools/recon/cero.md` — TLS SAN scraper post-asnmap CIDR feed.
- `agent/references/tools/recon/openssl-sans.md` — per-host TLS SAN extraction loop, cross-host SAN collision counter, vhost / cert mismatch detection, multi-time DNS resolution recipe; powers the "TLS SAN extraction as a primary source" section.
- `agent/references/tools/recon/alterx.md` — permutation generator with `{{sub}}/{{suffix}}` DSL.
- `agent/references/tools/recon/asnmap.md` — CIDR mapping by ASN, feeds cero.
- `agent/references/tools/recon/bbot.md` — multi-module passive preset.
- `agent/references/tools/recon/shuffledns.md` — lighter alternative to puredns.
- `agent/references/tools/recon/httpx.md` — HTTP probing and TLS-grab.
- `agent/references/subdomain-enumeration.md` — prioritization, sliding-window, and bound-rule companion doc.
- `agent/references/subdomain-takeover.md` — subdomain-takeover claimability: why a dangling-CNAME signature is necessary-but-not-sufficient, the per-provider claimability rules, and the benign own-account claim that proves (or kills) a takeover candidate before a finding is recorded.
- `agent/references/runtime-guides/docker-desktop-network-hazards.md` — the macOS Docker Desktop per-destination-IP userspace-proxy wedge (the I-001 incident): why a DNS brute's distinct-resolver-IP count (>~50 in-container), not qps, is the crash knob, and why the DNS-heavy stages route to the host (`--runtime host`).
- `agent/scripts/assess/data/resolvers/premium-anycast.txt` / `trusted-anycast.txt` — the shipped two-tier resolver lists (brute `-r` ~40 premium-anycast IPs / validate `--resolvers-trusted` ~12 trusted-anycast IPs); the default `vigil assess dns-discovery --brute` resolver pools.
- `agent/scripts/assess/data/resolvers/validated-trickest.txt` — an OPTIONAL wide brute tier synced from the externally-validated `trickest/resolvers` pool by `agent/scripts/refresh_resolvers.py` (a MAINTAINER task, run occasionally and committed — never engagement-time, so a slow/dead resolver never surfaces mid-brute). Point a large brute at it with `--resolvers <path>`; the curated premium/trusted tiers stay the safe defaults. Generated, so it is absent until a maintainer runs the refresh.
