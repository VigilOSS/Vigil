---
name: subdomain-enumeration
description: Subdomain discovery via subfinder, DNS brute-force, TLS SAN feedback, and resource-tier-aware staged composition
origin: Vigil
---

# Subdomain Enumeration

## When to Activate

- scope.json `hosts` holds `*.domain` entries. The **operator** runs the spine as the
  `vigil assess recon` job; a specialist loads this skill to **assess** that job's output
  (bound rules, stop reasons, completeness) and recommend re-runs, not to run the stages.
- Source, certificates or archives reference subdomains not yet enumerated.

Program carve-outs go in scope.json `out_of_scope` before enumerating; the pipeline
scope-filters between the dns and web stages, and a mid-run carve-out applies on `--resume`.
Audit flags: `--technique RECON` for active DNS work, `OSINT` for passive sources.

## On-demand appendices

`vigil assess list-references --skill subdomain-enumeration` lists every paired file. Load:

- `agent/references/recon/subdomain-enum-manual-stages.md` — when you run, tune or recommend a
  stage by hand (Phase 0-3 commands, crt.sh backoff, alterx, merge, tlsx/cero/dnsx, de-noise,
  ingest).
- `agent/references/tools/recon/subdomain-enumeration-tools.md` — before picking a
  non-default profile, reading a query-budget WARN, or choosing tools and passive API keys.
- `agent/references/subdomain-enumeration.md` — after enumeration, to prioritise subdomains
  and run them through the sliding window.
- `agent/references/runtime-guides/docker-desktop-network-hazards.md` — on Docker Desktop
  before an in-container DNS-heavy pass, or when the runtime wedges.
- Per-tool flags: `agent/references/tools/recon/{dnsx,openssl-sans,puredns,bbot,cero,alterx,asnmap,shuffledns,httpx}.md`.

## The composed verbs

- `vigil assess recon <apex…>` — supervised, checkpointed job: `dns-discovery → web-discovery`
  plus gau history and JS mining (on by default; `--no-gau`, `--no-js-mining`). `--background`
  returns a job id; poll `vigil assess recon-status [--job-id N]` (stage state, counts,
  failures, WARNs). `--resume` restarts at the first incomplete stage. On Docker Desktop
  `--runtime auto` routes DNS-heavy stages to the host and refuses to start if a host binary is
  missing. Also `--brute`, `--no-crawl`, `--stage-timeout`.
- `vigil assess dns-discovery <apex…>` — subfinder (non-recursive) + CT + optional `--brute` +
  productive-parent recursion → de-noise → per-parent wildcard pre-strip → dnsx, repeated until
  two consecutive passes add zero net-new hosts (`--max-passes` 3, `--no-converge`). Standalone,
  `--runtime auto` stays in-container unless `VIGIL_RECON_RUNTIME=host|auto`; pass
  `--runtime host` on Docker Desktop. Opt-in `--js-host-mining` and `--bbot` names count only
  after the resolve pass validates them.
- `vigil assess web-discovery <resolved_hosts.txt>` — de-noise → status-only httpx liveness
  (seeds the host-liveness ledger) → katana → optional work-buffer ingest.

`<verb> --help` lists every knob; the defaults are the safe settings.

**Tooling preflight.** puredns returns nothing, exit 0, when massdns is missing. Before active
work: `vigil assess kali exec --technique HEALTH --intent "subdomain-enum tooling preflight"
--probe-kind fingerprint --phase recon --timeout 60 -- which alterx asnmap bbot cero dnsx
github-subdomains massdns puredns shuffledns subfinder tlsx`. A missing binary is image drift
(check `vigil runtime resources`, rebuild `agent/docker/runtime-full/Dockerfile`,
`vigil runtime restart`), not a reason to degrade. If everything resolves but nothing answers
HTTP, run the egress reputation check (`agent/references/runtime-guides/cdn-ip-blocking.md`).

## Docker-resource-safe profiles

A DNS brute queries public resolvers, not the target, so rates protect **resolver fair-use and
local runtime networking**. `polite-CDN-fronted-target` (puredns 800) is the default for any
unknown target; `polite-residential` (2500) after assessing an SMB/residential target;
`bursty-OK` (5000) only with a dedicated pool and never on Standard tier. `--dns-rate` is TOTAL
qps (default 1500). Below Standard tier drop one profile: puredns truncates silently under RAM
pressure.

- **Host-CPU note.** On Docker Desktop the crash knob is distinct destination IPs (> ~50
  in-container), not qps. The shipped premium tier (~40 IPs) fits; larger pools go via
  `--runtime host`. Target HTTP work stays in-container.
- Never run a DNS brute alongside bulk httpx, or two bulk httpx passes: a solo 3,875-host
  httpx ran clean, the same with two siblings was RC137-killed.

## Decisions

- **Passive and CT always run.** CT added 1,758 net-new hosts over subfinder/bbot in one
  large-apex study and is the only clean source on DNS-sink apexes.
- **Brute only when it can pay.** Skip it above 5,000 passive subs or on a top-tier organisation
  (yield < 0.1%). Under 10 passive subs, check the `SUBFINDER_*` keys, then brute at 800 as the
  sole signal and log why. Log a skip with
  `vigil assess log operator "Phase 1 brute skipped" "skip" "<reason>" --actor-kind operator`.
- **Wildcard sinks, per parent, before bruting.** Resolve 3 random labels under the apex and each
  2nd/3rd-level parent (`*.review.acme-media.example`-style sinks are invisible to an apex-only
  probe); pre-strip candidates under a sink. On a fully sunk apex skip brute and PTR and rely on
  CT + TLS SAN. Keep each sink as a Host/SNI-fuzz surface
  (`scans/dns-discovery/wildcard_parents.txt`): its `*` proves a vhost frontend.
- **Resolver quality, not count.** Brute with `agent/scripts/assess/data/resolvers/premium-anycast.txt`,
  validate with `trusted-anycast.txt`. ~40 premium IPs sustained 250-500 names/s at ~0% REFUSED;
  ~1,349 single-query-"alive" resolvers managed ~4 names/s at 38% REFUSED.
- **Brute the wordlist head.** Frequency-ordered CT lists keep real labels on top; the image ships
  `/usr/share/wordlists/n0kovo_subdomains_500k.txt`. `--deep-tail` opts into a full list. Never
  sort such a list.
- Productive parents (≥ 5 children) are re-bruted; alterx runs estimate-first; TLS SANs feed
  back, and a shared multi-tenant cert or vhost-cert mismatch makes the SAN set a primary source.
- bbot is a mop-up: useful breadth on an unfamiliar target, unreliable output, never ingested
  unvalidated.
- Specialists run blocking `vigil assess kali` calls (`agent/shared-constraints.md` §2 owns
  synchronous execution and process cleanup); long runs belong to the operator's recon job.

## Bound rules

Stop (or judge the run complete) when one fires, and log each early stop or skip with
`vigil assess log operator "Subdomain enum bound rule fired" "<rule>" "<round-stats>" --actor-kind operator`:

- two consecutive passes add zero net-new resolved hosts, or `--max-passes` is reached;
- a round adds < 5% of the cumulative count;
- > 30% of a parent's hits share one wildcard answer (a sink, above);
- permutation estimate > 500k candidates (~30+ minutes for sub-1% yield);
- DNSSEC absent / NSEC3 / AXFR refused — probe once per NS, never retry (`dnsx.md`);
- `--recursive` only on a dedicated runtime, depth ≤ 2;
- a query-budget or per-resolver-qps WARN: trim before launching.

Judging a finished job: a `failed` stage, non-zero `exit_code`, or WARN (dest-IP cap, query
budget, truncated wordlist, dead resolvers) is a coverage gap. Name it and the operator action
that closes it (e.g. `vigil assess recon target.example --brute --resume`).

## What to Record

- Totals by source and live hosts with status; interesting hosts (staging, dev, admin, api,
  internal, beta), odd ports, third-party infrastructure, and the hypothesis each suggests.
- Wildcard parents and stripped candidates; productive parents; passes run, net-new per pass,
  and the stop rule; probe-once results; query budget; every bound-rule firing.
- **Dangling CNAMEs are a takeover screening signal, not a finding.** The bare signature is the
  #1 false-positive class here (one engagement: 7 perfect-signature CloudFront candidates, none
  claimable). Hand it to `agent/skills/cloud-exposure/SKILL.md` (claimability and the benign
  own-account claim, `agent/references/subdomain-takeover.md`) before anyone records a takeover.

After ingestion the operator runs the reactive nuclei sweep
(`agent/skills/nuclei-scanning/SKILL.md` "Reactive Sweep Mode").
