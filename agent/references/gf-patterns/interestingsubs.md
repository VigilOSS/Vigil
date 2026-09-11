---
name: gf-patterns:interestingsubs
description: Subdomain naming conventions that signal non-production and internal-bleed surface
origin: 1ndianl33t/Gf-Patterns@f686f06ae647726578920084c894100d702496cc (+ local overlay)
bucket: conceptual
---

# gf: interestingsubs

## What this bucket classifies

Subdomains whose labels hint at non-production environments, staging, internal services, or
internal-facing infrastructure that accidentally resolves publicly. Examples: `dev.`,
`staging.`, `internal.`, `qa.`, `jenkins.`, `grafana.`. These are the primary targets for
wildcard-enumeration follow-up.

## Load this reference when

- Wildcard enumeration (e.g. `puredns` resolving `*.target.example`) returned unusual subdomains
- The operator is picking which subdomains to pull through surface-collection ahead of the flat production origin
- Corpus analysis shows URLs split across many hostnames and bucketing by host is needed to prioritize

## Parameter keys that match

Not applicable — this bucket classifies hostnames, not parameters. `classify_work.py` does not
produce a direct `gf:interestingsubs` cluster; operator-visible clusters for this concept
come from path-fallback keys after per-host routing (e.g. `path:/jenkins/api`) or from the
subdomain-enumeration skill emitting separate work-item batches.

## Path patterns that match

Not applicable — see above.

## Weight and priority interpretation

- No direct priority_score is emitted by `classify_work.py` for this bucket. Use it to
  decide which hostnames to ingest in the first place — once ingested, individual URLs
  earn gf buckets normally (ssrf / sqli / etc.) against their host.
- Operator contract: when an interesting subdomain is found, it becomes a new ingest
  source for surface-collection, not a direct `gf:interestingsubs` work-item cluster.

## Example subdomains that match

- `staging.target.example` — staging environment often ships with verbose debug
- `internal.target.example` — internal-facing service accidentally resolvable
- `jenkins.target.example` — CI/CD surface, typical high-signal target
- `grafana.target.example` — metrics dashboards, often with default creds
- `dev-api.target.example` — developer-specific API endpoint

## What it does NOT classify

- Production subdomains under normal content-split routing (`www.`, `api.`, `assets.`) — those are expected and handled as normal targets
- CDN-backed aliases that resolve to the same origin — dedup by fingerprint before dispatching
- DNS wildcards that resolve everything to a sinkhole — identify via `puredns` wildcard filter, not gf

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [subdomain-enumeration reference](../subdomain-enumeration.md) — enumeration and prioritization rules

## Related

- `agent/skills/subdomain-enumeration/SKILL.md` — the follow-up enumeration skill
- `agent/references/subdomain-enumeration.md` — sliding-window prioritization rules
- `agent/references/tools/recon/puredns.md` — active DNS brute-force with wildcard filtering
