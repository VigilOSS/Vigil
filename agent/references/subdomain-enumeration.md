---
description: "After subdomain enumeration: prioritising discovered subdomains and the sliding-window rules for working them as child targets"
skill: subdomain-enumeration
category: Shared Runtime References
---

# Subdomain prioritisation and sliding window

Load after the recon job (or a manual enumeration) has produced a live subdomain set, when
deciding which subdomains to work first. Enumeration itself — stages, profiles, bound rules —
is `agent/skills/subdomain-enumeration/SKILL.md`.

## Prioritise

Announce the prioritised order and start. Stop to ask only for a decision on the operator
core's "PRESENT OR PROCEED" list (scope or ROE ambiguity, an `exploit_policy` pause, proof-run
approval, destructive or third-party reach, trusting repository code), in interactive and
autonomous runs alike.

Work first the subdomains with:

- distinct technologies
- exposed admin/auth surfaces
- API endpoints
- unusual ports
- signs of secrets, debug features, or data exposure

## Sliding window

- Process at most `N` subdomains in parallel, default `3`.
- Each subdomain runs the normal engagement flow.
- When one finishes, start the next queued target.
- Create child engagement directories only when a child starts, not all up front.

Before starting each child, run a WAF gate check and skip targets that return `403` together
with a clear Cloudflare or CloudFront challenge.

## Final report

Merge child findings through canonical backend state first, then synchronise the parent
`report.md` and any readable `findings.md` exports from that state.
