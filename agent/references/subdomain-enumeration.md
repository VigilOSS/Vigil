---
description: "Subdomain enumeration (when *.domain in hosts), prioritization, and sliding-window execution rules"
skill: subdomain-enumeration
category: Shared Runtime References
---

# Subdomain Enumeration

Activate when scope.json `hosts` contains `*.domain` entries (e.g., `*.example.com`).

## Phase 0: Enumerate Subdomains

The **operator** runs the staged composition end-to-end as the `vigil assess recon` job (not a specialist dispatch); a specialist uses this doc + `agent/skills/subdomain-enumeration/SKILL.md` to **assess** the job's output and prioritize what to re-run. This doc is the prioritization/sliding-window companion.

1. Identify which domains have `*.domain` entries in the `hosts` array.
2. **Tooling preflight** — `vigil assess kali exec --technique HEALTH --intent "subdomain-enum tooling preflight" --probe-kind fingerprint --phase recon --timeout 60 -- which massdns puredns dnsx subfinder shuffledns alterx cero asnmap bbot`. Missing binaries → fix the runtime, do not silently degrade.
3. Run the staged pipeline:
   - **Phase 0** — passive (`subfinder -all -recursive` + chaos + github-subdomains; optional bbot `subdomain-enum -rf passive` for deep coverage).
   - **Phase 1** — active brute (`puredns @ tier rate-limit, --wildcard-batch 100000, --wildcard-tests 30` for wildcard-heavy targets). Skip when Phase 0 returned >5000 subs or target is top-tier.
   - **Phase 2** — permutation (`alterx -enrich -estimate` first, then `-limit 100000`, then `puredns resolve`).
   - **Phase 3** — TLS SAN feedback (`httpx -tls-grab` against the merged set; `asnmap → cero` against owned CIDRs); final `dnsx` resolution drives live-host confirmation.
4. Apply the `subdomain-enumeration` skill's 3-stage filter:
   - DNS resolution
   - web-port reachability
   - lightweight fingerprinting

### Bound rules (stop early when any fires)

- **Recursion depth ≤ 2.** Further recursion produces marketing-tracker subs and stale CDN siblings.
- **New-subdomain ratio < 5% of prior round.** Marginal yield is below the cost-per-discovery threshold.
- **Wildcard ratio > 30%.** Apex is a wildcard sink — switch to TLS SAN / asnmap.
- **Permutation estimate > 500k candidates.** Abort Phase 2; narrow the input set first.

Record bound-rule firings via `vigil assess log operator "Subdomain enum bound rule fired" "<rule>" "<round-stats>" --actor-kind operator` so the audit trail explains the missing rounds.

### Resource-tier profiles (rate-limits)

Pick by target shape, not apex shape — wildcards expand the surface and the rate calibration must match the surface. The `vigil assess kali dnsx` wrapper defaults to `--dnsx-profile polite-cdn --resolver-profile public-tcp`; keep that default until the target and Docker host can justify stepping up. DNS bruteforce is the dominant host-CPU and host-network spike in the runtime, and aggressive profiles have crashed Docker on standard laptop hardware.

- **polite-CDN-fronted-target** — `puredns --rate-limit 800 --wildcard-tests 30`, `dnsx --dnsx-profile polite-cdn`. CDN-fronted, enterprise-WAF-protected, regulated, or household-name brand.
- **polite-residential** — `puredns --rate-limit 2500 --wildcard-batch 100000`, `dnsx --dnsx-profile polite-residential`. Standard runtime, public resolvers after explicit target assessment.
- **bursty-OK (opt-in only)** — `puredns --rate-limit 5000`, `dnsx --dnsx-profile bursty-ok`. Private resolver pool only AND with explicit operator opt-in.

Drop one tier when `VIGIL_RUNTIME_MEMORY_GB` is below the Standard tier (8 GB).

## Phase 0.5: Prioritize

- **Interactive**: present the prioritized list and wait for approval.
- **Autonomous**: announce the order and start immediately.

Prioritize subdomains with:
- distinct technologies
- exposed admin/auth surfaces
- API endpoints
- unusual ports
- signs of secrets, debug features, or data exposure

## Phase 0.9: Sliding Window

- Process a maximum of `N` subdomains in parallel, default `3`.
- Each subdomain runs the normal 5-phase engagement flow.
- When one subdomain finishes, start the next queued target.
- Never create every child engagement directory up front.

Before starting each child target, run a WAF gate check and skip targets that return `403` together with a clear Cloudflare or CloudFront challenge.

## Final Report

Merge child findings through canonical backend state first, then synchronize the
parent `report.md` and any readable `findings.md` exports from that state.
