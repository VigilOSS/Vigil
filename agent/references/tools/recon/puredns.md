---
description: puredns active brute and wildcard-aware resolve — silent zero-output failure without massdns, resolver-list paths inside the container, --rate-limit-trusted as a pool-wide total, tight-RAM --wildcard-batch
skill: subdomain-enumeration
---

# puredns

massdns plus a wildcard filter, run as
`vigil assess kali puredns {bruteforce,resolve} <wordlist_or_input> [domain]`. Stage commands are
`agent/references/recon/subdomain-enum-manual-stages.md` "Phase 1" and "Phase 2"; profile flag sets
are `subdomain-enumeration-tools.md` "Resource profiles and rate reality".

- **No massdns, no output.** puredns has no resolver of its own: with `massdns` missing it exits 0
  with zero output and no error. Run the skill's "Tooling preflight" before active work; a missing
  binary is image drift to rebuild, not a reason to switch tools.
- **Resolver paths.** `kali puredns` runs in the container with `/engagements/$ENGAGEMENT_KEY` as
  its working directory, so the shipped host-side lists under `agent/scripts/assess/data/resolvers/`
  are not visible to it. `vigil assess dns-discovery --brute` stages `premium-anycast.txt` and
  `trusted-anycast.txt` into `/engagements/$ENGAGEMENT_KEY/wordlists/` for you; for a hand-run call,
  copy the list to `$DIR/wordlists/` and pass the `/engagements/...` path.
- `--rate-limit-trusted` is one total qps budget for the whole trusted pool, as `--rate-limit` is
  for the brute pool; both values are in `agent/references/recon/rate-calibration.md` (the
  DNS-brute column and its footnote). Upstream resolvers that throttle per source IP are a separate effect, and it
  shows up as wildcard misses rather than rate errors.
- Wildcard handling is the reason to prefer puredns over shuffledns and over ffuf vhost fuzzing;
  raise `--wildcard-tests` on wildcard-heavy apexes (regulated apex, brand-name CDN). The
  wildcard dedup map dominates RAM and truncates silently rather than failing with an OOM; the
  tight-RAM `--wildcard-batch` value is in the manual stages' "Phase 1".
- Feed survivors to dnsx for enrichment on the lean-then-enrich pattern (`dnsx.md`
  "NXDOMAIN / CPU-spike trap").
