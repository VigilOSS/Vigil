# puredns

**Purpose:** Fast domain resolver and DNS brute-forcer with accurate wildcard filtering
For live engagement targets, run puredns via `aith assess kali puredns` (typed verb, audit-flag-aware).

## Hard `massdns` dependency (read first)

puredns is a wrapper around massdns + a wildcard filter — it has no resolver of its own. **If `massdns` is not on `$PATH`, puredns silently fails: zero output, no error, exit code 0.** Rerun the preflight (or fix the runtime) if your puredns invocation produced nothing. Run the tooling preflight (see `agent/skills/subdomain-enumeration/SKILL.md` "Tooling preflight") before any active step:

**Host-CPU and Docker-stability note.** DNS bruteforce is the dominant host-CPU and host-network spike in the engagement runtime — see `agent/skills/subdomain-enumeration/SKILL.md` "Host-CPU note" for the full mechanism. massdns sends thousands of UDP queries per second; the host kernel's per-packet network-stack overhead is amplified well beyond what `--cpus` cgroup limits constrain (cgroup CPU limits the userland process, not the host's kernel networking path). Aggressive puredns rate-limits have crashed Docker on standard laptop hardware. Default to `polite-residential` everywhere; step up to `bursty-OK` only on private/lab resolvers AND with explicit operator opt-in.

```bash
aith assess kali exec -- which massdns puredns \
  --technique RECON --intent "massdns/puredns preflight" \
  --probe-kind fingerprint --phase recon --timeout 30
```

`runtime-full/Dockerfile` installs massdns from the kali apt repo; if it's missing in a running container the image is drifting and the runtime needs a `aith runtime restart` after rebuild — do NOT swap to a degraded fallback.

## Resource-safe profiles

Match the rate-limit to the runtime/target tier — full tier rationale in `agent/skills/subdomain-enumeration/SKILL.md` "Docker-resource-safe profiles" and `agent/references/tools/recon/subdomain-enumeration-tools.md` "puredns — rate-limit reality".

| Profile | Flags |
|---------|-------|
| polite-CDN-fronted-target (CDN-fronted / WAF-protected / regulated cautious tier) | `--rate-limit 800 --wildcard-tests 30` |
| polite-residential default | `--rate-limit 2500 --wildcard-batch 100000` |
| bursty-OK (opt-in only) | `--rate-limit 5000` |

`--wildcard-batch 100000` is the default for the polite-residential profile; drop to `50000` on tight-RAM containers (`AITH_RUNTIME_MEMORY_GB=4` or lower) because the wildcard-filter dedup map dominates puredns's RAM usage and silent truncation produces missing subs without a clean OOM.

`--rate-limit-trusted 200` is the ceiling for the trusted-resolver pool — exceeding it triggers per-resolver rate-limits at the upstream, not local saturation, and the resulting failures look like wildcard misses rather than rate errors.

## Common invocations

**Brute-force subdomains:** `puredns bruteforce wordlist.txt target.example -r resolvers.txt -w results.txt`
**Resolve a list:** `puredns resolve subdomains.txt -r resolvers.txt -w resolved.txt`
**Wildcard detection:** Built-in — automatically filters wildcard DNS responses. Tune with `--wildcard-tests 30` for wildcard-heavy targets (regulated apex, brand-name CDN).
**Custom resolvers:** `-r resolvers.txt` (use trusted public resolvers to avoid false positives).
**Rate limit:** `--rate-limit 2500` (polite-residential default; see profiles above).
**Threads:** `-t 100`.

**Pipeline usage:** Use after subfinder (passive) to add active brute-force results. puredns handles wildcard domains correctly, which ffuf vhost fuzzing does not. Feed output into dnsx for record-type enrichment (lean profile — see `dnsx.md` NXDOMAIN trap), then httpx for live host confirmation.

**Resolver list:** Use a curated list of reliable public resolvers. Community lists available at `github.com/trickest/resolvers`.
