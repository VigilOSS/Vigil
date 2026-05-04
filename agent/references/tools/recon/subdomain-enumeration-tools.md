# Subdomain Enumeration Tooling

Subdomain enumeration is layered. No single tool covers the surface — passive sources miss internal-only certs, TLS scraping misses pure-DNS subs, bruteforce misses real-but-unguessable names, active probing assumes a candidate list. The phases below compose; do not skip Phase A and start at C.

The typed kali verbs map to the phases as: subfinder → A, bbot → A+, cero → B, alterx + puredns → C, dnsx → D. Methodology and example invocations live in `agent/skills/kali-exec/SKILL.md` "Subdomain enumeration: Phase A→D workflow"; this reference is the prioritization, cost, and decision detail.

## Tool-tier table

| Tool | Tier / Phase | Mode | Typical CPU/RAM | API key needed |
|------|--------------|------|-----------------|----------------|
| `subfinder` | A — passive | Aggregator over 30+ public sources | Low (single-digit MB), network-bound | Optional but worth-it (see below). Fail-open without keys. |
| `bbot` | A+ — deep passive | Multi-module pipeline (50+ passive sources, CT, DNS, security feeds) | 200-500 MB RAM during run, network-bound | Optional; provider keys lift coverage but bbot is meaningful unkeyed. |
| `cero` | B — TLS SAN scraping | TCP/TLS handshake against CIDR + port set, parses SAN | ~100 MB RAM at default concurrency=100 | None |
| `alterx` | C — permutation generator | Pattern engine (`{{sub}}`, `{{word}}`, `{{suffix}}`) | Low CPU, output stream | None |
| `puredns` | C — bruteforce resolver | massdns + wildcard filter wrapper | ~500 MB RAM at 5000 qps | None (resolver list required) |
| `dnsx` | D — active resolution | Bulk DNS resolver with record-type enumeration | ~150 MB RAM, low CPU | None (resolver list optional) |

## subfinder — API key value-for-cost

subfinder is fail-open without provider keys: it queries every source, drops the ones that fail, and aggregates whatever the free sources return. Coverage without keys is roughly 60-70% of the full-key set. Worth-it free keys, ranked by signal-per-key:

1. **SecurityTrails** — highest unique-coverage delta. Free tier is 50 requests/month, which is enough for ~50 wildcard scope entries per engagement.
2. **Censys** — CT-derived plus internet-wide certificate scans. Free tier covers most engagement-scale work.
3. **VirusTotal** — large historical coverage. Free tier is rate-limited (4/min) but works for batch enumeration.
4. **Shodan** — banner-derived sub discovery. Less unique value than the top three; useful when the target has many internet-exposed services.

Configure via `${SUBFINDER_SECURITYTRAILS_API_KEY}`, `${SUBFINDER_CENSYS_API_ID}` + `${SUBFINDER_CENSYS_API_SECRET}`, `${SUBFINDER_VIRUSTOTAL_API_KEY}`, `${SUBFINDER_SHODAN_API_KEY}` in `agent/.env.example`. The runtime exposes these to subfinder via the standard provider-config.yaml lookup chain — populating the env vars is enough.

PassiveTotal, Chaos, IntelX, URLScan, and GitHub tokens are also wired in `.env.example` (lines 71-85). Add them when the engagement budget supports the upstream API costs; the top four cover the high-signal cases.

## puredns — rate-limit reality

puredns wraps massdns + wildcard filter. Performance is governed by the resolver pool plus the per-resolver rate cap, not local CPU.

- **5000 qps** — safe across a healthy resolver list (curated `resolvers.txt`, ~30 trusted resolvers). This is the default we use in Phase C.
- **8-10k qps** — upper bound when the resolver list is large (>100 resolvers) and the wordlist is large enough that the work spreads. Past this you hit per-resolver rate-limits, not local saturation.
- **RAM** — ~500 MB at 5000 qps for a 200k-entry permutation set. RAM is dominated by the wildcard-filter dedup map.

When the target's authoritative DNS is rate-limited at the apex, drop the rate cap to 1000-2000 qps. Otherwise puredns consumes the full bandwidth of the resolvers without protecting them.

## alterx — permutation expansion

alterx takes known subdomains and emits permutations using built-in patterns (or custom patterns via `-p`). The expansion factor is 10-100x depending on the input size and pattern set:

- 100 known subs → 1000-10000 permutations with default patterns
- 1000 known subs → 10000-100000 permutations
- Custom `-p '{{sub}}-{{word}}.{{suffix}}'` with a payload list of ~50 words → fixed 50x expansion

Default patterns cover the common cases (`{sub}-staging`, `{sub}-dev`, `{sub}.{suffix}`, etc.). Reach for `-p`/`-pf` only when the engagement has obvious naming convention signals (e.g. company internal naming pattern leaked elsewhere).

The chain pattern is **alterx -> puredns resolve**, not `alterx -> dnsx`, because permutations have a high false-positive rate and need wildcard-filtering before downstream tools see them. Pipe directly with `aith assess kali alterx -l <subs>.txt -o /tmp/perms.txt && aith assess kali puredns resolve /tmp/perms.txt --rate-limit 5000 -w /tmp/perms_resolved.txt`.

## cero — CIDR-feed pattern

cero reads either a domain list or a CIDR block, opens a TCP connection on the listed ports (default 443,8443), completes the TLS handshake, and harvests Subject Alternative Names from the certificate. Two patterns:

1. **Domain list** — feed the output of subfinder/bbot. Marginal value over CT logs, mostly catches internal certs that targets host on internet-exposed IPs.
2. **CIDR block** — the high-value pattern. Feed CIDRs from `asnmap` (after ASN → CIDR mapping). This catches subdomain names that never appear in CT (private CAs, internal stage envs that share an apex) but DO appear in the cert SAN of a TLS-handshakable host on the IP block.

Default ports are 443 and 8443. Add 9443/8444/etc. when the target advertises additional TLS endpoints (visible in nmap or httpx output). Concurrency=100 is the default; lower to 50 against rate-sensitive targets, raise to 200 when sweeping large CIDRs (thousands of IPs).

## bbot — passive preset rationale

bbot's strength is the breadth of passive sources it queries in one invocation. The `subdomain-enum` preset enables the canonical sub-enum module set; `-rf passive` filters to passive-only modules so no traffic touches the target during the run.

- `bbot -p subdomain-enum -rf passive -t <target>` — canonical passive sweep. Runs ~15-25 minutes against a single target depending on rate-limits at the upstream sources.
- `-m crt` / `-m subdomain_relay` etc. — narrow to specific modules when the canonical preset is too broad or too slow.
- `--allow-deadly` enables active modules (fuzzing, brute-force, exploit attempts). The kali wrapper hard-fails when `--allow-deadly` is passed without `--destructive` because deadly modules attack the target — the audit row must reflect destructive intent.

bbot is not a subfinder replacement, it is an addition. Run subfinder first (Phase A); reach for bbot when the subfinder set is thin or the engagement budget allows the longer wall-clock for deeper coverage.

## When NOT to bruteforce

Phase C (alterx + puredns) is the highest-CPU step in the workflow. Skip when either signal fires — the marginal yield does not justify the cost.

- **Phase A returned >5000 unique subs.** At that volume, passive sources have already saturated the namespace. Permutation candidates against a 5000-sub apex rarely add live hosts; the live-host hit rate per permutation drops below 0.1%.
- **Target is a top-tier organization** (federal agency, F500 enterprise, well-funded bug-bounty program with broad scope). Such targets have years of CT logs, well-known passive footprint, and aggressive wildcard rejection. Passive + CT covers the namespace far better than permutations.

When skipping C, jump from Phase B to Phase D directly. Record the skip rationale via `aith assess log operator "Phase C bruteforce skipped" "<reason>" --actor-kind operator` so the audit trail explains the missing run instead of leaving a coverage gap unexplained.

## Cross-references

- Phase A→D workflow with example invocations: `agent/skills/kali-exec/SKILL.md` "Subdomain enumeration: Phase A→D workflow"
- subdomain-enumeration skill (when this matters in operator phase flow): `agent/skills/subdomain-enumeration/SKILL.md`
- Prioritization and sliding-window rules: `agent/references/subdomain-enumeration.md`
- puredns + dnsx flag detail: `agent/references/tools/recon/puredns.md`, `agent/references/tools/recon/dnsx.md`
