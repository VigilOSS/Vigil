# Recon Dispatch Resource Policy

Runtime guide extracted from `agent/operator-core.md` (operator-core phase-split, WS6). This is operator-owned cross-phase machinery — the single source of truth for per-target rate calibration and aggregate-concurrency / shared-VM safety. The Phase-1 and Phase-4 docs (`agent/phases/phase-1-recon.md`, `agent/phases/phase-4-consume-test.md`) point here for dispatch-shape and concurrency-floor/ceiling decisions.

Every active recon dispatch passes through this policy before the operator hands the
work to a specialist. The policy is the single source of truth for per-target rate
calibration; specialists pull values from this table rather than guessing, and the
operator catches dispatch-context drift before it reaches the runtime.

### Resource-safety preflight rule

Active recon dispatches must declare in dispatch context: candidate count, rate limit,
thread count, retry count, timeout, output mode (line / JSON / `-omit-raw`), stop
condition, and expected wall-clock. Specialists do not guess these — operators set them.

### Per-target rate calibration table

The trait-row table (Cloud-fronted / Origin / WAF-protected / High-friction / Vendor SaaS) and the runtime-tier × DNS-profile matrix live in `agent/references/recon/rate-calibration.md` (extracted from `shared-constraints.md` §14 to keep the every-specialist load lighter). Recon-class specialists pull values from there; this section covers tier selection and step-down rules.

### Picking a tier

Run `wafw00f` first; if a CDN/WAF is detected, pick the matching trait row. If httpx
fingerprint shows a known vendor SaaS host pattern, use the Vendor SaaS row. If neither,
default to **Origin / single-server** (the most cautious non-vendor row). Never default
to Cloud-fronted just because the apex looks bursty-friendly — wildcards and subdomains
often sit on origin servers.

### When to step down a tier

Watch for: 429s, sudden response-time degradation, or a CAPTCHA challenge served on
probes. Step down one tier (e.g., Cloud-fronted → WAF-protected) and rerun the
calibration. Do not step UP a tier mid-engagement.

### DNS bruteforce gating

The DNS-brute column is the rate ceiling for puredns/shuffledns invocations. Cross-reference
`agent/skills/subdomain-enumeration/SKILL.md` "Host-CPU note" — DNS bruteforce is the
dominant host-CPU and host-network spike in the engagement runtime, and aggressive
profiles have crashed Docker on standard laptop hardware. The runtime-tier matrix above is
what gates the `bursty-OK` profile: Standard tier never picks `bursty-OK`; Heavy tier may
opt in via `--intent`; Comfortable tier may use it by default for trait rows that allow it.
When in doubt, default to `polite-residential` for puredns/shuffledns and let the trait row pick the tier. For dnsx, the typed wrapper (`vigil assess kali dnsx`) defaults to `--dnsx-profile polite-cdn --resolver-profile public-tcp`; step up only after assessing the target.

### Aggregate concurrency + shared-VM ceiling

The per-target rate calibration above bounds a *single* probe. It does NOT bound the
*aggregate* load of several heavy operations running at once — which is what actually
crashed the runtime in past engagements (host load 36 on a 12-core host; 4 parallel recon
agents each running `subfinder -all -recursive` + `amass`). The aggregate limits below are
the **Standard-tier (shared-runtime) safety policy** — they exist to protect a co-tenant
shared VM, not to throttle the operator by default. On a Heavy or Comfortable (dedicated)
tier they do not apply; see the concurrency floor below.

**Standard-tier (shared runtime) — serialize heavy work:**

- **One heavy enum op at a time (engagement-wide).** "Heavy" = DNS brute
  (puredns/shuffledns/massdns), bulk `httpx`/`dnsx` liveness over large lists, full-template
  `nuclei` sweeps, and large-wordlist fuzzing. Serialize these — never run two concurrently
  on a Standard-tier (shared) runtime.
- **Concurrent-heavy-agent cap = 1 (Standard tier only).** On a Standard-tier shared runtime,
  at most one specialist runs a heavy enum op at a time; additional recon agents are dispatched
  sequentially or restricted to light/passive work. This `cap=1` is a shared-runtime safety
  measure — it is **not** the default operating mode and does **not** apply on Heavy/Comfortable.
  (The per-tool `Concurrent nmap procs cap` in `agent/references/recon/rate-calibration.md` is
  the narrower in-tool limit; this is the cross-agent limit.)
- **Shared-VM memory ceiling.** Before launching heavy enum, confirm the runtime is not
  co-tenant-starved: a shared Docker VM hosting other (especially production) containers must
  stay well under its `MemTotal`. Do not launch heavy enum when the shared VM is near its
  memory ceiling — prefer a dedicated runtime. (`vigil runtime start` performs a code-side
  shared-VM preflight; this policy is the human-judgment companion to it.)

**Heavy / Comfortable tier — run 4–6 specialists in parallel (concurrency FLOOR, not ceiling):**

On a dedicated Heavy or Comfortable runtime the operator SHOULD run **4–6 specialists
concurrently** — that is the floor for a properly-utilized dedicated box, not a limit to stay
under. The `cap=1` / one-at-a-time guidance above is Standard-tier-only; do not carry it onto
the Heavy tier and throttle to a single specialist. Under-utilizing a dedicated runtime by
running 1–2 agents is itself a failure mode (the long-tail-write-off pattern from the origin
engagement was driven in part by only ~2 specialists running at a time). Fan the swarm to 4–6,
size each specialist's per-target rate from the calibration table, and only step back from the
floor if the dedicated box's own health-check shows genuine saturation — not preemptively.

### Phase-1 dispatch shape: sequential on shared runtimes

The default "fan out `recon-specialist` + `source-analyzer` (+ OSINT) in parallel" shape is
correct only on a **dedicated** runtime (Heavy/Comfortable tier or a single-engagement VM).
On a shared/constrained **Standard-tier** runtime, default to a **sequential, monitored recon
pipeline**: run one heavy op (the `vigil assess recon` job is the heavy one to serialize), watch host load and the daemon health-check, then start the
next. Fan out only once you have confirmed the runtime can absorb concurrent heavy work. This
preserves the parallel-throughput win where the box can take it without reproducing the
load-36 near-crash on a shared box.

