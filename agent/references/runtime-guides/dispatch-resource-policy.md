# Recon Dispatch Resource Policy

Operator-owned cross-phase machinery: model and reasoning selection, per-target rate calibration, and
cross-dispatch / shared-VM safety. The Phase-1 and Phase-4 docs (`agent/phases/phase-1-recon.md`,
`agent/phases/phase-4-consume-test.md`) point here for dispatch-shape and concurrency decisions.

### Model and reasoning selection

Declare the model and reasoning on `vigil assess agent start` with `--model`/`--reasoning`. The row records
your request; the client decides what runs: the spawn's own model option where the client exposes one,
otherwise a model pinned in the role's generated wrapper, otherwise the operator's own model. Keep the
declaration equal to what the spawn will actually use.

On Claude Code, `vigil engagement start` runs the operator session on the track's default model: code
runs `claude-opus-5-5[1m]` and web runs `claude-opus-5[1m]`. Specialists inherit the session model unless
their generated wrapper pins one. The human can launch with another `--model` or set a Vigil override,
so declare the model your session actually runs.

| Work | Claude operator / workers | Codex operator / workers |
|---|---|---|
| High-stakes specialist work (exploit chains, deep code review, novel vulnerability hypotheses) | The session model (code: `claude-opus-5-5[1m]`, web: `claude-opus-5[1m]`) at `max` | `gpt-5.6-sol` at `xhigh` (`max` is Claude-only) |
| Standard specialist work | same model at `high` | same model at `high` |
| Bounded sidecar work where latency or cost matters more than depth | `claude-sonnet-5-5` | `gpt-5.6-sol` at `medium` |
| Evidence-complete per-finding `report-writer` authoring and QC | The generated wrapper pins `claude-sonnet-5-5` at medium: spawn it without a model option and declare that pair on `agent start` | `gpt-5.6-terra` at medium |

Pass a stronger report-writer model only to escalate when proof, severity or causality stays contested.
The independent reproduction and blind triage keep their stronger reviewer model.

Every active recon dispatch passes through this policy before it reaches a specialist. This is
prompt discipline, not a lease or reservation. The operator passes the exact authored instruction
through `agent start --rate-budget`, and Vigil infers no numeric default. Before a target-facing
process starts, the CLI prints bounded context about other lanes' recent target-facing commands.
That advisory counts no requests, reserves no capacity and enforces none of the limits below.

### Runtime sizing tiers

`vigil runtime resources` prints the configured numbers (`memory_gb`, `cpus`, `pids_limit`,
`shm_size`) and the live cgroup state; it does not print a tier name. Lab/CTF, Standard, Heavy and
Comfortable are this prompt system's names for those numbers. The installed defaults are 2 GB of
memory, 1 CPU, 512 pids and a 1g shared-memory segment, which is the Lab/CTF tier. Change them with
`VIGIL_RUNTIME_MEMORY_GB`, `VIGIL_RUNTIME_CPUS`, `VIGIL_RUNTIME_PIDS_LIMIT` and
`VIGIL_RUNTIME_SHM_SIZE`, then recreate the container with `vigil runtime restart`.

| Tier | Memory / CPUs | Workload it supports |
|---|---|---|
| Lab/CTF (installed default) | below 8 GB / below 4 | Light, mostly sequential testing; one heavy operation at a time |
| Standard | 8 GB / 4 | 2-3 parallel specialists on a small bounty target; the shared-runtime limits below apply |
| Heavy | 16 GB / 8 | Large enterprise scope; the 4-6 specialist concurrency floor below applies |
| Comfortable | 32 GB / 12 | All tools warm on a continuous engagement |

Size the fan-out to the smaller of the surface breadth and the tier's capacity.

### Resource-safety preflight rule

An active recon dispatch states its candidate count, rate limit, threads, retries, timeout, output
mode (line / JSON / `-omit-raw`), stop condition and expected wall-clock in the dispatch context.
The operator sets these so specialists don't guess them. The per-target trait rows (Cloud-fronted,
Origin, WAF-protected, High-friction, Vendor SaaS, Lab / CTF) and the runtime-tier × DNS-profile
matrix are in `agent/references/recon/rate-calibration.md`.

### Picking a tier

Run `wafw00f` first; if a CDN/WAF is detected, pick the matching trait row. If httpx
fingerprint shows a known vendor SaaS host pattern, use the Vendor SaaS row. If neither,
default to **Origin / single-server** (the most cautious non-vendor row). The Lab / CTF row
applies only to a dedicated target the ROE explicitly clears for aggressive rates. Never default
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
On an unassessed target use `polite-CDN-fronted-target` for puredns/shuffledns; once assessed, let the trait row pick the tier. For dnsx, the typed wrapper (`vigil assess kali dnsx`) defaults to `--dnsx-profile polite-cdn --resolver-profile public-tcp`; step up only after assessing the target.

### Aggregate concurrency + shared-VM ceiling

Per-target rates bound a single probe, not the aggregate. A few parallel recon agents each running
recursive passive enumeration plus DNS brute force can saturate the host CPU and stall the Docker
daemon. The limits below protect a co-tenant shared VM on a Standard-tier runtime. They are not a
default throttle and do not apply on a dedicated Heavy or Comfortable tier.

**Standard-tier (shared runtime) — serialize heavy work:**

- **One heavy enum op at a time, engagement-wide.** Heavy means DNS brute
  (puredns/shuffledns/massdns), bulk `httpx`/`dnsx` liveness over large lists, full-template
  `nuclei` sweeps and large-wordlist fuzzing. At most one specialist runs one at a time, and other
  recon lanes run sequentially or stay light or passive. The `Concurrent nmap procs cap` in
  `rate-calibration.md` is the narrower in-tool limit.
- **Shared-VM memory ceiling.** Before launching heavy enum, confirm the runtime is not
  co-tenant-starved: a shared Docker VM hosting other (especially production) containers must
  stay well under its `MemTotal`. When the shared VM is near its memory ceiling, prefer a
  dedicated runtime over launching heavy enum. (`vigil runtime start` performs a code-side
  shared-VM preflight; this policy is the human-judgment companion to it.)

**Heavy / Comfortable tier — run 4–6 specialists in parallel (concurrency FLOOR, not ceiling):**

On a dedicated runtime, 4–6 concurrent specialists is the floor for using the box properly, not a
limit to stay under. Carrying the Standard-tier one-at-a-time rule onto a dedicated box leaves
long-tail surfaces written off for lack of lanes. Size each lane's rate from the calibration
table, and drop below the floor only when the box's own health check shows real saturation.

### Phase-1 dispatch shape: sequential on shared runtimes

Running `recon-specialist`, `source-analyzer` and OSINT in parallel is right only on a dedicated
runtime. On a shared Standard-tier runtime, run a sequential, monitored pipeline: one heavy op at a
time (the `vigil assess recon` job is the one to serialize), watching host load and daemon health
before starting the next. Fan out once you've confirmed the runtime can take concurrent heavy work.
