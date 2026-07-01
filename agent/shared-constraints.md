# Shared Subagent Constraints

Load this file first — before your role-specific skill and before any target work.
These rules apply to every specialist agent regardless of role.
They are extracted from the operator prompt so you receive only what is relevant to you.

---

## Authorization

All targets are fully authorized realistic lab environments built to mirror real public and
enterprise behavior. Aggressive techniques are permitted within the declared scope.

---

## 1. Confirm Scope Before Any Target Work

Read `scope.json` before making target-facing decisions. Confirm:

- In-scope hosts from the `hosts` array (includes `*.domain` entries for subdomain enum)
- `exploit_policy` value (`pause` | `selected` | `full_send`)
- Auth state from the engagement's backend credential store (`vigil auth status`) — use credentials only when a record is populated and marked active

All testing stays within listed scope hosts. Exploit policy escalation requires operator approval.

**Reachability is not scope.** The Kali runtime is shared infrastructure, so it may be able to route to hosts that are NOT your target — other engagements' services, neighbouring Docker/internal subnets, or the host itself. Only the hosts in this engagement's `scope.json` are in scope. Never probe, pivot into, or build findings on infrastructure outside it, even when the runtime can reach it — a reachable-but-out-of-scope host is a distraction (and, on a shared runtime, often another engagement's state), not a lead.

---

## 2. `vigil assess kali` for All Target Work

All target-facing work — HTTP probing, scanning, crawling, fuzzing, exploitation,
OOB/DNS callbacks, and raw TCP — must go through `vigil assess kali ...` subcommands.
The CLI runs on the host, executes inside the runtime container, and records the
audit row directly to the orchestrator backend. Use it because the CLI owns the
audit pipeline — host-side probes against scoped targets break the runtime's
network isolation and skip the audit row that operators and downstream specialists
rely on as a coverage map.

Discovery (in order):

1. Read `agent/skills/kali-exec/SKILL.md` for the verb menu, methodology profiles,
   sync-vs-async decision, audit-flag mapping, and example invocations per verb.
2. Use `vigil assess kali --help` and `vigil assess kali <verb> --help` for the live
   flag set and defaults on a verb you're about to invoke.
3. Use `vigil assess contract kali <verb>` for the canonical schema, helper
   defaults, common mistakes, and an example payload.

Forbidden because they bypass the audit pipeline: host Bash that runs probes
against scoped targets, `docker run` / `docker exec` against the runtime, and
ad-hoc curl/nmap/sqlmap/etc. from the host. The host boundary is for
orchestration, not target traffic.

Target-facing dispatches run **synchronously by default**: each
`vigil assess kali <verb> ... --timeout N` call is blocking and awaited to
completion in-band — no `run_in_background`, no `vigil assess kali job start`,
no dtach, and no watcher/poll loop. A specialist must never background target
traffic and then halt waiting for a completion notification: the harness
auto-resumes the halted agent, which launches the next detached job and halts
again, producing unbounded relaunch thrash and duplicate probes — in past
engagements this burned 80–210 K tokens per agent and produced duplicate httpx
passes with near-zero net coverage (the failure mode that stalled multiple recon
dispatches — see the engagement post-mortem).
A generous `--timeout` is the correct tool for a single long probe
(`nmap+scripts`, `sqlmap`, `nuclei` sweep, `dirb`, `gobuster`, `ffuf` large
wordlists): when it expires the audit pipeline cascades SIGTERM→SIGKILL into
the in-container PID, so a synchronous call is killed cleanly and is never
orphaned.

That cascade governs the Vigil CLI's *own* `--timeout`. Above it sits a separate
**agent-harness ceiling you do not control**: if a single blocking tool call runs
longer than the harness allows, the harness auto-backgrounds the call and kills the
agent (**exit 144 / SIGUSR1**) at a timeout you cannot set — orphaning the in-flight
probe and any detached children, and writing no handoff. A larger `--timeout` does
not defeat this; it only widens the window in which the harness fires. So a single
synchronous probe must fit well under that ceiling (minutes, not tens of minutes),
and genuinely long enumeration — a full-apex `puredns` brute, bulk HTTP liveness
over thousands of hosts, a deep crawl — belongs in the operator-owned, supervised,
resumable `vigil assess recon` job that the operator polls, never a specialist's
blocking call. (This SIGUSR1/exit-144 kill is the failure mode that produced the
recon-dispatch thrash above.)

**"Synchronous" means awaited-in-band, NOT one-call-at-a-time and NOT
no-parallelism.** The ban is on the backgrounding / `dtach` / fire-and-forget /
poll-for-completion-later patterns above — not on concurrency. Issuing several
blocking calls in parallel, each awaited to completion in-band, is fine: the
prohibited thing is detaching a job and reaping it later, not running more than
one probe at once. (The operator likewise runs multiple specialists
concurrently — synchronous execution inside each does not mean a single global
in-flight call.)

`vigil assess kali job start` — the SQLite-backed, dtach-supervised worker that
survives calling-shell exit — is reserved for a **single** long-running sweep
the **operator** explicitly launches and monitors directly. It is never a
per-step pattern inside a specialist's agent loop and never a way to fan out
parallel detached probes. If a dispatched specialist believes a probe must
outlive its dispatch, it says so in its handoff and lets the operator own the
job rather than backgrounding it itself.

Host-side commands are limited to coordination and non-target support only:
`jq`, `sqlite3`, `python3`, `grep` / `rg`, `sed`, `awk`, `base64`, `openssl`,
plus `vigil assess` helpers for backend state writes.

If a required target-facing tool is missing from the runtime image, rebuild the
image rather than falling back to host or Docker-side execution paths — the
runtime image is the single source of truth for the tool surface.

**Reserve `echo` inside `vigil assess kali` commands for functional output only.**
Stdout is captured to the audit log, not shown to the user, and commentary-echoes
bloat the preview and pollute FTS search without adding retrievable signal. Use
`--intent` for a one-line purpose annotation. `echo` is legitimate when its output
is the command's real purpose — writing
to a file (`echo X > file`), piping into another tool, or generating a payload.

### Process cleanup — no broad `pkill`/`killall` by binary name

Agents MUST NOT use `pkill`, `killall`, or `kill -9 -f <binary>` against
shared-runtime processes. The Kali runtime is shared infrastructure across
parallel specialists, so a broad signal by binary name kills sibling agents'
work — losing potentially hours of recon. The audit pipeline already
cascades SIGTERM→SIGKILL into the in-container PID on timeout, so manual
cleanup is rarely needed; when it is, **PID-targeted kill is OK** — `kill
-TERM <pid>` against a tracked, in-container PID only signals your own
process, not siblings. The forbidden pattern is the *binary-name* selector
(`pkill -f nmap`, `killall nuclei`); the safe pattern is the *PID*
selector (`kill -TERM "$(cat /tmp/vigil-pid-<run_uuid>)"`).

What to do instead — track the lifecycle of every process you spawn and stop
only the one you started:

- **Synchronous runs (the specialist default) — let `--timeout` clean up.**
  A blocking `vigil assess kali <verb> ... --timeout N` cascades
  SIGTERM→SIGKILL into the in-container PID when the budget expires, so no
  manual cleanup is needed for the common case.
- **Operator-owned long sweeps — use the job lifecycle.** When the operator
  has launched a single authorized long sweep with `vigil assess kali job
  start ... -- <verb> ...`, stop it cleanly with `vigil assess kali job stop
  <id>`. The job worker SIGTERMs only the in-container PID it owns; sibling
  jobs stay alive. (Specialists do not start jobs — see §2.)
- **Mid-run synchronous cleanup — use the run-uuid PID file.**
  Every audit row carries a `run_uuid`. The runtime writes the
  in-container PID to `/tmp/vigil-pid-<run_uuid>` for the duration of the
  run, so cleanup is `vigil assess kali exec --technique META --intent
  "terminate tracked runtime pid" --probe-kind cleanup --phase <phase>
  --timeout 30 -- sh -c 'kill -TERM "$(cat
  /tmp/vigil-pid-<run_uuid>.pid)"'`. This signals only your run, not sibling
  runs of the same binary.
- **Last-resort hygiene for hours-long parallel runs — copy the binary
  per agent.** `vigil assess kali exec --technique META --intent
  "create per-agent nmap copy" --probe-kind cleanup --phase <phase>
  --timeout 30 -- cp /usr/bin/nmap /usr/local/bin/nmap-${AGENT_NAME}` so a later `pkill -f
  nmap-${AGENT_NAME}` only matches your processes. Prefer the job
  lifecycle; reach for this only when two specialists genuinely need
  multi-hour parallel sweeps of the same heavy binary.
- **Timeout-related cleanup is automatic.** `vigil assess kali exec` and
  every typed verb cascade SIGTERM→SIGKILL into the in-container PID via
  `docker exec ... kill` when `--timeout` expires. Operators do not need
  to kill anything manually for a timeout — the in-container tree is
  already gone.

### Command Metadata

Every target-facing `vigil assess kali` call carries audit metadata as CLI flags.
The CLI fails closed when required flags are missing — the audit row stays
truthful instead of degrading to a stale env-var default.

- **`--technique <enum>`** — the vulnerability class this command tests. One of
  `SSRF`, `XSS`, `XXE`, `SQLI`, `NOSQLI`, `SSTI`, `RCE`, `CMDI`, `IDOR`, `LFI`,
  `RFI`, `OPEN-REDIRECT`, `AUTH`, `JWT`, `CSRF`, `CORS`, `REQUEST-SMUGGLING`,
  `RATE-LIMIT`, `INFO-DISCLOSURE`, `RECON`, `DISCOVERY`, `FUZZ`, `OSINT`,
  `CVE-VALIDATION`, `EXPLOIT-CHAIN`, `META`, `HEALTH`, `LOG-READ`, `OTHER`. Derive it from the skill you
  loaded: for skills whose name maps 1:1 to an enum value (`ssrf-testing` →
  `SSRF`, `sqli-testing` → `SQLI`, `command-injection` → `CMDI`, etc.), use that
  mapping. When the mapping isn't obvious (e.g. `aws-iam-privesc`,
  `container-escape-detection`, `graphql-testing`), the skill file names the
  correct value at the top. Use `HEALTH` for runtime/tool inventory commands
  such as `which jadx apktool`. The CLI rejects unknown tags before writing an
  audit row so bad prompt vocabulary does not pollute command-history filters.
- **`--intent "<text>"`** — a ≤200-char one-liner describing what this specific
  command is trying to accomplish. Replaces the `echo "=== label ==="` pattern.
- **`--probe-kind <kind>`** — the kind of work this command represents:
  - `fingerprint` — learning the target (versions, headers, tech stack), no payload
  - `baseline` — vanilla control request against the target surface, for diff
  - `payload` — crafted attack payload testing a hypothesis
  - `exploit` — attacker-outcome proof (extract token, read a file, prove the impact)
  - `replay` — captured primitive used against a new surface (lateral)
  - `cleanup` — undoing target-side changes
- **`--destructive`** — pass when the command attempts a write, edit, or delete
  on the target (POST/PUT/PATCH/DELETE, file upload, account creation, config
  change, shell exec that modifies state). Off for read-only probes. Used by
  cleanup-tracking workflows.
- **`--timeout <seconds>`** — wall-clock budget. Required. Synchronous calls hit
  the timeout cleanly (SIGTERM→SIGKILL into the in-container PID), so raise the
  budget for a heavy single probe rather than backgrounding it. A long budget is
  not a reason to use `vigil assess kali job start` — that is operator-only (§2).
- **`--phase <enum>`** — REQUIRED on every call. Pass the phase the dispatch was
  authorized for, NOT `scope.json.current_phase`. The reason is that
  `scope.json.current_phase` is operator state and updates only on phase
  transitions, but engagements regularly operate **between phases** —
  mid-Phase-3 recon on a newly-discovered host, Phase-5 exploit-developer
  running additional fingerprinting, source-analyzer mid-engagement looking up
  version intel. The audit row must reflect what the dispatch was for, not what
  the engagement happened to be in at the time. The CLI rejects calls without
  `--phase` so agents cannot silently rely on a stale env-var default. Allowed
  values: `recon`, `collect`, `consume-test`, `verify`, `exploit`, `report`,
  `code-ingest`, `code-classify`, `code-hunt`, `code-verify`, plus the
  half-phase tags `recon-pivot` (mid-engagement recon on newly-surfaced host)
  and `exploit-recon` (additional fingerprinting during exploit phase).
- **`--force`** — suppress the dedup-warning log for an intentional retry.
  The CLI hashes `(command, argv_json)` and warns when an identical command
  ran within `KALI_AUDIT_DEDUP_WINDOW_SECONDS` (default 30s), but the new
  command always executes — the backend records a fresh audit row regardless,
  with `superseded_by_id` linking it to the predecessor when applicable. Pass
  `--force` only to suppress the warning text; it does not change run
  behavior or backend state.

`--engagement-key` is derived from `${ENGAGEMENT_DIR}/engagement.json`.
`--agent-name` resolves from the explicit flag, `$AGENT_NAME`, `$VIGIL_AGENT_NAME`,
then `operator`. Specialist dispatch wrappers must export `AGENT_NAME=<role>`;
if that context is missing, pass `--agent-name <role>` explicitly because a
silent `operator` attribution breaks coverage ownership.

---

## 2d. Side-Effect Preflight

Before sending a request that could **create persistent state or reach a human** —
signup, request-access, support/report/ticket, password-reset, contact-form, or any
endpoint whose name or path suggests a write that notifies someone — run this
procedure.

**Posture change: this section moved from zero-fire to capped-live-fire.**
Previously: "if yes, or if unknown: do not fire the probe" — permanent, no path to
resolve a genuine unknown. Now: static-first (unlimited), then a hard, small,
audited live-fire budget to resolve real ambiguity, gated by a durable recorded
decision. This is a deliberate loosening of a global default, not a relaxation of
caution — read the whole procedure, including the cross-dispatch rule, before
relying on the budget.

### Step 1 — mandatory-first, unlimited static characterization

Before any live fire, characterize the endpoint statically. This step carries no
request budget — run as many read-only, non-triggering probes as needed:

- The HTTP method(s) and parameters the endpoint accepts
- The response shape on a non-triggering `GET`/`HEAD`/`OPTIONS` (status, headers,
  body fields) — never the write verb itself
- What the source, API spec, or documentation say the endpoint does
- Cross-reference `ENGAGEMENT.md` §4 (No-Fire Endpoints) and §5 (Irreversible and
  Notifying Flows) for a pre-declared answer, including its Known-Safe Test
  Destinations table

### Step 2 — the reaches-a-real-third-party test

Ask: does success *or* failure land in a real inbox, queue, audit trail, or notify
a real person who is not the researcher?

**POSITIVE (reaches a real third party) — examples, not exhaustive:**
- A live support/ticket queue that a real agent reads and actions
- An email, SMS, or push notification delivered to a non-researcher-owned address
- A role/access request routed to a real approver
- A pager/on-call alert
- A post to a customer-visible channel (public comment, shared workspace, forum)

**NEGATIVE (does not reach a real third party) — examples, not exhaustive:**
- A researcher-owned test identity (an account, mailbox, or phone number the
  researcher provisioned and controls)
- A documented sandbox/staging environment with no live inbox behind it
- A mock/stub queue that accepts the request but has no delivery path
- A self-directed notification to the researcher's own test account

A proven-NEGATIVE endpoint is ordinary surface — hunt it fully; it carries no
side-effect risk. Step 1's static pass should aim to reach one of these two
answers; only genuine ambiguity after a thorough static characterization proceeds
to Step 3.

### Step 3 — hard 1-3 live-fire budget (POSITIVE, or unresolved after Step 1-2)

If Step 2 resolves POSITIVE, or static characterization leaves it genuinely
**unknown**, you may spend a budget of **1-3 live requests, per endpoint/action,
across the WHOLE engagement** (not per dispatch — see the cross-dispatch rule
below) to resolve the ambiguity. Stop the instant either condition is met:

- the probe **confirms** the endpoint reaches a real third party, or
- the budget (3 attempts) is **exhausted**.

**This budget is a prompt-enforced discipline / WARN backstop, not a hard technical
cap** — nothing in the CLI counts or blocks it. Hold yourself to it with the same
discipline as a hard cap anyway: it exists to bound the harm of a wrong "unknown"
call, not to license routine live-fire testing of notify-shaped endpoints. 1-3 is
the **global ceiling**; `ENGAGEMENT.md` may only **tighten** it for a program (cap
at 1 live attempt, or reinstate zero-fire for a named endpoint) — it may never
loosen it.

### Cross-dispatch rule — check before every fire, do not re-spend

**Before ANY live human-reach fire**, check for an existing `human_reach_decision`
already recorded against that exact endpoint/action — query the authoritative,
kind-filtered, paginated decision log:
`vigil assess fetch "dispatch-decisions?kind=human_reach_decision"` (grep the
returned JSON for the target host/endpoint to find the matching row). If a
`human_reach_decision` on that endpoint/action already carries a `payload.choice`
of `pending` or `denied`, treat it as **blocked — do not fire**, regardless of
whether your own dispatch has spent any of the nominal 1-3 itself.

**The 1-3 budget is per endpoint/action for the whole engagement, not per dispatch
and not per specialist** — a fresh dispatch does not get a fresh budget, and two
specialists must not each independently spend 3 against the same target. The
operator is expected to inject any open human-reach gate for a surface into the
dispatch context before sending a specialist at it (see `operator-core.md`
Dispatch Context Template), so the state is inherited rather than rediscovered —
but do not rely on that alone; check directly before firing.

### Recording and continuation gate

Any specialist records the decision directly (same pattern as `scope_decision`):

```bash
vigil assess agent decision --kind human_reach_decision --surfaced-to-user \
    --payload-json '{"choice": "pending", "endpoint": "<path-or-url>",
    "action": "<what-it-does>", "live_attempts_used": <n>,
    "destination_class": "real_third_party|unknown",
    "evidence": "<what Step 1-3 showed>"}'
```

The `choice` field **must** live inside `--payload-json` (as above), not as a
standalone `--choice` flag: when `--payload-json` is supplied the CLI uses it
verbatim and ignores the shorthand flags, so a top-level `--choice` would be
silently dropped and the cross-dispatch gate — which reads `payload.choice` —
would never fire. Do not continue live-firing that endpoint/action until the
operator resolves the decision. Valid resolutions:

- `approved_continue` — proceed with further live-fire (rare; the operator has
  independent grounds the destination is safe)
- `approved_limited` — proceed under a named, narrower constraint
- `denied` — do not fire again; treat as permanently blocked for this
  endpoint/action
- `not_real_recipient` — the destination was confirmed NOT a real third party;
  this **retroactively lifts the cap** for that endpoint and its siblings (it
  reverts to ordinary surface, per the negative-example list in Step 2)

Irreversible and notifying side-effects are not proved by triggering them beyond
this bounded, gated budget — firing past the budget, or past an open
`pending`/`denied` gate, is the harm this procedure exists to prevent. The
engagement-specific list of no-fire endpoints and known-safe test destinations
belongs in the `ENGAGEMENT.md` template (§4, §5); the principle here covers the
class.

---

## Contract-First Rule

Before the **first invocation of any `vigil assess` verb that mutates durable
state, dispatches a kali tool, or seats work-buffer rows**, run
`vigil assess contract <verb>` (or `vigil assess contract <verb> <variant>`)
to read the canonical schema, the required fields, the common mistakes, and
the example payload. Schema validation errors from guessing waste a full
round-trip, so reading the contract first is faster than re-running the
verb after a rejection.

Verbs covered by the rule (all have a contract entry; `vigil assess contract`
emits the canonical schema and an example):

- `kali <verb>` — `vigil assess contract kali <verb>`
- `record-finding` — `vigil assess contract record-finding`
- `record-intel <type>` — `vigil assess contract record-intel <type>`
- `record-surface` — `vigil assess contract record-surface`
- `agent <subverb>` for sub-verbs that mutate durable dispatch state or
  emit the canonical handoff blob:
  `start`, `done`, `handoff`, `decision`,
  `abort-duplicate`, `render-handoff` — `vigil assess contract agent <subverb>`
- Lifecycle helpers (`verify-finding`, `kill-finding`, `update-finding`,
  `reset-finding`, `resolve-surface`) — `vigil assess contract <verb>`

Verbs **not** covered (skip the contract round-trip — they are read-only or
have no payload to validate): `fetch`, `list-skills`, `list-clusters`,
`list-command-runs`, `get-command-run`, `check-phase-readiness`,
`filter-scope`, `work-buffer <db> stats|peek|fetch|done`,
`dispatch list`, `dispatch get`. Reading the contract for these adds
latency without preventing any error class.

Treat the contract output as the source of truth for arg ordering, flag
names, enum values, and required fields. Do not infer field names from
similar tools — five of the most common dispatch errors in recent
engagements (`record-surface` arg ordering, `record-finding` agent prefix,
`update-finding --details-patch`, `kali katana -H`, `kali exec
--probe-kind active`) would each have been prevented by running
`contract` before the first call.

---

## 2a. Listener, Tunnel, and OOB Responsibility

Shared listener infrastructure belongs to the operator because a listener, tunnel, or
interactsh server is global runtime state that can break other specialists if it is
started, restarted, or reconfigured mid-engagement.

Agents do their own readiness and evidence checks through `vigil`:
1. Inspect shared OOB state with `vigil oob status --json` before blind payload work.
   `server=true` and `frpc=true` means shared OOB infrastructure is ready.
2. Inspect infrastructure logs with `vigil logs oob --lines 80` when status is
   partial, callbacks are missing, or FRP/auth health is unclear.
3. Start, list, and stop named per-agent listener clients with `vigil oob client
   start|list|stop`. Per-agent interactsh clients are correlation handles, not
   shared tunnel infrastructure, so specialists can manage them directly.
4. Get correlated callback hits with `vigil oob poll --client <name>` — mint a
   nonce-tagged URL per payload with `vigil oob mint --client <name>` (it binds the
   nonce under that running client's interactsh id and prints the exact host to
   fire; pass `--client` to pick which one when several run), then `poll` matches
   each probe to its callback. `vigil oob client logs <name> --lines 80` and `vigil
   logs oob --lines 80` are raw listener-log tails for server/FRP debugging only,
   never for correlation.

When exploitation requires a reverse-shell listener or tunnel exposure:
1. Provide the exact listener or tunnel commands in your output using `# MANUAL:`
   annotation, because the operator owns shared listener processes.
2. Reference `agent/references/offensive-tactics/shell-handling.md` for shell
   listener commands.
3. Reference `agent/references/offensive-tactics/frp-tunneling.md` for OOB
   readiness, per-agent clients, tunnel exposure, and log interpretation.
4. Proceed after the listener URL file or `vigil oob` client is available; do not
   block on the operator for checks that `vigil oob status`, `vigil oob poll`, or
   the raw-debug tails (`vigil logs oob`, `vigil oob client logs`) can answer
   directly.

Starting, stopping, or restarting shared listener, tunnel, and OOB server processes
belongs to the operator — these are global runtime state whose disruption breaks
other concurrent specialists: pwncat-vl listeners, frp tunnels, chisel listeners,
`nc -lvp`, `socat` listeners, `frpc`, `oob-server`, interactsh servers, or
equivalent network listener processes.

---

## 2b. Coverage Check Before Probing

Every `vigil assess kali` call records its command, argv, tool, agent, phase,
technique, intent, probe_kind, destructive flag, exit code, timeout state,
timings, and an output preview (or artifact ref) to the orchestrator backend.
Treat that history as a **coverage map** — a record of what's already been
probed so your next probe goes somewhere the engagement hasn't covered yet.

Before issuing a probing, scanning, fuzzing, or credential-testing command,
search for prior work on this surface:

```bash
vigil assess list-command-runs --q <keyword> --show-matches
```

Default to an unscoped fuzzy search so finding aliases, nearby metadata, every
agent, and every phase are included; narrow with exact filters only if the broad
result is overwhelming. Cross-agent and cross-phase context is usually the most
valuable coverage signal.

Mode-of-search guidance:

- Default (`--q "VA-047 OIDC"`) OR-unions the raw input with every finding
  alias. Loose; surfaces anything related to the finding even when the topic
  token is missing. Best for coverage-mapping.
- `--all` keeps alias expansion but intersects every non-alias token — use when
  you want "rows that mention VA-047 (in any alias form) AND mention OIDC".
- `--exact` skips alias expansion entirely; the FTS phrase is searched
  verbatim. Strictest; use when a recall miss would be worse than a precision
  miss.

Read the results as a coverage map, not a reuse gate. Red-team depth comes
from variants — different SQLi techniques, different SSRF payload encodings,
different XXE entity styles, different wordlists, different auth contexts.
If `sqlmap` already ran against this endpoint with the audit row's
`--technique SQLI` and a `--intent` mentioning UNION, your next probe picks a
different SQLi class. If `ffuf` ran `raft-medium-directories`, try
`quickhits` or a tech-specific wordlist.

**The only probe you should skip is an identical command against identical
input.** Any variant — different payload family, different tool, different
flag, different target scope, different credentials — is new coverage and
belongs in the engagement. Don't ask for permission to probe a variant. Pass
the audit-flag set on every variant (`--technique`, `--intent`, `--probe-kind`,
`--phase`, `--timeout`, plus `--destructive` when applicable) so the next
specialist's coverage check sees it.

When a prior run genuinely covers your current question, cite its id in your
output — but first fetch the preview with `vigil assess get-command-run <id>`
and confirm the stored evidence actually answers that question. A row with
`success=true` only means `return_code=0`, not that the output is on-point.
Open the preview to rule out soft-failure pages, WAF intercepts, and
rate-limited stubs that exit cleanly. Citing an id you never looked at is
worse than running a fresh probe.

Full coverage-vs-duplicate decision table and output-field interpretation:
`agent/references/runtime-guides/command-history-auditing.md`.

---

## 2c. Resource-safety preflight

Active recon dispatches must declare candidate count, rate limit, thread count, retry,
timeout, output mode, stop condition, and expected wall-clock in dispatch context. The
Recon Dispatch Resource Policy in `agent/operator-core.md` is the calibration source of
truth.

---

## 3. Use Skills and References — They Are the Methodology

**Step 1 — Load the skill(s) named in your dispatch prompt.** The operator selects skills via
`vigil assess list-skills` (compact name + one-line "Use when:") and includes the path(s) in the
dispatch prompt. Read each named `agent/skills/<name>/SKILL.md` in full before doing anything else.
If no skill was named and you believe one exists, run `vigil assess list-skills` to discover it
yourself and report back rather than improvising — skill selection is the operator's job, but
discovery is fast (~200 tokens) and usually faster than guessing.

**Step 2 — Run `vigil assess list-references`** after loading the skill (add `--skill <name>` to
filter to that skill's paired references). Identify the paired
payload files, tool cheatsheets, and OWASP checklists that apply to your task and load them.

**Complete both reads before target-facing work begins.** Improvising a technique that
already exists in the skill/reference set wastes tokens, produces inconsistent results, and
misses methodology that the skill encodes (e.g., mitmproxy setup, payload libraries, tool flags).

**References are not a fallback.** The `references/` library contains:
- `payloads/` — 20 copy-pasteable attack payload files per bug class
- `api-security/` — OWASP API Security Top 10:2023 checklists
- `offensive-tactics/` — red team TTPs by kill-chain phase
- `tools/` — CLI tool cheatsheets (nmap, ffuf, sqlmap, hydra, etc.)

When a skill's "Extended Resources" section lists reference files, those are required reading
for that test class — not optional supplemental material.

Only improvise after confirming the reference set is genuinely insufficient.

---

## 4. Finding IDs and Recording

**MANDATORY: Every finding MUST be recorded via `vigil assess record-finding`.** Never hand-allocate
finding IDs. Never write findings only to markdown. Never skip the recording step. If you
produce a finding in any output section, you MUST also call `vigil assess record-finding` before your
task is complete. Findings that exist only in your output text and were not recorded via the
script are considered lost data.

| Agent | Prefix | Example |
|-------|--------|---------|
| exploit-developer | EX | EX-001 |
| vulnerability-analyst | VA | VA-001 |
| source-analyzer | SA | SA-001 |
| recon-specialist | RE | RE-001 |
| fuzzer | FZ | FZ-001 |
| osint-analyst | OS | OS-001 |
| surface-collector | SC | SC-001 |

**Title formula:** `[Bug Class] in [endpoint] allows [attacker role] to [impact] [victim/scope]`
Bad: "IDOR vulnerability found." Good: "IDOR in /api/users/{id} allows anonymous attacker to read any user's PII."

**CVSS↔severity must match:**

| Severity | CVSS range |
|----------|------------|
| critical | 9.0–10.0 |
| high | 7.0–8.9 |
| medium | 4.0–6.9 |
| low | 0.1–3.9 |
| info | 0.0 |

If your CVSS score does not fall within the matching severity range, adjust one or the other before recording.

**Deduplication:** Before recording, query existing findings via `vigil assess fetch findings`. If the same root cause on the same endpoint already exists, update the existing finding rather than creating a new one. Same vulnerability class across multiple parameter values of the same endpoint is one finding, not one per value.

Record every finding with:
```
vigil assess record-finding <agent-name> <finding-json-file>
```

The JSON payload must match `schemas/finding-record.schema.json`. Findings are always JSON — convert from markdown before recording.
Run `vigil assess contract record-finding` for the canonical field list and examples.
`record-finding` fills the initial finding lifecycle defaults — use those rather than setting lifecycle fields manually.

**CVSS and remediation** go in `details` as structured fields:
```json
"details": {
  "evidence": "...",
  "impact": "...",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "cvss_score": 9.1,
  "remediation": "Parameterize all SQL queries; use prepared statements",
  "steps_to_reproduce": ["Step 1...", "Step 2..."],
  "request_method": "POST",
  "cwe_id": "CWE-89"
}
```

This keeps CVSS queryable from the API and gives report-writer structured data to format.

When a finding is only reportable as part of a chain, keep it in the same finding lifecycle and
set chain metadata in `details` during `record-finding` or `update-finding`:
```json
"details": {
  "chain_required": true,
  "chain_rationale": "This primitive becomes meaningful only after pivoting into the admin export flow.",
  "required_followup": ["Test sibling privileged write routes", "Attempt authenticated export with stolen token"]
}
```
Use this instead of inventing a special workflow status for chain-only findings.

**Proof-not-collection — one minimal sample is sufficient.** When you have proven access
to a data set, one minimal **redacted** sample is all the evidence the finding needs.
Never bulk-pull real user records, credentials, or PII to "demonstrate" a finding —
volume does not strengthen the proof and only increases harm. The "evidence beats volume"
rule (`hunting.md §6`) applies at the collection boundary: more records is not more
proof, and extracting more is the harm, not the demonstration.

**The `notes` field must contain replayable commands** — not prose descriptions. Instead of
"Login to phpMyAdmin with blank password," write the actual command: curl with headers, cookies,
and POST body; sqlmap with exact flags; ysoserial with gadget chain and target; or whatever tool
proved the finding. The field allows up to 20 KB. If the operator or another agent needs to
reproduce the finding later, the notes field alone should be sufficient without re-discovering
the request format, session tokens, or tool parameters.

**Failure to use `vigil assess record-finding` is the single most common subagent defect.** If you
produce `#### Findings` output, each finding payload in that section must have been recorded
via `vigil assess record-finding` during your session. Do not defer recording to the operator.

---

## 5. Surface Candidates

When your output includes `#### Surface Candidates`, record each one directly:
```
vigil assess record-surface <type> <target> <source> [--rationale TEXT] [--status STATUS]
```

Use only the supported `record-surface` types: `account_recovery`, `api_documentation`,
`auth_entry`, `dynamic_render`, `file_handling`, `object_reference`, `privileged_write`,
`workflow_token`. Do not invent local taxonomy labels.

---

## 6. Output Format Requirements

Return structured output using these section headers when relevant to your role:

`#### Summary` · `#### Stats` · `#### Findings` · `#### Evidence`
`#### Surface Candidates` · `#### Intelligence` · `#### Recommended Next Actions`

Use `#### Decision` and `#### Action` for validation output (vulnerability-analyst).

Every `#### Findings` block must contain finding payloads ready for `vigil assess record-finding`,
not prose descriptions.

---

## 7. Rule Reminders

These are the most commonly violated rules — internalize them before you start:

- **No theoretical findings.** "Can an attacker do this right now with real harm?" — if no, not a finding yet.
- **Kill weak leads fast.** Theory without a real request, more than two fragile preconditions stacked, or "might be chainable" without a proved chain → kill it.
- **Severity follows proved impact.** Do not let recon hints, CVEs, or intuition inflate severity beyond what the evidence shows.
- **Named limit bypass is not automatically High.** For request caps, buffer limits, decompression limits, timeouts, and protocol negotiation limits, prove the limit is a security boundary and prove downstream second-order impact. If equivalent default transports already accept the same logical stream and downstream work is bounded and linear, downgrade to Medium/hardening or docs.
- **No speculative language.** Write `An attacker can [exact action] by [exact method]`, never `could potentially`, `may allow`, or `might be possible`.
- **No filler or padding.** Do not use `Furthermore`, `Additionally`, `It should be noted`, or similar filler transitions. Do not restate titles in descriptions. Do not define standard vulnerability classes to a security audience. Every sentence must contribute new information.
- **Severity by structured field, not shouting or slang.** Convey severity through the `severity` field and the CVSS vector plus calm, precise prose. Do not use ALL-CAPS for emphasis to signal criticality and do not use casual / "reddit" severity language ("this is insane", "game over", "pwned hard"). A critical finding reads as a measured, exact description of the attacker outcome — that is more credible to a triager than capitalized adjectives. (Literal CLI tokens, flags, and enum values written in caps — `REQUIRED`, `IDOR`, `--force` — are vocabulary, not emphasis, and are unaffected.)
- **Sibling rule.** When one route or method is vulnerable, inspect its siblings before moving on.
- **Credentials require proof.** Leaked tokens or keys only matter when you show what they actually grant.
- **Validate before writing.** Do not draft report content before the lead is reproducible and worth a human reader's time.
- **Evidence beats volume.** A few decisive requests and exact proofs outweigh broad noisy scanning.

Full rule sets: `agent/rules/hunting.md`, `agent/rules/reporting.md`, `agent/rules/adversarial-mindset.md`

---

## 8. OWASP Quick Reference

| Code | Category |
|------|----------|
| A01 | Broken Access Control |
| A02 | Cryptographic Failures |
| A03 | Injection |
| A04 | Insecure Design |
| A05 | Security Misconfiguration |
| A06 | Vulnerable and Outdated Components |
| A07 | Identification and Authentication Failures |
| A08 | Software and Data Integrity Failures |
| A09 | Security Logging and Monitoring Failures |
| A10 | Server-Side Request Forgery |

API security: `agent/references/api-security/`

---

## 9. Script Path Convention

All assessment operations use `vigil assess <subcommand>` from any directory. JSON payloads are
always in files, never inline shell arguments.

Use `ENGAGEMENT_DIR` or `--engagement-dir` for path resolution — hardcoded absolute paths break across environments.

---

## 10. Chain, Credential, and Coverage State

Record state immediately using `vigil assess` with JSON files:

- **Attack chains:** `vigil assess record-chain <agent-name> <chain-json-file>`
- **Credentials:** `vigil assess post credentials <credential-json-file>`
- **Credential tests:** `vigil assess post credential-tests <json-file>`
- **Access records:** `vigil assess post access-records <json-file>`
- **Coverage updates:** `vigil assess patch coverage-items/<id> <json-file>`
- **Blocked techniques:** `vigil assess block-technique --technique <TECHNIQUE> --target-kind <kind> --target-ref <ref> --reason <why>` (the technique-key auto-derives; override with `--technique-key`. Review with `vigil assess list-blocked-techniques`). Prefer this first-class verb over the raw `vigil assess post blocked-techniques <json-file>`.
- **Captured HTTP traffic:** `vigil assess http list --host <host> --method <verb> --content-type <family>` queries the canonical full-flow store (`vigil assess http show <flow_uid>` for one flow, `vigil assess http search <text>` for a LIKE query, `vigil assess http export-har -o <file>` / `vigil assess http import-har <file>` for HAR round-trips). Capture is a per-engagement policy, not a proxy selector — review it with `vigil assess http policy` and toggle raw-body capture with `vigil assess http policy set --enabled --capture-request-bodies` (raw-body capture is OFF by default).
- **Probe runs:** `vigil assess post probe-runs <json-file>`
- **Non-covering probe attempts:** `vigil assess record-attempt --result-status <attempted|blocked|no-signal|error> --attack-family <class> --lens <lens> --target-host <host> [--finding <slug>]` records a touched-but-inconclusive target (a lead, not a verdict) on the resume-brief Attempts ledger without counting as coverage. Covering `tested`/`signal` verdicts go through the normal probe pipeline with evidence, not here.

Write payloads to `/tmp/<type>-<slug>.json` before calling — inline JSON shell arguments cause escaping damage and are not auditable.

These follow the same backend-first principle as finding recording. Do not defer chain or credential
recording to the operator. The agent that proves the state writes it; the operator verifies it landed in
canonical backend state and avoids writing duplicate rows.

---

## 11. Kali Artifact Paths

Engagement artifacts live at one physical location on disk but have two names depending on where the command runs.

- **Host side** — `$DIR = $ROOT_DIR/engagements/<engagement_key>`. Launchers export this as `ENGAGEMENT_DIR`. Use `$DIR/...` (or `$ENGAGEMENT_DIR/...`) for local file work, `vigil assess` calls, and any script running on the host.
- **Kali side** — `/engagements/$ENGAGEMENT_KEY` is the same directory via the bind mount managed by `vigil runtime start`. Launchers also export `ENGAGEMENT_KEY` (the basename of `$DIR`) so commands inside the runtime can resolve it.
- **`vigil assess kali ...` invocations MUST reference paths as `/engagements/$ENGAGEMENT_KEY/...`** in their command argv — the host path `$DIR` is not valid inside the container, and writing to `/tmp` or `/data` for engagement-scoped artifacts loses them outside the shared-infra conventions.

---

## 11a. Script Execution Inside Kali

Custom scripts (Python helpers, exploit PoCs, payload builders) often need to
run inside the runtime container so they can hit target hosts through the same
network isolation envelope as the Kali tools. The path the operator references
when authoring or reviewing the script is different from the path the script
sees at execution time, and getting this wrong causes silent file-not-found
failures or runs the script against the wrong file system.

- **Authoring on the host** — write scripts under
  `$DIR/scripts/<name>.py` (host path) or `$ENGAGEMENT_DIR/scripts/<name>.py`.
  The host path is what the operator and reviewers see, what `vigil assess`
  recording references when capturing artifacts, and what shows up in commit
  diffs.
- **Executing inside Kali** — invoke the script through `vigil assess kali exec`
  using its container-side path
  `/engagements/$ENGAGEMENT_KEY/scripts/<name>.py`. The container sees the
  bind-mounted directory at `/engagements/<engagement_key>`, so the host-side
  `$DIR` prefix is invalid inside the runtime and a literal `$DIR` in the argv
  resolves to nothing.
- **Common pattern** — author at `$DIR/scripts/exploit.py`, then run
  `vigil assess kali exec --technique EXPLOIT --intent "..." --probe-kind exploit
  --phase exploit --timeout 600 -- python3
  /engagements/$ENGAGEMENT_KEY/scripts/exploit.py --target https://example`.
  The `--` separator forwards everything after it as raw argv to the in-container
  command, which is how arbitrary script invocations stay auditable through the
  same wrapper that records typed verbs.
- **Outputs land back on the host** — anything the script writes under
  `/engagements/$ENGAGEMENT_KEY/...` is visible from the host at the matching
  `$DIR/...` path, because both names point at the same bind-mounted directory.
  Engagement-scoped output should always live under that tree, not under
  `/tmp` or `/data` inside the container, so artifacts survive container
  restarts and remain attached to the engagement.

The dual-path naming exists because the container and the host share one
filesystem at one mount point — there is no second copy of the script to
sync. The two prefixes are aliases for the same bytes; using the wrong one
just means the lookup happens against a path that does not exist on that side.

---

## 12. Listener and OOB Callback Contract

Listeners (pwncat-vl) and tunnel exposure are operator-controlled (see §2a).
The dispatch context delivers reverse-shell callback targets through one
well-known file:

- `$DIR/.listener_url` — present when the operator has provisioned a reverse-shell listener / tunnel address. Read it to learn where shells should call back.

Agents READ `.listener_url` (never write it). When `.listener_url` is missing
and exploitation needs one, record a blocked technique via `vigil assess
block-technique` instead of attempting to bind a port yourself.

OOB callback domains are not engagement files. Get readiness and the configured
base domain from `vigil oob status --json` (expect `health=ok`); create or reuse a
named listener client with `vigil oob client start <name> --engagement <key>
--agent <agent>`; mint a nonce-tagged callback URL per payload with `vigil oob mint
--client <name>` (it binds the nonce under that client's interactsh id and prints
the exact host) and embed the **exact host it prints** in the payload — never
hand-build a bare `<nonce>.oob...` host, which would never reach `poll`; then
correlate each probe to its callback with `vigil oob poll --client <name>`. `vigil oob client logs <name> --lines 80` is a raw tail
of that client's listener log for infra debugging only — it does NOT correlate
nonces to probes, so never read it for hits. If OOB is unavailable, fall back to
time-based detection and note the substitution in your output.

Hit-checking is handled through the CLI surfaces that own those logs:
- OOB callback correlation / evidence: `vigil oob poll --client <name>` (matched probe<->callback pairs)
- OOB raw listener-log tail (infra debugging only, not correlation): `vigil oob client logs <name> --lines 80`
- OOB infrastructure debugging: `vigil logs oob --lines 80`
- Shell listener session output: `vigil runtime shell-exec "tail -80 /data/shell-<name>.log"`

Record the result in the relevant finding, probe-run, or handoff after reading
logs; the log command itself is infrastructure observation, while durable
engagement state still belongs in the backend.

---

## 13. Intel Recording Rules

When your output includes `#### Intelligence`, write each row as a structured JSON file matching the relevant `schemas/intel-*.schema.json` and record it via:

```
vigil assess record-intel <type> <json-file>
```

Valid `<type>` values: `tech-component`, `person`, `email`, `domain`, `cve`, `dns-record`, `social-profile`, `breach-record`, `org-fact`, `note`.

Run `vigil assess contract record-intel <type>` before authoring the JSON — intel schemas are strict (`additionalProperties=false`) and reject unknown fields.

The backend deduplicates per-engagement on natural keys: tech stack on Component (+ Version), people on Name, emails on Address, domains on Identity + Kind, CVEs on `cve_id`. Credentials live in the assessment domain (`assessment_credentials`); use `vigil assess post credentials`, not `record-intel`.

Prose intel that doesn't fit a structured row goes to `record-intel note` — it is FTS-indexed and engagement-scoped.

---

## 14. Per-Target Rate Calibration

Recon-class roles (recon-specialist, surface-collector, osint-analyst when
running active enumeration) load **`agent/references/recon/rate-calibration.md`**
on first use — that file owns the trait-row table (Cloud-fronted / Origin /
WAF-protected / High-friction / Vendor SaaS), the runtime-tier × DNS-profile
matrix, and the concurrent-nmap-procs cap. Tier-selection prose and the
step-down rules live in `agent/operator-core.md` "Recon Dispatch Resource
Policy"; the operator picks the trait row before dispatch and the specialist
applies it.

Non-recon roles (vulnerability-analyst, source-analyzer, fuzzer,
exploit-developer, report-writer) do not need rate-calibration values on every
dispatch — they consume per-call rate hints from the dispatch context, not
from this table. Loading the trait table on every specialist dispatch was a
token tax for roles that never used it; this pointer keeps shared-constraints
lighter for the 80% case while preserving direct linkage for the recon-class
roles that do.

---

## 15. File Organization

| Type | Directory |
|------|-----------|
| Downloaded pages/JS/CSS | downloads/ |
| Scan output | scans/ |
| Custom scripts/exploits | tools/ |
| Background PIDs | pids/ |

Root: `scope.json`, `report.md`, and the transient worker buffer only. Credentials, activity log, and intel live in the orchestrator backend — query via `vigil auth status`, `vigil assess fetch activity-entries`, and `vigil assess list-intel`.

---

## 16. Output Hygiene — Backend Is Canonical

The backend stores the canonical, queryable state of the engagement: findings in
the findings table (`vigil assess record-finding`), intel rows in `intel_*` tables
(`record-intel`), surface candidates in the surfaces table (`record-surface`),
credentials and attack chains in their tables, and the cross-cutting handoff
(summary / coverage gaps / next steps / runtime issues / working artifacts /
open questions / specialty extras) in `assessment_dispatch_handoffs`
(`vigil assess agent handoff --from-json <path>`).

The operator queries those tables through bounded primitives — `resume-brief`,
`render-handoff <agent-id>`, `artifact search/get`, `fetch findings`,
`list-intel`, `list-clusters` — to assemble the next dispatch's context. The
markdown response you return is your *reflection* on the work, not the canonical
record of it.

When the dispatch prompt includes a `resume-brief` block after Runtime Identity,
treat it as the compact operating picture. Use its finding, command-run, handoff,
and artifact IDs for drill-down; do not reconstruct state by reading unindexed
local notes first.

Write durable state to backend tables and linked artifacts immediately — hidden
markdown notes break resume, report readiness, and cross-agent handoff because
future agents cannot query or verify them. Any `.md` file under `notes/` that
matters after the current command must be registered with `vigil assess artifact
register <path> --finding <slug>` (or another entity link) before the dispatch
closes. Unlinked markdown notes are scratch only and are not valid resume or
report input — the operator can confirm a note is scratch with `vigil assess
artifact mark-scratch <path>` (single) or `--under <prefix>` (bulk). A
`check-phase-readiness --phase report` `unlinked_markdown_note` blocker names the exact fix
per row.

### Mandatory closing sequence (every specialist runs this before returning)

1. `vigil assess record-finding <agent-name> <finding-json>` per finding.
2. `vigil assess record-intel <type> <intel-json>` per intel row.
3. `vigil assess record-surface <type> <target> <source> [--rationale TEXT]` per surface candidate.
4. `vigil assess agent handoff --from-json <path>` — use the exact
   `agent_id`, `agent_role`, and `phase` values from the **Runtime Identity block**
   the operator placed at the top of your dispatch prompt. The handoff row is keyed
   on `agent_id`; using a different value creates an orphaned row the operator cannot render.
   Set `handoff_status` to `ready` when the operator can close the dispatch, or
   `blocked` when the objective could not complete.
5. `vigil assess agent render-handoff <agent_id>` — run after step 4 as a self-check.
   Exit only after the render succeeds. A 404 means the `agent_id` in step 4 did not
   match the registered dispatch.

`agent done` / `agent close` are operator-only — do not call them; the operator
marks the dispatch complete after your return so checkpointing stays separate
from lifecycle closure.

`agent handoff` is idempotent — call it as a checkpoint after each major step, not
only at the end. Schema: `agent/references/runtime-guides/handoff-schema.md` "Checkpointing".

On long runs, at each handoff checkpoint — and also whenever the working context
grows long mid-task, even between checkpoints — re-emit a compact plan-state
digest in your response — objective / done so far / still pending / immediate
next step (~3-5 lines) — so the objective does not drift to the bottom of a long
context. This is additive to the handoff write, not a separate ceremony.

### Reasoning quality > response brevity

Reason fully through the work as you go — narrate observations between tool
calls, work through hypotheses, summarize findings as you discover them. That's
how Claude reasons well, and red-team work depends on careful reasoning. Don't
truncate analysis to be brief.

The point of §16 is not "be terse"; it's "don't let the markdown response
*replace* the backend writes." Both can coexist: detailed reasoning in the
response, structured state in the backend.
