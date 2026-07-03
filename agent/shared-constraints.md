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
- `exploit_policy` value — `pause` (default) or `selected` require `exploit_review_state=approved`
  plus a non-empty `approved_targets` list, set once via `approve-exploit`, before exploitation
  proceeds (`pause` and `selected` are mechanically identical); `full_send` bypasses that review
  gate entirely
- Auth state from the engagement's backend credential store (`vigil auth status`) — use credentials only when a record is populated and marked active
  - Liveness is ground truth: a populated/active record is NOT proof the session is live — never trust cookie presence or the `stale` flag. There is NO auto-detection of where a site handles auth; to confirm with `vigil auth status --probe --probe-url <authed-endpoint>` you MUST first declare `material.liveness = {expect_status, authed_marker, dead_marker}` (via `vigil auth import`/`edit`). Pick an `authed_marker` that appears ONLY when logged in (the logged-in username, an account/settings link, a per-user CSRF token field) and a `dead_marker` from the login page — the same logged-in/logged-out markers a DAST scanner (InsightAppSec/Burp) uses to validate a session. No signature ⇒ liveness stays `unknown`.

`exploit_policy` governs *exploitation*, and it is resolved once **before** dispatch — not a
per-action approval you re-request mid-task. The invariants that hold regardless of its value: stay
within the in-scope hosts above, honor the program's ROE, and make no persistent or destructive
change to anything outside operator-owned infrastructure. §2d's human-reach preflight is the one
gate that survives every `exploit_policy` value and still applies per-action.

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
no dtach, and no watcher/poll loop. A specialist that backgrounds target
traffic and halts for a completion notification gets auto-resumed, launches the
next detached job, and halts again — unbounded relaunch thrash, duplicate
probes, near-zero net coverage. A generous `--timeout` is the correct tool for a
single long probe; on expiry the audit pipeline cascades SIGTERM→SIGKILL into
the in-container PID, so the call is killed cleanly and never orphaned. **Above
the CLI's own `--timeout` sits a separate agent-harness ceiling you do not
control**: a blocking call that runs too long is auto-backgrounded and the agent
is killed (**exit 144 / SIGUSR1**), orphaning the probe and writing no handoff. A
larger `--timeout` only widens that window — a single synchronous probe must fit
in minutes, not tens of minutes; genuinely long enumeration belongs in an
operator-owned supervised job.

**"Synchronous" means awaited-in-band, NOT one-call-at-a-time** — issuing several
blocking calls in parallel, each awaited in-band, is fine; the ban is on
detaching a job and reaping it later, not on concurrency. `vigil assess kali job
start` (the dtach-supervised worker that survives shell exit) is **operator-only**
— a single long sweep the operator launches and monitors, never a per-step or
fan-out pattern in a specialist loop. A specialist that needs a probe to outlive
its dispatch says so in its handoff and lets the operator own the job.

Full sync-vs-async decision, the mode table, and the SIGUSR1 rationale:
`agent/skills/kali-exec/SKILL.md` "Synchronous vs. async decision".

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

Never signal shared-runtime processes by binary name (`pkill -f nmap`,
`killall nuclei`) — a broad selector kills sibling specialists' parallel scans
in the shared runtime, losing hours of recon. Synchronous `--timeout` expiry
already cascades SIGTERM→SIGKILL into the in-container PID, so manual cleanup is
rarely needed; operator jobs stop with `vigil assess kali job stop <id>`. When
you must clean up mid-run, use the **PID selector**, not the binary name: every
audit row carries a `run_uuid` and the runtime writes its in-container PID to
`/tmp/vigil-pid-<run_uuid>`, so `kill -TERM "$(cat /tmp/vigil-pid-<run_uuid>)"`
signals only your run. Full rationale: `agent/skills/kali-exec/SKILL.md`
"Process cleanup discipline".

### Command Metadata

Every target-facing `vigil assess kali` call carries audit metadata as required CLI flags; the
CLI fails closed when they're missing rather than degrading to a stale env-var default. The
required set is `--technique`, `--intent`, `--probe-kind`, `--phase`, and `--timeout`, plus
`--destructive` when the command writes/edits/deletes target state and `--force` to suppress the
dedup-warning log on an intentional retry (a fresh audit row is written regardless;
`superseded_by_id` links it to the predecessor).

Two judgment points that the mechanical layers can't give you: derive `--technique` from the
skill you loaded (`ssrf-testing` → `SSRF`, `sqli-testing` → `SQLI`; `HEALTH` for runtime/tool
inventory), and pass `--phase` for the phase the **dispatch was authorized for**, NOT
`scope.json.current_phase` — engagements routinely operate between phases.

Full flag-by-flag purpose, the enum values for `--technique`/`--probe-kind`/`--phase`, and the
`--engagement-key`/`--agent-name` resolution order live in
`agent/skills/kali-exec/SKILL.md` ("Audit-flag mapping", "Phase tags") and are generated per-verb
by `vigil assess contract kali <verb>` / `vigil assess list-commands`. Dispatch wrappers must
export `AGENT_NAME=<role>` or pass `--agent-name <role>` — a silent `operator` attribution breaks
coverage ownership.

---

## 2d. Side-Effect Preflight

Before sending a request that could **create persistent state or reach a human** —
signup, request-access, support/report/ticket, password-reset, contact-form, or any
endpoint whose name or path suggests a write that notifies someone — run this
procedure.

**Posture: capped live-fire, not zero-fire.** Static characterization (Step 1) is unlimited;
genuine ambiguity gets a small, hard, audited live-fire budget (Step 3), gated by a durable
recorded decision — a bounded loosening, not routine live-fire license. Read the whole
procedure, including the cross-dispatch rule, before relying on the budget.

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
`update-finding` guessing a nonexistent `--details-patch` flag instead of
the real `--details-inline`/`--details-replace`, `kali katana -H`, `kali exec
--probe-kind active`) would each have been prevented by running
`contract` before the first call.

---

## 2a. Listener, Tunnel, and OOB Responsibility

Starting, stopping, restarting, or reconfiguring shared listener, tunnel, and OOB server
processes belongs to the **operator** — these are global runtime state whose disruption breaks
other concurrent specialists: pwncat-vl listeners, frp tunnels, chisel listeners, `nc -lvp`,
`socat` listeners, `frpc`, `oob-server`, interactsh servers, or equivalent.

Agent-side OOB readiness checks, named per-agent clients, and the mint→poll→correlate
procedure are canonical in `agent/references/offensive-tactics/frp-tunneling.md`
("Agent OOB Readiness Check" and "OOB Procedure (mint→poll→correlate)") — read those
sections there; do not re-derive the workflow here.

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

**Complete both reads before target-facing work begins, and only improvise after confirming
the set is genuinely insufficient.** References are not a fallback: improvising a technique that
already exists wastes tokens, produces inconsistent results, and misses encoded methodology
(mitmproxy setup, payload libraries, tool flags). A skill's "Extended Resources" list is required
reading for that test class, not optional. The `references/` library contains:
- `payloads/` — 20 copy-pasteable attack payload files per bug class
- `api-security/` — OWASP API Security Top 10:2023 checklists
- `offensive-tactics/` — red team TTPs by kill-chain phase
- `tools/` — CLI tool cheatsheets (nmap, ffuf, sqlmap, hydra, etc.)

---

## 4. Finding IDs and Recording

**MANDATORY: Every finding MUST be recorded via `vigil assess record-finding`.** Never hand-allocate
finding IDs. Never write findings only to markdown. Never skip the recording step. If you
produce a finding in any output section, you MUST also call `vigil assess record-finding` before your
task is complete. Findings that exist only in your output text and were not recorded via the
script are considered lost data.

Finding-ID prefix table, title formula, and the CVSS↔severity band table are canonical in
`agent/shared-constraints-core.md` "Finding IDs and the `record-finding` Contract" — read it
there, do not re-derive it here.

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
set chain metadata in `details` during `record-finding` (as part of the finding JSON payload), or on
an already-recorded finding via `vigil assess update-finding <slug> --details-inline '{"chain_required": true, "chain_rationale": "...", "required_followup": ["..."]}'`:
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

**Failure to use `vigil assess record-finding` is the single most common subagent defect.** Every
payload in a `#### Findings` block must have been recorded during your session — do not defer
recording to the operator.

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

These are the most commonly violated rules — internalize them before you start. Bullets already
covered in full in co-loaded `hunting.md`/`reporting.md` (no theoretical findings, kill weak leads
fast, speculative language, filler/padding, the sibling rule, credentials require proof, validate
before writing, evidence beats volume) are not restated here — see those files.

- **Severity by structured field, not shouting or slang.** Convey severity through the `severity` field and the CVSS vector plus calm, precise prose. Do not use ALL-CAPS for emphasis to signal criticality and do not use casual / "reddit" severity language ("this is insane", "game over", "pwned hard"). A critical finding reads as a measured, exact description of the attacker outcome — that is more credible to a triager than capitalized adjectives. (Literal CLI tokens, flags, and enum values written in caps — `REQUIRED`, `IDOR`, `--force` — are vocabulary, not emphasis, and are unaffected.)
- **Precondition analysis governs severity** (essence; full table in `reporting.md` §3). Before
  assigning severity, ask what the attacker needs to already have — every precondition not freely
  available to an anonymous internet attacker reduces severity, and stacking enough of them turns
  an impressive bug into low-impact. Defense-in-depth: if exploiting the finding requires already
  possessing the secret or credential it bypasses, rate the bypass relative to how hard that
  precondition is to satisfy independently, not as a standalone critical. Reduces severity: an
  authenticated session, a non-iterable identifier (UUID/GUID/token) the attacker can't enumerate,
  a second vulnerability supplying the input, source/CI access to extract a secret,
  attacker-controlled infrastructure, dev/staging-only reproduction. Does NOT reduce severity: an
  iterable integer ID, a free self-registration account, or a single crafted request with no prior
  knowledge.

Full rule sets: `agent/rules/hunting.md`, `agent/rules/reporting.md`, `agent/rules/adversarial-mindset.md`

---

## 8. OWASP Quick Reference

The OWASP Top 10:2021 category-code lookup is reference material, not a per-dispatch
constraint — it lives in `agent/references/owasp-quick-reference.md` (load on demand when
mapping a finding to a category). API-specific checklists: `agent/references/api-security/`.

---

## 9. Script Path Convention

Canonical in `agent/shared-constraints-core.md` "Script Path Convention" — `vigil assess
<subcommand>` from any directory, JSON payloads always in files. Read it there, do not
re-derive it here.

**Engagement resolution (no per-command `export ENGAGEMENT_DIR`).** `vigil assess`
resolves the target engagement in one shared resolver with this precedence
(highest → lowest): (1) `--engagement-dir <path>` flag; (2) **CWD walk-up** to the
nearest ancestor holding `scope.json` ("the tree I'm in" — concurrency-safe);
(3) the **persisted active pointer** set by `vigil use <key>` (mirrored at
`<engagements_root>/.active`); (4) `$ENGAGEMENT_DIR` (legacy / launcher-seeded
fallback); (5) hard error — never a silent most-recent auto-pick. Set the active
engagement **once** with `vigil use <key>` (or just work from inside the engagement
dir); every later `vigil assess` command targets it, from any cwd, across fresh
shells. `vigil engagement current` reports the resolved engagement and the winning
tier. A stale inherited `$ENGAGEMENT_DIR` can no longer silently beat your working
directory: cwd walk-up and the active pointer both out-rank it, and the resolver
warns on stderr when `$ENGAGEMENT_DIR` disagrees with the resolved engagement.

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

- **Host side** — `$DIR = $ROOT_DIR/engagements/<engagement_key>`. Launchers export this as `ENGAGEMENT_DIR`, but it is only the lowest-priority resolver fallback: `vigil assess` prefers a cwd walk-up to `scope.json` and the `vigil use` active pointer over `$ENGAGEMENT_DIR` (see "Script Path Convention" above). Use `$DIR/...` (or `$ENGAGEMENT_DIR/...`) for local file work and any script running on the host. Switching the active engagement is a **host-side concern only** — the shared mitmproxy (routes each flow by target host) and the Kali runtime (per-command working dir) are engagement-agnostic, do not read `ENGAGEMENT_DIR`, and need no restart when you switch.
- **Kali side** — `/engagements/$ENGAGEMENT_KEY` is the same directory via the bind mount managed by `vigil runtime start`. Launchers also export `ENGAGEMENT_KEY` (the basename of `$DIR`) so commands inside the runtime can resolve it.
- **`vigil assess kali ...` invocations MUST reference paths as `/engagements/$ENGAGEMENT_KEY/...`** in their command argv — the host path `$DIR` is not valid inside the container, and writing to `/tmp` or `/data` for engagement-scoped artifacts loses them outside the shared-infra conventions.

---

## 11a. Script Execution Inside Kali

Custom scripts (Python helpers, exploit PoCs, payload builders) run inside the
runtime container so they hit target hosts through the same isolation envelope as
the Kali tools. Host and container name the same bind-mounted bytes differently —
getting the prefix wrong causes silent file-not-found failures.

- **Author on the host** at `$DIR/scripts/<name>.py` (or
  `$ENGAGEMENT_DIR/scripts/<name>.py`) — the path the operator, reviewers, `vigil
  assess` artifact recording, and commit diffs see.
- **Execute inside Kali** via `vigil assess kali exec ... -- python3
  /engagements/$ENGAGEMENT_KEY/scripts/<name>.py ...`. The container sees the mount
  at `/engagements/<engagement_key>`, so a literal `$DIR` in the argv resolves to
  nothing. The `--` separator forwards everything after it as raw argv, keeping the
  invocation auditable through the same wrapper that records typed verbs.
- **Outputs land back on the host** — anything the script writes under
  `/engagements/$ENGAGEMENT_KEY/...` appears at the matching `$DIR/...` path.
  Keep engagement-scoped output under that tree, never `/tmp` or `/data` inside the
  container, so artifacts survive restarts and stay attached to the engagement.

A worked example lives in `agent/skills/kali-exec/SKILL.md` "Run a custom Python
helper inside the runtime".

---

## 12. Listener and OOB Callback Contract

Listeners (pwncat-vl) and tunnel exposure are operator-controlled (see §2a).
The dispatch context delivers reverse-shell callback targets through one
well-known file:

- `$DIR/.listener_url` — present when the operator has provisioned a reverse-shell listener / tunnel address. Read it to learn where shells should call back.

Agents READ `.listener_url` (never write it). When `.listener_url` is missing
and exploitation needs one, record a blocked technique via `vigil assess
block-technique` instead of attempting to bind a port yourself.

OOB callback domains are not engagement files. The mint→poll→correlate workflow — readiness,
named clients, minting the callback host, and correlating hits — is canonical in
`agent/references/offensive-tactics/frp-tunneling.md` ("OOB Procedure (mint→poll→correlate)");
do not re-derive it here. Shell listener session output is a separate surface: `vigil runtime
shell-exec "tail -80 /data/shell-<name>.log"`.

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

## 16. Mandatory Closing Sequence

> **Specialist context isolation, finding-recording format, closing-sequence wrapper, and output hygiene:** see agent/shared-constraints-core.md (in your Load First). This role adds only its own closing verbs below.

Every specialist runs this before returning:

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
