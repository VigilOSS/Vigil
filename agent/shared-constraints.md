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
- Auth state from `auth.json` — use credentials only when the file is populated and marked active

Do not test hosts not listed in scope. Do not exceed the exploit policy without operator approval.

---

## 2. `aith assess kali` for All Target Work

All target-facing work — HTTP probing, scanning, crawling, fuzzing, exploitation,
OOB/DNS callbacks, and raw TCP — must go through `aith assess kali ...` subcommands.
The CLI runs on the host, executes inside the runtime container, and records the
audit row directly to the orchestrator backend. Use it because the CLI owns the
audit pipeline — host-side probes against scoped targets break the runtime's
network isolation and skip the audit row that operators and downstream specialists
rely on as a coverage map.

Discovery (in order):

1. Read `agent/skills/kali-exec/SKILL.md` for the verb menu, methodology profiles,
   sync-vs-async decision, audit-flag mapping, and example invocations per verb.
2. Use `aith assess kali --help` and `aith assess kali <verb> --help` for the live
   flag set and defaults on a verb you're about to invoke.
3. Use `aith assess contract kali <verb>` for the canonical schema, helper
   defaults, common mistakes, and an example payload.

Forbidden because they bypass the audit pipeline: host Bash that runs probes
against scoped targets, `docker run` / `docker exec` against the runtime, and
ad-hoc curl/nmap/sqlmap/etc. from the host. The host boundary is for
orchestration, not target traffic.

Long-running probes (nmap+scripts, sqlmap, nuclei sweep, dirb, gobuster, ffuf
large wordlists) MUST use `aith assess kali job start ...` because synchronous
calls have a wall-clock budget and will be killed cleanly on timeout. The job
worker is SQLite-backed and dtach-supervised, so it survives across calling-shell
exit; synchronous calls do not.

Host-side commands are limited to coordination and non-target support only:
`jq`, `sqlite3`, `python3`, `grep` / `rg`, `sed`, `awk`, `base64`, `openssl`,
plus `aith assess` helpers for backend state writes.

If a required target-facing tool is missing from the runtime image, rebuild the
image rather than falling back to host or Docker-side execution paths — the
runtime image is the single source of truth for the tool surface.

**Do not `echo` as commentary, section headers, or breadcrumbs inside
`aith assess kali` commands.** Stdout is captured to the audit log, not shown to
the user, and commentary-echoes bloat the preview and pollute FTS search without
adding retrievable signal. Use `--intent` for a one-line purpose annotation.
`echo` is only legitimate when its output is the command's real purpose — writing
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
selector (`kill -TERM "$(cat /tmp/aith-pid-<run_uuid>)"`).

What to do instead — track the lifecycle of every process you spawn and stop
only the one you started:

- **Long-running probes — use the job lifecycle.** `aith assess kali job
  start --technique <enum> --intent "<text>" --probe-kind <kind> --phase
  <phase> --timeout <seconds> -- <verb> ...` returns a job id and writes
  an audit row. Stop it cleanly with `aith assess kali job stop <id>`.
  The job worker SIGTERMs the in-container PID it owns; sibling jobs stay
  alive.
- **Synchronous `aith assess kali exec` runs — use the run-uuid PID file.**
  Every audit row carries a `run_uuid`. The runtime writes the
  in-container PID to `/tmp/aith-pid-<run_uuid>` for the duration of the
  run, so cleanup is `aith assess kali exec --technique META --intent
  "terminate tracked runtime pid" --probe-kind cleanup --phase <phase>
  --timeout 30 -- sh -c 'kill -TERM "$(cat
  /tmp/aith-pid-<run_uuid>.pid)"'`. This signals only your run, not sibling
  runs of the same binary.
- **Last-resort hygiene for hours-long parallel runs — copy the binary
  per agent.** `aith assess kali exec --technique META --intent
  "create per-agent nmap copy" --probe-kind cleanup --phase <phase>
  --timeout 30 -- cp /usr/bin/nmap /usr/local/bin/nmap-${AGENT_NAME}` so a later `pkill -f
  nmap-${AGENT_NAME}` only matches your processes. Prefer the job
  lifecycle; reach for this only when two specialists genuinely need
  multi-hour parallel sweeps of the same heavy binary.
- **Timeout-related cleanup is automatic.** `aith assess kali exec` and
  every typed verb cascade SIGTERM→SIGKILL into the in-container PID via
  `docker exec ... kill` when `--timeout` expires. Operators do not need
  to kill anything manually for a timeout — the in-container tree is
  already gone.

### Command Metadata

Every target-facing `aith assess kali` call carries audit metadata as CLI flags.
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
  the timeout cleanly; longer budgets must use `aith assess kali job start`.
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
`--agent-name` resolves from the explicit flag, `$AGENT_NAME`, `$AITH_AGENT_NAME`,
then `operator`. Specialist dispatch wrappers must export `AGENT_NAME=<role>`;
if that context is missing, pass `--agent-name <role>` explicitly because a
silent `operator` attribution breaks coverage ownership.

---

## Contract-First Rule

Before the **first invocation of any `aith assess` verb that mutates durable
state, dispatches a kali tool, or seats work-buffer rows**, run
`aith assess contract <verb>` (or `aith assess contract <verb> <variant>`)
to read the canonical schema, the required fields, the common mistakes, and
the example payload. Schema validation errors from guessing waste a full
round-trip, so reading the contract first is faster than re-running the
verb after a rejection.

Verbs covered by the rule (all have a contract entry; `aith assess contract`
emits the canonical schema and an example):

- `kali <verb>` — `aith assess contract kali <verb>`
- `record-finding` — `aith assess contract record-finding`
- `record-intel <type>` — `aith assess contract record-intel <type>`
- `record-surface` — `aith assess contract record-surface`
- `agent <subverb>` for sub-verbs that mutate durable dispatch state or
  emit the canonical handoff blob:
  `start`, `done`, `handoff`, `decision`,
  `abort-duplicate`, `render-handoff` — `aith assess contract agent <subverb>`
- Lifecycle helpers (`verify-finding`, `kill-finding`, `update-finding`,
  `reset-finding`, `resolve-surface`) — `aith assess contract <verb>`

Verbs **not** covered (skip the contract round-trip — they are read-only or
have no payload to validate): `fetch`, `list-skills`, `list-clusters`,
`list-command-runs`, `get-command-run`, `check-scope-coverage`,
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

Agents do their own readiness and evidence checks through `aith`:
1. Inspect shared OOB state with `aith oob status --json` before blind payload work.
   `server=true` and `frpc=true` means shared OOB infrastructure is ready.
2. Inspect infrastructure logs with `aith logs oob --lines 80` when status is
   partial, callbacks are missing, or FRP/auth health is unclear.
3. Start, list, read, and stop named per-agent clients with `aith oob client
   start|list|logs|stop`. Per-agent interactsh clients are correlation handles,
   not shared tunnel infrastructure, so specialists can manage them directly.
4. Check correlated callback hits with `aith oob client logs <name> --lines 80`.
   Use `aith logs oob --lines 80` only for raw server/FRP debugging.

When exploitation requires a reverse-shell listener or tunnel exposure:
1. Provide the exact listener or tunnel commands in your output using `# MANUAL:`
   annotation, because the operator owns shared listener processes.
2. Reference `agent/references/offensive-tactics/shell-handling.md` for shell
   listener commands.
3. Reference `agent/references/offensive-tactics/frp-tunneling.md` for OOB
   readiness, per-agent clients, tunnel exposure, and log interpretation.
4. Proceed after the listener URL file or `aith oob` client is available; do not
   block on the operator for checks that `aith oob status`, `aith logs oob`, or
   `aith oob client logs` can answer directly.

Starting, stopping, or restarting shared listener, tunnel, and OOB server processes
belongs to the operator — these are global runtime state whose disruption breaks
other concurrent specialists: pwncat-vl listeners, frp tunnels, chisel listeners,
`nc -lvp`, `socat` listeners, `frpc`, `oob-server`, interactsh servers, or
equivalent network listener processes.

---

## 2b. Coverage Check Before Probing

Every `aith assess kali` call records its command, argv, tool, agent, phase,
technique, intent, probe_kind, destructive flag, exit code, timeout state,
timings, and an output preview (or artifact ref) to the orchestrator backend.
Treat that history as a **coverage map** — a record of what's already been
probed so your next probe goes somewhere the engagement hasn't covered yet.

Before issuing a probing, scanning, fuzzing, or credential-testing command,
search for prior work on this surface:

```bash
aith assess list-command-runs --q <keyword>
```

Default to an unscoped search so you see every agent's and every phase's
prior work on the target; narrow with `--agent-name` or `--phase` only if the
broad result is overwhelming. Cross-agent and cross-phase context is usually
the most valuable coverage signal.

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
output — but first fetch the preview with `aith assess get-command-run <id>`
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
`aith assess list-skills` (compact name + one-line "Use when:") and includes the path(s) in the
dispatch prompt. Read each named `agent/skills/<name>/SKILL.md` in full before doing anything else.
If no skill was named and you believe one exists, run `aith assess list-skills` to discover it
yourself and report back rather than improvising — skill selection is the operator's job, but
discovery is fast (~200 tokens) and usually faster than guessing.

**Step 2 — Read `agent/references/INDEX.md`** after loading the skill. Identify the paired
payload files, tool cheatsheets, and OWASP checklists that apply to your task and load them.

**Do not begin target-facing work until both reads are complete.** Improvising a technique that
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

**MANDATORY: Every finding MUST be recorded via `aith assess record-finding`.** Never hand-allocate
finding IDs. Never write findings only to markdown. Never skip the recording step. If you
produce a finding in any output section, you MUST also call `aith assess record-finding` before your
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

**Deduplication:** Before recording, query existing findings via `aith assess fetch findings`. If the same root cause on the same endpoint already exists, update the existing finding rather than creating a new one. Same vulnerability class across multiple parameter values of the same endpoint is one finding, not one per value.

Record every finding with:
```
aith assess record-finding <agent-name> <finding-json-file>
```

The JSON payload must match `schemas/finding-record.schema.json`.
Do not produce markdown findings — convert to JSON before recording.
If you need the canonical field list or examples, run `aith assess contract record-finding`.
Do not invent lifecycle fields from memory — `record-finding` fills the initial finding lifecycle defaults.

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

**The `notes` field must contain replayable commands** — not prose descriptions. Instead of
"Login to phpMyAdmin with blank password," write the actual command: curl with headers, cookies,
and POST body; sqlmap with exact flags; ysoserial with gadget chain and target; or whatever tool
proved the finding. The field allows up to 20 KB. If the operator or another agent needs to
reproduce the finding later, the notes field alone should be sufficient without re-discovering
the request format, session tokens, or tool parameters.

**Failure to use `aith assess record-finding` is the single most common subagent defect.** If you
produce `#### Findings` output, each finding payload in that section must have been recorded
via `aith assess record-finding` during your session. Do not defer recording to the operator.

---

## 5. Surface Candidates

When your output includes `#### Surface Candidates`, record each one directly:
```
aith assess record-surface <type> <target> <source> [--rationale TEXT] [--status STATUS]
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

Every `#### Findings` block must contain finding payloads ready for `aith assess record-finding`,
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

All assessment operations use `aith assess <subcommand>` resolved from the agent workspace
root after `cd agent`. JSON payloads are always in files, never inline shell arguments.

Do not hardcode absolute paths. Set `ENGAGEMENT_DIR` before calling aith assess, or pass `--engagement-dir`.

---

## 10. Chain, Credential, and Coverage State

Record state immediately using `aith assess` with JSON files:

- **Attack chains:** `aith assess record-chain <agent-name> <chain-json-file>`
- **Credentials:** `aith assess post credentials <credential-json-file>`
- **Credential tests:** `aith assess post credential-tests <json-file>`
- **Access records:** `aith assess post access-records <json-file>`
- **Coverage updates:** `aith assess patch coverage-items/<id> <json-file>`
- **Blocked techniques:** `aith assess post blocked-techniques <json-file>`
- **Probe runs:** `aith assess post probe-runs <json-file>`

Write payloads to `/tmp/<type>-<slug>.json` before calling — inline JSON shell arguments cause escaping damage and are not auditable.

These follow the same backend-first principle as finding recording. Do not defer chain or credential
recording to the operator. The agent that proves the state writes it; the operator verifies it landed in
canonical backend state and avoids writing duplicate rows.

---

## 11. Kali Artifact Paths

Engagement artifacts live at one physical location on disk but have two names depending on where the command runs.

- **Host side** — `$DIR = $ROOT_DIR/engagements/<engagement_key>`. Launchers export this as `ENGAGEMENT_DIR`. Use `$DIR/...` (or `$ENGAGEMENT_DIR/...`) for local file work, `aith assess` calls, and any script running on the host.
- **Kali side** — `/engagements/$ENGAGEMENT_KEY` is the same directory via the bind mount managed by `aith runtime start`. Launchers also export `ENGAGEMENT_KEY` (the basename of `$DIR`) so commands inside the runtime can resolve it.
- **`aith assess kali ...` invocations MUST reference paths as `/engagements/$ENGAGEMENT_KEY/...`** in their command argv — the host path `$DIR` is not valid inside the container, and writing to `/tmp` or `/data` for engagement-scoped artifacts loses them outside the shared-infra conventions.

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
  The host path is what the operator and reviewers see, what `aith assess`
  recording references when capturing artifacts, and what shows up in commit
  diffs.
- **Executing inside Kali** — invoke the script through `aith assess kali exec`
  using its container-side path
  `/engagements/$ENGAGEMENT_KEY/scripts/<name>.py`. The container sees the
  bind-mounted directory at `/engagements/<engagement_key>`, so the host-side
  `$DIR` prefix is invalid inside the runtime and a literal `$DIR` in the argv
  resolves to nothing.
- **Common pattern** — author at `$DIR/scripts/exploit.py`, then run
  `aith assess kali exec --technique EXPLOIT --intent "..." --probe-kind exploit
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
and exploitation needs one, record a blocked technique via `aith assess post
blocked-techniques <json-file>` instead of attempting to bind a port yourself.

OOB callback domains are not engagement files. Get readiness and the configured
base domain from `aith oob status --json`; create or reuse a named correlation
client with `aith oob client start <name> --engagement <key> --agent <agent>`;
read the unique callback URL and hits with `aith oob client logs <name> --lines
80`. If OOB is unavailable, fall back to time-based detection and note the
substitution in your output.

Hit-checking is handled through the CLI surfaces that own those logs:
- OOB client evidence: `aith oob client logs <name> --lines 80`
- OOB infrastructure debugging: `aith logs oob --lines 80`
- Shell listener session output: `aith runtime shell-exec "tail -80 /data/shell-<name>.log"`

Record the result in the relevant finding, probe-run, or handoff after reading
logs; the log command itself is infrastructure observation, while durable
engagement state still belongs in the backend.

---

## 13. Intel Recording Rules

When your output includes `#### Intelligence`, write each row as a structured JSON file matching the relevant `schemas/intel-*.schema.json` and record it via:

```
aith assess record-intel <type> <json-file>
```

Valid `<type>` values: `tech-component`, `person`, `email`, `domain`, `cve`, `dns-record`, `social-profile`, `breach-record`, `org-fact`, `note`.

Run `aith assess contract record-intel <type>` before authoring the JSON — intel schemas are strict (`additionalProperties=false`) and reject unknown fields.

The backend deduplicates per-engagement on natural keys: tech stack on Component (+ Version), people on Name, emails on Address, domains on Identity + Kind, CVEs on `cve_id`. Credentials live in the assessment domain (`assessment_credentials`); use `aith assess post credentials`, not `record-intel`.

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

Root: `scope.json`, `report.md`, `auth.json`, and the transient worker buffer only. Activity log and intel live in the orchestrator backend — query via `aith assess fetch activity-entries` and `aith assess list-intel`.

---

## 16. Output Hygiene — Backend Is Canonical

The backend stores the canonical, queryable state of the engagement: findings in
the findings table (`aith assess record-finding`), intel rows in `intel_*` tables
(`record-intel`), surface candidates in the surfaces table (`record-surface`),
credentials and attack chains in their tables, and the cross-cutting handoff
(summary / coverage gaps / next steps / runtime issues / working artifacts /
open questions / specialty extras) in `assessment_dispatch_handoffs`
(`aith assess agent handoff --from-json <path>`).

The operator queries those tables directly — `render-handoff <agent-id>`, `fetch
findings`, `list-intel`, `list-clusters` — to assemble the next dispatch's
context. The markdown response you return is your *reflection* on the work, not
the canonical record of it.

### Mandatory closing sequence (every specialist runs this before returning)

1. `aith assess record-finding <agent-name> <finding-json>` per finding.
2. `aith assess record-intel <type> <intel-json>` per intel row.
3. `aith assess record-surface <type> <target> <source> [--rationale TEXT]` per surface candidate.
4. `aith assess agent handoff --from-json <path>` — use the exact
   `agent_id`, `agent_role`, and `phase` values from the **Runtime Identity block**
   the operator placed at the top of your dispatch prompt. The handoff row is keyed
   on `agent_id`; using a different value creates an orphaned row the operator cannot render.
5. `aith assess agent render-handoff <agent_id>` — run after step 4 as a self-check.
   Exit only after the render succeeds. A 404 means the `agent_id` in step 4 did not
   match the registered dispatch.

`agent done` is operator-only — do not call it; the operator marks the dispatch
complete after your return.

`agent handoff` is idempotent — call it as a checkpoint after each major step, not
only at the end. Schema: `agent/references/runtime-guides/handoff-schema.md` "Checkpointing".

### Reasoning quality > response brevity

Reason fully through the work as you go — narrate observations between tool
calls, work through hypotheses, summarize findings as you discover them. That's
how Claude reasons well, and red-team work depends on careful reasoning. Don't
truncate analysis to be brief.

The point of §16 is not "be terse"; it's "don't let the markdown response
*replace* the backend writes." Both can coexist: detailed reasoning in the
response, structured state in the backend.
