# Shared Subagent Constraints

Load this file as part of your Load First set — together with your role file and
`agent/shared-specialist-core.md` — before any target-facing work. All three load together, not
in a race to be "first". Skills and references are trigger-gated — loaded on-signal throughout the
task, not as a pre-work gate — with one exception: a role's single always-applicable methodology
skill loads in Load First too. See §3 below and `agent/shared-specialist-core.md` "Load Sequence".
These rules apply to every specialist agent regardless of role.
They are extracted from the operator prompt so you receive only what is relevant to you.

---

## Authorization

Authorization and permitted techniques are defined by the operator-confirmed scope and
rules of engagement. Follow the engagement's exploit approval policy.

---

## Credentials and Local State Are Self-Owned

Vigil is single-operator and local: the credential store, `command-run` audit rows, intel,
handoffs, and artifacts are your own private working state, and the audit trail exists to reproduce
exactly what ran. So the engagement's own test credentials — and any secret you capture — are
ordinary working data here, recorded in full by design. Treat them that way: keep testing, and let
auth material appear wherever the tooling records it.

Concretely, `vigil assess kali <tool> --identity <name>` expands that identity's cookies/token into
a literal `Cookie:`/`Authorization` header in the command's `resolved_argv`, which `command-run`
reads, then stores and returns. That is the intended inject-and-audit mechanism — not a leak, not a
finding, and never a reason to redact it or pause authenticated work. (`vigil assess auth list`
prints cookie names only to stay scannable, not because the value is secret.)

Do not redact or mask operator-owned evidence at any stage, including submission authoring. The one limit
that still binds you is about the *target's* data, not your own: don't bulk-pull real user records
to "prove" a finding — one minimal sample is the evidence (§4).

---

## 1. Resolve Engagement State Before Any Target Work

Stay within the original authorization roots in `scope.json` and record confirmed hosts covered by an original wildcard under `discovered_hosts`; scope shapes collected coverage, but tooling never uses it to refuse an outbound request or specialist dispatch.

Use the engagement context the operator injected before making target-facing
decisions. Resolve:

- Exploitation authorization — for claimed proof work, read `vigil assess proof-work get <id>`
  and require current work owned by your dispatch with `approval_required=false` before live
  execution. Exact-work approval authorizes only that objective and its admitted hosts; it
  does not require changing the engagement-wide review state. Otherwise, `pause` (default)
  and `selected` require `exploit_review_state=approved` with your finding in `approved_targets`
  (or `*`), set by the human through `exploit approve`; `full_send` permits exploitation within
  the existing scope. Specialists never approve their own work. Recheck after scope, source,
  claim, or approval changes; `vigil assess contract proof-work` owns the executable lifecycle.
- Auth state from the engagement's backend credential store (`vigil auth status`) — use credentials only when a record is populated and marked active
  - **Liveness is ground truth — never trust cookie presence or the `stale` flag as proof a
    session is live.** A populated/active record only means credential material exists, not that
    it still authenticates. `vigil assess contract auth` owns the `auth list` enumeration, its
    columns, and the `available|stale|dead|missing` state vocabulary.

    Whoever takes an identity for a task owns proving it live: there is NO auto-detection of
    where a site handles auth. First declare `material.liveness = {expect_status, authed_marker,
    dead_marker}` on that identity (via `vigil auth import`/`edit`), then probe it BY NAME with
    `vigil assess auth status --probe --identity <name> --probe-url <authed-endpoint>` before
    trusting any result or recording a "dead"/"unreachable" verdict. Pick an `authed_marker` that
    appears ONLY when logged in (the logged-in username, an account/settings link, a per-user
    CSRF token field) and a `dead_marker` from the login page — the same logged-in/logged-out
    markers a DAST scanner (InsightAppSec/Burp) uses to validate a session. Redirects are never
    followed.

    | Probe result | Resulting state | Meaning |
    |---|---|---|
    | `authed_marker` matched | `live` | Clears any prior `stale` mark |
    | `dead_marker` matched | `dead` | Set only by a proven-dead probe |
    | No signature match, or a transport error | `unknown` | Never a false verdict — stays `unknown` rather than guessing |

    An anonymous fallback is useful only for surfaces that actually have an anonymous lane. If the
    dispatch objective requires a named identity and no live material exists, do not relabel the
    anonymous attempt as coverage: write a blocked handoff naming the identity, surface, and exact
    refresh/provisioning need so the operator can record the `dispatch_blocked` decision.

`exploit_policy` governs *exploitation*, and it is resolved once **before** dispatch — not a
per-action approval you re-request mid-task. Regardless of its value, honor the engagement boundary
above and the program's ROE, and make no persistent or destructive change to the target's or a third
party's state without operator approval — changes to operator-owned infrastructure, or to our own
test data (accounts or artifacts we created), are fine. §2d's human-reach preflight is the one gate
that survives every `exploit_policy` value and still applies per-action.

---

## 2. `vigil assess kali` for All Target Work

All target-facing work — HTTP probing, scanning, crawling, fuzzing, exploitation,
OOB/DNS callbacks, and raw TCP — must go through `vigil assess kali ...` subcommands.
The CLI runs on the host, executes inside the runtime container, and records the
audit row directly to the orchestrator backend. Use it because the CLI owns the
audit pipeline — host-side probes against scoped targets break the runtime's
network isolation and skip the audit row that operators and downstream specialists
rely on as a coverage map.

Discovery: `agent/skills/kali-exec/SKILL.md` holds the verb menu, methodology
profiles, and the sync-vs-async decision; `vigil assess contract kali <verb>` holds
that verb's schema, required flags, helper defaults, common mistakes, and an example
invocation.

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
runtime image is the single source of truth for the tool surface. A skill's tool
list is not proof of installation: `vigil assess kali exec ... -- command -v <tool>`
before you plan a step around a tool you have not run in this engagement.

### What the container has, and what it does not

The runtime is a tool sandbox, not a copy of your host. These gaps fail silently or
mid-run, so treat them as settled facts rather than rediscovering them:

- **`/engagements` is the bind mount.** `/engagements/$ENGAGEMENT_KEY/...` is the
  same bytes as the host's `$DIR/...` (§11); it is the only path whose contents
  survive back to the host.
- **There is no `vigil` executable in the container** — `command -v vigil` finds
  nothing. A helper script that shells out to `vigil assess ...` works when you
  test it on the host and dies with exit 127 on the only approved target-execution
  route. A script you run inside the runtime must be self-contained — stdlib
  (preferred) or the image's own installed libraries, **never the CLI**: pass what
  it needs in as argv, parse manifests and `scope.json` off the bind mount
  directly, and make the `vigil assess` recording calls from the host once the run
  returns.
- **The `aws` binary is installed but holds no credentials.** No `~/.aws`, no
  `AWS_PROFILE`, no `AWS_ACCESS_KEY_ID` is injected, so every signed call returns
  `NoCredentials`. Unsigned calls (`--no-sign-request`, unauthenticated Cognito)
  belong here; signed ones run on the host via `vigil assess host-exec`, which
  writes the same audit row (`route='host_exec'`) and so is an audited route, not
  a bypass of §2.

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

Every target-facing `vigil assess kali` call carries audit metadata as required CLI flags, and the
CLI fails closed when they're missing rather than degrading to a stale env-var default.
`vigil assess contract kali <verb>` owns the required set, each flag's purpose, the
`--technique`/`--probe-kind`/`--phase` enum values, and the `--agent-name` attribution rule;
`agent/skills/kali-exec/SKILL.md` ("Audit-flag mapping", "Phase tags") is the worked-example form.

Two judgment points that the mechanical layers can't give you: derive `--technique` from the
skill you loaded (`ssrf-testing` → `SSRF`, `sqli-testing` → `SQLI`; `HEALTH` for runtime/tool
inventory), and pass `--phase` for the phase the **dispatch was authorized for**, not
the mutable engagement phase — engagements routinely operate between phases.

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

Every `vigil assess kali` call records its full audit row to the orchestrator
backend. Treat that history as a **coverage map** — a record of what's already been
probed so your next probe goes somewhere the engagement hasn't covered yet.

Before issuing a probing, scanning, fuzzing, or credential-testing command,
search for prior work on this surface:

```bash
vigil assess command-run list --q <keyword> --show-matches
```

Default to the unscoped fuzzy search — cross-agent and cross-phase context is
usually the most valuable coverage signal — and narrow only if the broad result is
overwhelming. The search modes (`--q` alias-expanding fuzzy default, `--match-all`
to require every term, `--exact` to skip alias expansion), the filter set, and
paging are canonical in `vigil assess contract command-run list`.

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
output — but first fetch the preview with `vigil assess command-run get <id>`
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
Recon Dispatch Resource Policy in `agent/references/runtime-guides/dispatch-resource-policy.md` is the calibration source of
truth.

---

## 2d. Side-Effect Preflight

Before sending a request that could **create persistent state or reach a human** —
signup, request-access, support/report/ticket, password-reset, contact-form, or any
endpoint whose name or path suggests a write that notifies someone — run the
side-effect preflight. The posture is **capped live-fire, not zero-fire**: static
characterization is unlimited, and genuine ambiguity earns a small, hard, audited
budget gated by a recorded `human_reach_decision`. That budget is per endpoint/action
for the **whole engagement**, not per dispatch, and you do not fire past an exhausted
one, or past a `human_reach_decision` on that endpoint/action whose `payload.choice`
is `pending` or `denied`.

`vigil assess contract agent decision` owns the procedure — the static pass, the
reaches-a-real-third-party test, the 1-3 budget, the cross-dispatch check before
every fire, and the recording/continuation gate. Read it before the first such
request.

---

## Contract-First Rule

Canonical in `agent/shared-specialist-core.md` (in your Load First), which every
specialist loads on every track: run `vigil assess contract <verb>` before the
first invocation of any verb that mutates durable state, dispatches a runtime
tool, or seats work-buffer rows. That file carries the covered/not-covered verb
rosters and the errors the round-trip prevents.

---

## 3. Skills and References Are Trigger-Gated Procedures — With One Exception

The dividing line: **does the role pick this skill, or does the signal?** Role picks once and
always → MANDATORY, load it in your Load First batch. Signal picks → trigger-gated, load it the
instant the signal appears, never before.

**MANDATORY exception — a role's one always-applicable methodology skill.** Where a role pairs 1:1
with a single skill that applies on every dispatch it ever receives — `recon-specialist` ↔
`web-recon`, `surface-collector` ↔ `surface-collection` — that skill IS the role's methodology,
not a per-signal choice, so it belongs in the role's own `## Load First` MANDATORY list. (The code
track's analogous 1:1 pairs — `code-vuln-hunter` ↔ `code-vulnerability-analysis`, `code-architect`
↔ `code-architecture-mapping`, `code-vuln-verifier` ↔ `code-finding-verification`,
`code-fuzz-engineer` ↔ `code-fuzz-campaign` — follow the same rule; `agent/shared-constraints-code.md`
states them for that track.)

**Everything else is trigger-gated — load it the instant the signal appears, not before:**
- Every vuln-class skill selected by observed signal (`ssrf-testing`, `sqli-testing`,
  `idor-testing`, `jwt-testing`, …) — a `vulnerability-analyst` cannot know which applies until it
  sees the surface. A URL/hostname-shaped parameter or a fetch-on-behalf-of feature (webhook,
  importer, preview, PDF/screenshot renderer) → `ssrf-testing`; a JWT on the wire → `jwt-testing`.
- All CWE/vuln-pattern references (`agent/references/code-vuln-patterns/**`) — selected by the
  slot types actually observed in the code.
- **Every skill's `## Extended Resources` list, without exception — including a MANDATORY
  skill's own list.** This is the load-bearing half: Extended Resources are a menu the skill
  itself points at, loaded when the skill's own procedure needs one of them — never auto-required
   just because you loaded (or were required to load) the skill.

When your dispatch names a skill, load it before acting on that signal; when it doesn't and you
observe a signal a skill exists for, load that skill yourself — `vigil assess list-skills`
(compact name + one-line "Use when:") finds it faster than guessing. State which skill you loaded
and why in your response's `#### Recommended Next Actions` (and in the handoff if you checkpoint)
— that is the reporting requirement; loading it does not need an operator round-trip first.

Reach for the skill rather than improvising the invocation whenever one exists for what you are
about to do: it usually encodes harness specifics and measured calibration — mitmproxy setup, OOB
mint→poll binding, rate ceilings, tool-flag defaults — that you cannot derive from general
knowledge. Once you've loaded a skill, run `vigil assess list-references --skill <name>` for its
paired payload files, tool cheatsheets, and checklists — the same trigger-gated principle applies:
load the ones your current probe needs, not the whole set up front. The `references/` library:
- `payloads/` — copy-pasteable attack payload files per bug class
- `api-security/` — OWASP API Security Top 10:2023 checklists
- `offensive-tactics/` — red team TTPs by kill-chain phase
- `tools/` — CLI tool cheatsheets (nmap, ffuf, sqlmap, hydra, etc.)

---

## 4. Finding IDs and Recording

**MANDATORY: Every finding MUST be recorded via `vigil assess finding record`.** Never hand-allocate
finding IDs. Never write findings only to markdown. Never skip the recording step. If you
produce a finding in any output section, you MUST also call `vigil assess finding record` before your
task is complete. Findings that exist only in your output text and were not recorded via the
script are considered lost data.

Finding-ID prefix table, title formula, and the CVSS↔severity band table are canonical in
`agent/shared-specialist-core.md` "Finding IDs and the `finding record` Contract" — read it
there, do not re-derive it here.

**Deduplication:** Query existing findings with `vigil assess fetch findings` first. One
vulnerability class across many parameter values of the same endpoint is **one** finding, not one
per value — that judgment is yours. The enforced dedup key, what it refuses outright, and
`--update <slug>` versus `finding link` are in `vigil assess contract finding record`.

Record every finding with:
```
vigil assess finding record <agent-name> <finding-json-file> --agent-id <your-agent_id>
```

`--agent-id` is your DISPATCH id from the Runtime Identity block (e.g. `VA-RUN-3`), never the role
name the positional `<agent-name>` carries. The JSON payload must match
`schemas/finding-record.schema.json` — findings are always JSON, converted from markdown before
recording. **Run `vigil assess contract finding record` before your first record**: it owns the
canonical field list, the `details` keys (CVSS vector/score, remediation, CWE, chain metadata),
the lifecycle defaults, and the exact consequences of omitting or mis-stating `--agent-id`.

**The reproduction is yours to record, not the report-writer's to infer.** Write
`steps_to_reproduce` from what you actually ran, with concrete values (the real session cookie,
the real object id, the real payload) — you hold the live session and the exact argv, and nobody
downstream can recover them. `repro_runs` carries the `command-run` ids behind those steps, in step
order (`vigil assess command-run list --q "<url/param/payload>"` finds ids you did not note);
`export submission` renders their real argv and reports an id that does not resolve. **A step with
no run id behind it was imagined, not executed.** Do not sanitize as you write: credentials and
local state are self-owned (see "Credentials and Local State Are Self-Owned"). Preserve exact
values through submission; an unbound placeholder — or one placeholder reused
across different objects — makes the reproduction unfollowable by construction.

Record the working proof as readable Markdown while the session is still live: one numbered
`steps_to_reproduce` string, fenced commands/requests/responses, and annotated
`details.evidence` that says what each excerpt proves. Large raw captures belong in an artifact or
`poc_request`/`poc_response`. The report-writer owns final submission editing, but it must not have
to recover structure or distinguish commands from prose in an unformatted blob.

When a finding is only reportable as part of a chain, keep it in the same finding lifecycle and set
`details.chain_required`/`chain_rationale`/`required_followup` — at `finding record` time or later
via `vigil assess finding update <slug> --details-inline '{...}'` (shapes and enforcement:
`vigil assess contract finding record`). Never invent a special workflow status for chain-only
findings.

**Proof-not-collection — one minimal sample is sufficient.** When you have proven access
to a data set, one minimal sample is all the evidence the finding needs.
Never bulk-pull real user records, credentials, or PII to "demonstrate" a finding —
volume does not strengthen the proof and only increases harm. The "evidence beats volume"
rule (`hunting.md §6`) applies at the collection boundary: more records is not more
proof, and extracting more is the harm, not the demonstration.

**The `notes` field is an operational replay log and must contain replayable commands** — not prose
descriptions. Use readable Markdown: short sections or a numbered sequence, with exact commands,
requests, responses, and tool output in fenced code blocks. Instead of
"Login to phpMyAdmin with blank password," write the actual command: curl with headers, cookies,
and POST body; sqlmap with exact flags; ysoserial with gadget chain and target; or whatever tool
proved the finding. The field allows up to 20 KB. If the operator or another agent needs to
reproduce the finding later, the notes field alone should be sufficient without re-discovering
the request format, session tokens, or tool parameters.

Every payload in a `#### Findings` block must have been recorded during your session — do not defer
recording to the operator.

---

## 5. Surface Candidates

When your output includes `#### Surface Candidates`, record each one directly with
`vigil assess record-surface <type> <target> <source> ...`. Do not invent local taxonomy labels:
`vigil assess contract record-surface` lists every registered surface type and create status, the
argument order, and the orthogonal `--framework-registration` axis.

---

## 6. Output Format Requirements

Return structured output using these section headers when relevant to your role:

`#### Summary` · `#### Stats` · `#### Findings` · `#### Evidence`
`#### Surface Candidates` · `#### Intelligence` · `#### Recommended Next Actions`

Use `#### Decision` and `#### Action` for validation output (vulnerability-analyst).

Every `#### Findings` block must contain finding payloads ready for `vigil assess finding record`,
not prose descriptions.

---

## 7. Severity by Structured Field, Not Shouting or Slang

Convey severity through the `severity` field and the CVSS vector plus calm, precise prose. Do not use ALL-CAPS for emphasis to signal criticality and do not use casual / "reddit" severity language ("this is insane", "game over", "pwned hard"). A critical finding reads as a measured, exact description of the attacker outcome — that is more credible to a triager than capitalized adjectives. (Literal CLI tokens, flags, and enum values written in caps — `REQUIRED`, `IDOR`, `--force` — are vocabulary, not emphasis, and are unaffected.)

Everything else commonly violated — no theoretical findings, kill weak leads fast, the sibling
rule, credentials require proof, evidence beats volume, precondition analysis governing severity —
is owned by `agent/rules/hunting.md`, which every hunting role loads alongside this file (on the
code track, `agent/shared-constraints-code.md` §5 carries the equivalent bar). Read it there, not a
restatement here. `agent/rules/reporting.md` owns report *prose* and submission wording and is not
part of this Load-First set: load it only when you are authoring a confirmed finding's
report-ready `details` or an external submission.

---

## 8. OWASP Quick Reference

The OWASP Top 10:2021 category-code lookup is reference material, not a per-dispatch
constraint — it lives in `agent/references/owasp-quick-reference.md` (load on demand when
mapping a finding to a category). API-specific checklists: `agent/references/api-security/`.

---

## 9. Script Path Convention

Canonical in `agent/shared-specialist-core.md` "Script Path Convention" — `vigil assess
<subcommand>` from any directory, with full-record versus bounded nested JSON input rules. Read it there, do not
re-derive it here.

---

## 10. Chain, Credential, and Coverage State

Record state immediately using `vigil assess` with JSON files:

- **Attack chains:** `vigil assess record-chain <agent-name> <chain-json-file>`
- **Credentials:** `vigil assess post credentials <credential-json-file>` — recording a discovered credential (`status=discovered`) automatically flags a candidate finding and, when the secret is a session artifact (a session-hint cookie or a bearer/JWT), mints a usable identity from it and cross-links the two; a plain password records as intel plus a candidate finding only. List every identity a host holds with `vigil assess auth list --host <host> [--include-dead] [--json]`.
- **Credential tests:** `vigil assess post credential-tests <json-file>`
- **Access records:** `vigil assess post access-records <json-file>`
- **Coverage updates:** `covered` is never self-attested — recording a covering probe does not by
  itself mark a coverage item `covered`. `vigil assess resolve coverage-item` is that deliberate,
  rationale-bearing human verdict (`vigil assess contract resolve`).
- **Blocked techniques:** `vigil assess block-technique`, reviewed with
  `vigil assess list-blocked-techniques` (`vigil assess contract block-technique`).
- **Captured HTTP traffic:** capture is a per-engagement policy, not a proxy selector, and
  full-flow and raw-body capture are OFF by default. `vigil assess http` queries the flow store and
  shows or sets that policy (`vigil assess contract http`).
- **Probe runs (covering and non-covering):** `vigil assess record-probe` is one verb for every
  probe verdict, and one covering probe is the whole write — never a probe plus a separate drain or
  surface-advance call. `vigil assess contract record-probe` owns the status vocabulary, the full
  flag set (`--outcome-assertion`, `--lens`, `--no-drain` among them), and the cascade.

  The one thing to carry in your head: pass `--input-slot` and `--auth-context` on **every** call,
  never defaulted. The resume-brief's `## Per-Input Coverage` grid keys on
  **(host × path × attack_family × input_slot × auth_context)**, so letting `--auth-context`
  default to `anonymous` collapses every identity you actually tested into one cell and hides the
  exact cross-identity IDOR/BOLA gap the grid exists to surface.

Write payloads to `/tmp/<type>-<slug>.json` before calling — inline JSON shell arguments cause
escaping damage and are not auditable. This is host-side only: a transient JSON payload file for
the `vigil assess` call itself, distinct from the container-side rule in §11 below, which forbids
`/tmp`/`/data` for durable engagement artifacts written inside the Kali runtime.

These follow the same backend-first principle as finding recording. Do not defer chain or credential
recording to the operator. The agent that proves the state writes it; the operator verifies it landed in
canonical backend state and avoids writing duplicate rows.

---

## 11. Kali Artifact Paths

Engagement artifacts live at one physical location on disk but have two names depending on where the command runs.

- **Host side** — `$DIR = $ROOT_DIR/engagements/<engagement_key>`. Launchers export this as `ENGAGEMENT_DIR` for local file work; assessment-state selection follows the short binding rule in `agent/shared-specialist-core.md`, not this path variable. Use `$DIR/...` (or `$ENGAGEMENT_DIR/...`) for local files and host-side scripts. The Kali runtime remains engagement-agnostic (per-command working dir). The shared mitmproxy normally routes by target host; only an otherwise-unclaimed flow uses the global active pointer, and only when that selected engagement declares `scope_enforcement: bypass`, so attribution and capture still have one owner. Neither service reads `ENGAGEMENT_DIR`, and switching needs no restart.
- **Kali side** — `/engagements/$ENGAGEMENT_KEY` is the same directory via the bind mount managed by `vigil runtime start`. Launchers also export `ENGAGEMENT_KEY` (the basename of `$DIR`) so commands inside the runtime can resolve it.
- **`vigil assess kali ...` invocations MUST reference paths as
  `/engagements/$ENGAGEMENT_KEY/...`** in their command argv — the host path `$DIR` is not valid
  inside the container. Writing to `/tmp` or `/data` for engagement-scoped artifacts loses them:
  `/tmp` is container-local scratch that dies with the container, and `/data` — while a real bind
  mount — is the runtime's shared, engagement-agnostic data dir, so anything written there is
  detached from the engagement and invisible at `$DIR`. (Different `/tmp` than §10's host-side
  `/tmp/<type>-<slug>.json` payload convention above — that one is a transient JSON file for a
  host-side `vigil assess` call, never written inside the Kali container.)

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
vigil assess intel record <type> <json-file>
```

Run `vigil assess contract intel record` for the registered `<type>` values and
`vigil assess contract intel record <type>` before authoring the JSON — intel schemas are strict
(`additionalProperties=false`) and reject unknown fields.

The backend deduplicates per-engagement on natural keys: tech stack on Component (+ Version), people on Name, emails on Address, domains on Identity + Kind, CVEs on `cve_id`. Credentials live in the assessment domain (`assessment_credentials`); use `vigil assess post credentials`, not `intel record`.

Prose intel that doesn't fit a structured row goes to `intel record note` — it is FTS-indexed and engagement-scoped. Notes and org facts are authored interpretation, so supply their top-level `authored_by`, `scope`, and `validity_context` strings whenever you know them; use `provenance` separately for source evidence such as `agent_name` or `artifact_ref`. The backend supplies visible unknown-author, engagement-scope, and unreviewed-validity defaults when context is unavailable; those defaults are a revalidation warning, never authorization or permission to act.

---

## 14. Per-Target Rate Calibration

Recon-class roles (recon-specialist, surface-collector, osint-analyst when
running active enumeration) load **`agent/references/recon/rate-calibration.md`**
on first use — that file owns the trait-row table (Cloud-fronted / Origin /
WAF-protected / High-friction / Vendor SaaS), the runtime-tier × DNS-profile
matrix, and the concurrent-nmap-procs cap. Tier-selection prose and the
step-down rules live in `agent/references/runtime-guides/dispatch-resource-policy.md`;
the operator picks the trait row before dispatch and the specialist
applies it.

Non-recon roles (vulnerability-analyst, source-analyzer, fuzzer,
exploit-developer, report-writer) consume per-call rate hints from the dispatch
context instead, and do not load that table at all.

---

## 15. File Organization

| Type | Directory |
|------|-----------|
| Downloaded pages/JS/CSS | downloads/ |
| Scan output | scans/ |
| Custom scripts/exploits | tools/ |
| Background PIDs | pids/ |

Keep engagement-control metadata, `report.md`, and the transient worker buffer at
the engagement root only. Credentials, activity log, and intel live in the
orchestrator backend — query via `vigil auth status`, `vigil assess fetch
activity-entries`, and `vigil assess intel list`.

---

## 16. Mandatory Closing Sequence

**Two authorities, not one universal list.** The closing-sequence *wrapper* — the parts true
across every role regardless of what it records (why `agent handoff` is idempotent and worth
checkpointing mid-task, the exact `agent_id`/`agent_role`/`phase` values to use from the Runtime
Identity block and why a mismatch orphans the row, why `agent done`/`agent close` are
operator-only, the plan-state digest cadence) — is canonical in `agent/shared-specialist-core.md`
"Mandatory Closing Sequence — wrapper". Read it there; do not re-derive it here.

**The exact numbered verb list is role-specific.** Your role prompt states its own under
`### Closing verbs` (or its own `## Mandatory Closing Sequence` heading) — that list, not a fixed
sequence in this file, is what you run before returning. Every role's list draws on the same pool
of backend writes documented elsewhere in this file (finding record §4, intel record §13,
record-surface §5, `agent handoff` + `render-handoff` self-check), instantiated with that role's
agent-name, its own additional verbs, and its own ordering — there is no single sequence that
fits every role, which is why this file does not assert one.
