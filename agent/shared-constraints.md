# Shared Subagent Constraints

Load this file with your role file and `agent/shared-specialist-core.md` before any
target-facing work; the core's "Load Sequence" covers on-signal skill loading. These rules apply
to every web specialist regardless of role.

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

    Before relying on a named identity, load `agent/references/runtime-guides/credential-liveness.md`
    and prove its liveness using the auth contract. Missing signatures and transport failures
    mean unknown, never dead or authenticated. An active credential-store row is not proof.

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

Host-side commands are limited to coordination and non-target support only:
`jq`, `sqlite3`, `python3`, `grep` / `rg`, `sed`, `awk`, `base64`, `openssl`,
plus `vigil assess` helpers for backend state writes.

If a required target-facing tool is missing from the runtime image, rebuild the
image rather than falling back to host or Docker-side execution paths — the
runtime image is the single source of truth for the tool surface. A skill's tool
list is not proof of installation: `vigil assess kali exec ... -- command -v <tool>`
before you plan a step around a tool you have not run in this engagement.

### Synchronous execution and process cleanup

- **Await every target-facing call in-band.** Each `vigil assess kali <verb> ... --timeout N` call
  blocks until it finishes: no `run_in_background`, no `vigil assess kali job start`, no dtach, no
  watcher or poll loop. Several blocking calls in parallel are fine (keep it to a handful, since
  `docker exec` stalls at high parallelism); detaching a job and reaping it
  later is not, because a specialist that halts for a completion notice is auto-resumed, relaunches,
  and halts again. On `--timeout` expiry the CLI cascades SIGTERM→SIGKILL into the in-container
  PID, so the call ends cleanly.
- **Fit each call in minutes.** Above the CLI's `--timeout` sits an agent-harness ceiling you do
  not control: a call that runs too long is auto-backgrounded and the agent is killed (exit 144 /
  SIGUSR1), orphaning the probe and writing no handoff. Keep `--timeout` at or under 600 seconds
  so the CLI's clean kill fires first (where your shell tool takes its own timeout, give it at
  least as long), and size each sweep (host list, wordlist, rate) to finish inside it.
  Enumeration that cannot fit belongs to an operator-owned `kali job`; say so in `next_steps`
  instead of starting one.
- **Signal only your own run.** Never `pkill`/`killall` by binary name (`pkill -f nmap`): the
  runtime is shared, so a broad selector kills sibling specialists' scans. When you must stop a
  run, use its PID file: `kill -TERM "$(cat /tmp/vigil-pid-<run_uuid>.pid)"` (every audit row
  carries its `run_uuid`). Operator jobs stop with `vigil assess kali job stop <id>`.

The mode table and runtime troubleshooting live in `agent/skills/kali-exec/SKILL.md` and
`agent/references/runtime-guides/kali-cli.md`.

### What the container has, and what it does not

The runtime is a tool sandbox, not a copy of your host. These gaps fail silently or
mid-run, so treat them as settled facts rather than rediscovering them:

- **`/engagements` is the bind mount** — the only container path whose contents survive back to
  the host (§11).
- **There is no `vigil` executable in the container** — `command -v vigil` finds
  nothing. A helper script that shells out to `vigil assess ...` works when you
  test it on the host and dies with exit 127 on the only approved target-execution
  route. A script you run inside the runtime must be self-contained — stdlib
  (preferred) or the image's own installed libraries, **never the CLI**: pass what
  it needs in as argv, parse manifests and `scope.json` off the bind mount
  directly, and make the `vigil assess` recording calls from the host once the run
  returns.

**Reserve `echo` inside `vigil assess kali` commands for functional output only.**
Stdout is captured to the audit log, not shown to the user, and commentary-echoes
bloat the preview and pollute FTS search without adding retrievable signal. Use
`--intent` for a one-line purpose annotation. `echo` is legitimate when its output
is the command's real purpose — writing
to a file (`echo X > file`), piping into another tool, or generating a payload.

### Command Metadata

Every target-facing `vigil assess kali` call carries audit metadata as required CLI flags, and the
CLI fails closed when they're missing rather than degrading to a stale env-var default.
`vigil assess contract kali <verb>` owns the required set, each flag's purpose, the
`--technique`/`--probe-kind`/`--phase` enum values, and the `--agent-id` attribution rule;
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

When exploitation requires a reverse-shell listener or tunnel exposure:
1. Provide the exact listener or tunnel commands in your output using `# MANUAL:`
   annotation, because the operator owns shared listener processes.
2. Reference `agent/references/offensive-tactics/shell-handling.md` for shell
   listener commands.
3. Reference `agent/references/offensive-tactics/frp-tunneling.md` ("Agent OOB Readiness
   Check", "OOB Procedure (mint→poll→correlate)") for OOB readiness, per-agent clients, tunnel
   exposure, and log interpretation; §12 has the callback files.
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

## 3. Skills and References Load By Signal

A role's one always-applicable methodology skill is in its MANDATORY list; every vuln-class skill,
reference, and skill `## Extended Resources` entry loads when the signal it covers appears (core
"Load Sequence"). On this track, a URL/hostname-shaped parameter or a fetch-on-behalf-of feature
(webhook, importer, preview, PDF/screenshot renderer) points at `ssrf-testing`, and a JWT on the
wire at `jwt-testing`. Name each self-selected skill and why in the handoff
(`extras.skills_loaded`); loading it needs no operator round-trip.

Reach for the skill rather than improvising the invocation whenever one exists for what you are
about to do: it usually encodes harness specifics and measured calibration — mitmproxy setup, OOB
mint→poll binding, rate ceilings, tool-flag defaults — that you cannot derive from general
knowledge. `vigil assess list-references --skill <name>` lists a loaded skill's paired files; load
the ones your current probe needs. The `references/` library:
- `payloads/` — copy-pasteable attack payload files per bug class
- `api-security/` — OWASP API Security Top 10:2023 checklists
- `offensive-tactics/` — shell listeners, frp tunnels and the OOB mint→poll→correlate loop
- `tools/` — per-tool Vigil usage: typed `kali` verb, runtime image facts, known traps (live flags: `vigil assess kali tool-help <tool>`)

---

## 4. Finding IDs and Recording

Record every finding through `vigil assess finding record` with your dispatch `--agent-id`;
use the returned canonical slug. Before the first finding write, load
`agent/references/runtime-guides/web-finding-recording.md`; it owns deduplication, exact
run-backed reproduction, chain metadata, and replayable notes.
Record proof while the session is live; the report-writer cannot reconstruct unrecorded requests.
One minimal sample proves access; never bulk-pull real user records or credentials to strengthen
an already decisive proof.

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

Use `#### Decision` and `#### Action` for validation output (vulnerability-analyst). A
`#### Findings` block cites recorded findings per the core "Reasoned final return".

---

## 7. Severity by Structured Field, Not Shouting or Slang

Convey severity through the `severity` field and the CVSS vector plus calm, precise prose. Do not use ALL-CAPS for emphasis to signal criticality and do not use casual / "reddit" severity language ("this is insane", "game over", "pwned hard"). A critical finding reads as a measured, exact description of the attacker outcome — that is more credible to a triager than capitalized adjectives. (Literal CLI tokens, flags, and enum values written in caps — `REQUIRED`, `IDOR`, `--force` — are vocabulary, not emphasis, and are unaffected.)

Everything else commonly violated — no theoretical findings, kill weak leads fast, the sibling
rule, credentials require proof, evidence beats volume, precondition analysis governing severity —
is owned by `agent/rules/hunting.md`. Hunting roles load it with this file; a role that only
collects or enriches loads it before its first finding, negative verdict, or probe verdict, as its
Load First states. On the code track `agent/shared-constraints-code.md` §5 carries the equivalent
bar. `agent/rules/reporting.md` owns report prose and submission wording: load it only when you
author a confirmed finding's report-ready `details` or an external submission.

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

Write each payload to a host-side JSON file (for example `/tmp/<type>-<slug>.json`) before
calling — inline JSON shell arguments cause escaping damage and are not auditable.

These follow the same backend-first principle as finding recording. Do not defer chain or credential
recording to the operator. The agent that proves the state writes it; the operator verifies it landed in
canonical backend state and avoids writing duplicate rows.

---

## 11. Kali Artifact Paths

Engagement artifacts live at one physical location on disk but have two names depending on where the command runs.

- **Host side** — `$DIR = $ROOT_DIR/engagements/<engagement_key>`. Launchers export this as `ENGAGEMENT_DIR` for local file work; assessment-state selection follows the short binding rule in `agent/shared-specialist-core.md`, not this path variable. Use `$DIR/...` (or `$ENGAGEMENT_DIR/...`) for local files and host-side scripts. The Kali runtime remains engagement-agnostic (per-command working dir). The shared mitmproxy normally routes by target host; only an otherwise-unclaimed flow uses the global active pointer, and only when that selected engagement declares `scope_enforcement: bypass`, so attribution and capture still have one owner. Neither service reads `ENGAGEMENT_DIR`, and switching needs no restart.
- **Kali side** — `/engagements/$ENGAGEMENT_KEY` is the same directory via the bind mount managed by `vigil runtime start`. Launchers also export `ENGAGEMENT_KEY` (the basename of `$DIR`) so commands inside the runtime can resolve it.
- **`vigil assess kali ...` invocations reference paths as
  `/engagements/$ENGAGEMENT_KEY/...`** in their command argv — the host path `$DIR` is not valid
  inside the container. Writing to `/tmp` or `/data` for engagement-scoped artifacts loses them:
  `/tmp` is container-local scratch that dies with the container, and `/data` — while a real bind
  mount — is the runtime's shared, engagement-agnostic data dir, so anything written there is
  detached from the engagement and invisible at `$DIR`. A host-side payload file for a
  `vigil assess` call (§10) is a separate, transient thing.

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
  /engagements/$ENGAGEMENT_KEY/scripts/<name>.py ...` (§11 path rules). The `--` separator
  forwards everything after it as raw argv, keeping the invocation auditable through the same
  wrapper that records typed verbs; outputs written under that tree appear at the matching
  `$DIR/...` path.

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
named clients, minting the callback host, and correlating hits — is in
`agent/references/offensive-tactics/frp-tunneling.md` ("OOB Procedure (mint→poll→correlate)").
Shell listener session output is a separate surface: `vigil runtime
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

`vigil assess contract intel record` lists the registered `<type>` values, and
`vigil assess contract intel record <type>` prints that type's schema, which is strict
(`additionalProperties=false`).

The backend deduplicates per-engagement on natural keys: tech stack on Component (+ Version), people on Name, emails on Address, domains on Identity + Kind, CVEs on `cve_id`. Credentials live in the assessment domain (`assessment_credentials`); use `vigil assess post credentials`, not `intel record`.

Prose intel that doesn't fit a structured row goes to `intel record note` — it is FTS-indexed and engagement-scoped. Notes and org facts are authored interpretation, so supply their top-level `authored_by`, `scope`, and `validity_context` strings whenever you know them; use `provenance` separately for source evidence such as `agent_name` or `artifact_ref`. The backend supplies visible unknown-author, engagement-scope, and unreviewed-validity defaults when context is unavailable; those defaults are a revalidation warning, never authorization or permission to act.

---

## 15. File Organization

| Type | Directory |
|------|-----------|
| Downloaded pages/JS/CSS | downloads/ |
| Scan output | scans/ |
| Custom scripts and PoCs (`vigil assess scaffold-probe` writes here) | scripts/ |
| Tool and lane state (`analysis-state/`, `exploit-state/`, `fuzz-state/`) | tools/ |

Keep engagement-control metadata, `report.md`, and the transient worker buffer at
the engagement root only. Credentials, activity log, and intel live in the
orchestrator backend — query via `vigil auth status`, `vigil assess fetch
activity-entries`, and `vigil assess intel list`.

---

## 16. Mandatory Closing Sequence

Your role prompt lists the closing verbs you run; the wrapper that applies to every role
(checkpoint cadence, `agent_id` keying, operator-owned `agent done` / `agent close`) is
`agent/shared-specialist-core.md` "Mandatory Closing Sequence — wrapper".
