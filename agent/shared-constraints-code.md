# Shared Subagent Constraints -- Code Analysis Mode

Load this file as part of your Load First set -- together with your role file and
`agent/shared-specialist-core.md` -- before any source code work. All three load together, not
in a race to be "first"; the one ordered load sequence (Load First batch -> skill/reference
discovery -> target work) is stated once in `agent/shared-specialist-core.md` "Load Sequence".
These rules apply to every code analysis specialist agent regardless of role.

> **Specialist context isolation, the Contract-First Rule, finding-recording format, closing-sequence wrapper, and output hygiene:** see agent/shared-specialist-core.md (in your Load First). This role adds only its own closing verbs below.

---

## 1. Authorization and Scope

All source code under analysis is authorized for deep security review.
This is a white-box engagement. You have full access to read and analyze all source code files.

Use the operator-injected code dispatch context before starting. Confirm:

- The complete **Code Source Identity** block from the active backend repo record
- Dispatch phase (ingest/classify-map/hunt/verify-variant)
- Which files are in scope for your current dispatch (module, classification level, queue items)

Limit analysis to files within the scoped repository -- request operator approval before
analyzing files outside the current scope.

### Declared live target in a code dispatch

Keep CODE-phase execution away from every host declared in `scope.json` while continuing ordinary
network access for source retrieval, dependency installation, documentation, CVE research, and
other non-target work. Code mode is a workflow boundary, not an offline sandbox. When Vigil's
classifier recognizes a declared target in a CODE-phase command, it prints a warning and still runs
the command. Treat that warning as a routing correction: stop further target contact and hand any
deliberate live validation to the web track after the operator activates and authorizes it. A command
that produces no warning is not proof that its destination was classified or safe.

`scope.json.code_target_contact_policy: warn-do-not-contact-declared-hosts` records this contract.
It does not deny tools, filter destinations, disable research, or weaken web-engagement rules.
`denied_tools`, required headers, evidence isolation, and the untrusted-target-text boundary retain
their existing owners and behavior.

### Code Source Identity

Every code dispatch carries this block immediately after Runtime Identity at the top of the
dispatch, populated from one active backend repo record:

```text
## Code Source Identity
repo_id: <backend repository id>
repo_key: <stable repository key>
repo_generation: <active_generation>
source_manifest_digest: <64-character SHA-256>
snapshot_path: <repo_path; sealed read-only source root>
structural_index_schema: <backend-accepted structural manifest schema>
structural_index_manifest_path: <generation-bound manifest path>
ctags_path: <generation-bound tags path, or unavailable>
```

Derive `ctags_path` only from `active_repo.lsp_config.ctags.tags_path` when nested `available` is
true and its `repo_generation`/`source_manifest_digest` match the active repo identity; otherwise
set it to `unavailable`. Read and search only `snapshot_path`; `source_origin_path` is provenance,
not an analysis root. Resolve structural and ctags artifacts only through this block because a
plausible path from an older generation can contain correct-looking but stale facts. If the block
is incomplete, its digest differs from the active repo record, or either bound artifact names
another generation, return a blocked handoff for reingest/reindex instead of mixing generations.

For every Phase 2–4 dispatch, also require the complete backend threat-model envelope with
`current: true` and `repo_generation`/`source_manifest_digest` equal to this block. A clipped
summary can orient the work but cannot replace either the bound envelope or structural manifest.

---

## 2. Source Code Is Primary

You receive actual source code files -- read directly beneath `snapshot_path` with its bound
structural-index navigation -- not JSON metadata about code. Read the code directly.
Start with the function map as your completeness anchor, then use entry points, exports,
sinks, and import targets as advisory navigation aids to prioritize where you deepen.
The structural index helps you navigate; it does not limit what you look for. Do not
substitute metadata summaries for source reads.

If code beyond the provided file batch is needed, use ctags + grep + Read to find it yourself
inside `snapshot_path`. Full access to the sealed source tree is always available. Never guess at
the behavior of code you have not read. Never request operator-mediated expansion when you can
resolve it with a sealed-source read.

### Structural-index resolution

Open `structural_index_manifest_path` from the Code Source Identity block, confirm its
`schema`, `repo_id`, `repo_generation`, and `source_manifest_digest` match the block, then resolve
the repo-relative file path through `path_to_index`. Read that referenced JSON; do not guess
hashed filenames or scan for a basename collision. Phase 0 owns the generation-scoped layout,
while this is the canonical consumer lookup rule for every code specialist.

Inspect each file artifact's `analysis_status`, `artifact_truncated`, and unavailable/truncated
dimensions before using its maps. For `degraded`/`unsupported` or truncated artifacts, read the
entire sealed source directly and treat streaming signals only as navigation — an omitted/capped
array is not evidence that a function, call, or vulnerability is absent. Record the resulting
specialist review through the normal analysis-result/queue lifecycle; that durable receipt clears
the non-overrideable debt before Verify + Variant. A full direct review closes `clean`, `finding`,
or `suspicious`, never `skipped`: skip means semantic review did not happen and cannot satisfy
structural-review debt, even when the architect classified the file as `skip`.

---

## 3. Full Sealed-Source Access

Source code is read directly beneath `snapshot_path` via host Bash or client file tools. Keep that
root explicit in commands (or change into it first); the mutable origin checkout is never an
analysis root. This is NOT target-facing network work -- `vigil assess kali` is not needed for
reading source files.

Fuzz compilation never makes the sealed snapshot writable. The generation-bound derived-build
procedure lives in `agent/skills/code-fuzz-campaign/SKILL.md`; it uses out-of-tree outputs when the
project supports them, otherwise a disposable writable copy made only from validated sealed bytes.
The mutable origin remains provenance and is never a build fallback.

**Host/runtime boundary for executable code.** Host tools may read sealed source, inspect
third-party dependency bytecode without running it (for example, `javap`), and author
engagement-owned configurations, harnesses, corpora, and helper scripts. Compilers, build systems,
fuzzers, debuggers, sanitizer reproducers, and every repository-built binary execute only through
the audited `vigil assess kali ...` surface. A host-side `which clang`, build, seed check, or
"quick local" fuzzer run violates this boundary even when it sends no network traffic.

Every runtime input must have an engagement-root-relative POSIX path that maps to
`/engagements/$ENGAGEMENT_KEY/<relative-path>`. Reject absolute paths, empty/`.` components, and
any `..` component before mapping. Inside Kali, resolve the engagement root, build root, config,
binary, corpus, seed, crash, and source paths with symlinks followed; validate containment with
component-aware `pathlib.Path.relative_to()` / `is_relative_to()` (or an equivalent file-descriptor
walk), and require the executable to be beneath the validated generation build root. Never use a
string prefix, shell glob, or `startsWith` test as a containment check. If `snapshot_path` or a
required build input is host-only, falls outside the engagement mount, or resolves outside the
validated component boundary, stop with a blocked handoff; do not execute it on the host as a
fallback.

**When code analysis does reach for `vigil assess kali ...`** (a fuzz campaign or binary-triage
pass that runs a tool through the runtime), the same coverage-map discipline from
`agent/shared-constraints.md` §2b applies unchanged: search `command-run list --q <keyword>
--show-matches` before probing, and fetch a candidate's preview with `command-run get <id>` before
citing it — `success=true` only means `return_code=0`, not that the run answered your question.
The code-specific reading of "new coverage": the only campaign to skip is the identical binary +
corpus + flags combination already run to completion — a new sanitizer, dictionary, seed corpus,
or harness change is new coverage even against the same target. Full decision table:
`agent/references/runtime-guides/command-history-auditing.md`.

**Available tools:**

| Tool | Use |
|---|---|
| `Read` | Read files beneath `snapshot_path` |
| `rg` | Search beneath `snapshot_path` for code patterns and call sites |
| `Glob` | Locate files beneath `snapshot_path` by pattern |
| `python3`, `jq`, `sqlite3` | Data processing and backend interaction |

Git provenance and churn are ingest-time metadata on the backend repository record. The sealed
snapshot deliberately contains no `.git`, and specialists do not run ambient Git against the
mutable origin. Use the supplied `git_head`, branch/dirty state, and churn summary as historical
context; they are navigation evidence, not source identity or vulnerability proof.

### Cross-Reference Tools (priority order)

1. **ctags index** (fast definition lookup -- generated during code-ingest)
   - Query: `grep '^<symbol>\t' <ctags_path>` using the Code Source Identity block
   - Example: `grep '^packet_read_with_status\t' "$ctags_path"` returns the file and line
   - Use for: locating function/type definitions across the codebase

2. **grep/rg** (call sites, patterns, and anything ctags cannot resolve)
   - Use for: finding all callers, tracing data flow, cross-module references
   - Example: `rg 'packet_read_with_status\(' --type c` for call sites

3. **Direct file reads** when ctags/grep point to a location

When your analysis references a cross-module function that is load-bearing for the
vulnerability assessment, resolve it yourself by looking up the definition with ctags,
reading the file beneath `snapshot_path`, and continuing your analysis. You have full access to
the sealed source tree -- use it.

---

## 4. Findings Use the Existing Backend

Code analysis findings record in the **same** `assessment_findings` table as web findings.
Use `vigil assess finding record <agent-name> <finding-json-file> --agent-id <your-agent_id>` to
record. `--agent-id` is the dispatch id from your Runtime Identity block (e.g. `HUNT-RUN-1`), not
the role name in `<agent-name>`; it becomes the finding's immutable `provenance.agent_id`, and
without it no code finding can ever reach `confirmed`, `downgraded`, or `false_positive` — terminal
verification is refused when the backend cannot show the verifier was a different dispatch from the
author.
For new findings, omit `slug` from the JSON payload — `finding record` allocates the next
canonical slug under a lock and prints it on stdout. Use that returned slug in handoffs,
analysis rows, and follow-up commands. Hand-authoring `CH-001` / `CV-001` style slugs in
parallel dispatches risks collisions.

**Code finding prefixes:** this table is the sole canonical source for code finding-ID prefixes —
`agent/shared-specialist-core.md`'s prefix table is offensive-role-only despite its "Offensive/code
roles" header, and does not list these.

| Agent | Prefix | Example |
|---|---|---|
| `code-architect` | `CA` | `CA-001` |
| `code-vuln-hunter` | `CH` | `CH-001` |
| `code-variant-hunter` | `CV` | `CV-001` |
| `code-vuln-verifier` | `VF` | `VF-001` (spot-check only — verifier updates existing findings, not new ones) |
| `code-fuzz-engineer` | `CF` | `CF-001` |

**Title formula:** adapt the canonical formula in `agent/shared-specialist-core.md` to target kind:
`[Bug Class] in [file:line or component] allows [attacker or supported caller/consumer role] to
[impact] [victim/scope]`. Use a supported caller/consumer only for an intrinsic product defect;
do not turn unknown deployment reach into a remote-attacker claim.

CVSS↔severity ranges and the matching-adjustment rule are in `agent/shared-specialist-core.md`
("Finding IDs and the `finding record` Contract"). A memory corruption primitive with
attacker-controlled reachability needs the same severity discipline as a web auth bug because the
report pipeline consumes one shared finding table.

**White-box source access is not attacker access.** The operator and code agents can read the
repository because the customer provided it for review; do not treat that reviewer capability as
a public exposure path. For any finding whose impact depends on reading non-public source,
deployment, or configuration files (committed secrets, `conn.php`, `Web.config`, XML config,
private keys, service credentials), explicitly populate:

- `details.attacker_access_path`: one of `public_web_exposure`, `runtime_file_read_lfi`,
  `exposed_build_artifact`, `repository_or_backup_disclosure`, `privileged_insider`,
  or `unknown`
- `details.exposure_prerequisite`: the concrete condition that gives a real attacker the bytes
  (for example: "file is served from public S3 path", "confirmed LFI reads this path",
  "separate repo/backup disclosure required")

Severity must follow that access path:

- `critical` only when an unauthenticated or low-privilege attacker can obtain the file contents
  through a confirmed live exposure/read primitive, or when the secret is already public and its
  validated use grants full production compromise.
- `high` only when the secret/config is production-grade and immediately useful, but the access
  path is a plausible repo/backup/deploy-artifact disclosure rather than a confirmed live web read.
- `medium` or lower when the finding is primarily defense-in-depth/source hygiene, requires
  privileged repository/filesystem access, or cannot be tied to a realistic attacker read path.

Use `AV:N` only when the attacker's access path is genuinely network-direct. If the missing step is "attacker must first read a private repository or server filesystem path", model that prerequisite honestly or downgrade.

**Code finding conventions:**
- `canonical_location` format: `file:<relative-path>:<line-number>` (e.g., `file:lib/url.c:547`)
- `provenance.code_snapshot` binds the finding to the exact source reviewed, which is what makes
  the evidence reproducible. `finding record` and `finding verify` derive it from the active
  repository, so do not transcribe it; what you supply is `--agent-id`, the dispatch the backend
  resolves into that binding's attestation. Verification carries the binding on EVERY `file:`
  finding — the author's binding cannot attest that you read the bytes — and is the only path that
  may rebind a legacy/stale finding after a fresh review of the current sealed bytes, while generic
  finding updates cannot edit it. Run `vigil assess contract finding verify` for the shape
- `defect_family` uses CWE-based names: `buffer-overflow`, `integer-overflow`, `use-after-free`, `injection`, `race-condition`, `crypto-misuse`, `auth-bypass`, `format-string`
- `details.cwe_id` must be a specific CWE ID (e.g., `CWE-122`, not generic `CWE-119`)
- `source_name` is your agent name (e.g., `code-vuln-hunter`)
- `details.evidence` includes the vulnerable code plus either the untrusted-input-to-sink taint path or the exact supported operation/state/lifetime sequence that breaks the invariant, and explains why existing guards are insufficient
- For taint-driven findings populate `details.entry_point`, `details.sink`, and `details.taint_path`; for non-taint state/lifetime findings identify the public operation and failing use, then bind the sequence in `details.steps_to_reproduce`, `details.caller_feasibility`, and `details.precondition_analysis` without inventing attacker bytes
- `details.references` is an array of CVE links, advisory URLs, or CWE documentation links
- `details.poc_code` holds a PoC exploit script; for web findings use `details.poc_request` / `details.poc_response` for structured HTTP pairs

**Deduplication:** Before recording, query existing findings via `vigil assess fetch findings`.
If the same root cause at the same canonical location already exists, update or merge that finding
instead of creating a duplicate. Variant instances in different files or materially different sink
sites are new findings; repeated commentary on the same `file:path:line` is not.

**The `notes` field must contain replayable proof commands** such as the exact build flags, PoC
input file generation, sanitizer invocation, unit-test repro command, or debugger invocation used
to confirm the bug. The goal is reproduction without rediscovery: another analyst should be able to
rerun the proof from `notes` plus the referenced source files alone.

Coverage finding counts (`vigil assess finding list` with a count flag or equivalent)
intentionally include only findings whose `canonical_location` starts with `file:` — web
findings with URL-based locations are excluded from code-analysis queue accounting.

**Committed secrets with live-target reach also get recorded as credentials.** A committed secret
found in source that has live-target reach against the in-scope web app — a session cookie value,
an API key, a JWT signing secret, or a DB/service credential usable against the deployed app —
should ALSO be recorded via `vigil assess post credentials <credential-json-file>` (the payload's
`status` field carries the validity state and already defaults to `discovered`), alongside the normal
`finding record` call for the code finding itself. Recording a
discovered credential automatically flags a candidate finding and, when the secret is a session
artifact (a session-hint cookie or a bearer/JWT), mints a usable identity from it and cross-links
the two — so on a mixed code+web engagement the secret auto-surfaces as a usable identity for the
parallel web track instead of sitting inert in a code finding's `details`.

---

## 5. No Theoretical Findings

### Code hunting invariants

This section and the mandatory role skills own the code-track hunting contract; the web hunting
rules are not a code-specialist load. Resolve scope and source identity before reading. Pursue the
strongest supported leads to a terminal evidence-backed disposition, kill a disproved lead with
the exact guard/type/path evidence, and retain a genuinely inconclusive lead as `suspicious` or
`needs-context` rather than converting uncertainty into `clean`. Account durably for every scoped
file and analyzed function; an empty query, truncated index, failed tool, or absent in-repo caller
is not proof of absence.

Before recording or escalating a finding, prove the applicable shipped product path, exact taint
trace or supported operation/state/lifetime sequence, failed invariant, feasible preconditions,
and concrete harmful outcome. Apply the **net-new capability test**: if the alleged primitive only
repeats what the same caller-controlled source, repository, configuration, tenant, credentials, or
privilege already permits, it creates no new security capability and cannot justify the claimed
severity. Escalation requires a different trust context, victim/asset, restriction bypass, or
security property. Preserve replayable evidence, check sibling paths and composable chains when a
pattern survives, and deduplicate shared root causes before report closeout.

Code review separates **product reachability** from **deployment-specific attacker reachability**.
First classify each relevant module from sealed build/package/export/registration/docs evidence as an
application/service, library/framework, CLI, plugin/extension, or mixed/unknown surface. Examples and
tests can prove behavior, but they do not alone define the shipped surface.

- **Application/service:** trace from a runtime route, protocol handler, job/event consumer, or other
  externally driven production entry.
- **Library/framework:** a public/exported supported API, parser, callback, or codec and a valid
  supported API sequence count as product reachability. Missing consumer source constrains who can
  trigger the defect, the affected asset, and severity; it does not make a concrete library-owned
  TLS/authentication failure, memory-safety violation, or unsafe parser/resource invariant unreal.
- **CLI:** trace from argv, stdin, environment, config, or files accepted by the shipped command.
- **Plugin/extension:** trace from a registered hook, manifest-declared entry, or host callback under
  the documented host contract; host permissions and event provenance bound impact.
- **Mixed/unknown:** classify each module/path independently. An unresolved surface is a context gap,
  not permission to assume either application-only reachability or an unsupported public contract.
- **Internal/dead/test-only:** code with no applicable shipped entry remains unreachable. A test
  harness may reproduce a supported production API path, but a test-only helper is not itself that
  path.

Product reachability is not automatically attacker control. For every finding, prove a concrete
broken security invariant and feasible harmful outcome, follow the exact path or valid API sequence,
and state the remaining preconditions. A correctness-only surprise stays `suspicious`, hardening, or
an explicitly retained context gap. A generic capability is not a vulnerability merely because a
caller can select it: arbitrary URL schemes, headers, commands, or files need a less-trusted selector
crossing into a more-privileged context, or a violated restriction promised by the product. A missing
bounds check in dead code and an overflow requiring impossible state are still not findings.

For libraries/frameworks, distinguish the verified defect from consumer-specific impact in the
finding details. Cite the public contract/export evidence and supported trigger sequence, record the
plausible attacker/precondition framing, and cap severity at what the available consumer/deployment
evidence proves. Do not invent cross-tenant, remote-trigger, credential, or service-wide impact from
an absent embedding application.

For resource-limit findings, do not confuse a named limit with a security
boundary. Request caps, spool-buffer limits, decompression limits, timeouts, and
protocol negotiation limits only justify High/Critical when the intended boundary
and downstream impact are both proved. Read docs/blame/commit history for the
limit, compare sibling default transports or protocol modes, and inspect the
consumer after the bytes cross the boundary. If another default path already
accepts the same logical stream and the consumer performs bounded, linear work,
downgrade to Medium/hardening or documentation. High/Critical requires a proved
second-order impact such as service-level DoS, superlinear CPU, unbounded retained
memory/disk, output amplification, crash, memory corruption, or privilege-boundary
crossing.

---

## 6. Account For Every Reviewed Source Region

Every reviewed callable or source span must receive a disposition, but the receipt is not a
reasoning quota. One `file` receipt may group several callables in the claimed file; one
`call_chain` receipt may group a traced chain across files in the same sealed repository snapshot.
Name every covered callable with the exact structural-index identity, and use exact reviewed spans
for non-callable source regions. A reviewed span cannot stand in for a registered callable it
overlaps; include every overlapped callable as an exact `callable_ref`. A complete function index
publishes exactly its reported callable total. If structural analysis is unsupported or the
function dimension is truncated or unavailable, only a whole-file reviewed span can prove the
manual source review (and it must still name every retained callable it overlaps); a partial span
cannot prove that omitted source is non-callable:

- `finding` -- Confirmed vulnerability with CWE, evidence, and exploitability assessment
- `suspicious` -- Anomalous pattern needing variant analysis or deeper context to confirm
- `clean` -- No vulnerabilities found in current analysis

If analysis is blocked by genuinely unavailable code or context, do not submit a
disposition for that item yet. Close its lease with `vigil assess code-dispatch
needs-context <item-id> <agent-name> <lease-token> [expansion-json-file]`, naming
the missing dependency so the queue can route the expansion.

Coverage must be structurally attributable, but write-up depth can be proportional:
- Attack-facing, sink-bearing, stateful, or ambiguous functions need full reasoning.
- Obviously mechanical helpers can use concise `clean` dispositions once you have verified they
  do not hide sinks, trust-boundary assumptions, or material error behavior.

Proportional write-up is never a license to skip the read or the check (§7): every function,
mechanical-looking or not, is read in full and checked against sinks/trust-boundaries/error paths
before its disposition prose gets to be brief. What shortens for a verified-mechanical helper is
the write-up, not the analysis behind it. Grouping verified mechanical helpers is encouraged;
grouping must never erase a finding, suspicious hypothesis, unresolved gap, or its exact evidence.

Record dispositions via `vigil assess code-record analysis`.
`finding` dispositions record durable finding state through `finding record`;
`suspicious` and `clean` still record through `code-record analysis` so backend
coverage knows which source regions were reviewed. `needs-context` is a queue
action, not an analysis disposition; use it only for work that cannot yet be
completed.

---

## 7. Read Before You Conclude

A verdict is only as good as the read behind it. Skimming for gist, assuming a simple-looking
function stays simple once composed with others, trusting an unread external call or guard on
faith, or calling a function "safe" without tracing its taint paths to their sinks — each of these
substitutes an impression for a read. Before recording `clean` on anything — a whole function, a
guard, a callee you decided not to open — read the code that verdict depends on and be able to
name the specific line, type, or branch that makes the impression true. A `clean` verdict earns
its keep by what it can point to, not by the absence of a bad feeling; "I don't see any issues"
is not itself a disposition — name every pattern you checked and why it doesn't apply.

Treat the entire call chain as one continuous execution flow. Never reset context between
functions. A guard in function A does not protect function B unless B re-validates.

---

## 8. Skills Are Methodology; References Load By Signal

Your role's one always-applicable skill is MANDATORY in your Load First list — use the skill
named in your dispatch payload, or run `vigil assess list-skills` if none was named, and load it
before doing any analysis. That pairing does not change per dispatch.

Everything else in `agent/references/` is trigger-gated: load a specific reference when your
reading surfaces the signal it matches, not as a blanket preload before you open a source file.

**CWE pattern references** from `agent/references/code-vuln-patterns/` are trigger-gated by slot
type and code pattern: when your reading surfaces a signal (a parser over FILE-CONTENT, a crypto
call, memory allocation with attacker-influenced size, an auth check, ...), load the matching
file(s) yourself — list the directory or match filename to the observed signal. Do not load a
file for a class the batch does not exhibit.

**A skill's Extended Resources section is a menu, not a Step 2.** Read it when the skill's own
procedure sends you to a specific reference, not as a blanket read-everything-first pass. A
reference marked **(REQUIRED)** inside Extended Resources is required once that reference's
trigger fires for this dispatch — before the finding/disposition it informs is recorded — not
before you start reading.

**A toolchain-catchable pattern is a finding, not a skip.** `strcpy` into a fixed buffer,
`system(user_input)`, `free(p); *p = 0;` — on an unaudited codebase no prior tool run has caught
these, so they are real exploitable bugs and you record them when you meet them. What changes is
where primary analysis time goes, not whether the bug is reported: spend it on the multi-function
and semantic patterns a tool cannot reach, which is what `agent/references/code-vuln-patterns/`
calls "What You're Hunting (LLM-Advantage Patterns)". Reach for the matching reference rather than
improvising — it encodes CVE-grounded idioms and per-class blind spots, not supplemental depth.

---

## 9. Script Path Convention

The base convention (`vigil assess <subcommand>` from any directory, full-record versus bounded
nested JSON input, artifact paths, and assessment binding) is in
`agent/shared-specialist-core.md` "Script Path Convention". This section adds only the
code-specific quoting and banner rules below.

Shell-quote Java and Kotlin identifiers that contain `$` (anonymous classes, lambda
names, generated accessors — e.g. `com.example.Auth$$Lambda$1`): wrap in single quotes
or escape the `$` when passing to `grep`, `vigil`, or shell commands to prevent variable
interpolation.

**No `echo` section banners.** Do not use `echo "=== ... ==="` or similar shell banners for
progress markers, section headings, or breadcrumbs inside `vigil assess kali` invocations or
shell scripts that wrap them. The operator never sees that output, the command audit pipeline
captures the banner as the command stdout preview and pollutes FTS search, and `--intent`
on the kali call already records purpose in the durable audit row. `echo` is only legitimate
when its output is the command's real purpose (writing to a file, piping to another tool,
generating a payload). The web-mode rule lives in `agent/shared-constraints.md` §2; the same
rule applies in code mode wherever a kali wrapper is invoked from a code-analysis specialist.

---

## 10. Recording Format

Use the helper contracts as the canonical shape source before authoring durable JSON. Run
`vigil assess contract finding record` for finding payloads,
`vigil assess contract finding verify` before any verification/rebind, and
`vigil assess contract code-record analysis` for analysis-result payloads; this keeps agent output
aligned with backend validation instead of relying on copied prompt snippets.
`finding record` fills the initial lifecycle defaults (`workflow_status=active`, `verification_status=unreviewed`) when omitted — use those rather than setting lifecycle fields manually.
For later finding lifecycle changes, use the dedicated helpers instead of raw `post` or `patch`:
`finding verify` for confirm/downgrade/dispute decisions (`--status false_positive` with a completed
structured counter-check for a false-positive verification), `finding update --status draft` to reopen a
previously verified or false-positive finding, and `finding update` for non-verification metadata
or workflow updates. Reopening clears prior verification but deliberately leaves workflow status
`draft`; verification does not promote it. Before fuzz/complete, every retained draft must be
promoted explicitly with `finding update --status active`, merged, or killed. A confirmed-but-draft
finding remains a readiness blocker.

For code findings, put `cwe_id`, `impact`, `evidence`, `guards_evaluated`, `remediation`,
`slot_type`, `steps_to_reproduce`, and supported CVSS facts under `details`. Use `taint_path` for
taint findings; for operation/state/lifetime defects use the supported sequence plus
`caller_feasibility`/`precondition_analysis` as applicable. For analysis rows, include the fetched `queue_item_id`,
`agent_name`, and `lease_token`;
the backend derives `file_id` from that queue item and rejects mismatches when `file_id` is
supplied as an optional consistency check. Renew long-running claims with
`vigil assess code-dispatch heartbeat <item-id> <agent-name> <lease-token>` at least twice inside
the operator's stale-reset window (the standard 10-minute window means heartbeat every 5 minutes
or less); results and closeouts using a reclaimed lease are rejected.
For `finding` and `suspicious`, record inline `evidence` or an engagement-owned `evidence_ref` on
the current same-disposition result before closeout. A `clean` closeout carries non-empty family
coverage and review notes. These disposition-specific gates preserve evidence-backed queue state
while allowing proof to live inline or in a durable artifact.

**Report-readiness mandate:** `check-phase-readiness --phase report` blocks the final report if any
verified finding is missing `cvss_score`, `cvss_vector`, `steps_to_reproduce`,
`remediation`, `impact`, or `evidence`. Include all six fields at recording time so
findings pass readiness without a remediation loop. CVSS must align with severity per
the ranges in `agent/shared-specialist-core.md` ("Finding IDs and the `finding record`
Contract").

---

## 11. Mandatory Closing Sequence

The closing-sequence wrapper (resume-brief framing, unlinked-notes registration rule,
`agent done`/`agent close` being operator-only, idempotent/checkpoint handoff framing, and the
plan-state digest) is in `agent/shared-specialist-core.md`. That wrapper applies to every code
role; the exact numbered verb list is role-specific, not one universal sequence, because only
`code-vuln-hunter` fetches and completes a queue item (`code-record analysis` /
`code-dispatch done`) — `code-architect`, `code-variant-hunter`, `code-vuln-verifier`, and
`code-fuzz-engineer` never hold a queue lease and have no `code-record analysis` step in their
closing sequence. Every role's list is drawn from the same pool of backend writes this file
documents (`finding record` §4, `code-record analysis` §6, `agent handoff` + `render-handoff`),
instantiated with that role's own agent-name and ordering — see your role file's own `### Closing
verbs` or `## Mandatory Closing Sequence` section for the exact sequence you run.

---

## 12. Coverage Integrity

The backend derives callable coverage from exact structural references on current, unreplaced
analysis receipts and reports it as `coverage_integrity` on the `code-dispatch done` response.

1. Record grouped source receipts via `code-record analysis` BEFORE calling
   `code-dispatch done <item-id> <agent-name> <lease-token> <disposition> <coverage-json>
   [notes]` — the backend derives coverage from receipt anchors that already exist at
   completion time, not from the coverage JSON alone.
2. `functions_analyzed` is advisory self-reporting, never coverage proof. Each file's authoritative
   numerator is the union of exact `callable_refs` that name that file, including references from
   a current cross-file `call_chain`; `reviewed_spans` prove checked source that has no structural
   callable identity but do not invent callable coverage.
3. Cross-file callable coverage does not transfer lease ownership. Only a source receipt anchored
   to the claimed queue file can close its non-skipped review; referenced files retain
   their own queue, disposition, evidence, and closeout obligations.
   A sealed zero-byte file uses the explicit empty-file review form in `vigil assess contract
   code-record analysis`; never invent a source line.
4. Not-applicable entries (`disposition: "not_applicable"`) are exempt from the backing check.
5. Use `analysis_effort` in per-file coverage detail as the trustworthy effort projection: it is
   derived from current receipt rows, evidenced receipts, distinct structural callable bindings,
   and the structural-index function total rather than the submitted effort number alone.
