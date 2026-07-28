# Shared Subagent Constraints -- Code Analysis Mode

Load this file as part of your Load First set -- together with your role file and
`agent/shared-specialist-core.md` -- before any source code work. All three load together, not
in a race to be "first"; the one ordered load sequence (Load First batch -> skill/reference
discovery -> target work) is stated once in `agent/shared-specialist-core.md` "Load Sequence".
These rules apply to every code analysis specialist agent regardless of role.

> **Specialist context isolation, finding-recording format, closing-sequence wrapper, and output hygiene:** see agent/shared-specialist-core.md (in your Load First). This role adds only its own closing verbs below.

---

## 1. Authorization and Scope

All source code under analysis is authorized for deep security review.
This is a white-box engagement. You have full access to read and analyze all source code files.

Use the operator-injected code dispatch context before starting. Confirm:

- Repository path and name from the active repo record or code-index manifest
- Dispatch phase (ingest/classify-map/hunt/verify-variant)
- Which files are in scope for your current dispatch (module, classification level, queue items)

Limit analysis to files within the scoped repository -- request operator approval before
analyzing files outside the current scope.

---

## 2. Source Code Is Primary

You receive actual source code files -- read directly from the filesystem with structural
index navigation when available -- not JSON metadata about code. Read the code directly.
Start with the function map as your completeness anchor, then use entry points, exports,
sinks, and import targets as advisory navigation aids to prioritize where you deepen.
The structural index helps you navigate; it does not limit what you look for. Do not
substitute metadata summaries for source reads.

If code beyond the provided file batch is needed, use ctags + grep + Read to find it yourself.
Full filesystem access is always available. Never guess at the behavior of code you have
not read. Never request operator-mediated expansion when you can resolve it with a file read.

### Structural-index resolution

Resolve a file index through `tools/analysis-state/structural-index-manifest.json`:
select `repos.<repo_key>.manifest_path`, open that per-repo manifest, then resolve the
repo-relative file path through `path_to_index`. Read that referenced JSON; do not guess
hashed filenames or scan for a basename collision. Phase 0 owns the generated layout, while
this is the canonical consumer lookup rule for every code specialist.

---

## 3. Full Filesystem Access

Source code is read directly from the local filesystem via host Bash or Claude Code tools.
This is NOT target-facing network work -- `vigil assess kali` is not needed for reading source files.

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
| `Read` | Read source files |
| `rg` | Search code patterns, find call sites |
| `Glob` | Locate files by pattern |
| `python3`, `jq`, `sqlite3` | Data processing and backend interaction |
| `git log`, `git blame`, `git diff` | History analysis |

### Cross-Reference Tools (priority order)

1. **ctags index** (fast definition lookup -- generated during code-ingest)
   - Query: `grep '^<symbol>\t' <repo>/tags` to find definition file and line number
   - Example: `grep '^packet_read_with_status\t' /path/to/repo/tags` returns the file and line
   - Use for: locating function/type definitions across the codebase

2. **grep/rg** (call sites, patterns, and anything ctags cannot resolve)
   - Use for: finding all callers, tracing data flow, cross-module references
   - Example: `rg 'packet_read_with_status\(' --type c` for call sites

3. **Direct file reads** when ctags/grep point to a location

When your analysis references a cross-module function that is load-bearing for the
vulnerability assessment, resolve it yourself by looking up the definition with ctags,
reading the file, and continuing your analysis. You have full filesystem access -- use it.

---

## 4. Findings Use the Existing Backend

Code analysis findings record in the **same** `assessment_findings` table as web findings.
Use `vigil assess finding record <agent-name> <finding-json-file>` to record.
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

**Title formula:** the canonical formula owned by `agent/shared-specialist-core.md` ("Finding IDs
and the `finding record` Contract") applies unchanged: `[Bug Class] in [endpoint] allows [attacker
role] to [impact] [victim/scope]`. For code findings, `[endpoint]` is realized as `[file:line or
component]` (e.g., `lib/url.c:547`).

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
- `defect_family` uses CWE-based names: `buffer-overflow`, `integer-overflow`, `use-after-free`, `injection`, `race-condition`, `crypto-misuse`, `auth-bypass`, `format-string`
- `details.cwe_id` must be a specific CWE ID (e.g., `CWE-122`, not generic `CWE-119`)
- `source_name` is your agent name (e.g., `code-vuln-hunter`)
- `details.evidence` must include: the vulnerable code snippet, the taint path from untrusted input to sink, and why existing guards are insufficient
- `details.entry_point` and `details.sink` decompose the taint path into structured fields — populate both alongside the narrative `details.taint_path`
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
should ALSO be recorded via `vigil assess post credentials <credential-json-file> --status
discovered`, alongside the normal `finding record` call for the code finding itself. Recording a
discovered credential automatically flags a candidate finding and, when the secret is a session
artifact (a session-hint cookie or a bearer/JWT), mints a usable identity from it and cross-links
the two — so on a mixed code+web engagement the secret auto-surfaces as a usable identity for the
parallel web track instead of sitting inert in a code finding's `details`.

---

## 5. No Theoretical Findings

The same rule from web testing applies to code review:
- **Can this be exploited by an attacker controlling the identified input?** If yes, it is a finding.
- **Is the vulnerable code reachable from an external entry point?** If no, it is not a finding (yet).
- A missing bounds check in dead code is not a finding.
- A potential overflow that requires impossible input is not a finding.
- Document the specific attacker-controlled input and the concrete impact.

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

## 6. Account For Every Analyzed Function

Every function you analyze must still receive exactly one disposition because the backend
records one result per function:

- `finding` -- Confirmed vulnerability with CWE, evidence, and exploitability assessment
- `suspicious` -- Anomalous pattern needing variant analysis or deeper context to confirm
- `clean` -- No vulnerabilities found in current analysis
- `needs-context` -- Analysis blocked on missing information (specify exactly what is needed)

Coverage must be explicit, but write-up depth can be proportional:
- Attack-facing, sink-bearing, stateful, or ambiguous functions need full reasoning.
- Obviously mechanical helpers can use concise `clean` dispositions once you have verified they
  do not hide sinks, trust-boundary assumptions, or material error behavior.

Proportional write-up is never a license to skip the read or the check (§7): every function,
mechanical-looking or not, is read in full and checked against sinks/trust-boundaries/error paths
before its disposition prose gets to be brief. What shortens for a verified-mechanical helper is
the write-up, not the analysis behind it.

Record dispositions via `vigil assess code-record analysis`.
`finding` dispositions record durable finding state through `finding record`; `suspicious`,
`clean`, and `needs-context` still record through `code-record analysis` so backend coverage knows
which functions were reviewed and why the queue can advance or re-dispatch.

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
Loading every plausible reference up front is the failure mode this section exists to prevent —
under the old always-preload reading of this rule, a hunter dispatch spent ~109,000 tokens on
skill + 23 CWE pattern files before opening a single source file.

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

**References are not supplemental depth.** The `agent/references/code-vuln-patterns/` files contain:
- "What SAST Already Catches (Skip These)" -- so you do not waste time on patterns static tools find
- "What You're Hunting (LLM-Advantage Patterns)" -- the specific multi-function and semantic patterns only deep analysis can find
- Language-specific idioms and real CVE examples that ground pattern matching in reality

Reach for the matching reference rather than improvising the pattern when one exists for the code
in front of you — it encodes CVE-grounded idioms and the SAST-blind-spot split you would otherwise
have to rediscover per language.

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
`vigil assess contract finding record` for finding payloads and
`vigil assess contract code-record analysis` for analysis-result payloads; this keeps agent output
aligned with backend validation instead of relying on copied prompt snippets.
`finding record` fills the initial lifecycle defaults (`workflow_status=active`, `verification_state=unreviewed`, `verification_disposition=none`) when omitted — use those rather than setting lifecycle fields manually.
For later finding lifecycle changes, use the dedicated helpers instead of raw `post` or `patch`:
`finding verify` for confirm/downgrade/dispute decisions (`--disposition false_positive` with kill
metadata for a false-positive verification), `finding update --status draft` to reopen a
previously verified or false-positive finding, and `finding update` for non-verification metadata
or workflow updates.

For code findings, put code-specific proof fields under finding `details`: `cwe_id`, `impact`,
`evidence`, `taint_path`, `guards_evaluated`, `remediation`, `slot_type`,
`steps_to_reproduce`, `cvss_vector`, and `cvss_score` are all covered by the
`finding record` contract examples. For analysis rows, include the fetched `queue_item_id`,
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

The backend cross-references your `functions_analyzed` coverage claim against the actual
analysis-result rows recorded for that queue item, and reports the comparison back as
`coverage_integrity` on the `code-dispatch done` response.

1. Record each function's analysis result via `code-record analysis` BEFORE calling
   `code-dispatch done <item-id> <agent-name> <lease-token> <disposition> <coverage-json>
   [notes]` — the backend derives the comparison from result rows that already exist at
   completion time, not from the coverage JSON alone.
2. A `functions_analyzed` count is only as informative as the distinct `function_name` values
   behind it. The backend flags the claim as implausible when fewer than 30% of the claimed count
   has a matching distinct-function result row for that queue item — write one result row per
   function you actually dispose of, and the ratio takes care of itself.
3. Each file's coverage should reflect that file's own functions, entry chains, and code
   structure — assembled from this file's analysis, not adapted from another file's.
4. Not-applicable entries (`disposition: "not_applicable"`) are exempt from the backing check.
5. Use `analysis_effort` in per-file coverage detail as the trustworthy effort projection: it is
   derived from current nonsuperseded result rows, evidenced rows, distinct function names, and
   the structural-index function total rather than the submitted effort number alone.
