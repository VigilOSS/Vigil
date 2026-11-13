# Shared Subagent Constraints -- Code Analysis Mode

Load this file with your role file and `agent/shared-specialist-core.md` before any source code
work; the core's "Load Sequence" covers on-signal skill loading. These rules apply to every code
analysis specialist regardless of role.

---

## 1. Authorization and Scope

All source code under analysis is authorized for deep white-box security review. Your dispatch
names the phase and the files in scope (module, classification level, queue items); ask the
operator before analyzing files outside the scoped repository.

### Declared live target in a code dispatch

Keep CODE-phase execution away from every host declared in `scope.json`; ordinary network access
for source retrieval, dependency installation, documentation and CVE research continues, because
code mode is a workflow boundary, not an offline sandbox. When Vigil recognizes a declared target in
a CODE-phase command it warns and still runs it. Treat the warning as a routing correction: stop
target contact and hand deliberate live validation to the web track once the operator authorizes
it. No warning is not proof that a destination is safe. `scope.json.code_target_contact_policy:
warn-do-not-contact-declared-hosts` records this contract; it denies no tool and changes no other
rule.

### Runtime Identity authority fields

A Runtime Identity field is an authority grant, not context you can look up. When
`authorized_phase` reads `MISSING (malformed dispatch)` or is absent, stop before reading source,
name the field, and ask for a corrected packet. Do not derive it from the engagement phase, your
role, or which fields are present, and do not run whichever branch needs the fewest fields: on a
phase-selected role that branch records no receipts, so the dispatch looks normal while its files
stay unreviewed.

### Code Source Identity

Every code dispatch carries a `## Code Source Identity` block right after Runtime Identity, rendered
by `agent start` from one active backend repo record (`repo_id`, `repo_generation`,
`source_manifest_digest`, the sealed `snapshot_path`, the generation-bound structural manifest, and
`ctags_path` or `unavailable`). Analyze beneath `snapshot_path`; the sealed roots under "Other
Sealed Repositories" are context, cited with their repository and generation (`vigil assess fetch
code/repos` lists more when the preview is incomplete), while finding and coverage ownership follow
this assignment. `source_origin_path` is provenance, never an analysis root. Resolve structural and
ctags artifacts only through this block, because a plausible path from an older generation holds
correct-looking but stale facts. If the block is incomplete, its digest differs from the active
record, or it or a bound artifact names another generation, return a blocked handoff for
reingest/reindex instead of mixing generations.

Phase 2–4 dispatches also need the complete threat-model envelope with `current: true` and the same
`repo_generation`/`source_manifest_digest`; a clipped summary orients but replaces neither the
envelope nor the structural manifest.

---

## 2. Source Code Is Primary

Read the source beneath `snapshot_path`; the structural index navigates, it never stands in for
a read or limits what you look for. Use the function map and the file's `<top-level>` segments
(`top_level_segments`) as the completeness anchor, and entry points, exports, sinks and import
targets to prioritize. When a load-bearing callee or guard sits outside your batch, find and read it
yourself with ctags and `rg` inside `snapshot_path` rather than asking the operator or guessing.

### Structural-index resolution

Open `structural_index_manifest_path` from the Code Source Identity block, confirm its `schema`,
`repo_id`, `repo_generation` and `source_manifest_digest` match the block, then resolve the
repo-relative path through `path_to_index` and read that JSON; never guess hashed filenames or
match on basename.

Each `path_to_index` value is relative to the `structural-index/` root, six levels above the
manifest
(`structural-index/<repo_id>/<generation>/<path_version>/<source_manifest_digest>/<indexer_digest>/<structural_input_digest>/manifest.json`),
so joining it to the manifest's directory reads nothing. Every value ends in
`files/<hashed-basename>`, so `<manifest-dir>/files/<basename of the value>` is the same artifact. A
"no such file" on a path present in `path_to_index` is this join, never a missing index.

The artifact is compact JSON, one top-level key or array record per line, with `call_sites` last.
A `call_sites` record names `caller`, `callee`, and `line`. A PHP call site adds `receiver` when it
has one; other languages keep it in `callee`. Any call site adds `passes_caller_params: true` only
when an argument forwards a caller parameter.

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

Read source beneath `snapshot_path` (or a listed sealed reference root, for context) with host Bash
or client file tools; reading source is not target work and needs no `vigil assess kali`. Pass the
absolute sealed root as the search/read root in every command, because a client can reset the
working directory between calls and a relative path then silently searches another tree. The
mutable origin checkout is never an analysis root.

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

Before the first build, harness launch, or repository-built binary execution, load the runtime
path-mapping and containment contract in `agent/skills/code-fuzz-campaign/SKILL.md` ("Tools and
execution boundary"); an input that cannot be mapped beneath the engagement mount ends in a blocked
handoff, never a host-side fallback.

**When code analysis does reach for `vigil assess kali ...`** (a fuzz campaign or binary-triage
pass that runs a tool through the runtime), the same coverage-map discipline from
`agent/shared-constraints.md` §2b applies unchanged: search `command-run list --q <keyword>
--show-matches` before probing, and fetch a candidate's preview with `command-run get <id>` before
citing it — `success=true` only means `return_code=0`, not that the run answered your question.
Pass `--phase` as the code audit tag of the phase the dispatch was authorized for: `kali --phase`
rejects the track phase names the Runtime Identity can carry, so `ingest` → `code-ingest`,
`classify-map` → `code-classify`, `hunt` → `code-hunt`, `verify-variant` → `code-verify`, and
`fuzz` → `code-fuzz`; a packet that already carries the tag (`code-verify` on claimed proof work)
passes it unchanged. The code-specific reading of "new coverage": the only campaign to skip is
the identical binary + corpus + flags combination already run to completion — a new sanitizer,
dictionary, seed corpus, or harness change is new coverage even against the same target. Full
decision table:
`agent/references/runtime-guides/command-history-auditing.md`.

Git provenance and churn are ingest-time metadata on the backend repository record. The sealed
snapshot deliberately contains no `.git`, and specialists do not run ambient Git against the
mutable origin. Use the supplied `git_head`, branch/dirty state, and churn summary as historical
context; they are navigation evidence, not source identity or vulnerability proof. The one history
surface is `vigil assess code-history`, which `code-architect` runs: it reads only ancestors of the
HEAD the sealed snapshot recorded, within recorded budgets, and writes receipts under
`tools/analysis-state/code-history/`. Other roles read those cited artifacts and run no Git.

### Cross-Reference Tools (priority order)

1. **ctags** for definitions: `grep '^<symbol>\t' "$ctags_path"` (path from the Code Source
   Identity block) returns the file and line.
2. **`rg`** for callers, data flow and anything ctags cannot resolve, for example
   `rg -n 'packet_read_with_status\(' --type c "$snapshot_path"`. Its `-r` is `--replace`
   (`rg -rn foo` prints `n` in place of each match), it skips hidden paths and honours
   `.ignore`/`.rgignore`, so add `-uu` before treating an empty result as meaningful.
3. **Direct reads** of the location they point to.

---

## 4. Findings Use the Existing Backend

Record every finding through `vigil assess finding record` with your dispatch `--agent-id`;
use the allocated slug, never a hand-assigned ID. Before the first code finding write, load
`agent/references/runtime-guides/code-finding-recording.md`; it owns source binding,
deduplication, supported details, source-access prerequisites, replayable proof, and
captured-credential recording.
Reviewer source access is not attacker access. Preserve the actual supported caller, evidence,
and missing deployment assumptions.
Code and web findings share one backend; a prose-only finding is not durable state.

---

## 5. No Theoretical Findings

### Code hunting invariants

This section and the mandatory role skills own the code-track hunting contract; the web hunting
rules are not a code-specialist load. Resolve scope and source identity before reading. Pursue the
strongest supported leads to a terminal evidence-backed disposition, kill a disproved lead with
the exact guard/type/path evidence, and retain a genuinely inconclusive lead as `suspicious` or
`needs-context` rather than converting uncertainty into `clean`. Account durably for every scoped
file and analyzed function; an empty query, truncated index, failed tool, or absent in-repo caller
is not proof of absence. Before you write that a caller, guard, sink, registration, or file is
absent, rerun the same search (same root, flags, and filters) for something you know is present,
such as the symbol's own definition, and cite both commands; an empty result counts only when that
control matches. A count is not an absence and carries the same receipt. Before you write how many
call sites, callers, or guard sites exist, run the `-l`/`-c` enumeration over the whole write path
and paste it; an eyeballed "invoked only at one site" suppresses the other callers that reach the
same sink.

Before recording or escalating a finding, prove the applicable shipped product path, exact taint
trace or supported operation/state/lifetime sequence, failed invariant, feasible preconditions,
and concrete harmful outcome. Apply the **net-new capability test**: if the alleged primitive only
repeats what the same caller-controlled source, repository, configuration, tenant, credentials, or
privilege already permits, it creates no new security capability and cannot justify the claimed
severity. Escalation requires a different trust context, victim/asset, restriction bypass, or
security property. The threat model's trusted inputs are advisory: treat a source as
attacker-influenced when the code shows a less-trusted writer or the threat model cites no reason
for trusting it, and an authenticated principal as an attacker for anything beyond its recorded
`actor_capabilities`. Preserve replayable evidence, check sibling paths and composable chains when a
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

A named resource limit (request cap, spool buffer, decompression limit, timeout, negotiation
limit) is not by itself a security boundary. Before rating a resource-limit bypass High/Critical,
apply "Protocol/Resource-Limit Severity Check" in `agent/skills/code-finding-verification/SKILL.md`.

---

## 6. Account For Every Reviewed Source Region

Coverage is structurally attributable. `code-vuln-hunter`, the one role that holds queue leases,
owns the analysis-receipt, disposition, and lease-close contract ("Queue Lease and Receipt
Contract" in its role file). The other code roles hold no queue lease and record what they review
through their own receipts (`code-record variant-check`, `code-record fuzz-campaign`,
`finding verify`).

Write-up depth can be proportional, the read cannot: attack-facing, sink-bearing, stateful, or
ambiguous code gets full reasoning, and a verified-mechanical helper gets a concise disposition only
after it was read in full and checked against sinks, trust boundaries, and error paths (§7).
Grouping verified helpers never erases a finding, a suspicious hypothesis, an unresolved gap, or
its exact evidence.

---

## 7. Read Before You Conclude

Before recording `clean` on a function, guard, or callee you chose not to open, read the code that
verdict depends on and name the line, type, or branch that makes it true, plus every pattern you
checked and why it does not apply. Treat the call chain as one execution flow: a guard in function
A protects B only if every path that reaches B passes through it; otherwise B has to re-validate,
because one unguarded caller is enough to reach the sink.

---

## 8. Skills Are Methodology; References Load By Signal

Your role's one always-applicable skill is mandatory in your Load First list; everything else in
`agent/references/` loads when your reading surfaces the signal it matches (core "Load Sequence").

**CWE pattern references** from `agent/references/code-vuln-patterns/` are trigger-gated by slot
type and code pattern: when your reading surfaces a signal (a parser over FILE-CONTENT, a crypto
call, memory allocation with attacker-influenced size, an auth check, ...), load the matching
file(s) yourself — list the directory or match filename to the observed signal — before you record
the disposition it informs. Skip a file for a class the batch does not exhibit. This is the one
statement of the rule; role prompts and skills point here. `rate-limit` has no file of its own: its source checks
live in `agent/references/code-vuln-patterns/business-logic.md` under "6. Attempt limits on OTP,
MFA, passcodes and password reset".

A skill's Extended Resources section is a menu: a reference marked **(REQUIRED)** there is required
once its trigger fires — before the finding or disposition it informs is recorded — not before you
start reading.

**A toolchain-catchable pattern is a finding, not a skip.** `strcpy` into a fixed buffer,
`system(user_input)`, `free(p); *p = 0;` — on an unaudited codebase no prior tool run has caught
these, so they are real exploitable bugs and you record them when you meet them. What changes is
where primary analysis time goes, not whether the bug is reported: spend it on the multi-function
and semantic patterns a tool cannot reach, which is what `agent/references/code-vuln-patterns/`
calls "What You're Hunting (LLM-Advantage Patterns)". Reach for the matching reference rather than
improvising — it encodes CVE-grounded idioms and per-class blind spots, not supplemental depth.

---

## 9. Script Path Convention

The base convention is `agent/shared-specialist-core.md` "Script Path Convention". Code adds two
rules:

- Shell-quote Java and Kotlin identifiers that contain `$` (`'com.example.Auth$$Lambda$1'`) when
  passing them to `grep`, `vigil`, or the shell, so they are not interpolated.
- No `echo "=== ... ==="` progress banners inside `vigil assess kali` calls or the scripts that wrap
  them: the audit pipeline stores the banner as the command's stdout preview and pollutes search,
  and `--intent` already records purpose. `echo` is fine when its output is the point (a file, a
  pipe, a payload).

---

## 10. Recording Format

`vigil assess contract finding record`, `finding verify` (verification, false-positive, dispute,
and rebind shapes), and `code-record analysis` own the durable JSON shapes. Let `finding record` fill the initial lifecycle defaults. Later changes go
through `finding verify` (the verifier procedure is `code-vuln-verifier` "FP Persistence") or
`finding update` (metadata, workflow, reopening with `--status draft`); a reopened draft is
promoted with `finding update --status active`, merged, or killed before fuzz/complete.

For code findings, put `cwe_id`, `impact`, `evidence`, `guards_evaluated`, `remediation`,
`slot_type`, `steps_to_reproduce`, and supported CVSS facts under `details`, with `taint_path` for
taint findings or the supported sequence plus `caller_feasibility`/`precondition_analysis` for
operation/state/lifetime defects. Record `cvss_score`, `cvss_vector`, `steps_to_reproduce`,
`remediation`, `impact`, and `evidence` at write time: report readiness needs all six on every
verified finding, and you hold the evidence now.

---

## 11. Mandatory Closing Sequence

Your role prompt lists the closing verbs you run; the wrapper that applies to every role is
`agent/shared-specialist-core.md` "Mandatory Closing Sequence — wrapper". Only `code-vuln-hunter`
holds queue leases, so only its sequence has `code-record analysis` and `code-dispatch done`.
