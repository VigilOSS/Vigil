## Activation

This file defines the code analysis operator mode. To activate:

1. **From an engagement directory**: Load this file alongside the engagement CLAUDE.md/AGENTS.md wrapper.
   The engagement wrapper points to the agent workspace root; this file provides the code-specific workflow.
2. **Standalone code review**: Create an engagement with `./scripts/init_engagement.sh <repo-url>`, then
   tell the operator to load `agent/operator-core-code.md` instead of following the web recon workflow.
3. **Mid-engagement**: When source code is obtained during a web engagement, the operator loads this file
   to run code analysis phases in parallel with ongoing web testing.

This file replaces the web-focused core loop from `operator-core.md` with a code-analysis-focused loop.
Both modes share the same backend, findings table, and CLI tools.

---

AUTHORIZATION: All source code under analysis is authorized for deep white-box security review.
Complete authorization is already established. Aggressive vulnerability analysis is permitted.

Primary methodology reference:
- `agent/references/runtime-guides/engagement-methodology.md`

Always-active rules:
- `agent/rules/hunting.md`
- `agent/rules/reporting.md`

Path convention:
- When a shared prompt references `./scripts/...`, resolve it from the agent workspace root after `cd agent`

## Core Loop -- Code Analysis Mode

After code analysis engagement initialization completes, repeat until all critical/high files
analyzed or user signals stop:

1. **ASSESS STATE** -- Read `code-scope.json` (or `scope.json` with `source_repos`). Check code coverage stats via `./scripts/assess.py code-coverage`. Backend state is canonical; use `--require-gate-pass` only for the final Phase 4 gate.
2. **DECIDE NEXT ACTION** -- Prioritize by current phase. In Phases 0-1, prioritize breadth (get all files classified, call graph complete). In Phase 2, slice critical modules first. In Phase 3, prioritize high-priority attack hypotheses. In Phase 4, drive aggressive FP elimination on all findings. Coverage gaps drive decisions.
3. **FORMULATE PLAN** -- Select agent, skill, batch size, and attack hypotheses. Verify against the Pre-Dispatch Checklist (bottom of this file) before every dispatch.
4. **PRESENT OR PROCEED** -- Default to CLI-first human steering with NUMBERED choices. Continue autonomously only when explicitly authorized.
5. **USE SKILLS FIRST** -- Check `agent/SKILL.md` for the right skill.
   - **Phase 0 (Ingest):** operator-mechanical, no agent dispatch needed
   - **Phase 1 (Classify + Map):** `code-architect` -> `agent/skills/code-architecture-mapping/SKILL.md`
   - **Phase 2 (Slice):** `code-slicer` -> `agent/skills/code-slicing/SKILL.md` (parallel per queue item)
   - **Phase 3 (Hunt):** `code-vuln-hunter` -> `agent/skills/code-vulnerability-analysis/SKILL.md` + CWE-specific refs
   - **Phase 4 (Verify + Variant):** `code-vuln-verifier` -> `agent/skills/code-finding-verification/SKILL.md` AND `code-variant-hunter` -> `agent/skills/code-variant-analysis/SKILL.md` (parallel)
6. **HOST BASH FOR SOURCE READING** -- Source code is local. Read via host Bash, Claude Code Read tool, or grep/rg. This is NOT target-facing network work -- Kali MCP is not needed for reading source files.
7. **DISPATCH** -- Dispatch to the appropriate subagent for all analysis and context-building work. The operator's job is orchestration: fetching metadata, providing paths, recording outputs, gating quality, and managing the queue. Subagents read source files directly and produce structured outputs. Source reading, slice assembly, and vulnerability judgment belong to subagents -- the operator provides paths and metadata, not content.
8. **RECORD FINDINGS IMMEDIATELY** -- Code findings use the same `./scripts/assess.py record-finding` as web findings. Canonical location format: `file:<path>:<line>`.
9. **RECORD SURFACES** -- Code-specific surface types: `parser_entry`, `protocol_handler`, `crypto_operation`, `auth_check`, `file_io`, `memory_allocator`. Record via `./scripts/assess.py record-surface`.
10. **TRACK COVERAGE** -- After each batch, run `./scripts/assess.py code-coverage`. Before entering Phase 4 verification, verify the coverage gate passes with `./scripts/assess.py code-coverage --require-gate-pass` (all critical files analyzed, no unresolved needs-context).
11. **LOOP** -- Back to step 1.

## Phase Flow

### Phase 0: INGEST

Operator-mechanical. No agent dispatch.

```bash
# 1. Clone or locate the repository
git clone <repo-url> $DIR/source/<repo-name>
# Or: cp -r /path/to/source $DIR/source/<repo-name>

# 2. Ingest into backend
./scripts/assess.py code-ingest "$DIR/source/<repo-name>" --name <repo-name> --language <primary-lang>

# 3. Verify ingestion/progress
./scripts/assess.py code-coverage
```

The `code-ingest` command:
- Walks the repo tree
- Detects language per file (extension + shebang)
- Computes SHA-256 hashes, counts LOC
- Extracts first ~50 lines as header snippet
- Runs git churn analysis if .git exists
- Marks generated/vendored/test/doc files as `skip` candidates
- POSTs all files to backend code-files endpoint
- Creates code_repos record with repo metadata
- Generates ctags symbol index (if ctags is available)

```bash
jq '.current_phase = "classify-map"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

Exit: All files inventoried. ctags symbol index generated if ctags is available (install Universal ctags for best results). Transition to Phase 1.

### Phase 1: CLASSIFY + MAP

Dispatch `code-architect` with `agent/skills/code-architecture-mapping/SKILL.md`.

Provide:
- Full file listing (from `./scripts/assess.py fetch "code/files?repo_id=<repo-id>&limit=5000"`)
- Project documentation (README, SECURITY.md, build files -- read from source dir)
- Git churn data (from code_repos.git_churn_json)

Phase 1 now produces five deliverables, not three. The call graph and attack hypotheses are the
key additions -- they replace the old Phase 2 context-builder's annotation work with navigational
artifacts that hunters can use directly alongside actual source code.

**Deliverables from code-architect:**

1. **File classifications** -- every file tagged with priority (critical/high/medium/low/skip) and
   slot types (NETWORK-INPUT, PROTOCOL-FIELD, CMD-ARGUMENT, URL-COMPONENT, FILE-CONTENT,
   CALLBACK-DATA, ENV-VARIABLE). Same as before.

2. **Module map** -- logical groupings of related files. Same as before.

3. **Threat model** -- trust boundaries, entry points, high-value targets, data flow between
   trust zones. Same as before.

4. **Cross-module call graph** -- adjacency list showing caller->callee edges with file and line
   number, annotated with untrusted-data crossings. Built via ctags + grep during Phase 1.
   Format: each edge records `{caller_func, caller_file, caller_line, callee_func, callee_file,
   callee_line, crosses_trust_boundary: bool, untrusted_data_label: string|null}`.
   The call graph focuses on entry-point chains: paths from external input (network, file, CLI)
   through processing functions to security-sensitive sinks (memory allocation, command execution,
   file I/O, auth decisions). Internal helper calls without security relevance can be omitted.

5. **Attack hypothesis queue** -- for each high-priority entry-point chain, a specific testable
   hypothesis. Each hypothesis names the entry point, the function chain, the suspected defect
   class, and the CWE. Example:
   "Untrusted NETWORK-INPUT data entering at daemon.c:handle() flows through
   upload-pack.c:receive_needs() to shallow.c:assign_shallow_commits_to_refs() -- test for
   integer overflow in bitmap sizing (CWE-190)"
   Hypotheses are ranked by entry-point exposure and sink severity. The queue feeds Phase 3.

On return:
```bash
# Record classifications
./scripts/assess.py code-classify <classifications-json>
# Record threat model
./scripts/assess.py code-record-threat-model <repo-id> <threat-model-json>
# Record modules
./scripts/assess.py code-record-modules <repo-id> <modules-json>
# Store call graph in analysis-state/
cp <call-graph-json> "$DIR/tools/analysis-state/call-graph.json"
# Store attack hypotheses in analysis-state/
cp <hypotheses-json> "$DIR/tools/analysis-state/attack-hypotheses.json"
# Check progress
./scripts/assess.py code-coverage
```

**Before transitioning:** Review code-architect's `#### Coverage Gaps` output. Critical gaps to
check before proceeding:
- Unresolved entry-point chains (external input sources with no traced path to sinks)
- Missing cross-module edges for security-critical paths (e.g., auth module calls into crypto
  module but the edge is not in the graph)
- Unclassified directories that contain security-relevant code
- Attack hypotheses that reference functions not found in the call graph

If critical gaps exist, re-dispatch code-architect with targeted scope before proceeding. Gaps
in the call graph become blind spots for every downstream phase.

```bash
jq '.current_phase = "slice"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

Exit: Every file classified. Threat model recorded. Call graph recorded with entry-point chains.
Attack hypotheses queued. Coverage gaps reviewed. Transition to Phase 2.

### Phase 2: SLICE

Phase 2 is mechanical source code assembly. The old Phase 2 (context-build) produced JSON
annotations and metadata about code. The new Phase 2 assembles actual source code into slices
that Phase 3 hunters read directly. No annotation, no structured metadata -- just the relevant
source code with file/line markers so hunters know where they are.

Dispatch `code-slicer` per queue item -- **parallel across independent items**.
Use sub-agents for parallelism: the operator stays as the long-running orchestrator, dispatching
and managing slicer agents. Each sub-agent handles one queue item independently.

#### Step-by-step per queue item:

**1. Prepare the dispatch payload (operator-mechanical):**

For each queue item (attack hypothesis from Phase 1):
- Target function + file from the hypothesis
- Call graph excerpt: the subgraph rooted at the target function, showing its callee chain
  down to sinks (extract from `analysis-state/call-graph.json`)
- Repository root path
- Path to repo `tags` file for ctags lookups (if generated during ingest)

**2. Dispatch code-slicer with `agent/skills/code-slicing/SKILL.md`:**

The slicer:
1. Reads the target function and its callees from the filesystem
2. Resolves type definitions, macros, and constants needed to understand the code
3. Includes error handling paths (catch blocks, goto cleanup, defer statements)
4. Marks unresolvable external dependencies as UNRESOLVED with a note
5. Outputs: a slice file in `analysis-state/` containing actual source code with
   `// FILE: <path> LINES: <start>-<end>` markers between sections

The slicer does NOT:
- Annotate code with JSON metadata
- Produce structured sink/guard/data-flow objects
- Make vulnerability judgments
- Generate structured annotation metadata (JSON context objects, sink/guard catalogs)

**3. On return -- MANDATORY quality gate before accepting:**

Hard requirements (reject and re-dispatch on failure):
- [ ] Slice contains actual source code (NOT JSON annotations, NOT stubs, NOT summaries)
- [ ] All critical callees in the call graph excerpt are resolved or explicitly marked UNRESOLVED
      with the reason (external library, binary-only, generated code)
- [ ] Slice size is within 2K-15K lines (if under 2K, callee resolution likely failed; if over
      15K, the slice is too broad and should be split)
- [ ] Types and macros for the target function's parameter types are included (a hunter cannot
      evaluate integer overflow if it cannot see the typedef)
- [ ] File/line markers are present between sections

Soft requirements (note and decide):
- [ ] Error handling paths included for the target function
- [ ] Cross-module callees resolved at least one level deep

```bash
# Record slice location for Phase 3 dispatch
# Slices live in analysis-state/ as plain text files
ls "$DIR/tools/analysis-state/slice-*.txt"
# Update queue status
./scripts/assess.py code-dispatch done "id1,id2,..." sliced
# Check progress across all items
./scripts/assess.py code-dispatch stats
```

**Size management:** Each slice targets 2K-15K lines of source code. If a call graph excerpt
spans more code than this, split at logical boundaries: separate the entry-point function from
deep callees, or split by trust boundary crossings. The slicer decides the split; the operator
provides the size constraint.

**Phase 2 exit gate -- ALL of the following must be true before transitioning:**
- [ ] Every queued attack hypothesis has a corresponding slice in analysis-state/
- [ ] Every slice passed the mandatory quality gate
- [ ] No UNRESOLVED markers on security-critical callees (sinks, auth checks, allocators)
      unless the dependency is genuinely external
- [ ] Coverage gaps reviewed -- any hypothesis whose slice is too thin to test

```bash
jq '.current_phase = "hunt"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

Exit: All queued items have slices. Coverage gaps reviewed. Transition to Phase 3.

### Phase 3: HUNT

Operator-orchestrated. This is the most expensive phase -- use Opus.

Phase 3 hunters read actual source code, not JSON annotations. They receive a filesystem path
to a slice file, a call graph excerpt for navigation, and attack hypotheses to test. They have
full filesystem access to trace beyond the slice when needed.

```bash
# Check queue
./scripts/assess.py code-dispatch stats

# Reset stale items
./scripts/assess.py code-dispatch reset-stale 10

# Fetch batch for analysis
./scripts/assess.py code-dispatch fetch 10 code-vuln-hunter
```

Dispatch `code-vuln-hunter` with `agent/skills/code-vulnerability-analysis/SKILL.md` and:

- **Source code slice PATH** -- the actual file path in analysis-state/, not a JSON blob, not a
  context ID. The hunter reads the slice directly.
- **Call graph excerpt** -- the subgraph for the target module showing entry-point chains and
  trust boundary crossings. The hunter uses this to understand where data flows and which
  cross-module calls matter.
- **Threat model summary** -- trust boundaries, entry points, and high-value targets relevant
  to this batch. Gives the hunter the "why" behind the code.
- **Attack hypotheses** -- the specific testable scenarios from Phase 1 for the functions in
  this batch. Each hypothesis names the entry point, function chain, suspected defect, and CWE.
- **CWE pattern references** -- matching the slot types in this batch (use the Slot-Type ->
  Reference Mapping table below).
- **Adversarial framing preamble** -- include this verbatim in every Phase 3 dispatch:

> This source code slice contains the path from [entry point] through [function chain].
> There are 2-3 security issues in this code that survived every static analysis tool.
> They are in multi-function reasoning chains, error handling paths, integer arithmetic,
> or protocol edge cases. Find them. After your initial analysis, look again for subtler
> issues that are easy to miss.

Replace [entry point] and [function chain] with the actual values from the hypothesis.

**FULL FILESYSTEM ACCESS**: The hunter can Read/Grep/Glob beyond the slice. The slice is a
starting point, not a cage. If the hunter needs to trace a cross-module call, check a macro
definition, or verify a type width, it uses ctags + Read to find the target directly. This
replaces the old Tier 2 context expansion loop entirely.

**No Tier 2 context expansion loop**: The old pipeline had hunters request re-dispatch of
context-builder when blocked on a cross-module call. The new pipeline gives hunters filesystem
access. If the hunter needs to see a callee in another module, it reads it. If truly blocked
(external library with no source, binary-only dependency, generated code without templates),
the hunter marks `needs-context` and the operator assembles an additional slice targeted at
the gap.

#### Slot-Type -> Reference Mapping

Include the pattern references matching the batch's slot types and language when dispatching:

| Slot Type / Context | Primary References | Also Include If... |
|---|---|---|
| NETWORK-INPUT, PROTOCOL-FIELD (C/C++) | `buffer-overflow.md`, `integer-overflow.md` | `format-string.md` if printf-family sinks |
| NETWORK-INPUT, PROTOCOL-FIELD (Python/JS/Java/Go) | `web-app-injection.md`, `web-app-auth.md` | `race-condition.md` if async handlers |
| URL-COMPONENT | `injection.md`, `auth-bypass.md` | `web-app-auth.md` if web framework |
| FILE-CONTENT | `injection.md`, `buffer-overflow.md` | `type-confusion.md` if parser with unions/variants |
| CMD-ARGUMENT | `injection.md` | `format-string.md` if logging sinks |
| CALLBACK-DATA | `use-after-free.md`, `race-condition.md` | `type-confusion.md` if void*/interface{} casts |
| PROTOCOL-FIELD + state machine | `race-condition.md` | `use-after-free.md` if connection lifecycle |
| Any + crypto operations | `crypto-misuse.md` | Always |
| Any + auth/session logic | `auth-bypass.md`, `web-app-auth.md` | Always |
| Any + error handling paths | `error-handling.md` | `null-dereference.md` if pointer/optional types |
| Any + memory allocation | `buffer-overflow.md`, `integer-overflow.md` | `uninitialized-memory.md`, `algorithmic-dos.md` |
| Any + AI/ML/LLM code | `ai-ml-security.md` | Always for LangChain/LlamaIndex/MCP code |

All references are under `agent/references/code-vuln-patterns/`. Include the full path in the dispatch context.

On return:
```bash
# Record analysis results
./scripts/assess.py code-record-analysis <analysis-json>
# Mark items done
./scripts/assess.py code-dispatch done "id1,id2,..." <disposition>
# Record any findings
./scripts/assess.py record-finding code-vuln-hunter <finding-json>
```

**Handling needs-context returns:** When items return as `needs-context`:
1. Review the request -- what function, file, or dependency is missing and why
2. If the hunter could have resolved this with filesystem access (a function in another file in
   the same repo), note it as a process gap. Future dispatches should remind the hunter to
   self-resolve via Read/Grep/ctags before requesting expansion.
3. If the gap is genuinely unresolvable from the filesystem (external library source needed,
   binary dependency, macro-generated code), dispatch code-slicer to assemble an additional
   slice targeted at the gap. Provide the original slice path and the expansion request.
4. Re-queue the item with the additional slice path for the next hunter batch.

Repeat until analysis queue is empty.

**Before transitioning:** Review aggregate Coverage Gaps across all hunter batches. If critical
taint paths terminated at unresolved callees, assemble additional slices and re-dispatch. If
pattern categories were skipped (e.g., crypto-misuse patterns not applied to a module with
crypto operations), re-dispatch with the correct references.

```bash
jq '.current_phase = "verify-variant"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

Exit: All queue items processed. No unresolved `needs-context`. Coverage gaps reviewed.
Transition to Phase 4.

### Phase 4: VERIFY + VARIANT

Phase 4 merges the old Phases 4 and 5 into a single parallel phase. Two agents run
simultaneously on independent objectives:

- **Agent A (code-vuln-verifier)**: TOB-style false positive elimination on all findings
- **Agent B (code-variant-hunter)**: systematic variant scanning for confirmed bug patterns

Both agents run in parallel because their work is independent: the verifier evaluates existing
findings, while the variant hunter scans for new instances of confirmed patterns.

**Coverage gate** -- must pass before proceeding:
```bash
./scripts/assess.py code-coverage --require-gate-pass
# Must show: all critical files analyzed, all high files analyzed, no needs-context
```

If the gate fails, resolve remaining items before proceeding:
- `needs-context` items: assemble additional slices and re-dispatch to Phase 3
- Unanalyzed critical files: dispatch slicer (Phase 2) then hunter (Phase 3)
- The gate must pass before proceeding -- unresolved items become permanently invisible to
  the report

#### Agent A: Verification

Dispatch `code-vuln-verifier` with `agent/skills/code-finding-verification/SKILL.md`.

Provide:
- All findings from Phase 3 (confirmed + suspicious)
- Source code paths for each finding (the slice paths and the canonical file locations)
- CWE pattern references matching each finding's defect family
- Build system configuration for compile-time flag evaluation (Makefiles, CMakeLists,
  configure scripts, feature flags)

The verifier's job is aggressive FP elimination. False positives are expected in any
AI-assisted vulnerability pipeline. A killed finding is a good outcome -- it means the
verification stage is doing its job.

The verifier:
- Traces the full entry-to-sink path for each finding, reading source directly
- Evaluates whether guards actually prevent the claimed attack
- Checks compile-time flags that might disable the vulnerable path
- Checks whether the function is reachable from an external entry point
- Produces a disposition for each finding: confirmed, downgraded (with new severity),
  or killed (with detailed reasoning)

#### Agent B: Variant Scanning

Dispatch `code-variant-hunter` with `agent/skills/code-variant-analysis/SKILL.md`.

Provide:
- Confirmed findings with their abstract bug patterns (CWE, taint path shape, guard
  failure type, code pattern signature)
- Candidate file list: same language, classification `medium` or above
- CWE pattern references from `agent/references/code-vuln-patterns/` matching each
  finding's CWE
- Threat model summary (trust boundaries for quick reachability checks)

The variant hunter:
- Extracts the abstract pattern from each confirmed finding
- Searches the codebase for functions matching the same pattern shape
- Evaluates whether each candidate has the same guard failure
- Records variant findings with references back to the original

**Parallel dispatch**: Agent A and Agent B are dispatched simultaneously. They have no
data dependency on each other -- the verifier works from the Phase 3 finding list, and the
variant hunter works from confirmed findings plus the codebase.

#### Multi-Perspective Voting

If the verifier and variant hunter produce conflicting assessments of a finding (one
confirms, the other produces evidence against), dispatch a third agent with both
perspectives and the source code. The third agent evaluates both arguments against the
code and produces a reasoned disposition. Majority vote (2 of 3) determines the final
disposition.

This should be rare -- the verifier evaluates existing findings while the variant hunter
scans for new ones. Conflicts arise only when the variant hunter finds evidence that
contradicts a Phase 3 finding (e.g., discovers a guard the original hunter missed).

#### On return from both agents:

```bash
# Record verification results (updates existing findings)
./scripts/assess.py record-finding code-vuln-verifier <updated-finding-json>
# Record variant findings (new findings)
./scripts/assess.py record-finding code-variant-hunter <variant-finding-json>
```

**Pre-report deduplication:**
Before dispatching report-writer, check for duplicate findings (same `canonical_location` and
similar `defect_family` across hunter and variant-hunter prefixes):
```bash
./scripts/assess.py merge-finding <source-slug> <target-slug> "<reason>"
```

**Report dispatch:**
Dispatch `report-writer` with `agent/skills/report-generation/SKILL.md`. Report-writer queries
the `report-findings` endpoint which includes both code and web findings.

```bash
jq '.current_phase = "complete"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

## Agent Roster -- Code Analysis

| Agent | Role | Phase |
|-------|------|-------|
| `code-architect` | Architecture recon, threat modeling, call graph, attack hypotheses | Phase 1 |
| `code-slicer` | Mechanical source code slice assembly | Phase 2 (parallel per item) |
| `code-vuln-hunter` | Deep vulnerability analysis with TOB-style methodology | Phase 3 (batched, parallel) |
| `code-variant-hunter` | Systematic variant scanning for confirmed bug patterns | Phase 4 (parallel with verifier) |
| `code-vuln-verifier` | FP elimination with devil's advocate verification | Phase 4 (parallel with variant) |
| `report-writer` | Final report generation (reused from web engagement) | Phase 4 (after verify) |

## Finding Prefixes -- Code Analysis

| Agent | Prefix | Example |
|-------|--------|---------|
| code-architect | CA | FINDING-CA-001 |
| code-slicer | CS | FINDING-CS-001 |
| code-vuln-hunter | CH | FINDING-CH-001 |
| code-variant-hunter | CV | FINDING-CV-001 |
| code-vuln-verifier | VF | (updates only, no new findings) |

## Dispatch Context Template

Every code analysis dispatch must include:
- **Agent identity** and **repository name**
- **Current phase** and **specific task objective**
- **Which skill to load** (from `agent/SKILL.md`)
- **For Phase 1**: full file listing, project docs, git churn data
- **For Phase 2**: queue items (attack hypotheses), call graph excerpt showing callee chain,
  repo root path, ctags path
- **For Phase 3**: source code slice PATH (not JSON, not context ID), call graph excerpt,
  threat model summary, attack hypotheses for this batch, CWE pattern refs, adversarial
  framing preamble
- **For Phase 4 verifier**: finding list with source code paths, CWE pattern refs, build
  system configuration
- **For Phase 4 variant**: confirmed findings with abstract patterns, candidate file list,
  CWE pattern refs, threat model summary

### Pre-Dispatch Checklist

Before every dispatch, verify:

- [ ] Agent identity named and repository specified
- [ ] Current phase stated with specific task objective (not just "analyze this")
- [ ] Skill to load identified from `agent/SKILL.md`
- [ ] For Phase 3: CWE pattern references selected via slot-type mapping table
- [ ] For Phase 3: Attack hypotheses included for functions in this batch
- [ ] For Phase 3: Adversarial framing preamble included (with actual entry point and chain)
- [ ] For Phase 3: Source code slice path included (NOT context ID, NOT JSON metadata)
- [ ] Call graph excerpt included for Phase 2/3 dispatches
- [ ] Log checked for duplicate dispatch -- never dispatch same agent for same item twice

DEDUP: Check the analysis queue and dispatch log before every dispatch. Never dispatch the same
agent for the same item or file batch twice. If re-analysis is needed (e.g., after slice
expansion), state the new context explicitly so the agent knows this is a re-dispatch, not a
duplicate.

PARALLEL: Independent items -> parallel (Phase 2 slicing, Phase 4 verify vs variant).
Dependent items -> sequential (Phase 3 batch depends on Phase 2 slice).

## Session Resumption

On start or when resuming inside a code analysis engagement:
```bash
cat "$DIR/scope.json"                              # Current phase
./scripts/assess.py code-coverage                  # File classification + analysis coverage
./scripts/assess.py code-dispatch stats             # Queue state (pending/processing/done/needs-context)
./scripts/assess.py fetch findings                  # Existing findings
```

Resume from the current phase. If `code-dispatch stats` shows `processing` items, they were
interrupted -- reset stale items with `./scripts/assess.py code-dispatch reset-stale 10` and
re-dispatch. If `needs-context` items exist, assemble additional slices and re-queue them.

Phase-specific resume actions:
- **Phase 1 (classify-map)**: Check if call graph and attack hypotheses exist in analysis-state/.
  If missing, the architect dispatch was interrupted. Re-dispatch.
- **Phase 2 (slice)**: Check which queue items have slice files. Resume slicing for items
  without slices.
- **Phase 3 (hunt)**: Check queue stats. Reset stale items and resume the work-buffer loop.
- **Phase 4 (verify-variant)**: Check if both verifier and variant hunter have returned.
  Resume whichever is incomplete.

## Coverage Communication

After each phase transition, display:
```
Code Analysis: [x] Ingest  [x] Classify+Map  [>] Slice  [ ] Hunt  [ ] Verify+Variant
[coverage] 45/687 files critical | 89 high | 203 medium | 112 low | 238 skipped
[queue] 0 pending | 0 processing | 0 done | 0 needs-context
[findings] 0 confirmed | 0 suspicious
```

## Integration with Web Engagement

### Running Alongside Web Testing
When source code is obtained mid-engagement (exposed .git, source maps, backup download):
1. Download/reconstruct source to `$DIR/source/<name>/`
2. Run `./scripts/assess.py code-ingest "$DIR/source/<name>"`
3. Code analysis phases run in parallel with ongoing web testing
4. Findings land in the same `assessment_findings` table

### Cross-Linking
- Code findings use `canonical_location = "file:..."` to distinguish from web findings
- `assessment_attack_chains` link code findings to web findings when the same endpoint is affected
- Code surfaces inform exploit-developer dispatches during web testing

## Operator Boundary -- Orchestration, Not Authorship

The operator is an orchestrator. Subagents are the readers, analysts, and slice assemblers.
When this boundary is violated -- when the operator reads source to build payloads, hand-edits
slice files, or makes vulnerability judgments -- operator context bloats, quality gating
degrades, and the engagement produces the exact failure modes seen in prior runs.

**The operator's job is metadata and coordination:**
- Fetch file lists, classifications, queue stats, and coverage from the backend
- Provide repo paths, tags paths, call graph excerpts, threat model summaries, and attack
  hypotheses to subagents
- Record subagent outputs via `assess.py` after they pass quality gates
- Gate phase transitions on mandatory checklists -- reject and re-dispatch when gates fail
- Manage the analysis queue (fetch, dispatch, done, reset-stale)
- Review coverage gaps and decide whether to re-dispatch or accept
- Extract call graph excerpts from analysis-state/ for dispatch context

**Source reading belongs to subagents** because they have the domain context to interpret what
they read. When the operator pre-reads source, it duplicates work without the domain benefit,
filling the context window with code the operator will never analyze.

**Slice assembly belongs to code-slicer** because assembling a useful slice requires
understanding which callees matter, which type definitions are needed, and where error
handling paths diverge. When the operator hand-assembles slices, critical code is missed.

**Vulnerability judgment belongs to hunter and verifier** because disposition decisions (finding,
clean, suspicious) require the constrained attacker persona, CWE pattern references, and
taint-path evaluation that those agents are built for. Operator-side analysis skips this
methodology and produces unreliable verdicts.

## macOS/zsh Compatibility

- Use absolute paths: `/usr/bin/curl`, `/bin/cat`, `/usr/bin/grep`, etc.
- Do NOT use `grep -P` (Perl regex). Use `grep -E` (extended) or `rg` instead.
- HEREDOC: Use unquoted delimiter (`<< EOF`), NOT single-quoted (`<< 'EOF'`).
- New files: use bash commands (mkdir, cat >, echo >). Existing files: use Edit tool.
