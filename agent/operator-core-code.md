## Activation

This file replaces the web-focused core loop from `operator-core.md` with a code-analysis-focused loop.
Both modes share the same backend, findings table, and CLI tools.

**When this file applies:**
- Standalone code engagement (`scope.json` has `engagement_type: "code"`, `current_phase: "ingest"`)
- Mid-engagement when source code is obtained (exposed `.git`, source maps, backup download) —
  code analysis phases run in parallel with ongoing web testing

**Expected state on entry:** engagement directory exists with `scope.json`, `source/` directory,
and orchestrator backend reachable. The operator reads `scope.json` to determine the current phase
and resumes from there.

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

1. **ASSESS STATE** -- Read `code-scope.json` (or `scope.json` with `source_repos`). Check code coverage stats via `./scripts/assess.py code-coverage`. Check CWE effort matrix via `./scripts/assess.py code-coverage --cwe-matrix` when in Phase 2B. Backend state is canonical; use `--require-gate-pass` only for the final Phase 3 gate.
2. **DECIDE NEXT ACTION** -- Prioritize by current phase. In Phases 0-1, prioritize breadth (get all files classified, call graph complete, structural index generated). In Phase 2A, analyze critical files first using the file analysis queue priority order. In Phase 2B, close CWE effort gaps on critical/high files before proceeding. In Phase 3, drive aggressive FP elimination on all findings. Coverage gaps drive decisions.
3. **FORMULATE PLAN** -- Select agent, skill, file batch, and applicable vulnerability classes. Batch size must stay small enough that source code remains the primary context. Use adaptive batching by module, entry-chain cluster, or sink family instead of a fixed-size handoff. Verify against the Pre-Dispatch Checklist (bottom of this file) before every dispatch.
4. **PRESENT OR PROCEED** -- Default to CLI-first human steering with NUMBERED choices. Continue autonomously only when explicitly authorized.
5. **USE SKILLS FIRST** -- Check `agent/SKILL.md` for the right skill.
   - **Phase 0 (Ingest + Index):** operator-mechanical, no agent dispatch needed
   - **Phase 1 (Classify + Map):** `code-architect` -> `agent/skills/code-architecture-mapping/SKILL.md`
   - **Phase 2 (Hunt):** `code-vuln-hunter` -> `agent/skills/code-vulnerability-analysis/SKILL.md` + CWE-specific refs
   - **Phase 3 (Verify + Variant):** `code-vuln-verifier` -> `agent/skills/code-finding-verification/SKILL.md` AND `code-variant-hunter` -> `agent/skills/code-variant-analysis/SKILL.md` (parallel)
6. **HOST BASH FOR SOURCE READING** -- Source code is local. Read via host Bash, Claude Code Read tool, or grep/rg. This is NOT target-facing network work -- Kali MCP is not needed for reading source files.
7. **DISPATCH** -- Dispatch to the appropriate subagent for all analysis work. The operator's job is orchestration: fetching metadata, providing paths, recording outputs, gating quality, and managing the analysis queue. Subagents read source files directly and produce structured outputs. Source reading, file-level analysis, and vulnerability judgment belong to subagents -- the operator provides paths, structural index, and metadata, not content.
8. **RECORD FINDINGS IMMEDIATELY** -- Code findings use the same `./scripts/assess.py record-finding` as web findings. Canonical location format: `file:<path>:<line>`.
9. **RECORD SURFACES** -- Code-specific surface types: `parser_entry`, `protocol_handler`, `crypto_operation`, `auth_check`, `file_io`, `memory_allocator`. Record via `./scripts/assess.py record-surface`.
10. **TRACK COVERAGE** -- After each batch, run `./scripts/assess.py code-coverage`. During Phase 2B, use `./scripts/assess.py code-coverage --cwe-matrix` to check per-file CWE effort scores against thresholds. Before entering Phase 3 verification, verify the coverage gate passes with `./scripts/assess.py code-coverage --require-gate-pass` (all critical files analyzed, no unresolved needs-context, CWE effort thresholds met).
11. **LOOP** -- Back to step 1.

## Phase Flow

### Phase 0: INGEST + INDEX

Operator-mechanical. No agent dispatch.

```bash
# 1. Clone or locate the repository
git clone <repo-url> $DIR/source/<repo-name>
# Or: cp -r /path/to/source $DIR/source/<repo-name>

# 2. Ingest into backend
./scripts/assess.py code-ingest "$DIR/source/<repo-name>" --name <repo-name> --language <primary-lang>

# 3. Generate structural index (optional -- graceful fallback if tree-sitter not installed)
./scripts/assess.py code-index "$DIR/source/<repo-name>"

# 4. Verify ingestion and index
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

The `code-index` command:
- Uses tree-sitter to parse each source file
- Produces per-file JSON in `tools/analysis-state/structural-index/` (filenames are `sha256(rel_path)[:16].json`) containing: function map (names, signatures, line ranges), entry points (main functions, request handlers, exported APIs), security sinks (memory operations, file I/O, command execution, crypto calls), and call sites
- Writes a manifest at `tools/analysis-state/structural-index-manifest.json` with aggregate statistics and a `path_to_index` mapping (file relative path -> index filename) so consumers can look up index files by path
- If tree-sitter is not installed, exits cleanly with a warning -- downstream phases operate without it using manual triage as a fallback
- The structural index accelerates Phase 2 hunting by giving the hunter a pre-built function map and sink catalog instead of requiring manual code triage

Output: `tools/analysis-state/structural-index/` directory with per-file JSON + manifest (when tree-sitter is available).

```bash
jq '.current_phase = "classify-map"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

Exit: All files inventoried. ctags symbol index generated if ctags is available. Structural index generated if tree-sitter is available. Transition to Phase 1.

### Phase 1: CLASSIFY + MAP

Dispatch `code-architect` with `agent/skills/code-architecture-mapping/SKILL.md`.

Provide:
- Full file listing (from `./scripts/assess.py fetch "code/files?repo_id=<repo-id>&limit=5000"`)
- Project documentation (README, SECURITY.md, build files -- read from source dir)
- Git churn data (from code_repos.git_churn_json)
- Structural index manifest (from `tools/analysis-state/structural-index-manifest.json`, if available) -- gives the architect pre-computed function counts, entry points, and sink statistics per file

Phase 1 produces six deliverables. The call graph and attack hypotheses provide navigational guidance for hunters. The file analysis queue ensures every critical/high file is analyzed regardless of hypothesis coverage.

**Deliverables from code-architect:**

1. **File classifications** -- every file tagged with priority (critical/high/medium/low/skip) and
   slot types (NETWORK-INPUT, PROTOCOL-FIELD, CMD-ARGUMENT, URL-COMPONENT, FILE-CONTENT,
   CALLBACK-DATA, ENV-VARIABLE). Each record must include backend `file_id`; `file_path` is
   helper context, not the primary key.

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

5. **Attack hypotheses (guidance)** -- for each high-priority entry-point chain, a specific testable
   hypothesis. Each hypothesis names the entry point, the function chain, the suspected defect
   class, and the CWE. Hypotheses are guidance for hunters, not the sole work items -- they help
   hunters prioritize within files, but files without hypotheses still receive full unconstrained
   analysis during Phase 2. This prevents hypothesis anchoring where the analysis scope narrows
   to what the architect predicted.

6. **File analysis queue** -- every critical and high file queued for Phase 2 analysis regardless
   of whether a hypothesis names it. Files without hypotheses appear with an empty
   `guidance_hypotheses` array. The queue is grouped by `batch_theme` (logical module) so the
   hunter can reason across related files in the same dispatch. Priority scores determine
   dispatch order. The on-disk queue artifact is a flat per-file JSON array -- no nested batch
   wrappers or glob patterns.

On return:
```bash
# Record classifications
./scripts/assess.py code-classify <classifications-json>
# Record threat model
./scripts/assess.py code-record-threat-model <repo-id> <threat-model-json>
# Record modules
./scripts/assess.py code-record-modules <repo-id> <modules-json>
# Ensure analysis-state exists for Phase 2 handoff artifacts
mkdir -p "$DIR/tools/analysis-state"
# Store call graph in analysis-state/
cp <call-graph-json> "$DIR/tools/analysis-state/call-graph.json"
# Store attack hypotheses in analysis-state/
cp <hypotheses-json> "$DIR/tools/analysis-state/attack-hypotheses.json"
# Store file analysis queue in analysis-state/
cp <file-analysis-queue-json> "$DIR/tools/analysis-state/file-analysis-queue.json"
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
- Critical/high files missing from the file analysis queue -- every such file must appear

If critical gaps exist, re-dispatch code-architect with targeted scope before proceeding. Gaps
in the call graph become blind spots for every downstream phase. Missing files in the queue
become permanently invisible to the analysis pipeline.

```bash
jq '.current_phase = "hunt"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

Exit: Every file classified. Threat model recorded. Call graph recorded with entry-point chains.
Attack hypotheses queued as guidance. File analysis queue complete with every critical/high file.
Coverage gaps reviewed. Transition to Phase 2.

### Phase 2: HUNT

Operator-orchestrated. This is the most expensive phase -- use Opus.

Phase 2 has two sub-phases: **2A (Broad Hunt)** discovers vulnerabilities through comprehensive
file-level analysis, and **2B (CWE Coverage Review)** closes effort gaps on critical/high files
to ensure thorough coverage across all applicable vulnerability classes.

Hunters read actual source files directly from the filesystem, navigating with the structural
index (when available), call graph excerpts, and attack hypotheses as guidance. They have full
filesystem access to trace beyond the provided file batch when needed.

Adaptive batching is part of the method, not a convenience:
- Default to 1 logical module or 1-3 tightly related files per hunter dispatch
- Shrink further when files are large, parser-heavy, stateful, or the supporting metadata would
  crowd out the actual source
- Widen only when multiple files form one tight entry-chain and the added context materially
  improves reasoning
- Treat fetch size as queue mechanics, not mandatory prompt size

#### Phase 2A -- Broad Hunt

**Queue setup:**
```bash
# Load file analysis queue into the dispatch engine
./scripts/assess.py code-dispatch queue "$DIR/tools/analysis-state/file-analysis-queue.json"

# Check queue state
./scripts/assess.py code-dispatch stats
```

**Fetch loop:**
```bash
# Reset stale items from any interrupted work
./scripts/assess.py code-dispatch reset-stale 10

# Check stats
./scripts/assess.py code-dispatch stats

# Fetch batch for analysis -- returns file-based items grouped by batch_theme
./scripts/assess.py code-dispatch fetch 10 code-vuln-hunter
```

The fetch size is a queue convenience, not a required prompt batch size. Split fetched items into
smaller hunter dispatches whenever code volume, framework noise, or support metadata would make
the prompt context heavier than the source files themselves.

**Dispatch `code-vuln-hunter`** with `agent/skills/code-vulnerability-analysis/SKILL.md` and:

- **File paths** -- the actual source file paths from the fetched queue items. The hunter reads
  these files directly from the filesystem.
- **Batch theme** -- the logical module grouping from the file analysis queue. Files in the same
  batch share a module context, enabling cross-file reasoning within the batch.
- **Slot types** -- the slot type annotations for each file from Phase 1 classification.
- **Applicable vulnerability classes** -- ALL vulnerability classes for this file's slot types
  from `SLOT_VULN_CLASSES`. The hunter must evaluate every applicable class, not just the ones
  named in hypotheses. Use the slot-type to vulnerability class mapping:

  | Slot Type | Native (C/C++) | Managed (Python/JS/Java/Go) |
  |---|---|---|
  | NETWORK-INPUT | buffer-overflow, integer-overflow, format-string | web-app-injection, web-app-auth, ssrf, open-redirect, path-traversal |
  | PROTOCOL-FIELD | buffer-overflow, integer-overflow, format-string | web-app-injection, web-app-auth, race-condition |
  | URL-COMPONENT | injection, auth-bypass, ssrf, open-redirect, web-app-auth | (same) |
  | FILE-CONTENT | injection, buffer-overflow, type-confusion, path-traversal, xxe, file-upload | (same) |
  | CMD-ARGUMENT | injection, format-string, path-traversal | (same) |
  | CALLBACK-DATA | use-after-free, race-condition, type-confusion, deserialization | (same) |
  | ENV-VARIABLE | injection, path-traversal | (same) |
  | _crypto (any + crypto) | crypto-misuse | (always) |
  | _auth (any + auth) | auth-bypass, web-app-auth | (always) |
  | _error (any + error) | error-handling | (always) |

- **Guidance hypotheses** -- labeled "check AFTER broad analysis" in the dispatch context.
  These are the attack hypotheses from Phase 1 that touch files in this batch. The hunter
  performs unconstrained broad analysis first, then checks these hypotheses second. This
  ordering prevents hypothesis anchoring where the analysis scope narrows to the architect's
  predictions.
- **Structural index** (if available) -- include the relevant per-file index data from
  `tools/analysis-state/structural-index/`. For small batches, passing the full per-file JSON is fine.
  For larger files, prefer a trimmed summary containing the function map, entry points,
  relevant sink catalog, and the call sites touching the entry chains under review. Look up the
  index filename for each file via `tools/analysis-state/structural-index-manifest.json`'s `path_to_index` mapping
  using the file's relative path (e.g., `manifest["path_to_index"]["src/main.c"]` returns the
  index filename). The hunter uses this as a navigation map and completeness checklist: every
  catalogued sink still needs to be accounted for.
- **Call graph excerpt** -- the subgraph for the target module showing entry-point chains and
  trust boundary crossings from `tools/analysis-state/call-graph.json`. Include only the subgraph
  relevant to the files and chains in this dispatch.
- **Threat model summary** -- trust boundaries, entry points, and high-value targets relevant
  to this batch from the Phase 1 threat model. Keep this short and file-local; do not dump the
  full Phase 1 artifact when a 3-8 bullet summary will do.
- **CWE pattern references** -- matching the applicable vulnerability classes for this batch.
  Use the Slot-Type -> Reference Mapping table below to select which pattern files to include.
- **Effort score guidelines** -- effort thresholds for this file's classification tier:
  critical files target effort >= 70, high files target effort >= 50, medium files are
  best-effort. Include these thresholds in the dispatch context so the hunter calibrates
  analysis depth accordingly.
- **Adversarial framing preamble** -- include this verbatim in every Phase 2A dispatch:

> These source files contain the paths from [entry points] through [function chains].
> There are 2-3 security issues in this code that survived every static analysis tool.
> They are in multi-function reasoning chains, error handling paths, integer arithmetic,
> or protocol edge cases. Find them. After your initial analysis, look again for subtler
> issues that are easy to miss.

Replace [entry points] and [function chains] with the actual values from the batch context.

**FULL FILESYSTEM ACCESS**: The hunter can Read/Grep/Glob beyond the file batch. The provided
files are a starting point, not a cage. If the hunter needs to trace a cross-module call, check
a macro definition, or verify a type width, it uses ctags + Read to find the target directly.

**Context budget rule**: Dispatch context should help the hunter navigate, not outweigh the
source files. If structural index blobs, call-graph data, and threat-model prose are taking more
room than the code under review, compress them into summaries or narrower excerpts first.

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

**On return:**
```bash
# Record analysis results (with cwe_coverage and cross_file_triggers)
./scripts/assess.py code-record-analysis <analysis-json>

# Mark items done with structured cwe_coverage
./scripts/assess.py code-dispatch done "id1,id2,..." <disposition> "<notes>" <cwe-coverage-json>

# Record any findings
./scripts/assess.py record-finding code-vuln-hunter <finding-json>

# Process cross-file triggers (if analysis returned any)
./scripts/assess.py code-dispatch requeue-triggers <triggers-json>
```

**Handling needs-context returns:** When items return as `needs-context`:
1. Review the request -- what function, file, or dependency is missing and why.
2. If the hunter could have resolved this with filesystem access (a function in another file in
   the same repo), note it as a process gap. Future dispatches should remind the hunter to
   self-resolve via Read/Grep/ctags before requesting expansion.
3. If the gap is genuinely unresolvable from the filesystem (external library source needed,
   binary dependency, macro-generated code), re-queue the item with additional context about the
   external dependency.
4. Re-queue the item for the next hunter batch.

**Cross-file triggers:** When analysis returns `cross_file_triggers`, these indicate that a
finding or taint path in one file connects to another file that needs examination. Process
them with `code-dispatch requeue-triggers` which adds the target files to the analysis queue
if they are not already queued or completed.

**Repeat** the fetch-dispatch-done loop until the queue is drained.

**Phase 2A exit gate -- ALL of the following must be true:**
- [ ] All critical/high files from the file analysis queue analyzed at least once
- [ ] No unresolved `needs-context` items on critical/high files
- [ ] All cross-file triggers processed (target files queued or already completed)
- [ ] Coverage stats checked: `./scripts/assess.py code-coverage`

#### Phase 2B -- CWE Coverage Review

Phase 2B closes effort gaps that Phase 2A left open. The broad hunt may have covered some
vulnerability classes thoroughly while leaving others shallow -- 2B uses the CWE effort matrix
to find and close those gaps systematically.

**Step 1: Generate effort matrix:**
```bash
./scripts/assess.py code-coverage --cwe-matrix
```

This displays:
- For each critical/high file: expected vulnerability classes from `SLOT_VULN_CLASSES`, current
  effort scores per class, and threshold flags (! marks below-threshold scores)
- Structural index cross-check: if the structural index is available, compare self-reported
  `functions_analyzed` against structural index sink counts -- discrepancies indicate the hunter
  may have skipped sinks
- Effort thresholds: critical >= 70, high >= 50, medium >= 30 (medium is best-effort, not blocking)

If all critical/high files meet their effort thresholds AND no cross-file triggers are pending,
proceed directly to Phase 3.

**Step 2: Process any remaining cross-file triggers:**
```bash
# Check for pending triggers
./scripts/assess.py code-dispatch stats

# Reset stale items
./scripts/assess.py code-dispatch reset-stale 10
```

Process triggers before re-dispatch -- a trigger may add a file that covers a gap class,
reducing the re-dispatch scope.

**Step 3: Decision gate.**

If all critical/high files meet thresholds AND no triggers pending -> Phase 3. Otherwise continue.

**Step 4: Re-dispatch with CWE directives.**

Group files by which vulnerability classes have effort below threshold. Dispatch `code-vuln-hunter`
with CWE-Directed Re-Analysis Mode context:

```json
{
  "cwe_directives": ["path-traversal", "injection"],
  "prior_effort": {
    "path-traversal": {"effort": 25, "functions_analyzed": 1, "notes": "checked main handler only"},
    "injection": {"effort": 40, "functions_analyzed": 3, "notes": "basic sink check"}
  },
  "target_effort": 70,
  "entry_chains_to_trace": ["handleUpload -> FileUtils.copyFile -> FileOutputStream.write"],
  "cwe_pattern_refs": ["agent/references/code-vuln-patterns/injection.md", "agent/references/code-vuln-patterns/web-app-injection.md"]
}
```

Include the same structural index, call graph excerpt, and threat model summary as Phase 2A.
The hunter enters CWE-Directed Re-Analysis Mode: it reads the file in full, focuses on the
directed vulnerability classes, and aims to raise effort scores to the target threshold.

**On return from CWE-directed re-dispatch:**
```bash
# Mark done with updated cwe_coverage (backend uses max-effort merge)
./scripts/assess.py code-dispatch done "id1,id2,..." <disposition> "<notes>" <cwe-coverage-json>

# Record any new findings
./scripts/assess.py record-finding code-vuln-hunter <finding-json>

# Process any new cross-file triggers
./scripts/assess.py code-dispatch requeue-triggers <triggers-json>
```

**Step 5: Re-check effort matrix:**
```bash
./scripts/assess.py code-coverage --cwe-matrix
```

If gaps remain on critical files:
- **Re-dispatch** if the hunter marked `needs-context` or traced only a subset of entry chains
  (there is more analysis to do)
- **Accept with documented exclusion** if the vulnerability class is genuinely not applicable
  to this file despite the slot-type mapping suggesting it (e.g., a NETWORK-INPUT file that
  only handles binary protocol frames has no injection surface)
- **Maximum 2 re-dispatch rounds per file per class** -- after two directed passes, remaining
  gaps are either genuine non-applicability or diminishing returns. Document the exclusion and
  proceed.

**Phase 2B exit gate -- ALL of the following must be true:**
- [ ] All critical files: effort >= 70 on all applicable vulnerability classes (or excluded with documented rationale)
- [ ] All high files: effort >= 50 on all applicable vulnerability classes (or excluded)
- [ ] Medium files: best-effort (no blocking gate)
- [ ] No pending cross-file triggers
- [ ] Entry chain coverage: >= 80% of entry chains traced on critical files (from `cwe_coverage` `entry_chains_traced` / `total_entry_chains`)

**Phase 2 exit:** both 2A and 2B gates pass.

```bash
jq '.current_phase = "verify-variant"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

Exit: All critical/high files analyzed with effort thresholds met. CWE coverage gaps closed
or documented. No unresolved needs-context. No pending triggers. Transition to Phase 3.

### Phase 3: VERIFY + VARIANT

Phase 3 merges verification and variant scanning into a single parallel phase. Two agents run
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
- `needs-context` items: dispatch additional file batches to Phase 2 with targeted context
- Unanalyzed critical files: dispatch to Phase 2 (hunt) first
- CWE effort gaps on critical files: run Phase 2B re-dispatch loop
- The gate must pass before proceeding -- unresolved items become permanently invisible to
  the report

#### Agent A: Verification

Dispatch `code-vuln-verifier` with `agent/skills/code-finding-verification/SKILL.md`.

Provide:
- All findings from Phase 2 (confirmed + suspicious)
- Source code paths for each finding (the canonical file locations)
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

**Clean-file spot-check:** After processing all findings, the verifier samples 2-3 critical
files that have zero findings but high effort scores (>= 70 across applicable classes). The
verifier reads those files with CWE pattern references and checks whether the "clean"
assessment from Phase 2 holds. This catches systematic blind spots where the hunter's
analysis methodology consistently misses a pattern class. If the spot-check finds a missed
vulnerability, that file goes back to Phase 2B for re-analysis with the specific CWE
directive.

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
data dependency on each other -- the verifier works from the Phase 2 finding list, and the
variant hunter works from confirmed findings plus the codebase.

#### Multi-Perspective Voting

If the verifier and variant hunter produce conflicting assessments of a finding (one
confirms, the other produces evidence against), dispatch a third agent with both
perspectives and the source code. The third agent evaluates both arguments against the
code and produces a reasoned disposition. Majority vote (2 of 3) determines the final
disposition.

This should be rare -- the verifier evaluates existing findings while the variant hunter
scans for new ones. Conflicts arise only when the variant hunter finds evidence that
contradicts a Phase 2 finding (e.g., discovers a guard the original hunter missed).

#### Handling spot-check findings

If the verifier's clean-file spot-check discovers a missed vulnerability:
1. Record the finding via `./scripts/assess.py record-finding code-vuln-verifier <finding-json>`
2. Dispatch the file back to Phase 2B with a CWE directive targeting the missed class
3. After re-analysis completes, re-check the effort matrix for the affected file

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
| `code-architect` | Architecture recon, threat modeling, call graph, attack hypotheses, file analysis queue | Phase 1 |
| `code-vuln-hunter` | Deep file-level vulnerability analysis with TOB-style methodology | Phase 2 (batched, parallel) |
| `code-variant-hunter` | Systematic variant scanning for confirmed bug patterns | Phase 3 (parallel with verifier) |
| `code-vuln-verifier` | FP elimination with devil's advocate verification + clean-file spot-check | Phase 3 (parallel with variant) |
| `report-writer` | Final report generation (reused from web engagement) | Phase 3 (after verify) |

## Finding Prefixes -- Code Analysis

| Agent | Prefix | Example |
|-------|--------|---------|
| code-architect | CA | FINDING-CA-001 |
| code-vuln-hunter | CH | FINDING-CH-001 |
| code-variant-hunter | CV | FINDING-CV-001 |
| code-vuln-verifier | VF | (updates only, no new findings -- except spot-check) |

## Dispatch Context Template

Every code analysis dispatch must include:
- **Agent identity** and **repository name**
- **Current phase** and **specific task objective**
- **Which skill to load** (from `agent/SKILL.md`)
- **For Phase 1**: full file listing, project docs, git churn data, structural index manifest (if available)
- **For Phase 2 (Hunt)**: file paths from queue items, batch theme, slot types,
  applicable vulnerability classes (ALL classes from SLOT_VULN_CLASSES for these slot types),
  guidance hypotheses (labeled "check AFTER broad analysis"), structural index excerpt or
  per-file JSON (if available), relevant call graph subgraph, concise threat model summary,
  CWE pattern references matching applicable classes, effort score guidelines (thresholds for
  this tier), adversarial framing preamble
- **For Phase 2B (CWE Re-Analysis)**: cwe_directives (specific classes below threshold),
  prior_effort (scores from prior pass), target_effort (threshold), entry_chains_to_trace
  (chains not yet traced), cwe_pattern_refs -- plus structural index, call graph, threat model
- **For Phase 3 verifier**: finding list with source code paths, CWE pattern refs, build
  system configuration, list of critical clean files for spot-check
- **For Phase 3 variant**: confirmed findings with abstract patterns, candidate file list,
  CWE pattern refs, threat model summary

### Pre-Dispatch Checklist

Before every dispatch, verify:

- [ ] Agent identity named and repository specified
- [ ] Current phase stated with specific task objective (not just "analyze this")
- [ ] Skill to load identified from `agent/SKILL.md`
- [ ] For Phase 2: file paths from queue items included (NOT context IDs, NOT JSON metadata)
- [ ] For Phase 2: applicable vulnerability classes listed (ALL from SLOT_VULN_CLASSES for these slot types)
- [ ] For Phase 2: CWE pattern references selected via slot-type mapping table
- [ ] For Phase 2: guidance hypotheses included and labeled "check AFTER broad analysis"
- [ ] For Phase 2: structural index excerpt or per-file JSON included (if available)
- [ ] For Phase 2: adversarial framing preamble included (with actual entry points and chains)
- [ ] For Phase 2: effort score thresholds included for the file's classification tier
- [ ] For Phase 2B: cwe_directives and prior_effort included for CWE-directed re-analysis
- [ ] Call graph excerpt included for Phase 2 dispatches
- [ ] Supporting context clipped to the relevant files and chains; no unrelated JSON dumps
- [ ] Log checked for duplicate dispatch -- never dispatch same agent for same file batch twice

DEDUP: Check the analysis queue and dispatch log before every dispatch. Never dispatch the same
agent for the same file batch twice. If re-analysis is needed (e.g., CWE-directed re-dispatch),
state the new CWE directives explicitly so the agent knows this is a targeted re-analysis, not
a duplicate.

PARALLEL: Independent file batches -> parallel (Phase 2 hunting). Independent agents -> parallel
(Phase 3 verify vs variant). CWE-directed re-dispatch depends on prior effort matrix -> sequential.

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
re-dispatch. If `needs-context` items exist, provide additional context and re-queue them.

Phase-specific resume actions:
- **Phase 1 (classify-map)**: Check if call graph, attack hypotheses, and file analysis queue
  exist in `tools/analysis-state/`. If missing, the architect dispatch was interrupted. Re-dispatch.
- **Phase 2A (hunt)**: Check queue stats. Reset stale items and resume the fetch-dispatch-done
  loop for unprocessed file batches.
- **Phase 2B (hunt -- CWE review)**: Run `code-coverage --cwe-matrix` to check current effort
  scores. Resume CWE-directed re-dispatch for files below threshold.
- **Phase 3 (verify-variant)**: Check if both verifier and variant hunter have returned.
  Resume whichever is incomplete.

## Coverage Communication

After each phase transition, display:
```
Code Analysis: [x] Ingest  [x] Classify+Map  [>] Hunt  [ ] Verify+Variant
[coverage] 45/687 files critical | 89 high | 203 medium | 112 low | 238 skipped
[queue] 0 pending | 0 processing | 0 done | 0 needs-context
[findings] 0 confirmed | 0 suspicious
[cwe-effort] critical: 12/15 meet threshold | high: 34/40 meet threshold
```

## Integration with Web Engagement

### Running Alongside Web Testing
When source code is obtained mid-engagement (exposed .git, source maps, backup download):
1. Download/reconstruct source to `$DIR/source/<name>/`
2. Run `./scripts/assess.py code-ingest "$DIR/source/<name>"`
3. Run `./scripts/assess.py code-index "$DIR/source/<name>"` for structural index
4. Code analysis phases run in parallel with ongoing web testing
5. Findings land in the same `assessment_findings` table

### Cross-Linking
- Code findings use `canonical_location = "file:..."` to distinguish from web findings
- `assessment_attack_chains` link code findings to web findings when the same endpoint is affected
- Code surfaces inform exploit-developer dispatches during web testing

## Operator Boundary -- Orchestration, Not Authorship

The operator is an orchestrator. Subagents are the readers and analysts.
When this boundary is violated -- when the operator reads source to build payloads, hand-edits
files, or makes vulnerability judgments -- operator context bloats, quality gating
degrades, and the engagement produces the exact failure modes seen in prior runs.

**The operator's job is metadata and coordination:**
- Fetch file lists, classifications, queue stats, and coverage from the backend
- Provide repo paths, structural index paths, call graph excerpts, threat model summaries,
  applicable vulnerability classes, and effort thresholds to subagents
- Record subagent outputs via `assess.py` after they pass quality gates
- Gate phase transitions on mandatory checklists -- reject and re-dispatch when gates fail
- Manage the analysis queue (fetch, dispatch, done, reset-stale, requeue-triggers)
- Review coverage gaps and CWE effort matrix to decide whether to re-dispatch or accept
- Extract call graph excerpts and structural index data from `tools/analysis-state/` for dispatch context
- Run the Phase 2B CWE coverage review loop to close effort gaps systematically

**Source reading belongs to subagents** because they have the domain context to interpret what
they read. When the operator pre-reads source, it duplicates work without the domain benefit,
filling the context window with code the operator will never analyze.

**File-level analysis belongs to code-vuln-hunter** because finding vulnerabilities requires
reading code with the constrained attacker persona, structural index as navigation map, and
CWE pattern references as methodology. The operator provides file paths, structural index, and
applicable vulnerability classes -- the hunter reads the code and produces dispositions, effort
scores, and cross-file triggers.

**Vulnerability judgment belongs to hunter and verifier** because disposition decisions (finding,
clean, suspicious) require the constrained attacker persona, CWE pattern references, and
taint-path evaluation that those agents are built for. Operator-side analysis skips this
methodology and produces unreliable verdicts.

## macOS/zsh Compatibility

- Use absolute paths: `/usr/bin/curl`, `/bin/cat`, `/usr/bin/grep`, etc.
- Do NOT use `grep -P` (Perl regex). Use `grep -E` (extended) or `rg` instead.
- HEREDOC: Use unquoted delimiter (`<< EOF`), NOT single-quoted (`<< 'EOF'`).
- New files: use bash commands (mkdir, cat >, echo >). Existing files: use Edit tool.
