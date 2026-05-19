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
- `agent/rules/resume.md`
- `agent/rules/hunting.md`
- `agent/rules/reporting.md`
- `agent/rules/adversarial-mindset.md`

Path convention:
- All assessment operations use `aith assess <subcommand>` from any directory.

## Resume Gate -- Code Analysis Mode

Before taking a new code-analysis action in an existing engagement, apply `agent/rules/resume.md`
when `scope.json` shows `status: in_progress`, `code-scope.json` or `source_repos` already exists,
the phase is past ingest, backend rows may already exist, or the session state is uncertain. Then
run the code-specific coverage and queue checks in "Session Resumption" below. Resume hydration
comes before planning because code findings, queue ownership, CWE effort, dispatch handoffs, and
runtime/fuzz command history live in different backend projections.

## Core Loop -- Code Analysis Mode

After code analysis engagement initialization completes, repeat until all critical/high files
analyzed or user signals stop:

1. **ASSESS STATE** -- Read `code-scope.json` (or `scope.json` with `source_repos`). For resumed engagements, run `aith assess resume-brief` from `agent/rules/resume.md` before planning; use `--finding`, `--q`, or `--agent-id` for targeted continuation. Check code coverage stats via `aith assess code-coverage`. Check CWE effort matrix via `aith assess code-coverage --cwe-matrix` when in Phase 2B. Backend state is canonical; use `--require-gate-pass` only for the final Phase 3 gate.
2. **DECIDE NEXT ACTION** -- Prioritize by current phase. In Phases 0-1, prioritize breadth (get all files classified, call graph complete, structural index generated). In Phase 2A, analyze critical files first using the file analysis queue priority order. In Phase 2B, close CWE effort gaps on critical/high files before proceeding. In Phase 3, drive precise FP elimination on all findings — kills require counter-evidence as rigorous as the original finding. Coverage gaps drive decisions.
3. **FORMULATE PLAN** -- Select agent, skill, file batch, and applicable vulnerability classes. Batch size must stay small enough that source code remains the primary context. Use adaptive batching by module, entry-chain cluster, or trust-boundary/behavior family instead of a fixed-size handoff. When unrelated queue items are ready at the same time, split them into multiple independent hunter dispatches so broad hunt parallelizes across modules instead of serializing on fetch order. Verify against the Pre-Dispatch Checklist (bottom of this file) before every dispatch.
4. **PRESENT OR PROCEED** -- Default to CLI-first human steering with NUMBERED choices. Continue autonomously only when explicitly authorized.
5. **USE SKILLS FIRST** -- Use `aith assess list-skills` to pick the matching skill (compact name + one-line "Use when:"), then load that skill file in full before starting target work. After loading the skill, read `agent/references/INDEX.md` to identify paired CWE pattern references and tool cheatsheets. Do not begin analysis work until both reads are complete.
   - **Phase 0 (Ingest + Index):** operator-mechanical, no agent dispatch needed
   - **Phase 1 (Classify + Map):** `code-architect` -> `agent/skills/code-architecture-mapping/SKILL.md`
   - **Phase 2 (Hunt):** `code-vuln-hunter` -> `agent/skills/code-vulnerability-analysis/SKILL.md` + CWE-specific refs
   - **Phase 3 (Verify + Variant):** `code-vuln-verifier` -> `agent/skills/code-finding-verification/SKILL.md` AND `code-variant-hunter` -> `agent/skills/code-variant-analysis/SKILL.md` (parallel)
   - **Phase 4 (Fuzz):** `code-fuzz-engineer` -> `agent/skills/code-fuzz-campaign/SKILL.md` + memory-safety CWE refs (conditional, C/C++ only)
6. **HOST BASH FOR SOURCE READING** -- Source code is local. Read via host Bash, Claude Code Read tool, or grep/rg. This is NOT target-facing network work -- `aith assess kali` is not needed for reading source files. When code analysis does reach for `aith assess kali ...` (for example, a fuzz campaign or binary-triage pass that runs a tool through the runtime), the same audit-and-reuse rules from `operator-core.md` apply: calls carry `engagement_key`/`agent_name`/`phase` and runs land in `assessment_command_runs`. Default to an unscoped fuzzy search — `aith assess list-command-runs --q <keyword> --show-matches` — so you see every agent's and every phase's prior work on the target; narrow with `--agent-name` or `--phase` only after the broad result is overwhelming. Before telling a specialist to reuse a prior run, fetch its preview with `aith assess get-command-run <id>` — `success=true` only means `return_code=0`, so open the preview to confirm the stored evidence actually answers the current question. See `agent/references/runtime-guides/command-history-auditing.md`. `aith assess kali` calls made from code-analysis workflows (fuzz campaigns, binary triage) must also set the audit-metadata flags — `--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout`, plus `--destructive` when applicable — so the command row is filterable alongside web engagement calls; see the `Command Metadata` sub-section in `agent/shared-constraints.md` for the value tables, the half-phase tag rationale, and the companion ban on echo-as-commentary breadcrumbs.
7. **DISPATCH** -- Dispatch to the appropriate subagent for all analysis work. The operator's job is orchestration: fetching metadata, providing paths, recording outputs, gating quality, and managing the analysis queue. Subagents read source files directly and produce structured outputs. Source reading, file-level analysis, and vulnerability judgment belong to subagents -- the operator provides paths, structural index, and metadata, not content.
8. **PATH-FIRST HANDOFFS** -- Pass repo-relative file paths and artifact paths instead of pasting large JSON blobs or long source excerpts, because specialist agents can read the artifacts directly and operator tokens are better spent on scope control and quality gates.
9. **RECORD FINDINGS IMMEDIATELY** -- Code findings use the same `aith assess record-finding` as web findings. Canonical location format: `file:<path>:<line>`.
10. **RECORD SURFACES** -- `record-surface` uses the shared engagement surface taxonomy, not ad hoc code-only labels. Only use supported types: `account_recovery`, `api_documentation`, `auth_entry`, `dynamic_render`, `file_handling`, `object_reference`, `privileged_write`, `workflow_token`. If none apply, do not invent a new surface type.
11. **TRACK COVERAGE** -- After each batch, run `aith assess code-coverage`. During Phase 2B, use `aith assess code-coverage --cwe-matrix` to check per-file CWE effort scores against thresholds. Before entering Phase 3 verification, verify the coverage gate passes with `aith assess code-coverage --require-gate-pass` (all critical files analyzed, no unresolved needs-context, no unprocessed triggers, CWE effort thresholds met).
12. **LOOP** -- Back to step 1.

## Phase Flow

### Phase 0: INGEST + INDEX

Operator-mechanical. No agent dispatch.

```bash
# 1. Clone or locate the repository
git clone <repo-url> $DIR/source/<repo-name>
# Or: cp -r /path/to/source $DIR/source/<repo-name>

# 2. Ingest into backend
aith assess code-ingest "$DIR/source/<repo-name>" --name <repo-name> --language <primary-lang>

# 3. Generate structural index
aith assess code-index "$DIR/source/<repo-name>"

# 4. Sync structural metadata to backend
aith assess code-index-sync

# 5. Verify ingestion and index
aith assess code-coverage
```

The `code-ingest` command:
- Walks the repo tree
- Detects language per file (extension + shebang)
- Computes SHA-256 hashes, counts LOC
- Extracts first ~50 lines as header snippet
- Runs git churn analysis if .git exists
- Marks generated/vendored/test/doc files as `skip` candidates
- POSTs all files to backend code-files endpoint — the backend assigns each file an integer
  `file_id` (primary key). Retrieve the mapping via
  `aith assess fetch "code/files?repo_id=<repo-id>&limit=5000"`;
  queue fetch responses also include the full file object with `file_id`.
- Creates code_repos record with repo metadata
- Generates ctags symbol index (if ctags is available)

The `code-index` command:
- Runs through the `agent/scripts/assess.py` `uv` script entrypoint, which provides the
  bundled `tree-sitter` parser packages.
- Uses tree-sitter to parse each source file
- Produces per-file JSON in `tools/analysis-state/structural-index/` (filenames are `sha256(rel_path)[:16].json`) containing: function map (names, signatures, line ranges), entry points (main functions, request handlers, exported APIs), security sinks (memory operations, file I/O, command execution, crypto calls), and call sites
- Writes a manifest at `tools/analysis-state/structural-index-manifest.json` with aggregate statistics and a `path_to_index` mapping (file relative path -> index filename) so consumers can look up index files by path
- If tree-sitter is still unavailable, fix the local `uv` environment and rerun. Do not skip
  structural indexing for a fresh engagement.
- The structural index accelerates Phase 2 hunting by giving the hunter a pre-built function map, export list, import dependency graph, and advisory sink annotations instead of requiring manual code triage. The function map is the primary completeness anchor -- every function must be accounted for. Sinks, exports, and import targets are advisory metadata that aids navigation but does not constrain the hunter's analysis scope

Output: `tools/analysis-state/structural-index/` directory with per-file JSON + manifest.

```bash
aith assess transition-phase classify-map
```

Exit: All files inventoried. ctags symbol index generated if ctags is available. Structural index generated. Transition to Phase 1.

### Phase 1: CLASSIFY + MAP

Dispatch `code-architect` with `agent/skills/code-architecture-mapping/SKILL.md`.

Provide:
- Repo root path plus a file-list artifact or fetched JSON from `aith assess fetch "code/files?repo_id=<repo-id>&limit=5000"` -- do not paste thousands of rows inline
- Project documentation paths (README, SECURITY.md, build files) so the architect can read the source material directly
- Git churn data as a short summary or artifact path from `code_repos.git_churn_json`
- Structural index manifest path (from `tools/analysis-state/structural-index-manifest.json`) -- if it is missing, run `aith assess code-index` before dispatching. The manifest gives the architect pre-computed function counts, entry points, and sink statistics per file

Phase 1 produces six deliverables. The call graph and attack hypotheses provide navigational guidance for hunters. The file analysis queue ensures every critical/high file is analyzed regardless of hypothesis coverage.

Use the helper contracts as the durable shape source before authoring or reviewing Phase 1 machine artifacts: `aith assess contract code-classify`, `aith assess contract code-record-modules`, `aith assess contract code-record-threat-model`, and `aith assess contract code-dispatch`. Point dispatches at those contracts instead of embedding copied JSON templates, because the CLI contract stays aligned with backend validation and catches field-name drift.

**Deliverables from code-architect:**

1. **File classifications** -- every file tagged with priority (critical/high/medium/low/skip) and
   slot types (NETWORK-INPUT, PROTOCOL-FIELD, CMD-ARGUMENT, URL-COMPONENT, FILE-CONTENT,
   CALLBACK-DATA, ENV-VARIABLE, SERIALIZED-DATA). Each record must include backend `file_id`;
   `file_path` is helper context, not the primary key.

2. **Module map** -- logical groupings of related files. Same as before.

3. **Threat model** -- trust boundaries, entry points, high-value targets, data flow between
   trust zones. Same as before.

4. **Cross-module call graph** -- adjacency list showing caller->callee edges with file and line
   number, annotated with untrusted-data crossings. Built via ctags + grep during Phase 1.
   Format: each edge records `{caller_func, caller_file, caller_line, callee_func, callee_file,
   callee_line, crosses_trust_boundary: bool, untrusted_data_label: string|null}`.
   The call graph focuses on entry-point chains: paths from external input (network, file, CLI)
   through processing functions to security-relevant decisions, state transitions, and
   harm-bearing operations (memory allocation, command execution, file I/O, auth decisions,
   resource-limit checks). Internal helper calls without security relevance can be omitted.

5. **Attack hypotheses (guidance)** -- for each high-priority entry-point chain, a specific testable
   hypothesis. Each hypothesis names the entry point, the function chain, and the
   security-relevant decision, state transition, or harm-bearing operation where the suspected
   defect could emerge, plus the defect class and CWE. Hypotheses are guidance for hunters, not
   the sole work items -- they help hunters prioritize within files, but files without
   hypotheses still receive full unconstrained analysis during Phase 2. This prevents hypothesis
   anchoring where the analysis scope narrows to what the architect predicted.

6. **File analysis queue** -- every critical and high file queued for Phase 2 analysis regardless
   of whether a hypothesis names it. Files without hypotheses appear with an empty
   `guidance_hypotheses` array. The queue is grouped by `batch_theme` (logical module) so the
   hunter can reason across related files in the same dispatch. Queue `priority` is mapped from
   the classification `analysis_priority` so the backend dispatch order preserves the architect's
   ranking. The on-disk queue artifact is a flat per-file JSON array -- no nested batch wrappers
   or glob patterns.

On return:
```bash
# Record classifications
aith assess code-classify <classifications-json>
# Record threat model
aith assess code-record-threat-model <repo-id> <threat-model-json>
# Record modules
aith assess code-record-modules <repo-id> <modules-json>
# Ensure analysis-state exists for Phase 2 handoff artifacts
mkdir -p "$DIR/tools/analysis-state"
# Store call graph in analysis-state/
cp <call-graph-json> "$DIR/tools/analysis-state/call-graph.json"
# Store attack hypotheses in analysis-state/
cp <hypotheses-json> "$DIR/tools/analysis-state/attack-hypotheses.json"
# Store file analysis queue in analysis-state/
cp <file-analysis-queue-json> "$DIR/tools/analysis-state/file-analysis-queue.json"
# Check progress
aith assess code-coverage
```

**Before transitioning:** Review code-architect's `#### Coverage Gaps` output. Critical gaps to
check before proceeding:
- Unresolved entry-point chains (external input sources with no traced path to a security-relevant decision, state transition, or harm-bearing operation)
- Missing cross-module edges for security-critical paths (e.g., auth module calls into crypto
  module but the edge is not in the graph)
- Unclassified directories that contain security-relevant code
- Attack hypotheses that reference functions not found in the call graph
- Critical/high files missing from the file analysis queue -- every such file must appear

If critical gaps exist, re-dispatch code-architect with targeted scope before proceeding. Gaps
in the call graph become blind spots for every downstream phase. Missing files in the queue
become permanently invisible to the analysis pipeline.

```bash
aith assess transition-phase hunt
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
aith assess code-dispatch queue "$DIR/tools/analysis-state/file-analysis-queue.json"

# Check queue state
aith assess code-dispatch stats
```

Broad-hunt queue items are file-level only. Do not add `context_id` to the queue artifact. Each
item carries `file_id` and `file_path` plus `priority` mapped from classification
`analysis_priority`, plus metadata (`batch_theme`, `slot_types`,
`guidance_hypotheses`). `code-dispatch queue` normalizes the artifact before posting: it strips
`file_path` (resolving to `file_id` if only a path was provided) and sends only backend-accepted
fields. Include both identifiers in the artifact so the queue is human-readable and the
normalizer can resolve either one. `repo_id` is only a disambiguation helper during
normalization; it is not part of the backend queue schema.

**Fetch loop:**
```bash
# Reset stale items from any interrupted work
aith assess code-dispatch reset-stale 10

# Check stats
aith assess code-dispatch stats

# Fetch batch for analysis -- returns file-based items grouped by batch_theme
aith assess code-dispatch fetch 10 code-vuln-hunter
```

The fetch size is a queue convenience, not a required prompt batch size. Split fetched items into
smaller hunter dispatches whenever code volume, framework noise, or support metadata would make
the prompt context heavier than the source files themselves.
When fetched items belong to unrelated modules, entry chains, or trust boundaries, dispatch
multiple hunters in parallel instead of handing one oversized mixed batch to a single agent.
Independent batches do not benefit from shared context, and splitting them preserves depth while
using the available subagent budget.

**Dispatch `code-vuln-hunter`** with `agent/skills/code-vulnerability-analysis/SKILL.md` and:

- **File paths** -- the actual source file paths from the fetched queue items. The hunter reads
  these files directly from the filesystem.
- **Batch theme** -- the logical module grouping from the file analysis queue. Files in the same
  batch share a module context, enabling cross-file reasoning within the batch.
- **Slot types** -- the slot type annotations for each file from Phase 1 classification.
- **Applicable vulnerability classes** -- use the `applicable_vuln_classes` list from the backend
  queue fetch payload. The backend computes this canonically from slot types, role, and language.
  The hunter must evaluate every applicable class, not just the ones named in hypotheses.
  Reference mapping:

  | Slot Type | Native (C/C++) | Managed (Python/JS/Java/Go) |
  |---|---|---|
  | NETWORK-INPUT | buffer-overflow, integer-overflow, format-string | web-app-injection, web-app-auth, ssrf, open-redirect, path-traversal |
  | PROTOCOL-FIELD | buffer-overflow, integer-overflow, format-string | web-app-injection, web-app-auth, race-condition |
  | URL-COMPONENT | injection, auth-bypass, ssrf, open-redirect, web-app-auth | (same) |
  | FILE-CONTENT | injection, buffer-overflow, type-confusion, path-traversal, xxe, file-upload | (same) |
  | CMD-ARGUMENT | injection, format-string, path-traversal | (same) |
  | CALLBACK-DATA | use-after-free, race-condition, type-confusion, deserialization | (same) |
  | ENV-VARIABLE | injection, path-traversal | (same) |
  | SERIALIZED-DATA | buffer-overflow, integer-overflow, type-confusion, deserialization | deserialization |
  | Role contains crypto | crypto-misuse | (always) |
  | Role contains auth/session | auth-bypass, web-app-auth | (always) |
  | Role contains error/exception | error-handling, null-dereference | error-handling, null-dereference |
  | Role contains memory/allocator | uninitialized-memory, algorithmic-dos | algorithmic-dos |
  | Role contains parser/decoder/deserializer | algorithmic-dos | algorithmic-dos |
  | Role contains graphql/resolver/serializer/orm/controller/view | web-app-data-exposure | web-app-data-exposure |
  | Role contains llm/prompt/rag/mcp | ai-ml-security | ai-ml-security |

- **Guidance hypotheses** -- labeled "check AFTER broad analysis" in the dispatch context.
  These are the attack hypotheses from Phase 1 that touch files in this batch. The hunter
  performs unconstrained broad analysis first, then checks these hypotheses second. This
  ordering prevents hypothesis anchoring where the analysis scope narrows to the architect's
  predictions.
- **Structural index** -- pass the manifest path plus the relevant per-file index paths from
  `tools/analysis-state/structural-index/`. If the manifest is missing, stop and run
  `aith assess code-index` before dispatching. Inline only the minimal function
  excerpt needed for prioritization. The function map is the primary completeness anchor:
  every listed function must receive a disposition. Sinks, exports, and import targets are
  advisory metadata that helps the hunter navigate -- they do not limit what the hunter looks
  for. The hunter's unconstrained analysis may find issues tree-sitter cannot detect.
- **Call graph excerpt** -- give a short summary of the relevant entry chain plus the artifact path
  to `tools/analysis-state/call-graph.json`. Inline only the edges that materially change the
  hunter's reasoning for this dispatch.
- **Threat model summary** -- trust boundaries, entry points, and high-value targets relevant
  to this batch from the Phase 1 threat model. Keep this short and file-local; do not dump the
  full Phase 1 artifact when a 3-8 bullet summary will do.
- **Root-cause candidate capture** -- ask the hunter to put shared utility functions, shared
  guards, or common missing-control candidates in handoff `extras.root_cause_candidates` when
  several concrete findings appear to depend on the same cause. This stays schema-valid and gives
  the operator a Phase 4 grouping checklist without forcing speculative finding fields.
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
| SERIALIZED-DATA | `deserialization.md` | `type-confusion.md` if unions/variant decoding; `algorithmic-dos.md` for parser bombs |
| Any + crypto operations | `crypto-misuse.md` | Always |
| Any + auth/session logic | `auth-bypass.md`, `web-app-auth.md` | `web-app-data-exposure.md` if serializers, resolvers, or ORM exposure are in scope |
| Any + error handling paths | `error-handling.md` | `null-dereference.md` if pointer/optional types |
| Any + memory allocation | `buffer-overflow.md`, `integer-overflow.md` | `uninitialized-memory.md`, `algorithmic-dos.md` |
| Any + AI/ML/LLM code | `ai-ml-security.md` | Always for LangChain/LlamaIndex/MCP code |

All references are under `agent/references/code-vuln-patterns/`. Include the full path in the dispatch context.

**On return:**
```bash
# Confirm the analysis-result contract if the payload was hand-authored
aith assess contract code-record-analysis

# Record analysis results (with cwe_coverage and cross_file_triggers)
aith assess code-record-analysis <analysis-json>

# Preview the exact completion payload before committing queue history when unsure
aith assess code-dispatch done <item-id> <clean|finding|suspicious> <cwe-coverage-json> ["notes"] --dry-run

# cwe-coverage-json must be a file path, not inline JSON. Create it before the done call:
cat > /tmp/cwe_<item-id>.json <<'JSON'
[
  {
    "family": "buffer-overflow",
    "effort": 85,
    "functions_analyzed": 12,
    "entry_chains_traced": 3,
    "total_entry_chains": 3,
    "notes": "Traced all applicable parser entry chains"
  }
]
JSON

# Mark one file done with structured cwe_coverage after the payload is correct
aith assess code-dispatch done <item-id> <clean|finding|suspicious> /tmp/cwe_<item-id>.json ["notes"]

# Record any findings
aith assess record-finding code-vuln-hunter <finding-json>

# Process cross-file triggers (if analysis returned any)
aith assess code-dispatch requeue-triggers <triggers-json>

# Before fetching the next batch, reset items stuck in-progress:
aith assess code-dispatch reset-stale 10
```

Use `code-dispatch done` with one of `clean`, `finding`, or `suspicious`, because the queue
history is only useful if every completion records a valid disposition and a complete
`cwe_coverage` array instead of a half-formed backend 422. The coverage file content is the
bare JSON array that becomes `cwe_coverage`; do not wrap it in an object containing a
`cwe_coverage` field. Include one entry for every `applicable_vuln_classes` value from the
queue item, using explicit zero-effort gap entries for omitted/unexamined families.

**Handling needs-context returns:** When items return as `needs-context`:
1. Review the request -- what function, file, or dependency is missing and why.
2. If the hunter could have resolved this with filesystem access (a function in another file in
   the same repo), note it as a process gap. Future dispatches should remind the hunter to
   self-resolve via Read/Grep/ctags before requesting expansion.
3. If the gap is genuinely unresolvable from the filesystem (external library source needed,
   binary dependency, macro-generated code), re-queue the item with additional context about the
   external dependency.
4. Re-queue the item with `aith assess code-dispatch needs-context ...` -- do not use
   `code-dispatch done needs_context`, because incomplete work must carry explicit expansion
   metadata instead of looking complete in the queue history.

**Cross-file triggers:** When analysis returns `cross_file_triggers`, these indicate that a
finding or taint path in one file connects to another file that needs examination. Process
them with `code-dispatch requeue-triggers` which adds the target files to the analysis queue
if they are not already queued or completed. Unprocessed triggers are gate-blocking workflow
state: the phase does not pass until each trigger is queued or already completed.

**Findings-density signal:** After each hunter dispatch, if a single file yielded >= 2
findings AND the file is > 500 LOC, note it for the Phase 2C adversarial pass. Finding
density signals that more issues likely remain — the original hunter was anchored by its
first discoveries.

**Repeat** the fetch-dispatch-done loop until the queue is drained.

**Phase 2A exit gate -- ALL of the following must be true:**
- [ ] All critical/high files from the file analysis queue analyzed at least once
- [ ] No unresolved `needs-context` items on critical/high files
- [ ] All cross-file triggers processed (target files queued or already completed)
- [ ] Coverage stats checked: `aith assess code-coverage`

#### Phase 2B -- CWE Coverage Review

Phase 2B closes effort gaps that Phase 2A left open. The broad hunt may have covered some
vulnerability classes thoroughly while leaving others shallow -- 2B uses the CWE effort matrix
to find and close those gaps systematically.

**Step 1: Generate effort matrix:**
```bash
aith assess code-coverage --cwe-matrix
```

This displays:
- For each critical/high file: expected vulnerability classes from `SLOT_VULN_CLASSES`, current
  effort scores per class, and threshold flags (! marks below-threshold scores)
- Structural index cross-check: if the structural index is available, compare self-reported
  `functions_analyzed` against the structural index function count -- discrepancies indicate the
  hunter may have skipped functions that need a disposition
- Effort thresholds: critical >= 70, high >= 50, medium >= 30 (medium is best-effort, not blocking)

If all critical/high files meet their effort thresholds AND no cross-file triggers are pending,
proceed directly to Phase 3.

**Step 2: Process any remaining cross-file triggers:**
```bash
# Check for pending triggers and queue blockers
aith assess code-coverage

# Reset stale items
aith assess code-dispatch reset-stale 10
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
# Preview first when the updated effort matrix is large or hand-edited
aith assess code-dispatch done <item-id> <clean|finding|suspicious> <cwe-coverage-json> ["notes"] --dry-run

# Mark done with updated cwe_coverage (backend uses max-effort merge)
aith assess code-dispatch done <item-id> <clean|finding|suspicious> <cwe-coverage-json> ["notes"]

# Record any new findings
aith assess record-finding code-vuln-hunter <finding-json>

# Process any new cross-file triggers
aith assess code-dispatch requeue-triggers <triggers-json>
```

**Step 5: Re-check effort matrix:**
```bash
aith assess code-coverage --cwe-matrix
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

**Suspicious finding resolution:** Before leaving Phase 2, all `suspicious` findings must be
resolved. Re-dispatch the hunter with targeted context to close each gap — the hunter's
`suspicious` hypothesis documents exactly what was missing. After re-dispatch, the finding
must reach `confirmed` (promoted to finding) or `clean` (hypothesis disproven). Do not pass
unresolved suspicious findings to the verifier — the verifier's job is FP elimination on
confirmed findings, not investigation of incomplete ones.

**Phase 2 exit:** 2A, 2B, and 2C gates pass, AND no unresolved suspicious findings remain.

```bash
aith assess transition-phase verify-variant
```

Exit: All critical/high files analyzed with effort thresholds met. CWE coverage gaps closed
or documented. No unresolved needs-context. No pending triggers. No unresolved suspicious
findings. Adversarial depth pass complete. Transition to Phase 3.

#### Phase 2C -- Adversarial Depth Pass

After the coverage gate passes, select 10-20 files for an independent hostile reread.
The broad coverage pass anchors agents on "complete correctly" — this pass resets the
mission to "find the critical that survived."

**File selection:** Use judgment. The coverage pass likely missed findings in files where:
- Security decisions happen (auth, policy, access control, crypto)
- Finding density was high — 2+ findings in a file signals more remain
- Large files (>500 LOC) with entry points were analyzed under queue pressure
- Config/policy files define execution behavior but were classified medium

The operator picks 10-20 files that represent the highest-risk attack surface
for the specific codebase. No fixed category list — the selection should reflect
what an adversary would target given this project's architecture and threat model.

**Dispatch rules:**
- Use `deep-manual` mode (not item-iterating)
- Do NOT include prior findings from Phase 2A in the dispatch context — the hunter
  must approach fresh without anchoring on existing findings
- Include: structural index, call graph, threat model, CWE patterns, but NOT
  the list of already-found issues
- Dispatch objective: "Find High/Critical vulnerabilities in these files. Ignore
  coverage metrics. Focus on semantic fail-opens, logic bugs, and design flaws."

**On return:** Record findings and analysis results normally. This pass does NOT need to
satisfy CWE coverage thresholds — it produces findings, not coverage closure.

**Phase 2C exit:** All dispatched files reviewed. Findings recorded.

### Phase 3: VERIFY + VARIANT

Phase 3 merges verification and variant scanning into a single parallel phase. Two agents run
simultaneously on independent objectives:

- **Agent A (code-vuln-verifier)**: TOB-style false positive elimination on all findings
- **Agent B (code-variant-hunter)**: systematic variant scanning for confirmed bug patterns

Both agents run in parallel because their work is independent: the verifier evaluates existing
findings, while the variant hunter scans for new instances of confirmed patterns.

**Coverage gate** -- must pass before proceeding:
```bash
aith assess code-coverage --require-gate-pass
# Must show: all critical files analyzed, all high files analyzed, no needs-context, no pending triggers
```

If the gate fails, resolve remaining items before proceeding:
- `needs-context` items: dispatch additional file batches to Phase 2 with targeted context
- Unanalyzed critical files: dispatch to Phase 2 (hunt) first
- Pending cross-file triggers: requeue and analyze the target files before verification
- CWE effort gaps on critical files: run Phase 2B re-dispatch loop
- The gate must pass before proceeding -- unresolved items become permanently invisible to
  the report

#### Agent A: Verification

Dispatch `code-vuln-verifier` with `agent/skills/code-finding-verification/SKILL.md`.

Provide:
- All confirmed findings from Phase 2 (suspicious findings must be resolved by hunters
  before Phase 3 — see Phase 2 exit gate)
- Source code paths for each finding (the canonical file locations)
- CWE pattern references matching each finding's defect family
- Build system configuration for compile-time flag evaluation (Makefiles, CMakeLists,
  configure scripts, feature flags)

The verifier's job is precise FP elimination. False positives are expected in any
AI-assisted vulnerability pipeline, but so are wrongly killed real findings. A killed
finding is only a good outcome when the counter-evidence is as rigorous as the original
finding. If the verifier kills >80% of findings, review whether kills are based on
specific code evidence or circumstantial reasoning.

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
1. Record the finding via `aith assess record-finding code-vuln-verifier <finding-json>`
2. Dispatch the file back to Phase 2B with a CWE directive targeting the missed class
3. After re-analysis completes, re-check the effort matrix for the affected file

#### On return from both agents:

```bash
# Record verification results (updates existing findings)
aith assess verify-finding <slug> <verification-json>
# Or use the dedicated false-positive helper when you already have the kill rationale
aith assess kill-finding <slug> --reason "<kill rationale>" --kill-reason "<specific guard or proof>" --kill-check <1-5>
# Reopen a previously verified or false-positive finding when new evidence requires re-triage
aith assess reset-finding <slug> --reason "<why the prior verdict no longer holds>" --status draft
# Record variant findings (new findings)
aith assess record-finding code-variant-hunter <variant-finding-json>
```

**Pre-report deduplication:**
Before dispatching report-writer, check for duplicate findings (same `canonical_location` and
similar `defect_family` across hunter and variant-hunter prefixes):
```bash
aith assess merge-finding <source-slug> <target-slug> "<reason>"
```

**Pre-report deduplication (cross-phase):**
Before dispatching report-writer, also check for duplicate findings between Phase 3 and Phase 4
(fuzz findings that confirm static findings):
```bash
aith assess merge-finding <source-slug> <target-slug> "<reason>"
```

**Phase 3 exit:**
```bash
aith assess transition-phase fuzz
```

Exit: All findings verified. Variant scan complete. Transition to Phase 4 (Fuzz) if the
codebase is C/C++ with memory-safety targets, otherwise skip directly to report.

### Phase 4: FUZZ

Phase 4 uses AI-driven fuzz campaign orchestration to find memory-safety vulnerabilities that
static analysis missed. AI selects targets, writes harnesses, compiles under sanitizers, and
triages crashes. Coverage-guided mutation engines (libFuzzer, AFL++) do the actual exploration.

**Phase 4 is conditional.** Run it when ANY of the following are true:
- Phase 2/3 produced confirmed memory-safety findings (buffer overflow, integer overflow, UAF)
- Critical/high C/C++ files have attacker-reachable parsers with size arithmetic but low or
  no existing fuzz coverage (high structural risk even without a confirmed static finding)

Skip it when ALL of the following are true:
- Codebase is entirely memory-safe (Python, Go, Java, Rust without unsafe), OR
- No critical/high C/C++ files with attacker-reachable parsing code exist, OR
- All high-value parsing targets already have OSS-Fuzz coverage with >70% branch coverage

**Phase 4 entry gate:**
```bash
# Verify Phase 3 complete
aith assess code-coverage --require-gate-pass

# Check for memory-safety findings OR high structural risk in C/C++ code.
# Filter findings for defect_family in: buffer-overflow, integer-overflow,
# use-after-free, uninitialized-memory.
aith assess fetch findings

# Check for critical/high C/C++ files — fuzzing for memory-safety needs C/C++ targets.
# Even without confirmed memory-safety findings, high-risk C/C++ parsers with low
# existing fuzz coverage warrant a campaign.
aith assess fetch "code/files?repo_id=<id>&limit=5000"
# If no C/C++ files at critical/high classification, skip Phase 4.

# Verify build toolchain
which clang && clang --version
```

#### Phase 4A: Target Selection + Harness Construction

Dispatch `code-fuzz-engineer` with `agent/skills/code-fuzz-campaign/SKILL.md`.

Provide:

**Backend state (operator fetches and summarizes):**
- Memory-safety findings: `aith assess fetch findings` — extract findings with
  `defect_family` in `buffer-overflow`, `integer-overflow`, `use-after-free`,
  `uninitialized-memory`. Include slugs, canonical locations, severity, and
  `verification_state` (confirmed/unreviewed). Pass as a concise summary, not raw JSON dump.
- File classifications: `aith assess fetch "code/files?repo_id=<id>&limit=5000"` —
  identify critical/high C/C++ files with relevant slot types. The fuzz engineer uses these to
  cross-reference targets against structural index data.

**Filesystem artifact paths (the fuzz engineer reads these directly):**
- Structural index manifest: `tools/analysis-state/structural-index-manifest.json`
- Threat model: `tools/analysis-state/threat-model.json`
- Call graph: `tools/analysis-state/call-graph.json`
- Source repo root path for direct code reads

**Operator-provided context:**
- Build system type (Makefile/CMake/etc.) and compiler availability (`which clang`)
- Existing fuzzer inventory paths (from `rg 'LLVMFuzzerTestOneInput'` or `ls oss-fuzz/`)
- CWE pattern references: `buffer-overflow.md`, `integer-overflow.md`, `use-after-free.md`,
  `uninitialized-memory.md`, `fuzz-harness-patterns.md`

The fuzz engineer:
- Selects and ranks targets using structural index, threat model, and Phase 2 findings
- Audits selected targets for specific BOF/integer-overflow patterns
- Writes libFuzzer/AFL++ harnesses using real parser entrypoints
- Compiles under ASAN+UBSAN, validates seeds run clean
- Runs quick local campaigns (60-second validation runs)
- Configures longer campaigns for overnight execution

**On return from target selection + harness construction:**
```bash
# Campaign state written to tools/fuzz-state/
ls tools/fuzz-state/targets.json
ls tools/fuzz-state/harnesses/*/harness.c
ls tools/fuzz-state/campaigns/*.json

# Record any findings from quick validation runs or pre-fuzz audit
aith assess record-finding code-fuzz-engineer <finding-json>
```

#### Phase 4B: Campaign Execution

Campaign execution is a traditional tool run, not an AI agent task. The operator starts
campaigns based on the configurations from Phase 4A.

```bash
# Short campaigns (libFuzzer, 5-10 min) -- run immediately
for config in tools/fuzz-state/campaigns/*.json; do
    target_id=$(jq -r .target_id "$config")
    timeout=$(jq -r .run_budget.max_total_time "$config")
    ./fuzz_${target_id} \
        -artifact_prefix=tools/fuzz-state/crashes/${target_id}/ \
        tools/fuzz-state/harnesses/${target_id}/corpus/ \
        tools/fuzz-state/harnesses/${target_id}/seeds/ \
        -max_total_time=${timeout} -print_final_stats=1
done

# Deep campaigns (AFL++, overnight) -- start in screen/tmux
screen -dmS fuzz-campaign bash -c '
    for config in tools/fuzz-state/campaigns/*-deep.json; do
        target_id=$(jq -r .target_id "$config")
        # If campaign config has cmplog=true, build a CmpLog binary first:
        #   AFL_LLVM_CMPLOG=1 make fuzz_${target_id}_cmplog
        # Then pass -c ./fuzz_${target_id}_cmplog -l 2 to afl-fuzz.
        afl-fuzz -i tools/fuzz-state/harnesses/${target_id}/seeds/ \
                 -o tools/fuzz-state/harnesses/${target_id}/afl-out/ \
                 -t 1000 -- ./fuzz_${target_id}_afl @@
    done
'
```

#### Phase 4C: Crash Triage

After campaigns complete (or produce crashes during quick runs), dispatch `code-fuzz-engineer`
for crash triage.

Provide:
- Crash artifacts from `tools/fuzz-state/crashes/`
- Campaign configs from `tools/fuzz-state/campaigns/`
- Harness source from `tools/fuzz-state/harnesses/`
- Source code paths for the target functions

The fuzz engineer triages each crash through the false-positive pipeline:
minimize -> reproduce -> trace -> validate -> classify

**On return from crash triage:**
```bash
# Record true findings
aith assess record-finding code-fuzz-engineer <finding-json>

# Triage reports written to tools/fuzz-state/reports/
ls tools/fuzz-state/reports/*-triage.json
```

**Phase 4 exit gate:**
- [ ] All quick campaigns completed
- [ ] All crashes triaged (no untriaged crash artifacts)
- [ ] True findings recorded with full false-positive gate evidence
- [ ] Harness bugs fixed and campaigns re-run (if applicable)
- [ ] Campaign summary written to `tools/fuzz-state/reports/campaign-summary.json`

```bash
aith assess transition-phase complete --track code
```

**Report dispatch:**
For a final report, run `aith assess check-report-readiness` before dispatching
`report-writer`. Report-writer runs `aith assess list-report-findings --mode final --json` for final output and
`aith assess list-report-findings --mode draft --json` for interim output; both include code and web findings from the
shared backend with root-cause grouping applied. Fuzz findings (CF-xxx) include crash inputs and ASAN reports as evidence.
Use the same draft → review-and-fix QA → publish gate as runtime engagements: draft generation
writes `report.md` and returns the 13-check checklist, a fresh `report-writer` reviews and fixes
the rendered report, and publication plus `reported` lifecycle transitions wait for `QA PASS`.

## Agent Roster -- Code Analysis

| Agent | Role | Phase |
|-------|------|-------|
| `code-architect` | Architecture recon, threat modeling, call graph, attack hypotheses, file analysis queue | Phase 1 |
| `code-vuln-hunter` | Deep file-level vulnerability analysis with TOB-style methodology | Phase 2 (batched, parallel) |
| `code-variant-hunter` | Systematic variant scanning for confirmed bug patterns | Phase 3 (parallel with verifier) |
| `code-vuln-verifier` | FP elimination with devil's advocate verification + clean-file spot-check | Phase 3 (parallel with variant) |
| `code-fuzz-engineer` | AI-driven fuzz campaigns: target selection, harness construction, crash triage | Phase 4 (conditional, C/C++ only) |
| `report-writer` | Final report generation (reused from web engagement) | After Phase 3 or 4 completes |

## Finding Prefixes -- Code Analysis

| Agent | Prefix | Example |
|-------|--------|---------|
| code-architect | CA | CA-001 |
| code-vuln-hunter | CH | CH-001 |
| code-variant-hunter | CV | CV-001 |
| code-vuln-verifier | VF | (updates only, no new findings -- except spot-check) |
| code-fuzz-engineer | CF | CF-001 |

These examples describe the prefixes allocated by `aith assess record-finding`.
Do not ask parallel specialists to hand-author `slug` values; new finding JSON
omits `slug`, and the helper prints the canonical slug to reuse in handoffs and
analysis rows.

## Dispatch Context Template

Every code analysis dispatch must include:
- **Agent identity** and **repository name**
- **Current phase** and **specific task objective**
- **Which skill(s) to load** (selected via `aith assess list-skills`)
- **For Phase 1**: full file listing, project docs, git churn data, structural index manifest
- **For Phase 2 (Hunt)**: file paths from queue items, batch theme, slot types,
  applicable vulnerability classes (ALL classes from SLOT_VULN_CLASSES for these slot types),
  guidance hypotheses (labeled "check AFTER broad analysis"), structural index excerpt or
  per-file JSON, relevant call graph subgraph, concise threat model summary,
  CWE pattern references matching applicable classes, effort score guidelines (thresholds for
  this tier), adversarial framing preamble
- **For Phase 2B (CWE Re-Analysis)**: cwe_directives (specific classes below threshold),
  prior_effort (scores from prior pass), target_effort (threshold), entry_chains_to_trace
  (chains not yet traced), cwe_pattern_refs -- plus structural index, call graph, threat model
- **For Phase 3 verifier**: finding list with source code paths, CWE pattern refs, build
  system configuration, list of critical clean files for spot-check
- **For Phase 3 variant**: confirmed findings with abstract patterns, candidate file list,
  CWE pattern refs, threat model summary
- **For Phase 4 (Fuzz)**: memory-safety finding summaries from `aith assess fetch findings`
  (slugs, locations, severity, verification_state — not raw JSON dump), critical/high C/C++ file
  list from `aith assess fetch "code/files?..."`, filesystem artifact paths (structural index
  manifest, threat model, call graph — fuzz engineer reads these directly), source repo root,
  build system type, compiler availability, existing fuzzer inventory paths, CWE pattern refs
  (buffer-overflow, integer-overflow, use-after-free, uninitialized-memory, fuzz-harness-patterns)

### Runtime Identity Block

Every code-analysis dispatch prompt must include a Runtime Identity block so the specialist can use the exact values in its closing sequence:

```
## Runtime Identity
agent_id: <actual-id-from-register-or-spawn>
agent_role: <role>
authorized_phase: <phase>
```

The operator obtains `agent_id` by:
- **Claude Code**: use the id printed by `aith assess agent start` — choose or accept a unique string per dispatch (e.g. `hunt-b7c2`).
- **Codex**: use the id returned by `spawn_agent`.

Pass this block verbatim at the top of the dispatch prompt. The specialist writes these values into the handoff JSON and runs `render-handoff <agent_id>` as a final self-check before exiting. If this is a continuation or resumed engagement, include the relevant `aith assess resume-brief` output immediately after the Runtime Identity block so the specialist starts from compact backend state instead of local-note reconstruction.

Require immediate backend/artifact linkage for durable notes: if a specialist creates a `.md` file under `notes/` that should matter after the current command, they must register it with `aith assess artifact register <path>` and link it to a finding, chain, dispatch/agent, surface, request variant, or command run before closing. Unlinked markdown notes are scratch and cannot be used as resume or report input.

### Pre-Dispatch Checklist

Before every dispatch, verify:

- [ ] Agent identity named and repository specified
- [ ] Current phase stated with specific task objective (not just "analyze this")
- [ ] Skill name(s) identified from `aith assess list-skills` (the first column = `name`, matches `agent/skills/<name>/`)
- [ ] Full skill path(s) `agent/skills/<name>/SKILL.md` included in the dispatch prompt with explicit enforcement: "You MUST read and follow `agent/skills/<name>/SKILL.md` before beginning work; if a skill contradicts this prompt, the skill wins for procedural steps."
- [ ] Bare skill `name(s)` (not paths) passed to `--skills` on `aith assess agent start` for audit — the validator resolves names against `agent/skills/<name>/SKILL.md`
- [ ] For Phase 2: file paths from queue items included (NOT context IDs, NOT JSON metadata)
- [ ] For Phase 2: applicable vulnerability classes copied from backend `applicable_vuln_classes` when present; otherwise derived from slot types + role/language fallback rules
- [ ] For Phase 2: CWE pattern references selected via slot-type mapping table
- [ ] For Phase 2: guidance hypotheses included and labeled "check AFTER broad analysis"
- [ ] For Phase 2: structural index excerpt or per-file JSON included, or `code-index` rerun before dispatch
- [ ] For Phase 2: adversarial framing preamble included (with actual entry points and chains)
- [ ] For Phase 2: effort score thresholds included for the file's classification tier
- [ ] For Phase 2: unrelated fetched groups split into separate hunter dispatches so independent modules run in parallel
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

On start or when resuming inside a code analysis engagement, apply `agent/rules/resume.md` first (`aith assess resume-brief`, narrowed with `--finding`, `--q`, or `--agent-id` when useful).
Then run the code-mode state checks that do not exist in web/runtime engagements:

```bash
aith assess code-coverage                  # File classification + analysis coverage
aith assess code-dispatch stats             # Queue state (pending/processing/done/needs-context)
aith assess code-coverage --cwe-matrix      # CWE effort state when Phase 2B or later is active
```

Resume from the current phase. If `code-dispatch stats` shows `processing` items, they were
interrupted -- reset stale items with `aith assess code-dispatch reset-stale 10` and
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
- **Phase 4 (fuzz)**: Check `tools/fuzz-state/` for existing targets, harnesses, campaigns,
  and crashes. If targets.json exists but no harnesses, resume from Stage 3. If crashes
  exist without triage reports, resume from Stage 6 (crash triage).

## Coverage Communication

After each phase transition, display:
```
Code Analysis: [x] Ingest  [x] Classify+Map  [>] Hunt  [ ] Verify+Variant  [ ] Fuzz
[coverage] 45/687 files critical | 89 high | 203 medium | 112 low | 238 skipped
[queue] 0 pending | 0 processing | 0 done | 0 needs-context
[findings] 0 confirmed | 0 suspicious
[cwe-effort] critical: 12/15 meet threshold | high: 34/40 meet threshold
[fuzz] 0 targets | 0 harnesses | 0 campaigns | 0 crashes | 0 true findings
```

## Integration with Web Engagement

### Running Alongside Web Testing
When source code is obtained mid-engagement (exposed .git, source maps, backup download):
1. Download/reconstruct source to `$DIR/source/<name>/`
2. Run `aith assess code-ingest "$DIR/source/<name>"`
3. Run `aith assess code-index "$DIR/source/<name>"` to materialize the required structural index (the script bootstraps bundled tree-sitter packages through `uv` on first run)
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
- Record subagent outputs via `aith assess` after they pass quality gates
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
