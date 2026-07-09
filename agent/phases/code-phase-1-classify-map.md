# Code Phase 1 — Classify + Map

**Read-on-phase-entry.** When you ENTER Code Phase 1 (Classify + Map), Read this doc before
dispatching `code-architect`, and re-read it on a method re-anchor. It carries the full
`code-architect` dispatch shape (what to provide, the six deliverables), the on-return recording
commands, the pre-transition coverage-gap review, and the Phase 1 exit gate. Cross-phase machinery —
the Core Loop, the Phased mindset flow (code) (which sets `code-architect`'s survey lens), the Agent
Roster, and the Dispatch Context Template / Pre-Dispatch Checklist — stays in
`agent/operator-core-code.md`; this doc does not restate it.

### Phase 1: CLASSIFY + MAP

Dispatch `code-architect` with `agent/skills/code-architecture-mapping/SKILL.md`.

Provide:
- Repo root path plus a file-list artifact or fetched JSON from `vigil assess fetch "code/files?repo_id=<repo-id>&limit=5000"` -- do not paste thousands of rows inline
- Project documentation paths (README, SECURITY.md, build files) so the architect can read the source material directly
- Git churn data as a short summary or artifact path from `code_repos.git_churn_json`
- Structural index manifests (aggregate at `tools/analysis-state/structural-index-manifest.json`; per-repo at `tools/analysis-state/structural-index/<repo_key>-manifest.json`) -- if the aggregate is missing or only covers one repo, run `vigil assess code-index` per repo (one invocation per source repo) before dispatching. The aggregate gives the architect pre-computed function counts, entry points, and sink statistics per file scoped to the right repo

Phase 1 produces six deliverables. The call graph and attack hypotheses provide navigational guidance for hunters. The file analysis queue ensures every critical/high file is analyzed regardless of hypothesis coverage.

Use the helper contracts as the durable shape source before authoring or reviewing Phase 1 machine artifacts: `vigil assess contract code-classify`, `vigil assess contract code-record-modules`, `vigil assess contract code-record-threat-model`, and `vigil assess contract code-dispatch`. Point dispatches at those contracts instead of embedding copied JSON templates, because the CLI contract stays aligned with backend validation and catches field-name drift.

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

**Sizing check (informs Phase 2 batch sizing):** Run `vigil assess code-size-summary`
to get LOC buckets and large-file candidates across the indexed repo(s). Phase 2's
adaptive batching (1 logical module or 1-3 tightly related files per hunter dispatch,
shrunk further for large/parser-heavy/stateful files) is easier to plan up front when
the operator already knows which files are outsized outliers before dispatch begins.

On return:
```bash
# Record classifications
vigil assess code-classify <classifications-json>
# Record threat model
vigil assess code-record-threat-model <repo-id> <threat-model-json>
# Record modules
vigil assess code-record-modules <repo-id> <modules-json>
# Ensure analysis-state exists for Phase 2 handoff artifacts
mkdir -p "$DIR/tools/analysis-state"
# Store call graph in analysis-state/
cp <call-graph-json> "$DIR/tools/analysis-state/call-graph.json"
# Store attack hypotheses in analysis-state/
cp <hypotheses-json> "$DIR/tools/analysis-state/attack-hypotheses.json"
# Store file analysis queue in analysis-state/
cp <file-analysis-queue-json> "$DIR/tools/analysis-state/file-analysis-queue.json"
# Check progress
vigil assess code-coverage
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
vigil assess transition-phase hunt
```

Exit: Every file classified. Threat model recorded. Call graph recorded with entry-point chains.
Attack hypotheses queued as guidance. File analysis queue complete with every critical/high file.
Coverage gaps reviewed. Transition to Phase 2.

---

Phase index (path → purpose) lives in `agent/operator-core-code.md` under "Phase Index". Prior:
`agent/phases/code-phase-0-ingest-index.md`. Next: `agent/phases/code-phase-2-hunt.md`.
