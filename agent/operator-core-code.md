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

## Core Loop — Code Analysis Mode

After code analysis engagement initialization completes, repeat until all critical/high files
analyzed or user signals stop:

1. **ASSESS STATE** — Read `code-scope.json` (or `scope.json` with `source_repos`). Check code coverage stats via `./scripts/assess.py code-coverage`. Backend state is canonical; use `--require-gate-pass` only for the final Phase 5 gate.
2. **DECIDE NEXT ACTION** — Prioritize by current phase. In Phases 0-1, prioritize breadth (get all files classified). In Phase 2, prioritize critical modules first. In Phase 3, prioritize high-priority analysis queue items. In Phase 4, prioritize findings with highest severity for variant scanning. Coverage gaps drive decisions.
3. **FORMULATE PLAN** — Select agent, skill, module batch, and batch size. Verify against the Pre-Dispatch Checklist (bottom of this file) before every dispatch.
4. **PRESENT OR PROCEED** — Default to CLI-first human steering with NUMBERED choices. Continue autonomously only when explicitly authorized.
5. **USE SKILLS FIRST** — Check `agent/SKILL.md` for the right skill.
   - **Phase 0 (Ingest):** operator-mechanical, no agent dispatch needed
   - **Phase 1 (Classify):** `code-architect` → `agent/skills/code-architecture-mapping/SKILL.md`
   - **Phase 2 (Context):** `code-context-builder` → `agent/skills/code-context-building/SKILL.md` (parallel per module)
   - **Phase 3 (Analyze):** `code-vuln-hunter` → `agent/skills/code-vulnerability-analysis/SKILL.md` + CWE-specific refs
   - **Phase 4 (Variant):** `code-variant-hunter` → `agent/skills/code-variant-analysis/SKILL.md`
   - **Phase 5 (Verify):** `code-vuln-verifier` → `agent/skills/code-finding-verification/SKILL.md`
6. **HOST BASH FOR SOURCE READING** — Source code is local. Read via host Bash, Claude Code Read tool, or grep/rg. This is NOT target-facing network work — Kali MCP is not needed for reading source files.
7. **DISPATCH** — ALWAYS dispatch to subagent for analysis work. Operator handles mechanical pipeline: file ingestion, queue management, context expansion fetching, coverage tracking.
8. **RECORD FINDINGS IMMEDIATELY** — Code findings use the same `./scripts/assess.py record-finding` as web findings. Canonical location format: `file:<path>:<line>`.
9. **RECORD SURFACES** — Code-specific surface types: `parser_entry`, `protocol_handler`, `crypto_operation`, `auth_check`, `file_io`, `memory_allocator`. Record via `./scripts/assess.py record-surface`.
10. **TRACK COVERAGE** — After each batch, run `./scripts/assess.py code-coverage`. Before entering Phase 5, verify the coverage gate passes with `./scripts/assess.py code-coverage --require-gate-pass` (all critical files analyzed, no unresolved needs-context).
11. **LOOP** — Back to step 1.

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
jq '.current_phase = "classify"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

Exit: All files inventoried. ctags symbol index generated if ctags is available (install Universal ctags for best results). Transition to Phase 1.

### Phase 1: CLASSIFY

Dispatch `code-architect` with `agent/skills/code-architecture-mapping/SKILL.md`.

Provide:
- Full file listing (from `./scripts/assess.py fetch "code/files?repo_id=<repo-id>&limit=5000"`)
- Project documentation (README, SECURITY.md, build files — read from source dir)
- Git churn data (from code_repos.git_churn_json)

On return:
```bash
# Record classifications
./scripts/assess.py code-classify <classifications-json>
# Record threat model
./scripts/assess.py code-record-threat-model <repo-id> <threat-model-json>
# Record modules
./scripts/assess.py code-record-modules <repo-id> <modules-json>
# Check progress
./scripts/assess.py code-coverage
```

**Before transitioning:** Review code-architect's `#### Coverage Gaps` output. If critical gaps
exist (unclassified directories, missing entry points, unclear trust boundaries), re-dispatch
with targeted scope before proceeding. Gaps here are permanent — Phase 2+ cannot recover them.

```bash
jq '.current_phase = "context-build"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

Exit: Every file classified. Threat model recorded. Coverage gaps reviewed. Transition to Phase 2.

### Phase 2: CONTEXT-BUILD (Most Critical Phase)

Phase 2 determines the ceiling of the entire engagement. A missed annotation, an unresolved
cross-module call, or a poorly-traced data flow means the vulnerability hunter in Phase 3
cannot find the bug. Invest time here — speed in Phase 2 costs findings in Phase 3.

Dispatch `code-context-builder` per module — **parallel across independent modules**.
Use sub-agents for parallelism: the operator stays as the long-running orchestrator, dispatching
and managing context-builder agents. Each sub-agent handles one module batch independently.

#### Step-by-step per module:

**1. Prepare the dispatch context (operator-mechanical):**
```bash
# Fetch module's files with classifications and slot types
./scripts/assess.py fetch "code/files?module_id=<module-id>&limit=5000"

# Read critical/high file contents (host-side)
# Include ALL header files referenced by the module — struct definitions,
# type aliases, and macro definitions are mandatory context
```

**2. Assemble the dispatch payload:**
- Module file list with classifications and slot-type annotations from Phase 1
- Threat model summary (trust boundaries, entry points, high-value targets)
- Header files and type definitions as shared context — **do not skip these**
- Path to repo `tags` file for ctags lookups
- Cross-module boundary list from Phase 1 (which functions cross into other modules)

**3. Dispatch context-builder:**
```bash
# Target: ~15-20K lines per dispatch. Split large modules into sub-batches.
# If a module has 40K lines, split by subdirectory or logical file group.
```

**4. On return — quality check before recording:**

Before recording context slices, verify the return:
- [ ] Every critical/high function in the batch has a context slice
- [ ] Context slices include sink annotations (not just call graphs)
- [ ] Guard annotations are present for functions with identified sinks
- [ ] Cross-module calls are annotated with callee signatures and slot types
- [ ] `audit_metadata.cross_ref_usage` is present (documents how cross-refs were resolved)
- [ ] `#### Coverage Gaps` section reviewed — any blocker that would cause Phase 3 to miss a vulnerability

If the context-builder reports gaps in critical modules (unresolved callees for security-relevant
functions, macro-hidden sinks, header files it couldn't find), **re-dispatch with expanded scope
before moving to Phase 3.** Do not proceed with incomplete context on critical modules.

```bash
# Record context slices
./scripts/assess.py code-record-contexts <contexts-json>
# Build and populate analysis queue from returned context ids
./scripts/assess.py code-dispatch queue <queue-items-json>
# Check progress across all modules
./scripts/assess.py code-dispatch stats
```

**5. Context expansion loop (before Phase 3):**

After ALL module batches return, review the aggregate coverage gaps:
```bash
# Check: are all critical files contextualized? Any needs-context?
./scripts/assess.py code-dispatch stats
```
- If any critical module has unresolved cross-module calls that affect security-relevant
  functions, fetch the missing code and re-dispatch the context-builder for that module.
- If header files were missing, locate them and include them in a re-dispatch.
- This loop should resolve before Phase 3 begins — every `needs-context` at the context
  level is a vulnerability the hunter will miss.

**Size management:** Each dispatch targets ~15-20K lines of source code. Split large modules
by subdirectory or file group. Prefer splitting at logical boundaries (e.g., separate the
parser from the handler) rather than arbitrary file count splits.

```bash
jq '.current_phase = "analyze"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

Exit: All critical/high files have context slices with sink and guard annotations. Coverage gaps
in critical modules resolved. Analysis queue populated. Transition to Phase 3.

### Phase 3: ANALYZE

Operator-orchestrated work-buffer loop (same pattern as web engagement's Phase 3).

```bash
# Check queue
./scripts/assess.py code-dispatch stats

# Reset stale items
./scripts/assess.py code-dispatch reset-stale 10

# Fetch batch for analysis
./scripts/assess.py code-dispatch fetch 10 code-vuln-hunter
```

Dispatch `code-vuln-hunter` with:
- The fetched queue items (context slices — fetch response includes full context + file data)
- Threat model summary
- Path to repo `tags` file for ctags lookups (if generated during ingest)
- Relevant CWE pattern reference (based on slot types in the context)

#### Slot-Type → Reference Mapping

Include the pattern references matching the context's slot types and language when dispatching code-vuln-hunter:

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

**Context expansion loop:** When items return as `needs-context`:
1. Read the requested functions/files (host-side)
2. Append to the context slice
3. Re-queue the item
4. Re-dispatch in next batch

Repeat until analysis queue is empty.

**Before transitioning:** Review aggregate `#### Coverage Gaps` across all hunter batches. If
critical taint paths terminated at unresolved callees, expand context and re-dispatch those
items. If pattern categories were skipped (e.g., crypto-misuse patterns not applied to a module
with crypto operations), re-dispatch with the correct references.

```bash
jq '.current_phase = "variant"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

Exit: All queue items processed. No unresolved `needs-context`. Coverage gaps reviewed. Transition to Phase 4.

### Phase 4: VARIANT ANALYSIS

For each confirmed finding (and each `suspicious` result worth checking), scan the codebase
for the same bug pattern in other locations. This is the code equivalent of the "sibling rule."

```bash
# Get all findings for variant scanning
./scripts/assess.py fetch findings
```

**Per finding, prepare dispatch:**
1. Extract the abstract bug pattern from the finding (CWE, taint path shape, guard failure type)
2. Identify candidate files: same language, classification `medium` or above
3. Select the CWE pattern reference matching the finding's defect family (same file the hunter used)

Dispatch `code-variant-hunter` with:
- The finding details (CWE, pattern, taint path, guard failure)
- The abstract bug pattern (generalized from the specific finding)
- Candidate files (same language, classification medium or above)
- CWE pattern reference from `agent/references/code-vuln-patterns/` matching the finding's CWE
- Threat model summary (trust boundaries for quick reachability checks)

**Parallel dispatch**: Independent findings can be variant-scanned in parallel (different sub-agents).

On return:
```bash
# Record variant findings
./scripts/assess.py record-finding code-variant-hunter <variant-finding-json>
# Verify scan coverage — check that candidate files were actually scanned
```

Review the scan results table: if high-value candidate files were skipped or if the pattern
abstraction was too narrow (0 matches across many files), consider re-dispatching with a
broader pattern definition.

```bash
jq '.current_phase = "verify"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

Exit: All confirmed findings have been variant-checked. Scan results recorded. Transition to Phase 5.

### Phase 5: VERIFY AND REPORT

**Coverage gate** — must pass before proceeding:
```bash
./scripts/assess.py code-coverage --require-gate-pass
# Must show: all critical files analyzed, all high files analyzed, no needs-context
```

If the gate fails, resolve remaining items before proceeding:
- `needs-context` items: expand context and re-dispatch to Phase 3
- Unanalyzed critical files: dispatch context-builder (Phase 2) then hunter (Phase 3)
- Do NOT skip the gate

**Verification dispatch:**

Dispatch `code-vuln-verifier` with all confirmed + suspicious findings. Include:
- Full evidence packages from code-vuln-hunter (CWE, taint path, guard evaluation)
- Variant findings from code-variant-hunter (linked to originals)
- CWE pattern references matching each finding's defect family
- Build system configuration for compile-time flag evaluation

On return:
```bash
# Update finding statuses based on verification results
# Confirmed findings: status stays "confirmed"
# Downgraded: update severity via assess.py
# Killed (false positive): update status to "killed" with reasoning
./scripts/assess.py record-finding code-vuln-verifier <updated-finding-json>
```

**Pre-report deduplication:**
Before dispatching report-writer, check for duplicate findings (same `canonical_location` and
similar `defect_family` across hunter and variant-hunter):
```bash
./scripts/assess.py merge-finding <source-slug> <target-slug> "<reason>"
```

**Report dispatch:**
Dispatch `report-writer` with `agent/skills/report-generation/SKILL.md`. Report-writer queries
the `report-findings` endpoint which includes both code and web findings.

```bash
jq '.current_phase = "complete"' "$DIR/scope.json" > "$DIR/scope_tmp.json" && mv "$DIR/scope_tmp.json" "$DIR/scope.json"
```

## Agent Roster — Code Analysis

| Agent | Role | Phase |
|-------|------|-------|
| `code-architect` | Architecture recon, threat modeling, file classification | Phase 1 |
| `code-context-builder` | Function-level context extraction with call graphs and data flow | Phase 2 (parallel per module) |
| `code-vuln-hunter` | Deep vulnerability analysis with constrained attacker persona | Phase 3 (batched, parallel) |
| `code-variant-hunter` | Systematic variant scanning across codebase | Phase 4 (parallel per finding) |
| `code-vuln-verifier` | FP elimination via full entry-to-sink traces | Phase 5 |
| `report-writer` | Final report generation (reused from web engagement) | Phase 5 |

## Finding Prefixes — Code Analysis

| Agent | Prefix | Example |
|-------|--------|---------|
| code-architect | CA | FINDING-CA-001 |
| code-context-builder | CB | FINDING-CB-001 |
| code-vuln-hunter | CH | FINDING-CH-001 |
| code-variant-hunter | CV | FINDING-CV-001 |
| code-vuln-verifier | VF | (updates only, no new findings) |

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

## Coverage Communication

After each phase transition, display:
```
Code Analysis: [x] Ingest  [x] Classify  [>] Context  [ ] Analyze  [ ] Variant  [ ] Verify
[coverage] 45/687 files critical | 89 high | 203 medium | 112 low | 238 skipped
[queue] 0 pending | 0 processing | 0 done | 0 needs-context
[findings] 0 confirmed | 0 suspicious
```

## Dispatch Context Template

Every code analysis dispatch must include:
- **Agent identity** and **repository name**
- **Current phase** and **specific task objective**
- **Which skill to load** (from `agent/SKILL.md`)
- **CWE pattern references** matching the dispatch context's slot types (Phase 3/4/5)
- **Threat model summary** (trust boundaries, entry points, slot types)
- **Module being analyzed** (for Phase 2/3 dispatches)
- **Prior findings relevant** to this dispatch (for Phase 4/5)

### Pre-Dispatch Checklist

Before every dispatch, verify:

- [ ] Agent identity named and repository specified
- [ ] Current phase stated with specific task objective (not just "analyze this")
- [ ] Skill to load identified from `agent/SKILL.md`
- [ ] CWE pattern references selected from slot-type mapping table (Phase 3) or from finding's CWE (Phase 4/5)
- [ ] Threat model summary included (trust boundaries, entry points, high-value targets)
- [ ] Module/file scope for this dispatch defined (not "everything")
- [ ] Prior findings included for Phase 4/5 dispatches (finding slugs, CWEs, affected functions)
- [ ] Log checked for duplicate dispatch — never dispatch same agent for same module/batch twice

DEDUP: Check the analysis queue and dispatch log before every dispatch. Never dispatch the same
agent for the same module or file batch twice. If re-analysis is needed (e.g., after context
expansion), state the new context explicitly so the agent knows this is a re-dispatch, not a duplicate.

## Session Resumption

On start or when resuming inside a code analysis engagement:
```bash
cat "$DIR/scope.json"                              # Current phase
./scripts/assess.py code-coverage                  # File classification + analysis coverage
./scripts/assess.py code-dispatch stats             # Queue state (pending/processing/done/needs-context)
./scripts/assess.py fetch findings                  # Existing findings
```

Resume from the current phase. If `code-dispatch stats` shows `processing` items, they were
interrupted — reset stale items with `./scripts/assess.py code-dispatch reset-stale 10` and
re-dispatch. If `needs-context` items exist, expand context and re-queue them.
