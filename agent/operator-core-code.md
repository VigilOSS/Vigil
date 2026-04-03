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

1. **ASSESS STATE** — Read `code-scope.json` (or `scope.json` with `source_repos`). Check code coverage stats via `./scripts/assess.py code-coverage`. Backend state is canonical.
2. **DECIDE NEXT ACTION** — Prioritize by current phase. In Phases 0-1, prioritize breadth (get all files classified). In Phase 2, prioritize critical modules first. In Phase 3, prioritize high-priority analysis queue items. In Phase 4, prioritize findings with highest severity for variant scanning. Coverage gaps drive decisions.
3. **FORMULATE PLAN** — Select agent, skill, module batch, and batch size. Default model policy: Claude operator and substantial workers use `Opus 4.6`. Only drop to `Sonnet 4.6` for bounded sidecar work.
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
10. **TRACK COVERAGE** — After each batch, run `./scripts/assess.py code-coverage`. Before entering Phase 5, verify the coverage gate passes (all critical files analyzed, no unresolved needs-context).
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

# 3. Verify ingestion
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

Exit: All files inventoried. Transition to Phase 1.

### Phase 1: CLASSIFY

Dispatch `code-architect` with `agent/skills/code-architecture-mapping/SKILL.md`.

Provide:
- Full file listing (from `./scripts/assess.py fetch code-files`)
- Project documentation (README, SECURITY.md, build files — read from source dir)
- Git churn data (from code_repos.git_churn_json)

On return:
```bash
# Record classifications
./scripts/assess.py code-classify <classifications-json>
# Record threat model
./scripts/assess.py code-record-threat-model <threat-model-json>
# Record modules
./scripts/assess.py code-record-modules <modules-json>
# Check progress
./scripts/assess.py code-coverage
```

Exit: Every file classified. Threat model recorded. Transition to Phase 2.

### Phase 2: CONTEXT-BUILD

Dispatch `code-context-builder` per module — **parallel across independent modules**.

For each module:
1. Fetch module's file list: files with classification critical or high in that module
2. Read the source files (host-side)
3. Include relevant headers and type definitions as shared context
4. Dispatch context-builder with the module batch + threat model summary

On return:
```bash
# Record context slices
./scripts/assess.py code-record-contexts <contexts-json>
# Populate analysis queue
./scripts/assess.py code-dispatch queue <queue-items-json>
# Check progress
./scripts/assess.py code-dispatch stats
```

**Size management:** Each dispatch targets ~15-20K lines of source code. Split large modules.

Exit: All critical/high files have context slices. Analysis queue populated. Transition to Phase 3.

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
- The fetched queue items (context slices)
- Threat model summary
- Relevant CWE pattern reference (based on slot types in the context)

On return:
```bash
# Mark items done
./scripts/assess.py code-dispatch done "id1,id2,..."
# Record analysis results
./scripts/assess.py code-record-analysis <analysis-json>
# Record any findings
./scripts/assess.py record-finding code-vuln-hunter <finding-json>
```

**Context expansion loop:** When items return as `needs-context`:
1. Read the requested functions/files (host-side)
2. Append to the context slice
3. Re-queue the item
4. Re-dispatch in next batch

Repeat until analysis queue is empty.

Exit: All queue items processed. No unresolved `needs-context`. Transition to Phase 4.

### Phase 4: VARIANT ANALYSIS

For each confirmed finding (and each `suspicious` result worth checking):

```bash
# Get findings
./scripts/assess.py fetch findings
```

Dispatch `code-variant-hunter` with:
- The finding details (CWE, pattern, taint path, guard failure)
- Candidate files (same language, classification medium or above)

On return: record variant findings and scan results.

Exit: All findings have been variant-checked. Transition to Phase 5.

### Phase 5: VERIFY AND REPORT

**Coverage gate** — must pass before proceeding:
```bash
./scripts/assess.py code-coverage
# Must show: all critical files analyzed, all high files analyzed, no needs-context
```

Dispatch `code-vuln-verifier` with all findings for final FP elimination.

On return: update finding statuses (confirmed/downgraded/killed). Record attack chains.

Then dispatch `report-writer` with `agent/skills/report-generation/SKILL.md` for the final report.
Report-writer queries `report-findings` endpoint which includes both code and web findings.

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
- **Threat model summary** (trust boundaries, entry points, slot types)
- **Module being analyzed** (for Phase 2/3 dispatches)
- **Prior findings relevant** to this dispatch (for Phase 4/5)

## Claude Dispatch Syntax

Use `@agent-name` when dispatching subagents:
- `@code-architect`
- `@code-context-builder`
- `@code-vuln-hunter`
- `@code-variant-hunter`
- `@code-vuln-verifier`
- `@report-writer`
