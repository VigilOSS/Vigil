# Code Phase 2 — Hunt

**Read-on-phase-entry.** When you ENTER Code Phase 2 (Hunt), Read this doc before dispatching
`code-vuln-hunter` (broad hunt, CWE-directed re-analysis, adversarial reread, or system-level
synthesis), and re-read it on a method re-anchor or when the sub-phase changes (2A → 2B → 2C → 2D).
It carries the full 2A Broad Hunt (queue setup, fetch loop, dispatch fields, adversarial framing
preamble), the Slot-Type -> Reference Mapping table, 2B CWE Coverage Review (effort matrix,
CWE-directed re-dispatch, re-dispatch caps), 2C Adversarial Depth Pass, 2D System-Level Synthesis
Pass (seam manifest, seam-scaled dispatch, reduce pass), and every sub-phase exit gate. Cross-phase
machinery — the Core Loop, the Phased mindset flow (code) (which sets `code-vuln-hunter`'s
`hunt_scope`/lens per sub-phase), the Agent Roster, and the Dispatch Context Template / Pre-Dispatch
Checklist — stays in `agent/operator-core-code.md`; this doc does not restate it.

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

**CVE bug-shape seeding (when the architect produced `tools/analysis-state/cve-bug-shapes.txt`).**
Before the broad-hunt loop, hunt the historical bug-shapes — "is this old bug's fix complete and
applied everywhere?" is a faster path to a finding than rediscovering the class. Scale the dispatch
to the number of shapes:
- **Few shapes:** dispatch one `code-variant-hunter` over the bug-shape intel notes.
- **Many shapes (Git/libcurl carry dozens of historical CVEs):** cluster related shapes (e.g. all
  size-arithmetic integer overflows into one cluster) and fan out with
  `vigil assess agent start-swarm --role code-variant-hunter --items-file
  tools/analysis-state/cve-bug-shapes.txt --batch-size 1-2 --skills code-variant-analysis ...`,
  firing one specialist per worker row.
Each agent, for its shape(s): verify the fix is complete in this revision, then hunt sibling code
paths for the same pattern the patch never touched. Dedup results against the main hunt before
Phase 3. This pass is additive to the file-analysis queue, not a replacement for it.

**Queue setup:**
```bash
# Load file analysis queue into the dispatch engine
vigil assess code-dispatch queue "$DIR/tools/analysis-state/file-analysis-queue.json"

# Check queue state
vigil assess code-dispatch stats
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
vigil assess code-dispatch reset-stale 10

# Check stats
vigil assess code-dispatch stats

# Fetch batch for analysis -- returns file-based items grouped by batch_theme
vigil assess code-dispatch fetch 10 code-vuln-hunter
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
  queue fetch payload. The backend computes this canonically from slot types, role, and language
  (`SLOT_VULN_CLASSES` in `orchestrator/backend/app/services/code_analysis.py`, derived from the
  canonical taxonomy `agent/scripts/assess/lib/vuln_taxonomy.py`). Pass that computed list through;
  do NOT transcribe a slot→class table here — a hand-copied one drifts from the backend. The hunter
  must evaluate every class the payload names, not just the ones touched by hypotheses.

- **Guidance hypotheses** -- labeled "check AFTER broad analysis" in the dispatch context.
  These are the attack hypotheses from Phase 1 that touch files in this batch. The hunter
  performs unconstrained broad analysis first, then checks these hypotheses second. This
  ordering prevents hypothesis anchoring where the analysis scope narrows to the architect's
  predictions.
- **Structural index** -- pass the manifest path plus the relevant per-file index paths from
  `tools/analysis-state/structural-index/`. If the manifest is missing, stop and run
  `vigil assess code-index` before dispatching. Inline only the minimal function
  excerpt needed for prioritization. The function map is the primary completeness anchor:
  every listed function must receive a disposition. Sinks, exports, and import targets are
  advisory metadata that helps the hunter navigate -- they do not limit what the hunter looks
  for. The hunter's unconstrained analysis may find issues tree-sitter cannot detect.
- **Call graph excerpt** -- give a short summary of the relevant entry chain plus the artifact path
  to `tools/analysis-state/call-graph.json`. Inline only the edges that materially change the
  hunter's reasoning for this dispatch.
- **Threat model summary** -- trust boundaries, entry points, high-value targets, and **trusted
  inputs** (sources the hunter should NOT treat as attacker-controlled: operator-owned config,
  env secrets, internal mTLS/IAM callers, authenticated principals) relevant to this batch from
  the Phase 1 threat model. Passing the trusted set is what suppresses the most common false
  positive -- a guard flagged "missing" on input that was never attacker-controlled. Keep this
  short and file-local; do not dump the full Phase 1 artifact when a 3-8 bullet summary will do.
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
| FILE-CONTENT | `injection.md`, `buffer-overflow.md`, `path-traversal.md`, `file-upload.md` | `type-confusion.md` if parser with unions/variants; `xxe.md` if XML/SOAP/WSDL parser in scope |
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
vigil assess contract code-record-analysis

# Record analysis results (with cwe_coverage and cross_file_triggers)
vigil assess code-record-analysis <analysis-json>

# Preview the exact completion payload before committing queue history when unsure
vigil assess code-dispatch done <item-id> <clean|finding|suspicious> <cwe-coverage-json> ["notes"] --dry-run

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
vigil assess code-dispatch done <item-id> <clean|finding|suspicious> /tmp/cwe_<item-id>.json ["notes"]

# Record any findings
vigil assess record-finding code-vuln-hunter <finding-json>

# Process cross-file triggers (if analysis returned any)
vigil assess code-dispatch requeue-triggers <triggers-json>

# Before fetching the next batch, reset items stuck in-progress:
vigil assess code-dispatch reset-stale 10
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
4. Re-queue the item with `vigil assess code-dispatch needs-context ...` -- do not use
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
- [ ] Coverage stats checked: `vigil assess code-coverage`

#### Phase 2B -- CWE Coverage Review

Phase 2B closes effort gaps that Phase 2A left open. The broad hunt may have covered some
vulnerability classes thoroughly while leaving others shallow -- 2B uses the CWE effort matrix
to find and close those gaps systematically.

**Step 1: Generate effort matrix:**
```bash
vigil assess code-coverage --cwe-matrix
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
vigil assess code-coverage

# Reset stale items
vigil assess code-dispatch reset-stale 10
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
vigil assess code-dispatch done <item-id> <clean|finding|suspicious> <cwe-coverage-json> ["notes"] --dry-run

# Mark done with updated cwe_coverage (backend uses max-effort merge)
vigil assess code-dispatch done <item-id> <clean|finding|suspicious> <cwe-coverage-json> ["notes"]

# Record any new findings
vigil assess record-finding code-vuln-hunter <finding-json>

# Process any new cross-file triggers
vigil assess code-dispatch requeue-triggers <triggers-json>
```

**Step 5: Re-check effort matrix:**
```bash
vigil assess code-coverage --cwe-matrix
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

**Phase 2 exit:** 2A, 2B, 2C, and 2D gates pass, AND no unresolved suspicious findings remain.

```bash
vigil assess transition-phase verify-variant
```

Exit: All critical/high files analyzed with effort thresholds met. CWE coverage gaps closed
or documented. No unresolved needs-context. No pending triggers. No unresolved suspicious
findings. Adversarial depth pass (2C) and system-level synthesis pass (2D) complete. Transition
to Phase 3.

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

#### Phase 2D -- System-Level Synthesis Pass

Phases 2A-2C are file-local: each hunter sees one module. Some vulnerabilities exist only *between*
partitions — an auth check in module A that module B's entry path bypasses, a privilege escalation
formed by combining two individually-low findings, a trust boundary no single file owns. These are
invisible to any file-batch dispatch by construction, so they get a dedicated pass.

**The unit of synthesis is a seam, not "the whole codebase."** On a large repo (Git, libcurl, a
kernel) the full call graph + finding set never fits one context, and a single synthesis agent would
skim and miss exactly the cross-module bugs this pass exists to find. Enumerate bounded seams and
fan out one focused agent per seam. Tokens and wall-clock are not the constraint here — coverage is
(`agent/rules/hunting.md §16`); scale the agent count to the seam count.

**Step 1 — Build the seam manifest (operator-mechanical, from artifacts already on disk).** Derive
two seam classes and write each to `tools/analysis-state/seams/<seam_id>.json` plus a flat
`tools/analysis-state/seams.txt` index:
- **Structural seams** — group `call-graph.json` edges with `crosses_trust_boundary: true` by
  `(caller_module, callee_module)`. Each group is one seam carrying: the edge subgraph, the
  entry-point chains that traverse it, the trust boundary + trusted-inputs note for that crossing,
  and every finding whose location falls in either module.
- **Capability seams** — bucket findings by primitive (read / write / SSRF / redirect /
  auth-state-change / info-leak / injection-sink) and form the composable pairs from the
  `agent/agents/exploit-developer.md` A→B chain table (info-leak + redirect, SSRF + metadata, IDOR +
  impersonation, ...). Each promising pair-bucket is one seam. Bucket by capability so this stays
  O(capabilities²), never O(findings²).

**Step 2 — Scale the dispatch to the seam count.**
- **Few seams (the manifest fits one focused context):** dispatch ONE `code-vuln-hunter` in
  `deep-manual` mode with the whole seam manifest, the cross-module call graph, the threat model
  (trust boundaries + trusted inputs), and the module map.
- **Many seams (Git/libcurl scale):** fan out with
  `vigil assess agent start-swarm --role code-vuln-hunter --items-file
  tools/analysis-state/seams.txt --batch-size 1-3 --skills code-vulnerability-analysis --task
  "system-level synthesis: <objective>"`, then fire one specialist per worker row. Keep batch-size
  small (1-3 seams) so each agent reasons deeply about coherent crossings instead of skimming dozens;
  each worker reads its seam slice from `seams/<id>.json`.

Synthesis objective (per agent): "These seams join modules with different trust assumptions. For
each: does one side's guarantee fail to hold as the other side's assumption? Can a finding/primitive
on one side combine with the other to escalate? Does either entry path bypass the other's guard?
Reason across the seam; do not re-audit individual files."

**Step 3 — Reduce (transitive / multi-hop chains).** Seam agents find 2-module chains; 3+-module
chains (A→B→C) form by joining seam outputs that share a module. Collect all candidate chains and
dispatch a consolidation pass (`code-vuln-hunter` or `exploit-developer`) to hunt the joins. If the
candidate set is large, partition the reduce by subsystem — one reduce agent per subsystem touching
many seams — a tree, not a single reduce.

Record findings normally. This pass does not need to satisfy CWE coverage thresholds; it produces
findings, not coverage closure.

**Phase 2D exit:** Seam manifest built. One synthesis agent per seam (or a single dispatch when the
manifest fits one context). Reduce pass run for multi-hop chains. Findings recorded.

---

Phase index (path → purpose) lives in `agent/operator-core-code.md` under "Phase Index". Prior:
`agent/phases/code-phase-1-classify-map.md`. Next: `agent/phases/code-phase-3-verify-variant.md`.
