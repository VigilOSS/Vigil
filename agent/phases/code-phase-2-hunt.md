# Code Phase 2 — Hunt

**Read-on-phase-entry.** When you ENTER Code Phase 2 (Hunt), Read this doc before dispatching
`code-vuln-hunter` (broad hunt, CWE-directed re-analysis, adversarial reread, or system-level
synthesis), and re-read it on a method re-anchor or when the sub-phase changes (2A → 2B → 2C → 2D).
It carries the full 2A Broad Hunt (queue setup, fetch loop, dispatch fields, batch framing), 2B CWE
Coverage Review (effort matrix, CWE-directed re-dispatch), 2C Adversarial Depth Pass, 2D
System-Level Synthesis Pass (seam manifest, seam-scaled dispatch, reduce pass), and every sub-phase
exit gate. Cross-phase machinery — the Core Loop, the Phased mindset flow (code) (which sets
`code-vuln-hunter`'s `hunt_scope`/lens per sub-phase), the Agent Roster, and the Dispatch Context
Template / Pre-Dispatch Checklist — stays in `agent/operator-core-code.md`; this doc does not
restate it.

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
to the number of shapes: for a few, dispatch one `code-variant-hunter` over the bug-shape intel
notes; for many (Git/libcurl carry dozens of historical CVEs), cluster related shapes (e.g. all
size-arithmetic integer overflows) and fan out with `vigil assess agent start-swarm --role
code-variant-hunter --items-file tools/analysis-state/cve-bug-shapes.txt --batch-size 1-2 --skills
code-variant-analysis ...`, one specialist per worker row. Each agent verifies the fix is complete
in this revision, then hunts sibling code paths the patch never touched. Dedup results against the
main hunt before Phase 3 -- this pass is additive to the file-analysis queue, not a replacement.

**Queue setup:**
```bash
vigil assess code-dispatch queue "$DIR/tools/analysis-state/file-analysis-queue.json"
vigil assess code-dispatch stats
```

Broad-hunt queue items are file-level only (no `context_id`). Each item carries `file_id` and
`file_path` plus `priority` (mapped from classification `analysis_priority`), `batch_theme`,
`slot_types`, and `guidance_hypotheses`. `code-dispatch queue` normalizes the artifact before
posting -- include both `file_id` and `file_path` so the queue stays human-readable and the
normalizer can resolve either one; `repo_id` is a disambiguation helper only, not a queue field.

**Fetch loop:**
```bash
vigil assess code-dispatch reset-stale 10
vigil assess code-dispatch stats

# Claims up to 10 queue rows atomically (a queue-claim convenience, not a dispatch batch size)
vigil assess code-dispatch fetch 10 code-vuln-hunter

# Narrow a lane atomically by repo/class/theme or explicit queue ids
vigil assess code-dispatch fetch 10 code-vuln-hunter --repo-id <repo-id> --classification high --batch-theme <theme>
vigil assess code-dispatch fetch 10 code-vuln-hunter --ids-file <queue-ids-json>
```

Pass lane filters to `fetch` instead of claiming broadly and filtering the response -- repository,
classification, theme, and explicit-id predicates run inside the serialized claim query, leaving
unrelated pending work available. Preserve each returned `agent_name`, `lease_token`, and
`repo_generation` for results, heartbeats, and closeout.

Split the claimed batch into the smaller per-dispatch sizes above whenever code volume, framework
noise, or support metadata would outweigh the source files, or when fetched items span unrelated
modules/entry chains/trust boundaries -- dispatch multiple hunters in parallel rather than handing
one oversized mixed batch to a single agent.

**Dispatch `code-vuln-hunter`** with `agent/skills/code-vulnerability-analysis/SKILL.md` and:

- **File paths** -- from the fetched queue items; the hunter reads them directly from the filesystem.
- **Batch theme** -- the logical module grouping, so files in the batch share cross-file context.
- **Slot types** -- the slot type annotations for each file from Phase 1 classification.
- **Applicable vulnerability classes** -- pass the backend-computed `applicable_vuln_classes` list
  through unmodified (`SLOT_VULN_CLASSES` in `orchestrator/backend/app/services/code_analysis.py`,
  from the canonical taxonomy `agent/scripts/assess/lib/vuln_taxonomy.py`); do not hand-copy a
  slot->class table, it drifts from the backend. This is a coverage floor, not a ceiling -- every
  named class gets an effort score, and anything else the reading surfaces is still the hunter's
  to flag.
- **Guidance hypotheses** -- labeled "check AFTER broad analysis." The skill's Steps 3-4 already
  define why the first pass runs unconstrained by these hypotheses and checks them second (not
  re-derived here); "unconstrained" means not pre-anchored to the architect's guesses, not exempt
  from the applicable-classes floor above.
- **Structural index** -- the manifest path plus relevant per-file index paths from
  `tools/analysis-state/structural-index/` (run `vigil assess code-index` first if missing). The
  function map is the completeness anchor (`agent/shared-constraints-code.md` §2); sinks, exports,
  and import targets stay advisory navigation, not a scope limiter.
- **Call graph excerpt** -- the relevant entry chain plus the artifact path to
  `tools/analysis-state/call-graph.json`; inline only edges that change this dispatch's reasoning.
- **Threat model summary** -- trust boundaries, entry points, high-value targets, and **trusted
  inputs** (operator-owned config, env secrets, internal mTLS/IAM callers, authenticated
  principals -- sources the hunter should NOT treat as attacker-controlled, and the single biggest
  false-positive suppressor). A 3-8 bullet summary, not the full Phase 1 artifact.
- **Root-cause candidate capture** -- ask the hunter to put shared utilities/guards it suspects
  cause several findings in handoff `extras.root_cause_candidates`, for the Phase 4 grouping pass.
- **CWE pattern references** -- trigger-gated, not pre-loaded: when a slot type or code pattern in
  the batch signals a class, load the matching file(s) from `agent/references/code-vuln-patterns/`
  yourself (list the directory, or match filename to the observed signal -- e.g. a parser over
  FILE-CONTENT suggests `path-traversal.md`/`file-upload.md`; a crypto call suggests
  `crypto-misuse.md`). Pass the directory path in the dispatch context, not a pre-selected file
  list -- preloading every plausible file for a mixed batch is what blows the context budget below.
- **Effort score is a judgment, not a target to hit.** Per-family thresholds (critical 70, high 50)
  are a WARN at `transition-phase`; the operator enforces them after the fact with `vigil assess
  code-coverage --require-gate-pass`. Tell the hunter the goal -- examine every applicable class to
  the depth the file's role warrants -- not the number: the structural cross-check
  (`agent/shared-constraints-code.md` §12) catches an inflated score without matching depth
  regardless of what's submitted.
- **Batch framing** -- include verbatim, filled in with this batch's entry points and function
  chains:

> These source files sit on the traced path from [entry points] through [function chains] to a
> privileged operation or a trust-boundary crossing -- that reachability, not a prior finding, is
> why this batch was selected. Static analysis tools do not reason across function boundaries, so
> their blind spots are exactly the multi-function reasoning chains, error-handling paths, integer
> arithmetic, and protocol edge cases this pass should weigh most heavily. A batch that holds up
> under that scrutiny is a valid result -- report it clean with the reasoning that ruled each
> pattern out, not a forced finding.

**Full filesystem access** (`agent/shared-constraints-code.md` §3) applies here as everywhere --
the file batch is a starting point, not a cage.

**Context budget rule**: every field above stays sized to help the hunter navigate, not to
outweigh the source files -- compress structural index / call graph / threat model content before
dispatch if it is crowding out the code under review.

**On return:**
```bash
vigil assess contract code-record analysis   # confirm the shape if the payload was hand-authored
vigil assess code-record analysis <analysis-json>   # cwe_coverage + cross_file_triggers

# Preview the completion payload before committing queue history when unsure:
vigil assess code-dispatch done <item-id> <agent-name> <lease-token> <clean|finding|suspicious> <cwe-coverage-json> ["notes"] --dry-run

# cwe-coverage-json is a file path, not inline JSON -- write the bare array (shape:
# agent/skills/code-vulnerability-analysis/SKILL.md "CWE Coverage") to a temp file first:
cat > /tmp/cwe_<item-id>.json <<'JSON'
[{"family": "buffer-overflow", "effort": 85, "functions_analyzed": 12, "entry_chains_traced": 3, "total_entry_chains": 3, "notes": "Traced all applicable parser entry chains"}]
JSON

vigil assess code-dispatch done <item-id> <agent-name> <lease-token> <clean|finding|suspicious> /tmp/cwe_<item-id>.json ["notes"]
vigil assess finding record code-vuln-hunter <finding-json>
vigil assess code-dispatch requeue-triggers <triggers-json>   # if analysis returned cross_file_triggers
vigil assess code-dispatch reset-stale 10   # before fetching the next batch
```

Use `code-dispatch done` with `clean`, `finding`, or `suspicious` -- the queue history is only
useful if every completion records a valid disposition and a complete `cwe_coverage` array (the
bare JSON array, not wrapped in an object) instead of a half-formed backend 422. Include one entry
per `applicable_vuln_classes` value, with explicit zero-effort gap entries for anything unexamined.
Record the analysis result before closeout: `finding`/`suspicious` require a current result with
inline `evidence` or an `evidence_ref`; `clean` requires non-empty family coverage and review
notes. Per-file detail derives from result rows, evidenced rows, and distinct-function effort, so a
submitted effort number alone is not proof of work.

**Handling needs-context returns:** Check what's missing and why. If the hunter could have
self-resolved it via filesystem access, note that as a process gap for future dispatches. If the
gap is genuinely unresolvable (external library source, binary dependency, macro-generated code),
re-queue with `vigil assess code-dispatch needs-context ...` and the missing-dependency context --
never `code-dispatch done needs_context`, since incomplete work must carry explicit expansion
metadata instead of looking complete in the queue history.

**Cross-file triggers:** Process `cross_file_triggers` with `code-dispatch requeue-triggers`, which
queues the target files if not already queued or completed. Unprocessed triggers are
gate-blocking: the phase does not pass until each is queued or already completed.

**Findings-density signal:** If a single file yields >= 2 findings AND is > 500 LOC, note it for
the Phase 2C adversarial pass -- density signals the original hunter was anchored by its first
discoveries and more issues likely remain.

**Repeat** the fetch-dispatch-done loop until the queue is drained.

**Phase 2A exit gate -- ALL of the following must be true:**
- [ ] All critical/high files from the file analysis queue analyzed at least once
- [ ] No unresolved `needs-context` items on critical/high files
- [ ] All cross-file triggers processed (target files queued or already completed)
- [ ] Coverage stats checked: `vigil assess code-coverage`

#### Phase 2B -- CWE Coverage Review

Phase 2B closes effort gaps Phase 2A left open, using the CWE effort matrix.

```bash
vigil assess code-coverage --cwe-matrix
```

Shows, per critical/high file: expected classes from `SLOT_VULN_CLASSES`, current effort per class,
threshold flags (`!` = below threshold), and a structural cross-check (self-reported
`functions_analyzed` against the structural index's actual function count -- a gap suggests the
hunter skipped functions needing a disposition). If every critical/high file meets threshold and no
cross-file triggers are pending, go to Phase 3.

Otherwise: process any pending cross-file triggers first (`vigil assess code-coverage`, `vigil
assess code-dispatch reset-stale 10`) -- a trigger may add a file that closes a gap class, shrinking
the re-dispatch scope. Then group the remaining files by which classes are below threshold and
dispatch `code-vuln-hunter` in CWE-Directed Re-Analysis Mode:

```json
{"cwe_directives": ["path-traversal", "injection"], "prior_effort": {"path-traversal": {"effort": 25, "functions_analyzed": 1, "notes": "checked main handler only"}, "injection": {"effort": 40, "functions_analyzed": 3, "notes": "basic sink check"}}, "target_effort": 70, "entry_chains_to_trace": ["handleUpload -> FileUtils.copyFile -> FileOutputStream.write"], "cwe_pattern_refs": ["agent/references/code-vuln-patterns/injection.md", "agent/references/code-vuln-patterns/web-app-injection.md"]}
```

Include the same structural index, call graph excerpt, and threat model summary as Phase 2A. The
hunter reads the file in full, focuses on the directed classes, and raises effort toward the
target. On return, record and close out exactly as in Phase 2A's "On return" above (`code-record
analysis`, `code-dispatch done` with the updated `cwe_coverage` -- the backend uses a max-effort
merge -- any new findings, and any new triggers).

Re-check the matrix (`code-coverage --cwe-matrix`) after each round. If gaps remain on critical
files: re-dispatch when the hunter marked `needs-context` or traced only a subset of entry chains;
accept with a documented exclusion when the class is genuinely not applicable despite the
slot-type mapping suggesting it (e.g. a NETWORK-INPUT file that only handles binary protocol
frames has no injection surface); and stop re-dispatching a given file/class once another round
would plausibly add nothing new -- that judgment, not a round count, is what decides diminishing
returns. Document whichever reason applies and proceed.

**Phase 2B exit gate -- ALL of the following must be true:**
- [ ] All critical/high files meet the tier thresholds shown by `code-coverage --cwe-matrix` on every applicable vulnerability class, or carry a documented exclusion
- [ ] Medium files received best-effort review (no blocking gate)
- [ ] No pending cross-file triggers
- [ ] Every entry chain on a critical file that reaches a privileged operation or an untrusted input boundary has been traced to a guard or to a sink -- name any chain you could not trace and why (blocked on missing code, genuinely out of scope, or a chain the call graph never resolved)

**Suspicious finding resolution:** Before leaving Phase 2, resolve every `suspicious` finding by
re-dispatching the hunter with the documented gap as targeted context, until it reaches `confirmed`
(promoted to finding) or `clean` (hypothesis disproven). Do not pass unresolved `suspicious`
findings to the verifier -- its job is FP elimination on confirmed findings, not investigation of
incomplete ones.

**Phase 2 exit:** 2A, 2B, 2C, and 2D gates all hold, and no unresolved suspicious findings remain.

```bash
vigil assess transition-phase verify-variant
```

Transition to Phase 3. Adversarial depth pass (2C) and system-level synthesis pass (2D) below must
also be complete first.

#### Phase 2C -- Adversarial Depth Pass

After the coverage gate passes, select 10-20 files for an independent hostile reread. The broad
coverage pass anchors agents on "complete correctly"; this pass resets the mission to "find the
critical that survived."

**File selection is judgment, not a fixed category list.** The coverage pass likely missed
findings where security decisions happen (auth, policy, access control, crypto), where finding
density was high (2+ findings in a file signals more remain), in large files (>500 LOC) analyzed
under queue pressure, or in config/policy files that define execution behavior but were classified
medium. Pick the 10-20 files that represent the highest-risk attack surface for this specific
codebase and threat model -- what an adversary would actually target, not a generic checklist.

**Dispatch rules:**
- Use `deep-manual` mode (not item-iterating)
- Do NOT include prior findings from Phase 2A in the dispatch context — the hunter must approach
  fresh without anchoring on existing findings. This holds even when a file was selected for 2C
  because of its Phase 2A finding density: that density is the operator's selection criterion for
  choosing the file, not content the hunter receives — passing it through would recreate the
  anchoring the fresh pass exists to avoid.
- Include: structural index, call graph, threat model, CWE patterns, but NOT the list of
  already-found issues
- Dispatch objective: "Find High/Critical vulnerabilities in these files. Ignore coverage metrics.
  Focus on semantic fail-opens, logic bugs, and design flaws."
- If this pass independently re-surfaces a Phase 2A finding, that is convergent evidence the
  pattern is real, not an error — see `code-vuln-hunter.md` "On a RESUMED engagement" for how the
  backend's D4 guard treats a rediscovery of something Phase 3 already killed.

**On return:** Record findings and analysis results normally. This pass does NOT need to satisfy
CWE coverage thresholds — it produces findings, not coverage closure.

**Phase 2C exit:** All dispatched files reviewed. Findings recorded.

#### Phase 2D -- System-Level Synthesis Pass

Phases 2A-2C are file-local: each hunter sees one module. Some vulnerabilities exist only *between*
partitions — an auth check in module A that module B's entry path bypasses, a privilege escalation
formed by combining two individually-low findings, a trust boundary no single file owns. These are
invisible to any file-batch dispatch by construction, so they get a dedicated pass.

**The unit of synthesis is a seam, not "the whole codebase."** On a large repo (Git, libcurl, a
kernel) the full call graph + finding set never fits one context, and a single synthesis agent
would skim and miss exactly the cross-module bugs this pass exists to find. Enumerate bounded seams
and fan out one focused agent per seam. Tokens and wall-clock are not the constraint here — coverage
is (`agent/rules/hunting.md` §16); scale the agent count to the seam count.

**Step 1 — Build the seam manifest** (operator-mechanical, from artifacts already on disk). Derive
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

**Step 2 — Scale the dispatch to the seam count.** For a few seams (the manifest fits one focused
context), dispatch ONE `code-vuln-hunter` in `deep-manual` mode with the whole seam manifest, the
cross-module call graph, the threat model (trust boundaries + trusted inputs), and the module map.
At Git/libcurl scale, fan out with `vigil assess agent start-swarm --role code-vuln-hunter
--items-file tools/analysis-state/seams.txt --batch-size 1-3 --skills code-vulnerability-analysis
--task "system-level synthesis: <objective>"`, one specialist per worker row. Keep batch-size small
(1-3 seams) so each agent reasons deeply about coherent crossings instead of skimming dozens; each
worker reads its seam slice from `seams/<id>.json`.

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
