# Code Phase 2 — Hunt

**Read-on-phase-entry.** When you ENTER Code Phase 2 (Hunt), Read this doc before dispatching
`code-vuln-hunter` (broad hunt, CWE-directed re-analysis, adversarial reread, or system-level
synthesis), and re-read it on a method re-anchor or when the sub-phase changes (2A → 2B → 2C → 2D).
It carries the full 2A Broad Hunt (queue setup, fetch loop, dispatch fields, batch framing), 2B CWE
Coverage Review (effort matrix, CWE-directed re-dispatch), 2C Adversarial Depth Pass, 2D
System-Level Synthesis Pass (seam manifest, seam-scaled dispatch, reduce pass), and each sub-phase
completion/readiness check. Cross-phase machinery — the Core Loop, the Phased mindset flow (code) (which sets
`code-vuln-hunter`'s `hunt_scope`/lens per sub-phase), the Agent Roster, and the Dispatch Context
Template / Pre-Dispatch Checklist — stays in `agent/operator-core-code.md`; this doc does not
restate it.

### Phase 2: HUNT

Operator-orchestrated. This is the most expensive phase -- use Opus.

Phase 2 has four sub-phases: **2A (Broad Hunt)** discovers vulnerabilities through comprehensive
file-level analysis of every admitted file, **2B (CWE Coverage Review)** closes effort gaps on critical/high files,
**2C (Adversarial Depth)** independently rereads the highest-risk files, and **2D (System-Level
Synthesis)** hunts cross-module seams and chains.

Every Phase 2 dispatch carries the current Code Source Identity, its matching structural-index
manifest, and the complete backend threat-model envelope only when `current: true` and its
generation/digest match that identity. A clipped threat summary is supplemental navigation, never
a substitute for this bound tuple. If any member is missing or stale, return to its Phase 0/1 owner
before dispatch.

Hunters read actual source files directly from the sealed `snapshot_path`, navigating with the
bound structural index, call graph excerpts, and attack hypotheses as guidance. They have full
sealed-source access to trace beyond the provided file batch when needed.

Adaptive batching is part of the method, not a convenience:
- Default to 1 logical module or 1-3 tightly related files per hunter dispatch
- Shrink further when files are large, parser-heavy, stateful, or the supporting metadata would
  crowd out the actual source
- Widen only when multiple files form one tight entry-chain and the added context materially
  improves reasoning
- Treat fetch size as queue mechanics, not mandatory prompt size

#### Phase 2A -- Broad Hunt

**CVE bug-shape seeding (when the architect produced
`tools/analysis-state/cve-bug-shapes.jsonl`).**
Before the broad-hunt loop, hunt the historical bug-shapes — "is this old bug's fix complete and
applied everywhere?" is a faster path to a finding than rediscovering the class. The Phase 1
architecture contract defines one compact, evidence-backed JSON object per physical line, so a
two-line worker batch always carries one or two complete shapes. Scale the worker count from the
actual line count and use an integer batch size:

```bash
shape_count=$(wc -l < "$DIR/tools/analysis-state/cve-bug-shapes.jsonl")
worker_count=$(( (shape_count + 1) / 2 ))
vigil assess agent start-swarm --role code-variant-hunter --code-repo-id <repo-id> \
  --workers "$worker_count" --batch-size 2 \
  --items-file "$DIR/tools/analysis-state/cve-bug-shapes.jsonl" \
  --skills code-variant-analysis \
  --no-target-traffic \
  --task "Verify each assigned historical fix and hunt semantic siblings"
```

For each printed worker row, pass its exact assigned JSONL line range in the dispatch context; the
record's vulnerable/fixed evidence is the seed, while source reads remain rooted at the current
sealed snapshot. Each agent verifies the fix is complete in this revision, then hunts sibling code
paths the patch never touched. Dedup results against the main hunt before Phase 3 -- this pass is
additive to the file-analysis queue, not a replacement.
Dispatch it under the `code-variant-hunter.md` **Phase 2 discovery mode** contract: Runtime Identity
selects the mode, historical CVE/patch evidence supplies the seed, both Variant Receipt Authority
fields stay absent, and the handoff remains explicitly non-covering with no variant-check receipts.

**The queue is already loaded.** Phase 1's on-return sequence runs `code-dispatch queue`, and hunt
readiness refuses transition while any admitted current-generation file has no queue row -- so
arriving here unqueued is not a reachable state. Its payload contract lives with that step in
`agent/phases/code-phase-1-classify-map.md`. Start from `stats`, not from a second load:

```bash
vigil assess code-dispatch stats
```

**Fetch loop:**
```bash
vigil assess code-dispatch reset-stale 10
vigil assess code-dispatch stats

# Read-only: what is in the queue right now, and the exact ids for a lane
vigil assess code-dispatch list --repo-id <repo-id> --status pending
vigil assess code-dispatch list --repo-id <repo-id> --batch-theme <theme> --status pending --ids-only > ids.json

# Claims up to 10 queue rows atomically (a queue-claim convenience, not a dispatch batch size)
vigil assess code-dispatch fetch 10 code-vuln-hunter

# Narrow a lane atomically by repo/class/theme/queue-mode or explicit queue ids
vigil assess code-dispatch fetch 10 code-vuln-hunter --repo-id <repo-id> --classification high --batch-theme <theme>
vigil assess code-dispatch fetch 10 code-vuln-hunter --queue-mode trigger
vigil assess code-dispatch fetch 10 code-vuln-hunter --ids-file ids.json
```

`list` claims nothing and pages in the order `fetch` claims, so it is how you recover the ids for an
explicit-id batch: the insertion output caps at 200 rows and scrolls away, and its ids were
previously unrecoverable through any supported surface. Write `--ids-only` straight to the ids file
-- it is the same contract `fetch --ids-file` reads, so never scrape ids out of presentation text.
Two things make that file a *claim* set rather than an inventory: pass `--status pending`, because
`list` deliberately reports every current attempt while `fetch` only claims unleased pending rows;
and read its stderr, because a page that stopped at `--limit` says so there and nowhere else.
Requeued cross-file-trigger rows keep `queue_mode=trigger`, which is how you find them in either
command after they leave their original theme's lane.

Pass lane filters to `fetch` instead of claiming broadly and filtering the response -- repository,
classification, theme, queue-mode, and explicit-id predicates run inside the serialized claim query,
leaving unrelated pending work available. Preserve each returned `agent_name`, `lease_token`, and
`repo_generation` for results, heartbeats, and closeout.

Split the claimed batch into the smaller per-dispatch sizes above whenever code volume, framework
noise, or support metadata would outweigh the source files, or when fetched items span unrelated
modules/entry chains/trust boundaries -- dispatch multiple hunters in parallel rather than handing
one oversized mixed batch to a single agent.

**Dispatch `code-vuln-hunter`** with `agent/skills/code-vulnerability-analysis/SKILL.md` and:

- **File paths** -- from the fetched queue items; resolve every relative path beneath the current
  Code Source Identity `snapshot_path`, never beneath the mutable origin.
- **Batch theme** -- the logical module grouping, so files in the batch share cross-file context.
- **Slot types** -- the slot type annotations for each file from Phase 1 classification.
- **Applicable vulnerability classes** -- pass the backend-computed `applicable_vuln_classes` list
  through unmodified (`SLOT_VULN_CLASSES` in `orchestrator/backend/app/services/code_analysis.py`,
  from the canonical taxonomy `agent/scripts/assess/lib/vuln_taxonomy.py`); do not hand-copy a
  slot->class table, it drifts from the backend. This is a coverage floor, not a ceiling -- every
  named class gets an effort score, and anything else the reading surfaces is still the hunter's
  to flag. For every C/C++ file, sanity-check that the list includes `error-handling` and
  `algorithmic-dos`: cleanup/partial-I/O failures and attacker-controlled CPU, allocation,
  retry, or retention are baseline review surfaces, not optional memory-safety extras. A missing
  baseline family is a dispatch-input defect to repair before review, not permission to omit it.
- **Guidance hypotheses** -- labeled "check AFTER broad analysis." The skill's Steps 3-4 already
  define why the first pass runs unconstrained by these hypotheses and checks them second (not
  re-derived here); "unconstrained" means not pre-anchored to the architect's guesses, not exempt
  from the applicable-classes floor above.
- **Structural index** -- the manifest path plus relevant per-file index paths from
  the Code Source Identity block (return to Phase 0 for a generation-bound rebuild if missing). The
  function map is the completeness anchor (`agent/shared-constraints-code.md` §2); sinks, exports,
  and import targets stay advisory navigation, not a scope limiter.
- **Call graph excerpt** -- the relevant entry chain plus the artifact path to
  `tools/analysis-state/call-graph.json`; inline only edges that change this dispatch's reasoning.
- **Current threat-model envelope plus a clipped summary** -- fetch
  `code/threat-model/<repo-id>`, require `current: true` and generation/digest equality with Code
  Source Identity, then summarize the product surface profile and evidence, target-kind entry
  points, product-reachability versus attacker-control status, trust boundaries, high-value targets,
  and **trusted inputs** (operator-owned config, env secrets, internal mTLS/IAM callers, authenticated
  principals -- sources the hunter should NOT treat as attacker-controlled, and the single biggest
  false-positive suppressor). Pass the complete bound envelope and add a 3-8 bullet summary for
  orientation; do not replace the envelope with those bullets.
- **Lease scratch directory** -- pass the `scratch_dir` that `code-dispatch fetch` returned for
  this lease, and tell the hunter to write temporary files there in preference to any scratch
  location its own client harness offers. The lease namespace is what keeps two hunters working the
  same repository from overwriting each other; a client-provided scratch path is shared per session,
  not per lease. Inside any directory the client harness also writes to, require lane-unique
  filenames for the same reason.
- **Root-cause candidate capture** -- ask the hunter to put shared utilities/guards it suspects
  cause several findings in handoff `extras.root_cause_candidates`, for the Phase 4 grouping pass.
- **CWE pattern references** -- trigger-gated, not pre-loaded: when a slot type or code pattern in
  the batch signals a class, load the matching file(s) from `agent/references/code-vuln-patterns/`
  yourself (list the directory, or match filename to the observed signal -- e.g. a parser over
  FILE-CONTENT suggests `path-traversal.md`/`file-upload.md`; a crypto call suggests
  `crypto-misuse.md`). Pass the directory path in the dispatch context, not a pre-selected file
  list -- preloading every plausible file for a mixed batch is what blows the context budget below.
- **Effort score is a judgment, not a target to hit.** Per-family thresholds (critical 70, high 50)
  remain advisory at `transition-phase`; inspect them with `vigil assess code-coverage --cwe-matrix`
  or use `--require-gate-pass` only when a strict shell signal helps drive a quality-remediation
  loop. Tell the hunter the goal -- examine every applicable class to
  the depth the file's role warrants -- not the number: the structural cross-check
  (`agent/shared-constraints-code.md` §12) catches an inflated score without matching depth
  regardless of what's submitted.
- **Batch framing** -- include verbatim, filled in with this batch's entry points and function
  chains:

> These source files sit on the traced path from [entry points] through [function chains] to a
> security-relevant decision, state transition, harm-bearing operation, or trust-boundary crossing
> -- that target-kind product reachability, not a prior finding, is why this batch was selected.
> Static analysis tools do not reason across function boundaries, so
> their blind spots are exactly the multi-function reasoning chains, error-handling paths, integer
> arithmetic, and protocol edge cases this pass should weigh most heavily. A batch that holds up
> under that scrutiny is a valid result -- report it clean with the reasoning that ruled each
> pattern out, not a forced finding.

**Full sealed-source access** (`agent/shared-constraints-code.md` §3) applies here as everywhere --
the file batch is a starting point, not a cage, while the mutable origin is never an analysis root.

**Context budget rule**: every field above stays sized to help the hunter navigate, not to
outweigh the source files -- compress structural index / call graph / threat model content before
dispatch if it is crowding out the code under review. Structural Coverage Debt has its own
compression, and only that one: past 25 debt files it moves to the generation-bound ledger defined
in `agent/operator-core-code.md` ("Structural Coverage Debt"), which keeps every exact per-file line
rather than replacing them with a count. Do not summarize the debt block any other way.

**On return:**
```bash
vigil assess contract code-record analysis   # confirm the shape if the payload was hand-authored
vigil assess code-record analysis <analysis-json>   # cwe_coverage + cross_file_triggers

# Preview the completion payload before committing queue history when unsure:
vigil assess code-dispatch done <item-id> <agent-name> <lease-token> <clean|finding|suspicious|skipped> <cwe-coverage-json> ["notes"] --dry-run [--skip-reason <reason>]

# cwe-coverage-json is a file path, not inline JSON -- write the bare array (shape:
# agent/skills/code-vulnerability-analysis/SKILL.md "CWE Coverage") to a temp file first:
cat > /tmp/cwe_<item-id>.json <<'JSON'
[{"family": "buffer-overflow", "effort": 85, "functions_analyzed": 12, "entry_chains_traced": 3, "total_entry_chains": 3, "notes": "Traced all applicable parser entry chains"}]
JSON

vigil assess code-dispatch done <item-id> <agent-name> <lease-token> <clean|finding|suspicious|skipped> /tmp/cwe_<item-id>.json ["notes"] [--skip-reason <reason>]
vigil assess finding record code-vuln-hunter <finding-json> --agent-id <your-agent_id>
vigil assess code-dispatch requeue-triggers <triggers-json>   # if analysis returned cross_file_triggers
vigil assess code-dispatch reset-stale 10   # before fetching the next batch
```

For a run-accounted hunt, every `suspicious` analysis JSON also names its active
`assessment_run_id` and the exact inventoried `assessment_source_id`. The backend records the
analysis result and its deterministic open candidate atomically; a file/path/hash/repository-
generation mismatch rejects the whole write. After each bounded discovery pass, record the
attributed frontier/candidate set through `vigil assess run-audit discovery-pass record`; its
server-computed delta measures workflow progress, while neither the digest nor a
`frontier_exhausted` label independently proves comprehension. A pass stopped by an explicit cap
is retained as unresolved work; only evidence-backed `frontier_exhausted` or
`no_new_candidates` permits genuine code-scan completion.

Use `code-dispatch done` with `clean`, `finding`, `suspicious`, or an explicit `skipped` plus
`--skip-reason` -- the queue history is only useful if every admitted file receives a terminal,
attributable disposition. An analyzed completion records a complete `cwe_coverage` array (the bare
JSON array, not wrapped in an object) instead of a half-formed backend 422. Include one entry per
`applicable_vuln_classes` value, with explicit zero-effort gap entries for anything unexamined.
Record grouped file/call-chain receipts before closeout: `finding`/`suspicious` require a current result with
inline `evidence` or an `evidence_ref`; `clean` requires non-empty family coverage and review
notes. If the worker directly read a degraded/unsupported/truncated file to discharge Structural
Coverage Debt, close it through that normal result path; never label completed semantic review as
`skipped`, because skip records intentionally unreviewed material and cannot clear the debt
(`shared-constraints-code.md` §2). Every non-skipped receipt names exact structural callable
identities or reviewed source spans; critical/high closeout fails without one. Per-file detail
derives from current receipts, evidenced receipts, and the union of structurally bound callables,
so a submitted `functions_analyzed` or effort number alone is not proof of work.

**Handling needs-context returns:** Check what's missing and why. If the hunter could have
self-resolved it via filesystem access, note that as a process gap for future dispatches. If the
gap is genuinely unresolvable (external library source, binary dependency, macro-generated code),
re-queue with `vigil assess code-dispatch needs-context ...` and the missing-dependency context --
never `code-dispatch done needs_context`, since incomplete work must carry explicit expansion
metadata instead of looking complete in the queue history.

**Cross-file triggers:** Process `cross_file_triggers` with `code-dispatch requeue-triggers`, which
queues the target files if not already queued or completed. A `list-triggers` row is directly
consumable as input; each input names exactly one target with exactly one selector. Unprocessed
triggers are gate-blocking: the phase does not pass until each is queued or already completed.

Requeue applies per target, not per batch. Unblocked targets commit even when a sibling target is
refused, so a blocked target is a reason to reconcile that one file -- not to re-run the batch. The
command exits nonzero and names every blocked target with its reason on stderr; read the response's
`input_trigger_count` (trigger rows you submitted) against `target_count` (distinct files), whose
`inserted`/`already_queued`/`already_completed`/`blocked` buckets sum exactly. Reconcile a blocked
target through `code-dispatch list --queue-mode trigger` and the reason given, then requeue only
that target.

**Findings-density signal:** If a single file yields >= 2 findings AND is > 500 LOC, note it for
the Phase 2C adversarial pass -- density signals the original hunter was anchored by its first
discoveries and more issues likely remain.

**Repeat** the fetch-dispatch-done loop until the queue is drained.

**Phase 2A exit gate -- ALL of the following must be true:**
- [ ] Every admitted-file queue row is analyzed or explicitly closed `skipped` with a reason
- [ ] No unresolved `needs-context` item remains at any classification tier
- [ ] All cross-file triggers processed (target files queued or already completed)
- [ ] Coverage stats checked: `vigil assess code-coverage`

#### Phase 2B -- CWE Coverage Review

Phase 2B closes effort gaps Phase 2A left open, using the CWE effort matrix.

```bash
vigil assess code-coverage --cwe-matrix
```

Shows, per critical/high file: expected classes from `SLOT_VULN_CLASSES`, current effort per class,
threshold flags (`!` = below threshold), and callable coverage derived from exact references on
current receipts. `functions_analyzed` remains advisory context only. These scores steer review depth; they do not
authorize or block a phase transition. If no warning represents a material gap, record that
judgment and continue to 2C/2D. Pending cross-file triggers remain a separate structural-readiness
blocker regardless of the quality score.

Otherwise: process any pending cross-file triggers first (`vigil assess code-coverage`, `vigil
assess code-dispatch reset-stale 10`) -- a trigger may add a file that closes a gap class, shrinking
the re-dispatch scope. Then group the remaining files by which classes are below threshold and
dispatch `code-vuln-hunter` in CWE-Directed Re-Analysis Mode:

Before dispatch, write the selected files to a queue artifact and create an explicit reasoned
attempt. Never resubmit them through the initial `queue` verb:

```bash
vigil assess code-dispatch reanalyze \
  "$DIR/tools/analysis-state/phase-2b-reanalysis-queue.json" \
  "Phase 2B CWE effort gaps: <families and prior gap>"
```

`reanalyze` requires the prior row to be complete, links the new row to that predecessor, and
refuses active/error/needs-context rows without changing them. Fetch the new leases normally.

```json
{"cwe_directives": ["path-traversal", "injection"], "prior_effort": {"path-traversal": {"effort": 25, "functions_analyzed": 1, "notes": "checked main handler only"}, "injection": {"effort": 40, "functions_analyzed": 3, "notes": "basic sink check"}}, "target_effort": 70, "entry_chains_to_trace": ["handleUpload -> FileUtils.copyFile -> FileOutputStream.write"], "cwe_pattern_refs": ["agent/references/code-vuln-patterns/injection.md", "agent/references/code-vuln-patterns/web-app-injection.md"]}
```

Include the same current Code Source Identity, matching structural index, call graph excerpt, and
complete current threat-model envelope as Phase 2A; its clipped summary remains supplemental. The
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

**Phase 2B quality-review completion (advisory):**
- [ ] Inspect the matrix and either re-dispatch each meaningful critical/high gap or document why
      another pass would not add evidence; a target score is not itself transition authority
- [ ] Every medium/low row received review and every `skip` row has an explicit, evidence-based reason;
      classification priority never makes a lower-tier admitted file vanish
- [ ] Route and clear any pending cross-file triggers because transition readiness blocks on them
      independently of this quality review
- [ ] Trace every entry chain on a critical file that reaches a privileged operation or an
      untrusted input boundary to a guard or sink where possible; name any unresolved chain and why
      (missing code, genuinely out of scope, or unresolved call graph)

**Suspicious finding resolution:** Before leaving Phase 2, resolve every `suspicious` finding by
re-dispatching the hunter with the documented gap as targeted context, until it reaches `confirmed`
(promoted to finding) or `clean` (hypothesis disproven). Do not pass unresolved `suspicious`
findings to the verifier -- its job is FP elimination on confirmed findings, not investigation of
incomplete ones.

**Phase 2 exit:** 2A structural closure, the 2B advisory quality review, and the 2C/2D completion
work are done, with no unresolved suspicious findings. The executable structural/lifecycle gate
below alone authorizes the transition; a 2B quality warning remains steering, not a blocker.

```bash
vigil assess code-coverage --require-transition-ready verify-variant
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
- Materialize the selected file set as a queue artifact, then run `vigil assess code-dispatch
  reanalyze <artifact> "Phase 2C independent adversarial reread"`; fetch and preserve those new
  leases. An accidental second `queue` call is not a depth mechanism and conflicts with terminal
  evidence.
- Do NOT include prior findings from Phase 2A in the dispatch context — the hunter must approach
  fresh without anchoring on existing findings. This holds even when a file was selected for 2C
  because of its Phase 2A finding density: that density is the operator's selection criterion for
  choosing the file, not content the hunter receives — passing it through would recreate the
  anchoring the fresh pass exists to avoid.
- Include: current Code Source Identity, its matching structural index, the complete current
  threat-model envelope, call graph, and CWE patterns, but NOT the list of already-found issues
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
and fan out one focused agent per seam. Tokens and wall-clock do not narrow the eligible seam set;
scale the agent count to the seam count and retain explicit debt when execution is interrupted.

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
current Code Source Identity and matching structural index, the complete current threat-model
envelope (trust boundaries + trusted inputs), the cross-module call graph, and the module map.
At Git/libcurl scale, fan out with `vigil assess agent start-swarm --role code-vuln-hunter
--items-file tools/analysis-state/seams.txt --batch-size 1-3 --skills code-vulnerability-analysis
--no-target-traffic --task "system-level synthesis: <objective>"`, one specialist per worker row. Keep batch-size small
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
many seams — a tree, not a single reduce. Carry the same current Code Source Identity, matching
structural index, and complete current threat-model envelope into every reduce dispatch.

Every synthesis or reduce dispatch that records file analysis rows first creates explicit
reasoned reanalysis queue items for its anchoring files with `code-dispatch reanalyze`, then fetches
their leases. If the seam manifest is empty, record that evidence-backed no-candidate result rather
than creating queue work or a synthetic finding.

Record findings normally. This pass does not need to satisfy CWE coverage thresholds; it produces
findings, not coverage closure.

**Phase 2D exit:** Seam manifest built. One synthesis agent per seam (or a single dispatch when the
manifest fits one context). Reduce pass run for multi-hop chains. Findings recorded.

---

Phase index (path → purpose) lives in `agent/operator-core-code.md` under "Phase Index". Prior:
`agent/phases/code-phase-1-classify-map.md`. Next: `agent/phases/code-phase-3-verify-variant.md`.
