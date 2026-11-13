# Code Phase 2 — Hunt

**Read-on-phase-entry.** Read this doc before dispatching `code-vuln-hunter`, and re-read it on a
method re-anchor or when the sub-phase changes (2A → 2B → 2C → 2D). Cross-phase machinery (Core
Loop, mindset flow with each sub-phase's `hunt_scope` and lens, roster, Dispatch) stays in
`agent/operator-core-code.md`.

### Phase 2: HUNT

**2A (Broad Hunt)** analyzes every admitted file, **2B (CWE Coverage Review)** closes effort gaps on
critical/high files, **2C (Adversarial Depth)** independently rereads the highest-risk files, and
**2D (System-Level Synthesis)** hunts cross-module seams and chains.

Every Phase 2 dispatch, including 2B-2D and every reduce pass, carries the bound tuple from
"Operator duties" in `agent/operator-core-code.md`: current Code Source Identity, its matching
structural-index manifest, and the complete current threat-model envelope. If any member is missing
or stale, return to its Phase 0/1 owner before dispatch; a clipped summary never fills the gap.

Adaptive batching is part of the method:
- The unit of reasoning is one logical module or 1-3 tightly related files; one `code-record
  analysis` + `done` closes each unit on its own evidence.
- Shrink further when files are large, parser-heavy, or stateful, or when supporting metadata would
  crowd out the source. Widen only when several files form one tight entry chain and the added
  context materially improves reasoning. Fetch size is queue mechanics, not prompt size.
- One dispatch may carry several same-`batch_theme` leases worked sequentially, recording each
  item's receipt and `done` as it finishes; the hunter's ramp-up is paid once per dispatch. Stop
  adding leases where earlier items' context would crowd out the source of the one being read
  ("Context budget rule"). Unrelated modules, entry chains, or trust boundaries split into
  parallel dispatches.

#### Phase 2A -- Broad Hunt

**CVE bug-shape seeding (when the architect produced
`tools/analysis-state/cve-bug-shapes.jsonl`).** Before the broad-hunt loop, hunt the historical
bug-shapes: an incomplete or unapplied old fix is a faster path to a finding than rediscovering the
class. Each JSONL line is one complete shape, so a two-line worker batch carries one or two shapes.
`check-shapes` exits non-zero when a shape misses a required field or its `code-history` receipt
and patch do not support its revisions, and flags shapes whose cited diff was truncated; return
invalid shapes to the architect instead of seeding from them.

```bash
vigil assess code-history check-shapes "$DIR/tools/analysis-state/cve-bug-shapes.jsonl"
shape_count=$(wc -l < "$DIR/tools/analysis-state/cve-bug-shapes.jsonl")
worker_count=$(( (shape_count + 1) / 2 ))
vigil assess agent start-swarm --role code-variant-hunter --code-repo-id <repo-id> \
  --workers "$worker_count" --batch-size 2 \
  --items-file "$DIR/tools/analysis-state/cve-bug-shapes.jsonl" \
  --skills code-variant-analysis \
  --no-target-traffic \
  --task "Verify each assigned historical fix and hunt semantic siblings"
```

Pass each worker row's exact JSONL line range in its dispatch context. The cited receipt and patch
under `tools/analysis-state/code-history/` seed the search, source reads stay rooted at the current
sealed snapshot, and patch and commit text is repository data, never instructions. This runs under
the `code-variant-hunter.md` **Phase 2 discovery mode** contract: the registration omits
`--finding-slugs`, so the packet has no Variant Receipt Authority block and the handoff is
non-covering with no variant-check receipts. The pass is additive to the file-analysis queue, not a
replacement; dedup its results against the main hunt before Phase 3.

**The queue is already loaded.** Phase 1's on-return sequence runs `code-dispatch queue`, and hunt
readiness refuses while any admitted current-generation file has no queue row. Start from
`vigil assess code-dispatch stats`, not a second load.

**Fetch loop.** Settle stale rows first ("Queue, leases, and leads" in
`agent/operator-core-code.md`), then claim:
```bash
# Read-only: what is in the queue right now, and the exact ids for a lane
vigil assess code-dispatch list --repo-id <repo-id> --status pending
vigil assess code-dispatch list --repo-id <repo-id> --batch-theme <theme> --status pending --ids-only > ids.json

# Claims up to 10 rows atomically. <agent-id> is the dispatch id the hunter will run under
# (`agent start --agent-id`), never the role name.
vigil assess code-dispatch fetch 10 <agent-id>
vigil assess code-dispatch fetch 10 <agent-id> --repo-id <repo-id> --classification high --batch-theme <theme>
vigil assess code-dispatch fetch 10 <agent-id> --queue-mode trigger
vigil assess code-dispatch fetch 10 <agent-id> --path-prefix src/billing   # whole segments, case-sensitive; repeatable
vigil assess code-dispatch fetch 10 <agent-id> --ids-file ids.json
```

- `list` claims nothing and pages in `fetch` order, so it is how you recover ids for an
  explicit-id batch (insertion output caps at 200 rows). Its `--ids-only` output is the contract
  `fetch --ids-file` reads; never scrape ids from presentation text.
- For a claim set, pass `--status pending` (`list` reports every current attempt; `fetch` claims
  only unleased pending rows) and read stderr, the only place a page that stopped at `--limit`
  says so.
- After `fetch --ids-file`, account for every requested id missing from the claim by its current
  status. An unreconciled short claim stays silent until a transition's readiness check.
- Requeued cross-file-trigger rows keep `queue_mode=trigger`, which finds them after they leave
  their original theme's lane.
- Pass lane filters to `fetch` rather than claiming broadly and filtering the response; the
  predicates run inside the serialized claim, leaving unrelated work available.
- Preserve each returned `agent_name`, `lease_token`, and `repo_generation`. A lost token is
  recovered, not re-claimed: `code-dispatch progress <item-id>` or `code-dispatch list
  --show-tokens` prints the live holder. A token no longer shown against your `agent_name` was
  reclaimed, which makes it an `adopt-lease` or `reset-stale` decision.

**Dispatch `code-vuln-hunter`** with `agent/skills/code-vulnerability-analysis/SKILL.md`, the bound
tuple, and:

- **Lane and file paths** -- set `prompt_context.lane_file` to the `fetch` JSON (inventory check:
  `agent/operator-core-code.md` "Dispatch"); it also names each lease's `scratch_dir`. Paths
  resolve beneath the Code Source Identity `snapshot_path`, never the mutable origin.
- **Batch theme and slot types** -- the module grouping and each file's Phase 1 slot types.
- **Applicable vulnerability classes** -- do not type them. `prompt_context.queue_item_ids` (or
  `lane_file`) makes `agent start` render each item's `applicable_vuln_classes`,
  `path_suggested_vuln_classes`, `unread_code_suggested_vuln_classes`, and `missing_cwe_families`
  into the packet's backend queue manifest, refusing when a row cannot state its families. That
  manifest is the only backend-derived family channel into the packet, because the hunter never runs
  `fetch`. Prose restating it is an unvalidated second copy that loses to the backend at `done`; if
  you restate it, pass the backend list through unmodified rather than a hand-copied slot→class
  table. The list is a floor, not a ceiling. Every structurally analyzed code file's list includes
  `error-handling` and `algorithmic-dos`; one missing either is a dispatch-input defect to repair
  before review.
- **Path and unread-code hints** -- pass through beside the classes. `done` never requires a hint;
  a Phase 1 context tag (`value-transfer`, `provider-callback`, `one-time-secret`) on the
  classification is what makes those families required.
- **Guidance hypotheses** -- labeled "check after broad analysis" (skill Step 4). They never exempt
  the hunter from the applicable-classes floor.
- **Structural index** -- the manifest plus relevant per-file index paths from Code Source
  Identity (return to Phase 0 for a generation-bound rebuild if missing).
- **Call graph excerpt** -- the relevant entry chain plus the path to
  `tools/analysis-state/call-graph.json`; inline only edges that change this dispatch's reasoning.
- **Threat-model summary** -- beside the complete envelope from `code/threat-model/<repo-id>`, a
  3-8 bullet orientation summary: product surface profile and evidence, target-kind entry points,
  product-reachability versus attacker-control status, trust boundaries, high-value targets, and
  **trusted inputs** (operator-owned config, env secrets, internal mTLS/IAM callers), each with the
  threat-model evidence that makes it trusted, marked advisory.
- **Root-cause candidate capture** -- ask the hunter to put shared utilities or guards it suspects
  cause several findings in handoff `extras.root_cause_candidates`, for pre-report deduplication
  and ticket grouping.
- **CWE pattern references** -- the directory `agent/references/code-vuln-patterns/`, not a
  pre-selected file list; the hunter loads files as their signal appears, and preloading every
  plausible file for a mixed batch is what blows the context budget.
- **Effort** -- tell the hunter the goal (every applicable class examined to the depth the file's
  role warrants), not a number. Per-family thresholds (critical 70, high 50, medium 30) are advisory
  at `transition-phase`: inspect them with `code-coverage --cwe-matrix`, or use
  `--require-gate-pass` only when a strict shell signal helps a remediation loop.
  `coverage_integrity` checks receipt consistency, not depth.
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

**Context budget rule**: every field above stays sized to help the hunter navigate, not to outweigh
the source; compress structural index, call graph, and threat-model content when it crowds out the
code under review. Structural Coverage Debt has exactly one compression: past 25 files it moves to
the generation-bound ledger in `agent/operator-core-code.md` ("Structural Coverage Debt"), which
keeps every per-file line. Summarize the debt block no other way.

**On return:** the hunter's closing sequence records its findings, a `code-record analysis` receipt
per cluster, and `code-dispatch done` per leased item. `vigil assess contract code-dispatch done`
owns the closeout rules; on a critical/high file, each `applicable_vuln_classes` value with no
`cwe_coverage` entry is recorded at effort 0 as a reported coverage gap, and each family left at
effort 0 or below its floor raises a `depth_floor` trigger (`depth_floor_triggers` in the response;
Phase 2B settles them). Your side:

```bash
vigil assess code-dispatch progress <item-id>                 # what each leased item still owes
vigil assess code-dispatch requeue-triggers <triggers-json>   # cross_file_triggers or depth_floor_triggers
vigil assess code-dispatch stats                              # before fetching the next batch
```

- An item that still owes closeout after the lane ended is a stale row ("Queue, leases, and leads"),
  never something to close on the hunter's behalf.
- A completed review of a degraded, unsupported, or truncated file closes through the normal result
  path; `skipped` means unreviewed and cannot clear structural debt (`shared-constraints-code.md`
  §2). Per-file detail derives from current receipts and the callables they name, so a
  `functions_analyzed` or effort number alone proves nothing.
- A current lease-bound receipt that names an existing reportable root finding whose source binding
  is stale is accepted: closeout records the fresh review, and the finding keeps its original
  provenance and still owes independent verification against current source.

**Run-accounted hunts.** Every `suspicious` analysis JSON also names its active `assessment_run_id`
and the exact inventoried `assessment_source_id`; the backend records the result and its open
candidate atomically and rejects a mismatched file, hash, or generation. After each bounded
discovery pass, record the attributed frontier and candidate set with `vigil assess run-audit
discovery-pass record`. Its server-computed delta measures workflow progress, not comprehension; a
pass stopped by an explicit cap stays unresolved, and only evidence-backed `frontier_exhausted` or
`no_new_candidates` permits code-scan completion.

**Handling needs-context returns:** check what is missing and why. If the hunter could have
resolved it through filesystem access, note the process gap for future dispatches, supply the
context, and `retry-needs-context`. If the gap is genuinely unresolvable (external library source,
binary dependency, macro-generated code), the item closes with `code-dispatch needs-context ...`
and the missing-dependency context, never `code-dispatch done needs_context`, so incomplete work
carries explicit expansion metadata instead of looking complete.

**Cross-file triggers:** `code-dispatch requeue-triggers` queues each target not already queued or
completed; a `list-triggers` row is valid input, with exactly one selector per target. Unprocessed
triggers block the phase. Every recorded trigger names an admitted current-generation file unless
the hunter declared it `outside_snapshot`; those stay pending until you close each with
`code-dispatch resolve-triggers` and `external_context_unavailable`, naming what lies outside the
snapshot, or ingest the missing source and re-hunt.

Requeue applies per target: unblocked targets commit even when a sibling is refused, and the command
exits nonzero naming every blocked target and its reason on stderr. Check `input_trigger_count`
(rows submitted) against `target_count` (distinct files), whose `inserted`/`already_queued`/
`already_completed`/`blocked` buckets sum exactly, then reconcile each blocked target through
`code-dispatch list --queue-mode trigger` and requeue only that target.

**Findings-density signal:** a file that yields two or more findings and exceeds 500 LOC goes on the
Phase 2C list; density suggests the hunter anchored on its first discoveries.

Repeat the fetch-dispatch-done loop until the queue is drained. **Phase 2A ends** then: readiness
blocks on any admitted file without a terminal row, any `needs-context` item, and any unprocessed
trigger, so read `vigil assess code-coverage` rather than walking a list by hand.

#### Phase 2B -- CWE Coverage Review

```bash
vigil assess code-coverage --cwe-matrix
```

Per critical/high file the matrix shows expected classes (the same derivation as
`applicable_vuln_classes`), current effort per class, `!` below threshold, and callable coverage
from exact references on current receipts. A separate Path Hints list shows hinted families and
their effort; hints carry no threshold. The scores themselves steer depth and never authorize or
block a transition. A critical or high file closed with a family at effort 0 or below its floor is
also a pending `depth_floor` trigger on that file (`code-dispatch list-triggers`); those and pending
cross-file triggers are structural blockers. Settle each depth-floor trigger with
`code-dispatch requeue-triggers` (a directed pass for that family; only a pass that reaches the
floor settles it) or, when another pass would not move it, `code-dispatch resolve-triggers` with
the reason: `reviewed_at_sufficient_depth` when the file was read at depth and its recorded effort
understates it, `not_applicable` when the family cannot occur in the file. Triage before requeueing:
a requeued trigger is `queued`, which `resolve-triggers` does not touch, so a directed attempt sent
by mistake comes back with `code-dispatch withdraw <ids> --reason "<why>"` while no lane has claimed
it. Server-only families on a browser bundle point at a missing `client-bundle` tag
(`context_tags_unrecorded` names untagged files); have the architect re-classify the file rather
than settle each family by hand. If no remaining warning is a material
gap, record that judgment and continue to 2C/2D.

Otherwise process pending triggers and stale rows first (a trigger may add a file that closes a gap
class), group the remaining files by below-threshold class, and dispatch `code-vuln-hunter` in
CWE-Directed Re-Analysis Mode. Write the selected files to a queue artifact and create an explicit
reasoned attempt rather than resubmitting through `queue`:

```bash
vigil assess code-dispatch reanalyze \
  "$DIR/tools/analysis-state/phase-2b-reanalysis-queue.json" \
  "Phase 2B CWE effort gaps: <families and prior gap>"
```

`reanalyze` requires a complete prior row, links the new row to it, and refuses
active/error/needs-context rows unchanged; fetch the new leases normally. The dispatch context names
the directives:

```json
{"cwe_directives": ["path-traversal", "injection"], "prior_effort": {"path-traversal": {"effort": 25, "functions_analyzed": 1, "notes": "checked main handler only"}, "injection": {"effort": 40, "functions_analyzed": 3, "notes": "basic sink check"}}, "target_effort": 70, "entry_chains_to_trace": ["handleUpload -> FileUtils.copyFile -> FileOutputStream.write"], "cwe_pattern_refs": ["agent/references/code-vuln-patterns/injection.md", "agent/references/code-vuln-patterns/web-app-injection.md"]}
```

Handle the return as in 2A's "On return"; the backend max-merges the updated `cwe_coverage`
effort. Re-check the matrix after each round. For a remaining gap on a critical file: re-dispatch
when the hunter returned `needs-context` or traced only some entry chains; accept a documented
exclusion when the class is genuinely inapplicable despite the slot-type mapping (a NETWORK-INPUT
file that only handles binary protocol frames has no injection surface); and stop re-dispatching a
file/class once another round would plausibly add nothing new. That judgment, not a round count,
decides diminishing returns; document the reason.

**Phase 2B is done** when each meaningful critical/high gap was re-dispatched or documented as one
another pass would not move, and every entry chain on a critical file that reaches a privileged
operation or an untrusted input boundary was traced to a guard or sink, or named as unresolved with
the reason (missing code, out of scope, unresolved call graph). The judgment is yours; the score is
not transition authority.

**Suspicious finding resolution:** before leaving Phase 2, re-dispatch the hunter on every
`suspicious` finding with the documented gap as targeted context until it reaches `confirmed`
(promoted to a finding) or `clean` (hypothesis disproven). The verifier eliminates false positives
on confirmed findings; it does not finish incomplete investigations. A file closed `finding` can
still hold a `suspicious` receipt for a separate hypothesis; it raises the same
`unresolved_suspicious_analysis` blocker, and the `code-dispatch reanalyze` claim lists it in
`open_lead_receipts` for the re-review to settle.

#### Phase 2C -- Adversarial Depth Pass

After 2A structural closure and the 2B review, select files for an independent hostile reread. The
coverage pass anchors agents on completing correctly; this pass asks what critical survived.

**File selection is judgment, not a fixed category list.** Likely misses sit where security
decisions happen (auth, policy, access control, crypto), in files that already produced a finding
(review often stops at the first bug), in large files (>500 LOC) analyzed under queue pressure, and
in config/policy files that define execution behavior but were classified medium. Pick the 10-20
files an adversary would actually target in this codebase and threat model. Start from the depth
advisory in `vigil assess code-coverage` (and `--by-path` depth columns), which names critical/high
files with signal or findings whose only reviews are wide passes; it steers and never blocks.

**Area sweep -- the second selection form.** A drained queue ends the breadth pass, not the hunt.
Select a whole feature or trust boundary (an upload pipeline, the tenant-isolation layer, an admin
API) and dispatch it `deep-manual` under the `agent/rules/mindsets/business-logic.md` or
`agent/rules/mindsets/idor-bac.md` lens so the hunter follows the feature across files. Where
skip-tier files concentrate in an area, sample some into the sweep: a classification skip is a
priority decision, not evidence the files are safe.

**Dispatch rules:**
- `deep-manual`, never `item-iterating`.
- Materialize the selected files as a queue artifact, run `vigil assess code-dispatch reanalyze
  <artifact> "Phase 2C independent adversarial reread"`, and fetch and preserve the new leases. A
  second `queue` call is not a depth mechanism and conflicts with terminal evidence.
- Leave prior Phase 2A findings out of the dispatch context, even for a file selected because of
  them: they are your selection criterion, and passing them through recreates the anchoring this
  pass exists to avoid. Include the bound tuple, call graph, and CWE patterns.
- Objective: "Find High/Critical vulnerabilities in these files. Ignore coverage metrics. Focus on
  semantic fail-opens, logic bugs, and design flaws."
- A 2A finding re-surfaced independently is convergent evidence, not an error; a rediscovery of
  something Phase 3 already killed meets the D4 guard (`code-vuln-hunter.md` "Resumed-Finding
  Guard").

**On return:** record findings and analysis results normally. This pass produces findings, not
coverage closure, so CWE thresholds do not apply. **Phase 2C exit:** every dispatched file reviewed
and its findings recorded.

#### Phase 2D -- System-Level Synthesis Pass

Some vulnerabilities exist only between partitions: an auth check in module A that module B's entry
path bypasses, two individually low findings that compose into escalation, a trust boundary no
single file owns. File-batch dispatches cannot see them, so they get a dedicated pass. The unit is a
bounded seam, not the whole codebase: on a large repository one synthesis agent would skim. Tokens
and wall-clock never narrow the eligible seam set; scale the agent count to the seam count and keep
explicit debt when execution is interrupted.

**Step 1 — Build the seam manifest** from artifacts on disk, one
`tools/analysis-state/seams/<seam_id>.json` per seam plus a flat `tools/analysis-state/seams.txt`
index:
- **Structural seams** — `call-graph.json` edges with `crosses_trust_boundary: true` grouped by
  `(caller_module, callee_module)`. Each carries the edge subgraph, the entry chains that traverse
  it, the trust boundary and trusted-inputs note for that crossing, and every finding located in
  either module.
- **Capability seams** — findings bucketed by primitive (read / write / SSRF / redirect /
  auth-state-change / info-leak / injection-sink), paired using the `agent/agents/exploit-developer.md`
  A→B chain table. Each promising pair-bucket is one seam; bucketing by capability keeps this
  O(capabilities²), not O(findings²).

**Step 2 — Scale the dispatch to the seam count.** When the manifest fits one focused context,
dispatch one `code-vuln-hunter` `deep-manual` with the whole manifest, the bound tuple, the
cross-module call graph, and the module map. Otherwise fan out one specialist per worker row with
1-3 seams each, so each agent reasons deeply about coherent crossings; each worker reads its slice
from `seams/<id>.json`:

```bash
vigil assess agent start-swarm --role code-vuln-hunter --code-repo-id <repo-id> \
  --items-file tools/analysis-state/seams.txt --batch-size <1-3> \
  --skills code-vulnerability-analysis --no-target-traffic \
  --task "system-level synthesis: <objective>"
```

Synthesis objective (per agent): "These seams join modules with different trust assumptions. For
each: does one side's guarantee fail to hold as the other side's assumption? Can a finding/primitive
on one side combine with the other to escalate? Does either entry path bypass the other's guard?
Reason across the seam; do not re-audit individual files."

**Step 3 — Reduce (multi-hop chains).** Chains across three or more modules form by joining seam
outputs that share a module. Dispatch a consolidation pass over the candidate chains
(`code-vuln-hunter`, or `exploit-developer` registered with `--assessment-mode code`); for a large
candidate set, partition the reduce by subsystem as a tree rather than one reduce agent. Each reduce
dispatch carries the bound tuple.

A synthesis or reduce dispatch that records file analysis rows first creates reasoned reanalysis
items for its anchoring files with `code-dispatch reanalyze`, then fetches their leases. An empty
seam manifest is recorded as an evidence-backed no-candidate result, not queue work or a synthetic
finding. Record findings normally; CWE thresholds do not apply.

**Phase 2D exit:** seam manifest built, one synthesis agent per seam (or one dispatch when the
manifest fits one context), reduce pass run for multi-hop chains, findings recorded.

#### Phase 2 exit

2A structural closure, the 2B advisory quality review, and the 2C/2D work are done, with no
unresolved suspicious findings. Every lane that returned signal has had a `hunt_scope: deep` pass
(2C file-list or area sweep). The executable gate alone authorizes the transition:

```bash
vigil assess code-coverage --require-transition-ready verify-variant
vigil assess transition-phase verify-variant
```

A readiness command that times out is a tooling failure, not a verdict: retry once with narrower
flags, record an operator checkpoint, and surface the failure. Do not loop on it or `--force` past a
gate you could not read.

---

Phase index (path → purpose) lives in `agent/operator-core-code.md` under "Phase Index". Prior:
`agent/phases/code-phase-1-classify-map.md`. Next: `agent/phases/code-phase-3-verify-variant.md`.
