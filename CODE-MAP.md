# CODE-MAP

The repo's **invariant map**: the things a reader cannot derive by listing files
or reading one module — which file owns a contract, what must change with it,
and what silently breaks when it does not.

It is deliberately not an inventory. `ls`, `rg`, and a module's own docstring
answer "what is this file?" better than a gloss here ever will, and they cannot
go stale. Implementation detail belongs in the code it describes.

**Size budget: this file stays under 25 KB.** Past that it stops being read, and
an unread map drifts unnoticed. If an addition would break the budget, something
here has stopped earning its place — cut it, or push it into a docstring.

**Entry format** (enforced by `orchestrator/backend/tests/test_doc_dead_paths.py`):

- Every entry opens with a backticked repo-root-relative path. A concept that
  owns no file is not a map entry.
- Symbol names, never line numbers — `module.py:symbol_name`. Line numbers do
  not survive the next edit.
- No line over 300 characters.
- Point at an ADR or a test with `See:` instead of restating its reasoning.
- Engagement-local paths are written `<engagement>/…` so they are not mistaken
  for repo paths.

---

## Single sources of truth (drift-prone invariants)

These exist in exactly **one** place; every other consumer imports from there.
When you are about to copy one of these into a second file, stop and import.

- `agent/scripts/assess/lib/phases.py` owns all phase rosters, terminal phases, and input aliases.
  Backend/frontend mirrors are pinned by `orchestrator/backend/tests/test_phase_roster.py`.
- `orchestrator/backend/scripts/generate_agent_schemas.py` owns the ten generated schema specs.
  A schema without a spec is hand-written. See: `orchestrator/backend/tests/test_schema_generation.py`.
- `agent/scripts/assess/lib/vuln_taxonomy.py` owns classes, families, bucket/surface mappings,
  and skill mappings. See: `orchestrator/backend/tests/test_vuln_taxonomy.py`.
- `agent/scripts/assess/lib/classify_buckets.py:INERT_TYPES` owns inert work-item types;
  `agent/scripts/assess/commands/dispatch/work_items.py` mirrors the backend-side predicate.
- `agent/scripts/assess/lib/classify_buckets.py:_BUCKETS` owns URL bucket scoring and skip tags.
  Ingest classifies inline; `work-buffer reclassify` reapplies it.
- `orchestrator/backend/app/services/state_manager/coverage.py:PROBE_RESULT_STATUSES` owns result
  outcomes. Only `tested` and `signal` cover a class.
- `orchestrator/backend/app/services/state_manager/coverage.py:CoverageStatus` owns coverage status;
  the standalone CLI mirror is `agent/scripts/assess/commands/resolve.py:_COVERAGE_STATUSES`.
- `orchestrator/backend/app/services/state_manager/_common.py:SUBMISSION_STATUSES` owns submission
  status; `agent/scripts/assess/lib/contracts.py:SUBMISSION_STATUSES` is the CLI mirror.
- `orchestrator/backend/app/services/state_manager/_common.py:VERIFICATION_STATUSES` owns finding
  verification status; `agent/scripts/assess/lib/contracts.py:VERIFICATION_STATUSES` mirrors it.
- `orchestrator/backend/app/retry_state.py:RETRY_STATES` owns blocked-technique retries; unknown
  legacy prose becomes reviewable `pending`, never `no_retry`.
- `agent/scripts/assess/lib/audit_enums.py` owns Kali technique and probe-kind enums. These are
  host-side only and are not copied into the runtime image.
- `agent/scripts/assess/lib/contracts.py:KALI_TARGET_VERBS` and `KALI_MAINT_VERBS` own the Kali
  roster; `KALI_VERBS` is their union. Registration and `agent/skills/kali-exec/SKILL.md` mirror it.
- `agent/scripts/assess/lib/kali_output.py:KALI_EXIT_CODES` owns terminal status exit codes;
  `kali_cli.py:emit_result` is the output funnel and renders the help table.
- `agent/skills/<name>/SKILL.md` directories own skill names. Discovery is a directory walk; there
  is no roster. `--skills` enforcement is CLI-only and advisory under ADR 0019.
- `agent/scripts/assess/lib/findings.py:_AGENT_PREFIX_MAP` and
  `orchestrator/backend/app/services/state_manager/findings.py:_FINDING_PREFIX_BY_SOURCE` jointly
  own finding prefixes; operator prompt prefix tables mirror both.
- `agent/scripts/assess/lib/contracts.py` owns executable CLI metadata and phase discovery.
  `contract.py` and `list_commands.py` render it live; a wrong phase makes a verb undiscoverable.
- `src/vigil_cli/engagements.py:CLIENT_PROVIDER_KEYS` and `CLIENT_MESSAGE_FLAGS` own client launch
  identity. Generated launchers, preflight, and the benchmark consume them.
- `src/vigil_cli/image_freshness.py` owns the content-digest mechanism every freshness check uses —
  input entries, digests, the image label, exclusions. Content, never mtime.
- `src/vigil_cli/restart_manifest.py:consumer_states` owns what an install invalidated, per consumer.
  Presenters consume its rows; do not derive freshness beside it. See: `AGENTS.md` freshness section.
- `src/vigil_cli/install_manifest.py` and `src/vigil_cli/install_fs.py` own managed install paths,
  pinned/no-follow operations, and content digests.
- `agent/scripts/assess/lib/params.py:header_schema_from_headers` owns value-free header schemas.
- `agent/scripts/assess/lib/scope.py:ingest_scope_filter` must run on every new file-to-buffer ingest
  path. Arjun and proxy ingestion reuse already-filtered URLs.
- `orchestrator/backend/app/services/state_manager/work_buffer.py:_scope_excluded_hosts` owns
  claim-time scope exclusion, applied before ordering and limits.
- `agent/operator-core.md`, `agent/operator-core-code.md`, `agent/operator-core-blue.md`, and
  `agent/agents/*.md` own prompt prose. Generated wrappers are never authoring surfaces.
- `orchestrator/backend/app/services/state_manager/app_units.py:score_application_units` and
  `depth_ledger.py` own the web-only terminal depth gate. See: ADR 0012.
- `orchestrator/backend/app/services/assessment_memory.py` and `artifact_index.py` own the bounded
  resume brief and artifact index; output points to drill-down commands instead of embedding data.

---

## Sync rules worth remembering

- `agent/operator-core.md` and `agent/operator-core-blue.md` render to the committed wrappers, and `agent/agents/*.md` render to the per-client agent trees, through `agent/scripts/render-operator-prompts.sh`. Run it with `repo`; `check` fails on drift.
- `agent/commands/` is the canonical source for the operator commands — one `.md` per command. The renderer's explicit `COMMAND_NAMES` roster (not a glob) drives two generated wrapper trees: `agent/.claude/commands/<name>.md` and `agent/.codex/skills/<name>/SKILL.md`. See: ADR 0017.
- `src/vigil_cli/client_rosters.py` links those wrapper trees into an engagement as **per-entry symlinks** (`<engagement>/.claude/commands/`, `<engagement>/.codex/skills/`), so an engagement never carries a stale copy and an operator-authored command of the same name wins.
- `orchestrator/backend/app/api/assessment.py` and `orchestrator/backend/app/api/code_analysis.py` feed the generated `agent/schemas/*.json` through `orchestrator/backend/scripts/generate_agent_schemas.py`. Check drift with that script's `--check` mode.
- `agent/scripts/assess/lib/contracts.py` renders the engagement-binding invariant onto every executable command contract, so prompts do not restate it.
- `orchestrator/backend/app/db.py` is the single schema owner. Backend state is canonical for findings, coverage, services, chains, command runs, dispatch/handoff lifecycle, host liveness, and artifact metadata; large files stay engagement-local and are registered explicitly.
- `agent/scripts/assess/commands/code_index.py` writes the engagement-local structural manifest;
  `code_index_sync.py` publishes validated metadata. Legacy or wrong-schema artifacts are rejected.
- `agent/scripts/assess/lib/kali_audit.py` threads the command-run audit chain. A persisted Kali flag
  must also land in `kali_cli.py`, `orchestrator/backend/app/api/assessment.py`,
  `orchestrator/backend/app/db.py`, and `state_manager/command_runs.py`.

---

## Prompt-to-backend coupling

A prompt change is **not** prompt-only when the prompt defines an artifact the backend stores or the CLI parses.

- `agent/operator-core-code.md` defines `guidance_hypotheses`; code dispatch normalizes it and
  `orchestrator/backend/app/api/code_analysis.py` validates it. Keep it `list[str]`.
- `agent/skills/code-architecture-mapping/SKILL.md` owns the `call-graph.json`,
  `attack-hypotheses.json`, and `cve-bug-shapes.jsonl` contracts consumed by later code dispatches.
- `agent/scripts/assess/commands/code_dispatch.py` loads `file-analysis-queue.json`; its `priority` must exactly equal the file's current band-valid `analysis_priority`, with whole-batch rejection before mutation on drift.
- `agent/operator-core.md` phase gates call `vigil assess check-phase-readiness`. Dropping the gate call silently disables the phase boundary.
- **General rule:** if a prompt tells an agent to emit structured output that a CLI verb consumes or the backend stores, prompt and consumer are coupled. Check both sides.

---

## Easy-to-miss registration points

- `agent/scripts/assess/lib/findings.py:_AGENT_PREFIX_MAP` — a new finding-recording agent needs its
  prefix here, in the backend finding-prefix map, and in the applicable operator prompt table.
- `agent/scripts/assess/cli.py` — a verb can touch the import block, flat loop, four grouped
  registries, inline `kali` registry, and pre-parse action-help hook. See the recipe in `AGENTS.md`.
- `agent/scripts/assess/lib/contracts.py:_INLINE_DOCUMENTED_NAMESPACES` — a `<verb> <action>` leaf documented on its parent contract must have that parent listed here, or `vigil assess contract` cannot resolve it.
- `orchestrator/backend/app/services/state_manager/phase_readiness.py` — its readiness function names
  and HTTP routes are load-bearing for the phase gate, report export, and frontend. Refactor behind
  them or add a front door that delegates to them.
- `orchestrator/backend/app/services/state_manager/phase_readiness.py:PER_HOST_OBJECTIVES` has a CLI
  mirror in `agent/scripts/assess/lib/coverage_checks.py` and a `coverage_deferral` API literal.
- `orchestrator/backend/app/services/code_analysis.py` allowlists fields persisted by repo/file
  updates and structural sync. A new column must land here, in the DB, and in the API together.
- `agent/scripts/assess/commands/code_index_sync.py` — a structural field populated from tree-sitter output must be added here too, or the index artifact and the backend row disagree.
- `agent/scripts/assess/commands/check_phase_readiness.py` — the one phase-aware readiness command; five standalone check verbs folded into it. Reusable bodies live in `agent/scripts/assess/lib/coverage_checks.py`.
- `orchestrator/backend/app/main.py` registers each API router explicitly; a new router is inert
  until it is added there.

## Boundaries worth knowing

### agent/ — prompts and the assessment CLI

- `agent/operator-core.md` / `-code.md` / `-blue.md` — the three operator loops. Phase flow, dispatch rules, recording rules, and the backend-vs-artifact truth boundary start here.
- `agent/shared-constraints*.md` and `agent/shared-specialist-core.md` — the first-load specialist contract layer. A rule that must hold across many specialists belongs here or in the CLI, never in one role prompt.
- `agent/agents/` — canonical specialist prompt sources. `agent/rules/` — always-active behavioural overlays. `agent/phases/` — the per-phase operator docs, whose filenames are pinned to the phase roster.
- `agent/skills/` — the procedure layer, discovered by walking `agent/skills/*/SKILL.md` frontmatter. `agent/references/` — the payload/checklist library, discovered the same way.
- `agent/scripts/assess/cli.py` — the authoritative subcommand registry for `vigil assess`, including the `kali` subgroup that owns all target-facing tool execution.
- `agent/scripts/assess/lib/scope.py` — scope parsing, matching, and locked atomic mutation. There is deliberately **no outbound destination filtering**: `enforce_execution_policy` never refuses a command for its destination host. Staying inside the authorized roots is the operator's responsibility.
- `agent/scripts/assess/lib/config.py` — one fail-closed engagement-selection precedence for every `vigil assess` command: explicit `--engagement-dir`, else a root discovered from CWD, else the session variable exported by `vigil engagement start`.
- `agent/scripts/assess/lib/code_snapshot.py` — race-checked, content-addressed source copies.
  `orchestrator/backend/app/code_snapshot.py` independently attests them. See: ADR 0026.
- `agent/scripts/assess/lib/parser_boundary.py` + `parser_worker.py` — the structural-parser process boundary. Every typed failure becomes an explicit all-byte fallback with declared unavailable dimensions, never a silent skip. See: ADR 0029.
- `agent/scripts/assess/lib/reachability.py` — `classify_probe()` is the one per-host reachability verdict. A bare `connect=000` is NOT a blanket "blocked"; a verdict requires no TCP connect AND no resolved IP.
- `agent/scripts/assess/commands/export_submission.py` and `export_reply.py` assemble and present;
  neither rewrites authored content or masks credentials. Rendering helpers live in
  `agent/scripts/assess/lib/finding_render.py`.
- `agent/scripts/assess/commands/operator_checkpoint.py` — `vigil assess operator-checkpoint`, the operator's own durable state. References plus one intent note; every reference is existence-checked in the write transaction.
- `agent/scripts/assess/commands/resume_brief.py` — a **read**. It observes abandoned command runs, jobs and host children and names the verb that reconciles them; the reconciling write is owned solely by `vigil assess kali sweep-orphans`.
- `agent/scripts/assess/commands/eval_capture.py` — a maintainer/CI tool, deliberately off the operator surface.
- `agent/scripts/hooks/` — shared host hooks for scope checks, activity logging, compaction, and
  session end. `goose-hook-adapter.sh` adapts Goose tool names to the same contracts.
- `agent/schemas/` — the durable JSON payload contracts. See the generated-vs-hand-written invariant above before editing one.
- `agent/docker/runtime-full/Dockerfile` — the supported target-facing tool surface. All baked inputs participate in image-digest drift checks.
- `agent/engagements/` — the engagement artifact root. Map the directory's role, never per-engagement contents.

### src/vigil_cli/ — the universal CLI

- `src/vigil_cli/main.py` — the `vigil` entrypoint: install, config, doctor/status, runtime and orchestrator lifecycle, and the `vigil assess` passthrough.
- `src/vigil_cli/engagements.py` + `blue.py` + `client_rosters.py` — engagement bootstrap: run directories, bounded operator pointers, generated launchers, and the per-client prompt/command links.
- `src/vigil_cli/preflight.py` — `_preflight_engagement_start`, `_resolve_provider_key`, `_warn_if_install_stale`. It lives outside `main.py` so `blue.py` can import it without a cycle; `main.py` re-exports what it uses.
- `src/vigil_cli/quickstart.py` — the onboarding wizard. Plans by default; only installs behind an explicit flag.
- `src/vigil_cli/runtime.py` + `up.py` — one shared long-lived Kali container, reached host-side by `docker exec`. There is no in-container API server or MCP bridge.
- `src/vigil_cli/mitmproxy.py` — the single owner of the proxy `docker build` argv, including the inputs-digest label without which the image can never be proven current.
- `src/vigil_cli/bench/` — the benchmark harness. Verbs are `list`, `run`, `run-all`, `score`, `teardown`, `selftest`, `history`, and the `vm` group. `run-all` defaults to a **billed** launch; `run` does not. See: ADR 0020.
- `src/vigil_cli/bench/anticheat.py` — the bench guards are **generated at runtime as strings** by this module, not committed files: `bench-guard.sh` is written into the off-tree bench home, `bench-guard.js` into the attempt engagement's OpenCode plugin dirs.
- `src/vigil_cli/term.py` — the one place CLI output learns whether it is on a terminal. Off a TTY: same bytes or fewer, one record per line, no ESC. Style through it, never a raw escape at a call site.
- `src/vigil_cli/oob_relay.py` — the single owner of the install's OOB relay-slot identity contract; `oob.py`, `install.py`, `up.py`, and `status.py` consume that record rather than deriving routes independently.

### orchestrator/backend

- `orchestrator/backend/app/main.py` — FastAPI bootstrap. Routers are registered explicitly here.
- `orchestrator/backend/app/db.py` — the SQLite persistence boundary and the single schema owner.
- `orchestrator/backend/app/api/assessment.py` — the canonical live-state interface for recon, surfaces, coverage, readiness, findings, chains, credentials, dispatch/handoff registry writes, bulk ingestion, and command-run audit.
- `orchestrator/backend/app/api/code_analysis.py` — atomic repo refresh (the only repo/file ingest write
  path), lease-owned queue work, and generation-bound compare-and-swap for threat models and structural
  indexes. Also the read-only paginated queue listing (`GET analysis-queue`): its `item_ids` page is the
  ids-file contract `code-dispatch fetch --ids-file` consumes, so the two must keep one ordering and one
  current-generation filter.
- `orchestrator/backend/app/api/submissions.py` — the immutable submission-version and sent-reply API shared by the CLI and the web UI.
- `orchestrator/backend/app/services/state_manager/` — the live-state service package, re-exported
  through `__init__.py` so public `state_manager.<fn>` paths remain stable.
- `orchestrator/backend/app/services/submission_versions.py` — the one service behind `vigil assess export submission` and the web UI. It never changes `submission_status` and never submits externally. See: ADR 0025.
- `orchestrator/backend/app/reply_render.py` — the versioned exact-bytes outbound renderer; `agent/scripts/assess/lib/reply_render.py` is an import-only bridge so draft previews and the backend cannot fork the format.
- `orchestrator/backend/app/services/operator_checkpoints.py` — writes `assessment_operator_checkpoints`, an append-only table enforced by SQLite triggers. The only permitted mutation is stamping a null `superseded_by_id`.
- `orchestrator/backend/app/services/state_manager/run_accounting.py` — run identity, lifecycle, source inventory, obligations, and generation-bound receipt links shared by code, web and blue. `proofs.py` separately owns immutable evidence receipts. See: ADR 0028.
- `orchestrator/backend/app/services/engagements.py` — filesystem-to-DB sync. Explicit deletes are tombstoned so a later sync cannot resurrect them from leftover files.
- `orchestrator/backend/tests/` — the backend contract suite, including the doc-sync guards (`test_skill_cli_sync.py`, `test_coverage_probe_cli_sync.py`, `test_doc_dead_paths.py`). Markdown wording is reviewed through diffs, not pinned by tests.

### Frontend and the rest

- `orchestrator/frontend/` — the operator SPA. `orchestrator/frontend/src/components/TabBar.tsx`
  owns the tab contract; `orchestrator/frontend/src/lib/api.ts` owns REST helpers and types;
  `orchestrator/frontend/src/lib/theme.ts` and `orchestrator/frontend/src/app.css` own presentation.
- `orchestrator/frontend/src/components/RunsTab.tsx` — renders every value verbatim: no masking, no reveal toggle. See: ADR 0019.
- `orchestrator/report/` — a **third** Vite app (`vigil-report`), separate from the operator SPA and not built by CI.
- `orchestrator/tests/` — two bash end-to-end scripts, not a pytest suite.
- `agent/scripts/assess/tests/` — the assess-CLI pytest suite (~90 modules). Its `conftest.py` already puts `agent/scripts` on `sys.path`; new assess-CLI tests belong here, not in the backend suite.
- `tests/` — the root CLI and bench-harness suite. `tests/eval/` is the deterministic, zero-LLM eval replay harness and has its own README.
- `docs/` — user and maintainer documentation. `docs/adr/` holds the architecture decision records this map cites.
- `tools/` — repo-root maintainer scripts that regenerate the reporting lookup tables. Distinct from `<engagement>/tools/analysis-state/`, which is engagement-local code-analysis artifact state.
- `third_party/` — vendored upstream licences for the bundled pattern sets, with `THIRD_PARTY_NOTICES.md` at the root.
