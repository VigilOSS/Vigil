# CODE-MAP

The repo's **invariant map**: the things a reader cannot derive by listing files
or reading one module — which file owns a contract, what must change with it,
and what silently breaks when it does not.

**Size budget: this file stays under 32 KiB**, enforced by
`orchestrator/backend/tests/test_doc_dead_paths.py`. A map is only useful while it
can be scanned. If an addition
would break the budget, something here has stopped earning its place: cut it, or
push it into a docstring. Rewording until it fits is not the intended response —
a byte ceiling cannot be satisfied that way.

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
- `orchestrator/backend/app/services/code_analysis_support.py:CODE_REPO_ROLES` owns the repository
  obligation role — `analysis` carries coverage/queue/readiness duties, `reference` carries none;
  `contract_registry.py:CODE_REPO_ROLES` is the CLI mirror.
  See: `orchestrator/backend/tests/test_reference_repo_role.py`.
- `agent/scripts/assess/lib/contract_registry.py:FRAMEWORK_REGISTRATION_KINDS` owns the registration
  vocabulary on `assessment_surfaces`; `api/assessment.py` mirrors it as a Literal. Deliberately NOT
  in `agent/scripts/assess/lib/surfaces.py:VALID_SURFACE_TYPES` — registration kind is architecture,
  surface type security meaning. See: `orchestrator/backend/tests/test_surface_framework_registration.py`.
- `orchestrator/backend/app/api/assessment_operator.py:_LAUNCHED_CLIENT` owns the clients a dispatch can be
  BOUND to; `_DISPATCH_CLIENT` adds `unknown`, `contract_registry.py:BINDABLE_CLIENTS` mirrors it in the CLI.
  `_MIXED_ASSESSMENT_ROLES` owns mode-required roles; `contract_registry.py:MIXED_ASSESSMENT_ROLES` mirrors it.
  See: `orchestrator/backend/tests/test_dispatch_client_binding_api.py`.
- `agent/scripts/assess/lib/render_containment.py:contain_separators` owns how persisted,
  target-influenced text reaches an agent-readable document: lossless, indent-only, so nothing lands
  at column zero and forges a heading. ADR 0019 forbids masking it, so containment is the only lever.
  `operator_checkpoint.py` and `resume_brief.py` render through it.
  See: `agent/scripts/assess/tests/test_operator_checkpoint_render.py`.
- `agent/scripts/assess/lib/code_languages.py:CANONICAL_CODE_LANGUAGES` owns detected languages;
  backend structural languages must be a superset and cover every lightweight extractor.
  See: `orchestrator/backend/tests/test_structural_language_drift.py`.
- `agent/scripts/assess/lib/dependency_manifests.py:RECOGNIZED_MANIFESTS` owns manifests and readers;
  `classify_buckets.py:_BUCKETS` derives fragments from it. A missing reader is a GAP, not absence.
- `dependency_picture.py:SHIPMENT_OBSERVATIONS` / `REACHABILITY_OBSERVATIONS` /
  `DEPENDENCY_QUALIFIERS` own the dependency observation vocabularies: every member is
  `unverified_*`, and "looked and saw nothing" stays distinct from "could not look".
- `agent/scripts/assess/commands/code_dispatch.py:submit_queue_items` owns the audited write into
  `code_analysis_queue`; `code-dispatch queue/reanalyze` and `code-lead queue` go through it.
- `orchestrator/backend/app/services/state_manager/coverage.py:PROBE_RESULT_STATUSES` owns result
  outcomes. Only `tested` and `signal` cover a class.
- `orchestrator/backend/app/services/state_manager/coverage.py:CoverageStatus` owns coverage status;
  the standalone CLI mirror is `agent/scripts/assess/commands/resolve.py:_COVERAGE_STATUSES`.
- `orchestrator/backend/app/services/state_manager/command_run_queries.py:_RUN_NEEDS_ATTENTION_SQL` (twin
  `command_run_attention_reasons`) owns "run needs attention"; `command_runs.py:_derive_tool_bin` owns `tool_bin`; `db.py` re-derives old rows once.
- `orchestrator/backend/app/services/state_manager/_common.py:SUBMISSION_STATUSES` owns submission
  status; `agent/scripts/assess/lib/contract_registry.py:SUBMISSION_STATUSES` is the CLI mirror.
- `orchestrator/backend/app/api/assessment.py:FindingPatchRequest` owns patchable finding fields;
  `contract_registry.py:FINDING_PATCH_FIELDS` mirrors it. See:
  `orchestrator/backend/tests/test_finding_patch_contract_mirror.py`.
- `orchestrator/backend/app/services/state_manager/cvss.py:base_score` owns CVSS v3.1/v4.0 base-vector
  validation and scoring for finding writes and report readiness; `finding_details.py` owns the
  generated schema vocabulary. See: `orchestrator/backend/tests/test_cvss40.py`.
- `orchestrator/backend/app/services/state_manager/_common.py:VERIFICATION_STATUSES` owns finding
  verification status; `agent/scripts/assess/lib/contract_registry.py:VERIFICATION_STATUSES` mirrors it.
- `orchestrator/backend/app/retry_state.py:RETRY_STATES` owns blocked-technique retries; unknown
  legacy prose becomes reviewable `pending`, never `no_retry`.
- `agent/scripts/assess/lib/audit_enums.py` owns Kali technique and probe-kind enums. These are
  host-side only and are not copied into the runtime image.
- `agent/scripts/assess/lib/contract_registry.py:KALI_TARGET_VERBS` and `KALI_MAINT_VERBS` own the Kali
  roster; `KALI_VERBS` is their union. Registration and `agent/skills/kali-exec/SKILL.md` mirror it.
- `agent/scripts/assess/lib/kali_output.py:KALI_EXIT_CODES` owns terminal status exit codes;
  `kali_cli.py:emit_result` is the output funnel and renders the help table.
- `agent/skills/<name>/SKILL.md` owns discovered skill names; directory walking is the roster.
  `--skills` enforcement is CLI-only and advisory under ADR 0019.
- `orchestrator/backend/app/api/report_export.py`'s five `_*_FIELDS` rosters own what the
  client-delivered HTML carries; `orchestrator/report/src/types.ts` is the other half, index signature
  dropped so a renderer reaching past them is a type error. See: `docs/maintainer-guide.md` report-template section.
- `agent/scripts/assess/lib/contract_registry.py` owns executable CLI metadata; `contracts.py`
  resolves and renders it for `contract.py` and `list_commands.py`.
- `src/vigil_cli/host_tools.py` owns optional host recon install planning for `vigil doctor`; selected-client launch checks stay in `preflight.py`.
- `agent/scripts/assess/commands/proof_work.py` renders proof-claim packets through `commands/agent.py` before atomic ownership, validating source identity and deriving mandatory loads through `lib/prompt_census.py`.
- `src/vigil_cli/engagements.py:CLIENT_PROVIDER_KEYS` and `CLIENT_MESSAGE_FLAGS` own client launch
  identity. Generated launchers and preflight consume them.
- `src/vigil_cli/image_freshness.py` owns the content-digest mechanism every freshness check uses —
  input entries, digests, the image label, exclusions. Content, never mtime.
- `tools/runtime_release.py` owns native-platform runtime publication, OCI release labels,
  multi-platform index validation, and the immutable pin written into matched release artifacts.
  `.github/workflows/runtime-release.yml` supplies tag identity, native runners, registry
  authentication, and draft-release upload.
- `src/vigil_cli/restart_manifest.py:consumer_states` owns what an install invalidated, per consumer.
  `backend_state` provides the backend-only verdict for remediation commands. Presenters consume its rows; do not derive freshness beside it. See: `docs/maintainer-guide.md` freshness section.
- `src/vigil_cli/install_manifest.py` owns editable application input digests;
  `src/vigil_cli/install_fs.py` owns pinned/no-follow workspace and cache operations.
- `src/vigil_cli/assessment_clients.py` owns immutable native-client workspace bindings,
  context-bound helpers, managed pointers, plugin release identities, and managed-file digest manifests.
  GUI workspace opening never establishes native conversation ownership.
- `src/vigil_cli/client_projects.py` owns stable per-engagement/client/mode project entries,
  atomic new-task selections, and immutable protocol-v1 dispatcher staging. `agent/scripts/native-client/project-binding.mjs`
  attests native task bindings and create-once session receipts; project selection never migrates an existing task.
- `src/vigil_cli/client_checks.py` owns read-only client prerequisites and inspection of existing
  bound workspaces, asset manifests, and exact-context hook receipts. Historical `OBSERVED` events
  do not establish current native-build acceptance or completed backend hydration.
- `src/vigil_cli/client_context.py` discovers validated install-owned native project identity for mode,
  client-check and assess commands. It supplies session selectors only; application code, executable paths
  and backend endpoints retain their existing owners. `client_checks.py:validate_context_binding` owns shared binding validation.
- `src/vigil_cli/argv.py:passthrough_boundary` owns the opaque `--` boundary for universal CLI routing,
  startup forwarding and assessment root-flag hoisting; each parser retains ownership of its flags and validation.
- `src/vigil_cli/prompts.py` owns shared terminal questions and searchable start pickers for engagement and remediation, using `term.py:fuzzy_pick` or the terminal filter;
  `main.py` resolves engagement, client, then mode before preflight without changing ambient resolution for other commands.
- `src/vigil_cli/engagement_recency.py` owns the declared meaningful-work timestamp projection and UTC comparison;
  it reads existing database snapshots without initialization and excludes backend sync/housekeeping clocks.
- `src/vigil_cli/client_sessions.py` owns historical launch reads and separate official-open markers;
  picker recency never turns those markers into PID ownership or proof of native conversation readiness.
- `agent/scripts/assess/lib/scope.py:ingest_scope_filter` must run on every new file-to-buffer ingest
  path. Arjun and proxy ingestion reuse already-filtered URLs.
- `src/vigil_cli/engagements.py` owns durable offensive track creation, explicit add-track,
  session mode validation, official-start track initialization through `prepare_engagement_mode`, and engagement-local prompt routing. New offensive scopes store
  `tracks.web.phase` and/or `tracks.code.phase`; legacy scalar phase scopes remain readable.
  `agent/scripts/assess/lib/tracks.py` and
  `orchestrator/backend/app/services/engagement_tracks.py` read that contract for their
  respective assessment and backend paths. `VIGIL_OPERATOR_MODE` selects one prompt per
  session and never grants a track. Official starts repair only their selected engagement;
  `src/vigil_cli/install.py` repairs shared client files only under explicit maintenance flags.
- `src/vigil_cli/engagements.py:engagement_source_state` owns registered original-directory or manual-folder source inventory. `engagement.json:source_dir` selects the origin; first ingest/refresh requires conversational confirmation and creates one sealed copy directly from it.
- `orchestrator/backend/app/services/state_manager/app_units.py:score_application_units` and
  `depth_ledger.py` own the web-only terminal depth gate. See: ADR 0012.
- `orchestrator/backend/app/services/state_manager/findings.py:finding_mode_sql` owns candidate mode classification.
  `dispatches.py:dispatch_mode_sql` applies it to durable proof claims, including prior owners; reads and counts share this predicate before pagination. Execution route does not select memory ownership.

---

- `orchestrator/backend/app/api/assessment_operator.py:_CODE_ASSESSMENT_ROLES` defaults code-only dispatches to code;
  `agent/scripts/assess/commands/agent.py:_CODE_SOURCE_IDENTITY_ROLES` mirrors this set for source packets and CLI mode resolution.

## Sync rules worth remembering

- `agent/operator-core.md` and `agent/operator-core-blue.md` render to the committed wrappers, and `agent/agents/*.md` render to the per-client agent trees, through `agent/scripts/render-operator-prompts.sh`. Run it with `repo`; `check` fails on drift.
- `agent/commands/` owns operator commands. Renderer `COMMAND_NAMES` and explicit client metadata drive `agent/.claude/commands`, `agent/.codex/skills`, and native OpenCode/ZCode command trees. See: ADR 0017.
- `agent/scripts/render-operator-prompts.sh` renders native assessment command/role assets under
  `agent/.opencode/assessment` and `agent/.zcode/assessment`; `src/vigil_cli/assessment_clients.py`
  stages their immutable workspace/plugin consumers separately from other workflow assets.
- `agent/scripts/assess/lib/contracts.py` renders engagement binding into every command contract.
- `src/vigil_cli/client_rosters.py` links those wrapper trees into an engagement as **per-entry symlinks** (`<engagement>/.claude/commands/`, `<engagement>/.codex/skills/`), so an engagement never carries a stale copy and an operator-authored command of the same name wins.
- `orchestrator/backend/app/api/assessment.py` and `orchestrator/backend/app/api/code_analysis.py` feed the generated `agent/schemas/*.json` through `orchestrator/backend/scripts/generate_agent_schemas.py`. Check drift with that script's `--check` mode.
- `agent/scripts/assess/lib/treesitter_index.py` owns parsing and dispatch;
  `treesitter_catalogues.py` owns sink/entry queries, `treesitter_common.py` shared helpers,
  `treesitter_lightweight.py` line-based extractors, and `treesitter_streaming.py` bounded fallback.
- `agent/scripts/assess/commands/code_index.py` writes the engagement-local structural manifest;
  `code_index_sync.py` publishes validated metadata. Legacy or wrong-schema artifacts are rejected.
- `agent/scripts/assess/lib/code_structural_identity.py` owns the structural schema/path epoch (v7);
  `orchestrator/backend/app/services/code_analysis_support.py` mirrors the accepted schema. Rebuild and sync
  publish v7 beside retained historical v6 artifacts. See: `orchestrator/backend/tests/test_code_analysis_api.py`.
- `agent/scripts/assess/lib/code_structural_metadata.py` owns the artifact metadata and callable-identity
  validators shared by structural build and sync. See: `agent/scripts/assess/tests/test_structural_artifact_validation.py`.
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

---

## Easy-to-miss registration points

- `agent/scripts/assess/lib/findings.py:_AGENT_PREFIX_MAP` owns finding prefixes with
  `orchestrator/backend/app/services/state_manager/findings.py:_FINDING_PREFIX_BY_SOURCE`;
  a new finding-recording agent needs both maps and the applicable operator prompt table.
- `agent/scripts/assess/lib/contract_registry.py:_INLINE_DOCUMENTED_NAMESPACES` — a `<verb> <action>` leaf documented on its parent contract must have that parent listed here, or `vigil assess contract` cannot resolve it.
- `orchestrator/backend/app/services/code_analysis_support.py:_analysis_repo_sql` / `_analysis_repo_files_sql`
  — every query counting an OBLIGATION over `code_files` must carry one, or a `reference` repository
  regains coverage, queue and readiness duties. Reads must NOT: reference source stays searchable
  and citable. `code_fuzz_completion.py:fuzz_states` applies it at source.
- `orchestrator/backend/app/services/state_manager/dispatches.py:record_dispatch_client_binding`
  writes `assessment_dispatch_client_bindings`, append-only by SQLite trigger: a correction stamps
  the prior row's `superseded_by_id`, never an overwrite. `_DISPATCH_SELECT` carries the current
  binding — a dispatch read off that projection reports every specialist as unbound.
- `code_analysis.py:_record_source_generation` — every generation-bound row type must be handled on
  promotion. Queue rows, results and triggers are stamped superseded; `_rebase_lead_bindings` carries
  a lead binding forward only on an identical `file_hash`. A generation-bound table added without a
  line here claims a currency it does not have.
- `orchestrator/backend/app/services/state_manager/phase_readiness.py:PER_HOST_OBJECTIVES` has a CLI
  mirror in `agent/scripts/assess/lib/coverage_checks.py` and a `coverage_deferral` API literal.
- `state_manager/command_runs.py` registers output artifacts before and after execution, both
  gated on `route != "host_exec"`; a third route needs both registrations.

## Boundaries worth knowing

### agent/ — prompts and the assessment CLI

- `agent/scripts/assess/cli.py` — the authoritative subcommand registry for `vigil assess`, including the `kali` subgroup that owns all target-facing tool execution.
- `agent/scripts/assess/lib/scope.py` — scope parsing, matching, and locked atomic mutation. There is deliberately **no outbound destination filtering**: `enforce_execution_policy` never refuses a command for its destination host. Staying inside the authorized roots is the operator's responsibility.
- `agent/scripts/assess/lib/config.py` — one fail-closed engagement-selection precedence for every `vigil assess` command: explicit `--engagement-dir`, else a root discovered from CWD, else the session variable exported by `vigil engagement start`.
- `agent/scripts/assess/lib/code_snapshot.py` — race-checked, content-addressed source copies.
  `orchestrator/backend/app/code_snapshot.py` independently attests them; new v3 snapshots use
  decoded logical lines, while historical v2 snapshots retain their original attestation semantics. See: ADR 0026.
- `agent/scripts/assess/lib/parser_boundary.py` + `parser_worker.py` — the structural-parser process boundary. Every typed failure becomes an explicit all-byte fallback with declared unavailable dimensions, never a silent skip. See: ADR 0029.
- `agent/scripts/assess/commands/export_submission.py` and `export_reply.py` assemble and present;
  neither rewrites authored content or masks credentials. Rendering helpers live in
  `agent/scripts/assess/lib/finding_render.py`.
- `agent/scripts/assess/commands/operator_checkpoint.py` — `vigil assess operator-checkpoint`, the operator's own durable state. References plus one intent note; every reference is existence-checked in the write transaction.
- `agent/scripts/assess/commands/resume_brief.py` — a **read**. It observes abandoned command runs, jobs and host children and names the verb that reconciles them; the reconciling write is owned solely by `vigil assess kali sweep-orphans`.
- `agent/scripts/hooks/` — shared host hooks for activity logging, compaction, post-compaction
  operator rehydration, and session end. Command filtering is deliberately absent (ADR 0019).
  `goose-hook-adapter.sh` adapts Goose tool names.
- `agent/docker/runtime-full/Dockerfile` — the supported target-facing tool surface. All baked inputs participate in image-digest drift checks.

### src/vigil_cli/ — the universal CLI

- `src/vigil_cli/term.py` owns terminal-only Rich rendering and shared exact-candidate fuzzy selection with literal, temporary-file previews; callers retain plain/JSON output contracts.
- `src/vigil_cli/application.py` — explicit/imported release resolution, bundle validation and persistent content-addressed assets/helper CLI. Never discover source from workspace or CWD.
- `src/vigil_cli/workspace.py` — canonical private paths and in-place legacy adoption; `paths.py:workspace_root_for_engagement` resolves private ownership independently of application assets.
- `vigil_build.py` — tracked publisher inputs, matched CLI/backend/agent/docs/legal bundle and locked prebuilt UI provenance; its sdist builds wheels without Git or Node.
- `src/vigil_cli/process_identity.py` owns birth-identity checks shared by client sessions and backend process receipts;
  `orchestrator.py` uses those receipts for status/stop, preflight and restore ownership decisions.
- `src/vigil_cli/client_sessions.py` — live PID/birth-identity release bindings and shared-file bootstrap lock; old releases retain assets and must end before rebinding the same engagement.
- `src/vigil_cli/paths.py:resolve_orchestrator_base_url` — backend URL precedence and dotenv normalization; `vigil config resolve orchestrator_base_url` exposes it to generated client launchers at session start.
- `src/vigil_cli/preflight.py` owns launch checks shared with blue; managed-local backend recovery never replaces a configured remote endpoint. Static code startup does not query Docker.
- `src/vigil_cli/remediation.py` — case intake/context rendering, configured workspace/checks, reviewed PR publication, and consented development workflow commands; `remediation_browser.py` owns local browser execution. Backend APIs own case state.
  Interactive start selects remediation projects through shared prompts; the canonical engagement wizard creates projects.
  External-reference joins resolve to numeric case identity; identity/finalization/publication share a case lock.
  Branch finalization retains retry intent across local VCS and backend registration.
- `src/vigil_cli/remediation_regression.py` — paired red/green receipts; `agent/scripts/assess/lib/remediation_regression.py` owns disposable sources; `orchestrator/backend/app/services/remediation_regression.py` validates provenance.
- `src/vigil_cli/remediation_sessions.py` owns role routing and Claude native binding/attachment; launch receipts correlate job names with host UUIDs, and `start --session-id` recovers without redispatch.
  `join --fresh` replaces the case conversation under its session lock, preserving binding history and requiring consent before stopping a running worker.
- `src/vigil_cli/remediation_clients.py` owns OpenCode repository launch and ZCode's context-bound plugin preparation/workspace opening, without native conversation receipts. `agent/.zcode/hooks/` restores defensive case context.
- `agent/scripts/assess/lib/remediation_project.py` and `remediation_vcs.py` — shared PROJECT.md parsing and Git/JJ identity, workspace, diff, and push contracts; CLI import bridges are `project_config.py` and `remediation_vcs.py`.
  `remediation_vcs.py:tree_id` owns complete code-tree identity; backend evidence records it at intake.
  New configured workspaces use stable numeric case directories. Check stages select early execution; all captured checks remain approval requirements. Branch finalization validates unpublished same-revision rename and retry state.
  Local verification can carry across identical trees; approvals and served-runtime proof retain revision identity.
- `src/vigil_cli/runtime.py` + `up.py` — one shared long-lived Kali container, reached host-side by `docker exec`. There is no in-container API server or MCP bridge.
  `up.py:run_up` owns startup JSON/service states; `service_locks.py` serializes shared starts. `agent/scripts/assess/lib/kali_runtime_exec.py` owns first-use managed execution startup.
- `src/vigil_cli/runtime_images.py` owns immutable release pins and label validation; `.github/workflows/runtime-release.yml` embeds the published multi-platform pin in matched artifacts.
- `src/vigil_cli/mitmproxy.py` — the single owner of the proxy `docker build` argv, including the inputs-digest label without which the image can never be proven current.
- `src/vigil_cli/oob_relay.py` — the single owner of the install's OOB relay-slot identity contract; `oob.py`, `install.py`, `up.py`, and `status.py` consume that record rather than deriving routes independently.

### orchestrator/backend

- `orchestrator/backend/app/api/assessment.py` — live-state routes for recon, coverage, findings,
  command runs, and bulk ingestion; finding history supports summary and lossless transition reads.
  Coverage ledger reads (`coverage-items/page`, `facets`, `reasons`, one item, its page `position`) come from `state_manager/coverage.py`.
  Operator pages `command-runs/page|facets|{id}/position` (`command_run_queries.py`) and `request-variants/page|facets|{id}`
  `[/position|/observations]` (`coverage.py`); bare lists stay the CLI contract. `findings?view=summary` omits `details`/`notes`; `PATCH oob-probes/{nonce}` audits a verdict; `oob.py:oob_verdict_entry` defines one.
  `assessment_operator.py` owns dispatch/handoff/decision/checkpoint routes; `submissions.py` owns immutable submission/sent-reply APIs.
- `orchestrator/backend/app/api/intel.py` — per-engagement intel reads and writes. `/resolve` maps
  untyped finding intel ids through the canonical search index without guessing across entity tables;
  it reports resolved, missing, unsupported, dangling, and ambiguous ids.
- `orchestrator/backend/app/api/code_analysis.py` — the only repo/file ingest write, lease-owned queue
  work, generation-bound compare-and-swap, and paginated queue reads. Its `item_ids` page and
  `code-dispatch fetch --ids-file` share ordering and current-generation filtering.
  The Code view reads `analysis-results/page` (`scope=current|awaiting_verdict`) and `{id}[/position]` (`analysis-results`
  is the CLI listing), `analysis-queue?current_only=` lanes (stats SQL), `repos/review-progress`, readiness `track_enabled`.
- `orchestrator/backend/app/services/state_manager/proof_work.py` owns current proof preparation, atomic dispatch claims, live approval independent of bindings, derived `queue_state`/`reverification_required`, and explicit release after execution ends.
  `api/assessment_proof_work.py` and `agent/scripts/assess/commands/proof_work.py` expose it; finding status and its `next_test` still own proof owed.
  `orchestrator/backend/app/services/scope_admission.py` bridges to the canonical agent scope matcher.
- `orchestrator/backend/app/services/state_manager/finding_next_tests.py` owns runtime proof plans, written with the parking transition,
  and `owes_runtime_proof`/`runtime_proof_owed_sql` (parked, not merged). Proof work binds the current park.
  `contract_registry.py:NEXT_TEST_FIELDS`/`NEXT_TEST_ROUTE_HINTS`, `agent/scripts/assess/lib/next_test.py` bounds and `finding_next_tests.py:NEXT_TEST_FIELDS`
  mirror `api/assessment.py:FindingNextTestRequest`. See: `orchestrator/backend/tests/test_finding_next_test_contract_mirror.py`.
- `orchestrator/backend/app/services/state_manager/` — the live-state service package, re-exported
  through `__init__.py` so public `state_manager.<fn>` paths remain stable.
- `orchestrator/backend/app/services/state_manager/coverage_readiness.py` owns readiness and per-host verdicts; `finding_snapshots.py` owns finding snapshot/author provenance.
- `orchestrator/backend/app/services/state_manager/command_runs.py` owns run writes and output integrity; `command_run_queries.py`, `assessment_jobs.py`, and `host_liveness.py` own their reads and ledgers.
- `orchestrator/backend/app/services/submission_versions.py` — CLI/UI submission snapshots; neither changes submission status nor submits externally. See ADR 0025.
  `_ELIGIBLE_ATTACHMENT_SQL` owns what the attachment picker offers (never internal submission-workspace files);
  `publication_readiness` and `attachment_page` back the read-only readiness and attachment routes in `api/submissions.py`.
  `_packet_review_issue` checks package freshness for blind triage and Pass 1 QA;
  `_pass1_qa_state` projects selection-specific QA. `state_manager/dispatches.py:record_decision` validates auditor attribution.
- `orchestrator/backend/app/services/activity_feed.py` owns the merged Activity feed (`GET /activity`, `api/activity.py`):
  categories, mirrored-event exclusion, cursors, cached summary-text search, and entity `ref`/`unlinked_reason`.
- `orchestrator/backend/app/services/artifacts.py:ARTIFACT_SPECS` owns the engagement Files roster: listed root documents only, read with a byte bound.
- `orchestrator/backend/app/services/assessment_memory.py` and `artifact_index.py` own the bounded
  resume brief and artifact index; output points to drill-down commands instead of embedding data.
  `artifact_index.py:_store_artifact` records finding-linked digest changes atomically in `activity.py`;
  registration and refresh expose change receipts to `agent/scripts/assess/commands/artifact.py`.
- `orchestrator/backend/app/reply_render.py` — the versioned exact-bytes outbound renderer; `agent/scripts/assess/lib/reply_render.py` is an import-only bridge so draft previews and the backend cannot fork the format.
- `orchestrator/backend/app/services/state_manager/run_accounting.py` owns run identity and lifecycle; `run_inventory.py` owns sources and obligations, `run_evidence.py` owns linked receipts, and `run_comparisons.py` owns comparisons. `proofs.py` owns immutable evidence receipts. See: ADR 0028.
- `orchestrator/backend/app/services/engagements.py` — filesystem-to-DB sync. Explicit deletes are tombstoned so a later sync cannot resurrect them from leftover files.
- `orchestrator/backend/app/api/remediation.py` and `services/remediation.py` — case/source
  resolution, canonical finding links, captured review policy/base, typed verification, shared
  environment ownership/runtime identity, and approval/deployment gates; separate from assessment Findings.
  Optional primary external references are separate from intake provenance; identity versions prevent approval resurrection. Dedicated identity/finalization routes preserve numeric case ownership and normal patch branch immutability.
  `publication_intent` validates approval and writes a durable intent under the DB writer lock before initial push; later identity and branch changes cannot race that publication.
  `_details` owns evidence matches and PR/check projections; paged evidence/history reads preserve full review gates.

### Frontend and the rest

- `tools/public_identity_policy.py` owns local/CI private policy loading; tracked guards contain no private fingerprints.
- `orchestrator/frontend/` — operator SPA: `components/TabBar.tsx` owns tabs, `lib/api.ts` REST,
  `lib/theme.ts` theme state, and `app.css` shared tokens. `lib/serverTime.ts` owns backend
  timestamp parsing (zone-less database times are UTC); `components/formatting.tsx` `TimeStamp` renders them.
- `orchestrator/frontend/src/lib/workspaceRoutes.ts` — canonical hash links/history. `App.tsx` routes separate assessment/remediation workspaces.
- `orchestrator/frontend/src/components/record/RecordView.tsx` — the one record (detail) view tabs open an entity in: Back/position/Previous-Next bar,
  header, section tabs, Escape and focus return; `record/recordNavigation.ts` walks the shown order or asks the server (`position`) for paged lists.
- `orchestrator/frontend/src/components/ProofWorkTab.tsx` consumes durable proof work; UI actions never launch agents or verify findings.
- `orchestrator/frontend/src/components/FindingRecordHeader.tsx` shares finding identity/status axes and per-finding section navigation across review and disclosure queues.
