# CODE-MAP

Contract owners, coupled consumers, and invariants not evident from a file listing.

**Size budget: this file stays under 32 KiB**, enforced by
`orchestrator/backend/tests/test_doc_dead_paths.py`.

---

## Single sources of truth (drift-prone invariants)

Import contracts from their owner; pin standalone mirrors with regressions.

- `agent/scripts/assess/lib/phases.py` owns all phase rosters, terminal phases, and input aliases.
  Backend/frontend mirrors are pinned by `orchestrator/backend/tests/test_phase_roster.py`.
- `orchestrator/backend/scripts/generate_agent_schemas.py` owns the ten generated schema specs.
  A schema without a spec is hand-written. See: `orchestrator/backend/tests/test_schema_generation.py`.
- `agent/scripts/assess/lib/vuln_taxonomy.py` owns classes, families, bucket/surface mappings,
  and skill mappings. See: `orchestrator/backend/tests/test_vuln_taxonomy.py`.
- `agent/scripts/assess/lib/classify_buckets.py:INERT_TYPES` owns inert work-item types;
  `agent/scripts/assess/commands/dispatch/work_items.py` mirrors the backend-side predicate.
- `classify_buckets.py:_BUCKETS` owns URL bucket scoring and skip tags.
  Ingest classifies inline; `work-buffer reclassify` reapplies it.
- `orchestrator/backend/app/services/code_analysis_support.py:CODE_REPO_ROLES` owns the repository
  obligation role — `analysis` carries coverage/queue/readiness duties, `reference` carries none;
  `contract_registry.py:CODE_REPO_ROLES` is the CLI mirror.
  See: `orchestrator/backend/tests/test_reference_repo_role.py`.
- `contract_registry.py:FRAMEWORK_REGISTRATION_KINDS` owns the registration
  vocabulary on `assessment_surfaces`; `api/assessment.py` mirrors it as a Literal. Deliberately NOT
  in `agent/scripts/assess/lib/surfaces.py:VALID_SURFACE_TYPES` — registration kind is architecture,
  surface type security meaning. See: `orchestrator/backend/tests/test_surface_framework_registration.py`.
- `orchestrator/backend/app/api/assessment_operator.py:_LAUNCHED_CLIENT` owns the clients a dispatch can be
  BOUND to; `_DISPATCH_CLIENT` adds `unknown`, `contract_registry.py:BINDABLE_CLIENTS` mirrors it in the CLI.
  `_MIXED_ASSESSMENT_ROLES` owns mode-required roles; `contract_registry.py:MIXED_ASSESSMENT_ROLES` mirrors it.
  See: `orchestrator/backend/tests/test_dispatch_client_binding_api.py`.
- `agent/scripts/assess/lib/render_containment.py:contain_separators` owns lossless, indent-only containment of
  persisted target-influenced text in agent-readable documents, so none forges a column-zero heading (ADR 0019).
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
- `state_manager/coverage.py:PROBE_RESULT_STATUSES` owns result outcomes (only
  `tested` and `signal` cover a class); its `CoverageStatus` has the CLI mirror `agent/scripts/assess/commands/resolve.py:_COVERAGE_STATUSES`.
- `state_manager/command_run_queries.py:_RUN_NEEDS_ATTENTION_SQL` (twin
  `command_run_attention_reasons`) owns "run needs attention"; `command_runs.py:_derive_tool_bin` owns `tool_bin`; `db.py` re-derives old rows once.
- `state_manager/_common.py:SUBMISSION_STATUSES` and `VERIFICATION_STATUSES` own
  submission and finding verification status; `contract_registry.py` mirrors both under the same names.
- `api/assessment.py:FindingPatchRequest` owns patchable finding fields;
  `contract_registry.py:FINDING_PATCH_FIELDS` mirrors it. See:
  `orchestrator/backend/tests/test_finding_patch_contract_mirror.py`.
- `orchestrator/backend/app/services/state_manager/finding_change_policy.py` owns each finding write's verdict
  effect and the versioned claim digest (ADR 0039); `contract_registry.py:FINDING_CHANGE_EFFECTS` mirrors its
  table. See: `orchestrator/backend/tests/test_finding_change_effects_contract_mirror.py`.
- `state_manager/links.py:DEFAULT_ROOT_CAUSE_EFFECT` owns what a root-cause link with no stated effect
  means; `api/assessment.py:RootCauseLinkRequest` imports it, the CLI's `--effect` default mirrors it, and
  every read-side fallback that labels a sibling residual or root-resolved has to agree with it.
  See: `orchestrator/backend/tests/test_root_cause_effect_wire_default.py`.
- `finding_snapshots.py:resolve_snapshot_location` owns whether a cited path and line exist in the sealed
  generation, for finding locations, lead bindings and trigger targets.
- `repro_currentness.py:reproduction_basis` owns `source`, `runtime`, or `unknown` reproduction; readiness, the report,
  the `repro_rehearsal` gate and the export marker read it.
- `code_analysis_support.py:structural_review_obligation` owns the review proof a file owes (a function, each
  `<top-level>` segment or a whole-file span) for the receipt span gate and, via `structural_review_gaps`, the coverage
  gate; `function_callable_link_sql` keeps `<top-level>` out of function counts. See: `test_top_level_callable_review.py`.
- `code_analysis_support.py:_file_path_scope_sql` owns path scoping for queue list, claims and by-path coverage
  (`test_code_queue_path_scope.py`); `_current_analysis_status_sql`/`_structural_debt_sql` own the status buckets and
  debt the summary, readiness and by-path share (`test_code_coverage_by_path.py`).
- `code_analysis.py:WORKFLOW_CONTEXT_VULN_CLASSES` owns the workflow families: role words require them
  (`_applicable_families_for_file`), path words only suggest them (`_path_suggested_families_for_file`). Recomputed on
  every read. See: `test_workflow_state_families.py`.
- `orchestrator/backend/app/services/state_manager/cvss.py:base_score` owns CVSS v3.1/v4.0 base-vector
  validation and scoring for finding writes and report readiness; `finding_details.py` owns the
  generated schema vocabulary. See: `orchestrator/backend/tests/test_cvss40.py`.
- `orchestrator/backend/app/retry_state.py:RETRY_STATES` owns blocked-technique retries; unknown
  legacy prose becomes reviewable `pending`, never `no_retry`.
- `agent/scripts/assess/lib/audit_enums.py` owns Kali technique and probe-kind enums. Host-side only;
  never copied into the runtime image.
- `contract_registry.py:KALI_TARGET_VERBS` and `KALI_MAINT_VERBS` own the Kali
  roster; `KALI_VERBS` is their union. Registration and `agent/skills/kali-exec/SKILL.md` mirror it.
- `agent/scripts/assess/lib/kali_output.py:KALI_EXIT_CODES` owns terminal status exit codes;
  `kali_cli.py:emit_result` is the output funnel and renders the help table.
- `agent/skills/<name>/SKILL.md` owns discovered skill names; directory walking is the roster.
  `lib/contracts.py` rejects explicitly unknown names before dispatch; omitted skills allow self-selection.
- `orchestrator/backend/app/api/report_export.py`'s five `_*_FIELDS` rosters own what the
  client-delivered HTML carries; `orchestrator/report/src/types.ts` is the other half, index signature
  dropped so a renderer reaching past them is a type error. See: `docs/maintainer-guide.md` report-template section.
- `agent/scripts/assess/lib/contract_registry.py` owns executable CLI metadata; `contracts.py`
  resolves and renders it for `contract.py` and `list_commands.py`.
- `agent/scripts/assess/lib/config.py` checks backend engagement visibility through the
  engagement detail read before commands; summary/readiness assembly belongs to explicit readers.
- `src/vigil_cli/host_tools.py` owns optional host recon install planning for `vigil doctor`; selected-client launch checks stay in `preflight.py`.
- `agent/scripts/assess/commands/proof_work.py` renders proof-claim packets through `commands/agent.py` before atomic ownership, validating source identity and deriving mandatory loads through `lib/prompt_census.py`.
- `agent/scripts/assess/commands/agent.py` captures optional standing briefs by content digest;
  dispatch packets, launch continuations and `dispatch/handoff_renderer.py` share the immutable path and digest.
- `code_analysis.py:list_queue_items` and `list_code_files` own exact selected-item/path reads for
  dispatch preparation; `state_manager/findings.py:count_findings` owns the ledger's count-only read.
- `state_manager/assessment_summary.py` owns summary cache generations and shared build ownership;
  its async facade lets HTTP summary/report readers join without occupying request workers.
- `orchestrator/backend/app/request_diagnostics.py` owns long HTTP request tracking and independent
  all-thread stack capture; `main.py` owns its ASGI/lifespan integration.
- `artifact_index.py:prepared_artifact_health` owns root-pinned evidence observations;
  `state_manager/proofs.py` prepares health before finding writes and reconciles file identities
  and database receipt ownership before commit. Nested writers retain their atomic boundary.
- `state_manager/findings.py` owns verification request digests on canonical transitions;
  `code_analysis.py` owns exact closeout reconciliation. API audit mirrors distinguish these
  recorded replays from fresh mutations.
- `src/vigil_cli/engagements.py:CLIENT_PROVIDER_KEY` and `CLIENT_MESSAGE_FLAGS` own client launch
  identity. Generated launchers and preflight consume them.
- `src/vigil_cli/image_freshness.py` owns the content-digest mechanism every freshness check uses (never mtime).
- `src/vigil_cli/runtime_images.py` owns immutable release pins and label validation; the release workflow embeds the pin.
- `src/vigil_cli/mitmproxy.py` owns the proxy `docker build` argv and its inputs-digest label.
- `agent/docker/runtime-full/Dockerfile` — the supported target-facing tool surface. All baked inputs participate in image-digest drift checks.
- `tools/runtime_release.py` owns native-platform runtime publication, OCI release labels,
  multi-platform index validation, and the immutable pin written into matched release artifacts.
  `.github/workflows/runtime-release.yml` supplies tag identity, native runners, registry auth and draft uploads.
- `src/vigil_cli/restart_manifest.py:consumer_states` owns install invalidation; `backend_state` supplies remediation verdicts.
  Presenters consume these rows; see the maintainer freshness recipe.
- `src/vigil_cli/install_manifest.py` owns editable application input digests;
  `src/vigil_cli/install_fs.py` owns pinned/no-follow workspace and cache operations.
- `src/vigil_cli/assessment_clients.py` owns immutable native-client workspace bindings,
  context-bound helpers, managed pointers, plugin release identities, and managed-file digest manifests.
  Opening a GUI workspace does not establish conversation ownership.
- `src/vigil_cli/client_projects.py` owns stable per-engagement/client/mode project entries,
  atomic new-task selections, and immutable protocol-v1 dispatcher staging. `agent/scripts/native-client/project-binding.mjs`
  attests native task bindings and create-once session receipts; project selection never migrates an existing task.
- `src/vigil_cli/client_checks.py` owns client prerequisites, bound-workspace/assets and exact-context hook inspection.
  Historical `OBSERVED` events do not attest current builds or backend hydration.
- `src/vigil_cli/client_context.py` discovers install-owned project identity for mode/client-check/assess.
  It supplies session selectors, not application paths or endpoints; `client_checks.py:validate_context_binding` owns validation.
- `src/vigil_cli/argv.py:passthrough_boundary` owns the opaque `--` boundary for universal CLI routing,
  startup forwarding and assessment root-flag hoisting; each parser still owns its flags and validation.
- `src/vigil_cli/prompts.py` owns shared terminal questions and searchable start pickers for engagement and remediation;
  `main.py` resolves engagement, client, then mode before preflight without changing ambient resolution for other commands.
- `src/vigil_cli/engagement_recency.py` owns the declared meaningful-work timestamp projection and UTC comparison;
  it reads existing database snapshots without initialization and excludes backend sync/housekeeping clocks.
- `lib/scope.py:ingest_scope_filter` must run on every new file-to-buffer ingest
  path. Arjun and proxy ingestion reuse already-filtered URLs.
- `src/vigil_cli/engagements.py` owns offensive track creation, add-track, session mode validation, official-start
  track initialization (`prepare_engagement_mode`) and engagement-local prompt routing. Scopes store `tracks.web.phase`
  and/or `tracks.code.phase` (scalar phase scopes stay readable); `agent/scripts/assess/lib/tracks.py` and
  `orchestrator/backend/app/services/engagement_tracks.py` read them. `VIGIL_OPERATOR_MODE` selects one prompt per
  session and never grants a track. Official starts repair only their engagement; `src/vigil_cli/install.py`
  repairs shared client files only under explicit maintenance flags.
- `src/vigil_cli/engagements.py:engagement_source_state` owns registered original-directory or manual-folder source inventory. `engagement.json:source_dir` selects the origin; first ingest/refresh needs confirmation in conversation and seals one copy.
  It reads each snapshot's manifest, never its bytes: `code-index`, `code-index sync`,
  `code-history` and `code-dependencies` attest sealed bytes at point of use. It also backs
  `engagement mode`, run at every session start, resume and compaction.
- `orchestrator/backend/app/services/state_manager/app_units.py:score_application_units` and
  `depth_ledger.py` own the web-only terminal depth gate. See: ADR 0012.
- `orchestrator/backend/app/services/state_manager/findings.py:finding_mode_sql` owns candidate mode classification.
  `dispatches.py:dispatch_mode_sql` applies it to durable proof claims, prior owners included; reads and counts share it before pagination. Execution route does not select memory ownership.
- `api/assessment_operator.py:_CODE_ASSESSMENT_ROLES` defaults code-only dispatches to code;
  `agent/scripts/assess/commands/agent.py:_CODE_SOURCE_IDENTITY_ROLES` mirrors this set for source packets and CLI mode resolution.

---

## Sync rules worth remembering

- `agent/operator-core.md`, `agent/operator-core-blue.md` and `agent/agents/*.md` render to committed wrappers and per-client agent trees via `agent/scripts/render-operator-prompts.sh` (`repo` writes; `check` fails on drift).
- `agent/commands/` owns operator commands. Renderer `COMMAND_NAMES` and explicit client metadata drive `agent/.claude/commands`, `agent/.codex/skills`, and native OpenCode/ZCode command trees. See: ADR 0017.
- `render-operator-prompts.sh` renders native assessment command/role assets under
  `agent/.opencode/assessment` and `agent/.zcode/assessment`; `assessment_clients.py`
  stages their immutable workspace/plugin consumers separately from other workflow assets.
- `agent/scripts/assess/lib/contracts.py` renders engagement binding into every command contract.
- `src/vigil_cli/client_rosters.py` links those wrapper trees into an engagement as per-entry symlinks, so no stale copy exists and an operator-authored command of the same name wins.
- `api/assessment.py` and `api/code_analysis.py` feed the generated `agent/schemas/*.json` through `scripts/generate_agent_schemas.py` (`--check` for drift).
- `agent/scripts/assess/lib/treesitter_index.py` owns parsing and dispatch;
  `treesitter_catalogues.py` owns sink/entry queries, `treesitter_common.py` shared helpers,
  `treesitter_lightweight.py` line-based extractors, and `treesitter_streaming.py` bounded fallback.
  `PhpIncludeResolver` resolves PHP includes against the snapshot at build (`test_php_include_targets.py`).
- `agent/scripts/assess/commands/code_index.py` writes the engagement-local structural manifest;
  `code_index_sync.py` publishes validated metadata and rejects wrong-schema artifacts.
- `agent/scripts/assess/lib/code_structural_identity.py` owns the structural schema/path epoch (v7);
  `code_analysis_support.py` mirrors it; rebuild and sync
  publish v7 beside retained v6 artifacts. See: `orchestrator/backend/tests/test_code_analysis_api.py`.
- `agent/scripts/assess/lib/code_structural_metadata.py` owns the artifact metadata and callable-identity
  validators shared by structural build and sync. See: `agent/scripts/assess/tests/test_structural_artifact_validation.py`.
  Its `TOP_LEVEL_CALLABLE_NAME` is mirrored in `code_analysis_support.py`.
- `agent/scripts/assess/lib/kali_audit.py` threads the command-run audit chain. A persisted Kali flag
  must also land in `kali_cli.py`, `api/assessment.py`, `app/db.py`, and
  `state_manager/command_runs.py`.

---

## Prompt-to-backend coupling

Prompt-defined durable artifacts are executable contracts, not prose-only changes.

- `agent/skills/code-architecture-mapping/SKILL.md` owns `guidance_hypotheses` (queue field in
  `agent/phases/code-phase-1-classify-map.md`; code dispatch normalizes, `api/code_analysis.py`
  validates `list[str]`) and the `call-graph.json`, `attack-hypotheses.json`, `cve-bug-shapes.jsonl`
  contracts later code dispatches consume; `code-history check-shapes` checks the last.
- `code_dispatch.py` loads `file-analysis-queue.json`; each `priority` must equal the file's current band-valid `analysis_priority`; drift rejects the whole batch before mutation.
- `agent/operator-core.md` phase gates call `vigil assess check-phase-readiness`. Dropping the gate call silently disables the phase boundary.

---

## Easy-to-miss registration points

- `agent/scripts/assess/lib/findings.py:_AGENT_PREFIX_MAP` owns finding prefixes with
  `state_manager/findings.py:_FINDING_PREFIX_BY_SOURCE`;
  a new finding-recording agent needs both maps and the applicable operator prompt table.
- `contract_registry.py:_INLINE_DOCUMENTED_NAMESPACES` — a `<verb> <action>` leaf documented on its parent contract must have that parent listed here, or `vigil assess contract` cannot resolve it.
- `code_analysis_support.py:_analysis_repo_sql` / `_analysis_repo_files_sql`
  — every query counting an OBLIGATION over `code_files` must carry one, or a `reference` repository
  regains coverage, queue and readiness duties. Reads must NOT: reference source stays searchable
  and citable. `code_fuzz_completion.py:fuzz_states` applies it at source.
- `orchestrator/backend/app/services/state_manager/dispatches.py:record_dispatch_client_binding`
  writes `assessment_dispatch_client_bindings`, append-only by SQLite trigger: a correction stamps
  the prior row's `superseded_by_id`, never an overwrite. `_DISPATCH_SELECT` carries the current
  binding — a dispatch read off that projection reports every specialist as unbound.
- `code_analysis.py:_record_source_generation` — every generation-bound row type must be handled on
  promotion. Queue rows, results and triggers are stamped superseded; `_rebase_lead_bindings` carries
  a lead binding forward only on an identical `file_hash`. A new generation-bound table needs a line
  here, or it claims a currency it does not have.
- `state_manager/coverage_readiness.py:PER_HOST_OBJECTIVES` has a CLI
  mirror in `agent/scripts/assess/lib/coverage_checks.py` and a `coverage_deferral` API literal.
- `state_manager/command_runs.py` registers output artifacts before and after execution, both
  gated on `route != "host_exec"`; a third route needs both registrations.
- `agent/scripts/assess/commands/fetch.py` — a paged backend read must be registered or `fetch`
  silently truncates at one page, and WHICH table depends on the response shape:
  `_PAGED_ASSESSMENT_ENDPOINTS` maps a bare-array route to its `?limit=` ceiling;
  `_PAGED_ASSESSMENT_ENVELOPE_ENDPOINTS` maps an object-wrapped route to `(rows key, ceiling)`.
  Registering an envelope route in the array table turns a working read into a hard error.
  See: `agent/scripts/assess/tests/test_fetch_route_catalog.py`.

## Boundaries worth knowing

Per-subsystem ownership and boundaries live in
[docs/subsystem-boundaries.md](docs/subsystem-boundaries.md). This file keeps the
cross-cutting invariants above, which span directories and have no other home.
