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
  `GATED_DECISION_KINDS` owns the decision kinds stored canonically across case/separator spellings, with misspellings refused;
  `contract_registry.py:GATED_DECISION_KINDS` mirrors it for `agent decision --kind` help.
  See: `orchestrator/backend/tests/test_dispatch_client_binding_api.py`,
  `orchestrator/backend/tests/test_gated_decision_kind_mirror.py`.
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
- `state_manager/_common.py:CORROBORATION_LINK_KIND` owns the `corroborated_by` link kind
  (`target_kind='dispatch'`, naming a recorded dispatch that neither authored nor edited the finding);
  `state_manager/links.py` validates it, `commands/corroborate_finding.py` (`finding corroborate`) mirrors the
  kind, and a corroboration never changes verification status. `commands/list_chains.py` (`chain list`)
  counts a chain step verified on the same confirmed/downgraded pair report gates admit.
  See: `agent/scripts/assess/tests/test_finding_corroborate_and_chains.py`.
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
  `_review_depth_sql` owns a file's review depth (deep or wide-only) for the by-path and CWE-matrix depth
  columns and `depth_advisories`; depth is steering and never enters coverage or a gate (`test_code_review_depth.py`);
  `review_depth_params` supplies its bound parameters and deep packets are read once per query
  (`test_code_review_depth_scale.py`). `code_analysis.py:_effort_gap_summary` owns `gate.effort_gaps` (tier x family
  groups with counts, sample paths, `rows_omitted`, `full_list`; per-file `rows` only on `code/coverage?detail=cwe`).
  See: `test_code_coverage_payload.py`.
- `code_analysis.py:_record_depth_floor_triggers` owns what a critical/high closeout leaves below its tier's
  `code_analysis_support.py:EFFORT_THRESHOLDS` floor: a `depth_floor` trigger per family (`TRIGGER_ORIGIN_DEPTH_FLOOR`),
  never a refusal (ADR 0046). `trigger_review_basis` holds a bound trigger to the same floor; code readiness names
  pending ones as `depth_floor_triggers`, which `codeLabels.ts:BLOCKER_LABELS` labels. A family the closeout marks
  not_applicable raises none and is answered whatever a receipt scored (`code_analysis_support.py:_closeout_not_applicable_families`).
  `_untriggered_depth_shortfalls` owns `gate.untriggered_depth_shortfalls` (below-floor critical/high families no trigger
  names) and `_depth_floor_retired_files` owns `depth_floor_retired_files` (files whose triggers a reclassification
  retired); both are pointers, never gates. See: `test_code_depth_floor_triggers.py`, `test_code_reclassify_obligations.py`.
- `code_analysis.py:withdraw_queue_items` (`POST code/analysis-queue/withdraw`, `code-dispatch withdraw`) owns taking back
  an unclaimed `requeue-triggers` attempt: the row is removed and its live triggers return to pending.
  See: `test_code_queue_withdraw.py`.
- `code_analysis.py`'s `_*_REASON` constants own trigger supersession reasons; `api/code_analysis.py:list_code_triggers`
  mirrors them as its `supersession_reason` filter. See: `test_trigger_supersession_reason_mirror.py`.
- `state_manager/dispatches.py:_decision_recorder` owns recorder identity: a named dispatch with its own stored role,
  else the operator, an unknown id refused. Decision rows and `code-record classify` audits (`--agent-id`,
  `code_analysis.py:_classification_recorder`) record it as `recorded_by`. See: `test_code_reclassify_obligations.py`.
- `code_analysis.py:CONTEXT_TAG_VULN_CLASSES` owns the families each architect-recorded context tag (a file's `context_tags`) requires
  (`_applicable_families_for_file`; `app/api/code_analysis.py:CodeContextTag` is the same vocabulary), and
  `WORKFLOW_PATH_CONTEXT_TAGS` the tags whose families path words only suggest (`_path_suggested_families_for_file`).
  The free-text role adds no family. Recomputed on every read. See: `test_workflow_state_families.py`.
  `CLIENT_BUNDLE_OPTIONAL_FAMILIES` owns the server-only families a `client-bundle` tag makes optional
  (`_optional_families_for_file`, served as `optional_vuln_classes`). See: `test_client_bundle_context_tag.py`. `_markup_unread_code` owns what unread markup code adds:
  server-side code requires the code slot families, a browser `<script>` the browser families, and a streaming
  fallback only suggests them (`_unread_code_suggested_families_for_file`). See: `test_code_effort_obligations.py`.
- `orchestrator/backend/app/services/state_manager/cvss.py:base_score` owns CVSS v3.1/v4.0 base-vector
  validation and scoring for finding writes and report readiness; `finding_details.py` owns the
  generated schema vocabulary. See: `orchestrator/backend/tests/test_cvss40.py`.
- `orchestrator/backend/app/retry_state.py:RETRY_STATES` owns blocked-technique retries; unknown
  legacy prose becomes reviewable `pending`, never `no_retry`.
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
  resolves and renders it for `contract.py` and `list_commands.py`. `render_contract` is the compact
  view; `render_field_sections` is the one per-field renderer behind `contract --field` and a refused
  write's contract block (`lib/contract_sections.py` maps validator errors to the field names).
- `contract_registry.py:DISPATCH_MODES_BY_ROLE` owns the iteration modes each role prompt describes (default first);
  `agent start` warns on another mode. Pinned against each role's "Iteration mode" line by
  `agent/scripts/assess/tests/test_dispatch_role_roster.py`, which also keeps role names off the
  clients' built-in subagent names.
- `state_manager/dispatches.py:RENAMED_DISPATCH_ROLES` owns which role a retired role spelling means: a
  stored dispatch keeps its spelling and a handoff may name the current role (`general` → `blind-reviewer`). `contract_registry.py`
  mirrors it, and `agent start`/`start-swarm`/`continue` register the current role. See:
  `orchestrator/backend/tests/test_renamed_dispatch_roles_mirror.py`.
- `agent/scripts/assess/lib/producer_identity.py:resolve_report_writer` owns which dispatch a `report.md` or
  submission registration is attributed to when `--agent-id` is omitted (`export submission`,
  `artifact register --kind report`). See: `agent/scripts/assess/tests/test_report_writer_attribution.py`.
- `state_manager/proofs.py:attach_severity_variance` owns the `severity_variance` decision: only `reason` is
  authored; band, chosen severity, verifier and receipt come from the current verification, as on `finding verify
  --severity-variance-file`. Report readiness names an unexplained band departure `severity_cvss_mismatch`.
  See: `orchestrator/backend/tests/test_severity_variance_derivation.py`.
- `state_manager/dispatches.py:CURRENT_DECISION_SQL` owns which decision rows are current: a
  row recorded with `supersedes` stamps the replaced row `superseded_by_id`, and every gate,
  readiness reader and approval flow reads only current rows (`list_decisions` defaults to
  them). See: `orchestrator/backend/tests/test_decision_supersession.py`.
- `state_manager/report_readiness.py:report_qc_state` owns report.md QC currency (ADR 0045),
  served as report readiness `report_qc`; `transition_phase._report_qc_blockers` reads it.
  `finding_severity_band` owns the band-departure rule readiness and the finding point read share.
- `agent/scripts/assess/lib/config.py` checks backend engagement visibility through the
  engagement detail read before commands; summary/readiness assembly belongs to explicit readers.
- `src/vigil_cli/orchestrator.py:lifecycle_endpoint` owns the local endpoint backend start/restart bind: the owned
  receipt's, else the loopback endpoint `preflight.py:managed_backend_endpoint` derives from the workspace's
  resolved base URL, else 127.0.0.1:18000. `paths.py:global_default_install_root` owns which workspace the global
  `orchestrator_base_url` and `install.root` settings belong to; `agent/scripts/assess/lib/config.py:resolve_base_url`
  mirrors `paths.py:resolve_orchestrator_base_url` across the assess exec boundary. See:
  `tests/test_orchestrator_endpoint_selection.py`, `agent/scripts/assess/tests/test_assess_workspace_base_url.py`.
- `agent/scripts/assess/commands/proof_work.py` renders proof-claim packets through `commands/agent.py` before atomic ownership, validating source identity and deriving mandatory loads through `lib/prompt_census.py`.
- `agent/scripts/assess/commands/agent.py` captures optional standing briefs by content digest;
  dispatch packets, launch continuations and `dispatch/handoff_renderer.py` share the immutable path and digest.
- `code_analysis.py:list_queue_items` and `list_code_files` own exact selected-item/path reads for
  dispatch preparation; `state_manager/findings.py:count_findings` owns the ledger's count-only read.
- `orchestrator/backend/app/aggregate_reads.py` owns the aggregate GET budget, coalescing and deadline.
  `depth_projection_bytes` binds cancellable depth workers to the server's database. `main.py` registers the middleware.
  See `test_aggregate_read_limiter.py` and `test_terminal_backstop.py`.
- `orchestrator/backend/app/json_response.py` owns lossless JSON escaping for validation errors
  and the activity API; activity response models validate Python values before transport rendering.
- `services/activity_feed.py:get_activity_entry` owns `GET /engagements/{key}/activity/{entry_id}` (`audit:<id>` or
  `event:<id>`) from the feed's own page projection.
- `services/activity_feed.py:FeedCursor` owns feed cursors; clients catch up from each response's `catch_up_cursor`.
- `log_entry.py:_OCCURRED_AT_MAX_LENGTH` mirrors `ActivityEntryRecordRequest.occurred_at`; see `test_activity_api.py`.
- `standard-hooks.js` and `assessment-hooks.js` mirror spool `CLAIM`/`DRAIN`; see `test_opencode2_plugin.py`.
- `orchestrator/frontend/src/components/record/RecordView.tsx` is the one detail view: Submissions, Proof work
  (`?proof={slug}`) and Activity (`activity/ActivityRecord.tsx`, `?entry={id}`) open in it; `App.tsx` parses the routes.
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
- `src/vigil_cli/update.py` owns `vigil update`: verified release-wheel install, re-exec into the new CLI,
  and restarts of running services that `consumer_states` reports stale.
- `src/vigil_cli/install_manifest.py` owns editable application input digests;
  `src/vigil_cli/install_fs.py` owns pinned/no-follow workspace and cache operations.
- `src/vigil_cli/assessment_clients.py` owns immutable native-client workspace bindings,
  context-bound helpers, managed pointers, plugin release identities, and managed-file digest manifests.
  Opening a GUI workspace does not establish conversation ownership.
- `src/vigil_cli/client_projects.py` owns stable per-engagement/client/mode project entries,
  atomic new-task selections, and immutable protocol-v1 dispatcher staging. `agent/scripts/native-client/project-binding.mjs`
  attests native task bindings and create-once session receipts; project selection never migrates an existing task.
- `lib/scope.py:ingest_scope_filter` must run on every new file-to-buffer ingest
  path. Arjun and proxy ingestion reuse already-filtered URLs.
- `lib/scope.py:crawl_fence` owns the katana crawl fence (`-fs`/`-cs`/`-cos` from scope.json, matching `host_admitted`)
  that `kali katana` and `web-discovery` apply; scope flags in passthrough args replace it with a warning (ADR 0019).
  See: `agent/scripts/assess/tests/test_crawl_scope_fence.py`.
- `lib/kali.py:prepare_execution_command` owns required headers on every target request: `_apply_required_headers`
  injects them, `_verify_required_headers_in_script` reads scripts and inline programs, and `_require_attribution` refuses
  the rest unless `--no-target-requests REASON` (Kali verbs, `kali job start`, `host-exec`) and no target in argv.
  See: `agent/scripts/assess/tests/test_required_headers_every_request.py`.
- `lib/config.py:input_path` types every file/directory input: `cli.py` runs `resolve_input_path_arguments`, so a relative
  path absent from the cwd resolves under the engagement directory. See: `test_engagement_relative_input_paths.py`.
- `commands/code_dispatch.py:_keepalive` owns `heartbeat --keepalive` (one process per lane, `--claims-file`): each lease
  stops on its own answer, and all stop with the owner (`--owner-pid`), a dispatch no longer in progress, or `--max-lifetime`.
- `state_manager/findings.py:_file_location_is_line_bound` owns whether a `file:` line names one place; in a minified file
  (`LINE_UNBOUND_AVERAGE_LINE_BYTES`) duplicate and sibling matching compares `_IN_FILE_ANCHOR_KEYS` instead.
- `src/vigil_cli/runtime.py:NUCLEI_TEMPLATES_DIR` (`/data/nuclei-templates`, kept across recreates) is where
  `provision_nuclei_templates` downloads templates on a fresh runtime and `kali nuclei --update-templates` refreshes them.
- `agent/.opencode/plugin/assessment-hooks.js:resolveDispatch` binds an OpenCode specialist to its packet-verified dispatch
  (`agent bind-client-handle`); `statusReport` builds `Vigil dispatch status:` (handoff, held leases, next commands).
- `agent/scripts/assess/lib/vocabulary.py:word_folder` mirrors `api/assessment.py:folded_vocabulary` (case and
  `-`/`_`/space ignored) for CLI status and label flags. See: `agent/scripts/assess/tests/test_cli_word_folding.py`.
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

- `agent/operator-core.md`, `agent/operator-core-blue.md` and `agent/agents/*.md` render to untracked wrappers and
  per-client agent trees via `agent/scripts/render-operator-prompts.sh`: `repo` writes red and blue into `agent/` and
  prunes its `GENERATED_PATHS` (`.gitignore` mirrors them); `check` validates sources, determinism and red/blue agreement.
  `vigil install` renders a checkout (`install.py:render_checkout_client_trees`); `vigil_build.py:_render_client_trees`
  renders the release bundle.
- `agent/commands/` owns operator commands. Renderer `COMMAND_NAMES` and explicit client metadata drive `agent/.claude/commands`, `agent/.codex/skills`, and native OpenCode/ZCode command trees. See: ADR 0017.
- `render-operator-prompts.sh` renders native assessment command/role assets under
  `agent/.opencode/assessment` and `agent/.zcode/assessment`; `assessment_clients.py`
  stages their immutable workspace/plugin consumers separately from other workflow assets.
- `agent/scripts/assess/lib/contracts.py` renders engagement binding into every contract's `--notes` view.
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
  Its `TOP_LEVEL_CALLABLE_NAME` is mirrored in `code_analysis_support.py`, as is
  `treesitter_streaming.py:STREAMING_FALLBACK_BASELINE_UNAVAILABLE` (`test_structural_scan_scope_honesty.py`).
- `agent/scripts/assess/lib/code_snapshot.py:_require_source_binding` owns the sealed manifest's `source_path` rule
  (new seals record `source`; an absolute path is accepted only while it names the same `<repo_key>/<digest>/source`);
  `app/code_snapshot.py:_sealed_source_binding_matches` mirrors it for refresh attestation, and `rebind_snapshot_source`
  (`code-snapshot-repair`) rewrites an absolute binding in place, audited. Backend reads resolve the engagement-local copy
  through `code_analysis_support.py:_engagement_local_sealed_paths`. See: `agent/scripts/assess/tests/test_code_snapshot_relocation.py`,
  `orchestrator/backend/tests/test_code_snapshot_relocation_api.py`.
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
- `api/assessment.py:_RUN_CHILD_LISTERS` (13 run-child reads), `_ENGAGEMENT_LIST_ROUTES`
  (12 whole-engagement reads) and `api/intel.py:_INTEL_LIST_ROUTES` (10 intel reads) own the
  registration of those list routes; a new one is a table row, not a decorator. Each table's
  registration POSITION is load-bearing twice over: FastAPI matches in declaration order, so a
  literal path must register ahead of a parameterised sibling (`/finding-groups/{root_slug}`,
  `/blocked-techniques/history`), and it builds the OpenAPI `paths` mapping in registration
  order, so `_RUN_CHILD_LISTERS` registers after its sibling POST handlers to keep each path
  item listing `post` before `get`.
- `api/query_params.py:DeclaredQueryParamsRoute` is the `route_class` of every `api/*.py` router,
  so every mounted GET route, table-registered ones included, refuses an undeclared query key with
  400 naming the unknown and accepted keys. The accepted set is read off the route signature and
  its sub-dependencies by alias; a route that reads `request.query_params` directly must declare
  those keys as parameters, or they are refused. `reject_unknown_query_params` is the same check as
  a per-route dependency (`main.py`'s `/healthz` and `/readyz`).
- `CommandContract.variants` (`ContractVariant`) — an action documented on its command's contract (`code-dispatch done`) must be a variant with a usage line that runs it, or `vigil assess contract <verb> <action>` refuses it. See: `agent/scripts/assess/tests/test_contract_compact_view.py`.
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
- `state_manager/coverage_readiness.py:PER_HOST_OBJECTIVES` is the `coverage_deferral`
  objective vocabulary (`api/assessment_operator.py:CoverageDeferralPayload` derives its literal)
  and has a CLI mirror in `agent/scripts/assess/lib/coverage_checks.py`. Its
  `WAF_MEASUREMENT_VERDICTS` (`provenance.waf` on a tech-component row, checked on write by
  `check_waf_measurement`) is mirrored in `agent/schemas/intel-tech-component.schema.json`;
  its `_TECH_SCAN_SOURCE_TOKENS` is mirrored by `coverage_checks.py:_TECH_FINGERPRINT_SOURCES`,
  which the objective hints list.
  See: `orchestrator/backend/tests/test_recon_objective_records.py`,
  `agent/scripts/assess/tests/test_recon_objective_hints.py`.
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
