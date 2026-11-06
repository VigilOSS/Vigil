# Subsystem boundaries

What each subsystem owns, and the boundaries that are not evident from a file listing.
Read this when working inside one of these trees. For cross-cutting invariants — a contract
with two owners, a mirror that must be pinned, a registration that is easy to miss — read
[CODE-MAP.md](../CODE-MAP.md) instead.

## Boundaries worth knowing

### agent/ — prompts and the assessment CLI

- `agent/scripts/assess/cli.py` — the authoritative subcommand registry for `vigil assess`, including the `kali` subgroup that owns all target-facing tool execution.
- `agent/scripts/assess/lib/scope.py` — scope parsing, matching, and locked atomic mutation. Deliberately no destination filtering (`enforce_execution_policy` never refuses by host); scope is the operator's job.
- `agent/scripts/assess/lib/config.py` — fail-closed engagement selection for `vigil assess`: `--engagement-dir`, else a CWD-discovered root, else the `vigil engagement start` session variable.
- `agent/scripts/assess/lib/trusted_exec.py:TargetGit` — every Git call over ingested source, under
  Vigil-written config. See: ADR 0040. `commands/code_history.py` and `lib/code_history.py`
  bind `code-history` reads to the snapshot's recorded HEAD (ADR 0041); `lib/security_history.py` owns the
  security-commit vocabulary ingest shares.
- `agent/scripts/assess/lib/code_snapshot.py` — race-checked, content-addressed source copies.
  `orchestrator/backend/app/code_snapshot.py` independently attests them; v3 uses decoded logical lines,
  historical v2 keeps its semantics. See: ADR 0026.
- `agent/scripts/assess/lib/parser_boundary.py` + `parser_worker.py` — the structural-parser process boundary. Every typed failure is an explicit all-byte fallback declaring unavailable dimensions. See: ADR 0029.
  `ParserWorkerPool` leases warm fork servers that fork one limited child per file; `code-index build --jobs` sizes it;
  every count publishes identical bytes. See: `test_code_index_parallel_build.py`.
- `agent/scripts/assess/commands/export_submission.py` and `export_reply.py` assemble and present;
  neither rewrites authored content or masks credentials. Rendering helpers live in
  `agent/scripts/assess/lib/finding_render.py`.
  Submission owns exact `--body`/`--guidance` capture and `--prepare`; GHSA fields are owned by backend `finding_details.py`.
- `agent/scripts/assess/commands/operator_checkpoint.py` — `vigil assess operator-checkpoint`, the operator's own durable state: references plus one intent note, each existence-checked in the write transaction.
- `agent/scripts/assess/commands/resume_brief.py` — a read that names the reconciling verb for abandoned runs, jobs and host children; only `vigil assess kali sweep-orphans` writes.
- `agent/scripts/hooks/` — shared host hooks for activity logging, compaction, post-compaction
  operator rehydration, and session end. Command filtering is deliberately absent (ADR 0019).
  `goose-hook-adapter.sh` adapts Goose tool names.

### src/vigil_cli/ — the universal CLI

- `src/vigil_cli/application.py` — explicit/imported release resolution, bundle validation and persistent content-addressed assets/helper CLI. Never discover source from workspace or CWD.
- `src/vigil_cli/workspace.py` — canonical private paths and in-place legacy adoption; `paths.py:workspace_root_for_engagement` resolves private ownership independently of application assets.
- `vigil_build.py` — tracked publisher inputs, matched CLI/backend/agent/docs/legal bundle and locked prebuilt UI provenance; its sdist builds wheels without Git or Node.
- `src/vigil_cli/process_identity.py` owns birth-identity checks shared by client sessions and backend process receipts;
  `orchestrator.py` uses those receipts for status/stop, preflight and restore ownership decisions.
- `src/vigil_cli/client_sessions.py` — live PID/birth-identity bindings, historical starts and bootstrap lock. Shared-config starts reuse the live release without repair; native projects stay independent. Explicit maintenance guards upgrades; historical opens never prove ownership.
- `src/vigil_cli/paths.py:resolve_orchestrator_base_url` — backend URL precedence and dotenv normalization; `vigil config resolve orchestrator_base_url` exposes it to generated launchers at session start.
- `src/vigil_cli/preflight.py` owns launch checks shared with blue; managed-local backend recovery never replaces a configured remote endpoint. Static code startup does not query Docker.
- `src/vigil_cli/remediation.py` — case intake/context rendering, configured workspace/checks, reviewed PR publication, and consented development workflow commands; `remediation_browser.py` owns local browser execution. Backend APIs own case state.
  The canonical engagement wizard creates remediation projects.
  External-reference joins resolve to numeric case identity; identity/finalization/publication share a case lock.
  Branch finalization retains retry intent across local VCS and backend registration.
- `src/vigil_cli/remediation_regression.py` — paired red/green receipts; `agent/scripts/assess/lib/remediation_regression.py` owns disposable sources; backend `services/remediation_regression.py` validates provenance.
- `src/vigil_cli/remediation_sessions.py` owns role routing and Claude native binding/attachment; launch receipts correlate job names with host UUIDs, and `start --session-id` recovers without redispatch.
  `join --fresh` replaces the case conversation under its session lock, preserving binding history and requiring consent before stopping a running worker.
- `src/vigil_cli/remediation_clients.py` owns OpenCode repository launch and ZCode's context-bound plugin preparation/workspace opening, without native conversation receipts. `agent/.zcode/hooks/` restores defensive case context.
- `agent/scripts/assess/lib/remediation_project.py` and `remediation_vcs.py` — shared PROJECT.md parsing and Git/JJ identity, workspace, diff, and push contracts; CLI import bridges are `project_config.py` and `remediation_vcs.py`.
  `remediation_vcs.py:tree_id` owns complete code-tree identity; backend evidence records it at intake.
  New configured workspaces use stable numeric case directories. Check stages select early execution; all captured checks remain approval requirements. Branch finalization validates unpublished same-revision rename and retry state.
  Local verification can carry across identical trees; approvals and served-runtime proof retain revision identity.
- `src/vigil_cli/runtime.py` + `up.py` — one shared long-lived Kali container, reached host-side by `docker exec`. There is no in-container API server or MCP bridge.
  Resource-capacity preflight is advisory.
  `up.py:run_up` owns startup JSON/service states; `service_locks.py` serializes shared starts. `agent/scripts/assess/lib/kali_runtime_exec.py` owns first-use managed execution startup.
- `src/vigil_cli/oob_relay.py` owns the install's OOB relay-slot identity; `oob.py`, `install.py`, `up.py` and `status.py` consume it.
- `src/vigil_cli/term.py` owns terminal-only Rich rendering and fuzzy selection; callers keep plain/JSON output contracts.

### orchestrator/backend

- `orchestrator/backend/app/api/assessment.py` — live-state routes for recon, coverage, findings,
  command runs, and bulk ingestion; finding history supports summary and lossless transition reads.
  Coverage ledger reads (`coverage-items/page|facets|reasons|{id}[/position]`) come from `state_manager/coverage.py`.
  Operator pages `command-runs/page|facets|{id}/position` (`command_run_queries.py`) and `request-variants/page|facets|{id}`
  `[/position|/observations]` (`coverage.py`); bare lists stay the CLI contract. `findings?view=summary` omits `details`/`notes`; `PATCH oob-probes/{nonce}` audits a verdict; `oob.py:oob_verdict_entry` defines one.
  `assessment_operator.py` owns dispatch/handoff/decision/checkpoint routes; `submissions.py` owns immutable submission/sent-reply APIs.
  `state_manager/dispatches.py` owns atomic packet registration/replay and `HANDOFF_SUMMARY_MAX_CHARS`;
  `commands/agent.py` materializes packets and short web/code/proof launch receipts.
  `contract_registry.py` mirrors limits; `dispatch/handoff_renderer.py` bounds excerpts, not storage,
  and reads `dispatches/{id}/prompt-packet` for the authorized phase and lane basis it reports.
- `orchestrator/backend/app/api/intel.py` — per-engagement intel reads and writes. `/resolve` maps
  untyped finding intel ids through the canonical search index without guessing across entity tables,
  distinguishing resolved, missing, unsupported, dangling and ambiguous ids.
- `orchestrator/backend/app/api/code_analysis.py` — the only repo/file ingest write, lease-owned queue
  work, generation-bound compare-and-swap, and paginated queue reads. Its `item_ids` page and
  `code-dispatch fetch --ids-file` share ordering and current-generation filtering.
  `state_manager/links.py` validates explicit variant-child ancestry; historical ambiguous links remain recorded.
  `code_analysis.py` derives variant currency and stale-parent diagnostics from receipts.
  The Code view reads `analysis-results/page` (`scope=current|awaiting_verdict`) and `{id}[/position]` (`analysis-results`
  is the CLI listing), `analysis-queue?current_only=` lanes (stats SQL), `repos/review-progress`, readiness `track_enabled`.
- `state_manager/proof_work.py` owns current proof preparation, atomic dispatch claims, live approval independent of bindings, derived `queue_state`/`reverification_required`, and explicit release after execution ends.
  `api/assessment_proof_work.py` and `commands/proof_work.py` expose it; finding status and its `next_test` still own proof owed.
  `_early_proof_eligible` admits initial unreviewed work without changing the parked obligation roster or reviving invalidated verification.
  `orchestrator/backend/app/services/scope_admission.py` bridges to the canonical agent scope matcher.
- `state_manager/finding_next_tests.py` owns runtime proof plans, written with the parking transition,
  and `owes_runtime_proof`/`runtime_proof_owed_sql` (parked, not merged). Proof work binds the current park.
  `contract_registry.py:NEXT_TEST_FIELDS`/`NEXT_TEST_ROUTE_HINTS`, `agent/scripts/assess/lib/next_test.py` bounds and `finding_next_tests.py:NEXT_TEST_FIELDS`
  mirror `api/assessment.py:FindingNextTestRequest`. See: `orchestrator/backend/tests/test_finding_next_test_contract_mirror.py`.
- `orchestrator/backend/app/services/state_manager/` — the live-state package; `__init__.py` re-exports it so
  public `state_manager.<fn>` paths stay stable.
- `state_manager/coverage_readiness.py` owns readiness and per-host verdicts; `finding_snapshots.py` owns finding snapshot/author provenance.
- `state_manager/command_runs.py` owns run writes and output integrity; `command_run_queries.py`, `assessment_jobs.py`, and `host_liveness.py` own their reads and ledgers.
- `orchestrator/backend/app/services/submission_versions.py` — CLI/UI submission snapshots; neither changes submission status nor submits externally. See ADR 0025.
  `_ELIGIBLE_ATTACHMENT_SQL` owns what the attachment picker offers (never internal submission-workspace files);
  `publication_readiness` and `attachment_page` back the read-only readiness and attachment routes in `api/submissions.py`.
  `_packet_review_issue` checks package freshness for blind triage and Pass 1 QA;
  `_pass1_qa_state` projects selection-specific QA. `state_manager/dispatches.py:record_decision` validates auditor attribution.
  Body, guidance, and platform fields bind review identity; `app/db.py:_migrate_submission_platform` expands the GHSA constraint after backup.
- `orchestrator/backend/app/services/activity_feed.py` owns the merged Activity feed (`GET /activity`, `api/activity.py`):
  categories, mirrored-event exclusion, cursors, cached summary-text search, and entity `ref`/`unlinked_reason`.
- `orchestrator/backend/app/services/artifacts.py:ARTIFACT_SPECS` owns the engagement Files roster: listed root documents only, read with a byte bound.
- `orchestrator/backend/app/services/assessment_memory.py` and `artifact_index.py` own the bounded
  resume brief and artifact index; output points to drill-down commands instead of embedding data.
  `artifact_index.py:_store_artifact` records finding-linked digest changes atomically in `activity.py`;
  registration and refresh expose change receipts to `agent/scripts/assess/commands/artifact.py`.
- `orchestrator/backend/app/reply_render.py` — the versioned exact-bytes outbound renderer; `agent/scripts/assess/lib/reply_render.py` is an import-only bridge, so previews and backend share one format.
- `state_manager/run_accounting.py` owns run identity and lifecycle; `run_inventory.py`
  sources, obligations and the producer's source release; `run_evidence.py` linked receipts; `run_comparisons.py`
  comparisons; `proofs.py` immutable evidence receipts and the operator-authority waiver (ADR 0043). See: ADR 0028.
- `orchestrator/backend/app/services/engagements.py` — filesystem-to-DB sync; explicit deletes are tombstoned so leftover files cannot resurrect them.
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
- `orchestrator/frontend/src/components/FindingRecordHeader.tsx` shares finding identity/status axes and per-finding section navigation across review and disclosure queues.
- `orchestrator/frontend/src/components/ProofWorkTab.tsx` consumes durable proof work; UI actions never launch agents or verify findings.
