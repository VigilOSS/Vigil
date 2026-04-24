# CODE-MAP

This file is the repo's stable structure map.

Use it to answer:
- Where does this concern live?
- Which file owns the contract?
- Which generated files must stay in sync?

Keep it light:
- Track stable boundaries, entrypoints, ownership, and sync relationships.
- Omit caches, vendor trees, generated build output, and field-level trivia.
- If a change makes any statement here false, update this file in the same change.
- Do not churn this file for implementation-only edits that do not move a boundary.

## Root

- `README.md` - operator/install guide. Why: defines the supported runtime model and engagement startup flow.
- `AGENTS.md` - maintainer workflow. Why: local development rules, verification steps, and prompt regeneration requirements live here.
- `pyproject.toml` and `src/ai_threat_hunting_cli/` - universal CLI package. Why: `aith` / `security-research` owns install/update, config, doctor/status, centralized logs, engagement creation/listing/selection, orchestrator lifecycle, Kali runtime lifecycle plus non-interactive `runtime shell-exec`, mitmproxy capture startup, OOB/frp/interactsh control, backup/auth helpers, MCP registration guidance, and `aith assess` pass-through.
- `docker/kali-mcp-runtime/mcp-server-wrapper.sh` - container entry shim. Why: waits for the Kali API and then starts the MCP client.
- `docker/kali-mcp-runtime/patched_kali_server.py` - local patch over the upstream Kali API server. Why: normalizes command execution, timeout, partial-result behavior, and audit-record emission. Extracts `X-Engagement-Key`/`X-Agent-Name`/`X-Phase` audit headers (or env-var defaults), rejects tool calls missing them when `KALI_MCP_AUDIT_REQUIRED=1`, injects per-call `ENGAGEMENT_KEY`/`ENGAGEMENT_DIR` into command subprocesses, and enqueues each run for backend recording.
- `docker/kali-mcp-runtime/kali_mcp_audit.py` - async Kali command-run audit poster. Why: decouples backend `/engagements/{key}/assessment/command-runs` POSTs from the Flask response path with a bounded queue and circuit breaker.
- `docker/kali-mcp-runtime/patched_kali_client.py` - MCP stdio bridge wrapper. Why: re-execs the upstream `client.py` after monkey-patching module-level `requests` helpers, `requests.Session.request`, and FastMCP tool signatures so every local Kali API call carries audit headers sourced from per-call context or the `KALI_MCP_DEFAULT_*` environment variables.
- `docker/callback_listener.py` and `docker/start-callback.sh` - optional callback sink. Why: support OOB and exploit validation outside the main orchestrator path.

## agent/

### Prompt system

- `agent/operator-core.md` - primary operator loop for web/runtime engagements. Why: phase order, dispatch rules, recording rules, and backend-vs-artifact truth boundaries start here.
- `agent/operator-core-code.md` - operator loop for white-box code analysis. Why: same backend and CLI, different phase model.
- `agent/shared-constraints.md` and `agent/shared-constraints-code.md` - first-load specialist constraints. Why: global safety, scope, and output rules live outside individual agent prompts.
- `agent/rules/` - always-active policy overlays. Why: hunting/reporting guardrails that apply across prompts.
- `agent/agents/` - canonical specialist prompt sources. Why: role-specific behavior belongs here, not in generated wrappers.

### Skill and reference library

- `agent/SKILL.md` - routing index from task type to skill file. Why: this is the durable entrypoint into the procedure layer.
- `agent/skills/` - procedure layer. Why: workflow and vuln-family methodology lives here.
- `agent/references/INDEX.md` and `agent/references/` - methodology library. Why: payloads, checklists, tool notes, and code-vuln patterns are loaded on demand from here.
- `agent/references/gf-patterns/` - per-bucket gf-pattern reference files (one `.md` per bucket: `ssrf`, `idor`, `sqli`, `lfi`, `rce`, `xss`, `ssti`, `redirect`, `debug_logic`, `interestingparams`, `interestingsubs`, `interestingEXT`). Why: `agent/skills/gau-triage/SKILL.md` loads them on demand instead of inlining pattern explanations, so classification guidance stays modular as buckets are added or tuned.

### Generated prompt outputs

- `agent/scripts/render-operator-prompts.sh` - prompt renderer. Why: generates the committed operator-facing wrappers from `operator-core.md` plus hardcoded roster templates. `CLAUDE.md` and `AGENTS.md` share one template and are byte-identical outputs.
- `agent/AGENTS.md` and `agent/CLAUDE.md` - generated operator wrappers. Why: committed outputs, not source-of-truth.
- `agent/.codex/config.toml` - Codex project hook config. Why: wires Codex `PreToolUse`/`PostToolUse` events to the shared hook scripts.
- `agent/.codex/agents/` and `agent/.claude/agents/` - generated agent wrappers. Why: thin client-specific entrypoints that should stay derived from the source prompts.

### Runtime and CLI

- `agent/scripts/assess.py` - `aith assess` implementation entrypoint. Why: stable helper surface into the assessment and code-analysis workflows.
- `agent/scripts/assess/cli.py` - subcommand registry. Why: authoritative map of supported operator/backend actions.
- `agent/scripts/assess/commands/` - command families. Why: fetch/post/patch, filtered finding listing plus finding lifecycle helpers (`verify-finding`, `kill-finding`, `update-finding`, `reset-finding`), on-demand export (`export-findings`, `export-surfaces`), helper contract introspection (`contract` for finding lifecycle and record-intel schemas), record-*, dispatch/ingest, exploit/session, report readiness (`check-report-readiness`), Kali MCP command-run audit search (`list-command-runs`, `get-command-run`), signal-first work-buffer triage (`classify-work` applies deterministic gf-style bucketing → `priority_score` / `priority_reason` / `cluster_key`; `list-clusters` groups the buffer by `cluster_key` for operator manifest review; `dispatch fetch-by-priority` and `dispatch defer-cluster` drive priority-first fetch and cluster-level deferral), scope helpers (`check-scope-coverage` with `--require-stage enum|collection|consumption` exit codes, `filter-scope` for URL/host list filtering against `scope.json`), and `code-*` flows are split here. `code-index-sync` bridges tree-sitter structural metadata to backend `code_files` rows.
- `agent/scripts/assess/lib/` - shared plumbing. Why: API client, helper contract metadata, locking, auth, scope parsing/matching, DB helpers, schema validation, sessions, exploit-candidate gate helpers, and tree-sitter indexing live here.
- `agent/schemas/` - JSON payload contracts. Why: durable record formats for findings, intel, chains, credentials, access records, probe runs, proposals, and code-analysis outputs live here; backend-backed schemas are generated from backend request models plus explicit agent-side overlays, while `session-proposal.schema.json` remains local because it has no backend model.
- `agent/scripts/schema.sql` - transient local queue schema. Why: local case/work-item buffering, not orchestrator backend state. `work_items` carries four triage columns (`priority_score`, `priority_reason`, `cluster_key`, `terminal_reason`) plus a `(status, priority_score DESC, cluster_key)` index that power signal-first dispatch; `agent/scripts/assess/lib/db.py` runs `_apply_work_items_priority_migration` on open so existing engagement DBs self-upgrade.
- `agent/scripts/proxy_addon.py` - mitmproxy collector. Why: converts captured traffic into the transient work buffer.
- `src/ai_threat_hunting_cli/engagements.py` - engagement bootstrap. Why: creates run directories, seeds local wrappers, initializes scope/auth/runtime scaffolding, and exposes list/path/start helpers for universal `aith` use.
- `src/ai_threat_hunting_cli/runtime.py` and the runtime subcommands in `src/ai_threat_hunting_cli/main.py` - shared runtime bootstrap and execution. Why: starts and validates the canonical Kali MCP container, including image-ID drift against the configured image tag, and exposes non-interactive `aith runtime shell-exec` for host-initiated runtime commands. Bind-mounts `$INSTALL_ROOT/agent/engagements` at `/engagements` inside Kali (alongside the shared `/data` mount) so skills can reach engagement artifacts at `/engagements/$ENGAGEMENT_KEY/...` without ferrying files across the container boundary.
- `src/ai_threat_hunting_cli/orchestrator.py` - local UI/backend lifecycle. Why: builds the frontend when needed and manages the backend process on `127.0.0.1:18000`.
- `src/ai_threat_hunting_cli/mitmproxy.py` - mitmproxy capture lifecycle. Why: builds/starts/stops the Dockerized browser-capture proxy with an engagement bind mount and persistent CA volume.
- `src/ai_threat_hunting_cli/status.py`, `config.py`, `backup.py`, `auth.py`, and `oob.py` - operator control helpers. Why: these modules own readiness/live-state checks, local CLI config, DB snapshot commands, engagement auth file operations, and shared OOB/frp/interactsh tmux orchestration.
- `agent/docker/runtime-full/Dockerfile` - primary runtime image. Why: supported target-facing tool surface.
- `agent/docker/runtime-lightweight/Dockerfile` - development-only runtime image. Why: faster Dockerfile iteration, not an operator runtime.
- `agent/docker/docker-compose.yml` - local runtime composition. Why: runtime and mitmproxy images can be built together for development.
- `agent/scripts/hooks/scope-check.sh` and `agent/scripts/hooks/post-tool-log.sh` - Claude/Codex host hook scripts. Why: `scope-check.sh` blocks unsafe host-side target traffic before Bash runs, and `post-tool-log.sh` records selected tool activity through `aith assess log` into backend `activity_entries`.
- `agent/engagements/` - engagement artifact root. Why: container for run state; map the directory role, not per-engagement contents.

### Prompt-to-backend coupling

Prompt changes are NOT prompt-only when the prompts define artifacts that the backend stores or the CLI processes. Key coupling points:

- **`guidance_hypotheses`** — defined in architect prompts, stored in `code_analysis_queue.guidance_hypotheses_json` (db.py), normalized by `code_dispatch.py`, validated by `QueueItemRecord` / `RequeueItemRecord` (code_analysis.py API), and hydrated in service fetch/requeue logic. Keep it as `list[str]`: structured requeue trigger context now lives separately in `code_analysis_queue.cross_file_triggers_json`, so changes to either payload shape require backend + CLI + prompt/test updates together.
- **`call-graph.json` / `attack-hypotheses.json`** — filesystem artifacts written by Phase 1, consumed by Phase 2 dispatch context and Phase 3 agents. Removing them breaks operator-core-code.md dispatch instructions and agent pre-work checklists.
- **`file-analysis-queue.json`** — filesystem artifact loaded into backend via `code-dispatch queue`. Schema must match `QueueItemRecord` fields or normalization fails.
- **General rule:** if a prompt instructs an agent to produce structured output that an `aith assess` command consumes, or that the backend stores/serves, the prompt and the consumer are coupled. Check both sides before changing either.
- **Reactive nuclei rule + Phase 1a/1b/1c structure** — `agent/operator-core.md` "Reactive Nuclei on URL Discovery" and the Phase 1 sub-phases (1a wildcard enum, 1b parallel recon+source, 1c reactive nuclei sweep) couple to `agent/skills/nuclei-scanning/SKILL.md` "Reactive Sweep Mode" for mechanics; the operator rule points at the skill rather than duplicating the `nuclei` invocation so both stay in sync. Phase 1/2 exit gates run `aith assess check-scope-coverage --require-stage enum|collection`; dropping the gate call in `operator-core.md` silently disables the phase boundary check. `orchestrator/backend/tests/test_prompt_wording.py` locks both the headers and the gate invocations in place.

### Sync rules worth remembering

- `agent/operator-core.md` -> `agent/AGENTS.md`, `agent/CLAUDE.md`, `agent/.codex/agents/*`, `agent/.claude/agents/*` via `agent/scripts/render-operator-prompts.sh`.
- `orchestrator/backend/app/api/assessment.py` and `orchestrator/backend/app/api/code_analysis.py` -> backend-backed `agent/schemas/*.json` via `orchestrator/backend/scripts/generate_agent_schemas.py`.
- Backend state is canonical for findings, coverage, services, and chains; readable artifacts are produced on demand via `export-findings` and `export-surfaces`.
- `agent/scripts/assess/commands/code_index.py` writes per-file JSON under `tools/analysis-state/structural-index/` and writes `structural-index-manifest.json` beside that directory. `code_index_sync.py` pushes structural metadata (total_functions, total_entry_points, total_sinks, total_exports) from those index files to `code_files` rows in the backend via `POST code/files/bulk-structural-metadata`.
- `agent/scripts/schema.sql` is not the orchestrator schema. It only defines the transient local queue DB.
- Kali MCP audit context threads through five co-dependent files: upstream MCP tool schema changes in `docker/kali-mcp-runtime/patched_kali_client.py`, HTTP header extraction in `docker/kali-mcp-runtime/patched_kali_server.py`, async backend POST behavior in `docker/kali-mcp-runtime/kali_mcp_audit.py`, the Pydantic request model in `orchestrator/backend/app/api/assessment.py`, and the `assessment_command_runs` schema in `orchestrator/backend/app/db.py`. Any change to the audit header set (`X-Engagement-Key`, `X-Agent-Name`, `X-Phase`, `X-Engagement-Artifact-Dir`, `X-Technique`, `X-Intent`, `X-Probe-Kind`, `X-Destructive`) must land in the relevant client/server/API/schema layers.
- `docker/kali-mcp-runtime/audit_enums.py` is the single source of truth for `TECHNIQUE_ENUM` and `PROBE_KIND_ENUM` tuples shared between the patched Kali server, the FastMCP client tool-schema surface, and the `agent/scripts/assess/commands/list_command_runs.py` CLI.

### Easy-to-miss registration points

When adding a new agent that records findings:
- `agent/scripts/assess/lib/findings.py` `_AGENT_PREFIX_MAP` — add the agent name and 2-letter prefix. Without this, `record-finding` exits with "unknown finding prefix for agent."
- `agent/shared-constraints-code.md` prefix table (code agents) or `agent/operator-core.md` prefix table (web agents) — add the prefix so prompts reference it.
- `agent/operator-core-code.md` or `agent/operator-core.md` agent roster and finding prefix tables — add the agent row.

When adding a new agent or changing the agent roster:
- Edit `agent/operator-core.md` (web) or `agent/operator-core-code.md` (code), NOT `agent/AGENTS.md` or `agent/CLAUDE.md`. The latter two are generated outputs — direct edits are overwritten by `render-operator-prompts.sh`.

When adding a new code analysis phase or agent:
- Dispatch context in `operator-core-code.md` must separate backend data (fetched via `aith assess`) from filesystem artifacts (under `tools/analysis-state/`). Agents read filesystem artifacts directly; the operator fetches and summarizes backend state.

When working on scope-coverage gates:
- `check-scope-coverage` reads durable state directly (`GET /services`, `GET /surfaces`, local `work_items`) — there is no per-tool registry or argv-parsing layer. A scope entry "enumerated" when a live service, surface, or work item exists under it; "collected" when a surface or work item exists under it. If a tool should feed the gate, make sure its output lands in services/surfaces/work_items (via `record-surface`, `ingest-endpoints`, etc.). Extend `orchestrator/backend/tests/test_check_scope_coverage.py` for new fixtures.
- `state_manager._derive_tool_bin` still shell-parses command strings for audit/UI filtering (Commands tab), not for coverage. Wrapper-stripping changes there are independent of the scope-coverage gate.

When adding new patchable code-analysis fields or structural metadata totals:
- Update the backend schema in `orchestrator/backend/app/db.py`, the API layer in `orchestrator/backend/app/api/code_analysis.py`, and the service-layer allowlists in `orchestrator/backend/app/services/code_analysis.py` together. `update_code_repo`, `update_code_file`, and `bulk_update_structural_metadata` only persist fields that appear in their hard-coded allowlists/field sets; new columns are now rejected loudly at the PATCH/sync layer until those registration points are updated.
- If the field is populated from tree-sitter output, also update `agent/scripts/assess/commands/code_index_sync.py` and the `CODE-MAP.md` sync note for structural metadata so index artifacts and backend storage stay aligned.

## orchestrator/backend

- `orchestrator/backend/app/main.py` - FastAPI bootstrap. Why: process startup, DB init, engagement sync, router registration, websocket endpoint, health check, and SPA fallback meet here.
- `orchestrator/backend/app/config.py` - runtime settings boundary. Why: centralizes install/data/frontend path assumptions and public URL config.
- `orchestrator/backend/app/db.py` - SQLite persistence boundary. Why: durable schema and low-level data access for engagements, events, assessment state, and code-analysis state. Owns `assessment_command_runs` and its `assessment_command_runs_fts` FTS5 shadow table (plus the three insert/update/delete sync triggers). A `_require_fts5` startup check fails loudly if the bundled SQLite lacks FTS5.
- `orchestrator/backend/app/config/command_run_retention.json` - retention-policy boundary for command-run output. Why: declares `preview_bytes` and `suppress_patterns`; reloadable via the `COMMAND_RUN_RETENTION_CONFIG` env var so ops can tune suppression without a code change.
- `orchestrator/backend/app/api/engagements.py` - engagement/session read and delete API. Why: stable frontend entrypoint for what exists and where it is in the workflow, including exploit approval, assigned-target session state, and explicit typed-confirm engagement deletion.
- `orchestrator/backend/app/api/events.py` - event/timeline API. Why: records operator/agent events and exposes progress summaries.
- `orchestrator/backend/app/api/artifacts.py` - artifact read API. Why: allowlisted artifact exposure instead of arbitrary file serving.
- `orchestrator/backend/app/api/assessment.py` - runtime assessment API. Why: canonical live state interface for recon, surfaces, coverage, readiness (`exploit-candidates`, `coverage-readiness`, `report-readiness`), findings, finding verification/transitions, chains, credentials, blocked techniques, and Kali MCP command-run audit (`/command-runs` list/post and `/command-runs/{id}` detail).
- `orchestrator/backend/app/api/code_analysis.py` - code-analysis API. Why: repo/file/module ingestion, analysis queue, results, threat model, coverage gate, triggers, and bulk structural-metadata sync live here.
- `orchestrator/backend/scripts/generate_agent_schemas.py` - schema bundle generator. Why: derives the committed backend-backed `agent/schemas/*.json` bundle from request models plus the stricter agent-side overlays used by the local CLI validator.
- `orchestrator/backend/app/services/engagements.py` - filesystem-to-DB sync. Why: `agent/engagements/*` starts on disk, but the UI needs queryable state, legacy engagement artifacts need normalization, session assignment state must stay in sync with the DB, and explicit deletes are recorded under `agent/engagements/.deleted-engagements/` so later syncs do not recreate tombstoned engagements from leftover files.
- `orchestrator/backend/app/services/backup.py` - orchestrator DB backup scheduler. Why: writes WAL-coherent rotated snapshots of `orchestrator.sqlite3` independent of per-engagement bootstrap snapshots.
- `orchestrator/backend/app/services/events.py` - event domain logic. Why: timeline projection and summarization stay out of routers.
- `orchestrator/backend/app/services/artifacts.py` - artifact policy layer. Why: file exposure rules stay explicit.
- `orchestrator/backend/app/services/state_manager.py` - assessment domain logic. Why: normalization, dedupe/upsert behavior, exploit/coverage/report readiness projections, finding lifecycle projection, transition ledgering, and summary rollups are business rules, not CRUD.
- `orchestrator/backend/app/services/code_analysis.py` - code-analysis domain logic. Why: queue claiming/completion, needs-context flow, result recording, triggers, structural-metadata batch updates, and coverage rules are workflow logic.
- `orchestrator/backend/app/ws.py` - in-process websocket broadcaster. Why: fans API mutations out to the UI without external messaging infrastructure.
- `orchestrator/backend/tests/` - backend contract tests. Why: pins engagement bootstrap, websocket behavior, prompt rendering, CLI/backend contracts, and code-analysis workflow rules.

## orchestrator/frontend

- `orchestrator/frontend/src/main.tsx` - React entrypoint. Why: single root and global stylesheet load.
- `orchestrator/frontend/src/App.tsx` - top-level shell and hash router. Why: lightweight navigation without a larger routing layer.
- `orchestrator/frontend/src/routes/EngagementsPage.tsx` - engagement index screen. Why: stable fleet-overview page.
- `orchestrator/frontend/src/routes/EngagementPage.tsx` - engagement detail coordinator. Why: owns fetch fan-out, websocket updates, polling fallback, artifact selection, and tab composition.
- `orchestrator/frontend/src/components/TabBar.tsx` - top-level tab contract. Why: defines the durable operator-facing areas: `overview`, `findings`, `coverage`, `code`, `activity`, `artifacts`.
- `orchestrator/frontend/src/components/OverviewTab.tsx` - posture summary view. Why: quick scan of workflow state, findings, chains, and recent activity.
- `orchestrator/frontend/src/components/FindingsTab.tsx` - finding review boundary. Why: triage and proof inspection.
- `orchestrator/frontend/src/components/CoverageTab.tsx` - coverage boundary. Why: tested surface by host/service/technique.
- `orchestrator/frontend/src/components/CodeAnalysisTab.tsx` - code-analysis boundary. Why: separate file-centric review pipeline rendered in the same UI.
- `orchestrator/frontend/src/components/ActivityTab.tsx` and `orchestrator/frontend/src/components/TaskTimeline.tsx` - activity/timeline views. Why: operator progress and session history.
- `orchestrator/frontend/src/components/ArtifactViewer.tsx` - artifact inspection view. Why: read engagement artifacts without leaving the app.
- `orchestrator/frontend/src/components/CommandsTab.tsx` - Kali MCP command-run audit tab. Why: durable operator view onto `assessment_command_runs` with chip filters, tokenized search, and the technique/intent/probe_kind/destructive metadata columns.
- `orchestrator/frontend/src/components/IntelTab.tsx` - pre-attack intel surface. Why: durable operator view onto gathered intel before active findings exist.
- `orchestrator/frontend/src/components/PhaseWaterfall.tsx` - phase visualization. Why: workflow phase is a first-class product concept.
- `orchestrator/frontend/src/lib/api.ts` - shared client/types layer. Why: all REST helpers, websocket URL construction, and frontend-facing API types live here.
- `orchestrator/frontend/src/lib/theme.ts` - theme contract. Why: single source of truth for the `data-theme` attribute on `<html>`, the `aith.theme` localStorage key, and cross-tab sync; all CSS in `app.css` is authored against theme variables overridden at `:root[data-theme="dark"]`.
- `orchestrator/frontend/src/lib/modalScrollLock.ts` - body scroll lock primitive. Why: reference-counted `body.detail-modal-open` class so stacked or rapidly re-opened detail modals never leave the page-behind scrollable.
- `orchestrator/frontend/src/components/JsonView.tsx` - syntax-highlighted JSON viewer. Why: single inline tokenizer + CSS-variable color scheme used by the Intel Raw-record pane and other drawers; switches with the theme.
- `orchestrator/frontend/src/components/ThemeToggle.tsx` - light/dark toggle button. Why: mounted in both page headers; writes through `lib/theme.ts`.
- `orchestrator/frontend/src/components/formatting.tsx` - shared Notes / Provenance / PoC render helpers. Why: consolidates the `NotesBody`, `ProvenanceBlock`, `CopyInline`, `RelTime`, and `CodeBlock` presentational primitives so Intel and Findings drawers render the same shapes.
- `orchestrator/frontend/src/app.css` - global styling system. Why: layout primitives, panel styles, theme variables (light `:root` + dark `:root[data-theme="dark"]`), status colors, severity vocabulary, and responsive rules are centralized here.
- `orchestrator/frontend/vite.config.ts` - frontend/runtime contract. Why: relative base path and local dev proxy/websocket assumptions live here.

## What Not To Map

- `node_modules/`, `dist/`, `__pycache__/`, `.pytest_cache/`, `.playwright-mcp/`, `.cursor/`, `.claude/settings.local.json`, `.jj/`.
- Per-engagement files under `agent/engagements/*`.
- Exact request/response fields, table column inventories, enum spellings, or helper-level internals.
- Individual reference files or individual vuln-family skills unless they become hard dependencies of a core workflow.
- Installed tool inventories inside Dockerfiles.

## Update Triggers

Update this file when a change does any of the following:
- adds, removes, renames, or moves a stable entrypoint;
- changes which file owns a contract or boundary;
- changes a generation or sync relationship;
- adds or removes a durable API/service/tab/CLI command family;
- changes which directory is the canonical home for a concern.

Do not update this file for:
- implementation-only edits inside an unchanged boundary;
- temporary experiments, caches, or local machine state;
- field additions that do not create a new durable boundary.
