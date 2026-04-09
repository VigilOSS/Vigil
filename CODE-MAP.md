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
- `install.sh` - installer/upgrader for `claude` and `codex` installs. Why: copies the source-owned trees into an install root and preserves durable local state across upgrades.
- `orchestrator/start_local.sh` - local UI/backend launcher. Why: builds the frontend and serves the backend on `127.0.0.1:18000`.
- `docker/kali-mcp-runtime/mcp-server-wrapper.sh` - container entry shim. Why: waits for the Kali API and then starts the MCP client.
- `docker/kali-mcp-runtime/patched_kali_server.py` - local patch over the upstream Kali API server. Why: normalizes command execution, timeout, and partial-result behavior.
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

### Generated prompt outputs

- `agent/scripts/render-operator-prompts.sh` - prompt renderer. Why: generates the committed operator-facing wrappers from `operator-core.md` plus hardcoded roster/banner templates.
- `agent/AGENTS.md` and `agent/CLAUDE.md` - generated operator wrappers. Why: committed outputs, not source-of-truth.
- `agent/.codex/agents/` and `agent/.claude/agents/` - generated agent wrappers. Why: thin client-specific entrypoints that should stay derived from the source prompts.

### Runtime and CLI

- `agent/scripts/init_engagement.sh` - engagement bootstrap. Why: creates run directories, seeds local wrappers, and initializes scope/auth/runtime scaffolding.
- `agent/scripts/assess.py` - CLI entrypoint. Why: stable shell surface into the assessment and code-analysis workflows.
- `agent/scripts/assess/cli.py` - subcommand registry. Why: authoritative map of supported operator/backend actions.
- `agent/scripts/assess/commands/` - command families. Why: fetch/post/patch, filtered finding listing plus finding lifecycle helpers (`verify-finding`, `kill-finding`, `update-finding`, `reset-finding`), record-*, dispatch/ingest, exploit/session, and `code-*` flows are split here.
- `agent/scripts/assess/lib/` - shared plumbing. Why: API client, locking, auth, scope, DB helpers, schema validation, sessions, and tree-sitter indexing live here.
- `agent/schemas/` - JSON payload contracts. Why: durable record formats for findings, chains, credentials, access records, probe runs, proposals, and code-analysis outputs.
- `agent/scripts/schema.sql` - transient local queue schema. Why: local case/work-item buffering, not orchestrator backend state.
- `agent/scripts/proxy_addon.py` - mitmproxy collector. Why: converts captured traffic into the transient work buffer.
- `agent/scripts/start_kali_mcp_runtime.sh` - shared runtime bootstrap. Why: starts and validates the canonical Kali MCP container.
- `agent/docker/runtime-full/Dockerfile` - primary runtime image. Why: supported target-facing tool surface.
- `agent/docker/runtime-lightweight/Dockerfile` - lighter local iteration image. Why: non-primary runtime for faster local validation.
- `agent/docker/docker-compose.yml` - local runtime composition. Why: mitmproxy/metasploit/runtime images can be started together from here.
- `agent/scripts/hooks/` - host guardrails. Why: blocks unsafe host-side target traffic and records tool activity.
- `agent/engagements/` - engagement artifact root. Why: container for run state; map the directory role, not per-engagement contents.

### Sync rules worth remembering

- `agent/operator-core.md` -> `agent/AGENTS.md`, `agent/CLAUDE.md`, `agent/.codex/agents/*`, `agent/.claude/agents/*` via `agent/scripts/render-operator-prompts.sh`.
- Backend state is canonical for findings, coverage, services, and chains; readable artifacts are synchronized exports.
- `agent/scripts/schema.sql` is not the orchestrator schema. It only defines the transient local queue DB.

## orchestrator/backend

- `orchestrator/backend/app/main.py` - FastAPI bootstrap. Why: process startup, DB init, engagement sync, router registration, websocket endpoint, health check, and SPA fallback meet here.
- `orchestrator/backend/app/config.py` - runtime settings boundary. Why: centralizes install/data/frontend path assumptions and public URL config.
- `orchestrator/backend/app/db.py` - SQLite persistence boundary. Why: durable schema and low-level data access for engagements, events, assessment state, and code-analysis state.
- `orchestrator/backend/app/api/engagements.py` - engagement/session read API. Why: stable frontend entrypoint for what exists and where it is in the workflow.
- `orchestrator/backend/app/api/events.py` - event/timeline API. Why: records operator/agent events and exposes progress summaries.
- `orchestrator/backend/app/api/artifacts.py` - artifact read API. Why: allowlisted artifact exposure instead of arbitrary file serving.
- `orchestrator/backend/app/api/assessment.py` - runtime assessment API. Why: canonical live state interface for recon, surfaces, coverage, findings, finding verification/transitions, chains, credentials, and blocked techniques.
- `orchestrator/backend/app/api/code_analysis.py` - code-analysis API. Why: repo/file/module ingestion, analysis queue, results, threat model, coverage gate, and triggers live here.
- `orchestrator/backend/app/services/engagements.py` - filesystem-to-DB sync. Why: `agent/engagements/*` starts on disk, but the UI needs queryable state.
- `orchestrator/backend/app/services/events.py` - event domain logic. Why: timeline projection and summarization stay out of routers.
- `orchestrator/backend/app/services/artifacts.py` - artifact policy layer. Why: file exposure rules stay explicit.
- `orchestrator/backend/app/services/state_manager.py` - assessment domain logic. Why: normalization, dedupe/upsert behavior, finding lifecycle projection, transition ledgering, and summary rollups are business rules, not CRUD.
- `orchestrator/backend/app/services/code_analysis.py` - code-analysis domain logic. Why: queue claiming/completion, needs-context flow, result recording, triggers, and coverage rules are workflow logic.
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
- `orchestrator/frontend/src/components/PhaseWaterfall.tsx` - phase visualization. Why: workflow phase is a first-class product concept.
- `orchestrator/frontend/src/lib/api.ts` - shared client/types layer. Why: all REST helpers, websocket URL construction, and frontend-facing API types live here.
- `orchestrator/frontend/src/app.css` - global styling system. Why: layout primitives, panel styles, status colors, severity vocabulary, and responsive rules are centralized here.
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
