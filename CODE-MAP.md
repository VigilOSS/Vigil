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
- `pyproject.toml` and `src/ai_threat_hunting_cli/` - universal CLI package. Why: `aith` / `security-research` owns install/update, config, doctor/status, centralized logs, engagement creation/listing/selection (including Android APK artifact-only scope creation), all-up local stack startup via `aith up`, orchestrator lifecycle, Kali runtime lifecycle (including resource-tier env vars and the `aith runtime resources` introspection subcommand), non-interactive `runtime shell-exec`, mitmproxy capture startup, OOB/frp/interactsh control, backup/auth helpers, and `aith assess` pass-through. The Wave 1 cutover (2026-04-26) replaced Kali MCP with `aith assess kali` host-side subcommands; `aith mcp install/status/remove/repair` is a deprecation stub that exits 2 with a pointer at the new vocabulary.
- `docker/callback_listener.py` and `docker/start-callback.sh` - optional callback sink. Why: support OOB and exploit validation outside the main orchestrator path.

## agent/

### Prompt system

- `agent/operator-core.md` - primary operator loop for web/runtime engagements. Why: phase order, dispatch rules, recording rules, and backend-vs-artifact truth boundaries start here.
- `agent/operator-core-code.md` - operator loop for white-box code analysis. Why: same backend and CLI, different phase model.
- `agent/shared-constraints.md` and `agent/shared-constraints-code.md` - first-load specialist constraints. Why: global safety, scope, and output rules live outside individual agent prompts.
- `agent/rules/` - always-active policy overlays. Why: hunting/reporting guardrails that apply across prompts.
- `agent/agents/` - canonical specialist prompt sources. Why: role-specific behavior belongs here, not in generated wrappers.

### Skill and reference library

- `agent/SKILL.md` - **deprecated** roster of the procedure layer; superseded by `aith assess list-skills`. Why: keep the file as a soft pointer for older operators, but discovery should walk `agent/skills/*/SKILL.md` frontmatter directly so a new skill is visible the moment its directory exists, with no roster edit required.
- `agent/skills/` - procedure layer. Why: workflow and vuln-family methodology lives here. `agent/skills/kali-exec/SKILL.md` is the discovery anchor for the `aith assess kali` CLI surface; per-verb references live under `agent/references/tools/`.
- `agent/references/INDEX.md` and `agent/references/` - methodology library. Why: payloads, checklists, tool notes, and code-vuln patterns are loaded on demand from here.
- `agent/references/gf-patterns/` - per-bucket gf-pattern reference files (one `.md` per bucket: `ssrf`, `idor`, `sqli`, `lfi`, `rce`, `xss`, `ssti`, `redirect`, `debug_logic`, `cors`, `upload_fields`, `trust_surface`, `img_traversal`, `interestingparams`, `interestingsubs`, `interestingEXT`). Why: `agent/skills/gau-triage/SKILL.md` and the inline classifier load these on demand instead of inlining pattern explanations, so classification guidance stays modular as buckets are added or tuned.
- `agent/references/gf-patterns/DRIFT.md` - static accept/skip rationale for GF categories that do not map directly to Python buckets. Why: upstream GF buckets rarely change; keeping the curated rationale beside the bucket references is simpler than maintaining a sync script and vendored JSON cache.

### Generated prompt outputs

- `agent/scripts/render-operator-prompts.sh` - prompt renderer. Why: generates the committed operator-facing wrappers from `operator-core.md` plus hardcoded roster templates. `agent/AGENTS.md` is the canonical rendered operator prompt; `agent/CLAUDE.md` is intentionally a one-line pointer to `AGENTS.md` so Claude Code does not load the same operator instructions twice (~7k tokens of duplication eliminated).
- `agent/AGENTS.md` - generated canonical operator wrapper. Why: committed output, not a source-of-truth.
- `agent/CLAUDE.md` - thin pointer to `AGENTS.md`. Why: token deduplication for Claude Code, which auto-loads both files when present.
- `.cursor/rules/operator.md` - Cursor-specific rule that prevents `CLAUDE.md` from being loaded alongside `AGENTS.md`. Why: same deduplication concern, scoped to the Cursor IDE.
- `agent/.codex/config.toml` - Codex project hook config. Why: wires Codex `PreToolUse`/`PostToolUse` events to the shared hook scripts.
- `agent/.codex/agents/` and `agent/.claude/agents/` - generated agent definitions. Why: client-specific committed outputs embed canonical specialist prompt bodies from `agent/agents/*.md`; edit source prompts and rerender instead of editing these directly.

### Runtime and CLI

- `agent/scripts/assess.py` - `aith assess` implementation entrypoint. Why: stable helper surface into the assessment and code-analysis workflows.
- `agent/scripts/assess/cli.py` - subcommand registry. Why: authoritative map of supported operator/backend actions, including the `kali` subgroup that owns target-facing tool execution post-Wave-1 and `list-skills` for skill discovery from `agent/skills/*/SKILL.md` frontmatter.
- `agent/scripts/assess/commands/` - command families. Why: fetch/post/patch (with `fetch --jq <expr>` pipe-through), filtered finding listing plus finding lifecycle helpers (`verify-finding`, `kill-finding`, `update-finding`, `reset-finding`, `link-finding`, `list-finding-group`, `list-report-findings`), surface lifecycle (`record-surface`, `resolve-surface` for by-id PATCH), intel lifecycle (`record-intel`, `update-intel`, `supersede-intel`), on-demand export (`export-findings`, `export-surfaces`), helper contract introspection (`contract` for finding lifecycle, record-intel schemas, and the `kali` namespace), record-*, dispatch/ingest (`dispatch peek <type> N` previews without claiming, `dispatch defer-items <ids>` defers per-id, `dispatch stats --by source|cluster|host` slices the buffer), exploit/session, report readiness (`check-report-readiness`), command-run audit search (`list-command-runs`, `get-command-run`), cache-aware gau pipeline wrappers (`gau-endpoints`, `gau-secrets`, `gau-js-endpoints` — share a corpus per `(target, gau-flag-set)` tuple under `<engagement>/scans/gau-pipeline/<target_slug>/<cache_key_slug>/gau_output.txt` plus sidecar meta, so a single gau call serves the three downstream consumers but two targets — or the same target run with different `--subs`/`--providers` — never share `bodies/` or trufflehog input; `gau-secrets` defaults trufflehog to `--no-verification` so credentials are never auto-validated against third-party services; `gau-js-endpoints` extracts routes hidden in minified JS bundles via the LinkFinder-derived regex in `lib/gau_pipeline.py`, host-filters extractions to the exact target or its real subdomains so attacker-controlled CDN refs cannot be injected into the work buffer, and ingests them with `source='js-extract'`), signal-first work-buffer triage (`classify-work` re-applies deterministic gf-style bucketing → `priority_score` / `priority_reason` / `cluster_key`; default predicate is narrow — only rows still at the schema-default classification get touched, so a routine refresh cannot silently overwrite manual operator triage. `--reclassify-all` is the explicit opt-in for re-applying after a `_BUCKETS` change in `classify_buckets.py`. Inline classification at ingest is the primary write path; this command exists for re-application and pre-refactor DB repair only; `list-clusters` groups the buffer by `cluster_key` for operator manifest review with `--host <hostname>` post-filter; `dispatch fetch-by-priority` and `dispatch defer-cluster` drive priority-first fetch and cluster-level deferral; priority fetch keeps plain `unknown` unrouted but sends positive `gf:*` unknown rows to `vulnerability-analyst` so path-only trust-surface buckets do not strand high-signal work), scope helpers (`check-scope-coverage` with `--require-stage enum|collection|consumption` exit codes, `filter-scope` for URL/host list filtering against `scope.json`), `code-*` flows including `code-size-summary` for backend-backed code file counts/LOC buckets/classification summaries, and the **`kali_*` subcommands** (`kali_nmap`, `kali_nuclei`, `kali_httpx`, `kali_wafw00f`, `kali_ffuf`, `kali_sqlmap`, `kali_subfinder`, `kali_puredns`, `kali_dnsx`, `kali_nikto`, `kali_katana`, `kali_gau`, `kali_whatweb`, `kali_cero`, `kali_alterx`, `kali_asnmap`, `kali_bbot` — 17 typed verbs — plus `kali_exec` for raw passthrough and `kali_job` for SQLite-backed async lifecycle; every typed verb requires `--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout` flags). `code-index-sync` bridges tree-sitter structural metadata to backend `code_files` rows.
- `agent/scripts/assess/lib/` - shared plumbing. Why: API client (`client.py`), helper contract metadata (`contracts.py` — owns the `kali` root + per-verb contracts, the split `KALI_TARGET_VERBS`/`KALI_MAINT_VERBS` rosters (`KALI_VERBS` is the union for registration), full per-sub-verb contracts for every state-mutating dispatch verb (`register`, `update-status`, `record-handoff`, `record-decision`, `abort-duplicate`, `render-handoff`) so the Contract-First Rule's verb list and `aith assess contract dispatch <verb>` actually agree, and `validate_specialist_dispatch_contract` which requires `skills` for non-operator roles; the same enforcement is mirrored in `orchestrator/backend/app/api/assessment.py::DispatchCreate._enforce_skills_for_specialists` so both the CLI validator and the HTTP API reject specialist dispatches that omit `skills`), locking, auth, scope parsing/matching, DB helpers (`db.py` — owns the `kali_jobs` local-queue migration, the `work_items_per_host` view DDL via `_apply_work_items_per_host_view` (canonical for both fresh and legacy DBs; `schema.sql` deliberately does NOT define this view), and the inline call into `classify_buckets.classify_row()` so `db_insert_work_item()` populates `priority_score`/`priority_reason`/`cluster_key`/`terminal_reason` at ingest time; re-exports `INERT_TYPES` as `_SKIP_TYPES` so the inline insert path skips inert rows from the same set the bucket classifier uses), `classify_buckets.py` (single source of truth for the gf-style URL `_BUCKETS` table AND the public `INERT_TYPES` frozenset; used by both inline classification at ingest and `aith assess classify-work` re-application; also owns narrow cluster-selection tie-breakers such as upload rows preferring `upload_fields` over generic LFI/IDOR overlap), `gau_pipeline.py` (single source for the cache-decision rules, sidecar `gau_output.meta.json` read/write, the corpus-flag fingerprint `gau_cache_key()` plus its `slug_target()`/`slug_cache_key()` siblings that namespace artifacts as `scans/gau-pipeline/<target>/<key>/`, the LinkFinder-derived JS endpoint regex, and shared argparse flags consumed by the three `gau-*` wrapper verbs — keeping the cache logic, on-disk layout, and reuse semantics in one place ensures `gau-endpoints`, `gau-secrets`, and `gau-js-endpoints` cannot drift), schema validation, sessions, exploit-candidate gate helpers, tree-sitter indexing, **`audit_enums.py`** (single source of truth for `TECHNIQUE_ENUM` / `PROBE_KIND_ENUM`; consumed by `kali.py`, `list_command_runs.py`, and copied into the runtime image at `/opt/mcp-tools/audit_enums.py`), and the **`kali` family** (the docker-exec helper with `start_new_session=True` + `os.killpg` cleanup, two-namespace kill cascade with exact in-container pid-file targeting, line-1 stdout/stderr streaming, pre-exec `status=running` POST + post-exec PATCH-finalize, dedup-window check at write time, and the dtach-supervised job worker). Split for blast-radius minimization across:
  - **`kali.py`** — high-level orchestration (`kali_exec`, the `Popen` + kill-cascade flow). Also re-exports the public surface and the private helpers tests patch via `monkeypatch.setattr(kali, ...)`.
  - **`kali_audit.py`** — pre-exec `command-runs` POST, finalize PATCH, failed-audit marker, input validation, agent-name + engagement-dir resolution.
  - **`kali_runtime_exec.py`** — `_build_docker_exec` wrapper-shell construction, `_check_container_running`, `_read_container_pid` / `_kill_in_container` / `_cleanup_container_pid_file` (the exact-PID two-namespace kill cascade primitives).
  - **`kali_output.py`** — `_read_safely` head+tail preview, `_read_proc_peak_rss`, `_scope_version`, `_auth_context`, `_utcnow_iso`, and the `KaliResult` dataclass.
  - **`kali_tool_naming.py`** — `_derive_tool_name`, `_analyze_tool_name`, and the shell-pipeline parsing helpers (pure functions; no I/O).
  - **`kali_cli.py`** — argparse scaffolding (`add_required_kali_flags`, `add_passthrough_args_flag`, `extend_cmd_with_extra_args`, `kali_args_to_kwargs`, `emit_result`) shared by every `kali_<verb>` command file.
  - **`kali_jobs.py`** — async-job lifecycle helpers (`start_job`, `job_status`, `job_tail`, `job_stop`, `job_list`) for the dtach-supervised SQLite-backed job worker.
- `agent/schemas/` - JSON payload contracts. Why: durable record formats for findings, intel, chains, credentials, access records, probe runs, proposals, and code-analysis outputs live here; backend-backed schemas are generated from backend request models plus explicit agent-side overlays, while `session-proposal.schema.json` remains local because it has no backend model.
- `agent/scripts/schema.sql` - transient local queue schema. Why: local case/work-item buffering, not orchestrator backend state. `work_items` carries four triage columns (`priority_score`, `priority_reason`, `cluster_key`, `terminal_reason`) plus a `(status, priority_score DESC, cluster_key)` index that power signal-first dispatch; `agent/scripts/assess/lib/db.py` runs `_apply_work_items_priority_migration` on open so existing engagement DBs self-upgrade. The file deliberately defines tables/indexes only — the `work_items_per_host` view is owned by `db.py:_apply_work_items_per_host_view` so legacy and fresh DBs end up with the same DDL (no two-place drift). Fresh engagements get the view because `src/ai_threat_hunting_cli/engagements.py:_init_cases_db` calls `db_init()` rather than running `executescript(schema.sql)` directly.
- `agent/scripts/proxy_addon.py` - mitmproxy collector. Why: converts captured traffic into the transient work buffer through the shared `db_init()` / `db_insert_work_item()` path, so browser-captured rows receive the same schema migrations and inline classification as `ingest-endpoints` and `ingest-spec`.
- `src/ai_threat_hunting_cli/engagements.py` - engagement bootstrap. Why: creates run directories, seeds local wrappers, initializes scope/auth/runtime scaffolding, including Android `scope_mode: artifact-only` engagements with APK/AAB/XAPK artifacts kept out of `hosts`, and exposes list/path/start helpers for universal `aith` use. `_init_cases_db` delegates to `agent/scripts/assess/lib/db.py:db_init` (rather than running `executescript(schema.sql)` directly) so a fresh engagement DB ends up with the same schema, priority-column migration, AND `work_items_per_host` view as one created via the assess CLI — the DB-init path is the single seam that owns "what a cases.db looks like."
- `src/ai_threat_hunting_cli/runtime.py`, `src/ai_threat_hunting_cli/up.py`, and the runtime subcommands in `src/ai_threat_hunting_cli/main.py` - shared runtime bootstrap and execution. Why: starts and validates the canonical Kali container with explicit Docker resource flags (`--memory`, `--cpus`, `--pids-limit`, `--shm-size`, `--ulimit nofile/nproc`, `--oom-score-adj=-500`) sourced from `AITH_RUNTIME_*` env vars (`MEMORY_GB`, `CPUS`, `PIDS_LIMIT`, `SHM_SIZE`); compares image-ID drift against the configured image tag; exposes `aith runtime shell-exec` (host-initiated runtime commands) and `aith runtime resources` (prints configured tier + live cgroup state); coordinates all-up local stack startup (`runtime`, stale Docker image builds, mitmproxy, OOB, and orchestrator) without restarting existing OOB tmux sessions. Bind-mounts `$INSTALL_ROOT/agent/engagements` at `/engagements` inside Kali (alongside the shared `/data` mount) so skills can reach engagement artifacts at `/engagements/$ENGAGEMENT_KEY/...` without ferrying files across the container boundary. The Kali container is reached host-side via `docker exec` from `agent/scripts/assess/lib/kali.py` — there is no longer an in-container HTTP API server or MCP stdio bridge.
- `src/ai_threat_hunting_cli/orchestrator.py` - local UI/backend lifecycle. Why: builds the frontend when needed and manages the backend process on `127.0.0.1:18000`.
- `src/ai_threat_hunting_cli/mitmproxy.py` - mitmproxy capture lifecycle. Why: builds/starts/stops the Dockerized browser-capture proxy with an engagement bind mount and persistent CA volume.
- `src/ai_threat_hunting_cli/status.py`, `config.py`, `backup.py`, `auth.py`, and `oob.py` - operator control helpers. Why: these modules own readiness/live-state checks, local CLI config, DB snapshot commands, engagement auth file operations, and shared OOB/frp/interactsh tmux orchestration.
- `agent/docker/runtime-full/Dockerfile` - primary runtime image. Why: supported target-facing tool surface, including Android APK acquisition/decompile/signing/device utilities for mobile artifact engagements.
- `agent/docker/runtime-lightweight/Dockerfile` - development-only runtime image. Why: faster Dockerfile iteration, not an operator runtime.
- `agent/docker/docker-compose.yml` - local runtime composition. Why: runtime and mitmproxy images can be built together for development.
- `agent/scripts/hooks/scope-check.sh` and `agent/scripts/hooks/post-tool-log.sh` - Claude/Codex host hook scripts. Why: `scope-check.sh` blocks obviously destructive host commands before Bash runs, and `post-tool-log.sh` records selected tool activity through `aith assess log` into backend `activity_entries`.
- `agent/engagements/` - engagement artifact root. Why: container for run state; map the directory role, not per-engagement contents.

### Prompt-to-backend coupling

Prompt changes are NOT prompt-only when the prompts define artifacts that the backend stores or the CLI processes. Key coupling points:

- **`guidance_hypotheses`** — defined in architect prompts, stored in `code_analysis_queue.guidance_hypotheses_json` (db.py), normalized by `code_dispatch.py`, validated by `QueueItemRecord` / `RequeueItemRecord` (code_analysis.py API), and hydrated in service fetch/requeue logic. Keep it as `list[str]`: structured requeue trigger context now lives separately in `code_analysis_queue.cross_file_triggers_json`, so changes to either payload shape require backend + CLI updates together, plus prompt diff review.
- **`call-graph.json` / `attack-hypotheses.json`** — filesystem artifacts written by Phase 1, consumed by Phase 2 dispatch context and Phase 3 agents. Removing them breaks operator-core-code.md dispatch instructions and agent pre-work checklists.
- **`file-analysis-queue.json`** — filesystem artifact loaded into backend via `code-dispatch queue`. Schema must match `QueueItemRecord` fields or normalization fails.
- **General rule:** if a prompt instructs an agent to produce structured output that an `aith assess` command consumes, or that the backend stores/serves, the prompt and the consumer are coupled. Check both sides before changing either.
- **Reactive nuclei rule + Phase 1a/1b/1c structure** — `agent/operator-core.md` "Reactive Nuclei on URL Discovery" and the Phase 1 sub-phases (1a wildcard enum, 1b parallel recon+source, 1c reactive nuclei sweep) couple to `agent/skills/nuclei-scanning/SKILL.md` "Reactive Sweep Mode" for mechanics; the operator rule points at the skill rather than duplicating the `nuclei` invocation so both stay in sync. Phase 1/2 exit gates run `aith assess check-scope-coverage --require-stage enum|collection`; dropping the gate call in `operator-core.md` silently disables the phase boundary check. Prompt and doc wording are reviewed through markdown diffs rather than repository tests; executable CLI/API contracts should be covered by their owning backend tests.

### Sync rules worth remembering

- `agent/operator-core.md` -> `agent/AGENTS.md`, `agent/CLAUDE.md` via `agent/scripts/render-operator-prompts.sh`; `agent/agents/*.md` -> `agent/.codex/agents/*`, `agent/.claude/agents/*` through the same renderer.
- `orchestrator/backend/app/api/assessment.py` and `orchestrator/backend/app/api/code_analysis.py` -> backend-backed `agent/schemas/*.json` via `orchestrator/backend/scripts/generate_agent_schemas.py`.
- Backend state is canonical for findings, coverage, services, and chains; readable artifacts are produced on demand via `export-findings` and `export-surfaces`.
- `agent/scripts/assess/commands/code_index.py` writes per-file JSON under `tools/analysis-state/structural-index/` and writes `structural-index-manifest.json` beside that directory. `code_index_sync.py` pushes structural metadata (total_functions, total_entry_points, total_sinks, total_exports) from those index files to `code_files` rows in the backend via `POST code/files/bulk-structural-metadata`.
- `agent/scripts/schema.sql` is not the orchestrator schema. It only defines the transient local queue DB. The `work_items_per_host` view is defined in `agent/scripts/assess/lib/db.py:_apply_work_items_per_host_view`, NOT in `schema.sql` — fresh engagements run that helper via `db_init()` from `_init_cases_db` so both the schema and the view come up together.
- Kali command audit context threads through three co-dependent files post-Wave-1: the host-side helper family at `agent/scripts/assess/lib/kali*.py` (CLI flag → audit field mapping in `kali_cli.py` + `kali_audit.py`, pre-exec POST + post-exec PATCH-finalize in `kali_audit.py`, orchestration loop in `kali.py`), the Pydantic request models (`CommandRunRecordRequest` accepts the new lifecycle fields and treats `phase` as REQUIRED with no env-fallback; `CommandRunFinalize` for PATCH; `JobCreate`/`Update`/`Record` for the async-job lifecycle) in `orchestrator/backend/app/api/assessment.py`, and the `assessment_command_runs` + `assessment_jobs` schemas in `orchestrator/backend/app/db.py`. Any new CLI flag added to `aith assess kali <verb>` that should be persisted must land in `kali_cli.py` (argparse capture + `kali_args_to_kwargs` plumbing), `kali_audit.py` (`_post_pre_exec_row` payload field), `assessment.py` (Pydantic field), `db.py` (column + FTS5 sync trigger if searchable), and `state_manager.py` (record/finalize). `agent/scripts/assess/lib/contracts.py` `_kali_root_contract` / `_kali_verb_contract` should also be refreshed so `aith assess contract kali <verb>` documents the new flag.
- `agent/scripts/assess/lib/audit_enums.py` is the single source of truth for `TECHNIQUE_ENUM` and `PROBE_KIND_ENUM` tuples; consumed by `agent/scripts/assess/lib/kali.py` (host-side CLI flag validation), `agent/scripts/assess/commands/list_command_runs.py` (filter argparse), and copied into the runtime image at `/opt/mcp-tools/audit_enums.py` for legacy in-container scripts that still import it.

### Single sources of truth (drift-prone invariants)

These invariants exist in exactly **one** place. Every other consumer imports from there. Adding a new instance is a drift hazard — extend the canonical owner instead, and the consumers pick up the change automatically. When you find yourself about to copy one of these into a second file, stop and import.

| Invariant | Canonical owner | Consumers (read-only) |
|---|---|---|
| Inert work-item types (`image`, `video`, `font`, `archive`, `sourcemap`, `manifest`) | `agent/scripts/assess/lib/classify_buckets.py:INERT_TYPES` | `agent/scripts/assess/lib/db.py:_SKIP_TYPES` (alias), `agent/scripts/assess/commands/classify_work.py` (WHERE-clause builder) |
| `gf`-style URL bucket table + scoring | `agent/scripts/assess/lib/classify_buckets.py:_BUCKETS` + `classify_row` | `agent/scripts/assess/lib/db.py:db_insert_work_item` (inline at insert), `agent/scripts/assess/commands/classify_work.py` (re-application) |
| `work_items_per_host` view DDL | `agent/scripts/assess/lib/db.py:_apply_work_items_per_host_view` | `agent/scripts/schema.sql` (intentionally defers to db.py), `src/ai_threat_hunting_cli/engagements.py:_init_cases_db` (calls `db_init` so fresh DBs get the view) |
| `gau` cache rules + LinkFinder JS-endpoint regex + sidecar meta shape | `agent/scripts/assess/lib/gau_pipeline.py` | `agent/scripts/assess/commands/gau_endpoints.py`, `gau_secrets.py`, `gau_js_endpoints.py` |
| Kali audit enums (`TECHNIQUE_ENUM`, `PROBE_KIND_ENUM`) | `agent/scripts/assess/lib/audit_enums.py` | `agent/scripts/assess/lib/kali.py`, `agent/scripts/assess/commands/list_command_runs.py`, runtime image copy at `/opt/mcp-tools/audit_enums.py` |
| Kali verb roster (target-facing vs. host-maintenance) | `agent/scripts/assess/lib/contracts.py:KALI_TARGET_VERBS` + `KALI_MAINT_VERBS` (`KALI_VERBS` is their union) | `agent/scripts/assess/cli.py` (subcommand registration), `agent/skills/kali-exec/SKILL.md` (operator-facing doc — must mirror the union) |
| `dispatch` work-buffer vs. backend-registry action lists (`_DB_ACTIONS`, `_DBLESS_ACTIONS`) | `agent/scripts/assess/commands/dispatch.py` (top of file) | argparse `db_path` / `action` help strings (built from the tuples), the Unknown-action error message, and `agent/shared-constraints.md` Contract-First verb list (manual mirror — keep aligned when the dbless tuple changes) |
| Specialist `--skills` enforcement | `agent/scripts/assess/lib/contracts.py:validate_specialist_dispatch_contract` (CLI) and `orchestrator/backend/app/api/assessment.py:DispatchCreate._enforce_skills_for_specialists` (HTTP) | Both surfaces re-implement the same rule deliberately so a CLI bypass cannot defeat the HTTP enforcement; if the rule changes, edit BOTH. |
| Skill name resolution | `agent/skills/<name>/SKILL.md` directories on disk | `aith assess list-skills` (frontmatter scan), `validate_specialist_dispatch_contract`, every prompt that references skills by `name`. There is intentionally no roster file — discovery is the directory walk. |
| Finding-prefix → agent map | `agent/scripts/assess/lib/findings.py:_AGENT_PREFIX_MAP` | `agent/operator-core.md` and `agent/shared-constraints-code.md` prefix tables (operator-facing docs — must mirror; see "Easy-to-miss registration points" below) |
| Operator + specialist prompt prose | `agent/operator-core.md`, `agent/operator-core-code.md`, `agent/agents/*.md` | `agent/AGENTS.md`, `agent/CLAUDE.md`, `.claude/agents/*.md`, `.codex/agents/*.toml` (all generated by `agent/scripts/render-operator-prompts.sh` — every output starts with a `GENERATED FILE — DO NOT EDIT` banner) |
| Operator-facing CLI contract metadata | `agent/scripts/assess/lib/contracts.py` | `aith assess contract <verb>` is the only operator-facing surface for these — no doc duplicates the schema |

### Anti-patterns flagged by review

These came up during the mid-engagement review and the consolidation work above. Read them before adding a new "small" invariant copy:

- **Hardcoded SQL `IN ('image', ...)`**: build the placeholders from `INERT_TYPES` (see `classify_work.py` for the pattern). Hand-typed inert sets in SQL are the most-frequent drift class in the codebase history.
- **"Almost-the-same" verb tuples**: don't fork `KALI_VERBS` into a target-facing-only copy by hand. Add to `KALI_TARGET_VERBS` or `KALI_MAINT_VERBS` and recompose.
- **Help-string verb lists**: build with `', '.join(_TUPLE)`. Hand-typed argparse help that lists actions ages out within a release.
- **"Looks like a schema, isn't a schema"**: `agent/scripts/schema.sql` only owns CREATE TABLE / CREATE INDEX. Views and runtime migrations live in `db.py` so legacy DBs catch up on every `db_init`.
- **Operator reading skills**: skills are dispatched-to, not read by the operator (see `operator-core.md` step 5). The `--skills` flag exists for audit; the dispatch prompt carries the `path` for the specialist to load.
- **Editing generated wrappers**: never edit `agent/AGENTS.md`, `agent/CLAUDE.md`, or anything under `.claude/agents/` / `.codex/agents/`. They open with a `GENERATED FILE — DO NOT EDIT` banner; edit the source under `agent/operator-core.md` or `agent/agents/*.md` and run `agent/scripts/render-operator-prompts.sh repo`.

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
- `orchestrator/backend/app/db.py` - SQLite persistence boundary. Why: durable schema and low-level data access for engagements, events, assessment state, and code-analysis state. Owns `assessment_command_runs` (with `run_uuid`, lifecycle columns `status`, `stdout_path`, `stderr_path`, `peak_rss_bytes`, `cpu_user_seconds`, `cpu_system_seconds`, `working_dir`, `scope_version`, `auth_context`, `superseded_by_id`, `timeout_seconds_requested`, `partial_results`) and its `assessment_command_runs_fts` FTS5 shadow table (plus the three insert/update/delete sync triggers — new lifecycle columns are NOT FTS-indexed). Owns `assessment_dispatches` (with `skills` TEXT for the comma-separated skill list the operator declared at dispatch time, applied additively via `ALTER TABLE` for pre-existing DBs). Also owns `assessment_jobs` (id, engagement_id, parent_command_run_id FK, status, started_at, ended_at, exit_code, dtach_socket_path, stdout_path, stderr_path, audit_metadata_json) for the dtach-supervised async job lifecycle. A `_require_fts5` startup check fails loudly if the bundled SQLite lacks FTS5; legacy `ALTER TABLE … ADD COLUMN` migration paths apply safe defaults (`status='completed'`, generated `legacy-<id>` run UUIDs for pre-cutover rows) so existing engagement DBs upgrade without data loss.
- `orchestrator/backend/app/config/command_run_retention.json` - retention-policy boundary for command-run output. Why: declares `preview_bytes` and `suppress_patterns`; reloadable via the `COMMAND_RUN_RETENTION_CONFIG` env var so ops can tune suppression without a code change.
- `orchestrator/backend/app/api/engagements.py` - engagement/session read and delete API. Why: stable frontend entrypoint for what exists and where it is in the workflow, including exploit approval, assigned-target session state, and explicit typed-confirm engagement deletion.
- `orchestrator/backend/app/api/events.py` - event/timeline API. Why: records operator/agent events and exposes progress summaries.
- `orchestrator/backend/app/api/artifacts.py` - artifact read API. Why: allowlisted artifact exposure instead of arbitrary file serving.
- `orchestrator/backend/app/api/assessment.py` - runtime assessment API. Why: canonical live state interface for recon, surfaces, coverage, readiness (`exploit-candidates`, `coverage-readiness`, `report-readiness`), findings, root-cause finding groups, finding verification/transitions, chains, credentials, blocked techniques, dispatch/handoff/decision registry writes, and `aith assess` command-run audit (`/command-runs` list/post and `/command-runs/{id}` detail). Backend mutations append best-effort `activity_entries` rows so CLI writes are visible outside command-run audit.
- `orchestrator/backend/app/api/code_analysis.py` - code-analysis API. Why: repo/file/module ingestion, analysis queue, results, threat model, coverage gate, triggers, and bulk structural-metadata sync live here. Queue completion, trigger requeue, and analysis-result writes append best-effort `activity_entries` rows for audit visibility.
- `orchestrator/backend/scripts/generate_agent_schemas.py` - schema bundle generator. Why: derives the committed backend-backed `agent/schemas/*.json` bundle from request models plus the stricter agent-side overlays used by the local CLI validator.
- `orchestrator/backend/app/services/engagements.py` - filesystem-to-DB sync. Why: `agent/engagements/*` starts on disk, but the UI needs queryable state, legacy engagement artifacts need normalization, session assignment state must stay in sync with the DB, and explicit deletes are recorded under `agent/engagements/.deleted-engagements/` so later syncs do not recreate tombstoned engagements from leftover files.
- `orchestrator/backend/app/services/backup.py` - orchestrator DB backup scheduler. Why: writes WAL-coherent rotated snapshots of `orchestrator.sqlite3` independent of per-engagement bootstrap snapshots.
- `orchestrator/backend/app/services/events.py` - event domain logic. Why: timeline projection and summarization stay out of routers.
- `orchestrator/backend/app/services/artifacts.py` - artifact policy layer. Why: file exposure rules stay explicit.
- `orchestrator/backend/app/services/state_manager.py` - assessment domain logic. Why: normalization, dedupe/upsert behavior, root-cause grouping over finding links, exploit/coverage/report readiness projections, finding lifecycle projection, transition ledgering, and summary rollups are business rules, not CRUD.
- `orchestrator/backend/app/services/code_analysis.py` - code-analysis domain logic. Why: queue claiming/completion, needs-context flow, result recording, triggers, structural-metadata batch updates, and coverage rules are workflow logic.
- `orchestrator/backend/app/ws.py` - in-process websocket broadcaster. Why: fans API mutations out to the UI without external messaging infrastructure.
- `orchestrator/backend/tests/` - backend contract tests. Why: pins engagement bootstrap, websocket behavior, CLI/backend contracts, runtime-image tooling contracts (`test_runtime_tooling_contract.py` static-checks the subdomain-enum binary set in `runtime-full/Dockerfile` and live-checks via `docker exec` under the `integration` mark), and code-analysis workflow rules. Markdown prompt/doc wording is reviewed through generated diffs, not backend tests.

## orchestrator/frontend

- `orchestrator/frontend/src/main.tsx` - React entrypoint. Why: single root and global stylesheet load.
- `orchestrator/frontend/src/App.tsx` - top-level shell and hash router. Why: lightweight navigation without a larger routing layer.
- `orchestrator/frontend/src/routes/EngagementsPage.tsx` - engagement index screen. Why: stable fleet-overview page.
- `orchestrator/frontend/src/routes/EngagementPage.tsx` - engagement detail coordinator. Why: owns fetch fan-out, websocket updates, polling fallback, artifact selection, and tab composition.
- `orchestrator/frontend/src/components/TabBar.tsx` - top-level tab contract. Why: defines the durable operator-facing areas: `overview`, `findings`, `coverage`, `code`, `activity`, `artifacts`.
- `orchestrator/frontend/src/components/OverviewTab.tsx` - posture summary view. Why: quick scan of workflow state, report blockers, findings, chains, and recent activity.
- `orchestrator/frontend/src/components/FindingsTab.tsx` - finding review boundary. Why: triage, root-cause group review, and proof inspection.
- `orchestrator/frontend/src/components/CoverageTab.tsx` - coverage boundary. Why: tested surface by host/service/technique.
- `orchestrator/frontend/src/components/CodeAnalysisTab.tsx` - code-analysis boundary. Why: separate file-centric review pipeline rendered in the same UI.
- `orchestrator/frontend/src/components/ActivityTab.tsx` and `orchestrator/frontend/src/components/TaskTimeline.tsx` - activity/timeline views. Why: operator progress and session history.
- `orchestrator/frontend/src/components/ArtifactViewer.tsx` - artifact inspection view. Why: read engagement artifacts without leaving the app.
- `orchestrator/frontend/src/components/CommandsTab.tsx` - `aith assess` command-run audit tab. Why: durable operator view onto `assessment_command_runs` with chip filters, tokenized search, and the technique/intent/probe_kind/destructive metadata columns.
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
