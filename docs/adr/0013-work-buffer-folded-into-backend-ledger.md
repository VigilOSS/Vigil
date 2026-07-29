# ADR 0013 — Work buffer folded into the backend ledger: `assessment_work_items` replaces per-engagement `cases.db`

- Status: Accepted
- Date: 2026-07-08
- Update: The transitional legacy-buffer migrator described in the original
  decision was retired in the 2026-07 CLI consolidation. Current CLI and prompt
  surfaces accept only backend-backed commands with no local database path.

## Context

Since the earliest version of the assessment pipeline, each engagement kept its transient
triage/dispatch queue in a per-engagement SQLite file, `<engagement_dir>/cases.db`
(`agent/scripts/schema.sql`'s `work_items` table). This was a **second store**, separate from the
orchestrator backend that already held canonical findings, coverage, services, request-variants,
and chains (`docs/data-flow.md` §1, "Two stores, two jobs," as it read before this decision).

The two-store split had four concrete costs:

1. **Dual write, not one transaction.** Ingest verbs (`ingest-endpoints`, `ingest-candidates`,
   `ingest-spec`) POSTed the request-observation to the backend, then separately inserted a
   `work_items` row into the local SQLite file. The local row's backend FKs
   (`request_variant_id`/`service_id`/`coverage_item_id`) were populated only *after* the
   observation POST succeeded — a second, decoupled step, not the same transaction. A crash or
   partial failure between the two steps could leave the local row unlinked from the canonical
   state it was supposed to mirror.
2. **No real engagement identity.** A `cases.db` file is a path, not a database row. It carried no
   `engagement_id` FK, no referential integrity with the backend's `assessment_engagements` table,
   and no way for a caller with only an `AssessmentClient` (HTTP access, no local filesystem access
   to the engagement directory — e.g. a dispatched subagent without engagement-dir plumbing) to
   read or write it at all.
3. **Redundant CLI surface.** Because the file's location is fully determined by the engagement
   directory, every work-buffer and ingest verb still required a `<cases.db>` positional argument
   that carried no information beyond what `--engagement-dir` (or cwd resolution) already supplied
   — repeated, quotable, gettable-wrong boilerplate on every single invocation across every prompt,
   skill, and phase doc that touched the work buffer.
4. **SQLite-file fragility for a long-lived, sometimes-shared handle.** A long-held proxy connection
   risked the file being checkpointed, VACUUMed, or replaced out from under it (documented in
   `proxy_addon.py`'s own historical comments); a validation corpus's `cases.db` for one real
   engagement (Zendesk) was outright malformed by the time of the ADR 0004 taxonomy study — a
   concrete instance of the fragility, recorded there as "used qualitatively because its `cases.db`
   is malformed."

None of this was a case for moving OFF SQLite as a storage engine — the orchestrator backend
already runs SQLite via FastAPI, and it works well there. The problem was the *second*,
engagement-scoped-only-by-convention file, decoupled from the backend's transaction and FK model.

## Decision

**Fold `work_items` into a new backend table, `assessment_work_items`, and retire the per-engagement
`cases.db` file entirely. The backend derives the work-item row server-side, in the same
transaction as the observation/coverage-item write it already performs — no dual write.**

1. **One table, engagement-scoped, real FKs.** `assessment_work_items`
   (`orchestrator/backend/app/db.py:_create_assessment_work_items_table`) carries an `engagement_id`
   FK plus the same indexes the local table's `(status, priority_score DESC, cluster_key)` index
   served (`idx_assessment_work_items_priority` / `_status_type` / `_host` / `_consumed`), and is
   accessed exclusively over HTTP through `AssessmentClient` — the `GET/POST work-items*` routes
   under `orchestrator/backend/app/api/assessment.py`, served by
   `orchestrator/backend/app/services/state_manager/work_buffer.py`.
2. **Server-side derivation, one transaction.** The gf-style classification logic
   (`agent/scripts/assess/lib/classify_buckets.py`'s `_BUCKETS` table and
   `classify_from_fields()`) is **unchanged** and stays a client-side shared library — this decision
   moves WHERE the derived row is persisted, not WHAT computes it. Ingest verbs
   (`ingest-endpoints`, `ingest-candidates`, `ingest-spec`) compute `priority_score`,
   `priority_reason`, `cluster_key`, and `terminal_reason` inline exactly as before, then ship them
   as a `work_item` derivation block **inside** the `/request-observations[/bulk]` payload. The
   backend persists the derived `assessment_work_items` row in the SAME transaction as the
   request-variant/observation/coverage-item writes it already performs — there is no second POST
   and no window where the two can desync. Producers with no observation to attach to
   (`ingest-arjun`'s enrichment-only rows, out-of-scope/egress-blocked skip rows) POST directly to
   `/work-items/bulk` instead.
3. **`<cases.db>` dropped from every CLI verb.** The engagement resolves from cwd / `--engagement-dir`
   the same way every other backend-first verb already resolves it. Affected verbs: `work-buffer`
   (all actions — `stats`, `peek`, `fetch`, `fetch-by-priority`, `defer-cluster`, `defer-items`,
   `mark-manual`, `done`, `error`, `reset-stale`, `retry-errors`, `requeue`), `ingest-endpoints`,
   `ingest-candidates`, `ingest-spec`, `ingest-arjun`, `classify-work`, `list-clusters`,
   `link-surface-work-items`, `arjun-select`, `arjun-sweep`. The work-buffer `migrate` **action**
   (a schema-migration no-op left over from early SQLite-schema churn) is also removed — the
   backend owns its own schema via `init_db()`, so there is nothing left for a per-engagement
   action to migrate.
4. **The proxy no longer writes SQLite.** `agent/scripts/proxy_addon.py` posts the request-observation
   to the backend exactly as every other producer does; the backend's server-side derivation
   (item 2) produces the `assessment_work_items` row from that POST. The addon's local-DB seam
   (`db_path = entry.root / "cases.db"`, the long-held-connection WAL-checkpoint caution, the
   `db_init()`/`db_insert_work_item()` calls) is removed.
5. **The cutover used a one-time verified migration.** During the ADR 0013
   rollout, a transitional reader replayed legacy `work_items` rows through
   the idempotent `work-items/bulk` UPSERT, verified the backend count, and
   archived rather than deleted the source. That reader and its CLI command
   were removed after the cutover; current operators do not supply or migrate
   a local work-buffer file.
6. **`cases.db` / `agent/scripts/schema.sql` / the proxy-local-SQLite path are retired.** The
   local-DB helpers in `agent/scripts/assess/lib/db.py` that existed solely to create, migrate, and
   write a per-engagement `cases.db` (`db_init`, `_apply_work_items_per_host_view`,
   `_apply_work_items_priority_migration`, `db_insert_work_item`,
   `db_insert_out_of_scope_work_item`) and the `_init_cases_db` bootstrap seam in
   `src/vigil_cli/engagements.py` go with the file they served. The
   transitional reader in item 5 was later removed as part of the CLI
   consolidation.
7. **Previously-`cases.db`-only producers now route through the backend.** Before this decision,
   `ingest-arjun` wrote to the local file **only** (`docs/data-flow.md` §2 flagged it as "none —
   local `cases.db` only"), and out-of-scope/egress-skip rows were local-only terminal states. Both
   now write `assessment_work_items` rows directly via `/work-items/bulk` — reachable, queryable,
   and durable the same way every other work-item row is.

## Consequences

- **One store, one job.** `docs/data-flow.md` §1's "two stores, two jobs" collapses to one — the
  backend is canonical for the triage/dispatch queue as well as findings/coverage/services/
  request-variants/chains. There is no synchronization window where a work-item row's backend FKs
  can lag or desync from the observation that produced it.
- **Shorter, uniform CLI.** Every work-buffer/ingest invocation drops the `<cases.db>` positional —
  one less argument to compute, quote, or get wrong across every dispatch, prompt, skill, and phase
  doc that touches the work buffer.
- **HTTP-only callers can now participate.** A dispatched subagent or any caller with only an
  `AssessmentClient` — no local filesystem handle to the engagement directory — can read and write
  the work buffer directly, which was previously impossible without a local file.
- **No cutover backfill loss.** The transitional migration's
  verified-count-then-archive-never-delete design preserved in-progress
  triage state while ADR 0013 rolled out. That migration path is no longer a
  current operator action.
- **Classification logic is untouched.** `classify_buckets.py`'s taxonomy, weights, and
  `INERT_TYPES` are unaffected — this decision is purely about where the derived row lands, not
  what computes it.
- **Prompt/doc surfaces simplify.** `agent/agents/*.md`, `agent/phases/*.md`,
  `agent/skills/*/SKILL.md`, and `agent/references/**` drop every `<cases.db>` argument and the
  "local buffer vs backend ledger" framing that used to caveat work-buffer instructions throughout.

## Alternatives considered

1. **Keep `cases.db`, add a backend mirror/sync job.** Rejected: reintroduces the exact dual-write
   desync risk this decision eliminates, just moved into a background sync process instead of two
   sequential POSTs — worse, since the sync job's own failure mode is now a THIRD thing that can
   drift.
2. **Move the SQLite file into the backend's data directory but keep it a separate per-engagement
   file (not a table in the main backend DB).** Rejected: still requires a bespoke second
   connection/locking discipline instead of reusing the backend's existing engagement-scoped
   table/FK/HTTP machinery, and is still unreachable by an HTTP-only caller.
3. **Keep local `cases.db` for browser-proxy captures only (mitmproxy stays SQLite, everything else
   backend).** Rejected: the proxy's derived observation already POSTs to the same
   `/request-observations` route every other producer uses. Carving out a proxy-only local write
   path would resurrect the exact two-tier model this decision removes, for no benefit — the
   backend's per-transaction derivation handles proxy-originated rows identically to every other
   producer.

## Relationship to other items

- Supersedes the "two stores, two jobs" framing in `docs/data-flow.md` §1 (now "one store, one
  job") and the `cases.db`-flagged ingest-verb table rows in §2; the §8 dependency graph reflects
  the single-transaction derivation.
- `docs/adr/0001-coverage-as-harness-not-gate.md` and `docs/adr/0004-modern-surface-taxonomy.md`
  each cite a `cases.db`-specific fact from before this change (the four-taxonomy count's
  "gf-buckets in cases.db only," and the Zendesk corpus's "malformed `cases.db`" qualifier,
  respectively); both are amended with a pointer to this ADR. Their surrounding philosophy and
  historical corpus measurements stand as originally recorded — a rewrite would misrepresent what
  was actually measured at the time.
- Implemented by: `orchestrator/backend/app/db.py:_create_assessment_work_items_table`,
  `orchestrator/backend/app/services/state_manager/work_buffer.py`,
  `orchestrator/backend/app/api/assessment.py` (`/work-items*` routes); CLI side:
  `agent/scripts/assess/commands/work_buffer.py` + `dispatch/work_items.py`,
  `ingest_endpoints.py`, `ingest_candidates.py`, `ingest_spec.py`, `ingest_arjun.py`,
  `classify_work.py`, `list_clusters.py`, `link_surface_work_items.py`, `arjun_select.py`,
  `arjun_sweep.py`. Retired:
  `agent/scripts/schema.sql`, the local-DB seam in `agent/scripts/assess/lib/db.py`,
  `src/vigil_cli/engagements.py`'s `_init_cases_db`, and the local-write path in
  `agent/scripts/proxy_addon.py`, plus the transitional migration command used
  during the ADR 0013 cutover.
