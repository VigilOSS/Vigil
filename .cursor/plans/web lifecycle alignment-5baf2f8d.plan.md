---
todos:
  - id: "readiness-api"
    content: "Add backend-owned exploit, coverage, and report readiness projections plus final-report gating"
    status: pending
  - id: "target-rename"
    content: "Hard-cut approved_findings/assigned_findings to approved_targets/assigned_targets across DB, on-disk artifacts, CLI, API, prompts, and frontend"
    status: pending
  - id: "prompt-contracts"
    content: "Align web and code prompt layers with helper-owned lifecycle, findings-based dedup, and final-vs-draft reporting"
    status: pending
  - id: "schema-chain"
    content: "Add chain-required metadata to generated finding schemas and helper contract guidance"
    status: pending
  - id: "validation"
    content: "Cover migrations, readiness gates, renamed fields, prompt wording, schema generation, and frontend build"
    status: pending
isProject: false
---
# Lifecycle Readiness And Target Vocabulary Rewrite

## Summary
Implement a backend-owned readiness model for exploit review, coverage completion, and final
report generation, and hard-cut the exploit-session vocabulary from finding-scoped names to
target-scoped names.

This plan is based on the current repo state:
- Canonical finding lifecycle already lives in the backend as `workflow_status`,
  `verification_state`, and `verification_disposition` in
  `orchestrator/backend/app/api/assessment.py` and
  `orchestrator/backend/app/services/state_manager.py`.
- `report-findings` exists today as a report projection, but it has no `draft` vs `final` mode
  and no readiness gate.
- Web engagements already have a `Verify` phase in `agent/operator-core.md`; code analysis keeps
  its own phase model in `agent/operator-core-code.md`.
- `check-coverage` is already backend-backed via `surfaces`, but exploit review and report
  readiness are still inferred locally in CLI helpers and prompt text.
- The old finding-scoped session fields are still live in the current tree:
  - `scope.json` bootstrap uses `approved_findings` in `agent/scripts/init_engagement.sh`
  - exploit helpers use `approved_findings` / `assigned_findings` in
    `agent/scripts/assess/commands/approve_exploit.py`,
    `check_exploit_gate.py`, and `launch_session.py`
  - engagement sync/API/frontend still expose `approved_findings`,
    `assigned_findings`, and `assigned_findings_json` in
    `orchestrator/backend/app/services/engagements.py`,
    `orchestrator/backend/app/api/engagements.py`,
    `orchestrator/backend/app/db.py`,
    `orchestrator/frontend/src/lib/api.ts`, and
    `orchestrator/frontend/src/components/ActivityTab.tsx`
- Prompt drift is still present:
  - web and code shared constraints still dedup against `report-findings`
  - `agent/references/handoff-protocols.md` still places exploit in Phase 4
  - `agent/skills/report-generation/SKILL.md` still assumes a single ungated `report-findings`
    path and stale phase numbering

Desired state:
- readiness decisions are computed once in the backend and consumed everywhere else;
- final report generation is hard-gated, while interim drafts remain available;
- `approved_targets` and `assigned_targets` replace the old names everywhere with no aliases;
- web and code flows share lifecycle, dedup, and reporting contracts, while code keeps its own
  phase model;
- chain-only leads remain normal findings with structured metadata, not a second ledger.

## Decisions Locked For This Plan
- Scope includes web runtime plus shared code-analysis parity. Code keeps its current phase
  structure; only shared lifecycle, reporting, and naming seams are aligned.
- Final-report gating is enforced in both helpers and the backend. Helper checks provide operator
  clarity; backend rejection is the hard stop.
- The rename is a hard cutover:
  - `approved_findings` -> `approved_targets`
  - `assigned_findings` -> `assigned_targets`
  - `assigned_findings_json` -> `assigned_targets_json`
  No aliases remain after the migration lands.
- `approved_targets` and `assigned_targets` still carry finding slugs in this pass. The rename
  changes vocabulary and session semantics, not the reference type.
- Interim report generation remains available by explicit request. Final reports require readiness.

## Implementation

### 1. Backend readiness and final-report gating
- Add backend-owned readiness projections in `orchestrator/backend/app/services/state_manager.py`:
  - `list_exploit_candidates(engagement_id)`
  - `coverage_readiness(engagement_id)`
  - `report_readiness(engagement_id)`
- Add read-only endpoints in `orchestrator/backend/app/api/assessment.py`:
  - `GET /exploit-candidates`
  - `GET /coverage-readiness`
  - `GET /report-readiness`
- Extend `GET /report-findings` to accept `mode=draft|final`:
  - `mode=draft` preserves the current report-projection behavior except for any renamed fields
    or newly surfaced structured metadata.
  - `mode=final` first evaluates `report_readiness`. If blockers exist, return `409` with a
    machine-readable blocker payload. If clear, return the final report set.
- Add readiness counts to `assessment_summary()` so the frontend can show compact readiness state
  without duplicating decision logic.

Readiness rules to implement:
- `exploit-candidates` includes findings only when:
  - `workflow_status` is not `merged`, `false_positive`, `reported`, or `exploited`
  - `verification_state == "verified"`
  - `verification_disposition in {"confirmed", "downgraded"}`
  - severity is `medium` or above, or `details.chain_required == true`
- Each exploit candidate includes a `candidate_reason` string derived from the first matching rule:
  - `verified_critical`
  - `verified_high`
  - `verified_medium`
  - `verified_chain_required`
- `coverage-readiness` blocks when:
  - any surface remains `discovered`
  - any of `account_recovery`, `dynamic_render`, `object_reference`, or `privileged_write`
    remains `deferred`
  The payload returns counts plus the blocking rows.
- `report-readiness` blocks when:
  - `coverage-readiness` has blockers
  - any non-merged, non-false-positive finding that would be eligible for the report is not
    `verification_state == "verified"`
  - any such finding has `verification_disposition` outside `{"confirmed", "downgraded"}`
  - duplicate candidates remain unmerged, where duplicate candidates are findings sharing the same
    non-empty `root_cause_key`, or the same `canonical_location` plus `defect_family`
- Final-mode report projection returns only findings with:
  - `workflow_status` in `{"active", "blocked", "exploited", "reported"}`
  - `verification_state == "verified"`
  - `verification_disposition in {"confirmed", "downgraded"}`

### 2. Hard-cut rename to target-scoped session vocabulary
- Replace old finding-scoped names everywhere:
  - scope metadata: `approved_targets`
  - session assignment/index/API/UI: `assigned_targets`
  - database column: `assigned_targets_json`
- Update fresh scaffolding in `agent/scripts/init_engagement.sh` to emit only the new keys.
- Update exploit helpers:
  - `approve-exploit.py` writes `approved_targets`
  - `check_exploit_gate.py` reads `approved_targets` and validates them against
    `exploit-candidates`
  - `launch_session.py` persists `assigned_targets` and only launches for approved backend
    candidates
- Update backend engagement sync and API:
  - `orchestrator/backend/app/services/engagements.py`
  - `orchestrator/backend/app/api/engagements.py`
  - `orchestrator/backend/app/models/engagement_session.py`
  - `orchestrator/backend/app/db.py`
- Update frontend types and rendering:
  - `orchestrator/frontend/src/lib/api.ts`
  - `orchestrator/frontend/src/components/ActivityTab.tsx`

Migration plan for the hard cutover:
- Database:
  - in `orchestrator/backend/app/db.py`, add a startup migration that renames
    `engagement_sessions.assigned_findings_json` to `assigned_targets_json` with SQLite
    `ALTER TABLE ... RENAME COLUMN ...`
  - after the migration, all readers/writers use only `assigned_targets_json`
- On-disk engagement artifacts:
  - add an idempotent migration in `orchestrator/backend/app/services/engagements.py` that runs
    before sync and rewrites existing `scope.json`, `sessions/index.json`, and
    `sessions/*/assignment.json`
  - rewrite files in place from the old keys to the new keys
  - after the rewrite, the sync layer reads only the new keys
- No compatibility aliases remain in API responses, frontend types, or prompt text after the
  migration lands

### 3. CLI helpers become thin consumers of backend readiness
- `agent/scripts/assess/commands/review_exploits.py` stops locally filtering `draft` / `active`
  findings and consumes `exploit-candidates`
- `agent/scripts/assess/commands/check_exploit_gate.py` becomes a thin gate over
  `approved_targets` + backend `exploit-candidates`
- `agent/scripts/assess/commands/launch_session.py` validates requested slugs against approved
  candidates and writes `assigned_targets`
- `agent/scripts/assess/commands/check_coverage.py` stays backend-backed, but stops owning the
  policy directly; it should consume `coverage-readiness` instead of re-deriving readiness from
  raw surfaces
- Add `agent/scripts/assess/commands/check_report_readiness.py` to print blockers and exit
  non-zero when final reporting is not ready
- Keep `export-findings` and `export-surfaces` as read-only derived artifacts. No helper, prompt,
  or UI path should parse them to make lifecycle decisions

### 4. Prompt and reporting contract alignment
- Web prompt stack:
  - `agent/operator-core.md`
  - `agent/shared-constraints.md`
  - `agent/agents/vulnerability-analyst.md`
  - `agent/references/handoff-protocols.md`
  - `agent/agents/report-writer.md`
  - `agent/skills/report-generation/SKILL.md`
- Code shared-contract stack:
  - `agent/operator-core-code.md`
  - `agent/shared-constraints-code.md`
  - `agent/agents/report-writer.md`
  - `agent/skills/report-generation/SKILL.md`

Required prompt/reporting changes:
- Dedup guidance uses `./scripts/assess.py fetch findings`, not `report-findings`
- Lifecycle mutations point to `record-finding`, `verify-finding`, `kill-finding`,
  `reset-finding`, and `update-finding`, not raw payload folklore
- Web handoff text reflects the current `Verify` phase before exploit
- Code flow keeps its own phases, but pre-report dedup and report dispatch follow the same
  findings-based and readiness-gated rules
- `report-writer` and `report-generation` use:
  - `./scripts/assess.py fetch "report-findings?mode=draft"` for interim drafts
  - `./scripts/assess.py fetch "report-findings?mode=final"` for final reports
- Report publication updates findings to `reported` only after a successful final-mode report path

### 5. Chain-required metadata is added to the canonical schema bundle
- Add the following optional `details` fields in
  `orchestrator/backend/scripts/generate_agent_schemas.py`:
  - `chain_required: boolean`
  - `chain_rationale: string`
  - `required_followup: array[string]`
- Update `agent/scripts/assess/lib/contracts.py` so `record-finding` documents these fields and
  includes them in examples/notes
- Regenerate `agent/schemas/finding-record.schema.json`
- Exploit-candidate readiness uses `details.chain_required` as the explicit mechanism that allows
  low/info verified findings to remain exploit-eligible
- Do not add a separate hypotheses table or a special chain-only workflow status

### 6. Frontend alignment
- Extend `AssessmentSummary` and any new readiness types in
  `orchestrator/frontend/src/lib/api.ts`
- Add compact readiness display to the existing summary surface:
  - exploit candidate count
  - coverage blocker count
  - report blocker count
- Keep the current tabs. Do not add a new dashboard for this pass

### 7. CODE-MAP maintenance
- Update `CODE-MAP.md` in the same change because this work:
  - adds durable assessment API endpoints
  - adds a new CLI helper command family member (`check-report-readiness`)
  - changes the canonical session/approval vocabulary across API, DB, and frontend

## Test Plan
- Backend API tests:
  - exploit candidate selection and `candidate_reason`
  - coverage readiness blockers
  - report readiness blockers
  - `report-findings?mode=final` returns `409` when blocked
  - `report-findings?mode=draft` remains available
  - engagement/session responses expose `approved_targets` and `assigned_targets`
- Migration tests:
  - DB startup migration renames `assigned_findings_json`
  - legacy `scope.json`, `sessions/index.json`, and `assignment.json` are rewritten to the new
    keys before sync
- CLI tests:
  - `approve-exploit`
  - `review-exploits`
  - `check-exploit-gate`
  - `launch-session`
  - `check-coverage`
  - `check-report-readiness`
- Schema/contract tests:
  - generated schema includes `chain_required`, `chain_rationale`, and `required_followup`
  - contract output documents the new fields
- Prompt wording tests:
  - web and code shared constraints dedup against `findings`
  - report generation uses `mode=draft|final`
  - exploit handoff reflects Verify-before-Exploit for web
  - renamed target vocabulary is used everywhere
- Frontend validation:
  - updated engagement/session types compile
  - readiness counts render on the overview surface
  - activity tab renders `assigned_targets`

Run after implementation:
```bash
cd agent
./scripts/render-operator-prompts.sh repo
uv run --directory orchestrator/backend python scripts/generate_agent_schemas.py
uv run --directory orchestrator/backend python scripts/generate_agent_schemas.py --check
uv run --directory orchestrator/backend pytest tests/test_engagements_api.py
uv run --directory orchestrator/backend pytest tests/test_agent_script_regressions.py
uv run --directory orchestrator/backend pytest tests/test_schema_generation.py
uv run --directory orchestrator/backend pytest tests/test_code_assess_cli.py
uv run --directory orchestrator/backend pytest tests/test_prompt_wording.py
cd orchestrator/frontend && npm run build
```

## Non-goals
- No compatibility aliases for the old field names after migration
- No new hypothesis table or second lifecycle store
- No change to the code-analysis phase model
- No new lifecycle dashboard
- No regression back to export-file-based lifecycle decisions

## Assumptions
- Existing engagements may already contain the old on-disk keys, so the hard cutover includes a
  one-time persistent file rewrite before sync rather than runtime aliases
- `approved_targets` and `assigned_targets` remain arrays of finding slugs in this pass
- Final reports are the only report path that must pass readiness gating
