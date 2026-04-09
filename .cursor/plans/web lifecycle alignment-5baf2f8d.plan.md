<!-- 5baf2f8d-8b39-4bd0-8c48-b95529c4e605 -->
---
todos:
  - id: "backend-projections"
    content: "Add backend-owned exploit, coverage, and final-report readiness projections on top of the landed workflow+verification lifecycle"
    status: pending
  - id: "cli-gates"
    content: "Rewire exploit review/session launch and coverage/report gate commands to consume backend canonical state instead of local or legacy status views"
    status: pending
  - id: "prompt-alignment"
    content: "Align operator, shared constraints, exploit, vuln, handoff, and report prompts with the current lifecycle contract and positive ownership rules"
    status: pending
  - id: "frontend-alignment"
    content: "Expose readiness signals and fix remaining lifecycle/UI drift without adding a new workflow surface"
    status: pending
  - id: "validation"
    content: "Rerender generated prompts and run focused backend, prompt-wording, CLI, and frontend verification"
    status: pending
isProject: false
---
# Web Lifecycle Alignment

## Context
The backend has already moved to the real lifecycle model:
- `assessment_findings.status` is now workflow status.
- `verification_state` and `verification_disposition` are first-class fields.
- verification and merge already have dedicated mutation paths and transition history.

What is still broken is everything around that backend contract: prompts, exploit review/session helpers, coverage gates, dedup guidance, and a few UI surfaces still assume the old single-axis `status` model or trust local exports over backend state.

```170:172:orchestrator/backend/app/api/assessment.py
workflow_status: str = Field(default="active", min_length=1, max_length=32)
verification_state: str = Field(default="unreviewed", min_length=1, max_length=32)
verification_disposition: str = Field(default="none", min_length=1, max_length=32)
```

```37:43:agent/scripts/assess/commands/review_exploits.py
candidates = [
    row for row in findings
    if row.get("status") in {"draft", "confirmed"}
]
```

```25:28:agent/scripts/assess/commands/check_coverage.py
"""assess.py check-coverage — read surfaces.jsonl, report unresolved surfaces."""
```

This replacement plan treats the problem as lifecycle alignment, not another lifecycle redesign.

## Chosen Policy
- The backend workflow+verification split and `assessment_finding_transitions` ledger are canonical. Do not add a parallel status model.
- Do not add an `assessment_hypotheses` table in this pass. The old cursor plan was compensating for ambiguity that the backend has already mostly resolved another way.
- `report-findings` remains a report projection, not a general-purpose dedup or analyst listing endpoint.
- Add backend-owned readiness projections for exploit, coverage, and final report so the operator and CLI stop reconstructing lifecycle state in prompts or local files.
- Keep exploit/session scope finding-scoped in this pass. `approved_findings` and `assigned_findings` may stay if the implementation remains finding-only; do not do a partial rename unless the whole path is migrated together.
- `CHAIN REQUIRED` must map onto the existing finding model, not a second ledger. Use durable findings plus structured metadata in `details`/`provenance` to mark chain-only leads that are concrete enough to keep, but not yet final-report-ready.
- Low/info chain starters remain eligible for exploit review when they are chain-relevant. Exploit gating must not collapse to severity-only rules.
- Final-report gating belongs to backend projections plus helper commands and operator flow. Report-writer may still produce interim output when explicitly requested; it should not become the sole policy enforcer.
- Prompt constraints should be written as positive ownership rules. The operator dispatches and approves exceptions; helper commands and specialist agents do the routine state work.

## Target State
- Specialists record durable findings against the canonical backend schema using `workflow_status`, `verification_state`, and `verification_disposition`.
- Analysts deduplicate against `fetch findings` plus transition history, not `report-findings`.
- Exploit review and exploit session launch only consume backend-derived exploit candidates, with candidate reasons derived from lifecycle plus chain metadata.
- Coverage review queries backend coverage state and request/service observations. Local files remain sync/export artifacts, not gate sources.
- Final report readiness is explicit and machine-readable. The operator can tell the difference between “generate an interim draft” and “engagement is ready for final reporting.”
- The operator prompt gets shorter and more dispatch-focused because repetitive gate logic moves into `assess.py` helpers and backend projections.

## Implementation Plan

### 1. Backend-owned readiness projections
- `orchestrator/backend/app/services/state_manager.py`: add canonical projection helpers for:
  - `list_exploit_candidates()`
  - `report_readiness()`
  - `coverage_readiness()`
- `orchestrator/backend/app/services/state_manager.py`: define exploit-candidate logic in terms of `workflow_status`, `verification_state`, `verification_disposition`, severity, and explicit chain metadata in `details_json`. Do not key off the removed single-axis `status` model.
- `orchestrator/backend/app/services/state_manager.py`: define report-readiness blockers explicitly, for example:
  - unverified or disputed findings intended for the final report,
  - duplicate/merge debt that would make `report-findings` misleading,
  - blocked findings missing required blocker context,
  - unresolved coverage gaps that should block final reporting.
- `orchestrator/backend/app/services/state_manager.py`: use existing summary/open-coverage data as inputs, but centralize the readiness decision instead of making each prompt/CLI command infer it independently.
- `orchestrator/backend/app/api/assessment.py`: add read-only endpoints for exploit candidates and readiness projections, for example:
  - `GET /exploit-candidates`
  - `GET /report-readiness`
  - `GET /coverage-readiness`
- `orchestrator/backend/app/api/assessment.py`: keep `POST /findings/{slug}/verify` and `POST /findings/merge` as the only mutation paths for verification and merge transitions. The new plan must preserve that boundary.
- `orchestrator/backend/app/services/state_manager.py`: optionally extend `assessment_summary()` with lightweight readiness summaries such as `exploit_candidate_count`, `report_blocker_count`, and `coverage_blocker_count` so the UI can show state without duplicating logic.

### 2. Canonicalize `CHAIN REQUIRED` without a second ledger
- `agent/agents/vulnerability-analyst.md`, `agent/shared-constraints.md`, and `agent/references/handoff-protocols.md`: define `CHAIN REQUIRED` as a durable finding recorded in the existing backend model, not a prose-only note and not a new hypothesis record.
- Use existing `details` / `provenance` payloads to carry structured chain metadata, for example:
  - `details.chain_required = true`
  - `details.chain_rationale`
  - `details.required_followup`
- Keep the semantic rule tight:
  - speculative guesses do not become durable findings;
  - concrete but chain-dependent primitives do become durable findings;
  - such findings are exploit-eligible, but they are not final-report-ready until verification resolves them.
- `agent/schemas/finding-record.schema.json`: document the chain metadata contract so specialist agents emit it consistently.

### 3. CLI gates and exploit/session helpers
- `agent/scripts/assess/commands/review_exploits.py`: stop filtering on `row.get("status")`. Query the new backend exploit-candidate projection and display lifecycle fields plus candidate reason.
- `agent/scripts/assess/commands/check_exploit_gate.py`: keep the human approval policy from `scope.json`, but validate approved slugs against backend exploit candidates instead of blindly echoing `approved_findings`.
- `agent/scripts/assess/commands/launch_session.py`: only allow session launch for backend-approved exploit candidates. Render the assigned findings with `workflow_status`, `verification_state`, and `verification_disposition`, not the removed `status` field.
- `agent/scripts/assess/commands/check_coverage.py`: replace local `surfaces.jsonl` gating with backend `coverage-readiness` or canonical `coverage-items` / summary queries. If local artifacts are retained, treat them as drift diagnostics only.
- Add `agent/scripts/assess/commands/check_report_readiness.py`: query the backend final-report readiness projection and exit non-zero with a concise blocker list.
- `agent/scripts/assess/commands/record_finding.py`: keep the current backend-aligned defaults (`active`, `unreviewed`, `none`). Do not reintroduce CLI-side defaults that silently create old-style `confirmed` findings.
- `agent/scripts/assess/lib/findings.py`: surface chain metadata and the dual-axis lifecycle clearly in the readable export so `findings.md` remains human-usable without inventing its own semantics.

### 4. Prompt and workflow alignment
- `agent/operator-core.md`: remove stale single-status reasoning and the “drive HIGH findings to exploitation” shortcut. Replace it with backend/helper-driven exploit review based on candidate eligibility and chain relevance.
- `agent/operator-core.md`: move routine gate checks out of the operator narrative:
  - use `check-exploit-gate` before exploit dispatch,
  - use `check-coverage` before declaring coverage complete,
  - use `check-report-readiness` before final report dispatch.
- `agent/operator-core.md`: remove requirements to manually re-read synced local exports after backend writes when the backend is already canonical.
- `agent/shared-constraints.md` and `agent/agents/vulnerability-analyst.md`: change dedup guidance from `fetch report-findings` to `fetch findings` plus merge/transition review.
- `agent/agents/exploit-developer.md`: stop bootstrapping from `.status IN (...)`. Use the exploit-candidate helper and require lifecycle-aware updates through the existing patch/verify paths.
- `agent/skills/report-generation/SKILL.md` and `agent/agents/report-writer.md`: keep `report-findings` as the writer’s content source, but make final-report gate ownership explicit:
  - operator/helper checks final readiness before a final report;
  - writer can still be used for interim drafts when explicitly requested.
- `agent/references/handoff-protocols.md`: align exploit handoff language with the canonical lifecycle and the new chain metadata contract.
- Across prompt files, rewrite dense “do not” lists into positive ownership rules with reasoning, following the repo’s `AGENTS.md` authoring standard.

### 5. Frontend and UI alignment
- `orchestrator/frontend/src/lib/api.ts`: add types for the new exploit/coverage/report readiness projections if summary extension or dedicated endpoints are added.
- `orchestrator/frontend/src/components/FindingsTab.tsx`: keep the dual-axis finding display, but fix the render-time side effect (`setPage(0)` inside `useMemo`) so pagination/filtering remains stable while lifecycle views change.
- `orchestrator/frontend/src/components/OverviewTab.tsx` or the existing engagement summary surface: add compact readiness visibility, for example blocker counts or exploit-candidate counts, without introducing a new top-level tab.
- `orchestrator/frontend/src/components/ActivityTab.tsx`: if `assigned_findings` remains intentionally finding-scoped, document and keep it; if not, rename it only in a fully coordinated pass. Do not half-migrate this path.

### 6. Validation
- `orchestrator/backend/tests/test_engagements_api.py`: add coverage for exploit-candidate selection, report-readiness blockers, and coverage-readiness blockers.
- Add or update CLI tests for:
  - `review-exploits`
  - `check-exploit-gate`
  - `launch-session`
  - `check-coverage`
  - `check-report-readiness`
- Update prompt wording tests so they assert:
  - dedup uses `findings`, not `report-findings`,
  - operator delegates readiness checks to helpers,
  - exploit intake is not severity-only,
  - `CHAIN REQUIRED` maps to the current lifecycle model instead of a hypothetical ledger.
- Because `agent/operator-core.md` is a rendered source, rerender prompt artifacts after edits:

```bash
cd agent
./scripts/render-operator-prompts.sh repo
```

- Run focused verification:

```bash
uv run --directory orchestrator/backend pytest orchestrator/backend/tests/test_engagements_api.py
uv run --directory orchestrator/backend pytest tests/test_prompt_wording.py
cd orchestrator/frontend && npm run build
```

## Non-goals For This Pass
- Do not introduce an `assessment_hypotheses` table or a second durable lifecycle store.
- Do not partially rename `approved_findings` / `assigned_findings` unless the full backend, CLI, frontend, and session-file path is migrated together.
- Do not make `report-findings` the dedup or analyst endpoint.
- Do not push final-report policy into report-writer alone.
- Do not starve low/info chain starters by making exploit review severity-only.

## Notes For The Implementing Agent
- Treat this as an alignment pass around the lifecycle that already exists.
- Prefer backend projections and helper commands over stuffing more bookkeeping into operator-core.
- Preserve the current verify/merge mutation boundaries; do not reopen verification writes through generic patch paths.
- If you discover that finding-scoped exploit/session metadata is no longer sufficient, split that rename into its own coordinated migration rather than mixing it into the readiness/gating work.
