# Changelog

This file records notable changes to the Vigil framework — the operator
prompts, deterministic assessment verbs, orchestrator services, and the `vigil` CLI.
Entries are grouped by date and summarize shipped work at a high level; the code at the
cited paths and the [TODOv2.md](TODOv2.md) backlog remain the detailed record.

## 2026-06-09

### Command consolidation — one phase-aware readiness command (Wave 6d)

Five standalone readiness commands were folded into a single phase-aware command and
deleted (no aliases): **`vigil assess check-phase-readiness --phase <recon|collect|consume|verify|exploit|report>`**
replaces `check-coverage`, `check-scope-coverage`, `check-report-readiness`,
`check-exploit-gate`, and `check-intel-readiness`. Per-phase composition: `recon`=enum
evidence + intel advisory; `collect`=collection evidence; `consume`=consumption evidence +
surface-coverage gate + the EV-ranked depth ledger + intel advisory; `verify`=depth carry-over;
`exploit`=the exploit projection (`{exploit_policy, approved_targets}`, with the same
`full_send` / slug-list / `*` text tokens specialists key off); `report`=report-readiness
blockers + intel advisory. Flags: `--depth`/`--by-app-unit`, `--by-host`, `--auto-redispatch`,
`--strict` (CI exit-1 on any open advisory item — preserves the old intel `--strict`),
`--strict-deep` (gate on app-unit detection, default OFF), `--include-intel`, `--json`.

Behind the new front door, the existing gates are UNCHANGED: a new
`state_manager.phase_readiness` module + `GET …/assessment/phase-readiness?phase=…` endpoint
CALL the stable `coverage_readiness` / `report_readiness` / `per_host_coverage` / `depth_ledger`
functions (and the `/coverage-readiness`, `/coverage-readiness/by-host`, `/report-readiness`
routes), which the phase-transition gate, report export, and frontend still bind to. The
deleted commands' reusable logic moved into `agent/scripts/assess/lib/coverage_checks.py`.
The terminal report/complete hard block is independent of `--strict`/`--strict-deep`.

## 2026-06-01

A consolidation-and-hardening pass: the deterministic oracle verbs are now wired into the
specialist skills that need them, the assessment package layout was split into focused
modules without changing behavior, and the verification methodology gained an explicit
holding state for findings that lack runtime proof.

### Operator workflow

- **Oracle verbs wired into specialist skills.** The deterministic assessment oracles
  (`classify-payload`, `anomaly-score`, and `oob mint|poll`) are now referenced from the
  specialist skills that should drive off them, so the Phase 2 oracles are live in the
  workflow rather than available only as bare CLI verbs.
- **Phase 5 coverage auto-re-entry.** `vigil assess check-scope-coverage --auto-redispatch`
  turns a coverage gap into a deterministic, dedup-aware recommendation naming the specialist
  and skills to run next, instead of leaving the operator to translate a gap into a dispatch
  by hand. Prior dispatches power the dedup so the same gap is not re-recommended.
- **Working-memory pin.** A specialist plan-state digest rule keeps the current plan and
  coverage picture pinned in working memory across a dispatch, reducing silent drift between
  what was planned and what the backend records.

### Verification methodology (Phase 3)

- **`pending_runtime_proof` disposition.** A sticky holding state for findings that are
  reasoned but not yet runtime-confirmed, so theoretical findings no longer have to be either
  promoted prematurely or dropped. Surfaced through `vigil assess list-findings --holding`.
- **Verification-narrative debate artifact.** A client-side `--narrative` capture records the
  argument for and against a finding alongside the finding itself, so the verification
  reasoning is durable rather than living only in a transcript.
- **Holding-area view + gates.** Definition-of-Done and the operator prompts were updated so
  the holding area is an explicit review queue rather than an implicit one.

### Assessment package consolidation (Phase 3 prep)

- **`state_manager` package split.** The single large `state_manager` module is now a package
  under `orchestrator/backend/app/services/state_manager/` with focused modules
  (`findings`, `coverage`, `chains`, `command_runs`, `dispatches`, `links`, `oob`,
  `report_readiness`, `assessment_summary`). Behavior-preserving — call sites and the public
  surface are unchanged.
- **`dispatch` package split.** `agent/scripts/assess/commands/dispatch/` replaces the former
  god-module with `agent.py`, `work_items.py`, and `handoff_renderer.py` over shared helpers,
  and the inline `sqlite3` sites were moved onto the shared `lib/db.py` helpers
  (`db_connect`, `db_exec_returning`).
- **`StrEnum` status sets.** Status values used across the split modules are promoted to
  `StrEnum` instead of bare string literals, so the allowed values are defined in one place.

### QA hardening

- **OOB mint/poll migration completed.** The remaining specialist prompts, `operator-core.md`,
  `shared-constraints`, and the lagging skills (CRLF, OAuth/OIDC, CI/CD) were migrated to the
  `oob mint|poll` surface, and the operator OOB prose was aligned to match. Adds Phase 5
  branch tests (fuzzer high-volume, no-mapped-bucket) and clamps a negative
  `--max-recommendations`.

### Eval

- **`vigil assess eval-capture`.** Snapshots a real engagement's backend findings into a
  committed golden fixture — transforming the stored `details_json` / `provenance_json`
  strings back into objects and validating against `agent/schemas/finding-record.schema.json`
  before writing. Supports a `--definition` scaffold and a `--check` regression diff. This is
  the zero-token capture path: goldens come from a real human-driven engagement and replay
  without spending model tokens.

### Code analysis (Phase 4)

- **`write-probe-script` skill.** A skill plus the `vigil assess scaffold-probe` helper for the
  runtime authoring of single-file probes: draft -> run in the Kali runtime -> validate ->
  register the artifact -> reuse. Seeded with `agent/references/probe-scripts/` so specialists
  start from a known-good shape instead of an empty file.

### Developer ergonomics (Phase 6)

- **CI gate.** A pull-request CI workflow runs `ruff` + `mypy`, the backend `pytest` suite, and
  the `tests/eval` golden replay, alongside the existing `render-check` that diffs the
  generated operator wrappers against their source.
- **Markdown-vs-CLI sync-lint.** A lint that checks the command surface documented in the
  markdown against the CLI's actual verbs, catching doc drift the way `render-check` catches
  prompt-wrapper drift.
- **Onboarding consolidation.** The "clone to first dispatch" newcomer walkthrough is
  consolidated into the root `AGENTS.md` maintainer guide and points at `README.md` for install
  and runtime detail rather than duplicating it.
- **`vigil engagement export --format markdown-tree`.** Exports an engagement's state as a
  readable markdown tree.

### Release discipline

This is a Python project: builds, packaging, and versioning go through `uv` (the `vigil` CLI is
installed with `uv tool install`, and `vigil assess` runs as a `uv run --script` entrypoint with
inline dependencies). There is no goreleaser path — version metadata lives in `pyproject.toml`.
