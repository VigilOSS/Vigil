# OpenCode and ZCode web/code compatibility

Status: approved for implementation; independent cold review incorporated.

## Boundaries

Maximize practical Claude/Codex compatibility for OpenCode CLI/TUI stable 1.x and
ZCode desktop on macOS in web/code engagements. Preserve existing remediation and
Blue behavior, native approvals, scope admission, proof ownership, evidence, and
asserted-versus-provider-observed client identity. No MUX Beacon integration was
found; do not remove unrelated Mux dependencies or Beacon detection examples.

Implementation began in an isolated source copy. The owner subsequently approved
transferring the changes into the default workspace, preserving existing work as
the parent of one new jj change. Complete implementation and verification there.
Do not change the running engagement, live install, services, containers, or
authentication. No push, PR, or merge before separate owner approval.

## Setup and launch

- Add ZCode web/code start and mode selection, client registrations, mirrors, and
  generated schemas together. Reject unsupported modes and desktop CLI flags.
- Add read-only `vigil engagement client-check [key] --client opencode|zcode
  [--mode web|code] [--json]`, reusing doctor check representation. Pure shared
  diagnostics must never start services, repair files, materialize caches,
  create sessions, authenticate, or contact model providers.
- Report missing, unreachable, stale, and unverified prerequisites actionably.
  Distinguish installed hook configuration, real startup dispatch, real compact
  dispatch, context injection, and actual backend hydration.
- Use native selected models and authentication. OpenCode web/code must not
  require DeepSeek credentials or pin specialist models. Explain native Z.AI
  GLM Coding Plan setup; do not rewrite global configuration or credentials.
- Prepare an immutable ZCode workspace per release, engagement, and mode, with
  a bounded AGENTS router, explicit context binding, absolute matched helper,
  and explicitly resolved executable dependencies. Open that generated workspace
  in ZCode, not the Vigil source repository or an arbitrary source project.
- A reused GUI app does not inherit launcher environment. Supply literal paths
  and context-bound helper guidance to operators and specialists. Do not wrap
  every Bash command or change permission classification/cwd tracking.
- Use supported macOS workspace opening and explicit plugin enable/new-task
  instructions. Workspace-open success does not mean a conversation is ready.
- Reuse digest-based freshness, no-follow atomic preparation, collision reporting,
  selected-engagement repair, and retained immutable assets. Never use transient
  macOS `open` PIDs as live client-session ownership.

## Native assets and lifecycle

- Render seven assessment commands for both clients from canonical sources with
  complete client syntax/arguments. Start/resume/handoff/compact work in both
  tracks; web-specific commands explain their code-mode limitation without
  changing mode. Keep remediation/Blue assets and behavior separate.
- Render assessment-specific model-neutral OpenCode roles. Package ZCode commands,
  flat specialist roles, and hooks as a native plugin. Specialists explicitly set
  `injectAgentsMd: false` and receive their canonical mandatory context and tools.
  Do not introduce a nested code-lead hierarchy; the current operator is flat.
- Normalize supported tools, responses, native session/call IDs and role attribution
  through the existing activity path. Preserve logging-noise/recursion policy;
  add no command-execution filters or approval bypasses. Native IDs use atomic
  client/session/call deduplication and bypass text/time fallback deduplication.
- OpenCode: awaited compaction hook supplies the canonical preservation contract
  and current COMPACT.md. Awaited request-time context restores the selected mode
  after compaction; an asynchronous session.compacted event alone is insufficient.
- Correlate the current unfinished assistant request and successful completed
  summary through the native SDK, excluding summarizers and distinguishing
  operators/specialists. Respect reset/revert; ambiguous correlation produces a
  stop diagnostic without consuming pending recovery state.
- ZCode: implement documented SessionStart(compact) restoration but advertise it
  only after native acceptance on the exact desktop/engine build. Upstream issue
  357 reports missing dispatch on an older engine. Failed verification leaves
  explicit limited capability and manual resume instructions.
- Do not claim ZCode PreCompact, custom summarizer, a 510000-token setting, terminal
  SessionEnd, or exact native conversation attachment. Stop/idle/deletion are not
  termination. Hook injection does not prove completed hydration.
- Keep explicit backend checkpoints/handoffs as durable memory. Never invent
  intent at shutdown. A verified OpenCode launcher-process exit may have a
  distinctly labeled process receipt; hard termination remains unobservable.

## Documentation and acceptance

- Update README onboarding, a dedicated Markdown ZCode setup guide, client and
  session-command docs, and CODE-MAP together. State exactly which generated
  workspace to open, how to enable the local plugin/hooks, select Coding Plan and
  model, start a fresh task, verify operation, and recover from missing setup.
  Include bootstrap guidance independent of enabled hooks.
- Test-only isolation around system/user ZCode app discovery precedes feature
  work; preserve remediation production discovery. Planning baseline was 107
  passed and seven failures caused by the real system app shadowing fixtures.
- Failing-first executable tests cover command/argument/mode contracts, model
  inheritance, cold/warm GUI launch, concurrent engagements/modes, malformed
  bindings, no-follow collisions and repair, minimal GUI dependencies, activity
  dedup/attribution/failure, backend outages, manual/automatic/overflow compaction,
  COMPACT.md changes, reset/revert, and release retention. No wording/removal tests.
- Run impacted scopes and the full repository blocking matrix. Native candidate
  matrix is OpenCode 1.18.10 minimum and 1.19.3 stable, plus ZCode 3.15.3 (record
  engine version too). Raise the minimum if the lower candidate fails required
  gates. Mocked/stubbed verification is not native acceptance.
- Use only isolated test resources. Native GUI tests must not disturb the active
  engagement. Independent QC reviews the completed implementation and fixes.
  Report untested end-to-end behavior explicitly for owner verification, then
  let the owner review before a PR.

## Primary research

- https://opencode.ai/docs/plugins/
- https://opencode.ai/docs/providers/#zai
- https://zcode.z.ai/en/docs/plugin
- https://zcode.z.ai/en/docs/subagents
- https://zcode.z.ai/en/docs/hooks
- https://github.com/zai-org/feedback/issues/357

