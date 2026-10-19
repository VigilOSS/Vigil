# OpenCode / ZCode implementation review handoff

## Review boundary

Review jj change `zvooxymr` relative to parent `oqyvmrnr` (snapshot `20ebdd0c`).
The parent preserves the main workspace's existing release-reliability and
engagement-guidance edits. This change was created with the owner's approval;
no bookmarks were moved, and no PR, push, or merge was performed.

The implementation initially used an ordinary isolated source copy. Before
transferring its delta, every changed existing file was compared with both the
copy's starting baseline and the current main workspace. All matched that
baseline; there were no overlapping edits requiring conflict resolution.
Only the implementation delta was transferred, not caches, dependencies,
packaging metadata, or unrelated files. Work then continued in the default
workspace. The unrelated existing conflict on the `main` bookmark was untouched.

Use `jj show zvooxymr --stat` and `jj diff --from oqyvmrnr --to zvooxymr` for
the exact inventory and patch. Change IDs remain stable as this work is refined.

## Additions relative to the existing main workspace

| Owner / paths | Change and reason |
| --- | --- |
| `src/vigil_cli/assessment_clients.py` | New web/code launch and immutable native-context preparation. Absolute matched helper, resolved tool paths, per-engagement/mode workspace, collision-preserving writes, release retention guard before preparation, GUI instructions without a false process/session receipt. |
| `src/vigil_cli/client_checks.py` | New read-only prerequisite/context diagnostic. Checks dependencies, application metadata, explicit bindings, managed pointers/digests and historical native receipts without services, providers, app activation, repair, or active-pointer discovery. |
| `src/vigil_cli/main.py`, `engagements.py`, `preflight.py` | Register ZCode web/code starts and client-check; route OpenCode web/code through native configuration/authentication. Existing Blue/remediation launch paths remain separate. |
| `agent/scripts/render-operator-prompts.sh`, `agent/commands/*.md` | Generate assessment-specific commands and model-neutral native role trees from canonical sources. Web-only commands retain their mode limitation; compaction instructions describe native capabilities honestly. |
| `agent/.opencode/assessment/` | Generated seven commands, operator and specialist wrappers. Global native model/approvals preserved; ancestor engagement config excluded through launch flags and the explicit native config directory. |
| `agent/.opencode/plugin/assessment-hooks.js` | Native tool activity adapter, awaited preservation hook, request-time summary recovery, operator/specialist routing, revert and ambiguous-request handling, binding-qualified observations. Uses the native-discoverable `.js` suffix when staged. |
| `agent/.zcode/assessment/` | Native plugin/marketplace, seven commands, flat specialist wrappers with automatic AGENTS injection disabled, and process hook adapter. SessionStart restoration supports canonical and legacy scalar scopes; explicit specialist events do not load operator recovery. |
| `agent/scripts/hooks/post-tool-log.sh` | Atomic client/session/tool-call deduplication for native IDs. Existing no-ID policy retained; definite failed delivery releases its claim. |
| `agent/scripts/assess/lib/contract_registry.py`, `instruction_identity.py`, backend `app/api/assessment_operator.py` | Admit asserted ZCode client metadata and correct native role paths. Provider-observed identity remains unknown; proof, scope and approval gates are unchanged. |
| `README.md`, `docs/zcode-setup.md`, `docs/agent-clients.md`, `docs/session-commands.md`, `CODE-MAP.md` | Setup, exact project path, missing-setup bootstrap, model selection, diagnostic semantics, lifecycle limits and ownership map. |

Generated Claude/Codex compact wrappers have only renderer-produced whitespace
changes; their executable lifecycle behavior is not replaced. No remediation
production implementation or Blue prompt sources were edited by this change.

## Tests added or adjusted

- Native starts and argument merging, dual-mode binding, filesystem collisions,
  no-follow checks, native asset discovery and model inheritance.
- Diagnostic purity, missing dependencies, explicit context selection, executable
  integrity, managed links, plugin inventory/release checks and historical-only
  receipt interpretation.
- Protocol tool normalization, failure-event attribution, binding-qualified
  receipts, retryable receipt writes, native call deduplication and concurrency.
- Compaction preservation, summarizer exclusion, ambiguous unfinished requests,
  title/ordinary callback recovery, successful summaries, specialist isolation,
  native child sessions and reverted summaries.
- Generated workspace routers reuse the canonical specialist stop-sign, so
  auto-loaded operator bootstrap instructions do not apply to specialists.
- Backend asserted-client validation, retaining unknown provider-observed identity.
- Existing preflight tests now assert native authentication for web/code OpenCode;
  the Blue fixture declares its actual Blue scope and retains its DeepSeek guard.
- Existing entrypoint mocks now intercept native adapter delegation. The initial
  stale execv mock allowed one disposable pytest worker to become OpenCode; only
  that exact task-owned process was stopped, and the corrected tests prevent it.
- Release-retention fixture seeds a real old process receipt and verifies that
  incompatible-release launch is refused before native workspace preparation.

## Verification evidence

All checks below ran in the default workspace unless noted otherwise:

- Backend: 4,979 passed; four initially suspicious remediation approval cases also
  passed serially. Earlier isolated-copy failures did not reproduce in main.
- Assessment CLI: 4,898 passed. Evaluations: 60 passed.
- Frontend: 355 tests passed and production build passed.
- Report: 44 tests passed and production/resource verification build passed.
- Ruff, mypy over the complete CLI, schema freshness, and red/Blue render checks
  passed. Frontend emitted its existing chunk-size warning.
- Frontend/report used existing default-workspace dependencies; clean `npm ci`
  plus test/build had also passed in the earlier isolated source copy.
- Root suite: 1,635 passed and one expected not-applicable skip (the Git variant
  of a jj-operation-snapshot check). The final router-prefix change also passed
  its 46-test impacted set. Total across the main suites: 11,971 passed.
- Independent QC identified and re-reviewed filesystem, hook-protocol, request
  attribution, ancestor-config contamination and native plugin-discovery fixes.
  Its final review found no remaining concrete implementation defects.
- Real native OpenCode configuration checks passed on installed 1.18.10 and
  official checksum-verified 1.19.3, with network denied and all writable state
  disposable. They proved native global model/approval retention, exclusion of
  ancestor config, plugin and seven-command discovery, and the absolute router
  instruction. They did not prove model requests or hook/lifecycle execution.
- ZCode 3.15.3 opened the generated disposable workspace and accepted its local
  marketplace. The setup guide includes the observed sidebar UI path. Plugin
  installation/execution requires separate action-time confirmation.

## Native verification still required

Do not equate mocked protocol tests, native config discovery, historical receipts,
or opening a GUI workspace with a working native engagement conversation.

- Actual entitled GLM model requests in both clients, all command invocations,
  real specialist dispatch/tool activity, and canonical backend hydration.
- Manual and automatic/overflow compaction on each exact native build; ZCode
  engine identity and real SessionStart(compact) delivery need acceptance.
- ZCode plugin installation/enablement and fresh-task startup context delivery.
- Full live engagement and runtime/container integration tests. These were not
  run against the operator's active engagement or live services.
- ZCode has no documented equivalent establishing PreCompact steering, exact
  native conversation attachment, or terminal SessionEnd. These are explicit
  capability limits, not implemented guarantees. Hard termination is unobservable.

For ZCode, open the exact generated `workspace:` path printed by
`vigil engagement start`, not the canonical engagement root or source checkout.
See `docs/zcode-setup.md` for plugin, model, fresh-task and verification steps.
