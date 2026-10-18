# Hunting and onboarding implementation plan

## Agreed outcome

Make Vigil easier to start, preserve broad bug discovery and useful specialist
reasoning, and carry source-backed candidates through skeptical runtime proof.
Native Claude Code and Codex conversations remain the interface. The backend owns
durable work, evidence and claims. Human review remains essential.

## Implementation contract

1. Keep broad source review, fresh hostile rereads, cross-module reasoning and
   variant searches. Discovery missions name the surface and objective, rather
   than presupposing a bug. Proof missions challenge a candidate and can confirm,
   disprove, revise or block it. Source context does not silently select a route.
2. Use fresh specialists from the existing operator, with one explicit code or
   web method. Supply relevant evidence references and context on demand. Preserve
   the method; do not impose arbitrary prompt-byte or response-word quotas.
3. Add persistent proof work referencing canonical finding obligations, source
   identity, route, objective, targets, approval and execution ownership. Prepare
   idempotently; claim and dispatch atomically. Show owed work even before it is
   prepared. Revalidate currentness. Do not reclaim work merely because time
   passed or a native client exited. Reconciliation is explicit; resume is a read.
4. Local code proof runs in audited Kali without requiring web hosts. Live proof
   reuses admitted roots and existing exploit policy. New roots and required
   approval still require the human. Preparation never confirms a finding or
   advances an engagement phase. Fix pending-proof selection through a separate
   proof-specific approval path, not by weakening ordinary exploit candidates.
5. Expose agent-facing proof-work helpers, manual engagement prove recovery and
   an actionable proof-work UI showing owners, blockers, evidence and recovery.
   No browser chat or unattended native-client restart supervisor.
6. Require attributed independent recorded reviewers for new or changed
   blind-triage acceptances. Preserve unchanged accepted historical packets and
   audit records. Recorded identities do not prove reasoning independence.
7. Use install, engagement create, and engagement start as the onboarding path; doctor owns optional host-tool setup. Recover only
   the default managed backend. Start required services on demand; capture and
   OOB are optional capabilities. Keep explicit full-stack startup. Serialize
   shared startup and never interrupt another engagement's active services/jobs.
8. Register --source-dir without staging a second source tree. After explicit
   source confirmation, seal one audit snapshot directly from the original.
   Preserve manual source-folder intake. Missing originals prevent refresh, not
   use of an already sealed generation. Keep the original untouched.
9. Support pinned prebuilt Linux AMD64/ARM64 runtime images and release automation
   with content-digest verification, retaining deliberate local builds. Image
   publication and live architecture validation must be reported separately.
10. Preserve a reasoned specialist handoff: outcomes, material observations,
    uncertainty, next tests and why. Use existing handoff/intel state; no extra
    investigation file or operator acknowledgement ceremony. Optional prose can
    explain unexpected connections. Frontend specialist-final-output display is
    a future TODO, distinct from the included proof-work UI.
11. Update the entire README in simple concrete language, documenting implemented
    behavior and the limits of coverage/verification. Save launch titles/body to
    ~/writeup.md without posting them.

## Verification

Run behavioral regressions red before production changes and green afterwards.
Exercise concurrent startup/claims, recovery without duplicate workers, proof
route/approval separation, source refresh and accepted-packet upgrades. Keep
backend models, migrations, CLI metadata, schemas and live callers together.
Regenerate and review red/blue prompt wrappers. Run the complete blocking matrix
from AGENTS.md and independently review plan fidelity. Report failures, skips,
live-runtime and image-publication limitations explicitly. Do not claim better
bug yield from ledger correctness or offline tests.

## Implementation record — 2026-10-18

The implementation covers the contract above. The main executable owners are:

- `src/vigil_cli/host_tools.py`, `preflight.py`, `service_locks.py`, and `runtime.py`:
  selected prerequisites, managed backend recovery, serialized shared startup and
  first-use runtime execution. Native Linux onboarding leaves host recon optional.
- `src/vigil_cli/engagements.py`: original-directory registration, source inventory,
  and confirmation/resume messages. Existing code-ingest owns the sealed copy.
- `orchestrator/backend/app/services/state_manager/proof_work.py`: canonical
  candidate/source/scope binding, atomic ownership and dispatch creation, exact-work
  approval, progress retention and explicit recovery. Claims return whether native
  launch is required; replay never grants another launch. Unrelated selected-target
  approvals do not invalidate an unchanged candidate's authorization.
- `orchestrator/backend/app/db_proof_work_schema.py`: additive scheduling schema;
  database initialization backs up existing state and records the migration.
- `agent/scripts/assess/commands/proof_work.py` and `src/vigil_cli/main.py`:
  agent-driven proof work and manual `engagement prove` inspection/recovery.
- `orchestrator/frontend/src/components/ProofWorkTab.tsx`: pending candidates,
  owners, blockers, evidence links, preparation, approval and safe recovery.
- Reviewer attribution is validated by the existing decision owner. Historical
  accepted packets retain their original audit identity and exact-content checks.
  The handoff renderer and resume brief expose reasoning, observations and next
  tests through the existing fields; canonical prompts preserve detailed returns.
- `src/vigil_cli/runtime_images.py` and `.github/workflows/runtime-release.yml`:
  digest-pinned runtime delivery and matched application release preparation.

Independent review reproduced and corrected duplicate ownership through reworded
objectives, wrong-route roles, lost owner progress after claim edits, premature
release while detached jobs remain active, and shared startup/image replacement
races. Discovery remains a model task; these tests do not establish comparative
bug yield or prove independent reasoning.

### Release verification

Release readiness is established by the blocking matrix in `AGENTS.md`, focused
regressions for the contracts above, an isolated packaged-CLI smoke test, and
independent review of the complete change. Exact results belong in the pull
request and release record so this plan does not become a stale test snapshot.

Native OpenCode acceptance covers session startup, context delivery, and clean
exit. ZCode remains a preview until its desktop plugin activation, model selection,
compaction, and resume behavior can be exercised in the native application.
Registry publication and anonymous digest pulls for both supported architectures
must be verified from the release workflow before publishing the release.

These checks establish workflow and state-contract behavior. They do not establish
comparative bug yield or prove that two recorded reviewers reasoned independently.
