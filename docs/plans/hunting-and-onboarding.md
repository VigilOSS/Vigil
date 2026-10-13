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

### Final verification

| Check | Result |
|---|---|
| Backend pytest | 4,848 passed |
| Root CLI pytest | 1,387 passed, 1 skipped, 2 deselected |
| Assessment-helper pytest | 4,834 passed |
| Deterministic evals | 60 passed |
| Frontend tests | 326 component tests, 22 library tests, 1 SSR test passed |
| Report tests | 39 rendering/PoC tests, 5 built-resource checks passed |
| Frontend and report builds | Passed |
| Ruff and CLI mypy | Passed |
| Red and blue generated-wrapper checks | Passed; generated diffs reviewed |
| Generated schema check | Passed |
| Release-workflow actionlint | Passed |
| Packaged sdist → wheel → isolated CLI | Passed in root suite |
| README local links/assets and launch-post quotes | 64 links/assets and quotes verified |

The root skip is a Git-only immutable-refspec case for which a JJ operation
snapshot does not apply. The private identity-policy audits passed in the default
workspace. Live integration tests remain opt-in. Dependency
warnings and intentionally degraded parser fixtures produced backend warnings;
the frontend build reports its bundle-size warning.

### Independent QC and live workflows

Two independent reviews and live workflow checks found and corrected:

- Concurrent initializers inserting the same proof migration record. The first
  recorded backup remains canonical and both initializers can finish.
- Stopped runtime startup accepting an outdated cached image. Managed image
  freshness is resolved before creation; running runtimes remain undisturbed.
- Shared image preparation racing container startup or a manual build. Builds,
  release tagging and startup now use shared image ownership.
- A fixed 30-second backend deadline interrupting a large migration backup.
  Health and readiness share a configurable 600-second budget, with progress
  notices and immediate failure when the backend exits.
- Proof handoffs disappearing from the candidate's resume view. Canonical
  candidate ownership now selects memory independently of execution method;
  durable claim events preserve earlier workers after release and reassignment.
- Pending or blocked findings appearing in the verified resume bucket. Only
  confirmed and downgraded findings belong there; blockers remain visible on
  active summaries.

A real native Claude Code session ingested a confirmed original directory,
inspected its sealed inventory and resume state, and exited successfully. Live
backend/CLI checks exercised idempotent preparation, atomic claims, launch replay,
competing-owner rejection, retained blockers, linked runs, restart durability,
release refusal during active execution, safe release, source-refresh invalidation,
and use of sealed source when the original was unavailable. Handoffs retained seven
next-step rationales and non-finding observations. An admitted, explicitly approved
web proof for a source candidate remained in the code investigation without
enabling a web campaign. These were workflow checks, not a bug-yield benchmark or
a completed runtime reproduction.

An existing local workspace completed its backed-up database upgrade and the
normal backend was restarted and checked ready. The disposable backend was
stopped. Docker Desktop remained manually paused: real container execution,
registry pulls and both image architectures remain untested. The image workflow
and matched application artifacts have not been published. Browser interaction
was unavailable; frontend component/SSR tests, API checks and builds passed.

The README and focused guides now describe the implemented paths. Launch titles
and body were saved to the requested home-directory Markdown file. Specialist
final-output display in the frontend remains the agreed future TODO; the proof-work
UI is included.
