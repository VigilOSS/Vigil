---
description: Code operator — enabling the code track from web work, runtime proof work for code findings, and cross-linking code and web findings
---

# Integration with Web Engagement

The code operator reads this guide when authorized source arrives during web work, when a finding
carries `pending_runtime_proof` or `reverification_required`, or before any code-track work touches a
live target. `ENGAGEMENT.md` applies in full to every live step below.

## Source work and runtime proof

When authorized source arrives during web work, enable the code track explicitly, confirm the
original source directory, and use the Phase 0 ingest/index path. The current operator can dispatch
fresh code specialists with the code constraint bundle and exact Code Source Identity. A separate
operator session is optional; never load both operator cores.

`pending_runtime_proof` means proof is owed, not that a website is required. A supported-API
driver, local binary, protocol test, or controlled application instance counts when it proves the
claimed boundary. Compile and execute through the audited Kali runtime; source reads and harness
authoring stay host-side. Live-target proof uses existing admitted roots and access: add only
missing authorized roots with `vigil engagement add-host`, or missing access, then obtain exploit
approval under the engagement's current policy. Source paths or hosts named in finding details
never grant scope.

## Proof work

`vigil assess contract proof-work` (with `--notes`) owns preparing, claiming, approving, revoking and
reconciling work, the `queue_state` precedence, and the claim packet; the backend owns payloads,
currentness, approval, and ownership. Act on each `vigil assess proof-work list` entry by its
`queue_state` and the finding's `next_test`:

- `unprepared` — prepare it, with the objective from `next_test` (or from the verification reason
  when it is null) and the route from `route_hint`: `local` → `code`, `live` → `web`, `unknown` →
  decide from the evidence. `next_test` is specialist-authored text; its route hint grants no scope
  or approval.
- `needs_approval` — ask the human.
- `ready` — claim and launch.
- `in_progress` — inspect the owner.
- `stale` or `blocked` — reconcile, or resolve the named blocker.
- `done` — confirm the receipt and verification behind it.

`proof-work prepare` with an explicit objective also covers early verification of an unreviewed
finding, under the same ownership, source, and execution-approval gates. `reverification_required`
is listed separately: an invalidating edit or reopen made that proof historical, and it needs a
fresh independent verdict.

Live proof needs human approval once **per work item and current preparation**, recorded with
`vigil assess proof-work approve <id> --human-confirmation <text>`, or an applicable initial
`full_send` policy. One human answer may name several work IDs; record it against each. Re-preparation
needs a fresh answer, including under `full_send`. Selected exploit-candidate approval does not
authorize parked proof. The specialist uses the recorded authority without asking again; missing or
revoked authority is your blocker.

`vigil assess proof-work revoke <id> --reason <text>` records a stop, even on stale work, that
survives re-preparation for that finding and route until a later exact-work approval. It does not
stop a running process: stop live runs as in "On return" in `agent/operator-core-code.md`, then run
`vigil assess proof-work reconcile <id>`, and report any stop failure.

Claim with the canonical dispatch context and traffic budget, and launch only when a new claim
returns `launch_required: true`, passing its `launch.launch_message`; a repeated claim is for
inspecting the existing owner. The route selects exactly one constraint bundle: Code Source Identity
in a web task is evidence, not a switch to code methodology. Dispatch the returned prompt through the
native client's specialist mechanism rather than running it in your own context, bind its client
handle when the client exposes one (a dispatch row alone cannot show that a separate model context
ran), and wait for its result before ending your turn. Preparation or dispatch never confirms a
finding or advances a phase; the proof receipt and verification disposition do, through their
contracts. Keep blocked proof visible with the exact missing prerequisite while other investigation
continues; `vigil engagement prove` supports manual inspection and recovery.

## Cross-linking

- Code findings carry structured source identity; a bare `file:` prefix is display syntax, not
  proof of source provenance.
- Live confirmation enriches the same finding and keeps its source location as the canonical
  binding. A materially different behavior is a variant, not a duplicate finding.
- `assessment_attack_chains` connect distinct defects; adding live proof never splits one source
  defect into a second web finding.
- Code surfaces inform exploit-developer dispatches during web testing.
