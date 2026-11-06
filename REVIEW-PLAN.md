# Vigil review follow-up plan

Review, 2026-11-07: six initial reviewers, three deeper reviewers,
then an independent verifier. Implementation and release were subsequently
approved, with correctness and test speed as the scope. Preserve operator
flexibility; measure agent behavior before broader prompt or workflow changes.

The second pass observed `dd408064d145` against its parent, following the initial
`5af1df21` review. Working files changed concurrently without the snapshot ID
moving; dispositions below describe the contents actually checked. Re-run the
focused reproductions against the implementation baseline before editing.
Intent was assessed against the changelog, executable contracts and ADRs.

Implementation status: the nine fixes below are implemented or confirmed in the
updated tree. An independent verifier passed the completed changes after two
CLI edge cases were corrected. Test HTTP shutdown waits were reduced without
changing assertions. The opt-in protocol is in `tests/behavior/README.md`; live
trials remain unrun, and handoff policy and broader prompt behavior are unchanged.

## Agreed fixes

All nine open findings have high confidence. Implement each with a failing
behavior regression first, then run the owning suite.

| Order | Severity | Owner / change | Required regression outcome |
| --- | --- | --- | --- |
| 1 | Major | `agent/scripts/assess/lib/treesitter_index.py`, `_php_quoted_spans`: preserve executable PHP interpolation while excluding literal text. | `"{$pdo->query($sql)}"` retains its SQL sink; inert quoted examples do not produce one. |
| 2 | Major | `agent/scripts/assess/commands/code_classify.py`, `run`: reject duplicate resolved file IDs across the entire normalized input before any batch POST. | Duplicates spanning rows 1 and 501 cause no classification writes. |
| 3 | Major | `agent/scripts/assess/commands/dispatch/agent.py`, `_union_dispatch_finding_slugs`: stop a read-dependent update when the read fails. | A failed GET followed by an available PATCH cannot erase existing associations. Consider atomic addition at the backend owner separately for concurrency. |
| 4 | Major | `orchestrator/backend/app/services/state_manager/proofs.py`, `proof_receipts_for_finding`: resolve the current decision before choosing its receipts. | A newer receipt-free authority decision has no current receipts; kept edits preserve the current proof decision. Verify evidence-health and reproduction-basis projections too. |
| 5 | Major | `orchestrator/backend/app/services/state_manager/report_readiness.py`: recognize attributed severity-band divergence for a current terminal authority verdict. | An authority downgrade does not demand the variance that authority verification prohibits; CVSS vector/score arithmetic errors still block. |
| 6 | Minor | `agent/agents/code-vuln-verifier.md`, closing preflight: use the canonical finding/report-readiness projection for code findings. | Code-only and mixed engagements inspect relevant evidence/root-cause blockers before verification, without requiring post-verdict blockers to be cleared first. Adding `--phase` to the existing command is insufficient. |
| 7 | Minor | `orchestrator/frontend/src/lib/findingWorkflow.ts` and finding evidence views: distinguish prior authority from current verification. | After invalidation, an unreviewed finding retains its durable waiver history but does not describe that waiver as current verification evidence. |
| 8 | Minor | Finding transition summary projection and `orchestrator/frontend/src/components/FindingsTab.tsx`: carry compact authority qualification. | A collapsed historical authority verdict is qualified before its details are fetched. |
| 9 | Minor | `agent/scripts/assess/commands/code_dispatch.py`, `_queue_rows_by_item_id`: targeted ID retrieval or complete traversal. | A valid row beyond 50,000 is found; incomplete lookup is never reported as absence. |

The original streaming 64 KiB comment-boundary reproduction now passes in the
current files. Retain it as a regression and check chunk-partition invariance,
including split delimiters. Full partition invariance is not yet established.

## Behavioral follow-up

1. **Measure handoff qualification before changing its contract.** This is a pre-existing behavior gap,
   not an additional tip regression: a missing-artifact refusal leaves a stored
   ready handoff that closure can consume as completed. Preserve authored summaries
   and checkpoints; distinguish required deliverables from optional scratch paths
   before deciding whether readiness/closure needs a behavior change. Preserve explicit,
   attributed operator overrides. Do not introduce a universal artifact gate.
2. **Add deterministic lifecycle scenarios in the owning suites.** Cover
   record → verify → invalidate → reverify → readiness/export, and
   claim → checkpoint → output/read failure → recover → close. Assert durable
   state, proof currency, ownership and recoverability, including negative cases.
3. **Then add a separate opt-in live behavioral baseline.** Start with one
   supported client, synthetic Acme fixtures and the actual packet/launch path.
   Repeat verifier preflight, context-reset recovery, incomplete/no-lease returns,
   target-text containment and broad hunting across seeded defect families.
   Record client/model/prompt identities, traces, final database state and
   infrastructure failures separately from task failures. Score precision and
   recall; accept valid alternative tool paths. Do not run live trials as part of
   this read-only review or replace the existing offline JSON eval contract.

Vigil already has digest-bound packets, bounded retrieval, durable checkpoints
and resume hydration. Keep those mechanisms and measure their effect before
further prompt changes. Primary guidance supports task-specific tool/handoff
evaluations, environment-outcome grading and incremental progress across context
boundaries: [OpenAI evaluation best practices](https://developers.openai.com/api/docs/guides/evaluation-best-practices),
[Anthropic agent evals](https://www.anthropic.com/research/demystifying-evals-for-ai-agents),
[Anthropic long-running harnesses](https://www.anthropic.com/research/effective-harnesses-for-long-running-agents),
[Google behavioral harness evaluations](https://developers.googleblog.com/en/the-anatomy-of-harness-engineering-how-to-evaluate-iterate-and-guard-ai-coding-agents/).
The recommendations above are our application of that guidance to Vigil.

## Boundaries and validation

- Preserve ADR 0043 waiver persistence. Automatic backend revocation on
  invalidation is rejected; fix prior/current presentation instead.
- Preserve source attestation, proof independence, exploit approval and publication
  gates, and verbatim evidence with ADR 0018 containment. No new orchestration
  framework or wholesale prompt expansion is justified by this review.
- Final local blocking matrix: backend 5,913 passed; root 2,135 passed and four
  adapter-specific Git/Jujutsu skips; assess 6,378 passed; offline evals 60 passed;
  frontend 871 passed; report 68 passed. Both UI builds, Ruff, mypy, generated
  schemas, and red/blue prompt checks passed. Two report browser/PDF integration
  tests and ten public-example checks also passed.
- One initial backend run detected a source edit made while its modules were
  loaded; the final complete run above passed with implementation edits stopped.
  The verifier passed the final corrections and the two-worker CI configuration.
- An activity test group measured 21.40s before versus 10.97s after test-server
  shutdown changes; concurrent load limits exact attribution. Assertions and
  real-transport coverage are unchanged.
- Live client/model trials remain unrun. Runtime-container integration tests are
  excluded by the normal blocking matrix and need a prepared live runtime.
