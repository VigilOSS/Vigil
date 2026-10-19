# Steering an engagement

These optional prompts deepen an engagement that already has a selected Code or Web operator.
Normal phase work continues without repeating them. Replace bracketed values with your target;
keep the engagement's recorded scope, approval, rate limits and source identity in force.
For client commands and resume hooks, see [session commands](session-commands.md).

## Code hunting

The normal hunt already includes a developer-focused lens. Intake, mapping, conditional variant
analysis and fuzzing remain part of the [Code workflow](../agent/operator-core-code.md#phase-index).
First ingest and explicit refresh require human confirmation of the source and trust in its
build/test code. Ordinary resumption uses the sealed source; it does not require ingesting again.

### Investigate related files together

Use when small isolated assignments are missing relationships between functions.

> Group related files into coherent small batches and give each specialist a concrete boundary
> to investigate, with room to follow relevant callers and callees. Trace attacker-controlled
> inputs through guards and sinks, and record supported findings, negative evidence and unresolved paths.

Outcome: attributable coverage and evidence for each boundary, with specific follow-up work.

### Challenge completed coverage

Use when a file or module is marked complete but the evidence looks shallow.

> Review the recorded coverage for [module] against the sealed source and threat model. Identify
> the important paths that were actually checked, then dispatch focused follow-up for gaps in
> input handling, authorization, error paths or cross-module behavior; explain what the new evidence changes.

Outcome: confirmed coverage or named gaps with owners, without silently resetting prior work.

### Take a fresh developer-focused pass

Use when you want an independent look at assumptions behind a component.

> Dispatch a fresh specialist over [component] without prior hunter conclusions, preserving the
> necessary source and threat context. Examine assumptions, guards, alternate and error paths,
> and guarantees passed between modules; report concrete counterexamples or evidence that the guarantees hold.

Outcome: an independent assessment. Relevant variants follow the normal conditional workflow;
you do not need to request a variant pass after every finding.

## Web phases

### Recon: establish the reachable surface

> Review recon for the admitted hosts and distinguish observed live services from unresolved
> discovery leads. Fill concrete DNS, service and route-discovery gaps within the rate budget,
> and show which surfaces are ready for collection and which remain blocked.

Outcome: a supported surface inventory and explicit uncertainty.

### Collect: connect routes to inputs

> Deepen collection for [application] using discovered pages, scripts and API descriptions.
> Connect routes, methods, input locations and authentication contexts to recorded surfaces,
> then identify missing samples that prevent meaningful tests.

Outcome: actionable inputs and request variants, rather than an unexamined URL list.

### Consume-test: deepen testing

> Review [surface] for applicable vulnerability families and follow the most consequential
> untested boundaries, including alternate methods, encodings and error handling. Use controls
> to distinguish target behavior from tool failure, and retain inconclusive results with their blockers.

Outcome: evidence-backed coverage and candidates worth independent verification.

### Consume-test: provision distinct accounts

> Identify the account roles and owned objects needed to test [authorization boundary]. Use
> genuinely distinct authorized accounts and objects, or tell me exactly what access is missing;
> compare the allowed control with the cross-account attempt before claiming a failure.

Outcome: a valid actor/ownership comparison, or a precise provisioning request.

### Verify: challenge the candidate

> Dispatch a fresh verifier for [finding] with the evidence and required threat context, without
> the hunter's conclusions. Reproduce the supported path, test competing explanations and guards,
> and record confirm, downgrade, disprove or an explicit runtime/access blocker.

Outcome: an independent, durable verdict with the required proof and controls.

### Exploit: prove bounded impact

> For [finding], propose the smallest test that demonstrates the incremental attacker impact
> within admitted scope. Use current approval, or ask me once for the missing authorization before
> launch; stop at the bounded proof and record the result, controls and cleanup.

Outcome: attributable proof. The specialist checks the operator's recorded decision and does
not ask for it again. An explicit revoke blocks the work even under `full_send`.

### Report: rehearse before submission

> Prepare a standalone report for [finding] that matches the demonstrated actor, prerequisites
> and impact. Have an independent reviewer rehearse its reproduction from the supplied instructions,
> then resolve missing evidence and unsupported claims before giving me the draft to review.

Outcome: a reproducible report with remaining limitations visible. This does not send a submission.

## Either track

### Resume from recorded state

> Restore the selected operator mode and read the backend resume state and relevant handoffs.
> Reconcile existing workers, runs and proof ownership before starting replacements, then continue
> the next supported action and tell me about blockers that require my input.

Outcome: continuity without duplicate workers. A closed chat or old timestamp does not establish
that detached execution ended.

### Get a read-only status

> Give me a read-only account of current coverage, findings, active workers and proof obligations.
> Name each material blocker, its evidence and the next action or decision needed; distinguish
> parked runtime proof from findings needing verification again after a claim changed.

Outcome: an actionable status. This grants no approval, releases no owner and starts no test.

### Coordinate concurrent work

> Inspect the current ownership and handoffs before assigning [area]. Preserve work another
> specialist owns, divide independent tasks where useful, and reconcile unexpected state changes
> before deciding whether a replacement is needed.

Outcome: clear ownership and useful parallel work without competing writes or duplicate execution.

### Turn a source lead into proof

> For [finding], determine whether the supported API or binary can reproduce the claim locally,
> or whether it needs a specific admitted live target. Prepare that explicit route, obtain any
> missing live approval once, and dispatch a fresh specialist to confirm, disprove, revise or block it.

Outcome: proof attached to the same finding, with source identity preserved. A local proof does
not require a website, and one live test does not require a broader Web campaign.

### Challenge impact and severity

> Have an independent specialist challenge [finding]'s attacker prerequisites, supported entrypoint
> and incremental impact using the evidence and threat model. Test whether existing privileges or
> guards change the claim, then recommend the severity the demonstrated outcome supports.

Outcome: a defensible claim, including a downgrade or unresolved limitation when warranted.

### Assess triage feedback

> Review [finding], our submitted report and this feedback: [response]. Have a fresh specialist
> assess whether the criticism is fair; if evidence supports a reply, draft a concise response for
> my review, otherwise explain the correction or additional proof needed.

Outcome: a fair assessment and optional draft. Sending a reply requires your separate instruction.
