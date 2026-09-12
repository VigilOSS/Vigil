---
name: vigil-escalate-honestly
description: Escalate a finding on real impact — entrypoint, mechanism, attacker outcome — without inflating it
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-escalate-honestly.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

Escalate the finding the operator named in their message. If they did not name one, ask which
before doing anything else — escalating the wrong finding wastes a full cycle.

Work the escalation in this order and stop where the evidence stops.

**1. Real-world entrypoint.** Who can reach this, from where, holding what? An unauthenticated
internet-facing path and a same-tenant authenticated path are different findings. Name the
actual precondition set, not the most favourable one.

**2. Mechanism.** What is the defect, precisely — at the level of the code or the protocol
behaviour, not the scanner's label. If you cannot state the mechanism, you do not yet have a
finding, you have an observation.

**3. Attacker outcome.** What does the attacker end up holding? Data, an identity, execution,
persistence, money. Be concrete: which records, whose account, what scope.

**4. Can it go higher?** Look for a sibling with a weaker guard, or a chain where this is the
first link. Escalation by chaining is usually where the real severity is, and it is the step
most often skipped.

**5. Score the INCREMENTAL impact.** This is the discipline that matters. Grade what this adds
*over what the attacker already has* at the stated entrypoint. An authenticated user reading
their own data through an unusual route is not an access-control finding. If a precondition
already implies the outcome, the increment is zero and you should say so.

**6. Stop at proof of impact.** Do not keep exploiting past the point that proves it. Do not
touch data you do not need to touch to demonstrate it.

Then report: the honest severity with the reasoning that produced it, the evidence backing
each step, and explicitly — anything you could **not** substantiate. If the finding is weaker
than it first looked, say that plainly. Downgrading on your own evidence is a good outcome,
not a failure.

Record the outcome to the backend before you report.
