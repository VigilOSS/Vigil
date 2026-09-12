---
name: vigil-triage-reply
description: Assess a program's pushback on a submission and decide whether to rebut, resubmit, or drop
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-triage-reply.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

Assess the program pushback the operator described in their message. If they did not say which
finding and what the program said, ask for both before doing anything else.

Dispatch a **fresh, low-context** specialist. Your own attachment to the submission is exactly
the bias that produces a bad rebuttal, and a bad rebuttal costs reputation with the program.

Give the specialist three things and no conclusion: the finding record, the submission as sent,
and the program's reply verbatim. Ask it:

**1. Is the pushback fair?** Judge it on the merits. Programs are right a large fraction of the
time, and the honest answer is often "they are right".

**2. If we should push back** — draft a concise, professional reply that proves impact with
evidence. Constraints on that draft:

- It goes **here, to the operator, for review** — never straight into the submission.
- Only worth sending if it will actually **end** the pushback. A reply that restates the
  original submission in a firmer tone changes nothing and burns goodwill.
- Lead with the evidence that answers their specific objection, not with the general case.
- No indignation, no severity argument by assertion, no appeal to the VRT table alone.

**3. If they are right** — say so, and recommend one of: resubmit under a different VRT with
the correct framing, consolidate into an existing finding as the same root cause, or drop it.
Recommending "drop" is a legitimate, valuable outcome; a program relationship is worth more
than one contested P4.

Then report the recommendation with reasoning, and the draft reply if there is one. Record the
outcome and any state change against the finding in the backend before you report.
