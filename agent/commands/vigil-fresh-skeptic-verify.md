---
name: vigil-fresh-skeptic-verify
description: Dispatch a fresh low-context specialist to attack a finding as a hostile triager would
---

<!-- vigil:only claude -->
Finding to verify: $ARGUMENTS
<!-- vigil:end -->
<!-- vigil:only codex -->
Verify the finding the operator named in their message. If they did not name one, ask which.
<!-- vigil:end -->

Dispatch a **fresh, low-context** specialist for this. Fresh is the whole point: a specialist
that already helped build the finding will confirm it, and confirmation is not verification.
Give it the evidence and the target, not your conclusion.

Frame the dispatch as a skeptical triager and maintainer whose job is to kill the finding.
It must answer, with evidence for each:

- **Real-world impact, or just a band fit?** Does this actually harm someone, or does it merely
  match the shape of a severity band?
- **What in the code kills it?** Hunt for the guard, the filter, the framework default, the
  downstream validation. **Trust the code over the documentation** — the docs describe the
  intent, the code describes the behaviour, and they disagree more often than not.
- **Is it expected?** Public by design, already-privileged, documented behaviour, a deliberate
  product decision, or a feature the vendor will point at and close.
- **Is the evidence complete?** What is asserted but not shown? A missing request, a missing
  response, a step that "should" work — each is a place the finding falls apart under triage.
- **Are the preconditions honestly stated?** Would a triager consider them realistic?

Tell it to hunt **downgrades**, not confirmations, and to bullet exactly what is off.

Then bring back a recommendation — **confirm / downgrade / kill** — with the reasoning, and
apply it to the backend record. If the verifier killed it, kill it; do not relitigate a finding
back to life because it was expensive to produce. A finding that dies here would have died at
triage anyway, and dying here is free.
