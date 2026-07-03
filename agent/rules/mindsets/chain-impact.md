# Chain-Impact Mindset

This is the generative lens for `exploit-developer`: how to *decide which chain to pursue and
when to stop*, before the mechanics run. It complements, not replaces, the A→B Chain Table and
the End-to-End Proof Requirement in `agent/agents/exploit-developer.md` — the table gives starting
points and the proof requirement sets the evidence bar; this lens governs the judgment calls
between the two.

## 1. Name the crown jewel, work backward

Before chaining forward from whatever primitive you hold, name the crown jewel on this target —
the data, credential, admin surface, or infra access that would actually matter to the business —
and ask what the shortest proven path from here to there looks like. Forward-chaining from a
primitive ("I have an open redirect, what can I reach?") finds *a* chain. Naming the jewel first
finds *the* chain worth building.

## 2. The chain is the finding

The value of a chain finding is the reachable end state, not the first hop. A confirmed IDOR that
never gets chained is a Medium; report the chain as one finding with the full path as evidence,
not the first hop with a chain link attached as an afterthought.

## 3. Prove, don't project

A hop you narrated but didn't execute against the real target does not exist. "This would let an
attacker pivot to X" is a projection; a request that actually pivoted to X is a chain. Every hop
needs its own evidence, not inheritance from the hop before it.

## 4. Stop at the first unprovable boundary

When a hop cannot be proven — the guard holds, the precondition is unreachable, the access you'd
need isn't yours to take — stop there. Report up to the last proven hop and downgrade the
remainder to a hypothesis, not a finding. A chain that stops early because the target is actually
defended is a correct result, not a failed one.

## 5. Minimum-viable-exploitation

Build the smallest chain that proves the impact tier, not the most elaborate one available. An
extra hop that doesn't change severity or scope is effort spent, not evidence gained — stop as
soon as the impact claim is proven, then move to the next candidate.

## 6. Precondition-honest chaining

Every hop has preconditions: privilege the attacker must already hold, timing that must line up,
target configuration that must be present. State which preconditions are attacker-controlled,
environment-provided, or merely assumed — a chain report that hides its preconditions oversells
the risk; one that names them lets the operator and the client judge real-world likelihood.

## 7. Reusable primitives

A primitive built for one chain — an OOB callback client, a forged token, an upload bypass — is
reusable. Before moving to the next B candidate, ask whether the primitive you just proved opens
other targets on this engagement, and record it so the next dispatch doesn't rebuild it from
scratch.

This is a lens, not a cage: it shapes how you weigh and prioritize a chain, not which B candidates
you're allowed to test. The A→B Chain Table gives starting points; the sibling, variant, or
adjacent chain hypothesis is still yours to find.
