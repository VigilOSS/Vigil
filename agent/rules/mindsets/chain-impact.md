# Chain-Impact Mindset

This is the generative lens for `exploit-developer`: how to *decide which chain to pursue and
when to stop*, before the mechanics run. It complements, not replaces, the A→B Chain Table and
the End-to-End Proof Requirement in `agent/agents/exploit-developer.md` — the table gives starting
points and the proof requirement sets the evidence bar; this lens governs the judgment calls
between the two.

## 1. Name the crown jewel, work backward

The forward/backward framing this shape rests on is the baseline's — see
`agent/rules/adversarial-mindset.md` §6. What this lens adds is target-specific: before chaining
forward from whatever primitive you hold, name the crown jewel on *this* target — the data,
credential, admin surface, or infra access that would actually matter to the business here — and
ask what the shortest *proven* path from here to there looks like. Forward-chaining from a
primitive ("I have a stored XSS in the support-ticket viewer, what can I reach?") finds *a* chain.
Naming the jewel first — "the crown jewel is the finance team's export credential; what's the
shortest proven path to it?" — finds *the* chain worth building.

## 2. The chain is usually the finding

Default to reporting the chain as one finding with the full path as evidence — the value of a
chain is the reachable end state, not the first hop, and a confirmed IDOR that never gets chained
is a Medium regardless of how many chain links point at it. Splitting into separate findings with
a chain link is the exception, not a shrug: reach for it when a hop carries independently
reportable severity on its own, or when the operator's grouping needs the individual findings
addressable. The reporting-strategy call itself belongs to `agent/agents/exploit-developer.md`'s
Chain Method step 5 — this lens sets the default, not the rule.

## 3. Prove, don't project

A hop you narrated but didn't execute against the real target does not exist. "This would let an
attacker pivot to X" is a projection; a request that actually pivoted to X is a chain. Every hop
needs its own evidence, not inheritance from the hop before it.

## 4. Stop at the first unprovable boundary — but name which boundary

A hop that cannot be proven is not one verdict. Exactly one of the four routes below applies, and
only the first is a downgrade — reach for it last, not first:

- **The guard genuinely holds and the hop is dead on its merits.** Report **CHAIN DEAD** (every B
  candidate exhausted after thorough testing) or **CHAIN PRIMITIVE** (A stands, B never confirmed
  and no route to confirming it remains) per `agent/agents/exploit-developer.md`'s Chain
  Disposition, and revert to A's own base severity. This is the only case that is actually a
  downgrade, and it requires that you looked and found the door shut — not that you ran out of
  runway.
- **The hop is still provable, just not proven yet** — the guard did not hold, you simply have not
  landed the bug or the runtime proof that completes it. Do NOT revert severity: park it per
  `agent/rules/hunting.md` §2 with `evidence_type=theoretical` + `chain_required=true` at
  `verification_status=pending_runtime_proof`, and it stays out of the report until a runtime
  pass proves it. `CHAIN PRIMITIVE` covers a theoretical hop too, so decide which of these two you
  are in *before* you reach for the severity revert — the revert is correct only for the case
  above.
- **The final step is forbidden by ROE, not by the target.** The primitive is proved and only the
  demonstration is walled off by policy — grade the candidate at impact-if-true, set
  `details.roe_blocked=true` and `details.required_followup` to the exact unblocking test. Never
  lower severity to match what you were permitted to demonstrate — this is
  `agent/rules/hunting.md` §2's ROE-blocked-proof rule.
- **The precondition is missing entirely** — no account, credential, or access grant exists to
  even attempt the hop. This is `agent/rules/hunting.md` §2's blocked-for-provisioning category:
  record `details.block_reason` / `details.unblock_requirements` and keep the finding out of the
  report until the block lifts.

Only the first case is a finished result: the target is genuinely defended, and that is a correct
answer rather than a failed one. The other three are all unfinished in different ways — proof still
owed, permission withheld, precondition absent — and each carries its own disposition and its own
route back. Name which of the four you hit before you write the disposition; recording the wrong
one is how a live chain gets buried under a severity it never deserved to lose.

## 5. Minimum-viable-exploitation

Build the smallest chain that proves the impact tier, not the most elaborate one available. An
extra hop that doesn't change severity or scope is effort spent, not evidence gained — stop as
soon as the impact claim is proven, then move to the next candidate. This governs the *depth* of a
single chain only. It does not authorize leaving the sibling/variant sweep undone
(`agent/rules/hunting.md` §9, the sibling rule; §16a, exhaust confirmed leads first) or walking
away from a confirmed-but-unexploited lead — "move to the next candidate" means actually moving to
it, not ending the pass.

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

---

This is guidance, not a cage or a checklist: it does not restrict which candidates you may pursue,
and it does not enumerate every case you will find — the sibling, variant, or adjacent case is
still yours to find.
