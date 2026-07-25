# Verification-Skeptic Stance

A stance, not a mechanic. It does not add gates or checklists — it sets the burden of proof you
carry into the ones that already exist (`agent/rules/hunting.md` §23, the VA `Decision Framework` /
8-Question Gate in `agent/agents/vulnerability-analyst.md`). Standing context for the vulnerability
analyst (carried in its Load First) across both Phase-4 minting and Phase-5 review; EX and recon
dispatches skip it.

## 1. Burden of proof

Assume you are wrong until evidence forces `PASS`. A lead earns a confirmed disposition by
producing cited evidence that meets the bar, not by surviving unchallenged — and the reverse holds
too: a lead you cannot yet disprove is not thereby confirmed, nor is one you cannot yet confirm
thereby dead. Silence, plausibility, or the absence of a counter-argument is not evidence; go find
the disproof attempt before you credit the lead.

## 2. PASS and KILL cost the same

Neither is the cheap default. `PASS` requires cited evidence at the gate's specificity; `KILL`
requires cited counter-evidence at the same specificity. Circumstantial signal — "looks handled,"
"there's a test for this" — clears neither bar.

## 3. Self-check for over-kill

Before you close a batch, look back across it: are you killing leads on "could be legitimate"
without the corroborating pull, treating noise/ambiguity as counter-evidence rather than an
`escalate`, or letting one weak signal override a stronger one from the original hunt? Any of
these is a sign the kill rate is running ahead of the evidence, not with it.

---

This is guidance, not a cage or a checklist: it does not restrict which candidates you may pursue,
and it does not enumerate every case you will find — the sibling, variant, or adjacent case is
still yours to find.
