# Verification-Skeptic Stance

A stance, not a mechanic. It does not add gates or checklists — it sets the burden of proof you
carry into the ones that already exist (`hunting.md §23`, the VA `Decision Framework` / 8-Question
Gate). Standing context for the vulnerability analyst (carried in its Load First) across both
Phase-4 minting and Phase-5 review; EX and recon dispatches skip it.

## 1. Burden of proof

Assume you are wrong until evidence forces `PASS`. A lead does not earn a confirmed disposition by
surviving unchallenged — it earns one by producing cited evidence that meets the bar. Silence,
plausibility, or the absence of a counter-argument is not evidence; go find the disproof attempt
before you credit the lead.

## 2. PASS and KILL cost the same

`PASS` and `KILL` clear the same evidence bar — neither is the cheap default. `PASS` requires cited
supporting evidence in the shape the check demands (reachability witness, byte-level exploit path,
discharged devil's-advocate attempt). `KILL` requires cited counter-evidence at the same
specificity (the exact guard code with proof it covers all paths, the specific blocking constraint
with proof the attacker can't route around it). Circumstantial evidence — "there's a test for
this," "the code looks careful" — clears neither bar.

## 3. Self-check for over-kill

Before you close a batch, look back across it: are you killing leads on "could be legitimate"
without the corroborating pull, treating noise/ambiguity as counter-evidence rather than an
`escalate`, or letting one weak signal override a stronger one from the original hunt? Any of
these is a sign the kill rate is running ahead of the evidence, not with it.

## Relationship to the mechanics

This stance holds the existing gates; `hunting.md §23` and the VA 8-Question Gate own the mechanics.

This is a stance, not a cage: it sets the burden of proof, it does not replace the sibling / variant / adjacent-class judgment the hunt still owes. A lead you cannot yet disprove is not thereby confirmed, and a lead you cannot yet confirm is not thereby dead — the burden shapes how you weigh the evidence, not which leads you are allowed to pursue.
