---
description: Re-hydrate the engagement's generated operator role in a new session on an existing engagement, or after a restart, handoff, or unsteered compaction
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-resume.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

Resume the Vigil engagement in the current directory. Its generated operator contract decides the
role; current context, a handoff, and prior summaries do not.

**1. Re-read `scope.json` and restore the role its `engagement_type` routes you to.** Read this
engagement's `AGENTS.md`, follow its pointer to the canonical operator prompt, and read that prompt
in bounded parts, following its own Map of This File. Obey its **Engagement-Type Routing Gate**
branch for this engagement's `engagement_type` — **including a branch that says STOP**, and
including its instruction to stop and report an `engagement_type` it does not recognize. The gate
applies on resume by its own terms: a remembered mode is not evidence of the current one. Operator
discipline is the first thing lost at a context boundary, so restore the contract before acting on
any remembered or persisted state.

Use `/vigil-start` if this engagement has no work in it yet.

**2. Reload the remaining engagement-owned constraints.** Read `ENGAGEMENT.md` plus the additional
files the loaded operator prompt names, and treat them as authoritative over a compaction summary,
handoff, or remembered instruction.

**3. Load optional engagement memory.** Two files may sit in the engagement directory: `RESUME.md`,
the last handoff `vigil-handoff` wrote, and `COMPACT.md`, this engagement's local additions to the
compaction contract. Read whichever exist and report whichever are absent — a missing optional file
is not an error, but silently skipping one is.

!`for f in RESUME.md COMPACT.md; do if [ -f "$f" ]; then printf 'present  %-12s %s bytes\n' "$f" "$(wc -c < "$f" | tr -d ' ')"; else printf 'absent   %s\n' "$f"; fi; done`

**4. Re-establish live state from the backend.** The backend is canonical; recollection is not.
`agent/rules/resume.md` is an always-active rule, so it is already in your context and it owns this
procedure in full — the brief's drill-downs and narrowing flags, the orphan reconciliation it
requires before new target-facing work, and the bounds that keep resume affordable. Follow that rule
rather than a summary of it. Start with the brief:

!`vigil assess resume-brief 2>&1 || true`

If a hydration command fails, report the failure and stop; proceeding would restart work blindly.

**5. Re-anchor on the loaded operator seat.** Choose specialists, frame dispatches, judge evidence,
and use the execution boundary named by the active operator prompt. For every finding or incident
claim, separate backend-supported facts from specialist assertions before carrying it forward.

Operator focus for this resume (may be empty): $ARGUMENTS

Report in the loaded prompt's own output conventions — `[operator]` prefix, numbered choices, phase
tracker — the role and mode you loaded, live work in flight, material changes, relevant missing
memory, and the next action; then continue the active workflow.
