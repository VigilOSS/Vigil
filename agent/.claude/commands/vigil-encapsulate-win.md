---
description: Fold a win — a prompt, check or hypothesis that found a real bug or caught a real false positive — into the durable methodology
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-encapsulate-win.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

Something just worked. Write it into the methodology so the next engagement starts with it
instead of rediscovering it.

The win to encapsulate: $ARGUMENTS

**1. Establish that it is actually a win, before it becomes doctrine.** This is the step that
protects everything downstream. A lesson in the methodology is applied automatically, to every
future engagement, by agents who will not re-derive it — so the bar to enter is evidence, not
plausibility.

- If the claim is "this found a real bug": the finding must be verified in the backend, with
  evidence, not merely reported by a specialist. Check it.
- If the claim is "this caught a real false positive": the kill must be recorded, with the
  reason that killed it.
- If neither is true yet, **stop and say so.** Encapsulating an unverified hunch is how a
  methodology fills up with superstition, and superstition is expensive precisely because it
  looks like experience. Recommend verifying first and come back.

**2. Name the transferable lesson.** Not what happened — what to *do* next time. "The
`/api/v3/export` endpoint was vulnerable" transfers nothing. "Export endpoints that accept a
format parameter are worth testing for template injection before anything else" transfers.
If you cannot state it as an instruction that applies to a target you have never seen, it is
a finding note and belongs on the finding, not in the methodology.

**3. Choose exactly one home for it.** Put it where the agent that needs it will already be
reading. Adding it in two places is how the two copies start disagreeing:

- `agent/rules/hunting.md` — always-active hunting behaviour: how to look, where to look
  next, what a signal means. Use this only for lessons that apply across vuln classes.
- `agent/references/finding-fp-and-severity-gate.md` — the FP and severity gate. Use this for
  anything that kills a finding, downgrades one, or distinguishes a real bug from an expected
  behaviour. Most "caught a false positive" wins belong here.
- `agent/skills/<vuln-class>/SKILL.md` — the methodology for one vuln family. Use this when
  the lesson only makes sense inside that class.
- `agent/references/<area>/<name>.md` or a per-target reference — payloads, checklists,
  tooling invocations, and anything specific to one target or platform.

If the lesson is about a *target*, not a technique, it belongs in that engagement's own
`PROFILE.md`, not in the shared tree.

**4. Write it in the file's own idiom.** Read enough of the destination first to match its
voice, heading structure and level of detail. Add it to the section it belongs in rather than
appending a new one at the bottom, and keep it to the smallest instruction that carries the
lesson. Do not restate what the file already says — if a rule is already there and merely was
not followed, that is a different problem and adding a second copy will not fix it. Say so
instead.

**5. Keep the claim proportionate to the evidence.** One engagement is one data point. Write
"worth checking early on X" when that is what you know; write "always" only when the mechanism
guarantees it. State the reasoning, briefly, so the next reader can judge it rather than
having to trust it — a rule whose *why* is present can be correctly overridden; a bare
imperative can only be obeyed or ignored.

**6. Report the file path you changed**, the exact text you added, and which finding or kill
is the evidence for it. If you decided not to write anything, say that and why.
