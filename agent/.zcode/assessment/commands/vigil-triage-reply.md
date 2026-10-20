---
description: Assess a program's pushback on a submission and decide whether to rebut, resubmit, or drop
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-triage-reply.md -->


Use the absolute context-bound Vigil helper supplied by this native task context or Runtime Identity for every Vigil invocation. Read that immutable context router; the stable project helper inspects NEW-task setup only. Confirm the selected mode before acting.

Arguments from this invocation: $ARGUMENTS

This command implements the web workflow. In code mode, explain that limitation and use the selected code operator workflow instead; do not change modes or load a web operator core.

Assess the program pushback the operator described in their message.

**If the finding or the program's exact words are missing above, ask for both before doing anything
else** — a rebuttal written against a paraphrase answers the wrong objection.

**Judge the pushback first, and judge it fresh.** Your own attachment to the submission is exactly
the bias that produces a bad rebuttal, and a bad rebuttal costs reputation with the program.
Dispatch a fresh, low-context specialist with three things and no conclusion: the finding record,
the submission as sent, and the program's reply verbatim. Ask whether the pushback is fair on the
merits. Programs are right a large fraction of the time, and the honest answer is often "they are
right".

**If they are right**, say so and recommend one of: resubmit under a different VRT with the correct
framing, consolidate into an existing finding as the same root cause, or drop it. Recommending
"drop" is a legitimate, valuable outcome; a program relationship is worth more than one contested P4.

**If a reply is warranted, it goes through the reply pipeline — never a draft in chat.** Dispatch
`report-writer` in reply mode, per `agent/phases/phase-8-report.md` step g. Its "Closing verbs
(reply mode)" section owns the procedure end to end — `export reply --draft` scaffold, author,
`record-reply` write-back, re-render, pre-send checklist, the conditional blind-triage gate, and
`record-reply --sent` — and `agent/references/reply-format.md` owns the voice, the budgets, and the
pre-send checklist itself. Do not restate any of that here and do not shortcut it: a reply drafted
in chat never reaches the hygiene gate, and a final (non-`--draft`) `export reply` render **refuses**
while an internal-identifier flag remains. That gate is the only thing between a finding slug or an
engagement UUID and the triager's inbox.

One judgment stays yours before it goes out: a reply is worth sending only if it will actually
**end** the pushback. A reply that restates the original submission in a firmer tone changes
nothing and burns goodwill.

**Submission status does not move on its own.** `record-reply` never sets `submission_status`;
`--set-submission-status` is the explicit opt-in, folded into the `--sent` call when the reply
answers `needs_info`.
