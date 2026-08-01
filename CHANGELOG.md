# Changelog

Notable changes to Vigil. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at the changes below. Earlier history lives in `jj log` / `git log` and was not
back-filled, because reconstructing it after the fact would invent a precision the record does not
have.

## [Unreleased]

### Changed

- **Submissions are restructured for followability.** Step-verification outcomes now live inline in
  the step that produces them, and the Evidence section carries only what the steps cannot show:
  the decisive artifact (the bytes proving what a step's expected-result line can only assert), root
  cause, negative controls, post-exploitation boundaries, minimum required privilege, and
  environment facts that are load-bearing for Impact or Remediation. Evidence takes one block when a
  finding has one thing to prove and a labelled block per category when it has several — the shape
  follows the proof obligations, not a template. The previous split — steps own
  the action, Evidence owns the result — forced every outcome into a separate section downstream of
  the request that produced it, so the writer re-established request context to make results
  legible. That re-telling was the structural cause of duplicated, over-long submissions.
- **The report-writer may now edit a reproduction, not merely reformat it.** It can renumber,
  reword, merge, label, and drop steps. The boundary is fabrication, not editing: every command,
  argv, and response value must trace to a recorded `command-run` id in `details.repro_runs`.
  Dropping a step re-triggers the reproduction rehearsal, so a trimmed path is never shipped
  unexecuted. Specialists are unchanged — they continue to record the full executed sequence, and
  no probe or command run is deleted when a step is dropped from the narrative.
- **Attack Scenario is omitted whenever an exploit-flow block is present.** The two carry the same
  sequence, once mechanical and once narrative.

### Added

- **Findings carry their own reproduction.** `details.repro_runs` records the `command-run` id
  behind each step of `details.steps_to_reproduce`, so a reproduction can be diffed against what was
  actually executed. Submission export reports missing or unresolvable run ids, and report readiness
  blocks on an empty reproduction.
- **Exploit-flow block.** An optional three-to-five step plain-prose flow inside the finding
  `summary`, carrying no commands, so a triager understands the mechanism before reaching the
  reproduction.
- **Per-step actor labels.** Each step names the acting identity, derived from the recorded run's
  auth context.
- **Step ceiling.** Ten steps per reproduction, one action per step. Controls, edge cases, alternate
  endpoints, and source-code analysis do not belong in the steps; cleanup does, but only when the
  reproduction mutates state the triager will also mutate.
- **Sentence-length ceiling.** 25 words, 20 inside Steps to Reproduce, prose only. The cap limits
  how much a sentence says, not how much a submission says; long walk-throughs split rather than
  shrink.
- **Meta-commentary is a banned phrasing class.** The writer narrating its own reporting decisions
  ("read this as", "that bounds", "I would rather report", "to be clear about what I am not
  claiming") is deleted rather than reworded, and an anticipated objection is answered with evidence
  or not at all — never pre-rebutted in the body.
- **Four non-blocking submission advisories:** longest prose sentence, step count, section sentence
  budgets, and evidence block length. They read as suggestions and are surfaced in
  `submission-context.json`, on stderr, and in the operator reference section of a rendered
  submission.

### Removed

- **Severity-defence phrasing from the report-writer prompt.** Its canned phrases justified CVSS
  metrics in body prose, which the submission checklist already bans; the header carries required
  privileges, victim interaction, and demonstrated impact.
- **The report-writer pre-work checkpoint**, which restated checks the closing sequence and the
  report-generation skill already own.

### Fixed

- The five canonical example submissions now satisfy the rules they are meant to exemplify.
- A control that proves the causal claim — a safe branch escaping the same bytes, a pre-exploitation
  capability baseline — is corroborating proof, not a banned "ruled out" section.

### Notes

Nothing in this release changes what blocks a submission publish. The blocking set remains the four
internal-identifier hygiene checks; every new signal is advisory.
