# ADR 0031 — Findings carry their own reproduction

- Status: Accepted
- Date: 2026-10-13
- Relates to: [ADR 0028](0028-producer-provenance-binds-proof-to-work.md)

## Context

The report-writer used to build Steps to Reproduce from specialist handoffs and chain
narratives. Those steps read as followable to every downstream reviewer, including the blind
triage pass, but nobody had executed them in that form. A reconstructed sequence reads exactly
like a transcript, so prose review cannot tell the two apart.

## Decision

1. **Steps are recorded from the runs that produced them.** The specialist that proves a finding
   writes `details.steps_to_reproduce` as it works, and lists the `command-run` id behind each
   step, in step order, in `details.repro_runs`. A step with no run behind it was imagined.
2. **A fresh tester follows the steps before drafting.** Before `report-writer` is dispatched, a
   new verifier dispatch receives only the steps and their run ids, with no author handoff or
   chain narrative, and records a `repro_rehearsal` decision. A zero exit code is not success;
   the tester must observe the claimed outcome. A failure goes back to the specialist that
   recorded the finding, because the report-writer cannot run probes.
3. **The report-writer edits within a fabrication boundary.** It may renumber, reword, merge,
   label, and drop steps. It may not add a command, argument, or response value that does not
   trace to a recorded run.
4. **Any change re-opens the check.** The rehearsal decision stores a digest of the steps and the
   ordered run ids. Final export refuses a finding whose current reproduction does not match the
   latest successful rehearsal. A wording-only change can be accepted by a fresh reviewer as
   `equivalent` to a cited prior check.

## Consequences

- A submission's reproduction is something a third party has already followed cold.
- Report readiness blocks a finding with no steps, and advises when steps have no recorded runs.
- Trimming steps for readability is safe, because a dropped precondition is caught by the
  re-rehearsal rather than by the program's triager.

## Alternatives considered

- **Let the report-writer reconstruct steps from handoffs.** Rejected: that is the failure above.
- **Trust the blind triage pass to catch unfollowable steps.** Rejected: it judges the bytes it is
  given and cannot run them.
