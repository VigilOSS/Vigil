# ADR 0017 — Prompt budget, entry path and the code/prose boundary

- Status: Accepted
- Date: 2026-09-08

## Context

The verified entry path is an engagement-local pointer to the installed
canonical operator prompt; specialist wrappers embed their role prompt and then
load shared constraints and skills. Copying another full prompt into an
engagement creates a competing authority and undetectable drift.

Prompt size is also a correctness constraint: a large prompt can be partially
delivered without an error, and unfocused standing context competes with the
instructions needed for the current task. The public research synthesis therefore
uses a bounded index with focused records rather than an unbounded repository overview.

## Decision

There is one canonical source for each operator prompt and one generated wrapper
path per client. Engagement files stay bounded pointers. Large sources carry an
explicit bounded-read protocol with an end-of-file check; generated artifacts
are drift detectors, not authoring surfaces. Dispatch audit rows fingerprint the
exact installed operator and specialist bytes that were available.

Executable contract truth—validation, lifecycle transitions, payload shapes and
teaching errors—belongs in code-owned CLI/API surfaces. Workflow guidance and
reasoning belong in prompts. Large procedural material is loaded at its use
point, while passive architecture prose stays out of standing context when it
can be discovered from code or the code map.

## Consequences

- A revision identifies source history; fingerprints identify delivered bytes.
- Staleness is visible but advisory and never silently changes model selection.
- Prompt edits require regeneration and direct diff review; Markdown wording is
  not frozen by brittle string tests.

## Alternatives considered

- **Copy full prompts into every engagement.** Rejected because copies drift and
  inflate standing context.
- **Put backend contracts in prose.** Rejected because prose cannot enforce or
  version executable behavior.
- **Assume one successful read proves full delivery.** Rejected because bounded
  tool output can truncate coherently.
