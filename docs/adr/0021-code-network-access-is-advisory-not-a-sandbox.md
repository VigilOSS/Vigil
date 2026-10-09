# ADR 0021 — Ordinary code work keeps normal network access

- Status: Accepted — implemented
- Date: 2026-09-12

## Context

Code analysis needs ordinary Internet access for source acquisition, dependencies,
documentation, and vulnerability research. Treating the CODE track as an offline
sandbox would obstruct that work and would still not prove that arbitrary child
processes could not reach a target. Vigil can positively recognize some literal
target contacts, but a negative classifier result means only “not recognized.”

## Decision

Ordinary code and mixed engagements retain normal network access. When Vigil
positively recognizes a CODE command contacting a host declared in `scope.json`,
it emits a prominent warning, records the recognized host and classification,
and still runs the command. An unrecognized command is never described as safe,
offline, or non-target-facing.

Deliberate live validation belongs on an explicitly activated web track. Vigil
does not add a CODE firewall, VM, destination allowlist, global code/web network
switch, or per-command approval loop.

## Consequences

- Source and research workflows keep their expected network capabilities.
- The warning reduces accidental target contact without making a false
  enforcement claim.
- Scope, required-header, denied-tool, and evidence-isolation controls retain
  their existing independent authority.

## Alternatives considered

- **Make CODE offline.** Rejected because it blocks necessary work and requires a
  broader runtime boundary that ordinary engagements do not need.
- **Block positively recognized target commands.** Rejected because a partial
  lexical classifier would create inconsistent enforcement and false confidence.
- **Ask before every network command.** Rejected because it adds friction without
  proving destination coverage.
