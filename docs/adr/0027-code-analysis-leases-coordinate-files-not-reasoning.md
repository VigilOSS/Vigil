# ADR 0027 — Code-analysis leases coordinate files, not reasoning

- Status: Accepted — implemented
- Date: 2026-09-12

## Context

Leases are needed to prevent concurrent or crashed workers from writing as the
same queue owner. They are not a useful measure of how much code an LLM can
understand. The current one-row-per-function reporting instruction turns a
recovery token into clerical scope and relies on free-text function names that
are weaker than the structural identities already available.

## Decision

A code-analysis lease owns one file-level queue write boundary. One fetch may
claim several file rows, each with its own lease token. The assigned hunter may
inspect any relevant part of the full sealed snapshot, trace across files, and
analyze as many callables and chains as the investigation requires. Fetch limits,
lease counts, and `functions_analyzed` are never reasoning quotas, coverage
ceilings, or permission boundaries.

The lease token only authorizes heartbeat, result, recovery, replacement, and
closeout writes for that file row. Reassignment rejects stale writers without
claiming that the prior worker's reasoning was narrow or incomplete.

Mandatory one-row-per-function reporting is replaced by grouped file or call-chain
receipts that name the covered structural callable identities and source spans.
Findings, suspicious results, and unresolved work retain exact individual rows and
evidence. Grouping must preserve review coverage without forcing mechanical output
that crowds out analysis. This ADR makes no incremental scanning or reuse decision.

File-level claiming, multi-file fetches, full-snapshot reading, heartbeat,
stale-writer rejection, grouped receipt contracts, and structural coverage
projection are implemented. Every new non-skipped receipt names exact current
structural callables and/or disjoint non-callable source spans. A cross-file
call-chain receipt contributes each callable to its referenced file's coverage
union, while queue completion remains owned by the claimed file and lease.
Source spans are accepted only after the generation's callable publication is
sealed. A complete function dimension must publish exactly `total_functions`
callable identities; only `total_functions: 0` with an empty registry proves
that a file has no callables. When structural analysis is unsupported or the
function dimension is truncated or unavailable, a source span can prove manual
review only by covering the whole file (and still naming every registered
callable it overlaps), so a partial span cannot make omitted callable source
look non-callable. New writes have no free-text `function_name` field;
structural references and spans are their only source identity. Ambiguous or
missing legacy bindings remain visible in explicit history but do not count as
current results, readiness, or coverage. Queue-less
legacy rows remain readable only through that explicit history surface.

## Consequences

- Recovery and concurrent-write safety do not choke investigation depth.
- Coverage receipts become structurally attributable without multiplying empty
  “clean” rows.
- Schema, CLI contract, backend projections, prompts, and generated wrappers
  enforce the grouped receipt model as one coherent contract.

## Alternatives considered

- **Lease one function at a time.** Rejected because it fragments cross-function
  reasoning and mistakes queue mechanics for analysis scope.
- **Keep one mandatory row per function.** Rejected because it adds output pressure
  without proving that the function was understood.
- **Use one repository-wide lease.** Rejected because it prevents safe parallelism
  and makes crash recovery unnecessarily broad.
