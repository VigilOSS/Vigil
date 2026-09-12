# ADR 0029 — Structural parsers are contained with honest fallback

- Status: Accepted — implemented
- Date: 2026-09-12

## Context

Repository source is untrusted parser input. Malformed, huge, or adversarial files
can hang, exhaust, crash, or induce side effects in an exact parser. Running that
parser in the assessment process would risk the whole ingest while a silent skip
could turn parser failure into false clean coverage.

## Decision

Exact structural parsing runs over the unchanged source bytes in a dedicated child
process with parent-owned time, memory, output, and cancellation limits. The child
denies network sockets, process creation, filesystem writes, and core/file output.
The parent verifies the request/source digest and validates the complete typed
result before accepting it.

Timeout, memory exhaustion, crash, malformed output, invalid UTF-8, oversized
source or lines, result flooding, and denied capabilities become explicit degraded
or incomplete outcomes. The bounded streaming fallback still accounts for every
input byte and names unavailable dimensions; it never reports the file clean or
fully indexed.

Parser products are navigation metadata. The sealed raw source remains unchanged
and directly available to the LLM and operator; containment does not sanitize,
redact, summarize, or replace it.

## Consequences

- One hostile file cannot silently crash or stall the parent indexing workflow.
- Failure remains visible coverage debt rather than a false negative.
- Exact source evidence retains the verbatim visibility required by ADR 0019.

## Alternatives considered

- **Parse in process.** Rejected because parser failure shares the assessment's
  fate and resource budget.
- **Skip failed files.** Rejected because absence of parser output is not clean.
- **Sanitize source before parsing or model review.** Rejected because it changes
  evidence and can hide the vulnerability-bearing bytes.
