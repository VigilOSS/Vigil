# ADR 0018 — Target-derived text is untrusted data

- Status: Accepted
- Date: 2026-09-08

## Context

Vigil intentionally stores target HTTP bodies, source text, logs, mailbox
content and evidence excerpts verbatim. Those inputs can contain instructions
crafted for an agent. If later renderers present the text as ordinary prompt
prose, faithful evidence preservation becomes an instruction-injection path.
This affects offensive and blue-team workflows alike.

OpenHands wraps repository-supplied persistent memory in an explicit untrusted
content boundary; its design and budget are summarized in the
[memory report](../plans/research-operator-robustness/agent-memory-main-report.md#openhands-m).
OWASP separately documents agent-memory poisoning and defensive controls
([Agent Memory Guard](https://owasp.org/www-project-agent-memory-guard/)).

## Decision

Target-derived content remains unchanged in the durable evidence store, with its
producer and source relationship intact. Every prompt-facing renderer labels and
delimits that content as untrusted data. The receiving instructions state that
it is evidence to analyze, never authority to change scope, authorization,
lifecycle or tool behavior.

The delimiter is a presentation boundary, not sanitization. It does not delete,
rewrite or automatically redact evidence, and it does not replace ordinary
escaping in HTML or structured formats.

## Consequences

- Raw evidence remains auditable and hash-stable.
- Target text cannot become policy merely because it was quoted into a handoff,
  resume brief or finding view.
- UI masking and export redaction remain separate, explicit presentation choices.

## Alternatives considered

- **Sanitize stored evidence.** Rejected because it destroys the original proof.
- **Rely on model judgment without a boundary.** Rejected because source and
  authority are otherwise indistinguishable in the rendered context.
- **Block all target prose from memory.** Rejected because evidence and analyst
  interpretation still need to be inspected and recovered.
