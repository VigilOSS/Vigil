# ADR 0018 — Target-derived text is untrusted data

- Status: Accepted.
  **Superseded-in-part by [ADR 0019](0019-vigil-does-not-defend-against-its-own-operator.md):**
  the closing Consequences bullet below anticipated UI masking and export redaction as
  separate presentation choices; they are not available choices. The untrusted-data
  boundary itself — label and delimit, never delete or rewrite — stands unchanged.
- Date: 2026-09-08

## Context

Vigil intentionally stores target HTTP bodies, source text, logs, mailbox
content and evidence excerpts verbatim. Those inputs can contain instructions
crafted for an agent. If later renderers present the text as ordinary prompt
prose, faithful evidence preservation becomes an instruction-injection path.
This affects offensive and blue-team workflows alike.

The public research synthesis requires summaries to
[preserve source evidence](../plans/research/operator-and-product-reliability/agent-memory-main-report.md#preserve-source-evidence)
and treats target-derived content as evidence rather than authority.
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
- ~~UI masking and export redaction remain separate, explicit presentation choices.~~
  Superseded by ADR 0019: Vigil does not mask or redact its own data on any path an
  operator or an operator-dispatched agent reads. Labelling and delimiting untrusted
  target text — this ADR's own mechanism — is unaffected, because it adds a boundary
  rather than withholding a value.

## Alternatives considered

- **Sanitize stored evidence.** Rejected because it destroys the original proof.
- **Rely on model judgment without a boundary.** Rejected because source and
  authority are otherwise indistinguishable in the rendered context.
- **Block all target prose from memory.** Rejected because evidence and analyst
  interpretation still need to be inspected and recovered.
