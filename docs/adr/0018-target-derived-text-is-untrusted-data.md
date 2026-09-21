# ADR 0018 — Target-derived text is untrusted data

- Status: Accepted.
  **Superseded-in-part by [ADR 0019](0019-vigil-does-not-defend-against-its-own-operator.md):**
  the closing Consequences bullet below anticipated UI masking and export redaction as
  separate presentation choices; they are not available choices.
- Date: 2026-09-08
- Amended: 2026-09-21 — prompt containment is distinguished from operator-UI
  presentation; repetitive trust-warning labels are not a frontend requirement.

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
producer and source relationship intact.

When persisted target text crosses into an agent prompt or another instruction-bearing
document, the renderer structurally delimits it and the receiving instructions state
that it is evidence to analyze, never authority to change scope, authorization,
lifecycle or tool behavior. A human-readable export whose structure could be forged by
the embedded text likewise uses content-sized fences or equivalent containment.

The operator frontend does not need a repeated "untrusted" notice merely because it
shows target evidence. Provenance is already inherent in the evidence view, and an
ambient label does not create an authority boundary for the human operator. The UI
still treats the bytes as hostile input at the technical rendering boundary: escape
HTML, sanitize Markdown, keep remote images inert, constrain links, and never interpret
evidence as code or UI instructions. Useful source/provenance metadata may be shown as
metadata; it is not a warning banner.

The delimiter is a presentation boundary, not sanitization. It does not delete,
rewrite or automatically redact evidence, and it does not replace ordinary
escaping in HTML or structured formats.

## Consequences

- Raw evidence remains auditable and hash-stable.
- Target text cannot become policy merely because it was quoted into an agent-facing
  handoff or resume brief.
- Operator views remain quiet and readable without weakening HTML, Markdown, URL,
  image, export-structure, or prompt-authority safeguards.
- ~~UI masking and export redaction remain separate, explicit presentation choices.~~
  Superseded by ADR 0019: Vigil does not mask or redact its own data on any path an
  operator or an operator-dispatched agent reads. Structural containment remains where
  content crosses an instruction or document-structure boundary; repetitive frontend
  warning labels are not part of that mechanism.

## Alternatives considered

- **Sanitize stored evidence.** Rejected because it destroys the original proof.
- **Rely on model judgment without a boundary.** Rejected because source and
  authority are otherwise indistinguishable in the rendered context.
- **Block all target prose from memory.** Rejected because evidence and analyst
  interpretation still need to be inspected and recovered.
