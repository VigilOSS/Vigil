# ADR 0025 — Final external communications are versioned and immutable

- Status: Accepted — implemented
- Date: 2026-09-12

## Context

Draft submissions and replies need ordinary editing. After an operator finalizes
a submission or marks a reply sent, however, later in-place edits would make the
durable record disagree with what the recipient received. A correction must not
rewrite that history.

## Decision

Draft external communications remain editable. A finalized submission becomes a
new immutable numbered version containing the exact package bytes, size, digest,
source-finding version, and selected attachment manifest. Downloads revalidate
the stored bytes against that metadata.

A sent reply likewise preserves the exact sent bytes and their digest under a
positive sequence identity. It cannot be edited or deleted in place. A correction
is a new version that explicitly links to the earlier sent version; the original
remains readable. Marking a record finalized or sent is an operator action, never
an inference from export or rendering.

Completed submission versions and sent replies both implement this boundary. At
the explicit sent transition, the backend selects the persisted nonempty draft
inside the write transaction and derives the exact UTF-8 reply bytes itself. It
stores those bytes with their length, SHA-256, server-owned renderer
identity/version, and positive reply sequence; callers cannot supply any of
those integrity claims. Every sent read verifies the stored bytes. Rows sent
before this record existed remain explicit legacy/unavailable state and are
never backfilled from mutable authored content.

## Consequences

- Audit history can reproduce what was finalized or sent at each point in time.
- Corrections are visible events rather than silent rewrites.
- A digest mismatch is an integrity failure, not a reason to regenerate bytes
  from newer finding state.

## Alternatives considered

- **Keep only the latest text.** Rejected because it destroys external history.
- **Infer “sent” from file creation.** Rejected because rendering is not delivery.
- **Edit the old row and append a note.** Rejected because prose cannot restore
  the bytes that were replaced.
