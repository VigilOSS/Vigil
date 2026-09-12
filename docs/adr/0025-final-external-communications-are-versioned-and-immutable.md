# ADR 0025 — Final external communications are versioned and immutable

- Status: Accepted — partially implemented; a digest-bound sent-reply byte record remains pending
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

Completed submission versions and sent-reply authored-content/correction rules
are implemented. Sent replies do not yet persist the exact final outbound byte
sequence and its digest as one immutable record, so that part of this decision
remains open.

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
