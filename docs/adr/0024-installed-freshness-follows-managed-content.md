# ADR 0024 — Installed freshness follows managed content

- Status: Accepted — implemented
- Date: 2026-09-12

## Context

Vigil's installed working root can differ from its source checkout even when both
name the same revision. In a Jujutsu working copy, unsnapshotted edits may also be
newer than the revision identifier. Revision equality therefore cannot establish
that the prompts, scripts, schemas, and other managed bytes actually installed
are current.

## Decision

Installation freshness is decided by a normalized digest of the managed bytes
actually copied into the working root, compared with the same managed-content
manifest over the current source. The installer computes the installed digest
from the destination after synchronization.

The source revision remains recorded as provenance and may support diagnostic
commit-distance output, but it never overrides a content mismatch or substitutes
for an unavailable content comparison.

## Consequences

- Unsnapshotted source changes cannot appear installed merely because the
  revision is unchanged.
- Copy-time drift is detected against destination bytes rather than a later
  reread of source.
- Legacy revision-only stamps remain diagnosable until a supported reinstall
  writes a content digest.

## Alternatives considered

- **Compare only revisions.** Rejected because revisions do not identify live
  working-copy bytes.
- **Hash source after installation.** Rejected because source may change after
  the copy and falsely describe destination content.
- **Use timestamps.** Rejected because they do not prove byte equality.
