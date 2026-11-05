# ADR 0041 — Architect history reads are bounded and snapshot-bound

- Status: Accepted — implemented
- Date: 2026-11-04
- Amends: the code-track rule that the architect runs no Git against the mutable origin
  (`agent/shared-constraints-code.md`, `agent/skills/code-architecture-mapping/SKILL.md`).

## Context

Phase 1 can write `tools/analysis-state/cve-bug-shapes.jsonl`: historical fixes
distilled into the vulnerable code shape and the guard the fix added. Phase 2
seeds a variant swarm from it. A shape needs the fixed commit's diff against
its first parent, and the architect had no way to read one. The sealed snapshot
holds no `.git`, and the architect was barred from running Git against
`source_origin_path` because that checkout is mutable: its HEAD and branches
can move after ingest, and its repository configuration can name programs Git
runs ([ADR 0040](0040-target-repositories-never-configure-git-execution.md)).
Ingest records only which files security commits touched, which is enough to
rank files and not enough to describe a bug.

## Decision

The architect still runs no ambient Git. It reads history only through
`vigil assess code-history`, a bounded, read-only verb bound to the sealed
snapshot:

- **Binding.** The snapshot manifest validates against the backend's
  `snapshot_digest`; its digest-bound `git.head` must equal the backend
  `commit_hash`, the backend `source_kind` must be `git`, and the origin path is
  the manifest's `source_origin_path`. A mismatch exits non-zero and writes
  nothing.
- **Explicit revisions.** Git receives full object ids only: the recorded HEAD
  and the commits a caller names, each verified as that HEAD or one of its
  ancestors. No ref, `--all` or relative date reaches Git, so moving the
  origin's HEAD or branches cannot change what the verb reports.
- **Contained execution.** Every call is plumbing (`rev-list`, `cat-file`,
  `diff-tree -p --no-textconv --no-ext-diff --no-renames`) run through
  `trusted_exec.TargetGit`.
- **Budgets.** Commits walked, patch bytes and files per diff have defaults
  (500, 256 KiB, 50) and ceilings, and each commit object and changed-path list
  has a fixed bound. Every receipt records the budgets, the Git version and
  which budget truncated output. Commit text never changes a budget, path
  filter or walk.
- **Honest absence.** When history cannot be read, the verb reports
  `history_status: unavailable` with a reason code (`directory_source`,
  `origin_missing`, `origin_not_git`, `head_object_missing`, `git_unavailable`)
  and exits 0, as [ADR 0015](0015-honest-instruments-distinguish-no-measurement-from-clean.md)
  requires. A shallow origin reports `partial_shallow`.
- **Citable artifacts.** Output lands under
  `tools/analysis-state/code-history/<repo>/<generation>/<head>/` with a receipt
  holding inputs, budgets, truncation flags and output digests. A bug shape's
  `vulnerable_revision` is a cited diff's first parent, its `fixed_revision` is
  that commit, and its `evidence_refs` name the receipt and patch.
  `code-history check-shapes` rejects a shape whose citations do not hold or
  whose description is only identifiers.
- **Untrusted text.** Commit messages, identities, paths and patches are target
  text under [ADR 0018](0018-target-derived-text-is-untrusted-data.md). They
  are stored verbatim (non-UTF-8 as base64), and the text report indents every
  line of them so nothing reaches column zero.

Other code specialists keep the rule unchanged: they read the sealed snapshot
and the architect's cited artifacts, and run no Git.

## Consequences

- Phase 1 can produce `cve-bug-shapes.jsonl` from real vulnerable-to-fixed
  diffs, and Phase 2 can check every shape before seeding a swarm from it.
- The same request against the same recorded HEAD and Git version yields
  byte-identical artifacts, whatever the origin has done since ingest.
- History that is missing, moved away or shallow is named as such; it is never
  reported as a repository without security history.
- A dirty worktree at ingest is flagged on every receipt, since the recorded
  HEAD's history then describes code that differs from the sealed bytes.

## Alternatives considered

- **Seal `.git` into the snapshot.** Rejected because it copies a
  target-controlled metadata directory into analysis state and multiplies the
  snapshot by the repository's history.
- **Record full security history at ingest.** Rejected because ingest cannot
  know which commits a shape will need, and an unbounded ingest-time read makes
  every refresh pay for history the architect may never use.
- **Let the architect run Git directly.** Rejected because nothing would bind
  its reads to the recorded HEAD, bound their size or keep repository
  configuration from running programs.
