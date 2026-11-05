# ADR 0040 — Target repositories never configure Git execution

- Status: Accepted — implemented
- Date: 2026-11-04

## Context

`code-ingest` records Git HEAD, branch, dirty state, per-file churn and
security-history commits for an ingested repository, and rechecks the
provenance before publication. The repository often arrives with its `.git`
directory, which makes its config, `info/attributes`, hooks and submodule
metadata target-controlled input.

Git runs programs named in that input. A clean or process filter runs when
`git status` re-reads a stat-dirty file; `gpg.program` runs under
`log.showSignature` for every signed commit `git log` walks; a partial clone's
missing object makes Git fetch through `core.sshCommand` or a remote helper;
textconv and external diff drivers run on patch output; and `include.path`
or `includeIf` can add any of these from another file. `git status` also runs
a child Git inside each submodule under that submodule's own config.
Command-line `-c` overrides cannot close this: a filter or diff driver is
selected by an attribute name only the repository knows. Git's ownership
check (`safe.directory`) does not apply either: an extracted or copied
repository belongs to the operator who ingests it.

[ADR 0019](0019-vigil-does-not-defend-against-its-own-operator.md) trusts the
operator. It does not extend that trust to an assessed repository's code.

## Decision

Git never opens a target metadata directory as its `GIT_DIR`. Every Git call
over ingested source goes through `trusted_exec.TargetGit`, which builds a
private metadata directory for the call:

- the config is written by Vigil: a fixed set of settings that cannot name a
  program, plus the repository's own values for a short list of settings that
  shape results without naming a program (filesystem probes such as
  `core.fileMode`, line-ending and stat policy, sparse checkout, extra
  exclude and attribute files, object and ref format). Each value must be a
  boolean, a member of a closed set, or a control-free path;
- objects and the index (with a split index's shared part beside it) are read
  in place through `GIT_OBJECT_DIRECTORY` and `GIT_INDEX_FILE`; refs, packed refs, reftable, the worktree list, the
  shallow boundary and `info/` are linked as data, so HEAD, every ref `--all`
  reaches (other worktrees' HEADs and a linked worktree's own refs included)
  and exclude rules mean what they mean to the repository's Git;
- replace refs, a grafts file and the commit-graph are not read, so a commit's
  parents and content are its object's bytes and an origin rewritten after
  ingest without moving HEAD reports the same history;
- status stops at the gitlink commit (`--ignore-submodules=dirty`), and Vigil
  inspects each checked-out submodule worktree through its own `TargetGit`;
- lazy fetch is disabled and the partial-clone extension is not carried.

Git calls on the operator's own checkout, such as the remediation helpers that
run that checkout's own test suite, are the operator's repository and stay
plain invocations.

## Consequences

- No filter, diff driver, fsmonitor, hook, pager, signature verifier,
  transport, credential or askpass helper, or include file from an ingested
  repository or its submodules runs. Hostile-repository regressions with
  positive controls pin this.
- A hostile repository yields the same HEAD, branch, dirty bit, churn,
  security history and `--all` reach as a benign repository with the same
  history.
- Dirty state always covers checked-out submodule content. A submodule
  `ignore` setting does not hide a difference from the sealed bytes.
- A partial clone's missing blob degrades churn with a warning instead of
  reaching the network. Its `extensions.partialClone` setting is not carried,
  so any read of a missing object fails instead of fetching.
- A repository setting outside the carried list, such as a rename-detection
  or grep-pattern default, does not change what Vigil records; Git's defaults
  apply.

## Alternatives considered

- **`-c` overrides for every executable key.** Rejected because driver names
  are open-ended and Git keeps adding keys that name programs. A denylist
  fails open.
- **Copy refs into a scratch repository.** Rejected because a copy is a
  second view of refs and worktree HEADs that every layout (linked worktrees,
  reftable, per-worktree refs) would have to reproduce exactly; linking the
  repository's own files keeps one source of truth.
- **Compute dirty state without Git.** Rejected because Git's racy-clean,
  line-ending and ignore semantics cannot be reproduced exactly outside Git.
