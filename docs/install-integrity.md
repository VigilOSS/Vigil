# Install integrity and staleness detection

How `vigil install` / `vigil update` / `vigil up` copy the managed tree, and how
Vigil detects a working root that has drifted behind the CLI binary.

For the operator-facing summary — the two layers and the three warning surfaces —
see [the README](../README.md#the-two-layers-cli-binary-vs-working-root).

## The install stamp

Every sync path stamps a SHA-256 manifest of the managed tree it actually copied
into `<install-root>/.vigil-install-meta.json`. Status then compares that stamp
against the same normalized manifest computed over the live source tree.

Each manifest entry records the entry type, path, file mode, length, and exact
bytes. Caches, build outputs, installer-created preserved-path ancestors, and
preserved engagement/database state are normalized by the same rules the copier
uses, so they cannot produce a false difference.

The stamp also retains the source revision, which is what drives provenance and
commit-distance reporting. Freshness therefore sees unsnapshotted Jujutsu edits
without mutating the working copy, while later snapshotting identical bytes does
not create a false stale warning.

Because the write happens inside the sync itself, the three sync paths cannot
disagree about what is installed.

## What the manifest catches

- The copy-then-hash race: the manifest is of the bytes actually written.
- Executable-bit changes, which a content-only hash would miss.
- Removals, and file↔directory type changes.
- Hardlink aliases being overwritten in place.

## Descriptor-pinned copy

Source and destination ancestry, plus every copied child, are opened through
pinned, no-follow directory descriptors. Candidate files are opened nonblocking
and accepted only after descriptor type checks; regular destination files
(including the install stamp) are atomically replaced. The destination-root
descriptor stays open for the duration of the install.

Later roster, entrypoint, OOB, stamp, and image-build helpers run inside a
globally locked, scoped working directory established with `fchdir` on that
descriptor, so root-relative filesystem and Docker-context paths start from the
copied root inode even if its public name is replaced. The original working
directory is descriptor-restored on success or failure, and attachment checks
abort after a detected replacement.

Scope of the guarantee: this bridge pins the root name only. Preflight and the
descriptor-native copy reject child links, but the path-based repair and build
helpers do not claim to defeat a concurrent same-UID replacement of a descendant
after validation.

Because `fchdir` changes process-global state, the lock serializes installer
scopes. Unrelated threads must not perform relative-path I/O concurrently; the
supported CLI callers are synchronous.

## Derived root entrypoints

`AGENTS.md`, `CLAUDE.md`, `.codex`, and `.claude` at the install root are
reconciled in the same pass, including removal when their source disappears.
Generated launcher and hook content retains the requested absolute install path.

## Recovering from a stale root

Run `vigil install` (or `vigil up`) to refresh the working root. To upgrade the
CLI binary itself, run `uv tool upgrade vigil`.

A stale working root is the first thing to check when a documented `vigil assess`
verb, flag, or skill appears not to exist: argparse reports it as an "invalid
choice" rather than as a version mismatch.
