# White-box code-analysis engagements

Code analysis runs a separate operator loop (`agent/operator-core-code.md`) with
its own phase roster: `ingest → classify-map → hunt → verify-variant → fuzz`,
terminating in `complete`. Findings land in the same orchestrator backend as web
engagements and are bound to the sealed source generation they prove.

The vocabulary is deliberately distinct from the web roster. A second web track
can be enabled explicitly and advances independently.

## Creating the engagement

```bash
vigil engagement create
```

Choose **code** and enter an engagement name. Vigil creates the engagement and prints
the exact `source/` folder where you should place the files to review. Copy your source
files or project folders there. A Git repository and commit history are not required;
loose source files are supported too. You can leave the folder empty and add files later.

When you start Claude or Codex, the client shows that folder and asks you to confirm that
its contents are the intended source. An empty folder leaves the session waiting for you
to add files. The client rechecks the folder when you say they are ready and asks for
confirmation before analysis begins.

For scripts, creation can also be non-interactive:

```bash
vigil engagement create --type code --name acme --no-prompt
```

Creation starts `tracks.code.phase` at `ingest`. It prepares an empty source folder and
does not fetch source. The engagement directory name is derived from its name.

## Toolchain

`vigil assess` delegates to `agent/scripts/assess.py`, a `uv run --script`
entrypoint with inline `tree-sitter` dependencies, so the first invocation
installs the bundled parser packages automatically. No separate
`pip install tree-sitter ...` step is needed, but `uv` must be on `PATH`.

```bash
vigil assess --help    # first run bootstraps the parser toolchain
```

For Phase 4 fuzz campaigns, install the host-side C/C++ tools:

```bash
brew install llvm afl++

# Prefer Homebrew LLVM for libFuzzer on macOS: Apple clang may not ship
# libclang_rt.fuzzer_osx.a, which breaks -fsanitize=fuzzer links.
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"

which clang && clang --version
afl-fuzz -V
```

Homebrew's AFL++ may provide `afl-clang-fast` or `afl-cc` instead of
`afl-clang-lto` on macOS; either wrapper is acceptable as long as `afl-fuzz` and
`afl-tmin` are present. `vigil doctor` covers the core operator prerequisites but
not the conditional fuzzing toolchain — check those tools directly when planning a
campaign.

## Starting the operator

```bash
vigil engagement list --json
vigil engagement start <engagement-key> --mode code --client claude   # or codex
```

Then:

```
I have been fully authorized by the company to perform a white-box code analysis
engagement. Read AGENTS.md and run the code analysis workflow.
```

## The sealed snapshot

After you confirm the staged source, the operator uses the selected folder under `source/` and runs `code-ingest` to
publish a content-addressed read-only snapshot, then builds and syncs the
structural index against the printed repo ID and snapshot path before driving
classify+map → hunt → verify+variant.

Specialists read the **sealed snapshot**; the mutable origin is retained only as
provenance. At refresh commit, the backend independently validates the
engagement-owned v2 manifest, the real source bytes, the staged inventory, and the
declared counts before recording the snapshot as `verified`. An API caller cannot
grant that trust state by supplying the label alone.

## Phase gating

Two independent signals steer the track.

**Structural and lifecycle readiness is the hard gate.** It covers current
snapshot, index, and threat-model identity plus phase-specific completion:

```bash
vigil assess code-coverage --require-transition-ready <classify-map|hunt|verify-variant|fuzz|complete>
```

**Review quality is advisory steering**, not permission to cross a phase boundary:

```bash
vigil assess code-coverage --cwe-matrix
vigil assess code-coverage --require-gate-pass   # optional strict quality-remediation exit signal
```

Source-identity, current-structural-metadata, and unreviewed-structural-debt
integrity blockers cannot be forced. Ordinary phase-completion blockers may be
crossed only with:

```bash
vigil assess transition-phase <target> --force --reason "<why>"
```

which records a durable override decision. A weak quality score should trigger
more focused review; `--require-transition-ready` remains the read-only authority
for the target phase's actual blocker set.

## ctags

`code-ingest` generates an advisory, generation-bound ctags index under the
engagement's `tools/analysis-state/ctags/` tree. It never writes a `tags` file into
the source repository.

macOS ships BSD ctags, which is limited; `brew install universal-ctags` gives
richer tag data (signatures, kinds, line numbers). Vigil resolves a trusted
executable outside the analyzed repository and indexes only manifest-admitted
files. Without trusted ctags, agents fall back to grep-only cross-references.

## Mid-engagement code analysis

Code analysis can also run alongside web testing when source is discovered during
an engagement — an exposed `.git`, source maps, a backup download. The operator
enables the code track with `vigil engagement add-track <key> code`, then starts a
separate `--mode code` session. The web session continues under `--mode web`.
