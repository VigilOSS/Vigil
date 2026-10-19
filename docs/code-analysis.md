# White-box code-analysis engagements

Code analysis runs a separate operator loop (`agent/operator-core-code.md`) with
its own phase roster: `ingest → classify-map → hunt → verify-variant → fuzz`,
terminating in `complete`. Findings land in the same orchestrator backend as web
engagements and are bound to the sealed source generation they prove.

The vocabulary is deliberately distinct from the web roster. A second web track
can be enabled explicitly and advances independently.

## Creating the engagement

```bash
vigil engagement create --type code --name acme --source-dir ./acme --no-prompt
vigil engagement start <engagement-key> --mode code --client codex
```

`--source-dir` registers the original directory. The operator shows its location and inventory,
then asks for confirmation before ingest. The same question asks you to confirm that you trust the
repository's build and test code to run inside the Vigil runtime: local proof compiles and runs
that code in the shared runtime container, which also holds engagement data and recon credentials.
Ingest creates one sealed audit copy directly from that directory and leaves the original
untouched. Git history is optional.

You can also create without `--source-dir` and place loose files or project folders in the
printed `source/` folder. An empty source waits for files and confirmation. Neither registration
nor copying files grants consent to ingest or refresh. Starting an existing engagement resumes
its sealed source and durable work without repeating the same confirmation. If the original is
unavailable, the sealed source remains usable; refresh waits for the original to return.

Add `--no-autoprompt` to enter your own opening request. Source confirmation still applies
before first ingest or refresh. Creation starts `tracks.code.phase` at `ingest`.

## Toolchain

`vigil assess` delegates to `agent/scripts/assess.py`, a `uv run --script`
entrypoint with inline `tree-sitter` dependencies, so the first invocation
installs the bundled parser packages automatically. No separate
`pip install tree-sitter ...` step is needed, but `uv` must be on `PATH`.

```bash
vigil assess --help    # first run bootstraps the parser toolchain
```

Static source review runs on the host. Builds, repository binaries, sanitizers,
and fuzz campaigns run through the audited Kali runtime. With Docker running, the first audited
command starts Kali when needed. Let the operator check the toolchain for the selected campaign:

```bash
vigil assess kali exec --technique FUZZ --intent "verify fuzz compiler and engine toolchain" \
  --probe-kind baseline --phase code-hunt --timeout 60 -- \
  sh -c 'command -v clang && clang --version'
```

Check AFL++ and its compiler wrapper through the same audited surface only when
the selected campaign uses that engine. A libFuzzer-only target does not need
AFL++. `vigil doctor` covers the core operator prerequisites; the code operator
and fuzz engineer check campaign-specific tools, source mounts, and build inputs.
If an input cannot be reached inside the engagement mount, repair that boundary
before execution. The [fuzz workflow](../agent/phases/code-phase-4-fuzz.md) owns
the campaign procedure.

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

After you confirm the selected source directory, the operator runs `code-ingest` directly on it to
publish a content-addressed read-only snapshot, then builds and syncs the
structural index against the printed repo ID and snapshot path before driving
classify+map → hunt → verify+variant.

Specialists read the **sealed snapshot**; the mutable origin is retained only as
provenance. At refresh commit, the backend independently validates the
engagement-owned manifest, the real source bytes, the staged inventory, and the
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

## Runtime proof owed

When a verifier accepts the source evidence but cannot run the decisive test, it records
`pending_runtime_proof` with a next test: the hypothesis, the observation that would confirm it,
the observation that would falsify it, and whether the test looks local or live. The operator
prepares proof work from that plan. The route hint is a suggestion and grants no scope or
approval. See [proof work](engagements.md#proof-work-and-continuation).

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
enables the code track with `vigil engagement add-track <key> code`, asks you to
confirm the source and that you trust its build and test code to run inside the Vigil
runtime, and dispatches code specialists from the current session. A separate
`--mode code` session is optional; each session loads one operator workflow.
