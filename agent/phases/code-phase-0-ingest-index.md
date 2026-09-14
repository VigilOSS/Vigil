# Code Phase 0 — Ingest + Index

**Read-on-phase-entry.** When you ENTER Code Phase 0 (Ingest + Index), Read this doc before running
the clone/ingest/index commands, and re-read it on a method re-anchor (Core Loop -- Code Analysis
Mode, "Re-anchor on method mid-run" equivalent in `agent/operator-core-code.md`) if the current phase
is uncertain. It carries the full ingest → index → sync → verify bash walkthrough, what `code-ingest`
and `code-index` each do, and the Phase 0 exit gate. Cross-phase machinery — the Core Loop, the
Phased mindset flow (code), the Agent Roster, and the Dispatch Context Template — stays in
`agent/operator-core-code.md`; this doc does not restate it. Phase 0 itself dispatches no agent.

### Phase 0: INGEST + INDEX

Operator-mechanical. No agent dispatch.

```bash
# 1. Clone or locate the repository
git clone <repo-url> $DIR/source/<repo-name>
# Or: cp -r /path/to/source $DIR/source/<repo-name>

# 2. For recovered browser source maps, extract first and review the manifest.
# Run the separate code-ingest command printed by this command.
vigil assess code-sourcemap-extract "$DIR/source-maps/<name>"

# 3. Ingest into backend (use the printed source-map handoff when applicable)
vigil assess code-ingest "$DIR/source/<repo-name>" --name <repo-name> --language <primary-lang>

# 4. Copy repo_id and the sealed snapshot path from the ingest summary, then index that snapshot
vigil assess code-index build --repo-id <repo-id> <sealed-snapshot-path>/source

# 5. Sync structural metadata to backend
vigil assess code-index sync

# 6. Verify the hard source/index transition contract separately from review-quality warnings
vigil assess code-coverage --require-transition-ready classify-map
```

`code-sourcemap-extract` writes a traversal-safe, content-addressed source tree and manifest.
The manifest accounts for rejected paths, malformed maps, missing content, and deterministic
duplicate names. Unchanged input reuses its snapshot; changed maps require `--refresh` and create
a new snapshot. Publication remains the normal atomic `code-ingest` refresh, and the extracted
tree is the covering representation instead of a second copy of its mapped minified bundle.

The `code-ingest` command:
- Selects analysis files plus explicit includes and records every excluded entry in a manifest
- Reads each admitted regular file once without following symlinks, deriving copied bytes, SHA-256,
  LOC, and header from that same read
- Publishes a content-addressed, read-only sealed source copy under
  `tools/analysis-state/code-snapshots/`; the origin remains provenance, not an analysis root
- Detects language per file (extension + shebang)
- Captures Git HEAD, branch, and dirty state through a trusted external Git executable when a Git
  marker exists, then rechecks the source before publication
- Marks generated/vendored/test/doc files as `skip` candidates
- Atomically refreshes the backend manifest — the backend assigns each file an integer
  `file_id` (primary key). Retrieve the mapping via
  `vigil assess fetch "code/files?repo_id=<repo-id>&limit=5000"`;
  queue fetch responses also include the full file object with `file_id`.
- Prints the authoritative repo ID, active generation, source-manifest digest, sealed snapshot path,
  and the exact index/sync follow-up commands
- Generates an advisory ctags symbol index outside the source tree when trusted ctags is available;
  its backend path is bound to the same generation and digest

An exact reingest reuses the validated snapshot and generation. An analysis-relevant manifest
change creates a new generation while preserving older snapshots and artifacts as history. A
legacy repo remains readable but cannot satisfy readiness until it is reingested, reindexed, and
its threat model is rebound.

The `code-index` command:
- Runs through the `agent/scripts/assess.py` `uv` script entrypoint, which provides the
  bundled `tree-sitter` parser packages.
- Uses tree-sitter or a language-specific lightweight parser for normal source files; when an
  untrusted file crosses the parser resource boundary, scans every byte with the bounded streaming
  security fallback instead of risking an operator-process OOM
- Parses the exact sealed bytes whose SHA-256 is recorded, and writes generation-scoped per-file
  JSON containing the function map, entry points, security sinks, exports, and call sites
- Marks each artifact `complete`, `degraded`, or `unsupported`, names unavailable/truncated
  dimensions, and retains full observed signal counts even when bounded artifact arrays are capped
- Reconciles the complete sealed path/hash inventory with the current backend language inventory;
  documented aliases such as `c++` normalize to the parser identity `cpp`, while unknown labels fail
  closed instead of falling back from the filename
- Writes a `structural-index/v6` per-repo manifest bound to `repo_id`, generation, source-manifest
  digest, snapshot path, per-file source hashes, and a canonical structural-input digest that includes
  every indexed language. Its `path_to_index` map is the only supported file-to-index lookup; the
  backend's `structural_index_schema` and `structural_index_manifest_path` record the accepted
  contract and location. A language-only correction creates a distinct immutable derived artifact
  while retaining the old one as history
- Upgrades only the exact writer-shaped legacy v3 aggregate during build, after the new v6 artifact
  is complete: unique keys, numeric/digest/path bindings, and debt-count invariants are validated;
  its exact bytes are then retained at
  `structural-index/history/aggregates/v3/<sha256>.json`, and the canonical file is atomically
  replaced by v4 containing only the freshly rebuilt repo. Legacy repo pointers are not trusted or
  imported; malformed and unknown schemas fail closed
- `code-index sync` validates every selected manifest and file against the current complete backend
  path/hash/language inventory before its first write, recomputes aggregate debt from the per-file
  records, then updates backend structural counts and debt metadata with an all-or-none
  generation/digest/hash compare-and-swap. Sync rejects legacy schemas and never performs the
  build-only archival upgrade
- If tree-sitter is still unavailable, fix the local `uv` environment and rerun. Do not skip
  structural indexing for a fresh engagement.
- The structural index accelerates Phase 2 hunting by giving the hunter a pre-built function map, export list, import dependency graph, and advisory sink annotations instead of requiring manual code triage. The function map is the completeness anchor (`agent/shared-constraints-code.md` §2); sinks, exports, and import targets stay advisory navigation, not a scope limiter

Output: a retained, generation-scoped structural-index directory and the manifest path printed by
the command/backend repo record.

```bash
vigil assess transition-phase classify-map
```

Exit: The sealed source snapshot is verified and structural metadata is current for every admitted
file in its exact generation. Degraded/unsupported/truncated artifacts remain visible coverage debt
but do not circularly block entry to Classify + Map or Hunt; route those files through direct
sealed-source specialist review in Phase 2. Their durable analyzed/done receipts are a
non-overrideable requirement before Verify + Variant. ctags remains advisory. Transition to Phase 1.

---

Phase index (path → purpose) lives in `agent/operator-core-code.md` under "Phase Index". Next: `agent/phases/code-phase-1-classify-map.md`.
