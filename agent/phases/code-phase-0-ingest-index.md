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

# 4. Generate structural index
vigil assess code-index "$DIR/source/<repo-name>"

# 5. Sync structural metadata to backend
vigil assess code-index sync

# 6. Verify ingestion and index
vigil assess code-coverage
```

`code-sourcemap-extract` writes a traversal-safe, content-addressed source tree and manifest.
The manifest accounts for rejected paths, malformed maps, missing content, and deterministic
duplicate names. Unchanged input reuses its snapshot; changed maps require `--refresh` and create
a new snapshot. Publication remains the normal atomic `code-ingest` refresh, and the extracted
tree is the covering representation instead of a second copy of its mapped minified bundle.

The `code-ingest` command:
- Walks the repo tree
- Detects language per file (extension + shebang)
- Computes SHA-256 hashes, counts LOC
- Extracts first ~50 lines as header snippet
- Runs git churn analysis if .git exists
- Marks generated/vendored/test/doc files as `skip` candidates
- POSTs all files to backend code-files endpoint — the backend assigns each file an integer
  `file_id` (primary key). Retrieve the mapping via
  `vigil assess fetch "code/files?repo_id=<repo-id>&limit=5000"`;
  queue fetch responses also include the full file object with `file_id`.
- Creates code_repos record with repo metadata
- Generates ctags symbol index (if ctags is available)

The `code-index` command:
- Runs through the `agent/scripts/assess.py` `uv` script entrypoint, which provides the
  bundled `tree-sitter` parser packages.
- Uses tree-sitter to parse each source file
- Produces per-file JSON under `tools/analysis-state/structural-index/<repo_key>/` (filenames are `sha256(repo_key::rel_path)[:16].json`, scoped per repo so the same relative path in different repos never collides) containing: function map (names, signatures, line ranges), entry points (main functions, request handlers, exported APIs), security sinks (memory operations, file I/O, command execution, crypto calls), and call sites
- Writes a per-repo manifest at `tools/analysis-state/structural-index/<repo_key>-manifest.json` (its `path_to_index` maps repo-relative file path -> index filename relative to `structural-index/`, e.g. `<repo_key>/<fid>.json`) and updates an aggregate manifest at `tools/analysis-state/structural-index-manifest.json` (schema `structural-index-aggregate/v1`, top-level `repos` dict keyed by `repo_key` with `manifest_path` and `index_dir`, plus an `aggregate` totals block). Consumers resolve a per-repo index by: aggregate -> `repos[<repo_key>]` -> read `manifest_path` -> per-repo `path_to_index[<rel_path>]`
- If tree-sitter is still unavailable, fix the local `uv` environment and rerun. Do not skip
  structural indexing for a fresh engagement.
- The structural index accelerates Phase 2 hunting by giving the hunter a pre-built function map, export list, import dependency graph, and advisory sink annotations instead of requiring manual code triage. The function map is the primary completeness anchor -- every function must be accounted for. Sinks, exports, and import targets are advisory metadata that aids navigation but does not constrain the hunter's analysis scope

Output: `tools/analysis-state/structural-index/` directory with per-file JSON + manifest.

```bash
vigil assess transition-phase classify-map
```

Exit: All files inventoried. ctags symbol index generated if ctags is available. Structural index generated. Transition to Phase 1.

---

Phase index (path → purpose) lives in `agent/operator-core-code.md` under "Phase Index". Next: `agent/phases/code-phase-1-classify-map.md`.
