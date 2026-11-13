# Code Phase 0 — Ingest + Index

**Read-on-phase-entry.** Read this doc on entering Code Phase 0 and re-read it on a method re-anchor
(`agent/operator-core-code.md` Core Loop). It carries the ingest → index → sync → verify walkthrough
and the exit gate. Phase 0 is operator-mechanical and dispatches no agent.

### Phase 0: INGEST + INDEX

Complete `agent/operator-core-code.md`'s Source confirmation step first. Use the confirmed
original directory returned by `vigil engagement mode --json`, or a project subdirectory
within the manual source folder. Ingest directly; the sealed snapshot is the audit copy.

```bash
# 1. For recovered browser source maps, extract first, review the manifest, then run the
#    separate code-ingest command this prints.
vigil assess code-sourcemap-extract "$DIR/source-maps/<name>"

# 2. Ingest the confirmed directory (or the printed source-map handoff)
vigil assess code-ingest "<confirmed-source-directory>" --name <project-name> --language <primary-lang>

# 3. Run the build command the ingest summary prints under "Next:"; it carries the repo_id and the
#    "Sealed source:" path that code-index binds to.
vigil assess code-index build --repo-id <repo-id> <sealed-source-path>

# 4. Sync structural metadata to the backend
vigil assess code-index sync --repo-id <repo-id>

# 5. Check the source/index transition contract separately from review-quality warnings
vigil assess code-coverage --require-transition-ready classify-map
```

`code-sourcemap-extract` writes a traversal-safe, content-addressed source tree and a manifest that
accounts for rejected paths, malformed maps, missing content, and duplicate names. Changed maps need
`--refresh`; the extracted tree is the covering representation, not a second copy of the bundle.

**What ingest admits.** `code-ingest` publishes a content-addressed, read-only sealed copy under
`tools/analysis-state/code-snapshots/` (the origin stays provenance, never an analysis root), records
every excluded entry in a manifest, and captures Git HEAD, branch, and dirty state as data without
running anything the repository's config, attributes, or hooks name. The default policy excludes
`vendor/` and `env/` only when they hold package-manager or virtualenv output, plus `.phps`
source-display copies and minified JavaScript/CSS. A copied-in project, or a `vendor/`/`env/`
holding no tool output, is admitted as source; when such a directory is a quarter or more of the
admitted set, the ingest summary names it and the `--exclude-path` that drops it. Re-admit with
`--include-path '<dir>/**'`, `--include-minified`, or `--include-skipped`; `code-index build` warns for
each excluded directory a PHP include reaches. Inspect the exclusion manifest whenever a path you
expected is absent.

Ingest prints the authoritative `repo_id: <id>`, active generation, source-manifest digest, sealed
snapshot path, and the exact follow-up `code-index` commands. The backend assigns each file an
integer `file_id`; read the mapping with `vigil assess fetch "code/files?repo_id=<repo-id>"
--paginate`, since without `--paginate` the route serves one bounded page and later ids read as
missing. An exact reingest reuses the snapshot and generation; an analysis-relevant change creates a
new generation and keeps older snapshots as history. A repository that predates the current
snapshot format must be reingested, reindexed, and have its threat model rebound before readiness.

**What the index records.** `code-index build` parses the exact sealed bytes, one resource-limited
child process per file (`--jobs`), falling back to a bounded streaming security scan when a file
crosses the parser boundary. Each per-file artifact holds the function map, `<top-level>` file-scope
segments, entry points, sinks, exports, and call sites, and is marked `complete`, `degraded`, or
`unsupported` with its unavailable or truncated dimensions. The manifest's `path_to_index` map is the
only supported file-to-index lookup; its values are relative to the `structural-index/` root. The
artifact path carries an indexer digest, so rebuilding after a Vigil upgrade writes a new immutable
artifact for sync to publish. `code-index sync` validates every file against the backend
inventory before an all-or-none write. If tree-sitter is unavailable, fix the local `uv` environment
and rerun; never skip structural indexing for a fresh engagement.

The function map and `<top-level>` segments are the hunter's completeness anchor
(`agent/shared-constraints-code.md` §2); sinks, exports, and import targets are advisory navigation,
not a scope limit. An advisory ctags index, when trusted ctags is available, is bound to the same
generation and digest.

```bash
vigil assess transition-phase classify-map
```

Exit: the sealed snapshot is verified and structural metadata is current for every admitted file in
its exact generation. Degraded, unsupported, or truncated artifacts remain visible coverage debt but
do not block Classify + Map or Hunt; route those files through direct sealed-source review in Phase
2, whose durable receipts are a non-overrideable requirement before Verify + Variant. ctags stays
advisory.

---

Phase index (path → purpose) lives in `agent/operator-core-code.md` under "Phase Index". Next: `agent/phases/code-phase-1-classify-map.md`.
