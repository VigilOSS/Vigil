# Maintainer recipes

Read [AGENTS.md](../AGENTS.md) for repository-wide rules and the verification matrix,
[CONTRIBUTING.md](../CONTRIBUTING.md) for contribution setup, and [CODE-MAP.md](../CODE-MAP.md)
for ownership and registration boundaries. Read the applicable recipe before changing a subsystem.
Installation and the first engagement walkthrough live in [README.md](../README.md) and
[the installation guide](installation.md).

# Adding to the system: step-by-step recipes

Each recipe lists every registration point a change must touch so it does not half-land. When a
recipe mentions a contract owner or sync relationship, [`CODE-MAP.md`](../CODE-MAP.md) is the
authority for which file owns what — these recipes name the files; the map explains the boundaries.

## Add a skill

Skills are the procedure layer: workflow and vuln-family methodology that specialists load on
dispatch. Discovery walks the skill directories; there is no roster file.

1. Create `agent/skills/<name>/SKILL.md` with YAML frontmatter. `description` is what
   `vigil assess list-skills` shows the operator; `name` is optional metadata (the directory name is
   the canonical identifier that `--skills` resolves on disk):

   ```markdown
   ---
   name: <name>
   description: One-line "use when" summary the operator scans to pick this skill
   origin: Vigil
   vuln_class: <canonical-class>  # required when one or more classes accurately own the skill
   ---

   # <Title>

   ## When to Activate
   ...

   ## Tools
   ...
   ```

2. For an offensive/code skill, set `vuln_class:` to one or more values from
   `agent/scripts/assess/lib/vuln_taxonomy.py`. A process, blue, mobile, or genuinely multi-class
   skill with no accurate class must instead be added to `SKILLS_WITHOUT_VULN_CLASS` in
   `orchestrator/backend/tests/test_vuln_taxonomy.py`; do not invent a class to clear the test.

3. Confirm discovery:

   ```bash
   vigil assess list-skills | grep <name>
   ```

   The directory name is the canonical dispatch identifier. `description` is the discovery summary;
   `name` is optional metadata. Do not add the skill to the deprecated `agent/SKILL.md` pointer.

4. Reference the directory name from the prompt layer that should dispatch it
   (`agent/operator-core*.md` or a role prompt under `agent/agents/`). The operator passes the skill
   `path` to the specialist; the operator itself does not read skill bodies.

5. Run `test_vuln_taxonomy.py`, the list-skill coverage in `test_vigil_cli.py`, and any behavior test
   for the skill's executable helper. Prompt/doc changes are reviewed by diff, not wording tests.

## Add a reference

References are the payload, checklist, and tooling library specialists load on dispatch. Discovery
scans the entire `agent/references/` tree.

1. Create `agent/references/<area>/<name>.md` with YAML frontmatter that includes
   a `description` and, when the reference belongs to a skill, a `skill:` key:

   ```markdown
   ---
   description: One-line summary the operator scans in `vigil assess list-references`
   skill: <skill-name>   # comma-separated when several skills own it
   ---

   # <Title>
   ...
   ```

   Every `skill:` value must resolve to `agent/skills/<name>/`. A deliberately cross-cutting or
   currently unowned reference must be added, with a reason, to `_KNOWN_UNPAIRED` in
   `orchestrator/backend/tests/test_reference_frontmatter.py`; omission alone is a CI failure.

2. Confirm discovery and pairing:

   ```bash
   vigil assess list-references | grep <name>
   vigil assess list-references --skill <skill-name>   # the ref must appear here
   ```

3. Run `test_reference_frontmatter.py` and the list-reference coverage in `test_vigil_cli.py`.
   Remove an allowlist entry as soon as the reference gains a real skill owner.

## Add a `vigil assess` verb

`vigil assess` is the agent-facing contract surface. `agent/scripts/assess/cli.py` is the
authoritative registry, but registration shape depends on the command.

1. Before production edits, add the smallest behavior test under `agent/scripts/assess/tests/` and
   run it through the assess-suite command until it fails for the intended missing behavior. Backend
   persistence also needs a failing backend API/service test.

2. Create `agent/scripts/assess/commands/<name>.py` exposing a `register(subparsers)` that adds the
   parser and sets the handler, plus the `run(args)` handler itself:

   ```python
   def register(subparsers) -> None:
       p = subparsers.add_parser("<verb-name>", help="One-line help.")
       p.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON.")
       p.set_defaults(func=run)

   def run(args) -> None:
       ...
   ```

   Keep payload-shape and lifecycle truth in the command/lib, not in prompts — prompts should point
   at `vigil assess contract <verb>` rather than duplicating the schema.

3. Wire the applicable `cli.py` touch points: the import block plus either the flat loop, one of four
   `_register_subcommand_group(...)` calls, or the inline Kali loop. A command with bespoke action
   help may also need the pre-`parse_args` hook. A Kali verb joins `KALI_TARGET_VERBS` or
   `KALI_MAINT_VERBS`; `KALI_VERBS` is their computed union.

4. If the verb carries durable contract metadata operators should introspect, add its declarative
   entry to `agent/scripts/assess/lib/contract_registry.py`. Dynamic lookup and rendering live in
   `contracts.py`; `vigil assess contract <verb>` is the operator-facing surface.

5. Make the focused test green, then run the assess suite and registry-shape guard:

   ```bash
   uv run --directory orchestrator/backend --extra dev pytest \
     "$VIGIL_REPO/agent/scripts/assess/tests/test_<name>.py"
   uv run --directory orchestrator/backend --extra dev pytest \
     "$VIGIL_REPO/agent/scripts/assess/tests/test_cli_canonical_shapes.py"
   ```

   If the verb persists a new field that the backend stores, follow the coupling and registration
   notes in [`CODE-MAP.md`](../CODE-MAP.md) (Prompt-to-backend coupling and Easy-to-miss registration
   points) so the CLI, Pydantic model, DB column, and service layer all land together.

## Remove or rename a `vigil assess` verb

A shipped verb is a contract. Its callers are prompts, references, transcripts, and operator muscle
memory — none of which a compiler checks — so a rename breaks them even when the behavior is
identical. Removing or renaming one therefore means sweeping every caller, not just the parser.

1. **Prefer an alias to a hard break, and know when the shape of the rename forbids one.** Two
   renames are possible and only one of them has an alias mechanism.

   *Verb to verb, both top level.* `sub.add_parser(new, aliases=[old])` keeps the retired spelling
   routing to the same handler; warn once on stderr. An alias is a registered verb as far as
   `test_skill_cli_sync.py` is concerned — argparse puts aliases in `choices` as their own keys and
   `_assess_registries` reads `set(top)` — so it needs an entry in that file's
   `_KNOWN_UNDOCUMENTED_ASSESS`, because the retired spelling is deliberately absent from the docs
   and that is exactly what the allowlist is for. Pair the entry with the reason, as the existing
   ones do.

   *Top level folded into a group action* — `list-command-runs` → `command-run list`,
   `code-record-analysis` → `code-record analysis`, the two shipped folds. There is
   no alias for this. `_register_subcommand_group` (`agent/scripts/assess/cli.py:98`) takes
   `name`, `help_text`, `dest` and `leaf_modules` and no `aliases`, and an alias on the `list` leaf
   would only add `command-run list-command-runs` — it cannot put a hyphenated spelling back at the
   top level, where the old caller typed it. Keeping the old name means deliberately registering it
   a second time as its own top-level parser that forwards to the group's handler and warns; that
   parser is a registered verb too, so it carries the same allowlist obligation. Nothing in the tree
   does this today: both shipped folds were hard breaks, taken because nothing still referenced the
   old spelling. Verify that claim (`rg` the old name across `agent/`, `docs/`, `README.md`,
   `orchestrator/`, and the contract surface) before making the same call, and say in the change
   that you did.

   Break a name only when keeping it would lie — the old spelling names behavior that no longer
   exists — or when the fold above makes the shim cost more than the callers are worth. Say which,
   in the change.

2. **Keep the old spelling out of the README, docs, and `CHANGELOG.md`.** History lives only in
   ADRs; write one when the decision behind the change is durable.

3. **Move the contract surface with the verb.** `agent/scripts/assess/lib/contract_registry.py` owns
   declarative contract entries; `contracts.py` resolves and renders them. Update the dict key,
   `name`, and every `preferred_invocations` / `notes` /
   `common_mistakes` string that spells the verb. Then sweep the prompt layer under `agent/`,
   `docs/`, and `README.md` — the new spelling everywhere, including an alias you kept, which stays
   out of the docs and in the allowlist instead. `orchestrator/backend/tests/test_skill_cli_sync.py`
   fails in both directions — on prose naming a verb the CLI no longer registers, and on a
   registered verb nothing documents — so run the backend suite before you call the sweep done.

4. **Sweep the strings the CLI *writes*, not only the ones it reads.** Audit titles, activity-row
   titles, and snapshot `metadata.command` values are stamped with the verb name and keep minting
   the old spelling until someone changes them. That is how one verb ends up with two spellings in
   the activity table.

5. **Leave history alone.** Audit rows, activity entries, command runs, and agent transcripts
   written before the change go on naming the verb that existed when they ran, and that is correct —
   they record what was actually executed. Do not add a retroactive alias, a backfill, or a
   display-time rewrite to make old rows read as the new name; that would make the ledger claim
   something that never happened. Aliases are for callers that still run, not for records that
   already did.

## Add a deterministic oracle

Oracles are pure decision helpers — no LLM, no network, no backend store. They give specialists a
reproducible verdict (anomaly ranking, payload classification, reachability) the operator can trust.
`anomaly-score` is the reference implementation.

1. Add focused pure-function and CLI tests under `agent/scripts/assess/tests/`, then run them and
   observe the intended behavioral failure before adding the implementation.

2. Put the pure logic in `agent/scripts/assess/lib/<name>.py`. It must be deterministic and
   side-effect-free: same input, same output, every time — that is what lets an agent rely on the
   verdict without re-running a tool.

3. Add a thin CLI wrapper at `agent/scripts/assess/commands/<name>.py` that reads input (file or
   stdin), calls the lib, and prints a human table (default) or `--json`. Register it through the
   applicable path in the verb recipe. The command stays I/O-only so the testable logic
   lives in the lib.

4. Make the focused tests green, then run the full assess suite. Keep file and stdin cases
   deterministic:

   ```bash
   uv run --directory orchestrator/backend --extra dev pytest \
     "$VIGIL_REPO/agent/scripts/assess/tests/test_<name>.py"
   ```

   When an invariant must exist in exactly one place (a bucket table, an enum, a noise filter), make
   the lib the single source of truth and have consumers import it — see Single sources of truth in
   [`CODE-MAP.md`](../CODE-MAP.md) before copying a constant into a second file.

## Add a language, sink family, or entry-point pattern

The structural index enters through `agent/scripts/assess/lib/treesitter_index.py`.
Tree-sitter dispatch lives there; query, sink, and entry catalogues live in
`treesitter_catalogues.py`, shared helpers in `treesitter_common.py`, line-based extractors in
`treesitter_lightweight.py`, and bounded degraded scanning and its catalogues in
`treesitter_streaming.py`. The registrations span two trees and the catalogue tests carry exact counts.

**A new language or extension:**

1. `agent/scripts/assess/lib/code_languages.py` — `detect_language`, and
   `STRUCTURAL_SUPPORTED_LANGUAGES` for a new language code. A compound suffix (`.blade.php`) needs
   its rule *before* the `Path(name).suffix` lookup, which only ever sees the last extension.
2. `agent/scripts/assess/lib/treesitter_index.py` — tree-sitter extractor, language roster, and
   dispatch. Put query/entry/sink catalogue entries in `treesitter_catalogues.py`, line-based
   extractors in `treesitter_lightweight.py`, and entries in each
   `_STREAM_*_PATTERNS` table in `treesitter_streaming.py`. Without the streaming entries the degraded
   path reports nothing rather than reporting a gap.
3. `orchestrator/backend/app/services/code_analysis_support.py` and `code_analysis.py` — **both**
   language sets.
   `_CANONICAL_STRUCTURAL_LANGUAGES` gates the request: a value missing here 400s `code-index sync`
   for the whole repository. `STRUCTURALLY_ANALYZED_LANGUAGES` grants the baseline vuln families;
   a language in it with no extractor is a set that lies. `test_structural_language_drift.py` exists
   because `.ps1` shipped in exactly that state.
4. Tests that enumerate languages: `test_treesitter_index.py`, `test_code_snapshot_cli.py`, and
   `test_dependency_manifests.py`. Add a behavior test for the extractor itself.

**A new sink family, entry-point pattern, or taint source** is an entry in `_SINK_DEFINITIONS`,
`_ENTRY_*`/`_GLOBAL_ENTRY_LINE_PATTERNS`, or `_STREAM_SOURCE_PATTERNS`. Two rules bind it:

- Every `vuln_classes` string must already exist in `agent/scripts/assess/lib/vuln_taxonomy.py`.
  `test_indexer_scan_scope.py` AST-sweeps the index, catalogues, and lightweight extractor for invented classes.
  A security *source*
  deliberately carries no vuln class.
- The catalogue sweeps assert an exact pattern count and demand every pattern be either exercised by
  a case with a working fixture or listed in that file's exclusion table with a prose reason — never
  both, never neither. They are `test_entry_point_catalogue.py`, `test_streaming_catalogue.py`, and
  the three `test_sink_catalogue_*.py` files. Expect to update a count in the same change.

Fixtures are inline source constants in those test modules; the repository tracks no sample source
files. Update `CODE-MAP.md` only if the change moves a boundary — it is near its size budget.

## Add an eval case

The eval harness replays captured engagement outputs (JSON finding arrays) as offline, deterministic
quality checks — no LLM, no network, no real backend. Cases live under `tests/eval/`.

1. **Hand-authored:** drop a JSON array of finding records into `tests/eval/fixtures/<name>.json`
   (each record validates against `agent/schemas/finding-record.schema.json`), then add a
   `tests/eval/definitions/<name>.yaml` naming the fixture and its assertions (`min_findings`,
   `expected_cwes`, `severity_distribution`, `attacker_outcome_present`, ... each `strict` or `soft`).

2. **Captured from a real engagement:** snapshot a human-blessed engagement's backend findings with
   the orchestrator running. This transforms each row into a schema-valid record, validates every one
   (hard-fail on drift), and can scaffold a green-by-construction definition:

   `eval-capture` is a maintainer/CI tool, intentionally off the operator
   `vigil assess` surface — invoke the module directly (its import chain is
   stdlib-only, so no venv is needed):

   ```bash
   python agent/scripts/assess/commands/eval_capture.py \
     --engagement-dir <engagement-dir> \
     --out tests/eval/fixtures/golden_<name>.json \
     --definition tests/eval/definitions/<name>.yaml
   ```

3. Run the deterministic eval command in the [verification matrix](../AGENTS.md#tests--verification)
   from the repo root. It uses the backend venv with `--extra dev` and an absolute
   suite path, so `uv --directory` cannot change which tests the path selects.

   Commit the fixture and definition together so replay stays zero-token. Use
   `python agent/scripts/assess/commands/eval_capture.py ... --check` after a re-run to diff a fresh
   capture against the committed baseline without overwriting it; it exits non-zero on a coverage regression.

# Freshness and restart-manifest maintenance

`src/vigil_cli/restart_manifest.py` derives what an install invalidated; read its docstring before
changing this area.

**Never judge application content by mtime.** A release is one matched CLI/backend/agent/docs/UI
bundle; `install.py` initializes or adopts private data without copying source. Compare content
digests stamped on consumers — see `src/vigil_cli/image_freshness.py`. `workspace.json` records
initialization provenance; it is not the release identity of an already-running process.

`application.py` validates the exact bundle inventory and materializes immutable version/digest
cache paths. Do not delete retained releases on upgrade: backend processes and client helpers may
still use them. Official client starts serialize shared-file repair and PID/birth-identity receipts
through `client_sessions.py`; explicit global client maintenance uses the same lock. Routine adoption
does not refresh client files. Restart requirements belong to `restart_manifest.consumer_states`.

`vigil_build.py` reads the tracked publisher inventory, excludes private/state/auth files, builds both
locked UI projects in a temporary stage, and records input/output digests. Snapshot intended JJ files
before a publisher build. The resulting sdist carries matched assets and prebuilt UI; its wheel build
must work without Git or Node. Keep bundle inputs and CLI snapshots matched, including hidden client
trees, backend lockfile, Docker definitions, documentation and legal notices.

Sets derived from `sys.modules` need no upkeep, with one qualification: the startup snapshot is
taken once at import, so a module first imported LATER is in neither the snapshot nor the declared
set. `app/main.py:_ImportDigestRecorder` sits in `sys.meta_path` ahead of `PathFinder` and digests
each application source file as it is imported, so the comparison uses the bytes the import
actually read — read it before changing how cross-tree imports are compared, and note that mtime
cannot substitute for it (a byte-identical `vigil install` rewrite would then report a restart).

Declared lists do need upkeep, and each has a guard test that fails before you can forget:

| Change | Update | Guard |
|---|---|---|
| `COPY` in `agent/docker/runtime-full/Dockerfile` | `runtime.py:runtime_image_inputs` | `test_runtime_dockerfile_copy_sources_are_declared_runtime_image_inputs` |
| `COPY` in `agent/docker/mitmproxy/Dockerfile` | `mitmproxy.py:mitmproxy_image_inputs` **and** `_proxy_build_context` | `test_every_proxy_dockerfile_copy_is_covered_by_the_declared_image_inputs` + the staged-context test |
| frontend/report build config or source dir | `restart_manifest.py:frontend_build_inputs` / `report_build_inputs` | `test_*_build_config_files_are_all_declared_inputs`, `test_*_source_directories_are_all_declared_inputs` |
| backend dependency manifest | `app/main.py:_BACKEND_DEPENDENCY_MANIFESTS` | `test_every_top_level_dependency_manifest_is_a_declared_input` |

A new consumer that bakes or caches managed content needs the same three parts: a declared input
set, a digest stamped where the artifact lives, and a row from `consumer_states`.

# Orchestrator report template

`orchestrator/report/` is a separate Vite app that builds the single-file
`dist/template.html` the backend injects an engagement payload into. Its
`src/types.ts` and the field allow-lists in `report_export.py` are two halves of
one contract: the exported HTML is delivered to the *client*, so the export
narrows every projection it calls to the fields the template renders. Change one
side and the other moves with it — and derive the allow-list from what the
components read, not only from what `types.ts` declares. The narrowing belongs
at that delivery boundary and never in the projections themselves: they also
back `GET report-findings` and `vigil assess finding report --json`, where
ADR 0019 requires every column verbatim.

```bash
cd orchestrator/report
npm run build      # typecheck + bundle to dist/template.html
npm test           # shell-quoting tests for the copy-and-run PoC
```

The report renders a `curl` invocation built from attacker-influenced finding
data, and a reader is expected to paste it into a terminal. Quoting it is
therefore a security boundary (ADR 0018), not formatting: `src/lib/poc.ts` owns
it and `src/lib/poc.test.ts` asserts the argv a real `bash` produces. Evidence
and PoC blocks render verbatim in `<pre>`, never through markdown — markdown
rewrites `__init__.py`, eats `>` transcript markers and collapses HTTP pairs onto
one line, which is mutating the operator's capture.

# Test runner notes

- **The backend suite runs in parallel by default.** `addopts` in
  `orchestrator/backend/pyproject.toml` carries `-n auto` (pytest-xdist, one worker per CPU),
  Add **`-n 0`** to force a single process —
  required for `--pdb`, and for reading `--durations` as CPU rather than wall time. The suite is
  process-parallel safe because every test gets its own temp tree (`isolate_settings`), the one
  stub HTTP server binds port 0, and no test writes into the checkout; keep all three true when
  adding tests.
- **Integration tests are deselected by default** (`-m 'not integration'` in both pyprojects); opt in with `pytest -m integration` only after rebuilding the runtime image (`test_oob_correlate.py`, backend `test_runtime_tooling_contract.py`, `test_kali_cli.py`).

- **CI covers all four pytest scopes.** `backend-tests`, `quality-checks` (eval), `root-tests`, and `assess-tests`
  are blocking. Path-scoped jobs use absolute paths because `uv --directory` changes the working
  directory. Check pytest's exit status and collected count; an empty selection proves nothing.
- **The `**/data/` ignore trap.** Required resolver lists, fixtures, or golden files under `data/`
  need targeted `.gitignore` negations for every ignored path level. Track them with
  `jj file track <path>` and confirm with `jj file list <path>`; a local untracked file is absent in CI.
