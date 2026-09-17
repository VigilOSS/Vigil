# Maintainer & contributor guide

This is the development guide for the repository: local setup, the
"clone -> first dispatch" walkthrough, step-by-step recipes for extending the system, and the
verification and regeneration rules contributors must follow.

Read alongside this file:
- [`README.md`](README.md) — install, runtime model, and engagement startup reference for users.
- [`CODE-MAP.md`](CODE-MAP.md) — the stable structure/ownership map: where a concern lives, which
  file owns a contract, and which generated files must stay in sync. This guide does not restate it;
  consult it whenever a change might move a boundary.

# Code quality

This is production security tooling held to a top-tier bar: the standard is what a leading
autonomous-offensive-security company (XBOW, Horizon3, Armadin) would ship and maintain for years —
not a prototype. Every change should leave the codebase clearer than it found it.

- **Correctness over speed.** Verify behavior (the right test scope, or a real run) before calling
  something done — never hedge a passing result or bury a failure. "Probably works" is not finished.
- **Every line earns its place.** Prefer deleting to adding; match the surrounding idiom, naming, and
  comment density; a comment explains *why*, not what. No dead code, no speculative abstraction, no
  second copy of a value that already has a single source of truth.
- **Land changes whole.** Touch every registration point a change needs (see the recipes + `CODE-MAP.md`)
  so nothing half-lands, and keep generated artifacts, schemas, and the map in sync in the same change.
- **Durable over expedient.** Fix the root cause, not the symptom. Choose the design that still reads
  well in a year and write it so the next maintainer needs no archaeology.
- **Tests fail first.** For a behavior change or bug fix, write the smallest focused regression and
  run it before production edits. The failure must demonstrate the missing behavior—not a collection,
  import, fixture, or syntax error—then make it green and run the impacted suite.
- **Coverage is the mission; difficulty never narrows scope.** This is threat-hunting tooling — the
  goal is *precision and deep coverage* so a real finding is never missed. Never drop, defer, or
  down-scope a detection/classification improvement because the correct mechanism is more code or
  harder to build; implement the behaviorally-correct, robust version. The *only* reason to reshape a
  change is correctness — an additive/boost-only invariant, a pinned regression, or a mechanism that
  would misclassify (e.g. naively splitting compound param keys routes every `?return_url=` to SSRF
  because `url` is a high-weight key). When correctness forces a reshape, you change *how* the
  improvement lands (e.g. curated whole-keys + a capped weak-signal tier), not *whether* it lands. A
  simpler mechanism that misroutes or misses signal is not an acceptable trade for less code.
- **Never hide Vigil's data from Vigil's operator.** Credentials, tokens, cookies, `Authorization`
  headers, proxy URLs and raw argv render verbatim — in the frontend, in CLI and `--json` output, in
  agent-readable stdout, and in exports. Do not add masking, redaction, `[masked]`/`***`
  substitution, secret-shaped regexes, reveal toggles, redaction profiles, or
  length/prefix/shape projections (`Bearer (length=40)`). Vigil runs on the operator's machine,
  against authorized targets, with the engagement's own credentials; there is no adversary on the
  operator's side of that boundary, so such a control has no true positive to find and only its
  false positives are observable — a previous masker silently truncated whole command lines out of
  the audit view. [ADR 0019](docs/adr/0019-vigil-does-not-defend-against-its-own-operator.md) is the
  authority, and it carves out the four controls that *do* have a real adversary and must not be
  removed by citing it: benchmark anti-cheat, scope/ROE enforcement, proof and evidence integrity,
  and the untrusted-target-text boundary (ADR 0018). Before adding any control that withholds data,
  name the adversary it excludes; if the answer is "the operator, from their own data", it is
  theater and the evidence cost is the only real effect.

# Explaining work (breakdowns & planning)

When asked for a breakdown, an explanation, or to justify a change, answer at BOTH altitudes:
a **high-level** framing (why it matters for Vigil's mission — precision, deep coverage, trustworthy
state over vibe) and a **low-level** view (the concrete files/mechanics), and argue each change on how
it helps quality and depth. Do not answer at one altitude only — a single-altitude answer is incomplete.

# Version control: Jujutsu (jj)

Maintainers work this repository with **[Jujutsu (`jj`)](https://github.com/jj-vcs/jj)**
(v0.40+), **colocated** with Git. A fresh `git clone` has no `.jj/`, so colocate yours once:

```bash
jj git init --colocate
```

After that a `.jj/` and a `.git/` sit side by side. Plain `git` *read* commands (`git log`,
`git status`, `git diff`) still work and reflect the live state, but make all commits /
branches / pushes with `jj`, **not** `git` — mixing in `git commit`/`checkout`/`branch`
desyncs the colocation. To learn more load the Jujutsu skill.

# Newcomer walkthrough: clone to first dispatch

This is the shortest path from a fresh clone to a running operator loop. It points at `README.md`
for install and runtime detail rather than duplicating it — read [Quick Start](README.md#quick-start)
there for the full reference, env-var precedence, and resource sizing.

1. **Install the CLI and working root.** The `vigil` CLI is the only supported entrypoint. From a
   checkout you are developing on:

   ```bash
   uv tool install --editable .
   vigil install ~/vigil
   ```

   `vigil install ~/vigil` seeds (or upgrades, in place) the working root that holds the
   shared prompt tree, generated client wrappers, runtime assets, and orchestrator state. Engagements,
   the orchestrator DB, and `.env` are never moved or deleted on re-install. See
   [The two layers: CLI binary vs working root](README.md#the-two-layers-cli-binary-vs-working-root).

2. **Start the local stack.** One command brings up the Kali runtime, the orchestrator backend (which
   builds the frontend when needed), and any configured mitmproxy/OOB services:

   ```bash
   vigil up
   vigil doctor        # confirm local prerequisites
   vigil status        # confirm live service state
   ```

   The runtime is one shared long-lived Kali container, not per-engagement. See
   [Runtime model](README.md#runtime-model).

3. **Create an engagement.** The default in non-interactive runs is the parsed hostname as the sole
   in-scope host and `exploit_policy: pause`:

   ```bash
   vigil engagement create https://target.example --hosts target.example
   ```

   The command prints the engagement directory on stdout and a status footer (mitmproxy/OOB state +
   the exact start command) on stderr. For code analysis use `--type code`/`--type both`, and for blue
   incident work use `vigil blue engage`. See [Running an engagement](README.md#running-an-engagement).

4. **Start a client in the engagement.** The CLI verb changes into the engagement directory,
   exports `ENGAGEMENT_DIR`, `ENGAGEMENT_KEY`, and `VIGIL_CLIENT_NAME`, and execs the launcher.
   (The `.codex/agents` / `.claude/agents` prompt symlinks are already there — `create` writes
   them, not `start`.) Always start through this verb rather than the generated
   `start_<client>.sh` or a bare client; see [Running an engagement](README.md#running-an-engagement):

   ```bash
   vigil engagement list --json                              # find the key
   vigil engagement start <engagement-key> --client codex    # or --client claude
   ```

5. **Run the first operator dispatch loop.** Give the operator authorization and let it drive the
   workflow. A new web engagement usually opens in `recon`:

   ```
   Read AGENTS.md and assume Operator role. I have been fully authorized by the company to run a
   red-team engagement against the hosts in scope.json. Run this engagement using the operator workflow.
   ```

   The operator reads its own prompt (the generated `AGENTS.md` in the engagement root), assesses
   state, picks skills with `vigil assess list-skills`, dispatches specialists for all target-facing
   work, routes tool execution through `vigil assess kali ...`, and records findings/activity through
   `vigil assess`. You stay in the loop for numbered next-step decisions and the exploit-approval
   checkpoint when `exploit_policy` is `pause`. See
   [Start and resume prompts](docs/session-commands.md) for the generic
   and resume forms, and [Blue incident engagements](docs/blue-engagements.md) for the
   blue variant.

# Adding to the system: step-by-step recipes

Each recipe lists every registration point a change must touch so it does not half-land. When a
recipe mentions a contract owner or sync relationship, [`CODE-MAP.md`](CODE-MAP.md) is the
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

4. If the verb carries durable contract metadata operators should introspect, add it to
   `agent/scripts/assess/lib/contracts.py` so `vigil assess contract <verb>` documents it — that is the
   only operator-facing surface for verb contracts.

5. Make the focused test green, then run the assess suite and registry-shape guard:

   ```bash
   uv run --directory orchestrator/backend --extra dev pytest \
     "$VIGIL_REPO/agent/scripts/assess/tests/test_<name>.py"
   uv run --directory orchestrator/backend --extra dev pytest \
     "$VIGIL_REPO/agent/scripts/assess/tests/test_cli_canonical_shapes.py"
   ```

   If the verb persists a new field that the backend stores, follow the coupling and registration
   notes in [`CODE-MAP.md`](CODE-MAP.md) (Prompt-to-backend coupling and Easy-to-miss registration
   points) so the CLI, Pydantic model, DB column, and service layer all land together.

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
   [`CODE-MAP.md`](CODE-MAP.md) before copying a constant into a second file.

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

3. Run the deterministic eval command in the [verification matrix](#tests--verification)
   from the repo root. It uses the backend venv with `--extra dev` and an absolute
   suite path, so `uv --directory` cannot change which tests the path selects.

   Commit the fixture and definition together so replay stays zero-token. Use
   `python agent/scripts/assess/commands/eval_capture.py ... --check` after a re-run to diff a fresh
   capture against the committed baseline without overwriting it; it exits non-zero on a coverage regression.

# Code map maintenance

If you make a change that would make `CODE-MAP.md` inaccurate, update `CODE-MAP.md` in the same change.

Update it when you:
- add, remove, rename, or move a stable entrypoint;
- change which file owns a contract or subsystem boundary;
- change a generation or sync relationship;
- add or remove a durable API, service layer, tab, or CLI command family;
- move a concern to a different canonical directory.

Do not churn it for:
- implementation-only edits inside an unchanged boundary;
- field-level or helper-level changes that do not create a new durable seam;
- caches, generated artifacts, vendor trees, or local-machine state.

# Freshness and restart-manifest maintenance

`src/vigil_cli/restart_manifest.py` derives what an install invalidated; read its docstring before
changing this area.

**Never judge install-managed content by mtime.** `install.py` rewrites every managed file
unconditionally, so any timestamp comparison reads stale the instant an install finishes. Use a
content digest stamped on the consumer — see `src/vigil_cli/image_freshness.py`.

Sets derived from `sys.modules` need no upkeep, with one qualification: the startup snapshot is
taken once at import, so a module first imported LATER is in neither the snapshot nor the declared
set. `app/main.py:_ImportDigestRecorder` sits in `sys.meta_path` ahead of `PathFinder` and digests
each install-root source file as it is imported, so the comparison uses the bytes the import
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

# Operator prompt regeneration

`agent/operator-core.md` is the source for the rendered red operator prompts.
`agent/operator-core-blue.md` is the source for the canonical blue operator prompt. When you change
`agent/operator-core.md`, `agent/operator-core-blue.md`, `agent/agents/*.md`, or
`agent/scripts/render-operator-prompts.sh`, rerender the affected tracked artifacts before handing off:

```bash
cd agent
./scripts/render-operator-prompts.sh repo
# If blue prompt sources or shared blue-role prompts changed:
./scripts/render-operator-prompts.sh repo --type blue
```

After rerendering, review the generated prompt diffs directly. The repository does not
maintain tests that assert markdown prompt/doc wording, headings, or exact strings.

The Claude `PreCompact` hook's stdout is currently used as summarizer instructions. That behavior
was verified against Claude Code 2.1.261 but is a third-party implementation detail, not a published
contract; re-verify it when upgrading the client. Codex compaction steering is not shipped.

# Assess schema regeneration

Backend-backed schemas in `agent/schemas/` are generated from backend request models plus explicit
agent-side overlays in `orchestrator/backend/scripts/generate_agent_schemas.py`. Regenerate them
when you change assessment/code-analysis request models or the agent-side schema overlays:

```bash
uv run --directory orchestrator/backend python scripts/generate_agent_schemas.py
```

Check for schema drift with:

```bash
uv run --directory orchestrator/backend python scripts/generate_agent_schemas.py --check
```

# Prompt system flow

`CODE-MAP.md` owns file boundaries; this section routes prompt edits.

## Prompt layers

- `agent/operator-core.md` owns the web/runtime operator loop; `operator-core-code.md` is its
  white-box overlay; `operator-core-blue.md` owns the blue incident loop.
- `agent/AGENTS.md`, `agent/AGENTS-blue.md`, and `agent/CLAUDE.md` are generated outputs. Edit their
  source prompts and rerender.
- `agent/agents/*.md` owns role-specific identity, reasoning, and handoffs.
- `agent/shared-constraints*.md` owns rules that every applicable specialist loads first.
- `agent/rules/*.md` owns always-active behavior, not payload or endpoint contracts.
- `vigil assess` helpers own durable payload and lifecycle truth; prompts point to those helpers.

## Editing rules

- Put workflow in operator cores, cross-role rules in shared constraints, and role-specific guidance
  in `agent/agents/*.md`.
- Put payload and lifecycle truth in CLI helpers such as `vigil assess contract`, `finding record`,
  `finding verify`, and `finding update`; do not duplicate schemas in prompts.
- Generated artifacts are drift detectors, never authoring targets.

## Prompt edit checklist

When changing any finding, lifecycle, or dispatch wording, review these files together before
editing so the change stays coherent across layers:

1. `agent/operator-core.md`
2. `agent/operator-core-code.md` if code analysis is involved
3. `agent/operator-core-blue.md` if blue incident response is involved
4. Relevant `agent/agents/*.md` role prompts
5. `agent/shared-constraints.md`, `agent/shared-constraints-code.md`, or `agent/shared-constraints-blue.md`
6. The owning `vigil assess` / `vigil blue` helper command and its tests
7. Generated operator wrappers after rerendering

If a change affects prompt generation, rerender and review the generated wrapper diffs.
If a change affects CLI ownership or lifecycle behavior, run the relevant backend CLI and API tests,
not markdown wording tests.

Run the change against the **prompt health ruleset** in
[`docs/prompt-authoring-standards.md`](docs/prompt-authoring-standards.md) as well — it is the
standing checklist for Load-First budgets, MANDATORY-vs-LOAD-ON-FIRST-USE splits, duplication, and
dispatch-field placement, and applies on top of the coherence pass above.

If the change adds a primitive to a role (a Load-First shape, a dispatch field, a disposition
vocabulary, a pointer form), it is not done until it is propagated and grep-verified across every
role it applies to — see Rule 12 of that ruleset. "Added to one role" is a prototype, not a landed
change.

## Markdown prompt/doc testing policy

Do not add or maintain repository tests that assert `.md` prompt/doc wording, headings, or exact
strings. Markdown prompts and docs are authored prose; brittle wording tests turn normal prompt
editing into fixture maintenance and encourage preserving stale phrasing instead of improving the
instructions. Keep durable contracts in code-owned surfaces instead: CLI helpers, backend request
models, schema generation, API/service behavior, and tests for those executable contracts. For
prompt/doc changes, rerender generated artifacts when required and review the markdown diffs.

# Prompt authoring standards

Every prompt in this system — operator doctrine, role prompts, skills, shared constraints, and
rules — follows the conventions in
[`docs/prompt-authoring-standards.md`](docs/prompt-authoring-standards.md): the twelve-rule
**prompt health ruleset** (Load-First budgets, MANDATORY-vs-LOAD-ON-FIRST-USE splits, DRY,
mode-gating, dispatch-field placement, FP-gate naming, root-causing prohibitions, and primitive
propagation) plus the authoring principles behind it (positive instructions with reasoning,
division of labor over prohibition, role clarity, checklist verification). Run every prompt/doc
edit through that ruleset in addition to the **Prompt edit checklist** above.

# Tests & verification

The verification surface is **not one command**: 4 pytest scopes + a render-check + a schema-check + lint/types + the bench rungs. All four pytest scopes use the backend venv; the other gates have their own prerequisites and costs. CI (`.github/workflows/ci.yml`) is authoritative for the blocking gates — backend pytest, the markdown-vs-CLI sync-lint, the deterministic eval, the root `tests/` suite, the assess CLI suite, the frontend build, ruff, and mypy.

> **Never run a bare `pytest` from the repo root, and always go through the backend venv.** Scope every run to one suite — duplicate `test_vigil_cli.py` basenames in `tests/` and `agent/scripts/assess/tests/` collide under a single collection. The backend venv (`uv run --directory orchestrator/backend --extra dev …`) is the one interpreter that can collect every suite; the root `.venv` hard-errors on `tests/eval` (unconditional `import yaml`), and `uv run` *without* `--extra dev` fails to spawn pytest in a clean env.

Set `VIGIL_REPO` to your checkout root first — the commands below are absolute
because `uv --directory` changes the working directory:

```bash
VIGIL_REPO=$(git rev-parse --show-toplevel)   # or: VIGIL_REPO=$(jj root)
```

| Suite / gate | Command | Cost |
|---|---|---|
| Backend (incl. sync-lint) | `uv run --directory orchestrator/backend --extra dev pytest` | free |
| Root CLI / bench harness (excluding eval) | `uv run --directory orchestrator/backend --extra dev pytest "$VIGIL_REPO/tests" --ignore="$VIGIL_REPO/tests/eval"` | free |
| Assess CLI | `uv run --directory orchestrator/backend --extra dev pytest "$VIGIL_REPO/agent/scripts/assess/tests"` | free |
| Deterministic eval | `uv run --directory orchestrator/backend --extra dev pytest "$VIGIL_REPO/tests/eval"` | free |
| Prompt render-check | `cd agent && ./scripts/render-operator-prompts.sh check` | free |
| Schema `--check` | `uv run --directory orchestrator/backend python scripts/generate_agent_schemas.py --check` | free |
| Lint / types | `uvx ruff check .`  ·  `uvx --with-editable . mypy src/vigil_cli` | free |
| Bench factory solvability gate | `python -m vigil_cli.bench.factory.verify --family <id> --seeds 0 1 2` | free, **docker** |
| Bench selftest (pipeline, no LLM) | `vigil bench selftest` | free |
| Bench run (live agent) | `vigil bench run --launch auto …` | **BILLED** — see Live tests |

- **Integration tests are deselected by default** (`-m 'not integration'` in both pyprojects); opt in with `pytest -m integration` only after rebuilding the runtime image (`test_oob_correlate.py`, backend `test_runtime_tooling_contract.py`, `test_kali_cli.py`).
- **Pre-push: mirror the blocking CI gates locally.** Before pushing a branch, run the gates CI blocks on — all four pytest rows above (backend, root `tests/`, assess CLI, deterministic eval; the sync-lint rides inside backend pytest), `uvx ruff check .`, and `uvx --with-editable . mypy src/vigil_cli`. CI runs on a clean checkout, so it catches drift a warm local venv hides.
- **CI covers all four pytest scopes.** `backend-tests`, `eval`, `root-tests`, and `assess-tests`
  are blocking. Path-scoped jobs use absolute paths because `uv --directory` changes the working
  directory. Check pytest's exit status and collected count; an empty selection proves nothing.
- **The `**/data/` ignore trap.** Required resolver lists, fixtures, or golden files under `data/`
  need targeted `.gitignore` negations for every ignored path level. Track them with
  `jj file track <path>` and confirm with `jj file list <path>`; a local untracked file is absent in CI.
- **`skeleton/` sidecars vs mypy.** Bench `skeleton/` `.py` files are container-runtime sidecars that import runtime-only siblings (e.g. `oracle_checkpoint`) mypy can't resolve. They are excluded from mypy via `[tool.mypy] exclude` in `pyproject.toml` (or keep sidecars as `.tmpl`, which mypy ignores). Do **not** "fix" such an `import-not-found` by adding the runtime module to the type path.

## Live tests (billed — read before launching)

`vigil bench run --launch auto` spawns real Claude/Codex agents against generated targets: it **costs money and runs for hours** (reference: a full K=5 × 3 seed-0 run is ~5–6h / ~$50). Validate without a model first via the free paths — `--launch scripted` (reference solver, docker) and `vigil bench selftest`. Do not launch `--launch auto` without an explicit go-ahead.

## Per-family wall-clock timeouts

`src/vigil_cli/bench/models.py:FAMILY_TIMEOUTS` owns measured family budgets. Set one only from an
observed run (roughly 1.5–2× its maximum); unknown families deliberately use the generous fallback.

# Orchestrator backend

The backend is Python 3.11+ and `uv`-first. Use `uv`, not ad hoc `pip` installs:

```bash
uv sync --directory orchestrator/backend --extra dev
uv run --directory orchestrator/backend uvicorn app.main:app --reload
```

Run the backend tests with `uv` (see **Tests & verification** for the full matrix):

```bash
uv run --directory orchestrator/backend --extra dev pytest
```

# Orchestrator frontend

The frontend uses Vite and React:

```bash
cd orchestrator/frontend
npm install
npm run dev
```

Build the frontend before handing off significant UI changes:

```bash
cd orchestrator/frontend
npm run build
```

# Runtime validation

Build the primary runtime image from the repo root:

```bash
docker build -t vigil:latest -f agent/docker/runtime-full/Dockerfile .
```
