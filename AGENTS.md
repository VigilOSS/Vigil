-
# Maintainer & contributor guide

This is the hand-maintained development guide for the repository: local setup, the
"clone -> first dispatch" walkthrough, step-by-step recipes for extending the system, and the
verification and regeneration rules contributors must follow. It is **not** the operator prompt —
`agent/AGENTS.md` is the generated operator wrapper, and editing it directly is overwritten on the
next render.

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

# Version control: Jujutsu (jj)

This repository is managed with **[Jujutsu (`jj`)](https://github.com/jj-vcs/jj)** (v0.40+),
**colocated** with Git — a `.jj/` and a `.git/` sit side by side. Plain `git` *read* commands
(`git log`, `git status`, `git diff`) still work and reflect the live state, but make all
commits / branches / pushes with `jj`, **not** `git` — mixing in `git commit`/`checkout`/`branch`
desyncs the colocation. If you only know Git, internalize these differences first:

- **No staging area.** The working copy *is* a commit (the change at `@`). `jj` auto-snapshots your
  edits into it on every command — there is no `git add`. `jj st` shows the working-copy diff and the
  current change.
- **Describe, then start the next change.** `jj describe -m "msg"` sets the current change's commit
  message; `jj new` opens a fresh empty change on top (so the described one becomes its parent).
  `jj log` shows the graph: the short *change-id* on the left, the Git commit hash on the right, and
  any bookmarks inline.
- **Bookmarks are branches.** `jj` uses *bookmarks* instead of Git branches. PRs here are created with
  `jj git push --change @` (alias `-c`), which mints an auto-named `push-<random>` bookmark and pushes
  it — that is why the PR head branches are named e.g. `push-ommwlslwsorl`. To update an open PR,
  re-run `jj git push` (the bookmark tracks your change). Create/move a named bookmark with
  `jj bookmark set <name> -r @`.
- **Nothing is "detached" or dangling.** Unlike Git there is no detached-HEAD hazard: every change is
  tracked, and `jj op log` + `jj undo` recover any prior state. A Git-style "this commit isn't on a
  branch, move it before you lose it" instinct does **not** apply here.
- **Common map:** `git switch`→`jj edit <rev>` / `jj new <rev>`; `git commit -a`→`jj describe`;
  `git rebase`→`jj rebase`; `git push -u origin HEAD`→`jj git push -c @`; `git stash`→just `jj new`
  (the WIP stays its own change). Pull with `jj git fetch`.

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
   [Install the CLI and workspace](README.md#install-the-cli-and-workspace).

2. **Start the local stack.** One command brings up the Kali runtime, the orchestrator backend (which
   builds the frontend when needed), and any configured mitmproxy/OOB services:

   ```bash
   vigil up
   vigil doctor        # confirm local prerequisites
   vigil status        # confirm live service state
   ```

   The runtime is one shared long-lived Kali container, not per-engagement. See
   [Stack details](README.md#stack-details).

3. **Create an engagement.** The default in non-interactive runs is the parsed hostname as the sole
   in-scope host and `exploit_policy: pause`:

   ```bash
   vigil engagement create https://target.example --hosts target.example
   ```

   The command prints the engagement directory on stdout and a status footer (mitmproxy/OOB state +
   the exact start command) on stderr. For code analysis use `--type code`/`--type both`, and for blue
   incident work use `vigil blue engage`. See [Starting an engagement](README.md#starting-an-engagement).

4. **Start a client in the engagement.** The CLI verb changes into the engagement directory, exports
   `ENGAGEMENT_DIR`, mounts the `.codex/agents` / `.claude/agents` prompt symlinks, and execs the
   launcher:

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
   [Engagement operator start prompts](README.md#engagement-operator-start-prompts) for the generic
   and resume forms, and [Blue incident engagements](README.md#blue-incident-engagements) for the
   blue variant.

# Adding to the system: step-by-step recipes

Each recipe lists every registration point a change must touch so it does not half-land. When a
recipe mentions a contract owner or sync relationship, [`CODE-MAP.md`](CODE-MAP.md) is the
authority for which file owns what — these recipes name the files; the map explains the boundaries.

## Add a skill

Skills are the procedure layer: workflow and vuln-family methodology that specialists load on
dispatch. Discovery is a directory walk, so a skill is self-registering — there is intentionally no
roster file to edit.

1. Create `agent/skills/<name>/SKILL.md` with YAML frontmatter. `description` is what
   `vigil assess list-skills` shows the operator; `name` is optional metadata (the directory name is
   the canonical identifier that `--skills` resolves on disk):

   ```markdown
   ---
   name: <name>
   description: One-line "use when" summary the operator scans to pick this skill
   origin: Vigil
   ---

   # <Title>

   ## When to Activate
   ...

   ## Tools
   ...
   ```

2. Confirm discovery — no other file needs editing:

   ```bash
   vigil assess list-skills | grep <name>
   ```

   `agent/scripts/assess/commands/list_skills.py` globs `agent/skills/*/SKILL.md` and parses the
   frontmatter, so the skill appears the moment its directory exists. If `description` is omitted it
   falls back to the first `# ` heading. The deprecated `agent/SKILL.md` roster is a soft pointer
   only — do not add the new skill there.

3. Reference the skill by `name` from the prompt layer that should dispatch it
   (`agent/operator-core*.md` or a role prompt under `agent/agents/`). The operator passes the skill
   `path` to the specialist; the operator itself does not read skill bodies.

## Add an `vigil assess` verb

`vigil assess` is the agent-facing contract surface. A verb is one command module plus its wiring and
a test. `agent/scripts/assess/cli.py` is the authoritative subcommand registry.

1. Create `agent/scripts/assess/commands/<name>.py` exposing a `register(subparsers)` that adds the
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

2. Wire it into `agent/scripts/assess/cli.py` in **both** places: add `<name>` to the
   `from assess.commands import (...)` block and add the module to the `for mod in (...)`
   registration loop. (Kali tool verbs register into the separate `kali_sub` loop instead.)

3. If the verb carries durable contract metadata operators should introspect, add it to
   `agent/scripts/assess/lib/contracts.py` so `vigil assess contract <verb>` documents it — that is the
   only operator-facing surface for verb contracts.

4. Add a test under `orchestrator/backend/tests/test_<name>.py`. Load the command module with the
   `sys.path.insert(0, agent/scripts)` + `importlib` pattern used by
   `orchestrator/backend/tests/test_anomaly_score.py`, then assert on `run(...)` behavior:

   ```bash
   uv run --directory orchestrator/backend pytest orchestrator/backend/tests/test_<name>.py
   ```

   If the verb persists a new field that the backend stores, follow the coupling and registration
   notes in [`CODE-MAP.md`](CODE-MAP.md) (Prompt-to-backend coupling and Easy-to-miss registration
   points) so the CLI, Pydantic model, DB column, and service layer all land together.

## Add a deterministic oracle

Oracles are pure decision helpers — no LLM, no network, no backend store. They give specialists a
reproducible verdict (anomaly ranking, payload classification, reachability) the operator can trust.
`anomaly-score` is the reference implementation.

1. Put the pure logic in `agent/scripts/assess/lib/<name>.py`. It must be deterministic and
   side-effect-free: same input, same output, every time — that is what lets an agent rely on the
   verdict without re-running a tool.

2. Add a thin CLI wrapper at `agent/scripts/assess/commands/<name>.py` that reads input (file or
   stdin), calls the lib, and prints a human table (default) or `--json`. Register it exactly as in
   the verb recipe above (both spots in `cli.py`). The command stays I/O-only so the testable logic
   lives in the lib.

3. Add `orchestrator/backend/tests/test_<name>.py` covering the lib's pure function and a CLI smoke
   for file + stdin input, mirroring `test_anomaly_score.py`. Keep every case deterministic:

   ```bash
   uv run --directory orchestrator/backend pytest orchestrator/backend/tests/test_<name>.py
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

   ```bash
   vigil assess eval-capture \
     --engagement-dir <engagement-dir> \
     --out tests/eval/fixtures/golden_<name>.json \
     --definition tests/eval/definitions/<name>.yaml
   ```

3. Run the harness from the repo root (the backend venv supplies `assess.lib.*`; running from inside
   `orchestrator/backend` silently collects zero tests — see `tests/eval/README.md`):

   ```bash
   uv run --directory orchestrator/backend pytest ../../tests/eval
   ```

   Commit the fixture and definition together so replay stays zero-token. Use
   `vigil assess eval-capture ... --check` after a re-run to diff a fresh capture against the committed
   baseline without overwriting it; it exits non-zero on a coverage regression.

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

# Operator prompt regeneration

`agent/operator-core.md` is the source for the rendered red operator prompts.
`agent/operator-core-blue.md` is the source for blue per-engagement operator prompts. When you change
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

Use this section when editing prompts. It is intentionally architectural rather than field-specific.
`CODE-MAP.md` documents file ownership; this section documents how the prompt layers fit together
so edits land in the right place and do not create drift.

## Prompt layers

- `agent/operator-core.md` is the source-of-truth operator loop for web/runtime engagements.
  It defines phase flow, dispatch rules, recording rules, and backend-vs-artifact truth boundaries.
- `agent/operator-core-code.md` is a mode overlay for white-box code analysis. It reuses the same
  backend and CLI, but changes phases, dispatch context, and specialist responsibilities.
- `agent/operator-core-blue.md` is the source-of-truth operator loop for blue-team incident
  engagements. It defines intake/triage/investigate/verify/respond/report flow, tenant-reference
  injection, and containment proposal/approval/recording boundaries.
- `agent/AGENTS.md` and `agent/CLAUDE.md` are generated operator wrappers. They are committed outputs,
  not authoring surfaces. If they need semantic changes, edit the source prompt and rerender.
- `agent/agents/*.md` are role prompts. They define agent identity, responsibilities, handoffs,
  and examples for a specific specialist. They should not become an independent source of backend
  contract truth.
- `agent/shared-constraints.md`, `agent/shared-constraints-code.md`, and `agent/shared-constraints-blue.md` are the first-load
  specialist contract layer. Rules that must hold across many specialists belong here or in the
  CLI, not in only one role prompt.
- `agent/rules/*.md` are always-active behavioral rules. They shape methodology and writing style;
  they are not the place to define endpoint ownership or payload schemas.
- `vigil assess` and the underlying `agent/scripts/assess.py` helper subcommands are the agent-facing contract surface for
  durable state. If a helper owns a lifecycle transition, prompts should point to that helper
  instead of teaching raw endpoint payloads from memory.

## Editing rules

- Put workflow and orchestration changes in `operator-core.md`, `operator-core-code.md`, or `operator-core-blue.md`,
  because those files define how the system moves between phases and specialists.
- Put cross-specialist constraints in `shared-constraints*.md`, because that is where subagents
  load durable recording and scope rules before role-specific instructions.
- Put role-specific reasoning guidance in `agent/agents/*.md`, because that is where identity,
  examples, and handoff semantics live.
- Put payload-shape and lifecycle truth in CLI helpers when possible. Prompts should reference
  helper commands such as `vigil assess contract`, `record-finding`, `verify-finding`, `kill-finding`,
  `reset-finding`, and `update-finding` rather than duplicating raw schema details.
- Treat generated artifacts as drift detectors, not authoring targets. If you edit a generated
  prompt directly, the next render will overwrite it.

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

## Markdown prompt/doc testing policy

Do not add or maintain repository tests that assert `.md` prompt/doc wording, headings, or exact
strings. Markdown prompts and docs are authored prose; brittle wording tests turn normal prompt
editing into fixture maintenance and encourage preserving stale phrasing instead of improving the
instructions. Keep durable contracts in code-owned surfaces instead: CLI helpers, backend request
models, schema generation, API/service behavior, and tests for those executable contracts. For
prompt/doc changes, rerender generated artifacts when required and review the markdown diffs.

# Tests & verification

The verification surface is **not one command**: 4 pytest scopes + a render-check + a schema-check + lint/types + the bench rungs, each with a different venv, prereqs, and cost. CI (`.github/workflows/ci.yml`) is authoritative for the blocking gates — backend pytest, the markdown-vs-CLI sync-lint, the deterministic eval, ruff, and mypy.

> **Never run a bare `pytest` from the repo root, and always go through the backend venv.** Scope every run to one suite — duplicate `test_vigil_cli.py` basenames in `tests/` and `agent/scripts/assess/tests/` collide under a single collection. The backend venv (`uv run --directory orchestrator/backend --extra dev …`) is the one interpreter that can collect every suite; the root `.venv` hard-errors on `tests/eval` (unconditional `import yaml`), and `uv run` *without* `--extra dev` fails to spawn pytest in a clean env.

| Suite / gate | Command | Cost |
|---|---|---|
| Backend (incl. sync-lint) | `uv run --directory orchestrator/backend --extra dev pytest` | free |
| Root CLI / bench harness | `uv run --directory orchestrator/backend --extra dev pytest "$(git rev-parse --show-toplevel)/tests"` | free |
| Assess CLI | `uv run --directory orchestrator/backend --extra dev pytest "$(git rev-parse --show-toplevel)/agent/scripts/assess/tests"` | free |
| Deterministic eval (absolute path is load-bearing) | `uv run --directory orchestrator/backend --extra dev pytest "$(git rev-parse --show-toplevel)/tests/eval"` | free |
| Prompt render-check | `cd agent && ./scripts/render-operator-prompts.sh check` | free |
| Schema `--check` | `uv run --directory orchestrator/backend python scripts/generate_agent_schemas.py --check` | free |
| Lint / types | `uvx ruff check .`  ·  `uvx --with-editable . mypy src/vigil_cli` | free |
| Bench factory solvability gate | `python -m vigil_cli.bench.factory.verify --family <id> --seeds 0 1 2` | free, **docker** |
| Bench selftest (pipeline, no LLM) | `vigil bench selftest` | free |
| Bench run (live agent) | `vigil bench run --launch auto …` | **BILLED** — see Live tests |

- **Integration tests are deselected by default** (`-m 'not integration'` in both pyprojects); opt in with `pytest -m integration` only after rebuilding the runtime image (`test_oob_correlate.py`, backend `test_runtime_tooling_contract.py`, `test_kali_cli.py`).
- **CI gap:** CI does not gate the root `tests/` (bench harness) or the assess CLI suite — run those two locally before handing off harness/recon changes.

## Live tests (billed — read before launching)

`vigil bench run --launch auto` spawns real Claude/Codex agents against generated targets: it **costs money and runs for hours** (reference: a full K=5 × 3 seed-0 run is ~5–6h / ~$50). Validate without a model first via the free paths — `--launch scripted` (reference solver, docker) and `vigil bench selftest`. Do not launch `--launch auto` without an explicit go-ahead.

## Per-family wall-clock timeouts (D-5)

The benchmark harness kills a stuck run at a **per-family** wall-clock budget, defined in the editable table `FAMILY_TIMEOUTS` in `src/vigil_cli/bench/models.py`. A measured family uses a budget derived from its observed runs (≈1.5–2× the observed max wall time under `~/.vigil-bench/runs/`); an unmeasured family (no table entry) falls back to the generous `GENEROUS_UNKNOWN_FAMILY_TIMEOUT` so it is never killed before its real duration is known.

- [ ] **TODO — record a new family's wall time and set its timeout.** When a new benchmark family is run for the first time, record its observed wall-clock time and set/refresh its per-family timeout in the codebase (`FAMILY_TIMEOUTS` in `src/vigil_cli/bench/models.py`) if none exists yet. Until then it runs under the generous unmeasured-family fallback; do not leave a family on the fallback once you have real timing data.

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

# Prompt Authoring Standards

All prompts in this system — operator instructions, agent prompts, skill definitions, and rules — follow
these conventions based on [Anthropic's prompt engineering guidance](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/overview). Apply them when writing new prompts or editing existing ones.

## Positive instructions with reasoning

State what to do, then explain why. The reasoning helps the model generalize to edge cases that
the literal rule doesn't cover.

Instead of: "Do NOT test directly with host-side commands."
Write: "Dispatch to the appropriate subagent for testing — analysis and testing belong to specialist agents because they carry the skill context and methodology depth that the operator prompt lacks."

The reasoning ("because they carry the skill context") lets the model judge novel situations where
the rule might or might not apply, rather than pattern-matching on the prohibition.

## Why this matters for LLM prompts

Negative instructions ("don't do X") tell the model what to avoid but leave the desired behavior
unspecified. The model must infer what to do instead, which introduces ambiguity. Positive
instructions ("do Y, because Z") specify the desired behavior directly and ground it in a reason
the model can evaluate.

## Structure for constraints

When a constraint is load-bearing (safety, correctness, or quality depends on it):

```
[What to do] — [why, in terms of what breaks if violated]
```

Examples from this prompt set:
- "Use `vigil assess record-surface` for all surface writes — calling the library directly bypasses backend sync"
- "Finding IDs are allocated by `vigil assess record-finding` under a lock — hand-allocating risks collisions"
- "Route all in-scope target work through Kali MCP — host-side probes bypass the runtime's network isolation"

## Role clarity in agent prompts

Each agent prompt starts with a single sentence that establishes identity and scope. This focuses
the model's behavior without requiring prohibition lists.

Example: "You are the primary vulnerability analyst for source code. You receive pre-built context
slices and your job is to determine whether an attacker controlling the identified inputs can
cause harm."

## Checklist format for verification

Use markdown checkboxes for pre-work and pre-output verification steps. Checklists are more
reliable than prose instructions because the model can evaluate each item independently.

## Division of labor over prohibition

When the operator should not do something, frame it as belonging to a specific agent rather
than as a prohibition on the operator.

Instead of: "The operator must not evaluate guards or sinks."
Write: "Guard and sink evaluation belong to code-vuln-hunter — the operator provides the context slices and records the results."
