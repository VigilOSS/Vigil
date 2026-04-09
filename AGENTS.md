# jujutsu VCS

git commands will corrupt data, see ~/.codex/skills/jujutsu/SKILL.md always use jujustu before new changes. Meaning you always add a jj describe appending to the existing jj describe if one exists (jj st)

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

`agent/operator-core.md` is the source for the rendered operator prompts. When you change
`agent/operator-core.md` or `agent/scripts/render-operator-prompts.sh`, rerender the tracked
artifacts before handing off:

```bash
cd agent
./scripts/render-operator-prompts.sh repo
```

Validate prompt wording and renderer drift with:

```bash
uv run --directory orchestrator/backend pytest tests/test_prompt_wording.py
```

# Orchestrator backend

The backend is Python 3.11+ and `uv`-first. Use `uv`, not ad hoc `pip` installs:

```bash
uv sync --directory orchestrator/backend --extra dev
uv run --directory orchestrator/backend uvicorn app.main:app --reload
```

Run the backend tests with `uv`:

```bash
uv run --directory orchestrator/backend pytest
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
docker build -t security-research:latest -f agent/docker/runtime-full/Dockerfile .
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
- "Use `assess.py record-surface` for all surface writes — calling the library directly bypasses backend sync"
- "Finding IDs are allocated by `assess.py record-finding` under a lock — hand-allocating risks collisions"
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
