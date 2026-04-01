# jujutsu VCS

git commands will corrupt data, see ~/.codex/skills/jujutsu/SKILL.md always use jujustu before new changes.

# Repo conventions

- `README.md` is the human/operator-facing setup and engagement guide.
- `AGENTS.md` is for repo-local development workflow and verification expectations.
- Backend work lives under `orchestrator/backend`.
- Frontend work lives under `orchestrator/frontend`.

# Operator prompt regeneration

`agent/operator-core.md` is the source for the rendered operator prompts. When you change
`agent/operator-core.md` or `agent/scripts/render-operator-prompts.sh`, rerender the tracked
artifacts before handing off:

```bash
cd agent
./scripts/render-operator-prompts.sh repo
```

These generated files are committed in git and must stay in sync:

- `agent/AGENTS.md`
- `agent/CLAUDE.md`
- `agent/.codex/agents/*`
- `agent/.claude/agents/*`

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

# Making edits to the codebase? READ THIS

## Architecture Overview

### File Hierarchy (under `agent/`)

**Orchestration layer:**

- `operator-core.md` — THE brain. Phase flow, core loop, dispatch rules, credential auto-use, finding format. 
CLAUDE.md and AGENTS.md are generated wrappers of this filesh`
- `shared-constraints.md` — Rules every subagent loads FIRST
- `rules/hunting.md` — Always-active hunting rules
- `rules/reporting.md` — Always-active reporting rules

**Skill index**:

- `SKILL.md` — Routing table. Every agent loads this to find the right skill via "Use when:" line. Each entry has "Paired references:" pointing to the reference cheatsheets.

**References library (under `references/`):**

- `INDEX.md` — Library index. Points to all reference files organized by category.


### Dispatch & Skill Loading Chain

operator-core (phase logic)
→ dispatches agent (e.g., vulnerability-analyst)
    → agent loads shared-constraints.md FIRST
    → agent loads SKILL.md (routing table)
    → matches "Use when:" line to find correct skill
    → loads skill (e.g., skills/xss-testing/SKILL.md)
    → skill lists tools + methodology steps
    → skill's "Extended Resources" points to reference cheatsheets (e.g., references/payloads/xss-payloads.md)