# jujutsu VCS
git commands will corrupt data, see ~/.codex/skills/jujutsu/SKILL.md always use jujustu before new changes.

# Repo conventions

- `README.md` is the human/operator-facing setup and engagement guide.
- `AGENTS.md` is for repo-local development workflow and verification expectations.
- Backend work lives under `orchestrator/backend`.
- Frontend work lives under `orchestrator/frontend`.
- The primary runtime image is `agent/docker/runtime-full/Dockerfile`.

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
- `agent/.codex/agents/operator.toml`
- `agent/.claude/agents/operator.md`

Validate prompt wording and renderer drift with:

```bash
uv run --directory orchestrator/backend pytest orchestrator/backend/tests/test_prompt_wording.py
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
