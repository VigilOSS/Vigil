# jujutsu VCS
git commands will corrupt data, see ~/.codex/skills/jujutsu/SKILL.md

# Repo conventions

- `README.md` is the human/operator-facing setup and engagement guide.
- `AGENTS.md` is for repo-local development workflow and verification expectations.
- Backend work lives under `orchestrator/backend`.
- Frontend work lives under `orchestrator/frontend`.
- The primary runtime image is `agent/docker/runtime-full/Dockerfile`.

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
