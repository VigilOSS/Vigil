#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR/orchestrator/frontend"
npm install
npm run build

cd "$ROOT_DIR"
uv run --directory orchestrator/backend uvicorn app.main:app --host 127.0.0.1 --port 18000
