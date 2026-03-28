#!/usr/bin/env bash
set -euo pipefail

CALLBACK_HOST="${CALLBACK_HOST:-0.0.0.0}"
CALLBACK_PORT="${CALLBACK_PORT:-8000}"
USE_NGROK="${USE_NGROK:-0}"

python3 /opt/mcp-tools/callback_listener.py --host "$CALLBACK_HOST" --port "$CALLBACK_PORT" &
CALLBACK_PID=$!

cleanup() {
  kill "$CALLBACK_PID" 2>/dev/null || true
}
trap cleanup EXIT

if [[ "$USE_NGROK" == "1" ]]; then
  if [[ -n "${NGROK_AUTHTOKEN:-}" ]]; then
    ngrok config add-authtoken "$NGROK_AUTHTOKEN" >/dev/null
  fi
  exec ngrok http "http://127.0.0.1:${CALLBACK_PORT}"
fi

wait "$CALLBACK_PID"
