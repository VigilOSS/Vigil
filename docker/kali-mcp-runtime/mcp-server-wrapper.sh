#!/usr/bin/env sh
set -e

PATCHED_CLIENT_PATH="${KALI_MCP_PATCHED_CLIENT_PATH:-/opt/mcp-tools/patched_kali_client.py}"

cd /usr/share/mcp-kali-server/
if ! curl -s http://localhost:5000/health >/dev/null 2>&1; then
  python3 /opt/mcp-tools/patched_kali_server.py >&2 2>&1 &

  for i in $(seq 1 10); do
    curl -s http://localhost:5000/health >/dev/null 2>&1 && break
    sleep 1
  done
fi

if [ "${1:-}" != "" ] && [ "${1#-}" = "$1" ]; then
  shift
fi

# The patched client re-exports the upstream MCP stdio bridge after
# monkey-patching `requests.Session.request` so every call to the local Kali
# API server carries audit headers sourced from per-call context or the
# KALI_MCP_DEFAULT_* environment variables. Audit recording lands in the
# orchestrator backend via the patched Kali server regardless.
exec python3 "$PATCHED_CLIENT_PATH" "$@"
