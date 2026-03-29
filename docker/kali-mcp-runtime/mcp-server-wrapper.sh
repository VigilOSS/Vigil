#!/usr/bin/env sh
set -e

UPSTREAM_CLIENT_PATH="${KALI_MCP_CLIENT_PATH:-/usr/share/mcp-kali-server/client.py}"

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

exec python3 "$UPSTREAM_CLIENT_PATH" "$@"
