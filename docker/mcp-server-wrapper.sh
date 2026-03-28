#!/usr/bin/env sh
set -e

cd /usr/share/mcp-kali-server/
if ! curl -s http://localhost:5000/health >/dev/null 2>&1; then
  python3 /opt/mcp-tools/patched_kali_server.py >&2 2>&1 &

  for i in $(seq 1 10); do
    curl -s http://localhost:5000/health >/dev/null 2>&1 && break
    sleep 1
  done
fi

exec python3 /opt/mcp-tools/mcp_transform_proxy.py "$@"
