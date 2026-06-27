#!/usr/bin/env bash
#
# Shell helpers for auth runtime state. Credentials live in the centralized
# orchestrator credential store (no per-engagement auth.json file); these
# helpers delegate to the Python assess lib (assess.lib.auth), which fetches the
# active identity from the backend and fails closed to anonymous when the
# backend is unreachable. The Python path (assess.lib.auth) is authoritative;
# this file is the thin shell front for tool wrappers that build curl/httpx
# argv.

auth_runtime_snapshot_json() {
    local eng_dir="${1:?engagement dir required}"
    python3 - "$eng_dir" <<'PY'
import json
import sys

from assess.lib.auth import auth_runtime_snapshot

print(json.dumps(auth_runtime_snapshot(sys.argv[1]), ensure_ascii=True))
PY
}

auth_active_context() {
    local eng_dir="${1:?engagement dir required}"
    auth_runtime_snapshot_json "$eng_dir" | jq -r '.auth_context // "anonymous"'
}

auth_warn_if_needed() {
    local eng_dir="${1:?engagement dir required}"
    local warning
    warning="$(auth_runtime_snapshot_json "$eng_dir" | jq -r '.warning // empty')"
    if [[ -n "$warning" ]]; then
        printf '[auth] %s\n' "$warning" >&2
    fi
}

auth_header_args_stream() {
    local eng_dir="${1:?engagement dir required}"
    local snapshot_json
    snapshot_json="$(auth_runtime_snapshot_json "$eng_dir")"
    python3 - "$snapshot_json" <<'PY'
import json
import sys

snapshot = json.loads(sys.argv[1])
if not snapshot.get("active_use"):
    raise SystemExit(0)

headers = []
cookies = snapshot.get("cookies") or {}
if isinstance(cookies, dict) and cookies:
    cookie_value = "; ".join(f"{key}={value}" for key, value in cookies.items())
    headers.extend(["-H", f"Cookie: {cookie_value}"])

for key, value in (snapshot.get("headers") or {}).items():
    headers.extend(["-H", f"{key}: {value}"])

sys.stdout.buffer.write("\0".join(headers).encode("utf-8"))
if headers:
    sys.stdout.buffer.write(b"\0")
PY
}
