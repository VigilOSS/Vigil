#!/usr/bin/env bash

auth_file_path() {
    local eng_dir="${1:?engagement dir required}"
    printf '%s\n' "$eng_dir/auth.json"
}

_auth_runtime_snapshot_python() {
    python3 - <<'PY' "$1"
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def parse_iso8601(value):
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


auth_path = Path(sys.argv[1])
raw = {}
file_exists = auth_path.exists()
file_error = ""
if file_exists:
    try:
        raw = json.loads(auth_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raw = {}
        file_error = str(exc)

mode = str(raw.get("mode") or "none").strip() or "none"
if mode not in {"none", "manual", "auth_json", "proxy_capture"}:
    mode = "manual"

cookies = raw.get("cookies") if isinstance(raw.get("cookies"), dict) else {}
headers = raw.get("headers") if isinstance(raw.get("headers"), dict) else {}
notes = str(raw.get("notes") or "")
auth_context = str(raw.get("auth_context") or "").strip()
if not auth_context:
    auth_context = "authenticated" if (cookies or headers) else "anonymous"

use_for_requests = raw.get("use_for_requests")
if not isinstance(use_for_requests, bool):
    use_for_requests = mode != "none"

expires_at = raw.get("expires_at")
explicit_state = str(raw.get("state") or "").strip().lower()
expired = explicit_state == "expired"
parsed_expiry = parse_iso8601(expires_at)
if parsed_expiry is not None and parsed_expiry <= datetime.now(timezone.utc):
    expired = True

warning = ""
state = "none"
if file_error:
    state = "invalid"
    warning = "auth.json is not valid JSON; continuing without auth."
    use_for_requests = False
    auth_context = "anonymous"
elif mode == "none":
    state = "none"
    use_for_requests = False
    auth_context = "anonymous"
elif expired:
    state = "expired"
    warning = "Auth material is expired; continuing without auth until auth.json is refreshed."
elif cookies or headers:
    state = "available"
else:
    state = "missing"
    if use_for_requests:
        warning = "Auth mode is enabled but auth.json has no cookies or headers; continuing without auth."

active_use = bool(use_for_requests and state == "available")
if not active_use:
    auth_context = "anonymous"

snapshot = {
    "path": str(auth_path),
    "exists": file_exists,
    "mode": mode,
    "state": state,
    "use_for_requests": use_for_requests,
    "active_use": active_use,
    "auth_context": auth_context,
    "cookies": cookies,
    "headers": headers,
    "expires_at": expires_at,
    "notes": notes,
    "warning": warning,
}
print(json.dumps(snapshot, ensure_ascii=True))
PY
}

auth_runtime_snapshot_json() {
    local eng_dir="${1:?engagement dir required}"
    _auth_runtime_snapshot_python "$(auth_file_path "$eng_dir")"
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
    local auth_file snapshot_json
    auth_file="$(auth_file_path "$eng_dir")"
    snapshot_json="$(_auth_runtime_snapshot_python "$auth_file")"
    python3 - <<'PY' "$snapshot_json"
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

write_auth_scaffold() {
    local eng_dir="${1:?engagement dir required}"
    local mode="${2:?auth mode required}"
    local timestamp="${3:-}"
    local auth_file
    auth_file="$(auth_file_path "$eng_dir")"
    python3 - <<'PY' "$auth_file" "$mode" "$timestamp"
import json
import sys
from pathlib import Path

auth_file, mode, timestamp = sys.argv[1:]
if mode == "none":
    payload = {
        "mode": "none",
        "state": "none",
        "use_for_requests": False,
        "auth_context": "anonymous",
        "expires_at": None,
        "updated_at": timestamp or None,
        "cookies": {},
        "headers": {},
        "notes": "No authenticated context configured for this engagement.",
    }
else:
    payload = {
        "mode": mode,
        "state": "missing",
        "use_for_requests": True,
        "auth_context": "authenticated",
        "expires_at": None,
        "updated_at": timestamp or None,
        "cookies": {},
        "headers": {},
        "notes": "Populate cookies and/or headers here, or refresh them through mitmproxy.",
    }

Path(auth_file).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}
