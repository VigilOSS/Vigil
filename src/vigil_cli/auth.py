from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def auth_path(engagement_dir: Path) -> Path:
    return engagement_dir.expanduser().resolve() / "auth.json"


def read_auth(engagement_dir: Path) -> dict[str, object]:
    path = auth_path(engagement_dir)
    if not path.exists():
        return _empty_auth()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid auth.json at {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"Invalid auth.json at {path}: expected a JSON object")
    return payload


def write_auth(engagement_dir: Path, payload: dict[str, object]) -> None:
    auth_path(engagement_dir).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def status_line(engagement_dir: Path) -> str:
    payload = read_auth(engagement_dir)
    cookies_value = payload.get("cookies")
    cookies = cookies_value if isinstance(cookies_value, dict) else {}
    headers_value = payload.get("headers")
    headers = headers_value if isinstance(headers_value, dict) else {}
    expires_at = payload.get("expires_at")
    stale = _is_stale(str(expires_at)) if expires_at else False
    return (
        f"{engagement_dir.name}\tmode={payload.get('mode', 'unknown')}\tstate={payload.get('state', 'unknown')}"
        f"\tcookies={len(cookies)}\theaders={len(headers)}\texpires_at={expires_at or '-'}\tstale={str(stale).lower()}"
    )


def clear_auth(engagement_dir: Path) -> None:
    payload = read_auth(engagement_dir)
    mode = str(payload.get("mode") or "manual")
    payload.update(
        {
            "state": "none" if mode == "none" else "missing",
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cookies": {},
            "headers": {},
            "expires_at": None,
        }
    )
    write_auth(engagement_dir, payload)


def import_auth(engagement_dir: Path, source: str | None) -> None:
    if source is None or source == "-":
        raw = os.read(0, 1_000_000).decode()
    else:
        raw = Path(source).expanduser().read_text(encoding="utf-8")
    try:
        incoming = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON: {exc}") from exc
    if not isinstance(incoming, dict):
        raise SystemExit("Auth import expects a JSON object")
    payload = read_auth(engagement_dir)
    payload.update(incoming)
    payload.setdefault("mode", "manual")
    payload["state"] = "present"
    payload["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload.setdefault("cookies", {})
    payload.setdefault("headers", {})
    write_auth(engagement_dir, payload)


def edit_auth(engagement_dir: Path) -> None:
    path = auth_path(engagement_dir)
    if not path.exists():
        write_auth(engagement_dir, _empty_auth())
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    raise SystemExit(subprocess.call([editor, str(path)]))


def _empty_auth() -> dict[str, object]:
    return {
        "mode": "manual",
        "state": "missing",
        "use_for_requests": True,
        "auth_context": "authenticated",
        "expires_at": None,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cookies": {},
        "headers": {},
        "notes": "Populate cookies and/or headers here, or refresh them through mitmproxy.",
    }


def _is_stale(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return True
    return parsed <= datetime.now(timezone.utc)
