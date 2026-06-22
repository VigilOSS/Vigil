"""``vigil auth`` — manage engagement credentials in the centralized store.

Credentials live in the orchestrator backend (one record per
``(engagement, identity)``), not in a per-engagement ``auth.json`` file. These
helpers are the operator-facing read/write path; the runtime (kali ``-H``
injection, ``auth-status``) reads the same store through the backend.
"""
from __future__ import annotations

import http.client
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .paths import resolve_orchestrator_base_url

DEFAULT_IDENTITY = "default"


def _install_root(engagement_dir: Path) -> Path:
    # engagement_dir = <install_root>/agent/engagements/<key>
    return engagement_dir.expanduser().resolve().parents[2]


def _key(engagement_dir: Path) -> str:
    return engagement_dir.expanduser().resolve().name


def _api(
    engagement_dir: Path,
    method: str,
    path: str = "",
    payload: dict | None = None,
) -> Any:
    base = resolve_orchestrator_base_url(_install_root(engagement_dir), engagement_dir)
    parsed = urlparse(base)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    prefix = (parsed.path or "").rstrip("/")
    conn_cls = (
        http.client.HTTPSConnection
        if parsed.scheme == "https"
        else http.client.HTTPConnection
    )
    full = f"{prefix}/engagements/{_key(engagement_dir)}/credentials{path}"
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    conn = conn_cls(host, port, timeout=10)
    try:
        conn.request(method, full, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        status_code = resp.status
    except OSError as exc:
        raise SystemExit(
            f"Cannot reach orchestrator at {base}: {exc}. Is `vigil up` running?"
        ) from exc
    finally:
        conn.close()
    if status_code == 404 and method == "GET":
        return {}
    if status_code >= 400:
        raise SystemExit(f"HTTP {status_code} from {method} {full}: {data}")
    if not data:
        return {}
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return {}


def read_auth(engagement_dir: Path) -> dict[str, object]:
    """Full identity map: ``{"identities": {...}, "active_identity": ...}``."""
    result = _api(engagement_dir, "GET")
    return result if isinstance(result, dict) else {"identities": {}, "active_identity": DEFAULT_IDENTITY}


def _active_material(engagement_dir: Path) -> dict[str, Any]:
    resolved = _api(engagement_dir, "GET", "/resolve")
    material = resolved.get("material") if isinstance(resolved, dict) else None
    return material if isinstance(material, dict) else {}


def status_line(engagement_dir: Path) -> str:
    material = _active_material(engagement_dir)
    cookies_val = material.get("cookies")
    cookies = cookies_val if isinstance(cookies_val, dict) else {}
    headers_val = material.get("headers")
    headers = headers_val if isinstance(headers_val, dict) else {}
    expires_at = material.get("expires_at")
    stale = _is_stale(str(expires_at)) if expires_at else False
    return (
        f"{_key(engagement_dir)}\tmode={material.get('mode', 'none')}"
        f"\tstate={material.get('state', 'none')}"
        f"\tidentity={material.get('identity_name', '-')}"
        f"\tcookies={len(cookies)}\theaders={len(headers)}"
        f"\texpires_at={expires_at or '-'}\tstale={str(stale).lower()}"
    )


def clear_auth(engagement_dir: Path, identity: str | None = None) -> None:
    path = "" if identity is None else f"/{identity}"
    _api(engagement_dir, "DELETE", path)


def import_auth(
    engagement_dir: Path, source: str | None, identity: str = DEFAULT_IDENTITY
) -> None:
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
    incoming.setdefault("mode", "manual")
    incoming.setdefault("use_for_requests", True)
    incoming["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    incoming["make_active"] = True
    _api(engagement_dir, "PUT", f"/{identity}", incoming)


def set_auth(
    engagement_dir: Path,
    identity: str,
    *,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    make_active: bool = True,
) -> None:
    payload: dict[str, Any] = {
        "mode": "manual",
        "use_for_requests": True,
        "cookies": cookies or {},
        "headers": headers or {},
        "make_active": make_active,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    _api(engagement_dir, "PUT", f"/{identity}", payload)


def set_active(engagement_dir: Path, identity: str) -> None:
    _api(engagement_dir, "POST", f"/{identity}/activate", {})


def edit_auth(engagement_dir: Path, identity: str | None = None) -> None:
    """Fetch an identity's material, open it in $EDITOR, and PUT it back."""
    target = identity or DEFAULT_IDENTITY
    material = (
        _active_material(engagement_dir)
        if identity is None
        else _api(engagement_dir, "GET", f"/{identity}")
    )
    if not material:
        material = _empty_auth()
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    ) as fh:
        json.dump(material, fh, indent=2, sort_keys=True)
        tmp_path = Path(fh.name)
    try:
        if subprocess.call([editor, str(tmp_path)]) != 0:
            raise SystemExit("editor exited non-zero; credentials unchanged")
        edited = json.loads(tmp_path.read_text(encoding="utf-8"))
        if not isinstance(edited, dict):
            raise SystemExit("edited credential must be a JSON object")
        edited["make_active"] = True
        edited["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _api(engagement_dir, "PUT", f"/{target}", edited)
    finally:
        tmp_path.unlink(missing_ok=True)


def export_curl_args(engagement_dir: Path, identity: str | None = None) -> str:
    """Render the identity's material as curl ``-H`` arguments (operator copy-paste)."""
    material = (
        _active_material(engagement_dir)
        if identity is None
        else _api(engagement_dir, "GET", f"/{identity}")
    )
    parts: list[str] = []
    cookies = material.get("cookies") if isinstance(material.get("cookies"), dict) else {}
    if cookies:
        cookie_value = "; ".join(f"{k}={v}" for k, v in cookies.items())
        parts.append(f"-H 'Cookie: {cookie_value}'")
    for key, value in (material.get("headers") or {}).items():
        parts.append(f"-H '{key}: {value}'")
    return " ".join(parts)


def _empty_auth() -> dict[str, object]:
    return {
        "mode": "manual",
        "use_for_requests": True,
        "auth_context": "authenticated",
        "expires_at": None,
        "cookies": {},
        "headers": {},
        "notes": "Populate cookies and/or headers, or capture them through mitmproxy.",
    }


def _is_stale(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed <= datetime.now(timezone.utc)
