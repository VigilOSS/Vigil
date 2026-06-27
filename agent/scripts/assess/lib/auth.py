"""Auth runtime snapshot — sourced from the centralized credential store.

Replaces the old per-engagement ``auth.json`` reader. The active identity's
material is fetched from the orchestrator backend via :mod:`creds_client`
(fail-closed to anonymous when the backend is unreachable). The derived
snapshot shape is unchanged so downstream consumers (kali ``-H`` injection,
``auth-status``) are storage-agnostic.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import creds_client


def _parse_iso8601(value: Any) -> datetime | None:
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


def auth_runtime_snapshot(engagement_dir: str) -> dict[str, Any]:
    """Return the full auth runtime snapshot for the engagement's active identity.

    The material comes from the centralized credential store; an engagement with
    no credentials (or an unreachable backend) yields the anonymous snapshot.
    """
    raw = creds_client.active_material(engagement_dir)
    material_present = bool(raw)

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
    parsed_expiry = _parse_iso8601(expires_at)
    if parsed_expiry is not None and parsed_expiry <= datetime.now(timezone.utc):
        expired = True

    warning = ""
    if mode == "none":
        state = "none"
        use_for_requests = False
        auth_context = "anonymous"
    elif expired:
        state = "expired"
        warning = (
            "Auth material is expired; continuing without auth until "
            "credentials are refreshed (vigil auth import / mitmproxy capture)."
        )
    elif cookies or headers:
        state = "available"
    else:
        state = "missing"
        if use_for_requests:
            warning = (
                "Auth mode is enabled but the stored credential has no cookies "
                "or headers; continuing without auth."
            )

    active_use = bool(use_for_requests and state == "available")
    if not active_use:
        auth_context = "anonymous"

    return {
        "path": f"backend:engagements/{Path(engagement_dir).name}/credentials",
        "exists": material_present,
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


def auth_active_context(engagement_dir: str) -> str:
    """Return the active auth context string (e.g., 'anonymous' or 'authenticated')."""
    snapshot = auth_runtime_snapshot(engagement_dir)
    return snapshot.get("auth_context", "anonymous")
