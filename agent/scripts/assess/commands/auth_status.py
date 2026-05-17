"""aith assess auth-status — one-shot view of the engagement's auth state.

Reads ``auth.json`` in the engagement directory and surfaces:
- ``auth_context`` (anonymous / authenticated / admin / specific role)
- ``mode`` (proxy_capture / manual / auth_json / none)
- ``use_for_requests`` flag
- ``state`` (available / missing / expired)
- ``expires_at`` (with a flag when it has passed or is within 5 minutes)
- Token shapes present (Bearer header, session cookies, OAuth refresh_token)
- Timestamp of the most recent live-credential probe via
  ``list-command-runs --technique AUTH``
- Recommended refresh path per the C42 Auth-expiry recovery loop

Pairs with the recovery loop in ``agent/operator-core.md`` Credential
Auto-Use section. The CLI is read-only; it does not write to auth.json
or trigger a refresh.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "auth-status",
        help="One-shot view of the engagement's auth state + refresh recommendation",
    )
    p.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Emit the auth status as a JSON object",
    )
    p.add_argument(
        "--expires-warning-seconds",
        dest="expires_warning_seconds",
        type=int,
        default=300,
        help="Seconds before expires_at to flag as 'expiring soon' (default: 300)",
    )
    p.set_defaults(func=run)


def _read_auth_json(engagement_dir: Path) -> dict:
    path = engagement_dir / "auth.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def _parse_iso8601(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    # Be permissive: accept both `Z` and `+00:00` forms; tolerate microseconds.
    raw = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _token_shapes(auth: dict) -> list[str]:
    """Identify which token shapes auth.json carries today."""
    shapes: list[str] = []
    headers = auth.get("headers") or {}
    if isinstance(headers, dict):
        for key, value in headers.items():
            if not isinstance(value, str):
                continue
            lower_key = key.lower()
            if lower_key == "authorization" and value.lower().startswith("bearer "):
                shapes.append(f"Authorization: Bearer (length={len(value)})")
            elif lower_key == "authorization":
                shapes.append(f"Authorization: <other> (length={len(value)})")
            elif lower_key in {"x-csrf-token", "x-userrtoken", "x-userToken".lower(), "x-requestdigest"}:
                shapes.append(f"{key}: {value[:20]}{'...' if len(value) > 20 else ''}")
    cookies = auth.get("cookies") or {}
    if isinstance(cookies, dict) and cookies:
        names = ",".join(sorted(cookies.keys())[:4])
        more = "" if len(cookies) <= 4 else f" + {len(cookies) - 4} more"
        shapes.append(f"flat_cookies: {names}{more}")
    host_cookies = auth.get("host_cookies") or []
    if isinstance(host_cookies, list) and host_cookies:
        shapes.append(f"host_cookies: {len(host_cookies)} host bucket(s)")
    tokens = auth.get("tokens") or {}
    if isinstance(tokens, dict):
        for key, value in tokens.items():
            if isinstance(value, str):
                shapes.append(f"tokens.{key}: <string len={len(value)}>")
            else:
                shapes.append(f"tokens.{key}: {type(value).__name__}")
    return shapes


def _refresh_recommendation(auth: dict, token_shapes: list[str]) -> str:
    """Heuristic refresh-path recommendation matching the C42 recovery loop."""
    has_bearer = any(s.startswith("Authorization: Bearer") for s in token_shapes)
    has_session = any(s.startswith("flat_cookies") or s.startswith("host_cookies") for s in token_shapes)
    has_refresh = any("refresh_token" in s for s in token_shapes)
    if has_refresh:
        return (
            "OAuth refresh_token present — re-run the OAuth authorization-code grant "
            "with the refresh token before invalidating the session."
        )
    if has_bearer:
        return (
            "Bearer token present — refresh via the documented token-refresh endpoint "
            "(or re-run the login flow). One-shot operator action; do NOT dispatch a "
            "specialist for the refresh itself."
        )
    if has_session:
        return (
            "Session cookie present — re-capture via mitmproxy-assisted login. "
            "Restart the browser flow through the proxy; proxy_addon.py writes the "
            "refreshed cookie set into auth.json automatically."
        )
    return (
        "No token material detected. Operator must run the login flow to populate "
        "auth.json (manual or proxy-assisted capture)."
    )


def _last_auth_probe(client: AssessmentClient | None) -> dict | None:
    """Best-effort fetch of the most recent command-runs row with
    --technique AUTH so the operator sees when the auth was last validated.
    Returns None on any failure (network, missing endpoint, parse error).
    """
    if client is None:
        return None
    try:
        rows = client.get_engagement("command-runs?technique=AUTH&limit=1")
    except Exception:  # noqa: BLE001 — best-effort read
        return None
    items: list[dict] = []
    if isinstance(rows, dict):
        items = rows.get("items") or rows.get("rows") or []
    elif isinstance(rows, list):
        items = rows
    if not items:
        return None
    row = items[0]
    return {
        "run_id": row.get("id"),
        "status": row.get("status"),
        "intent": row.get("intent"),
        "completed_at": row.get("completed_at"),
        "started_at": row.get("started_at"),
    }


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    engagement_dir = Path(cfg.engagement_dir)
    auth = _read_auth_json(engagement_dir)
    shapes = _token_shapes(auth) if auth else []

    expires_at_raw = auth.get("expires_at") if isinstance(auth, dict) else None
    expires_dt = _parse_iso8601(expires_at_raw)
    now = datetime.now(timezone.utc)
    expires_state = "unset"
    expires_in_seconds: int | None = None
    if expires_dt is not None:
        delta = (expires_dt - now).total_seconds()
        expires_in_seconds = int(delta)
        warn_window = int(getattr(args, "expires_warning_seconds", 300) or 300)
        if delta <= 0:
            expires_state = "expired"
        elif delta <= warn_window:
            expires_state = "expiring_soon"
        else:
            expires_state = "valid"

    client: AssessmentClient | None = None
    try:
        client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    except Exception:  # noqa: BLE001
        client = None
    try:
        last_probe = _last_auth_probe(client)
    finally:
        if client is not None:
            client.close()

    state = {
        "engagement_key": cfg.engagement_key,
        "auth_context": auth.get("auth_context") or "anonymous",
        "mode": auth.get("mode") or "none",
        "use_for_requests": bool(auth.get("use_for_requests")),
        "state": auth.get("state") or ("missing" if not auth else "available"),
        "expires_at": expires_at_raw,
        "expires_state": expires_state,
        "expires_in_seconds": expires_in_seconds,
        "tokens": shapes,
        "last_auth_probe": last_probe,
        "recommend": _refresh_recommendation(auth, shapes),
    }

    if getattr(args, "json_output", False):
        print(json.dumps(state, ensure_ascii=False, indent=2))
        return

    print(f"engagement_key: {state['engagement_key']}")
    print(f"auth_context:   {state['auth_context']}")
    print(f"mode:           {state['mode']}")
    print(f"use_for_requests: {state['use_for_requests']}")
    print(f"state:          {state['state']}")
    if expires_at_raw:
        suffix = ""
        if expires_state == "expired":
            suffix = "  (EXPIRED)"
        elif expires_state == "expiring_soon":
            minutes = max(1, (expires_in_seconds or 0) // 60)
            suffix = f"  (expires in ~{minutes}m)"
        print(f"expires_at:     {expires_at_raw}{suffix}")
    if shapes:
        print("tokens:")
        for s in shapes:
            print(f"  - {s}")
    else:
        print("tokens:         (none detected)")
    if last_probe:
        print(
            f"last_auth_probe: run_id={last_probe.get('run_id')} "
            f"status={last_probe.get('status')} "
            f"completed_at={last_probe.get('completed_at') or '-'}"
        )
    else:
        print("last_auth_probe: (no AUTH-technique command-run rows found)")
    print(f"recommend:      {state['recommend']}")
