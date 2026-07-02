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

# HTTP verbs that mutate server state and therefore need a CSRF double-submit
# header. Duplicated (not imported) from ``assess.lib.kali._STATE_CHANGING_METHODS``
# on purpose: this operator CLI lives in a different package than the assess
# runtime and must not depend on it. Keep the two in sync.
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _csrf_export_arg(
    material: dict[str, Any], cookies: dict[str, str], method: str | None
) -> str:
    """Render the opt-in CSRF double-submit ``-H`` arg for the copy-paste path.

    Mirrors ``assess.lib.kali._csrf_double_submit_pair`` so the printed curl matches
    what ``vigil assess kali --identity`` injects at exec time: the header is emitted
    ONLY on a state-changing ``method``, ONLY when the identity declares the
    app-specific ``csrf`` mapping AND the named cookie is present in the rendered
    cookie view, and NEVER when the identity already carries that header (so an
    operator-set header is not duplicated). Returns ``""`` in every other case.
    """
    if not method or str(method).strip().upper() not in _STATE_CHANGING_METHODS:
        return ""
    csrf = material.get("csrf")
    if not isinstance(csrf, dict):
        return ""
    cookie_name = str(csrf.get("cookie") or "").strip()
    header_name = str(csrf.get("header") or "").strip()
    if not cookie_name or not header_name:
        return ""
    value = cookies.get(cookie_name)
    if not isinstance(value, str) or not value.strip():
        return ""
    existing = {str(k).lower() for k in (material.get("headers") or {})}
    if header_name.lower() in existing:
        return ""
    return f"-H '{header_name}: {value}'"


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
    # Honesty fix: `stale` is a claim about liveness. We can only compute it from
    # an expiry timestamp. With no expires_at (the cookie-capture case — F5 APM /
    # SiteMinder sessions carry none) the old code hardcoded `stale=false`, i.e.
    # asserted the session was fresh when we had no basis to. A dead session then
    # reads as live (a false negative). Emit `stale=unknown` instead; a live probe
    # (`vigil assess auth-status --probe`) is the only way to confirm liveness.
    if expires_at:
        stale_repr = "true" if _is_stale(str(expires_at)) else "false"
    else:
        stale_repr = "unknown"
    return (
        f"{_key(engagement_dir)}\tmode={material.get('mode', 'none')}"
        f"\tstate={material.get('state', 'none')}"
        f"\tidentity={material.get('identity_name', '-')}"
        f"\tcookies={len(cookies)}\theaders={len(headers)}"
        f"\texpires_at={expires_at or '-'}\tstale={stale_repr}"
    )


def clear_auth(
    engagement_dir: Path, identity: str | None = None, *, all_identities: bool = False
) -> None:
    if all_identities:
        # Explicit, opt-in wipe of EVERY identity (the collection DELETE).
        _api(engagement_dir, "DELETE", "")
        return
    if identity is None:
        # Default = the ACTIVE identity (the documented contract), NOT the whole
        # collection. Clearing an expired session must never erase the other named
        # identities (user_a/user_b/admin). Resolve the active name like edit_auth.
        resolved = _api(engagement_dir, "GET", "/resolve")
        resolved = resolved if isinstance(resolved, dict) else {}
        identity = str(resolved.get("identity_name") or DEFAULT_IDENTITY)
    _api(engagement_dir, "DELETE", f"/{identity}")


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
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Legacy multi-identity shape ({"identities": {name: material}, "active_identity"}):
    # PUT each contained identity into its OWN slot. Otherwise the whole wrapper
    # lands in one identity and the backend — which extracts only top-level
    # cookies/headers/tokens — restores nothing usable, defeating the documented
    # `vigil auth import auth.json` recovery for upgraded multi-identity engagements.
    identities = incoming.get("identities")
    if isinstance(identities, dict) and identities:
        active = str(incoming.get("active_identity") or DEFAULT_IDENTITY)
        for name, material in identities.items():
            if not isinstance(material, dict):
                continue
            payload = dict(material)
            payload.setdefault("mode", "manual")
            payload.setdefault("use_for_requests", True)
            payload["updated_at"] = now
            payload["make_active"] = str(name) == active
            _api(engagement_dir, "PUT", f"/{name}", payload)
        return
    incoming.setdefault("mode", "manual")
    incoming.setdefault("use_for_requests", True)
    incoming["updated_at"] = now
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
    if identity is None:
        # No --identity: edit whatever is active and write BACK to that same identity.
        # Resolve the active name from /resolve (a sibling of `material`, not inside it)
        # rather than assuming `default` — otherwise editing a non-default active identity
        # forks the edit into `default` and make_active flips the engagement onto it,
        # silently corrupting `default` and leaving the intended identity unchanged.
        resolved = _api(engagement_dir, "GET", "/resolve")
        resolved = resolved if isinstance(resolved, dict) else {}
        target = str(resolved.get("identity_name") or DEFAULT_IDENTITY)
        material = resolved.get("material")
        material = material if isinstance(material, dict) else {}
    else:
        target = identity
        material = _api(engagement_dir, "GET", f"/{identity}")
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


def export_curl_args(
    engagement_dir: Path,
    identity: str | None = None,
    *,
    host: str | None = None,
    method: str | None = None,
) -> str:
    """Render the identity's material as curl ``-H`` arguments (operator copy-paste).

    ``host`` overlays the matching ``host_cookies`` bucket(s) on top of the
    legacy flat ``cookies`` view — the same host-scoped lookup
    ``vigil assess kali --identity`` already applies at injection time (I-22).
    Without it, a multi-host engagement (several unrelated domains under one
    scope.json) only ever exports whatever happened to land in the flat
    ``cookies`` field, which silently drops every host except the one that
    capture-time scoping flattened against — pass the target host explicitly
    to get the right session.

    ``method`` gates the opt-in CSRF double-submit header the same way exec-time
    injection does: pass ``POST``/``PUT``/``PATCH``/``DELETE`` and the printed curl
    gains the app-specific ``-H '<csrf-header>: <cookie-value>'`` so a copy-pasted
    write is not CSRF-rejected. Safe methods (or an unset method) print no CSRF
    header — matching what a GET run injects.
    """
    material = (
        _active_material(engagement_dir)
        if identity is None
        else _api(engagement_dir, "GET", f"/{identity}")
    )
    raw_cookies = material.get("cookies")
    cookies = dict(raw_cookies) if isinstance(raw_cookies, dict) else {}
    if host:
        from .paths import add_assess_import_path

        add_assess_import_path(_install_root(engagement_dir))
        from assess.lib.identity import host_cookies_for  # type: ignore[import-not-found]

        cookies.update(host_cookies_for(material, host))
    parts: list[str] = []
    if cookies:
        cookie_value = "; ".join(f"{k}={v}" for k, v in cookies.items())
        parts.append(f"-H 'Cookie: {cookie_value}'")
        csrf_arg = _csrf_export_arg(material, cookies, method)
        if csrf_arg:
            parts.append(csrf_arg)
    for key, value in (material.get("headers") or {}).items():
        parts.append(f"-H '{key}: {value}'")
    return " ".join(parts)


# Location substrings that mark a redirect as a bounce back to authentication —
# an authed request that lands here means the SESSION IS DEAD (F5 APM `/my.policy`,
# a login/SSO/SAML redirect, an OAuth/OIDC authorize hop). App-specific enough to
# vary, but these cover the common gate shapes; ambiguous 3xx to a non-login page
# is left UNKNOWN rather than falsely called dead.
_LOGIN_LOCATION_MARKERS = (
    "/my.policy",
    "/login",
    "/signin",
    "/sign-in",
    "/saml",
    "samlrequest",
    "/idp",
    "/authorize",
    "/oauth2/authorize",
    "/adfs/",
    "/auth/realms",
    "returnurl=",
    "redirect_uri=",
)


def _classify_liveness(status: int, location: str) -> str:
    """Classify an authed-probe response as ``live`` / ``dead`` / ``unknown``.

    LOCKED rule: a 3xx redirect to a login/`/my.policy`-style location, or an
    explicit 401, means the session is DEAD (the authed request was bounced to
    re-auth). A 2xx is LIVE. Everything else — a transport error, an ambiguous 3xx
    to a non-login page, a 403 that may be WAF/authz rather than session death — is
    UNKNOWN. Never assert a liveness we cannot prove.
    """
    loc = (location or "").lower()
    if 200 <= status < 300:
        return "live"
    if status == 401:
        return "dead"
    if 300 <= status < 400:
        if any(marker in loc for marker in _LOGIN_LOCATION_MARKERS):
            return "dead"
        return "unknown"
    return "unknown"


def _bearer_token(material: dict[str, Any]) -> str:
    """Return a bearer token from legacy top-level fields or ``tokens`` material.

    Mirrors ``assess.lib.kali._identity_bearer_token`` so the CLI probe carries the
    same Authorization the runtime injects.
    """
    for value in (material.get("token"), material.get("bearer")):
        if isinstance(value, str) and value.strip():
            return value.strip()
    tokens = material.get("tokens")
    if isinstance(tokens, dict):
        for key in ("access_token", "accessToken", "bearer", "token", "id_token", "idToken"):
            value = tokens.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _authed_request_headers(
    engagement_dir: Path, material: dict[str, Any], host: str
) -> dict[str, str]:
    """Build the request headers for a host-side authed probe from identity material.

    Cookies are host-scoped the same way ``vigil assess kali --identity`` injects
    them (the matching ``host_cookies`` bucket, falling back to the flat view), plus
    the identity's headers and a bearer token when present.
    """
    headers: dict[str, str] = {}
    for key, value in (material.get("headers") or {}).items():
        if str(key).strip():
            headers[str(key)] = str(value)
    cookies: dict[str, str] = {}
    host_scoped: dict[str, str] = {}
    try:
        from .paths import add_assess_import_path

        add_assess_import_path(_install_root(engagement_dir))
        from assess.lib.identity import host_cookies_for  # type: ignore[import-not-found]

        host_scoped = host_cookies_for(material, host)
    except Exception:  # noqa: BLE001 — assess import optional; fall back to flat view
        host_scoped = {}
    if host_scoped:
        cookies.update(host_scoped)
    else:
        raw = material.get("cookies")
        if isinstance(raw, dict):
            cookies.update({str(k): str(v) for k, v in raw.items()})
    if cookies and not any(k.lower() == "cookie" for k in headers):
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    token = _bearer_token(material)
    if token and not any(k.lower() == "authorization" for k in headers):
        headers["Authorization"] = f"Bearer {token}"
    return headers


def probe_liveness(
    engagement_dir: Path,
    url: str,
    identity: str | None = None,
    *,
    timeout: int = 15,
) -> dict[str, Any]:
    """Send a lightweight authed GET with the active identity's material and
    classify session liveness.

    Redirects are NOT followed — a 302 to a login page IS the dead-session signal.
    Returns ``{"liveness", "http_status", "location", "error"}``; a transport error
    yields ``liveness="unknown"`` with a populated ``error`` (never a false verdict).
    """
    material = (
        _active_material(engagement_dir)
        if identity is None
        else _api(engagement_dir, "GET", f"/{identity}")
    )
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {
            "liveness": "unknown",
            "http_status": None,
            "location": None,
            "error": f"invalid probe URL {url!r} (expected an absolute http(s) URL)",
        }
    headers = _authed_request_headers(engagement_dir, material, parsed.hostname)
    conn_cls = (
        http.client.HTTPSConnection
        if parsed.scheme == "https"
        else http.client.HTTPConnection
    )
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    conn = conn_cls(parsed.hostname, port, timeout=timeout)
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        location = resp.getheader("Location") or ""
        resp.read()
    except OSError as exc:
        return {
            "liveness": "unknown",
            "http_status": None,
            "location": None,
            "error": f"probe request failed: {exc}",
        }
    finally:
        conn.close()
    return {
        "liveness": _classify_liveness(status, location),
        "http_status": status,
        "location": location or None,
        "error": None,
    }


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
