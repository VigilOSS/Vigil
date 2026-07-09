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
import re
import shutil
import subprocess
import sys
import tempfile
import time
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
    """Import identity material (cookies/headers/tokens) from a file or stdin.

    The incoming JSON MAY also carry a ``material.liveness`` signature —
    ``{"expect_status": 200, "authed_marker": "...", "dead_marker": "sessionExpired"}``
    (every key optional) — which is persisted verbatim via the backend store's
    extra-keys passthrough. It changes NO import behavior here, but it is what lets
    ``vigil auth status --probe`` and ``vigil auth keepalive`` return a real
    ``live``/``dead`` verdict (matched case-sensitively against the probe response's
    status line + headers incl. ``Location`` + body) instead of ``unknown``.
    """
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

    ``host`` selects the matching ``host_cookies`` bucket(s) and uses it ALONE —
    the same host-scoped lookup ``vigil assess kali --identity`` applies at
    injection time (I-22). The flat ``cookies`` field is a UNION across every
    captured host, so seeding it and overlaying the bucket (the old behavior)
    would leave cookie names unique to OTHER hosts in the printed ``Cookie``
    header — cross-host session bleed. We fall back to the flat view ONLY for
    identities with no per-host buckets at all (legacy/manual identities); when
    buckets exist but none match ``host`` we omit cookies entirely rather than
    route the display-only union onto an unrelated target. Without ``host``, a
    multi-host engagement (several unrelated domains under one scope.json) only
    ever exports whatever happened to land in the flat ``cookies`` field, which
    silently drops every host except the one that capture-time scoping flattened
    against — pass the target host explicitly to get the right session.

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
    flat_cookies = dict(raw_cookies) if isinstance(raw_cookies, dict) else {}
    if host:
        from .paths import add_assess_import_path

        add_assess_import_path(_install_root(engagement_dir))
        from assess.lib.identity import (  # type: ignore[import-not-found]
            host_cookie_hosts,
            host_cookies_for,
        )

        host_scoped = host_cookies_for(material, host)
        if host_scoped:
            # Authoritative per-host bucket: use it ALONE (no flat-union blend),
            # so a cookie captured for a DIFFERENT host never rides this export.
            cookies = dict(host_scoped)
        elif not host_cookie_hosts(material):
            # No per-host buckets at all (legacy/manual identity): the flat union
            # is the only cookie view we have, so fall back to it.
            cookies = flat_cookies
        else:
            # Buckets exist but none match this host → omit cookies rather than
            # route the display-only union onto an unrelated target.
            cookies = {}
    else:
        # No target host requested: preserve the flat view (unchanged behavior).
        cookies = flat_cookies
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


def _classify_liveness(
    status: int | None,
    haystack: str | None,
    liveness: dict[str, Any] | None,
) -> tuple[str, str]:
    """Deterministic, operator-configured session-liveness classifier.

    There is exactly ONE way to decide liveness: an operator-declared signature in
    ``material['liveness'] = {expect_status, authed_marker, dead_marker}`` (each key
    optional), matched against ``haystack`` — the probe response's status line +
    headers (INCLUDING ``Location``) + body text. This mirrors how a DAST scanner
    (InsightAppSec / Burp) validates a session with logged-in / logged-out markers;
    NO auth/login location is auto-detected. Precedence (first match wins):

      1. no response captured (transport error)         -> unknown
      2. no liveness signature configured               -> unknown (names the shape to set)
      3. dead_marker set AND present in haystack         -> dead
      4. authed_marker set AND absent from haystack      -> dead
      5. expect_status set AND status != expect_status   -> dead
      6. otherwise                                       -> live

    Marker matching is case-sensitive substring against the combined haystack.
    Returns ``(verdict, reason)`` where ``reason`` names the rule that fired. Pure
    function: unit-tested without a network, and kept in lockstep with its mirror
    (``vigil_cli.auth`` <-> ``assess.commands.auth_status``) — the two must classify
    identical inputs identically.
    """
    if status is None:
        return "unknown", "no response captured (transport error)"

    cfg = liveness if isinstance(liveness, dict) else {}
    raw_expect = cfg.get("expect_status")
    expect_status = raw_expect if isinstance(raw_expect, int) and not isinstance(raw_expect, bool) else None
    raw_authed = cfg.get("authed_marker")
    authed_marker = raw_authed if isinstance(raw_authed, str) and raw_authed else None
    raw_dead = cfg.get("dead_marker")
    dead_marker = raw_dead if isinstance(raw_dead, str) and raw_dead else None

    if expect_status is None and authed_marker is None and dead_marker is None:
        return (
            "unknown",
            "no liveness signature configured; set "
            "material.liveness = {expect_status, authed_marker, dead_marker}",
        )

    hay = haystack or ""
    if dead_marker is not None and dead_marker in hay:
        return "dead", f"dead_marker {dead_marker!r} present"
    if authed_marker is not None and authed_marker not in hay:
        return "dead", f"authed_marker {authed_marker!r} absent"
    if expect_status is not None and status != expect_status:
        return "dead", f"status {status} != expect {expect_status}"

    confirmations: list[str] = []
    if authed_marker is not None:
        confirmations.append("authed_marker present")
    if dead_marker is not None:
        confirmations.append("dead_marker absent")
    if expect_status is not None:
        confirmations.append(f"status {status}")
    return "live", ", ".join(confirmations)


def _build_liveness_haystack(
    status: int,
    reason: str,
    headers: list[tuple[str, str]],
    body: str,
) -> str:
    """Combine the status line + response headers (incl. ``Location``) + body into
    the single case-sensitive haystack the liveness classifier matches against."""
    status_line = f"HTTP {status} {reason}".rstrip()
    header_text = "\n".join(f"{name}: {value}" for name, value in headers)
    return "\n".join(part for part in (status_line, header_text, body) if part)


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
    them: the matching ``host_cookies`` bucket is used ALONE, falling back to the
    flat ``cookies`` view ONLY for identities with no per-host buckets at all.
    When buckets exist but none match the probed host we omit cookies entirely —
    the flat view is a display-only UNION across every captured host, so injecting
    it would bleed another host's session cookies onto this host (cross-host
    session bleed). Plus the identity's headers and a bearer token when present.
    """
    headers: dict[str, str] = {}
    for key, value in (material.get("headers") or {}).items():
        if str(key).strip():
            headers[str(key)] = str(value)
    cookies: dict[str, str] = {}
    host_scoped: dict[str, str] = {}
    has_host_buckets = False
    try:
        from .paths import add_assess_import_path

        add_assess_import_path(_install_root(engagement_dir))
        from assess.lib.identity import (  # type: ignore[import-not-found]
            host_cookie_hosts,
            host_cookies_for,
        )

        host_scoped = host_cookies_for(material, host)
        has_host_buckets = bool(host_cookie_hosts(material))
    except Exception:  # noqa: BLE001 — assess import optional; fall back to flat view
        host_scoped = {}
        has_host_buckets = False
    if host_scoped:
        cookies.update(host_scoped)
    elif not has_host_buckets:
        # No per-host buckets at all (legacy/manual identity): fall back to the
        # flat ``cookies`` view. When buckets DO exist but none match this probed
        # host we deliberately OMIT cookies — ``material['cookies']`` is a
        # display-only UNION across every captured host, so injecting it here
        # would bleed another host's uniquely-named session cookies onto this
        # host. Mirrors ``assess.lib.kali._identity_header_pairs``.
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
    classify session liveness against the identity's operator-configured
    ``material['liveness']`` signature.

    Redirects are NOT followed — a 302 to a login page is preserved as a signal in
    the haystack rather than chased. The full response (status line + headers incl.
    ``Location`` + body) is fed to ``_classify_liveness``. Returns
    ``{"liveness", "reason", "http_status", "error"}``; any transport error yields
    ``liveness="unknown"`` with a populated ``error`` (never a false verdict).
    """
    material = (
        _active_material(engagement_dir)
        if identity is None
        else _api(engagement_dir, "GET", f"/{identity}")
    )
    liveness_cfg = material.get("liveness") if isinstance(material, dict) else None
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {
            "liveness": "unknown",
            "reason": "invalid probe URL",
            "http_status": None,
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
        reason_line = resp.reason or ""
        resp_headers = list(resp.getheaders())
        body = resp.read().decode("utf-8", "replace")
    except OSError as exc:
        return {
            "liveness": "unknown",
            "reason": f"probe request failed: {exc}",
            "http_status": None,
            "error": f"probe request failed: {exc}",
        }
    finally:
        conn.close()
    haystack = _build_liveness_haystack(status, reason_line, resp_headers, body)
    verdict, reason = _classify_liveness(status, haystack, liveness_cfg)
    return {
        "liveness": verdict,
        "reason": reason,
        "http_status": status,
        "error": None,
    }


def persist_liveness(
    engagement_dir: Path,
    identity: str,
    verdict: str,
    probed_at: str | None = None,
) -> dict[str, Any]:
    """Persist an LLM/operator-owned per-session liveness verdict (WS4).

    POSTs the classified ``verdict`` (``live|dead|unknown``) to the backend
    ``/credentials/{identity}/liveness`` route, which reconciles the session's
    ``state`` (dead->dead, live->available clearing a stale flag, unknown leaves
    state untouched — never a false verdict). ``probed_at`` defaults to now (UTC).
    Only called for an explicit ``--identity`` probe; the active-identity path
    stays read-only. Returns the updated material.
    """
    if probed_at is None:
        probed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = _api(
        engagement_dir, "POST", f"/{identity}/liveness",
        {"verdict": verdict, "probed_at": probed_at},
    )
    return result if isinstance(result, dict) else {}


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


# ---------------------------------------------------------------------------
# vigil auth keepalive — keep long-lived (enterprise SSO / reverse-proxy) sessions live
# ---------------------------------------------------------------------------
#
# Ported and generalized from the proven CMS reference keepalive. Each cycle it
# re-resolves the freshest full-anchor capture PER distinct login (auto-follows
# re-logins, skips captured logouts), fires ONE read-only authed GET per identity
# through the kali-exec path to reset the enterprise IDLE clock, and tees a
# LIVE/DEAD + userId verdict to a log. The live probe is the AUTHORITATIVE
# liveness oracle — cookie presence/age is never trusted on its own.
#
# There are NO built-in anchor-cookie names. Vigil bakes in NO target-specific auth
# knowledge — every engagement's session/cookies differ, so the operator MUST declare
# the session-anchor cookie name(s) per engagement via ``--anchor-cookie`` (repeatable).
# An anchor cookie's VALUE identifies a distinct login (so captures dedup to one per
# login) and the server emits the literal value ``deleted`` on logout — the marker of a
# captured logout to skip. (The full per-engagement liveness ADAPTER — anchors + probe
# path + live/dead classification the LLM authors for the target — is roadmap item R5.)

_HTTP_STATUS_RE = re.compile(r"HTTP/\d(?:\.\d)?\s+(\d{3})")
# The userId lands inside the JSON-escaped ``stdout_preview`` of the kali-exec
# envelope, so its quotes may be backslash-escaped (``\"userId\"``); tolerate both.
_USER_ID_RE = re.compile(r'\\?"userId\\?"\s*:\s*\\?"([^"\\]*)')

_KEEPALIVE_CAVEATS: tuple[str, ...] = (
    "  keepalive resets the enterprise IDLE timeout only. Hard ceilings it CANNOT defeat:",
    "    - the absolute / max-session lifetime (e.g. F5 APM ~80 min) still expires on schedule",
    "    - a same-user browser re-login tears this session down (Set-Cookie: <anchor>=deleted)",
    "    => for multi-hour / cross-account runs you STILL need a fresh browser login periodically.",
)


def _ka_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_caps(
    identities: dict[str, Any],
    caps: int,
    *,
    anchor_cookies: tuple[str, ...],
) -> list[str]:
    """Freshest full-anchor capture per distinct login, newest-first, capped to ``caps``.

    Ports the reference ``resolve_caps``: from the FULL identity map (cookie VALUES
    included — the value-redacted ``auth list`` view cannot do this) keep only
    captures that carry one of the OPERATOR-DECLARED ``anchor_cookies`` (this
    engagement's session-anchor cookie name(s); Vigil assumes none), DROP any whose
    anchor value is the literal ``deleted`` (a captured logout folded into the jar),
    then dedup by the anchor identity — so re-logins are auto-followed and one login
    is not probed N times — keeping the newest ``updated_at``. Pure, cheap PRE-FILTER
    only: a clean-looking cap can still be DEAD server-side; the live probe is the
    authoritative oracle.
    """
    anchor_set = set(anchor_cookies)
    rows: list[tuple[str, str, tuple[tuple[str, str], ...]]] = []
    for name, info in (identities or {}).items():
        if not isinstance(info, dict):
            continue
        raw_cookies = info.get("cookies")
        cookies = raw_cookies if isinstance(raw_cookies, dict) else {}
        present = {
            str(k): str(v)
            for k, v in cookies.items()
            if k in anchor_set and v not in (None, "")
        }
        if not present:
            continue  # anchor-less junk row — no declared session-anchor cookie
        if any(v.strip().lower() == "deleted" for v in present.values()):
            continue  # captured logout -> skip
        anchor_key = tuple(sorted(present.items()))
        rows.append((str(info.get("updated_at") or ""), str(name), anchor_key))
    # Newest ``updated_at`` first; name is a deterministic tie-break.
    rows.sort(key=lambda r: (r[0], r[1]), reverse=True)
    seen: set[tuple[tuple[str, str], ...]] = set()
    resolved: list[str] = []
    for _updated, name, anchor_key in rows:
        if anchor_key in seen:
            continue
        seen.add(anchor_key)
        resolved.append(name)
    return resolved[: max(caps, 0)]


def _parse_probe_blob(
    raw: str,
    *,
    anchor_cookies: tuple[str, ...],
) -> dict[str, Any]:
    """Lenient regex parse of the raw ``vigil assess kali exec`` output blob.

    HARD RULE — never ``json.loads`` this. ``emit_result`` prints a single JSON
    envelope whose ``stdout_preview`` is a head+tail TRUNCATION of the curl ``-i``
    response; a cut in the middle of that escaped string yields ``Unterminated
    string``, so a ``json.loads`` here is a latent false-negative. Regex the raw
    text instead. Returns ``{status, status_line, user_id, deleted}`` where
    ``status`` is the int HTTP code (or ``None`` when unparseable) and ``deleted``
    is True when the RESPONSE tore the session down (``<anchor>=deleted``
    Set-Cookie for one of the operator-declared ``anchor_cookies``), which is a
    server logout regardless of the status code.
    """
    raw = raw or ""
    m = _HTTP_STATUS_RE.search(raw)
    status_line = m.group(0) if m else "?"
    status = int(m.group(1)) if m else None
    muid = _USER_ID_RE.search(raw)
    user_id = muid.group(1) if muid else "-"
    deleted = any(f"{name}=deleted" in raw for name in anchor_cookies)
    return {
        "status": status,
        "status_line": status_line,
        "user_id": user_id,
        "deleted": deleted,
    }


def _classify_probe(
    parsed: dict[str, Any],
    raw: str,
    liveness_cfg: dict[str, Any] | None,
) -> tuple[bool, str]:
    """Decide LIVE vs DEAD for one probe from its parsed blob.

    Precedence:
      1. a RESPONSE-side teardown (``<anchor>=deleted`` Set-Cookie) is a hard DEAD
         override — the server is killing the session no matter the status code;
      2. else, when the identity declares a ``material.liveness`` signature, defer to
         the shared ``_classify_liveness`` classifier (kept in lockstep with
         ``assess.commands.auth_status``);
      3. else the reference default: HTTP 200 with no ``sessionExpired`` marker.

    Returns ``(is_live, reason)``.
    """
    if parsed.get("deleted"):
        return False, "response set <anchor>=deleted (server logout teardown)"
    status = parsed.get("status")
    status_int = status if isinstance(status, int) else None
    if isinstance(liveness_cfg, dict) and liveness_cfg:
        verdict, reason = _classify_liveness(status_int, raw or "", liveness_cfg)
        return verdict == "live", f"{verdict}: {reason}"
    expired = "sessionExpired" in (raw or "")
    if status_int == 200 and not expired:
        return True, "HTTP 200, no sessionExpired marker"
    return False, f"{parsed.get('status_line', '?')}, sessionExpired={expired}"


def _vigil_assess_argv(
    engagement_dir: Path, identity: str, probe_url: str
) -> list[str]:
    """Build the argv for ONE authed liveness GET routed through the kali-exec path.

    Routing through ``vigil assess kali exec`` (correct egress + command-run audit +
    identity injection) with an argv LIST — NEVER ``bash -c`` (a shell wrapper eats
    the ``--identity`` flag and the session is not injected). Mirrors
    ``assess.commands.auth_status._run_identity_probe``: a read-only ``curl -sS -i``
    (status line + headers incl. ``Location``, no ``-L``) tagged ``--technique AUTH``
    / ``--probe-kind fingerprint`` in the always-allowed ``recon`` phase. Prefers the
    ``vigil`` binary on PATH; falls back to invoking ``agent/scripts/assess.py``
    directly (what the ``vigil assess`` passthrough execs anyway) so PATH is not a
    hard dependency.
    """
    vigil = shutil.which("vigil")
    if vigil:
        prefix = [vigil, "assess", "--engagement-dir", str(engagement_dir)]
    else:
        assess = _install_root(engagement_dir) / "agent" / "scripts" / "assess.py"
        prefix = [str(assess), "--engagement-dir", str(engagement_dir)]
    return [
        *prefix,
        "kali", "exec",
        "--identity", identity,
        "--technique", "AUTH",
        "--intent", "session keepalive liveness probe",
        "--probe-kind", "fingerprint",
        "--phase", "recon",
        "--timeout", "30",
        "--",
        "curl", "-sS", "-i", probe_url,
    ]


def _keepalive_probe(engagement_dir: Path, identity: str, probe_url: str) -> str:
    """Run ONE authed liveness GET; return the raw combined stdout+stderr blob for
    ``_parse_probe_blob``. Any spawn/timeout failure returns an error blob so the
    cycle records DEAD and the loop never crashes."""
    argv = _vigil_assess_argv(engagement_dir, identity, probe_url)
    env = dict(os.environ)
    env["ENGAGEMENT_DIR"] = str(engagement_dir)
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, env=env, timeout=90
        )
    except subprocess.TimeoutExpired:
        return "__keepalive_probe_error__ kali exec timed out"
    except OSError as exc:  # noqa: BLE001 — a probe must never crash the loop
        return f"__keepalive_probe_error__ {exc}"
    return (proc.stdout or "") + (proc.stderr or "")


def _keepalive_cycle(
    engagement_dir: Path,
    explicit: list[str],
    caps: int,
    anchor_cookies: tuple[str, ...],
    probe_url: str,
    emit,
    iteration: int,
) -> None:
    """One keepalive cycle: (re-)resolve caps, probe each, tee a verdict line.

    ``anchor_cookies`` are the operator-declared session-anchor cookie name(s) for
    this engagement — they drive both the freshest-per-anchor cap resolution and the
    ``<anchor>=deleted`` server-logout detection in the parsed probe blob.
    """
    auth_map = read_auth(engagement_dir)
    identities = auth_map.get("identities") if isinstance(auth_map, dict) else {}
    identities = identities if isinstance(identities, dict) else {}
    cap_names = (
        list(explicit)
        if explicit
        else _resolve_caps(identities, caps, anchor_cookies=anchor_cookies)
    )
    if not cap_names:
        emit(f"{_ka_ts()}  iter={iteration}  (no live-looking caps — log back in)")
        return
    for cap in cap_names:
        material = identities.get(cap)
        material = material if isinstance(material, dict) else {}
        liveness_cfg = material.get("liveness")
        raw = _keepalive_probe(engagement_dir, cap, probe_url)
        parsed = _parse_probe_blob(raw, anchor_cookies=anchor_cookies)
        live, reason = _classify_probe(
            parsed, raw, liveness_cfg if isinstance(liveness_cfg, dict) else None
        )
        emit(
            f"{_ka_ts()}  iter={iteration}  {cap}  "
            f"{'LIVE' if live else 'DEAD'}  {parsed['status_line']}  "
            f"userId={parsed['user_id']}  deleted={parsed['deleted']}  ({reason})"
        )
        time.sleep(1)  # <=2 req/s deconfliction pacing between caps


def _redirect_daemon_stdio(log_file: Path) -> None:
    """Point the daemon's stdin at /dev/null and stdout/stderr at the log, so the
    keepalive loop's ``print`` tee lands in the log and any traceback is captured."""
    sys.stdout.flush()
    sys.stderr.flush()
    with open(os.devnull, "rb", 0) as devnull:
        os.dup2(devnull.fileno(), 0)
    log_fd = os.open(str(log_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.dup2(log_fd, 1)
        os.dup2(log_fd, 2)
    finally:
        os.close(log_fd)


def _detach_into_background(engagement_dir: Path, log_file: Path) -> int | None:
    """Double-fork into a detached daemon that outlives the launching shell.

    Returns the daemon PID in the ORIGINAL parent (so the caller can print it plus a
    ``kill <pid>`` line), or ``None`` in the fully-detached grandchild — which then
    runs the keepalive loop with stdout/stderr redirected to ``log_file`` and its PID
    written to ``<engagement>/pids/keepalive.pid``. A pipe hands the grandchild PID
    back to the parent across the intermediate child.
    """
    if not hasattr(os, "fork"):
        raise SystemExit("--detach requires a POSIX platform (os.fork unavailable)")
    pids_dir = engagement_dir / "pids"
    pids_dir.mkdir(parents=True, exist_ok=True)
    pid_file = pids_dir / "keepalive.pid"

    sys.stdout.flush()
    sys.stderr.flush()
    read_fd, write_fd = os.pipe()

    pid1 = os.fork()
    if pid1 > 0:
        # Original parent: read the daemon PID off the pipe (blocks until every
        # write end is closed → both child1 exit and grandchild write+close), then
        # reap the fast-exiting intermediate child.
        os.close(write_fd)
        with os.fdopen(read_fd, "r") as reader:
            data = reader.read().strip()
        try:
            os.waitpid(pid1, 0)
        except OSError:
            pass
        return int(data) if data.isdigit() else None

    # Intermediate child #1.
    try:
        os.close(read_fd)
        os.setsid()
        if os.fork() > 0:
            os._exit(0)  # child1 exits; the grandchild is reparented to init
        # Grandchild (the daemon).
        pid = os.getpid()
        try:
            os.write(write_fd, str(pid).encode())
        finally:
            os.close(write_fd)
        try:
            pid_file.write_text(f"{pid}\n", encoding="utf-8")
        except OSError:
            pass
        _redirect_daemon_stdio(log_file)
        return None
    except BaseException:
        os._exit(1)


def keepalive(
    engagement_dir: Path,
    *,
    identities: list[str] | None = None,
    anchor_cookies: list[str] | None = None,
    interval: int = 285,
    iters: int = 120,
    caps: int = 4,
    probe_url: str | None = None,
    log_path: str | Path | None = None,
    detach: bool = False,
) -> None:
    """Keep long-lived (enterprise SSO / reverse-proxy) sessions live across a long
    engagement.

    Every ``interval`` seconds, for ``iters`` cycles, fire ONE read-only authed GET
    per identity to reset the idle clock and tee a LIVE/DEAD + userId verdict to a
    log. ``anchor_cookies`` are REQUIRED: the operator-declared session-anchor cookie
    name(s) for THIS engagement (Vigil bakes in none). They drive freshest-per-anchor
    cap resolution and ``<anchor>=deleted`` server-logout detection. When
    ``identities`` is empty each cycle auto-resolves the freshest ``caps``
    full-anchor captures per distinct login (skipping captured logouts), so
    re-logins are auto-followed; passing ``--identity`` overrides that. The live
    probe is the authoritative liveness oracle. ``detach`` double-forks into a
    background daemon (PID file under ``<engagement>/pids/``) that outlives the shell.
    """
    engagement_dir = Path(engagement_dir).expanduser()
    probe_url = (probe_url or "").strip()
    if not probe_url:
        raise SystemExit(
            "keepalive requires --probe-url <url> (an authed endpoint that returns "
            "logged-in content; cookie presence alone is not proof of liveness)"
        )
    anchors = tuple(a.strip() for a in (anchor_cookies or []) if a and a.strip())
    if not anchors:
        raise SystemExit(
            "keepalive requires at least one --anchor-cookie naming this engagement's "
            "session-anchor cookie(s) (e.g. --anchor-cookie SESSIONID --anchor-cookie "
            "AUTHTOKEN). Vigil bakes in no target-specific cookie names — every "
            "engagement's session/cookies differ, so declare them per engagement."
        )
    explicit = [i.strip() for i in (identities or []) if i and i.strip()]
    log_file = (
        Path(log_path).expanduser()
        if log_path
        else engagement_dir / "tools" / "keepalive.log"
    )
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Startup banner + hard-ceiling caveats to the launching terminal (always, even
    # when detaching, so the operator sees the limits up front).
    print(
        f"keepalive: interval={interval}s iters={iters} caps={caps} "
        f"identities={explicit or 'auto'} anchors={list(anchors)} "
        f"probe_url={probe_url} log={log_file}",
        flush=True,
    )
    for line in _KEEPALIVE_CAVEATS:
        print(line, flush=True)

    if detach:
        pid = _detach_into_background(engagement_dir, log_file)
        if pid is not None:
            # Original parent: report and return; the daemon runs the loop.
            print(f"keepalive detached: pid={pid}  log={log_file}", flush=True)
            print(f"stop it with: kill {pid}", flush=True)
            return
        # Daemon (grandchild): stdout/stderr are already redirected to the log.

    def emit(line: str) -> None:
        # Tee: print → the operator's terminal (foreground) or the log via the
        # daemon's dup2 (detached). A foreground run ALSO appends explicitly so the
        # log persists; the daemon skips the append (its print already lands there).
        print(line, flush=True)
        if not detach:
            with open(log_file, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    emit(
        f"{_ka_ts()}  KEEPALIVE START  interval={interval}s iters={iters} "
        f"caps={caps} identities={explicit or 'auto'} anchors={list(anchors)} "
        f"probe_url={probe_url}"
    )
    try:
        for i in range(1, max(iters, 0) + 1):
            _keepalive_cycle(
                engagement_dir, explicit, caps, anchors, probe_url, emit, i
            )
            if i < iters:
                time.sleep(interval)
    except KeyboardInterrupt:
        emit(f"{_ka_ts()}  KEEPALIVE INTERRUPTED (operator Ctrl-C)")
    finally:
        emit(f"{_ka_ts()}  KEEPALIVE EXITED (relaunch if still testing)")
