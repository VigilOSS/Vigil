"""vigil assess auth status — one-shot view of the engagement's auth state.

Reads the active identity from the centralized credential store (orchestrator
backend) and surfaces:
- ``auth_context`` (anonymous / authenticated / admin / specific role)
- ``mode`` (proxy_capture / manual / auth_json / none)
- ``use_for_requests`` flag
- ``state`` (available / missing / expired)
- ``expires_at`` (with a flag when it has passed or is within 5 minutes)
- The auth material it carries, values included (Authorization header,
  session cookies, OAuth tokens)
- Timestamp of the most recent live-credential probe via
  ``command-run list --technique AUTH``
- Recommended refresh path per the C42 Auth-expiry recovery loop

Pairs with the recovery loop in ``agent/operator-core.md`` Credential
Auto-Use section. The CLI is read-only; it does not write credentials
or trigger a refresh.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from assess.lib.auth_liveness import (
    classify_liveness as _classify_liveness,
    probe_scope_key,
)

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.creds_client import (
    active_material,
    persist_liveness,
    resolve_identity,
)


def register_status(subparsers) -> None:
    p = subparsers.add_parser(
        "status",
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
    p.add_argument(
        "--identity",
        dest="identity",
        default=None,
        help=(
            "Target a SPECIFIC stored identity (opaque name from `vigil assess "
            "auth list`) instead of the active one — the multi-identity store can "
            "hold several sessions for one site (IDOR/BOLA). Without --probe this "
            "just views that identity's state; with --probe it probes AS that "
            "identity and PERSISTS the verdict (live->available, dead->dead). "
            "Default (omitted) keeps the read-only active-identity behavior."
        ),
    )
    p.add_argument(
        "--probe",
        action="store_true",
        help=(
            "Actively verify session liveness: GET --probe-url through the kali "
            "runtime AS the active identity (its cookies are injected by the same "
            "code the runtime uses), then classify the response against the "
            "identity's operator-configured material.liveness signature — either "
            "{expect_status, authed_marker, dead_marker} or a per-origin map "
            "{'https://app.example': {...}}. Presence of credentials is NOT "
            "liveness; without --probe, liveness is 'unknown'. With no signature "
            "for the probed origin the probe stays 'unknown'. 'dead' needs "
            "POSITIVE evidence (dead_marker, or an auth challenge); a missing "
            "authed_marker alone reports 'unknown', not a killed session."
        ),
    )
    p.add_argument(
        "--probe-url",
        dest="probe_url",
        help=(
            "URL to GET as the active identity for the --probe liveness check. The "
            "response (status line + headers incl. Location + body) is matched "
            "case-sensitively against material.liveness = {expect_status, "
            "authed_marker, dead_marker}; redirects are NOT followed."
        ),
    )
    p.add_argument(
        "--scope",
        default="",
        help=(
            "Logical application scope for alias resolution and liveness "
            "persistence. Omitted with --probe, the scope defaults to the "
            "--probe-url origin, so a verdict earned on one host is never "
            "recorded as a verdict about every host this identity reaches."
        ),
    )
    p.set_defaults(func=run)


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


def _run_identity_probe(
    engagement_dir: str,
    identity: str | None,
    url: str,
    *,
    liveness_cfg: dict[str, Any] | None,
    scope_key: str = "",
    timeout: int = 15,
) -> dict[str, Any]:
    """GET ``url`` as ``identity`` through the kali-exec path and classify liveness.

    Shells the existing ``kali_exec`` runtime path with ``identity=<active>`` so the
    request carries the identity's cookies via ``_apply_identity_material`` — the
    SAME injection code the runtime uses, never reinvented here. curl runs with
    ``-i`` (response status line + headers, INCLUDING ``Location``, + body) and no
    ``-L`` so a 302 to a login page is preserved in the haystack as a signal rather
    than chased, plus ``--suppress-connect-headers`` to keep an egress proxy's
    CONNECT reply out of that haystack. The numeric status is read from the
    trailing ``-w`` ``VIGIL_HTTP_CODE=`` marker; the remaining stdout IS the
    haystack matched against the operator-configured ``material.liveness``
    signature. Any exec / transport failure or unparseable status yields
    ``liveness="unknown"`` with a populated ``error`` (never a false verdict).
    """
    from pathlib import Path

    try:
        from assess.lib.kali import kali_exec
    except Exception as exc:  # noqa: BLE001 — import guarded so probe never hard-fails
        return {"liveness": "unknown", "reason": "probe unavailable",
                "http_status": None, "error": f"probe unavailable: {exc}"}
    # --suppress-connect-headers keeps an HTTP egress proxy's CONNECT reply
    # ("HTTP/1.1 200 Connection established" + its own headers) out of the -i
    # output. The numeric status here is read from curl's %{http_code}, which is
    # already the ORIGIN's, so this is about the HAYSTACK: the proxy's header
    # block is another hop's text and has no business being matched against this
    # identity's authed_marker / dead_marker / Location.
    cmd = ["curl", "-sS", "-i", "--suppress-connect-headers",
           "--max-time", str(timeout),
           "-w", "\nVIGIL_HTTP_CODE=%{http_code}\n", url]
    try:
        result = kali_exec(
            cmd,
            technique="AUTH",
            intent="auth liveness probe (auth status --probe)",
            probe_kind="fingerprint",
            phase="recon",
            timeout=timeout + 10,
            engagement_dir=Path(engagement_dir),
            identity=identity,
            identity_scope=scope_key,
            # The liveness probe is the documented recovery path for a session
            # the store has flagged. It MUST be able to run against the state it
            # recovers from, so it is the one caller allowed to replay an
            # identity the store has already marked `dead` (an age-flagged
            # `stale` identity is replayable by every caller). Without this the
            # store deadlocks: the flag blocks the probe that would clear it.
            identity_probe=True,
            tool_name="curl",
        )
    except Exception as exc:  # noqa: BLE001 — a live probe must never crash auth-status
        return {"liveness": "unknown", "reason": "probe exec failed",
                "http_status": None, "error": f"probe exec failed: {exc}"}
    # Match against the FULL response, not the 32K head+tail ``stdout_preview``:
    # with ``curl -i`` a marker in the elided MIDDLE of a large body would be
    # silently dropped, diverging from the CLI mirror (which matches the full
    # ``resp.read()`` body) and risking a false verdict. Read the complete stdout
    # file kali_exec streamed to; fall back to the preview if it is unreadable so
    # the probe never crashes.
    out = getattr(result, "stdout_preview", "") or ""
    stdout_path = getattr(result, "stdout_path", "") or ""
    if stdout_path:
        try:
            out = Path(stdout_path).read_bytes().decode("utf-8", "replace")
        except OSError:
            pass
    status: int | None = None
    haystack_lines: list[str] = []
    for line in out.splitlines():
        if line.startswith("VIGIL_HTTP_CODE="):
            raw = line[len("VIGIL_HTTP_CODE="):].strip()
            try:
                status = int(raw) if raw else None
            except ValueError:
                status = None
        else:
            haystack_lines.append(line)
    haystack = "\n".join(haystack_lines)
    if status in (None, 0) or getattr(result, "transport_error", False):
        return {
            "liveness": "unknown",
            "reason": "no HTTP status parsed from probe output",
            "http_status": status,
            "error": getattr(result, "transport_error_detail", "")
            or "no HTTP status parsed from probe output",
        }
    verdict, reason = _classify_liveness(status, haystack, liveness_cfg)
    return {
        "liveness": verdict,
        "reason": reason,
        "http_status": status,
        "error": None,
    }


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


def _cookie_pairs(cookies: dict) -> str:
    return "; ".join(f"{name}={cookies[name]}" for name in sorted(cookies))


def _token_material(auth: dict) -> list[str]:
    """Render every piece of auth material the credential carries, values included.

    These are the engagement's own credentials on the operator's own machine, so
    the live value is what makes the view useful: it is what gets replayed by
    hand, pasted into a repro, and compared against a 401. Nothing is filtered by
    name either — a stored record holds auth material by construction, and a
    name allowlist could only drop a header the operator deliberately stored."""
    material: list[str] = []
    headers = auth.get("headers") or {}
    if isinstance(headers, dict):
        for key, value in headers.items():
            material.append(f"{key}: {value}")
    cookies = auth.get("cookies") or {}
    if isinstance(cookies, dict) and cookies:
        material.append(f"flat_cookies: {_cookie_pairs(cookies)}")
    for bucket in auth.get("host_cookies") or []:
        if not isinstance(bucket, dict):
            continue
        bucket_cookies = bucket.get("cookies")
        if isinstance(bucket_cookies, dict) and bucket_cookies:
            material.append(
                f"host_cookies[{bucket.get('host') or '-'}]: {_cookie_pairs(bucket_cookies)}"
            )
    tokens = auth.get("tokens") or {}
    if isinstance(tokens, dict):
        for key, value in tokens.items():
            material.append(f"tokens.{key}: {value}")
    return material


def _refresh_recommendation(auth: dict) -> str:
    """Heuristic refresh-path recommendation matching the C42 recovery loop.

    Reads the stored record directly rather than the rendered material lines —
    those now carry live cookie and token values, and a target-chosen value that
    happens to spell ``refresh_token`` must not pick the refresh path."""
    headers = auth.get("headers")
    headers = headers if isinstance(headers, dict) else {}
    tokens = auth.get("tokens")
    tokens = tokens if isinstance(tokens, dict) else {}
    has_bearer = any(
        str(key).lower() == "authorization" and str(value).lower().startswith("bearer ")
        for key, value in headers.items()
    )
    has_session = bool(auth.get("cookies")) or bool(auth.get("host_cookies"))
    has_refresh = any("refresh_token" in str(key) for key in tokens)
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
            "refreshed cookie set into the credential store automatically."
        )
    return (
        "No token material detected. Operator must run the login flow to populate "
        "credentials (vigil auth import, or proxy-assisted capture)."
    )


def _last_auth_probe(
    client: AssessmentClient | None, identity_name: str | None = None
) -> dict | None:
    """Best-effort fetch of the most recent command-runs row with
    --technique AUTH so the operator sees when the auth was last validated.

    With ``identity_name`` the newest row FOR THAT IDENTITY is reported: the
    multi-identity store routinely holds several sessions, and the globally
    newest AUTH run usually belongs to a different one, which would date the
    wrong session's last validation. Returns None on any failure (network,
    missing endpoint, parse error).
    """
    if client is None:
        return None
    try:
        # /command-runs is registered on the assessment router
        # (/engagements/{key}/assessment/command-runs), so go through
        # `.get()` which carries the /assessment prefix — `.get_engagement()`
        # targets the non-assessment scope and 404s here.
        query: list[tuple[str, str]] = [("technique", "AUTH")]
        if identity_name:
            query.append(("auth_context", identity_name))
        query.append(("limit", "1"))
        rows = client.get(f"command-runs?{urlencode(query)}")
    except Exception:  # noqa: BLE001 — best-effort read
        return None
    items: list[dict] = []
    if isinstance(rows, dict):
        items = rows.get("items") or rows.get("rows") or []
    elif isinstance(rows, list):
        items = rows
    if identity_name:
        items = [
            row
            for row in items
            if str(row.get("auth_context") or "") == identity_name
        ]
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
    # --identity targets a SPECIFIC stored session (multi-identity store); without
    # it we view/probe the active identity exactly as before.
    requested_identity = getattr(args, "identity", None)
    configured_scope = str(getattr(args, "scope", "") or "")
    probe_url_arg = getattr(args, "probe_url", None)
    # A probe with no explicit --scope is scoped to the probe URL's own origin,
    # never to the legacy global scope: a verdict earned on one application host
    # must not be recorded as a verdict about every host this identity reaches.
    scope_key = (
        probe_scope_key(probe_url_arg, configured_scope)
        if getattr(args, "probe", False)
        else configured_scope
    )
    resolved_identity: str | None = None
    # This read is INSPECTION, never a use: `auth status` only looks at the stored
    # record. Recording a use here would refresh `last_seen_at`, and the 8-hour
    # stale flag and 5-day purge both key off it — so a status loop would keep an
    # unused session looking fresh forever and print a misleading age. When
    # --probe runs, the USE is recorded where the credential actually goes on the
    # wire: _run_identity_probe shells kali_exec with --identity, and that
    # injection path resolves for replay.
    if requested_identity:
        if scope_key:
            resolved_identity, auth = resolve_identity(
                cfg.engagement_dir,
                requested_identity,
                scope_key=scope_key,
                record_use=False,
            )
        else:
            resolved_identity, auth = resolve_identity(
                cfg.engagement_dir, requested_identity, record_use=False
            )
    else:
        auth = active_material(cfg.engagement_dir, record_use=False)

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
    subject_identity = str(
        resolved_identity
        or (auth.get("identity_name") if isinstance(auth, dict) else "")
        or requested_identity
        or ""
    )
    try:
        last_probe = _last_auth_probe(client, subject_identity or None)
    finally:
        if client is not None:
            client.close()

    # Liveness is UNKNOWN unless actively probed: a stored credential's presence
    # (cookies/headers) is NOT proof the session is still valid. --probe runs a
    # real authed GET to confirm live vs dead.
    liveness = "unknown"
    liveness_detail: dict | None = None
    if getattr(args, "probe", False):
        probe_url = getattr(args, "probe_url", None)
        if not probe_url:
            liveness_detail = {"liveness": "unknown", "reason": "--probe requires --probe-url",
                               "http_status": None, "error": "--probe requires --probe-url <url>"}
        elif not auth:
            miss = (
                f"no such identity to probe: {requested_identity}"
                if requested_identity
                else "no active identity/session to probe"
            )
            liveness_detail = {"liveness": "unknown", "reason": "no identity",
                               "http_status": None, "error": miss}
        else:
            probe_identity = resolved_identity or requested_identity or (
                auth.get("identity_name") if isinstance(auth, dict) else None
            )
            liveness_cfg = auth.get("liveness") if isinstance(auth, dict) else None
            liveness_detail = _run_identity_probe(
                cfg.engagement_dir,
                probe_identity,
                probe_url,
                liveness_cfg=liveness_cfg,
                scope_key=scope_key,
            )
            liveness_detail.setdefault("identity_name", str(probe_identity))
            liveness_detail.setdefault("scope_key", scope_key)
            # WS4 opt-in persistence: only when a SPECIFIC identity was targeted
            # does auth-status write — it persists the classified verdict so a
            # proven-dead session is hidden from the default list and a `live`
            # probe clears a stale mark. The active-identity path stays read-only.
            # A transport error / no-signature verdict is `unknown`, which
            # set_liveness records WITHOUT marking the session dead (never a false
            # verdict). Persistence must never crash the read-only status view.
            if requested_identity and probe_identity:
                probed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                try:
                    kwargs = {}
                    if scope_key:
                        kwargs = {
                            "scope_key": scope_key,
                            "source": "auth-status",
                            "reason": str(liveness_detail.get("reason") or ""),
                        }
                    persisted_material = persist_liveness(
                        cfg.engagement_dir,
                        str(probe_identity),
                        liveness_detail["liveness"],
                        probed_at,
                        **kwargs,
                    )
                    # The persist RECONCILES state (a live verdict revives a
                    # stale/dead projection), so the reconciled material is what
                    # this view must report — not the pre-probe read.
                    if isinstance(persisted_material, dict) and persisted_material:
                        auth = {**auth, **persisted_material}
                    liveness_detail["persisted"] = True
                except Exception as exc:  # noqa: BLE001 — status view must not crash
                    liveness_detail["persisted"] = False
                    liveness_detail["persist_error"] = str(exc)
        liveness = liveness_detail["liveness"]

    material = _token_material(auth) if auth else []
    state = {
        "engagement_key": cfg.engagement_key,
        "identity_name": subject_identity or None,
        "auth_context": auth.get("auth_context") or "anonymous",
        "mode": auth.get("mode") or "none",
        "use_for_requests": bool(auth.get("use_for_requests")),
        "state": auth.get("state") or ("missing" if not auth else "available"),
        "expires_at": expires_at_raw,
        "expires_state": expires_state,
        "expires_in_seconds": expires_in_seconds,
        "tokens": material,
        "liveness": liveness,
        "liveness_probe": liveness_detail,
        "last_auth_probe": last_probe,
        "recommend": _refresh_recommendation(auth),
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
    if material:
        print("tokens:")
        for line in material:
            print(f"  - {line}")
    else:
        print("tokens:         (none detected)")
    if liveness_detail is not None:
        detail = f"http_status={liveness_detail.get('http_status')}"
        if liveness_detail.get("reason"):
            detail += f" reason={liveness_detail['reason']}"
        if liveness_detail.get("error"):
            detail += f" error={liveness_detail['error']}"
        print(f"liveness:       {liveness}  ({detail})")
    else:
        print(f"liveness:       {liveness}  (not probed; presence != live — pass --probe)")
    if last_probe:
        print(
            f"last_auth_probe: run_id={last_probe.get('run_id')} "
            f"status={last_probe.get('status')} "
            f"completed_at={last_probe.get('completed_at') or '-'}"
        )
    else:
        print("last_auth_probe: (no AUTH-technique command-run rows found)")
    print(f"recommend:      {state['recommend']}")
