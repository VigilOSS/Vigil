"""Engagement credential store service (centralized — replaces auth.json).

Wraps :mod:`app.db` credential CRUD with the merge + named-identity logic the
proxy capture path and the ``vigil auth`` CLI need. The named-identity model is
preserved end to end: an engagement holds N identities and exactly one is
active (resolved when no ``--identity`` is requested).

The proxy used to merge captured cookies into ``auth.json`` itself; that merge
now lives here (:func:`capture_material`) so the mitmproxy addon stays a thin
HTTP client and the merge is unit-tested server-side.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from .. import db

DEFAULT_IDENTITY = "default"

# Session-anchor cookie NAMES (case-insensitive). A capture's identity is derived
# from these plus a JWT/bearer anchor, so the same login coalesces (refresh) while
# a genuinely-distinct login appends (multi-identity IDOR/BOLA). Deliberately
# generic (no per-provider hardcoding): a rotating anti-CSRF cookie or a per-client
# stickiness cookie (AWSALB) is high-entropy too, so keying on "any high-entropy
# cookie" would either churn on every reload or wrongly merge two accounts. Keeping
# the anchor hint-scoped is what makes reload-refresh and shared-cookie-no-merge
# both correct.
_SESSION_HINT_COOKIE_NAMES = frozenset(
    {
        "sid", "sessionid", "session", "sess", "jsessionid", "phpsessid",
        "asp.net_sessionid", "connect.sid", "laravel_session", "_session",
        "mrhsession", "smsession",
    }
)

# JWT payload claims used as a stable identity anchor, in priority order. A `sub`
# is stable across a token refresh, so the same user's refreshed bearer coalesces
# to one row while a different subject appends.
_JWT_ANCHOR_CLAIMS = ("sub", "uid", "user_id", "email")

# Token dict keys (case-insensitive) whose value may hold a bearer credential —
# mirrors proxy_addon.BEARER_TOKEN_PRIORITY so the derivation sees the same bearer
# the addon would synthesize into an Authorization header.
_BEARER_TOKEN_KEYS = ("access_token", "id_token", "jwt")
_NON_BEARER_VALUES = frozenset({"bearer", "basic"})

# Fields stored in typed columns or used as control flags — everything else in
# an upsert payload is preserved verbatim in raw_json.
_MODELED_KEYS = frozenset(
    {
        "identity_name", "mode", "state", "use_for_requests", "auth_context",
        "is_active", "cookies", "headers", "tokens", "host_cookies", "notes",
        "expires_at", "created_at", "last_seen_at", "liveness_verdict",
        "last_probed_at", "updated_at", "make_active",
    }
)


def load_identities(
    engagement_id: int,
    *,
    host: str | None = None,
    include_dead: bool = False,
) -> dict[str, Any]:
    """Return ``{"identities": {name: material}, "active_identity": name}``.

    Mirrors the shape the legacy ``identity.load_identities`` produced from
    auth.json, so runtime consumers are storage-agnostic. ``host`` filters to
    sessions usable at that host (subdomain-aware); ``include_dead`` surfaces
    probe-proven-dead sessions that are hidden by default.
    """
    rows = db.list_credentials(engagement_id, host=host, include_dead=include_dead)
    identities = {row["identity_name"]: row for row in rows}
    active = next(
        (row["identity_name"] for row in rows if row.get("is_active")),
        next(iter(identities), DEFAULT_IDENTITY),
    )
    return {"identities": identities, "active_identity": active}


def resolve_identity(
    engagement_id: int, requested: str | None
) -> tuple[str | None, dict[str, Any]]:
    """Resolve a ``--identity`` request, matching legacy semantics.

    * ``requested`` is None -> the active identity, or ``(None, {})`` when the
      engagement declares no identities (caller keeps legacy auth_context).
    * known identity -> that identity's material.
    * unknown identity -> ``(requested, {})`` so the caller can warn while the
      requested name is still recorded as the probe's auth_context.
    """
    if requested is None:
        material = db.get_active_credential(engagement_id)
        if material is None:
            return (None, {})
        return (str(material.get("identity_name") or DEFAULT_IDENTITY), material)
    requested = requested.strip()
    material = db.get_credential(engagement_id, requested)
    return (requested, material or {})


def upsert_material(
    engagement_id: int,
    identity_name: str,
    material: dict[str, Any],
    *,
    make_active: bool = False,
) -> dict[str, Any]:
    """Insert/replace one identity's material from a full payload dict."""
    cookies = _as_dict(material.get("cookies"))
    headers = _as_dict(material.get("headers"))
    tokens = _as_dict(material.get("tokens"))
    host_cookies = material.get("host_cookies")
    host_cookies = host_cookies if isinstance(host_cookies, list) else []
    has_material = bool(cookies or headers or tokens)
    mode = str(material.get("mode") or "manual")
    state = str(material.get("state") or ("available" if has_material else "missing"))
    # raw_json preserves ONLY fields we don't model as typed columns, so weird
    # session shapes survive without re-surfacing control flags on read.
    extras = {k: v for k, v in material.items() if k not in _MODELED_KEYS}
    return db.upsert_credential(
        engagement_id,
        identity_name,
        mode=mode,
        state=state,
        use_for_requests=bool(material.get("use_for_requests", True)),
        auth_context=str(material.get("auth_context") or "authenticated"),
        cookies=cookies,
        headers=headers,
        tokens=tokens,
        host_cookies=host_cookies,
        raw=extras,
        notes=str(material.get("notes") or ""),
        expires_at=material.get("expires_at"),
        make_active=make_active,
    )


def derive_capture_identity(
    cookies: dict[str, str],
    headers: dict[str, str],
    tokens: dict[str, str],
) -> str | None:
    """Derive a deterministic, stateless capture ``identity_name`` from a
    capture's session-anchor material — or ``None`` when there is none.

    This is the churn fix + the multi-identity key (2026-07). The same login
    (same anchor) hashes to the same ``cap-<sha1>`` name so the existing UPSERT
    REFRESHES one row; a genuinely-distinct login (different anchor) yields a
    different name so it APPENDS a new row. Anchor material, in order:

    * **anchor cookies** — cookies whose NAME is in the generic session-hint set
      (:data:`_SESSION_HINT_COOKIE_NAMES`, case-insensitive). If none match, the
      fallback is every cookie with ``len(value) >= 16``. Rotating anti-CSRF /
      per-client stickiness cookies are excluded from the hint path so a reload
      refreshes (no churn) and two accounts sharing an ``AWSALB`` still separate.
    * **JWT / bearer anchor** — an ``Authorization: Bearer <jwt>`` header (or a
      bearer in ``tokens``): decode the JWT payload (middle segment only, NO
      signature check) and anchor on the first present of
      ``sub``/``uid``/``user_id``/``email`` — stable across a token refresh — else
      the raw bearer string.

    Deletion/logout cookie values are filtered before deriving, so a pure-logout
    capture (only ``deleted``/empty cookies, no bearer) derives ``None`` and is a
    no-op that never evicts a live row.

    Guiding rule (behavioral pass): when the anchor is ambiguous the derivation
    errs toward a DISTINCT key (an extra row the LLM ignores + the age backstop),
    never toward collapsing two sessions. Overwrite only ever happens within one
    derived identity (= one login).
    """
    anchor_pairs: list[tuple[str, str]] = []

    # Filter deletion/logout cookies and dequote so `sid="abc"` and `sid=abc`
    # anchor identically and a logout cookie contributes no anchor.
    live_cookies = {
        str(name): _dequote_cookie_value(value)
        for name, value in (cookies or {}).items()
        if not _is_deletion_cookie_value(value)
    }
    hint_cookies = {
        name: value
        for name, value in live_cookies.items()
        if name.lower() in _SESSION_HINT_COOKIE_NAMES
    }
    if hint_cookies:
        anchor_cookies = hint_cookies
    else:
        anchor_cookies = {
            name: value
            for name, value in live_cookies.items()
            if isinstance(value, str) and len(value) >= 16
        }
    for name, value in anchor_cookies.items():
        anchor_pairs.append((name, str(value)))

    jwt_anchor = _bearer_anchor_term(headers, tokens)
    if jwt_anchor is not None:
        anchor_pairs.append(jwt_anchor)

    if not anchor_pairs:
        return None
    key_material = "\n".join(sorted(f"{name}={value}" for name, value in anchor_pairs))
    digest = hashlib.sha1(key_material.encode("utf-8")).hexdigest()[:10]
    return f"cap-{digest}"


def _bearer_anchor_term(
    headers: dict[str, str], tokens: dict[str, str]
) -> tuple[str, str] | None:
    """Return a ``(name, value)`` anchor pair from a bearer/JWT, or ``None``.

    Prefers a decoded JWT claim (stable across refresh); falls back to the raw
    bearer string. The pair name is namespaced (``jwt:<claim>`` / ``bearer``) so
    it can never collide with a cookie named ``sub``.
    """
    bearer = _extract_bearer(headers, tokens)
    if not bearer:
        return None
    claim = _jwt_payload_claim(bearer)
    if claim is not None:
        claim_name, claim_value = claim
        return (f"jwt:{claim_name}", str(claim_value))
    return ("bearer", bearer)


def _extract_bearer(headers: dict[str, str], tokens: dict[str, str]) -> str | None:
    """Pull a bearer credential from an Authorization header or the token bag."""
    for name, value in (headers or {}).items():
        if str(name).lower() == "authorization" and isinstance(value, str):
            stripped = value.strip()
            if stripped.lower().startswith("bearer "):
                return stripped[7:].strip()
    lowered = {str(k).lower(): v for k, v in (tokens or {}).items()}
    for key in _BEARER_TOKEN_KEYS:
        value = lowered.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        stripped = value.strip()
        if stripped.lower() in _NON_BEARER_VALUES:
            continue
        if stripped.lower().startswith("bearer "):
            stripped = stripped[7:].strip()
        return stripped or None
    return None


def _jwt_payload_claim(bearer: str) -> tuple[str, Any] | None:
    """Decode a JWT payload (middle segment, no signature check) and return the
    first present anchor claim as ``(name, value)``, or ``None``.

    Stdlib base64 + json only; tolerates missing base64url padding. A malformed
    or non-JWT bearer yields ``None`` (caller falls back to the raw bearer).
    """
    parts = bearer.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    try:
        padded = payload + "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        claims = json.loads(decoded.decode("utf-8"))
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(claims, dict):
        return None
    for name in _JWT_ANCHOR_CLAIMS:
        value = claims.get(name)
        if value not in (None, ""):
            return (name, value)
    return None


def capture_material(
    engagement_id: int,
    identity_name: str | None,
    *,
    host: str,
    cookies: dict[str, str],
    headers: dict[str, str],
    tokens: dict[str, str],
    scope_host: str,
) -> dict[str, Any]:
    """Merge a proxy-captured delta into a DERIVED identity and persist it.

    The identity is derived server-side by :func:`derive_capture_identity` from
    the capture's session-anchor material; any caller-supplied ``identity_name``
    is IGNORED (the addon posts a placeholder). This is what makes the store
    append-only + multi-identity: the same login refreshes one row, a distinct
    login appends. A capture with no anchor material (anonymous / pre-login /
    pure-logout) creates and refreshes NOTHING and returns ``{}``.

    Replicates the merge the mitmproxy addon used to do against auth.json:
    cookies are accumulated into per-host buckets, and the flat ``cookies`` view
    is recomputed as a UNION across every captured (in-scope) host bucket so
    flat-view consumers (e.g. ``vigil auth status``) never undercount a
    multi-host session. ``scope_host`` here is the host that was ACTUALLY
    captured (the addon passes the captured host, not a "primary" scope pattern);
    it only breaks cookie-name collisions in the flat view — the freshest
    captured host wins. ``host_cookies`` remains the authoritative per-host
    source of truth. Any extracted bearer/Authorization headers + tokens are
    merged in. Marks the identity proxy_capture / available / authenticated.
    """
    derived = derive_capture_identity(cookies or {}, headers or {}, tokens or {})
    if derived is None:
        # No session-anchor material — anonymous/pre-login/pure-logout traffic.
        # Never mint a spurious row and never evict an existing session.
        return {}
    identity_name = derived
    existing = db.get_credential(engagement_id, identity_name) or {}
    host_cookies: list[dict[str, Any]] = list(existing.get("host_cookies") or [])
    index = {
        str(b.get("host", "")).lower(): i
        for i, b in enumerate(host_cookies)
        if isinstance(b, dict) and b.get("host")
    }
    host_l = (host or "").lower()
    if cookies:
        # Strip deletion cookies before merging — never let a logout
        # Set-Cookie (value == "deleted", empty) overwrite or evict a stored
        # live session cookie.  The primary filter is in the proxy_addon
        # (full Set-Cookie directive available); this is defense-in-depth
        # at the persist layer in case any caller sends a deletion delta.
        live_cookies = {
            k: _dequote_cookie_value(v)
            for k, v in cookies.items()
            if not _is_deletion_cookie_value(v)
        }
        if live_cookies:
            if host_l in index:
                merged = dict(host_cookies[index[host_l]].get("cookies") or {})
                merged.update(live_cookies)
                host_cookies[index[host_l]]["cookies"] = merged
            else:
                host_cookies.append({"host": host_l, "cookies": dict(live_cookies)})

    merged_headers = _as_dict(existing.get("headers"))
    merged_headers.update(headers or {})
    merged_tokens = _as_dict(existing.get("tokens"))
    merged_tokens.update(tokens or {})

    flat_cookies = _flat_cookies_for_scope(host_cookies, scope_host)

    return db.upsert_credential(
        engagement_id,
        identity_name,
        mode="proxy_capture",
        state="available" if flat_cookies or merged_headers else "missing",
        use_for_requests=True,
        auth_context=str(existing.get("auth_context") or "authenticated")
        if existing.get("auth_context") not in (None, "", "anonymous")
        else "authenticated",
        cookies=flat_cookies,
        headers=merged_headers,
        tokens=merged_tokens,
        host_cookies=host_cookies,
        # Carry the existing raw_json extras forward — a capture only changes the
        # cookie/header/token deltas, so unmodeled custom fields (custom token /
        # session shapes) must survive. A bare `raw={}` here silently dropped them
        # on every proxy refresh. `existing` is the merged material (raw_json base +
        # typed overlay), so the non-modeled keys ARE the preserved extras.
        raw={k: v for k, v in existing.items() if k not in _MODELED_KEYS},
        notes=str(existing.get("notes") or ""),
        expires_at=existing.get("expires_at"),
        make_active=db.get_active_credential(engagement_id) is None,
    )


def set_active(engagement_id: int, identity_name: str) -> bool:
    return db.set_active_identity(engagement_id, identity_name)


def clear(engagement_id: int, identity_name: str | None) -> None:
    if identity_name is None:
        db.delete_all_credentials(engagement_id)
    else:
        db.delete_credential(engagement_id, identity_name)


def _flat_cookies_for_scope(
    host_cookies: list[dict[str, Any]], scope_host: str
) -> dict[str, str]:
    """Flatten host-cookie buckets into the legacy single-host ``cookies`` view.

    UNION across EVERY captured host bucket (all buckets are in-scope — the proxy
    never captures an out-of-scope host) so a multi-host session is never
    undercounted by flat-view consumers. On a cookie-name collision the bucket
    matching ``scope_host`` (the just-captured host, or its subdomains) wins so
    the freshest capture is reflected; ``host_cookies`` stays the authoritative
    per-host source of truth for consumers that need host-correct values.

    INVARIANT: this flat union is for DISPLAY / aggregate consumers only (e.g.
    ``vigil auth status``). Per-host REPLAY must NOT inject this union — it would
    bleed one host's uniquely-named cookies into another host's request. Replay
    reads ``host_cookies`` per request host (kali ``_identity_header_pairs`` uses
    the matching bucket ALONE, falling back to the flat view only when the host
    has no bucket). Do not route this union into a per-host request path.
    """
    scope = (scope_host or "").lower().lstrip("*.")
    flat: dict[str, str] = {}
    scoped: dict[str, str] = {}
    for bucket in host_cookies:
        if not isinstance(bucket, dict):
            continue
        entry = bucket.get("cookies")
        if not isinstance(entry, dict):
            continue
        pairs = {str(k): str(v) for k, v in entry.items()}
        flat.update(pairs)
        bhost = str(bucket.get("host", "")).lower()
        if scope and (bhost == scope or bhost.endswith("." + scope)):
            scoped.update(pairs)
    # Captured-host buckets win name collisions.
    flat.update(scoped)
    return flat


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _dequote_cookie_value(value: Any) -> Any:
    """Strip a single pair of surrounding DQUOTEs from a cookie value.

    RFC 6265 permits a quoted cookie-value (``name="value"``). A quoted-empty
    logout cookie (``MRHSession=""``) must be recognized as a deletion, and a
    live quoted value must be STORED unquoted so a later injection doesn't
    double-quote it. Non-strings and unbalanced quotes pass through untouched.
    """
    if not isinstance(value, str):
        return value
    v = value.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def _is_deletion_cookie_value(value: Any) -> bool:
    """Return True if a cookie value is a deletion sentinel.

    Complements the full Set-Cookie parsing in proxy_addon._is_deletion_set_cookie
    as a last-resort filter at the persist layer: any caller that sends a cookie
    with value ``deleted`` (case-insensitive), empty, or quoted-empty (``""``) is
    treated as a no-op for that key rather than overwriting a stored live session
    value.
    """
    if not isinstance(value, str):
        return False
    v = _dequote_cookie_value(value)
    if not isinstance(v, str):
        return False
    v = v.strip()
    return not v or v.lower() == "deleted"
