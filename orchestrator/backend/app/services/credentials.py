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

from typing import Any

from .. import db

DEFAULT_IDENTITY = "default"

# Fields stored in typed columns or used as control flags — everything else in
# an upsert payload is preserved verbatim in raw_json.
_MODELED_KEYS = frozenset(
    {
        "identity_name", "mode", "state", "use_for_requests", "auth_context",
        "is_active", "cookies", "headers", "tokens", "host_cookies", "notes",
        "expires_at", "updated_at", "make_active",
    }
)


def load_identities(engagement_id: int) -> dict[str, Any]:
    """Return ``{"identities": {name: material}, "active_identity": name}``.

    Mirrors the shape the legacy ``identity.load_identities`` produced from
    auth.json, so runtime consumers are storage-agnostic.
    """
    rows = db.list_credentials(engagement_id)
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
    loaded = load_identities(engagement_id)
    identities: dict[str, dict[str, Any]] = loaded["identities"]
    if requested is None:
        if not identities:
            return (None, {})
        active = loaded["active_identity"]
        return (active, identities.get(active, {}))
    requested = requested.strip()
    return (requested, identities.get(requested, {}))


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


def capture_material(
    engagement_id: int,
    identity_name: str,
    *,
    host: str,
    cookies: dict[str, str],
    headers: dict[str, str],
    tokens: dict[str, str],
    scope_host: str,
) -> dict[str, Any]:
    """Merge a proxy-captured delta into an identity and persist it.

    Replicates the merge the mitmproxy addon used to do against auth.json:
    cookies are accumulated into per-host buckets, the flat ``cookies`` view is
    recomputed from buckets matching the engagement's primary scope host (or its
    subdomains), and any extracted bearer/Authorization headers + tokens are
    merged in. Marks the identity proxy_capture / available / authenticated.
    """
    existing = db.get_credential(engagement_id, identity_name) or {}
    host_cookies: list[dict[str, Any]] = list(existing.get("host_cookies") or [])
    index = {
        str(b.get("host", "")).lower(): i
        for i, b in enumerate(host_cookies)
        if isinstance(b, dict) and b.get("host")
    }
    host_l = (host or "").lower()
    if cookies:
        if host_l in index:
            merged = dict(host_cookies[index[host_l]].get("cookies") or {})
            merged.update(cookies)
            host_cookies[index[host_l]]["cookies"] = merged
        else:
            host_cookies.append({"host": host_l, "cookies": dict(cookies)})

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
        make_active=not db.list_credentials(engagement_id),
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
    """Flatten per-host cookie buckets matching the primary scope host/subdomains."""
    scope = (scope_host or "").lower().lstrip("*.")
    flat: dict[str, str] = {}
    for bucket in host_cookies:
        if not isinstance(bucket, dict):
            continue
        bhost = str(bucket.get("host", "")).lower()
        if not scope or bhost == scope or bhost.endswith("." + scope):
            entry = bucket.get("cookies")
            if isinstance(entry, dict):
                flat.update({str(k): str(v) for k, v in entry.items()})
    return flat


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}
