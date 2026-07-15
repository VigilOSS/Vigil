"""Named identities — sourced from the centralized credential store.

Access-control depth (IDOR/BOLA/BFLA) is only REAL when measured across NAMED
identities — a cross-tenant pass needs ≥2 users. Identities now live in the
orchestrator backend credential store (one row per ``(engagement, identity)``)
instead of a per-engagement ``auth.json`` file; this module is a thin adapter
over :mod:`creds_client` that preserves the long-standing
``{"identities": {name: material}, "active_identity": name}`` surface every
consumer expects.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import creds_client

DEFAULT_IDENTITY = creds_client.DEFAULT_IDENTITY


def normalize_identities(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize a raw identities payload to ``{"identities": {...}, "active_identity": str}``.

    Retained as a pure helper for callers that already hold a payload (e.g. a
    backend response). Tolerates both the ``identities`` map shape and a legacy
    flat single-identity dict (wrapped as ``default``).
    """
    if isinstance(data.get("identities"), dict):
        identities: dict[str, dict[str, Any]] = {
            str(name): material
            for name, material in data["identities"].items()
            if isinstance(material, dict)
        }
        active = str(data.get("active_identity") or "").strip()
        if active not in identities:
            active = next(iter(identities), DEFAULT_IDENTITY)
        return {"identities": identities, "active_identity": active}
    if not data:
        return {"identities": {}, "active_identity": DEFAULT_IDENTITY}
    return {"identities": {DEFAULT_IDENTITY: data}, "active_identity": DEFAULT_IDENTITY}


def load_identities(engagement_dir: str | Path) -> dict[str, Any]:
    """Return ``{"identities": {name: material}, "active_identity": name}`` from
    the credential store (empty when none / backend unreachable)."""
    return creds_client.load_identities(engagement_dir)


def identity_names(engagement_dir: str | Path) -> list[str]:
    """List the named identities declared for the engagement (may be empty)."""
    return creds_client.identity_names(engagement_dir)


def host_cookies_for(material: dict[str, Any], host: str) -> dict[str, str]:
    """Return the cookies captured for ``host`` from an identity's per-host jar.

    The store keeps captured cookies in per-host buckets
    (``host_cookies = [{"host": ..., "cookies": {...}}, ...]``). A browser sends a
    cookie set on ``example.com`` to ``app.example.com`` too, so a bucket matches
    when its host equals ``host`` OR ``host`` is a subdomain of it; the exact-host
    bucket overlays a parent-domain bucket on key collisions (most-specific wins),
    mirroring how a browser layers cookies. Returns ``{}`` when nothing matches or
    no buckets exist — the caller then falls back to the flat ``cookies`` view.

    This is the read side of the host-cookie jar (I-22): a cookie-session app on a
    host other than the capture-time primary scope host would otherwise be sent
    the flat (mismatched/empty) cookie view and read the request as "session
    stale" — a fail-closed false negative.
    """
    raw = material.get("host_cookies")
    target = (host or "").strip().rstrip(".").lower()
    if not isinstance(raw, list) or not target:
        return {}
    # (specificity, cookies) — exact host = 2, parent domain = 1. Applied in
    # ascending specificity so the exact-host bucket wins on key collisions.
    matched: list[tuple[int, dict[str, str]]] = []
    for bucket in raw:
        if not isinstance(bucket, dict):
            continue
        bhost = str(bucket.get("host", "")).strip().rstrip(".").lower()
        cookies = bucket.get("cookies")
        if not bhost or not isinstance(cookies, dict):
            continue
        if target == bhost:
            specificity = 2
        elif target.endswith("." + bhost):
            specificity = 1
        else:
            continue
        matched.append((specificity, {str(k): str(v) for k, v in cookies.items()}))
    out: dict[str, str] = {}
    for _specificity, cookies in sorted(matched, key=lambda m: m[0]):
        out.update(cookies)
    return out


def host_cookie_hosts(material: dict[str, Any]) -> list[str]:
    """Host labels for which the identity carries a non-empty captured cookie
    bucket. Used to WARN when a run's request host matches none of them."""
    raw = material.get("host_cookies")
    if not isinstance(raw, list):
        return []
    hosts: list[str] = []
    for bucket in raw:
        if not isinstance(bucket, dict):
            continue
        bhost = str(bucket.get("host", "")).strip().rstrip(".").lower()
        cookies = bucket.get("cookies")
        if bhost and isinstance(cookies, dict) and cookies:
            hosts.append(bhost)
    return hosts


def resolve_identity(
    engagement_dir: str | Path, requested: str | None, *, scope_key: str = ""
) -> tuple[str | None, dict[str, Any]]:
    """Resolve a ``--identity`` request against the engagement's credentials.

    Semantics are unchanged from the legacy auth.json loader:
      * ``requested`` is None  -> the ACTIVE identity, or ``(None, {})`` when no
        identities are declared (caller keeps legacy auth_context behavior).
      * known identity -> that identity's material.
      * UNKNOWN identity -> ``(requested, {})`` so the caller can warn while the
        requested name is still recorded as the probe's auth_context.
    """
    if scope_key:
        return creds_client.resolve_identity(
            engagement_dir, requested, scope_key=scope_key
        )
    return creds_client.resolve_identity(engagement_dir, requested)
