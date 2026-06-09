"""Named identities in ``auth.json`` (depth-gate Wave 4 / identity).

Access-control depth (IDOR/BOLA/BFLA) is only REAL when measured across
NAMED identities — a cross-tenant pass needs ≥2 users. The legacy
single-identity ``auth.json`` could only ever say "an authenticated pass
happened", never "a cross-identity pass happened". This module is the
tolerant loader that returns the engagement's named identities and the
active one from either the new multi-identity shape OR a legacy flat file.

New shape::

    {
      "identities": {
        "user_a": { ...auth material... },
        "user_b": { ... },
        "admin":  { ... }
      },
      "active_identity": "user_a"
    }

Legacy (flat) shape — the whole file IS one identity's auth material::

    { "mode": "auth_json", "cookies": {...}, "headers": {...}, ... }

BACKWARD-COMPAT (this is engagement STATE, the DB-style compat exception
applies — depth-gate Wave 4 / master plan §4): a legacy flat ``auth.json``
MUST still parse. It is normalized at load time to::

    {"identities": {"default": <old contents>}, "active_identity": "default"}

so every downstream consumer sees the same named-identity surface
regardless of on-disk shape.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_IDENTITY = "default"


def _auth_json_path(engagement_dir: str | Path) -> Path:
    return Path(engagement_dir) / "auth.json"


def _read_auth_raw(engagement_dir: str | Path) -> dict[str, Any]:
    """Load auth.json as a dict, tolerant of a missing/invalid/non-dict file.

    Returns ``{}`` on any failure — callers treat that as "no identities".
    """
    path = _auth_json_path(engagement_dir)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _is_multi_identity_shape(data: dict[str, Any]) -> bool:
    """True when ``data`` uses the new ``identities`` map shape.

    The presence of a dict ``identities`` key is the discriminator; the new
    shape is opt-in and a legacy flat file never carries it.
    """
    return isinstance(data.get("identities"), dict)


def normalize_identities(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize either auth.json shape to ``{"identities": {...}, "active_identity": str}``.

    * New shape: validate the ``identities`` map (drop non-dict entries) and
      pick ``active_identity`` (falling back to the first declared identity,
      then ``DEFAULT_IDENTITY``).
    * Legacy flat shape: wrap the whole file as the single ``default`` identity
      (the DB-style state-compat exception, depth-gate Wave 4). An empty/absent
      file yields an empty identities map.
    """
    if _is_multi_identity_shape(data):
        raw_identities = data.get("identities") or {}
        identities: dict[str, dict[str, Any]] = {
            str(name): material
            for name, material in raw_identities.items()
            if isinstance(material, dict)
        }
        active = str(data.get("active_identity") or "").strip()
        if active not in identities:
            active = next(iter(identities), DEFAULT_IDENTITY)
        return {"identities": identities, "active_identity": active}

    if not data:
        return {"identities": {}, "active_identity": DEFAULT_IDENTITY}
    return {
        "identities": {DEFAULT_IDENTITY: data},
        "active_identity": DEFAULT_IDENTITY,
    }


def load_identities(engagement_dir: str | Path) -> dict[str, Any]:
    """Return ``{"identities": {name: material}, "active_identity": name}``.

    Tolerant of both the new multi-identity shape and a legacy single-identity
    flat file (which normalizes to a single ``default`` identity). A missing or
    invalid auth.json yields an empty identities map with ``active_identity``
    defaulting to ``DEFAULT_IDENTITY``.
    """
    return normalize_identities(_read_auth_raw(engagement_dir))


def identity_names(engagement_dir: str | Path) -> list[str]:
    """List the named identities declared for the engagement (may be empty)."""
    return list(load_identities(engagement_dir)["identities"].keys())


def resolve_identity(
    engagement_dir: str | Path, requested: str | None
) -> tuple[str | None, dict[str, Any]]:
    """Resolve a ``--identity`` request against the engagement's auth.json.

    Returns ``(name, material)`` where:
      * ``requested`` is None  -> the ACTIVE identity (or ``(None, {})`` when no
        identities are declared — the caller then keeps legacy auth_context
        behavior).
      * ``requested`` names a known identity -> that identity.
      * ``requested`` names an UNKNOWN identity -> ``(requested, {})`` so the
        caller can warn; the request still stamps the requested name (the
        operator's intent is recorded) but no auth material is selected.
    """
    loaded = load_identities(engagement_dir)
    identities: dict[str, dict[str, Any]] = loaded["identities"]
    if requested is None:
        active = loaded["active_identity"]
        if not identities:
            return (None, {})
        return (active, identities.get(active, {}))
    requested = requested.strip()
    return (requested, identities.get(requested, {}))
