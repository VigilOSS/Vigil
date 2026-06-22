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


def resolve_identity(
    engagement_dir: str | Path, requested: str | None
) -> tuple[str | None, dict[str, Any]]:
    """Resolve a ``--identity`` request against the engagement's credentials.

    Semantics are unchanged from the legacy auth.json loader:
      * ``requested`` is None  -> the ACTIVE identity, or ``(None, {})`` when no
        identities are declared (caller keeps legacy auth_context behavior).
      * known identity -> that identity's material.
      * UNKNOWN identity -> ``(requested, {})`` so the caller can warn while the
        requested name is still recorded as the probe's auth_context.
    """
    return creds_client.resolve_identity(engagement_dir, requested)
