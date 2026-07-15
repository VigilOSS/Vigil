"""Client for the centralized engagement credential store (replaces auth.json).

Runtime consumers — kali identity injection, the auth runtime snapshot, and
``vigil assess auth-status`` — read credentials through the orchestrator backend
instead of a per-engagement ``auth.json`` file. The ``vigil auth`` CLI uses the
write helpers.

Design (per the centralization decision):
  * Backend is the single source of truth. There is no on-disk credential file.
  * READS fail closed: if the backend is unreachable the runtime degrades to
    anonymous (empty identities) with a single stderr warning, mirroring the
    legacy "missing auth.json => anonymous" behavior. The runtime already
    depends on the backend for probe/command recording, so this adds no new
    hard dependency.
  * A per-process in-memory cache avoids a backend round-trip on every tool
    exec. Write helpers invalidate it.
  * WRITES surface errors (the operator/CLI should see a failed import).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, quote

from .client import AssessError, AssessmentClient
from .config import resolve_base_url

DEFAULT_IDENTITY = "default"
_RESOLVE_CACHE_TTL_SECONDS = 1.0

# Per-process cache of load_identities() results, keyed by engagement key.
_cache: dict[str, dict[str, Any]] = {}
_resolve_cache: dict[
    tuple[str, str | None, str],
    tuple[float, tuple[str | None, dict[str, Any]]],
] = {}
_warned: set[str] = set()


def invalidate_cache(engagement_dir: str | Path | None = None) -> None:
    if engagement_dir is None:
        _cache.clear()
        _resolve_cache.clear()
    else:
        key = _key_for(engagement_dir)
        _cache.pop(key, None)
        for cache_key in [item for item in _resolve_cache if item[0] == key]:
            _resolve_cache.pop(cache_key, None)


def _key_for(engagement_dir: str | Path) -> str:
    return Path(engagement_dir).name


def _client(engagement_dir: str | Path) -> AssessmentClient:
    eng_dir = str(Path(engagement_dir))
    agent_root = str(Path(eng_dir).parent.parent)
    base_url = resolve_base_url(eng_dir, agent_root)
    return AssessmentClient(base_url, Path(eng_dir).name)


def _warn_once(key: str, message: str) -> None:
    if key in _warned:
        return
    _warned.add(key)
    print(f"creds_client: {message}", file=sys.stderr)


def _empty_identities() -> dict[str, Any]:
    return {"identities": {}, "active_identity": DEFAULT_IDENTITY}


def _resolve_from_loaded(
    loaded: dict[str, Any], requested: str | None
) -> tuple[str | None, dict[str, Any]]:
    identities = loaded.get("identities")
    if not isinstance(identities, dict):
        identities = {}
    if requested is None:
        if not identities:
            return (None, {})
        active = str(loaded.get("active_identity") or DEFAULT_IDENTITY)
        material = identities.get(active)
        return (active, material if isinstance(material, dict) else {})
    material = identities.get(requested)
    return (requested, material if isinstance(material, dict) else {})


def load_identities(
    engagement_dir: str | Path, *, use_cache: bool = True
) -> dict[str, Any]:
    """Return ``{"identities": {name: material}, "active_identity": name}``.

    Fail-closed: an unreachable backend (or an engagement the backend does not
    know yet) yields an empty identities map, so callers degrade to anonymous.
    """
    key = _key_for(engagement_dir)
    if use_cache and key in _cache:
        return _cache[key]
    try:
        data = _client(engagement_dir).get_engagement("credentials")
    except (AssessError, OSError) as exc:
        _warn_once(
            key, f"backend unreachable for {key} — treating as anonymous ({exc})"
        )
        data = _empty_identities()
        cacheable = False
    else:
        cacheable = True
    if not isinstance(data, dict) or not isinstance(data.get("identities"), dict):
        data = _empty_identities()
    if not data["identities"]:
        # Credentials are backend-owned now; there is no auto-import of a
        # pre-existing on-disk auth.json. Surface the gap loudly instead of
        # silently running anonymous, so an engagement upgraded with a populated
        # auth.json is recovered via `vigil auth import` rather than losing its
        # identities. Auto-migration is intentionally left as a maintainer choice.
        try:
            legacy = Path(engagement_dir) / "auth.json"
            if legacy.is_file() and legacy.stat().st_size > 2:
                _warn_once(
                    f"{key}:legacy-auth",
                    f"{key} has no backend credentials but a legacy auth.json is "
                    f"present ({legacy}) — it is NOT auto-imported; run "
                    f"`vigil auth import {legacy}` to restore those identities, "
                    f"otherwise this engagement runs anonymous.",
                )
        except OSError:
            pass
    if cacheable:
        _cache[key] = data
    return data


def resolve_identity(
    engagement_dir: str | Path, requested: str | None, *, scope_key: str = ""
) -> tuple[str | None, dict[str, Any]]:
    """Resolve a ``--identity`` request without loading every stored identity."""
    requested = requested.strip() if requested is not None else None
    key = _key_for(engagement_dir)
    cache_key = (key, requested, scope_key)
    now = time.monotonic()
    cached = _resolve_cache.get(cache_key)
    if cached is not None and cached[0] > now:
        return cached[1]
    _resolve_cache.pop(cache_key, None)
    try:
        query_args = {"scope": scope_key} if scope_key else {}
        if requested:
            query_args["identity"] = requested
        query = urlencode(query_args, quote_via=quote)
        data = _client(engagement_dir).get_engagement("credentials/resolve", query=query)
    except (AssessError, OSError) as exc:
        loaded = _cache.get(key)
        if loaded is not None:
            return _resolve_from_loaded(loaded, requested)
        _warn_once(
            key, f"backend unreachable for {key} — treating as anonymous ({exc})"
        )
        result = (None if requested is None else requested, {})
        return result

    if not isinstance(data, dict):
        result = (None if requested is None else requested, {})
    else:
        identity_name = data.get("identity_name")
        material = data.get("material")
        result = (
            str(identity_name) if identity_name is not None else None,
            material if isinstance(material, dict) else {},
        )
    _resolve_cache[cache_key] = (time.monotonic() + _RESOLVE_CACHE_TTL_SECONDS, result)
    return result


def identity_names(engagement_dir: str | Path) -> list[str]:
    return list(load_identities(engagement_dir)["identities"].keys())


def active_material(engagement_dir: str | Path) -> dict[str, Any]:
    """Material for the active identity (``{}`` when none)."""
    return resolve_identity(engagement_dir, None)[1]


# -- write helpers (CLI) — surface errors -----------------------------------


def put_identity(
    engagement_dir: str | Path,
    identity_name: str,
    material: dict[str, Any],
    *,
    make_active: bool = False,
) -> dict[str, Any]:
    payload = dict(material)
    payload["make_active"] = make_active
    result = _client(engagement_dir).put_engagement(
        f"credentials/{identity_name}", payload
    )
    invalidate_cache(engagement_dir)
    return result


def persist_liveness(
    engagement_dir: str | Path,
    identity_name: str,
    verdict: str,
    probed_at: str | None = None,
    *,
    scope_key: str = "",
    ttl_seconds: int = 900,
    source: str = "auth-status",
    reason: str = "",
) -> dict[str, Any]:
    """Persist an LLM-owned per-session liveness verdict (WS4).

    POSTs to ``/credentials/{identity}/liveness`` so the backend reconciles the
    session's ``state`` (dead->dead, live->available clearing a stale flag,
    unknown->state untouched). Invalidates the per-process cache so a subsequent
    read reflects the new verdict. Returns the updated material.
    """
    payload = {
        "verdict": verdict,
        "probed_at": probed_at,
        "scope_key": scope_key,
        "ttl_seconds": ttl_seconds,
        "source": source,
        "reason": reason,
    }
    result = _client(engagement_dir).post_engagement(
        f"credentials/{quote(str(identity_name), safe='')}/liveness", payload
    )
    invalidate_cache(engagement_dir)
    return result


def set_active(engagement_dir: str | Path, identity_name: str) -> dict[str, Any]:
    result = _client(engagement_dir).post_engagement(
        f"credentials/{identity_name}/activate", {}
    )
    invalidate_cache(engagement_dir)
    return result


def clear(engagement_dir: str | Path, identity_name: str | None = None) -> None:
    client = _client(engagement_dir)
    if identity_name is None:
        client.delete_engagement("credentials")
    else:
        client.delete_engagement(f"credentials/{identity_name}")
    invalidate_cache(engagement_dir)
