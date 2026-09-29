"""Canonical durable engagement track parsing.

``scope.json`` owns the enabled tracks and their independent phases.  The
legacy ``engagement_type`` / ``current_phase`` / ``code_phase`` shape remains
readable while existing engagements are migrated, but new consumers must not
need a synthetic ``both`` engagement type to discover the code track.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


_KNOWN_TRACKS = frozenset({"web", "code", "blue", "android", "remediation"})


def track_phases(scope: dict[str, Any]) -> dict[str, str]:
    """Return the enabled track-to-phase map, preferring canonical ``tracks``.

    Invalid entries are omitted rather than guessed.  A malformed new tracks
    object must not accidentally widen an engagement into a web track.
    """
    raw_tracks = scope.get("tracks")
    if isinstance(raw_tracks, dict):
        result: dict[str, str] = {}
        for track, state in raw_tracks.items():
            if track not in _KNOWN_TRACKS or not isinstance(state, dict):
                continue
            phase = state.get("phase")
            if isinstance(phase, str) and phase.strip():
                result[track] = phase.strip()
        return result

    engagement_type = str(scope.get("engagement_type") or "web").strip().lower()
    if engagement_type == "offensive":
        return {}
    current_phase = str(scope.get("current_phase") or "unknown")
    if engagement_type == "both":
        result = {"web": current_phase}
        code_phase = scope.get("code_phase")
        if isinstance(code_phase, str) and code_phase.strip():
            result["code"] = code_phase.strip()
        else:
            result["code"] = "repair-required"
        return result
    if engagement_type in _KNOWN_TRACKS:
        return {engagement_type: current_phase}
    # Legacy red and untyped engagements are web engagements.
    return {"web": current_phase}


def read_track_phases(engagement_root: Path) -> dict[str, str]:
    """Read an engagement's durable track state, returning no tracks on error."""
    try:
        payload = json.loads((engagement_root / "scope.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return track_phases(payload) if isinstance(payload, dict) else {}


def has_track(engagement_root: Path, track: str) -> bool:
    return track in read_track_phases(engagement_root)
