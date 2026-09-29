"""Read durable scope tracks, including existing engagement formats."""

from __future__ import annotations

from typing import Any


def track_phases(scope: dict[str, Any]) -> dict[str, str]:
    tracks = scope.get("tracks")
    if isinstance(tracks, dict):
        return {
            name: state["phase"].strip()
            for name, state in tracks.items()
            if name in {"web", "code", "blue", "android", "remediation"}
            and isinstance(state, dict)
            and isinstance(state.get("phase"), str)
            and state["phase"].strip()
        }
    kind = str(scope.get("engagement_type") or "web").strip().lower()
    if kind == "offensive":
        return {}
    phase = str(scope.get("current_phase") or "unknown")
    if kind == "both":
        result = {"web": phase}
        code_phase = scope.get("code_phase")
        if isinstance(code_phase, str) and code_phase.strip():
            result["code"] = code_phase.strip()
        else:
            result["code"] = "repair-required"
        return result
    return {kind if kind in {"web", "code", "blue", "android", "remediation"} else "web": phase}
