"""Canonical deterministic classifier for credential liveness probes."""
from __future__ import annotations

from typing import Any


def classify_liveness(
    status: int | None,
    haystack: str | None,
    liveness: dict[str, Any] | None,
) -> tuple[str, str]:
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
