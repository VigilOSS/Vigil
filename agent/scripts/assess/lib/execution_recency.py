"""Non-blocking cross-lane activity context for target-facing executions."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from .run_notices import emit_once, in_scope

_REPEAT_NOTE = "; not repeated for the rest of this run unless the reading changes"


def _parse_time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def emit_foreign_lane_recency(
    client,
    *,
    current_agent: str,
    now: datetime | None = None,
) -> None:
    """Print all-history foreign-lane timing without blocking an execution.

    There is deliberately no implicit rolling window, rate, cooldown, or
    throttle. The operator-authored dispatch budget remains the governing
    instruction; this readout is only coordination context. The backend owns
    the all-history aggregate so this pre-command advisory never replays
    command-run list pages.

    Inside a run scope (``run_notices.notice_scope``: a recon job and its
    stages) the line prints once per distinct reading — the foreign count and
    latest start time — so it repeats only when another lane's activity
    actually changed, and the first line says so.
    """
    note = _REPEAT_NOTE if in_scope() else ""
    try:
        payload = client.get(
            "command-runs/foreign-lane-recency?"
            + urlencode({"agent_name": str(current_agent or "")})
        )
        if not isinstance(payload, dict):
            raise ValueError("foreign-lane recency response is not an object")
        foreign_count = payload.get("foreign_count")
        if (
            not isinstance(foreign_count, int)
            or isinstance(foreign_count, bool)
            or foreign_count < 0
        ):
            raise ValueError("foreign-lane recency count is invalid")
        latest_raw = payload.get("latest_started_at")
        if latest_raw is not None and not isinstance(latest_raw, str):
            raise ValueError("foreign-lane recency timestamp is invalid")
        latest = _parse_time(latest_raw)
    except Exception as exc:  # noqa: BLE001 - coordination context never gates work
        emit_once(
            f"foreign-lane-recency-unavailable:{exc}",
            f"target concurrency advisory unavailable: {exc}; proceeding without "
            f"a reservation or rate-enforcement claim{note}",
        )
        return

    reading_key = f"foreign-lane-recency:{foreign_count}:{latest_raw}"
    if not foreign_count:
        emit_once(
            reading_key,
            "target concurrency advisory: no foreign-lane target-facing commands "
            f"recorded (all history); advisory only; no reservation or rate enforcement{note}",
        )
        return
    if latest is None:
        latest_text = "latest time unavailable"
    else:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        latest_text = f"latest {max(0, int((current - latest).total_seconds()))}s ago"
    emit_once(
        reading_key,
        "target concurrency advisory: "
        f"{foreign_count} foreign-lane target-facing command(s) recorded (all history); "
        f"{latest_text}; advisory only; no reservation or rate enforcement{note}",
    )
