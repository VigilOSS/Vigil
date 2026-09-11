"""Non-blocking cross-lane activity context for target-facing executions."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode


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
    """
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
        print(
            f"target concurrency advisory unavailable: {exc}; proceeding without "
            "a reservation or rate-enforcement claim",
            file=sys.stderr,
        )
        return

    if not foreign_count:
        print(
            "target concurrency advisory: no foreign-lane target-facing commands "
            "recorded (all history); advisory only; no reservation or rate enforcement",
            file=sys.stderr,
        )
        return
    if latest is None:
        latest_text = "latest time unavailable"
    else:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        latest_text = f"latest {max(0, int((current - latest).total_seconds()))}s ago"
    print(
        "target concurrency advisory: "
        f"{foreign_count} foreign-lane target-facing command(s) recorded (all history); "
        f"{latest_text}; advisory only; no reservation or rate enforcement",
        file=sys.stderr,
    )
