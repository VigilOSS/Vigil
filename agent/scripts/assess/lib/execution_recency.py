"""Non-blocking cross-lane activity context for target-facing executions."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any

_PAGE_SIZE = 1000
_MAX_PAGES = 1000


def _parse_time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_target_facing(row: dict[str, Any]) -> bool:
    notes = row.get("notes")
    if not isinstance(notes, str):
        return False
    try:
        policy = json.loads(notes)
    except json.JSONDecodeError:
        return False
    return isinstance(policy, dict) and policy.get("target_facing") is True


def emit_foreign_lane_recency(
    client,
    *,
    current_agent: str,
    now: datetime | None = None,
) -> None:
    """Print all-history foreign-lane timing without blocking an execution.

    There is deliberately no implicit rolling window, rate, cooldown, or
    throttle. The operator-authored dispatch budget remains the governing
    instruction; this readout is only coordination context.
    """
    try:
        foreign_count = 0
        latest: datetime | None = None
        offset = 0
        prior_page_signature: tuple[tuple[Any, Any, Any], ...] | None = None
        complete = True
        for _page_number in range(_MAX_PAGES):
            page = client.get(
                f"command-runs?offset={offset}&limit={_PAGE_SIZE}&sort=recent"
            )
            if not isinstance(page, list):
                raise ValueError("command-runs response is not a list")
            page_signature = tuple(
                (row.get("id"), row.get("agent_name"), row.get("started_at"))
                for row in page
                if isinstance(row, dict)
            )
            if page_signature and page_signature == prior_page_signature:
                complete = False
                break
            prior_page_signature = page_signature
            for row in page:
                if not isinstance(row, dict):
                    continue
                if not _is_target_facing(row):
                    continue
                if str(row.get("agent_name") or "") == str(current_agent or ""):
                    continue
                foreign_count += 1
                timestamp = _parse_time(row.get("started_at") or row.get("created_at"))
                if timestamp is not None and (latest is None or timestamp > latest):
                    latest = timestamp
            if len(page) < _PAGE_SIZE:
                break
            offset += len(page)
        else:
            complete = False
    except Exception as exc:  # noqa: BLE001 - coordination context never gates work
        print(
            f"target concurrency advisory unavailable: {exc}; proceeding without "
            "a reservation or rate-enforcement claim",
            file=sys.stderr,
        )
        return

    completeness = "all history" if complete else "bounded history sample; older rows not counted"
    if not foreign_count:
        print(
            "target concurrency advisory: no foreign-lane target-facing commands "
            f"recorded ({completeness}); advisory only; no reservation or rate enforcement",
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
        f"{foreign_count} foreign-lane target-facing command(s) recorded ({completeness}); "
        f"{latest_text}; advisory only; no reservation or rate enforcement",
        file=sys.stderr,
    )
