"""Structural reader for the finding-owned outgoing reply thread."""

from __future__ import annotations

from assess.lib.client import AssessError
from assess.lib.finding_render import details_object


def reply_versions(finding: dict, *, operation: str) -> list[dict]:
    raw = details_object(finding).get("replies")
    if raw is None:
        return []
    slug = str(finding.get("slug") or "")
    if not isinstance(raw, list):
        raise AssessError(
            f"{operation}: finding {slug!r} has corrupt details.replies: expected an array"
        )
    rows: list[dict] = []
    seen: set[int] = set()
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise AssessError(
                f"{operation}: finding {slug!r} has corrupt details.replies[{index}]: "
                "expected an object"
            )
        seq = entry.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            raise AssessError(
                f"{operation}: finding {slug!r} has corrupt details.replies[{index}]: "
                "reply seq must be a positive integer"
            )
        if seq in seen:
            raise AssessError(
                f"{operation}: finding {slug!r} has corrupt details.replies: "
                f"duplicate reply seq {seq}"
            )
        seen.add(seq)
        rows.append(entry)
    return rows


def reply_seq(entry: dict) -> int:
    """Return the sequence after ``reply_versions`` has validated the thread."""

    return int(entry["seq"])
