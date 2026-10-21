"""UTC timestamp parsing shared by the audit-log and event readers.

Stored rows mix SQLite ``YYYY-MM-DD HH:MM:SS`` (zone-less, UTC) with
ISO-8601 spellings, so neither text order nor raw values are safe to show.
"""
from __future__ import annotations

from datetime import datetime, timezone


def parse_utc(raw: str) -> datetime | None:
    """Parse either stored spelling as an aware UTC instant, or ``None``."""
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso_z(parsed: datetime) -> str:
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def iso_utc(value: str | None) -> str:
    """Render a stored timestamp as ISO-8601 UTC with a ``Z`` suffix.

    An unparseable value is returned verbatim rather than guessed at.
    """
    raw = str(value or "").strip()
    parsed = parse_utc(raw) if raw else None
    return iso_z(parsed) if parsed is not None else raw
