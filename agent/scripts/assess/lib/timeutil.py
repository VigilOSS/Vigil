"""UTC timestamp helpers — replaces lib/time.sh."""
from __future__ import annotations

from datetime import datetime, timezone


def now_utc() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def today_local() -> str:
    """Return today's date in local timezone as YYYY-MM-DD."""
    return datetime.now().strftime("%Y-%m-%d")


def header_date_from_utc(iso_utc: str) -> str:
    """Convert a UTC ISO timestamp to a local YYYY-MM-DD date string."""
    dt = datetime.strptime(iso_utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime("%Y-%m-%d")
