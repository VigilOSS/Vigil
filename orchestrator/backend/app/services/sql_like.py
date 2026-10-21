"""SQL ``LIKE`` patterns that match operator text literally.

Each pattern escapes ``%``, ``_`` and ``\\`` with a backslash, so callers pair it
with ``LIKE ? ESCAPE '\\'``.
"""
from __future__ import annotations


def escape_like(value: str) -> str:
    """``value`` with its ``LIKE`` metacharacters escaped."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def like_contains(value: str) -> str:
    """A pattern matching text that contains ``value``."""
    return f"%{escape_like(value)}%"


def like_prefix(value: str) -> str:
    """A pattern matching text that starts with ``value``."""
    return f"{escape_like(value)}%"
