"""Small shared primitives for structural index extractors."""
from __future__ import annotations

from typing import Any

def _snippet(line: str, limit: int = 120) -> str:
    s = line.strip()
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return s

def _empty_func(name: str, line_start: int, line_end: int) -> dict[str, Any]:
    return {
        "name": name,
        "qualified_name": name,
        "line_start": line_start,
        "line_end": line_end,
        "params": [],
        "modifiers": [],
        "annotations": [],
        "is_entry_point": False,
    }
