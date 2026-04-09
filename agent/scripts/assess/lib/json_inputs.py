"""Helpers for CLI JSON payload arguments."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse_json_argument(
    raw_value: str,
    *,
    inline: bool = False,
    description: str = "JSON payload",
) -> tuple[Any, str]:
    """Parse a CLI JSON argument from a file path or inline JSON text."""
    candidate = Path(raw_value)
    source = raw_value
    raw_text = ""

    if not inline and candidate.is_file():
        raw_text = candidate.read_text(encoding="utf-8")
    else:
        looks_like_json = raw_value.lstrip().startswith(("{", "["))
        if not inline and not looks_like_json:
            raise ValueError(
                f"{description} file not found: {raw_value}. "
                "Pass --inline to treat the argument as raw JSON."
            )
        raw_text = raw_value
        source = "<inline>"

    try:
        return json.loads(raw_text), source
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid {description.lower()} in {source}: "
            f"{exc.msg} at line {exc.lineno} column {exc.colno}"
        ) from exc


def parse_optional_inline_json(
    raw_value: str | None,
    *,
    default: Any,
    description: str,
) -> Any:
    """Parse an optional inline JSON fragment or return a caller-provided default."""
    if raw_value in (None, ""):
        return default
    value, _ = parse_json_argument(raw_value, inline=True, description=description)
    return value
