"""Shared helpers for the dispatch package (CLI arg parsing, time, JSON).

Small pure utilities used by both the work-buffer (``work_items``) and the
backend lifecycle (``agent``) submodules. Kept here so neither submodule has
to import the other just to reach a CSV splitter or an ISO timestamp.
"""
from __future__ import annotations

import datetime as _dt
import json
import sys
from typing import Any


def _utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [token.strip() for token in value.split(",") if token.strip()]


def _load_json_arg(value: str | None) -> Any:
    """Read a `--*-json` flag that may be inline JSON or a path to a JSON file."""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if text.startswith("@") or text.startswith("/") or text.endswith(".json"):
        candidate = text[1:] if text.startswith("@") else text
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            # Fall through and try parsing as inline JSON.
            pass
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: failed to read JSON from {candidate}: {exc}", file=sys.stderr)
            sys.exit(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON: {exc}", file=sys.stderr)
        sys.exit(1)


def _safe_int_arg(value: str, name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        print(f"ERROR: {name} must be an integer (got '{value}')", file=sys.stderr)
        sys.exit(1)


def _validate_id_list(id_list) -> list[int]:
    """Parse and validate IDs given as a comma-separated string OR a list of tokens.

    Accepts either ``"1,2,3"``, ``["1", "2", "3"]``, or mixed forms like
    ``["1,2", "3"]``. Pure-comma strings (``","``) and empty inputs raise so a
    typo doesn't silently turn into a no-op UPDATE.
    """
    if isinstance(id_list, (list, tuple)):
        tokens: list[str] = []
        for entry in id_list:
            tokens.extend(str(entry).split(","))
    else:
        tokens = str(id_list).split(",")
    cleaned = [token.strip() for token in tokens if token.strip()]
    if not cleaned:
        print(
            "ERROR: id_list must contain at least one numeric ID (got empty/comma-only input)",
            file=sys.stderr,
        )
        sys.exit(1)
    ids: list[int] = []
    for token in cleaned:
        if not token.isdigit():
            print(
                f"ERROR: id_list must contain only numeric IDs (got '{token}')",
                file=sys.stderr,
            )
            sys.exit(1)
        ids.append(int(token))
    return ids
