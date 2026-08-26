from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import NoReturn

from assess.lib.code_snapshot import MAX_JSON_ARTIFACT_BYTES, read_bounded_regular_file


LOWER_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class DuplicateJSONField(ValueError):
    pass


def fail(label: str, message: str) -> NoReturn:
    print(f"{label}: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_strict_object(
    source: str,
    *,
    label: str,
    required_fields: frozenset[str],
) -> dict[str, object]:
    if source == "-":
        stream = getattr(sys.stdin, "buffer", sys.stdin)
        raw = stream.read(MAX_JSON_ARTIFACT_BYTES + 1)
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        if len(raw) > MAX_JSON_ARTIFACT_BYTES:
            fail(label, f"input exceeds {MAX_JSON_ARTIFACT_BYTES} bytes")
    else:
        try:
            raw = read_bounded_regular_file(
                Path(source),
                max_bytes=MAX_JSON_ARTIFACT_BYTES,
                label=f"{label} input",
            )
        except (OSError, RuntimeError, ValueError) as exc:
            fail(label, f"could not read input file: {exc}")
    if not raw:
        fail(label, "input is empty")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(label, f"input is not UTF-8: {exc}")

    def reject_duplicate_fields(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        parsed: dict[str, object] = {}
        for key, value in pairs:
            if key in parsed:
                raise DuplicateJSONField(key)
            parsed[key] = value
        return parsed

    try:
        payload = json.loads(text, object_pairs_hook=reject_duplicate_fields)
    except DuplicateJSONField as exc:
        fail(label, f"duplicate JSON field: {exc}")
    except json.JSONDecodeError as exc:
        fail(label, f"input is not valid JSON: {exc}")
    if not isinstance(payload, dict):
        fail(label, "input must contain one JSON object")
    missing = required_fields - set(payload)
    if missing:
        fail(label, f"missing required fields: {', '.join(sorted(missing))}")
    unknown = set(payload) - required_fields
    if unknown:
        fail(label, f"unknown fields: {', '.join(sorted(unknown))}")
    return payload


def positive_integer(label: str, payload: dict[str, object], field: str) -> int:
    value = payload[field]
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        fail(label, f"{field} must be a positive integer")
    return value


def nonnegative_integer(label: str, payload: dict[str, object], field: str) -> int:
    value = payload[field]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(label, f"{field} must be a non-negative integer")
    return value


def bounded_string(
    label: str,
    payload: dict[str, object],
    field: str,
    *,
    maximum: int,
) -> str:
    value = payload[field]
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        fail(label, f"{field} must be 1 to {maximum} characters")
    if value != value.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        fail(label, f"{field} must be canonical and contain no control characters")
    return value


def sha256(label: str, payload: dict[str, object], field: str) -> str:
    value = payload[field]
    if not isinstance(value, str) or LOWER_SHA256_RE.fullmatch(value) is None:
        fail(label, f"{field} must be a lowercase SHA-256 digest")
    return value


def canonical_string_list(
    label: str,
    payload: dict[str, object],
    field: str,
    *,
    maximum: int,
    require_nonempty: bool = False,
) -> list[str]:
    value = payload[field]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        fail(label, f"{field} must be a JSON string array")
    if len(value) > maximum or (require_nonempty and not value):
        qualifier = "1 to" if require_nonempty else "at most"
        fail(label, f"{field} must contain {qualifier} {maximum} entries")
    if value != sorted(set(value)):
        fail(label, f"{field} must be sorted and unique")
    for item in value:
        if (
            not item
            or item != item.strip()
            or len(item) > 256
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
        ):
            fail(label, f"{field} entries must be canonical strings up to 256 characters")
    return value
