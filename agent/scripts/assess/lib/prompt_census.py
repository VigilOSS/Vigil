"""Structural, advisory measurements for specialist prompt standing load."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any


_LOAD_FIRST = re.compile(r"^##\s+Load First\s*$", re.IGNORECASE)
_LEVEL_TWO = re.compile(r"^##\s+")
_MANDATORY = re.compile(r"^(?:\*\*|#{3,}\s*)MANDATORY\b", re.IGNORECASE)
_LAZY = re.compile(r"^(?:\*\*|#{3,}\s*)LOAD-ON-FIRST-USE\b", re.IGNORECASE)
_AGENT_PATH = re.compile(r"`(agent/[^`]+)`")


def _lines_with_offsets(raw: bytes) -> list[tuple[int, int, str]]:
    rows: list[tuple[int, int, str]] = []
    offset = 0
    for line in raw.splitlines(keepends=True):
        end = offset + len(line)
        rows.append((offset, end, line.decode("utf-8").strip()))
        offset = end
    return rows


def _section_bounds(
    rows: list[tuple[int, int, str]], raw_size: int
) -> tuple[int | None, int | None, int | None, int | None]:
    load_index: int | None = None
    for index, (_start, _end, text) in enumerate(rows):
        if _LOAD_FIRST.match(text):
            load_index = index
            break
    if load_index is None:
        return None, None, None, None

    load_start = rows[load_index][0]
    load_end = raw_size
    mandatory_start: int | None = None
    lazy_start: int | None = None
    for index in range(load_index + 1, len(rows)):
        start, _end, text = rows[index]
        if _LEVEL_TWO.match(text):
            load_end = start
            break
        if mandatory_start is None and _MANDATORY.search(text):
            mandatory_start = start
        if lazy_start is None and _LAZY.search(text):
            lazy_start = start
    return load_start, load_end, mandatory_start, lazy_start


def _visibility(
    read_bytes: int | None, load_start: int | None, load_end: int | None
) -> str:
    if load_start is None or load_end is None:
        return "missing"
    if read_bytes is None:
        return "not_reported"
    if read_bytes <= load_start:
        return "not_reached"
    if read_bytes < load_end:
        return "partial"
    return "complete"


def census_role(prompt_root: Path, role_path: Path, read_bytes: int | None) -> dict[str, Any]:
    raw = role_path.read_bytes()
    rows = _lines_with_offsets(raw)
    load_start, load_end, mandatory_start, lazy_start = _section_bounds(rows, len(raw))
    mandatory_end = lazy_start if lazy_start is not None else load_end
    mandatory_text = ""
    if mandatory_start is not None and mandatory_end is not None:
        mandatory_text = raw[mandatory_start:mandatory_end].decode("utf-8")

    references: list[dict[str, Any]] = []
    advisories: list[str] = []
    seen: set[str] = set()
    for referenced in _AGENT_PATH.findall(mandatory_text):
        if referenced in seen:
            continue
        seen.add(referenced)
        relative = referenced.removeprefix("agent/")
        resolved = prompt_root / relative
        if not resolved.is_file():
            advisories.append(f"mandatory reference is not a regular file: {referenced}")
            references.append({"path": referenced, "present": False, "bytes": None})
            continue
        references.append(
            {"path": referenced, "present": True, "bytes": len(resolved.read_bytes())}
        )

    expected = {
        "load_first": load_start is not None,
        "mandatory": mandatory_start is not None,
        "load_on_first_use": lazy_start is not None,
    }
    for section, present in expected.items():
        if not present:
            advisories.append(f"expected section not detected: {section}")
    visibility = _visibility(read_bytes, load_start, load_end)
    if visibility in {"not_reached", "partial"}:
        advisories.append(f"reported read is {visibility} for the Load First section")

    referenced_bytes = sum(
        int(reference["bytes"])
        for reference in references
        if reference["bytes"] is not None
    )
    return {
        "role": role_path.stem,
        "path": f"agent/agents/{role_path.name}",
        "role_bytes": len(raw),
        "load_first_byte_range": (
            {"start": load_start, "end": load_end}
            if load_start is not None and load_end is not None
            else None
        ),
        "expected_sections": expected,
        "mandatory_references": references,
        "approximate_mandatory_reference_bytes": referenced_bytes,
        "approximate_standing_bytes": len(raw) + referenced_bytes,
        "read_bytes": read_bytes,
        "read_visibility": visibility,
        "advisories": advisories,
    }


def collect_prompt_census(prompt_root: Path, read_bytes: int | None = None) -> dict[str, Any]:
    roles_dir = prompt_root / "agents"
    if not roles_dir.is_dir():
        raise ValueError(f"roles directory not found: {roles_dir}")
    roles = [
        census_role(prompt_root, role_path, read_bytes)
        for role_path in sorted(roles_dir.glob("*.md"))
    ]
    return {
        "blocking": False,
        "prompt_root": str(prompt_root),
        "read_bytes": read_bytes,
        "roles": roles,
        "advisory_count": sum(len(role["advisories"]) for role in roles),
    }
