"""Structural, advisory measurements for prompt standing load."""
from __future__ import annotations

import re
from itertools import product
from pathlib import Path
from typing import Any


_LOAD_FIRST = re.compile(r"^##\s+Load First\s*$", re.IGNORECASE)
_LEVEL_TWO = re.compile(r"^##\s+")
_MANDATORY = re.compile(r"^(?:\*\*|#{3,}\s*)MANDATORY\b", re.IGNORECASE)
_LAZY = re.compile(r"^(?:\*\*|#{3,}\s*)LOAD-ON-FIRST-USE\b", re.IGNORECASE)
_AGENT_PATH = re.compile(r"`(agent/[^`]+)`")
_BULLET = re.compile(r"^(\s*)-\s+(.*)$")
_OPTION_LABEL = re.compile(r"^\*\*(.+?)\*\*")
# Operator doctrine is loaded once per operator session; a role's standing load is
# paid again on every dispatch. Keeping the two categories apart stops a session-cost
# figure from being compared against a per-dispatch budget.
_OPERATOR_CORE_GLOB = "operator-core*.md"
# Alternative groups multiply combinatorially. Today's prompts carry at most one
# group per role; beyond this cap the census reports the groups but declines to
# enumerate every track rather than emitting an unreadable variant list.
_MAX_VARIANTS = 16


def _lines_with_offsets(raw: bytes) -> list[tuple[int, int, str]]:
    rows: list[tuple[int, int, str]] = []
    offset = 0
    for line in raw.splitlines(keepends=True):
        end = offset + len(line)
        rows.append((offset, end, line.decode("utf-8").strip()))
        offset = end
    return rows


def _line_count(raw: bytes) -> int:
    if not raw:
        return 0
    return raw.count(b"\n") + (0 if raw.endswith(b"\n") else 1)


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


def _alternative_groups(mandatory_text: str) -> list[dict[str, Any]]:
    """Find "exactly one of these" bundles in a MANDATORY block.

    The signal is structural, not lexical: a top-level bullet that names no file
    of its own, followed by indented sub-bullets that each name one. Nested
    entries are sub-items of a single requirement, so summing them would report a
    standing load no real dispatch ever pays — exploit-developer and
    source-analyzer each choose one of a code/web constraint bundle.
    """
    groups: list[dict[str, Any]] = []
    selector: str | None = None
    options: list[dict[str, Any]] = []

    def close() -> None:
        nonlocal selector, options
        # A sub-bullet that names no file is prose, not an option, but it still had
        # to be tracked above so its continuation lines were not credited to the
        # option before it.
        loaded = [option for option in options if option["paths"]]
        for option in loaded:
            if not option["label"]:
                option["label"] = Path(option["paths"][0]).stem
        if selector is not None and len(loaded) >= 2:
            groups.append({"selector": selector, "options": loaded})
        selector = None
        options = []

    for line in mandatory_text.splitlines():
        bullet = _BULLET.match(line)
        if bullet is not None:
            indent, text = len(bullet.group(1).expandtabs(4)), bullet.group(2)
            paths = _ordered_unique(_AGENT_PATH.findall(text))
            if indent == 0:
                close()
                if not paths:
                    selector = text.strip()
                continue
            if selector is None:
                continue
            label = _OPTION_LABEL.match(text.strip())
            options.append(
                {
                    "label": label.group(1).strip() if label is not None else "",
                    "paths": paths,
                }
            )
            continue
        if selector is not None and options and line.strip() and line[:1].isspace():
            # An indented continuation line of the option bullet above it.
            options[-1]["paths"] = _ordered_unique(
                [*options[-1]["paths"], *_AGENT_PATH.findall(line)]
            )
            continue
        if line.strip() and not line[:1].isspace():
            close()
    close()
    return groups


def _ordered_unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def _resolve_reference(
    prompt_root: Path, referenced: str, advisories: list[str]
) -> dict[str, Any]:
    resolved = prompt_root / referenced.removeprefix("agent/")
    if not resolved.is_file():
        advisories.append(f"mandatory reference is not a regular file: {referenced}")
        return {"path": referenced, "present": False, "bytes": None}
    return {"path": referenced, "present": True, "bytes": len(resolved.read_bytes())}


def _reference_bytes(references: list[dict[str, Any]]) -> int:
    return sum(
        int(reference["bytes"])
        for reference in references
        if reference["bytes"] is not None
    )


def census_role(prompt_root: Path, role_path: Path, read_bytes: int | None) -> dict[str, Any]:
    raw = role_path.read_bytes()
    rows = _lines_with_offsets(raw)
    load_start, load_end, mandatory_start, lazy_start = _section_bounds(rows, len(raw))
    mandatory_end = lazy_start if lazy_start is not None else load_end
    mandatory_text = ""
    if mandatory_start is not None and mandatory_end is not None:
        mandatory_text = raw[mandatory_start:mandatory_end].decode("utf-8")

    advisories: list[str] = []
    groups: list[dict[str, Any]] = []
    exclusive: set[str] = set()
    for group in _alternative_groups(mandatory_text):
        options = []
        for option in group["options"]:
            resolved = [
                _resolve_reference(prompt_root, path, advisories)
                for path in option["paths"]
            ]
            exclusive.update(option["paths"])
            options.append(
                {
                    "label": option["label"],
                    "references": resolved,
                    "bytes": _reference_bytes(resolved),
                }
            )
        groups.append({"selector": group["selector"], "options": options})

    references = [
        _resolve_reference(prompt_root, referenced, advisories)
        for referenced in _ordered_unique(_AGENT_PATH.findall(mandatory_text))
        if referenced not in exclusive
    ]

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

    referenced_bytes = _reference_bytes(references)
    base_bytes = len(raw) + referenced_bytes
    base_paths = [f"agent/agents/{role_path.name}"] + [
        reference["path"] for reference in references
    ]
    variants: list[dict[str, Any]] = []
    combinations = 1
    for group in groups:
        combinations *= len(group["options"])
    if groups and combinations > _MAX_VARIANTS:
        advisories.append(
            f"{combinations} mutually exclusive load tracks exceed the "
            f"{_MAX_VARIANTS}-variant enumeration cap"
        )
    elif groups:
        for choice in product(*(group["options"] for group in groups)):
            chosen = [
                reference["path"]
                for option in choice
                for reference in option["references"]
            ]
            variants.append(
                {
                    "label": " + ".join(option["label"] for option in choice),
                    "paths": [*base_paths, *chosen],
                    "approximate_standing_bytes": base_bytes
                    + sum(int(option["bytes"]) for option in choice),
                }
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
        "mandatory_alternative_groups": groups,
        "approximate_mandatory_reference_bytes": referenced_bytes,
        # A role whose bundle choice is exclusive has no single standing load;
        # the per-track variants below are the only real dispatch costs.
        "approximate_standing_bytes": None if groups else base_bytes,
        "standing_byte_variants": variants,
        "read_bytes": read_bytes,
        "read_visibility": visibility,
        "advisories": advisories,
    }


def census_operator_core(core_path: Path) -> dict[str, Any]:
    """Measure one operator-doctrine file.

    Reported as size only. Operator cores have no MANDATORY Load-First block to
    resolve and no per-dispatch multiplier, and this command does not own their
    budget — inventing one here would create governance the ruleset never set.
    """
    raw = core_path.read_bytes()
    return {
        "core": core_path.stem,
        "path": f"agent/{core_path.name}",
        "bytes": len(raw),
        "lines": _line_count(raw),
    }


def collect_prompt_census(prompt_root: Path, read_bytes: int | None = None) -> dict[str, Any]:
    roles_dir = prompt_root / "agents"
    if not roles_dir.is_dir():
        raise ValueError(f"roles directory not found: {roles_dir}")
    roles = [
        census_role(prompt_root, role_path, read_bytes)
        for role_path in sorted(roles_dir.glob("*.md"))
    ]
    cores = [
        census_operator_core(core_path)
        for core_path in sorted(prompt_root.glob(_OPERATOR_CORE_GLOB))
        if core_path.is_file()
    ]
    return {
        "blocking": False,
        "prompt_root": str(prompt_root),
        "read_bytes": read_bytes,
        "operator_cores": cores,
        "roles": roles,
        "advisory_count": sum(len(role["advisories"]) for role in roles),
    }
