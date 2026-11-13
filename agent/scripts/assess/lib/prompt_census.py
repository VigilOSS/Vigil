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
# An operator core names what it loads in plain prose: a standing list read once at
# session start, and trigger-loaded files named beside their trigger (a lead-in line
# that mentions the trigger followed by bullets, or a Trigger/Load table, or either
# under a heading that mentions triggers). The census reads those shapes
# structurally so a trigger-loaded file is visible beside the session figure
# without being billed as standing load.
_STANDING_LEAD_IN = re.compile(
    r"^(?:(?:Always-active|Standing)\s+(?:rules|references)|Primary\s+methodology\s+references?)\b[^:]*:$",
    re.IGNORECASE,
)
_TRIGGER_WORD = re.compile(r"\btrigger", re.IGNORECASE)
_HEADING = re.compile(r"^#{1,6}\s+(.*)$")
_TRIGGER_SEPARATOR = re.compile(r"^\s*(?:[\u2014\u2013:-]|--)\s*")
# Alternative groups multiply combinatorially. Today's prompts carry at most one
# group per role; beyond this cap the census reports the groups but declines to
# enumerate every track rather than emitting an unreadable variant list.
_MAX_VARIANTS = 16
# A path into an operator core. Specialists never load one (`agent/shared-
# specialist-core.md` "Specialist Context Isolation"), so a file a role loads
# that points into one names a rule its reader cannot follow. A structural path
# check: the bare file name, with or without the `agent/` prefix.
_OPERATOR_CORE_PATH = re.compile(r"(?<![\w./-])(?:agent/)?(operator-core(?:-[a-z]+)?\.md)\b")


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


def _lazy_references(
    prompt_root: Path, lazy_text: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """Trigger-loaded files a role names under LOAD-ON-FIRST-USE.

    Lazy entries also name globs, directories, and skills chosen at run time, so only
    pointers that resolve to a regular file are measured; they are reported apart
    from the standing load because a dispatch pays for them only when the trigger fires.
    Every other pointer is returned by path so the output can say what it left out.
    """
    rows: list[dict[str, Any]] = []
    unmeasured: list[str] = []
    for referenced in _ordered_unique(_AGENT_PATH.findall(lazy_text)):
        resolved = prompt_root / referenced.removeprefix("agent/")
        if resolved.is_file():
            rows.append({"path": referenced, "bytes": len(resolved.read_bytes())})
        else:
            unmeasured.append(referenced)
    return rows, unmeasured


def _table_cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _core_rule_lists(
    prompt_root: Path, text: str, advisories: list[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    standing: list[dict[str, Any]] = []
    triggered: list[dict[str, Any]] = []
    seen: set[str] = set()
    section_triggered = False
    lead_in: list[dict[str, Any]] | None = None
    trigger_column: int | None = None
    open_row: dict[str, Any] | None = None

    def add(target: list[dict[str, Any]], referenced: str, trigger: str | None) -> dict[str, Any] | None:
        if referenced in seen:
            return None
        seen.add(referenced)
        resolved = prompt_root / referenced.removeprefix("agent/")
        present = resolved.is_file()
        row: dict[str, Any] = {
            "path": referenced,
            "present": present,
            "bytes": len(resolved.read_bytes()) if present else None,
        }
        if target is triggered:
            row["trigger"] = trigger or ""
        if not present:
            kind = "trigger-loaded" if target is triggered else "standing"
            advisories.append(f"{kind} reference is not a regular file: {referenced}")
        target.append(row)
        return row

    for line in text.splitlines():
        stripped = line.strip()
        heading = _HEADING.match(stripped)
        if heading is not None:
            section_triggered = bool(_TRIGGER_WORD.search(heading.group(1)))
            lead_in, trigger_column, open_row = None, None, None
            continue
        if not stripped:
            open_row = None
            continue
        bare = stripped.strip("*_ ")
        if not stripped.startswith(("-", "|")) and not line[:1].isspace():
            open_row, trigger_column = None, None
            if _STANDING_LEAD_IN.match(bare):
                lead_in = standing
            elif bare.endswith(":") and _TRIGGER_WORD.search(bare):
                lead_in = triggered
            else:
                lead_in = None
            continue
        target = lead_in if lead_in is not None else (triggered if section_triggered else None)
        if target is None:
            continue
        if stripped.startswith("|"):
            cells = _table_cells(stripped)
            if trigger_column is None:
                lowered = [cell.lower() for cell in cells]
                if "trigger" in lowered:
                    trigger_column = lowered.index("trigger")
                continue
            if all(set(cell) <= set("-: ") for cell in cells):
                continue
            trigger = cells[trigger_column] if trigger_column < len(cells) else ""
            for index, cell in enumerate(cells):
                if index == trigger_column:
                    continue
                for referenced in _AGENT_PATH.findall(cell):
                    add(target, referenced, trigger)
            continue
        bullet = _BULLET.match(line)
        if bullet is not None and len(bullet.group(1).expandtabs(4)) == 0:
            open_row = None
            match = _AGENT_PATH.search(bullet.group(2))
            if match is None:
                continue
            trailing = bullet.group(2)[match.end():]
            open_row = add(
                target,
                match.group(1),
                _TRIGGER_SEPARATOR.sub("", trailing, count=1).strip(),
            )
            continue
        if open_row is not None and "trigger" in open_row:
            # An indented continuation of the bullet above: it extends that entry's
            # trigger text; paths it mentions are prose, not further loads.
            open_row["trigger"] = " ".join(f"{open_row['trigger']} {stripped}".split())
    return standing, triggered


def _reference_bytes(references: list[dict[str, Any]]) -> int:
    return sum(
        int(reference["bytes"])
        for reference in references
        if reference["bytes"] is not None
    )


def _operator_core_citations(prompt_root: Path, paths: list[str]) -> list[str]:
    """One advisory per line of a specialist-loaded file that cites an operator core."""
    advisories: list[str] = []
    for referenced in _ordered_unique(paths):
        resolved = prompt_root / referenced.removeprefix("agent/")
        if not resolved.is_file():
            continue
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
        for number, line in enumerate(lines, start=1):
            cores = _ordered_unique(_OPERATOR_CORE_PATH.findall(line))
            if cores:
                advisories.append(
                    f"specialist_cites_operator_core: {referenced}:{number} cites "
                    f"{', '.join(f'agent/{core}' for core in cores)}; specialists do not "
                    "load operator cores, so point at a specialist-loaded file or drop "
                    "the pointer"
                )
    return advisories


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
    lazy_text = ""
    if lazy_start is not None and load_end is not None:
        lazy_text = raw[lazy_start:load_end].decode("utf-8")
    standing_paths = {reference["path"] for reference in references} | exclusive
    lazy_rows, unmeasured_lazy = _lazy_references(prompt_root, lazy_text)
    trigger_loaded = [row for row in lazy_rows if row["path"] not in standing_paths]

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

    advisories.extend(_operator_core_citations(prompt_root, [
        f"agent/agents/{role_path.name}",
        *(reference["path"] for reference in references),
        *(
            reference["path"]
            for group in groups
            for option in group["options"]
            for reference in option["references"]
        ),
        *(row["path"] for row in trigger_loaded),
    ]))

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
        "trigger_loaded_references": trigger_loaded,
        "approximate_trigger_loaded_bytes": sum(row["bytes"] for row in trigger_loaded),
        # Globs, directories, missing files, and run-time skill choices: named here
        # because they are outside the trigger-loaded byte figure.
        "unmeasured_trigger_pointers": unmeasured_lazy,
        "read_bytes": read_bytes,
        "read_visibility": visibility,
        "advisories": advisories,
    }


def census_operator_core(prompt_root: Path, core_path: Path) -> dict[str, Any]:
    """Measure one operator-doctrine file and the rules it names.

    The session standing figure is the core plus its standing rules, paid once per
    operator session; trigger-loaded rules are listed with their triggers and summed
    only into the every-trigger-fires ceiling. Both figures are advisory: this
    command does not own an operator budget, and inventing one here would create
    governance the ruleset never set.
    """
    raw = core_path.read_bytes()
    advisories: list[str] = []
    standing, triggered = _core_rule_lists(
        prompt_root, raw.decode("utf-8"), advisories
    )
    session = len(raw) + _reference_bytes(standing)
    return {
        "core": core_path.stem,
        "path": f"agent/{core_path.name}",
        "bytes": len(raw),
        "lines": _line_count(raw),
        "standing_references": standing,
        "trigger_loaded_references": triggered,
        "approximate_session_standing_bytes": session,
        "approximate_session_ceiling_bytes": session + _reference_bytes(triggered),
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
    cores = [
        census_operator_core(prompt_root, core_path)
        for core_path in sorted(prompt_root.glob(_OPERATOR_CORE_GLOB))
        if core_path.is_file()
    ]
    return {
        "blocking": False,
        "prompt_root": str(prompt_root),
        "read_bytes": read_bytes,
        "operator_cores": cores,
        "roles": roles,
        "advisory_count": sum(len(row["advisories"]) for row in (*roles, *cores)),
    }
