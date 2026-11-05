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

def _php_import_record(kind: str, name: str, alias: str, line: int) -> dict[str, Any]:
    """One name a PHP `use` declaration imports, as every PHP reader publishes it.

    `raw` is the fully qualified name, so `imports` and `import_targets` stay one
    entry per imported name. Only a class import names something a file can
    declare; a function or a constant resolves to no file.
    """
    qualified_name = "".join(name.split()).lstrip("\\")
    return {
        "raw": qualified_name,
        "resolved": qualified_name.replace("\\", "/") if kind == "class" else "",
        "kind": kind,
        "qualified_name": qualified_name,
        "alias": alias,
        "line": line,
    }
