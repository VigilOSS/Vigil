"""Shared zero-dependency frontmatter parser for the assess CLI.

`list-skills` and `list-references` both need to read the simple `key: value`
YAML frontmatter that Vigil owns on its `SKILL.md` / reference `.md` files. We
deliberately avoid pulling in PyYAML: the frontmatter we own is flat (no nested
structures, no multi-line values), so a hand-rolled parser is sufficient,
faster, and keeps these discovery commands dependency-free.

This module is the single source of truth for that parsing so the two commands
cannot drift in how they interpret a file's metadata.
"""
from __future__ import annotations

from pathlib import Path


def parse(path: Path) -> dict[str, str]:
    """Parse the YAML frontmatter of ``path`` into a flat ``dict``.

    - Keys are lowercased; matching surrounding quotes are stripped from values.
    - Every ``key: value`` pair in the frontmatter block is returned; callers
      pick the fields they care about (``description``, ``skill``, ``source`` …).
    - ``description`` is always present: if the frontmatter omits it (or the file
      has no frontmatter block at all), the first ``# `` H1 heading of the body
      is used as a fallback, and ``""`` if there is no heading either.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {"description": ""}

    lines = text.splitlines()
    meta: dict[str, str] = {}

    if lines and lines[0].strip() == "---":
        for raw in lines[1:]:
            line = raw.rstrip()
            if line.strip() == "---":
                break
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            # Strip a matching pair of surrounding quotes if present.
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            if key:
                meta[key] = value

    if not meta.get("description"):
        meta["description"] = first_heading(lines)

    return meta


def first_heading(lines: list[str]) -> str:
    """Return the text of the first ``# `` H1 heading, or ``""`` if none."""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
    return ""
