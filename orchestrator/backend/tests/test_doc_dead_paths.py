"""Structural guards for the repository invariant map.

The map is maintained prose, so this test does not pin headings or wording. It
only enforces the file's declared size/line limits and verifies that concrete
directory-rooted repository paths in code spans still resolve.

Both checks block, and neither is a wording test. `AGENTS.md`'s "Markdown
prompt/doc testing policy" bans asserting on what the map SAYS -- a byte ceiling
asserts nothing about wording and cannot be satisfied by rewording, which is why
the map's own header states the ceiling and says to cut an entry that has stopped
earning its place rather than to reword one until it fits.
"""

from __future__ import annotations

import re
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[3]
_CODE_MAP = _REPO_ROOT / "CODE-MAP.md"
_MAX_BYTES = 25 * 1024
_MAX_LINE_LENGTH = 300
_REPO_PATH = re.compile(
    r"`((?:agent|docs|orchestrator|src|tests|third_party|tools)/[^`\s]+)`"
)


def _referenced_paths() -> list[tuple[str, str]]:
    references: list[tuple[str, str]] = []
    for token in _REPO_PATH.findall(_CODE_MAP.read_text(encoding="utf-8")):
        if "<" in token or ">" in token:
            continue
        path_text = token.split(":", 1)[0]
        references.append((token, path_text))
    return references


def test_code_map_stays_within_declared_format_limits() -> None:
    content = _CODE_MAP.read_bytes()
    assert len(content) <= _MAX_BYTES, (
        f"CODE-MAP.md is {len(content)} bytes; limit is {_MAX_BYTES}. "
        "Cut an entry that has stopped earning its place -- do not reword to fit."
    )

    long_lines = [
        (number, len(line))
        for number, line in enumerate(content.decode("utf-8").splitlines(), start=1)
        if len(line) > _MAX_LINE_LENGTH
    ]
    assert not long_lines, f"CODE-MAP.md lines exceed {_MAX_LINE_LENGTH} chars: {long_lines}"


def test_code_map_repo_paths_resolve() -> None:
    missing: list[str] = []
    for token, path_text in _referenced_paths():
        if any(char in path_text for char in "*?["):
            if not list(_REPO_ROOT.glob(path_text)):
                missing.append(token)
        elif not (_REPO_ROOT / path_text.rstrip("/")).exists():
            missing.append(token)

    assert not missing, "CODE-MAP.md references missing repo paths: " + ", ".join(missing)
