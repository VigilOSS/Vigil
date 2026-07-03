"""Pin the dispatch_mode default map against each role prompt's declared default.

`contracts._DISPATCH_MODE_BY_ROLE` (resolved via `default_dispatch_mode_for_role`)
must agree with every offensive/code role file's "**Default when omitted:** `<mode>`"
line. This catches the exact failure mode where a role is added (e.g. a new code-*
specialist) but never wired into the map — it then silently resolves to the
`hypothesis-driven` fallback instead of its declared default.

Blue/IR roles resolve their defaults via `vigil_cli.blue._default_dispatch_mode_for_role`
(a separate source), so they are identified by their `operator-core-blue.md` reference
and skipped here.

NOT a wording test: it asserts a machine contract (the resolver's output), not prose.
"""
from __future__ import annotations

import re
from pathlib import Path

from assess.lib import contracts

_AGENTS_DIR = Path(__file__).resolve().parents[3] / "agents"
_DEFAULT_RE = re.compile(r"Default when omitted:\*\*\s*`([a-z-]+)`")


def _declared_defaults() -> dict[str, str]:
    declared: dict[str, str] = {}
    for role_file in sorted(_AGENTS_DIR.glob("*.md")):
        text = role_file.read_text(encoding="utf-8")
        if "operator-core-blue.md" in text:
            continue  # blue/IR roles resolve via vigil_cli.blue, not contracts
        match = _DEFAULT_RE.search(text)
        if match:
            declared[role_file.stem] = match.group(1)
    return declared


def test_contracts_dispatch_mode_matches_role_declared_defaults() -> None:
    declared = _declared_defaults()
    assert declared, "no offensive/code role file declared a dispatch_mode default"
    mismatches = [
        f"{role}: role prompt declares {want!r} but resolver returns "
        f"{contracts.default_dispatch_mode_for_role(role)!r}"
        for role, want in sorted(declared.items())
        if contracts.default_dispatch_mode_for_role(role) != want
    ]
    assert not mismatches, "dispatch_mode default drift:\n" + "\n".join(mismatches)
