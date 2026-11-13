"""The engagement pointer names a section map only when the operator prompt has one.

The web and blue operator prompts open with a "Map of This File" table; the
code core does not. Telling a code operator to follow a map that does not exist
sends it looking for a section it will never find.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from test_client_entrypoint_contracts import _legacy_engagement
from vigil_cli import engagements


@pytest.mark.parametrize(
    ("mode", "prompt_name", "prompt_text", "names_map"),
    [
        ("web", "AGENTS.md", "# Operator\n\n## Map of This File\n\n| When | Section |\n", True),
        ("code", "operator-core-code.md", "# Code operator\n\n## Activation\n", False),
    ],
)
def test_pointer_names_the_map_only_for_a_prompt_that_has_one(
    tmp_path: Path, mode: str, prompt_name: str, prompt_text: str, names_map: bool
) -> None:
    _install_root, agent_root, engagement_dir = _legacy_engagement(tmp_path, f"acme-{mode}")
    (agent_root / prompt_name).write_text(prompt_text, encoding="utf-8")
    (engagement_dir / "scope.json").write_text(
        f'{{"engagement_type":"offensive","tracks":{{"{mode}":{{"phase":"init"}}}},"status":"active"}}\n',
        encoding="utf-8",
    )

    engagements._write_prompt_wrappers(
        agent_root, engagement_dir, "codex", engagement_type="offensive"
    )

    pointer = (engagement_dir / "AGENTS.md").read_text(encoding="utf-8")
    assert str(agent_root / prompt_name) in pointer
    assert ("Map of This File" in pointer) is names_map
