"""Shell argument signals that dispatch agents to input-handling scripts."""

import pytest

from assess.lib.treesitter_index import index_file


@pytest.mark.parametrize("expansion", ["$@", "$*", "${@}", "${*}", "${1}", "${10}"])
def test_shell_all_arguments_expansions_are_sources(expansion: str) -> None:
    source = f'#!/bin/sh\nprintf "%s\\n" "{expansion}"\n'.encode()
    indexed = index_file("script.sh", "shell", source)

    assert indexed["analysis_status"] == "complete"
    assert any(
        observation["kind"] == "positional_parameter" and observation["line"] == 2
        for observation in indexed["security_sources"]
    )


def test_shell_sourced_file_has_a_navigation_target() -> None:
    indexed = index_file("scripts/deploy.sh", "shell", b"#!/bin/sh\n. ./lib.sh\n")

    assert indexed["import_targets"] == [{"raw": "./lib.sh", "resolved": "./lib.sh"}]
