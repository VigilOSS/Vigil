"""The per-dimension signal limit keeps every kind it saw.

A file past the limit is truncated and owes a whole-file read, but the records
it keeps are the hints a reviewer starts from, so the cut takes them in turn
across kinds: one inclusion or mass assignment is not lost behind thousands of
echoes, wherever in the file it sits.
"""
from __future__ import annotations

from collections import Counter

import pytest

from assess.lib.treesitter_index import STRUCTURAL_SIGNAL_LIMIT, index_file
from assess.lib.treesitter_streaming import _fallback_from_bytes

_RARE = "include $_GET['page'];\n$f();\n$o = `ls`;\nextract($_POST);\n"
_ECHOES = "echo $x;\n" * (STRUCTURAL_SIGNAL_LIMIT + 100)


@pytest.mark.parametrize("body", [_RARE + _ECHOES, _ECHOES + _RARE], ids=["first", "last"])
def test_tree_sitter_index_keeps_every_sink_kind_past_the_limit(body: str) -> None:
    indexed = index_file("public/page.php", "php", f"<?php\n{body}".encode())

    kinds = Counter(sink["kind"] for sink in indexed["security_sinks"])
    assert len(indexed["security_sinks"]) == STRUCTURAL_SIGNAL_LIMIT
    assert indexed["signal_counts"]["security_sinks"] == STRUCTURAL_SIGNAL_LIMIT + 104
    assert "security_sinks" in indexed["truncated_dimensions"]
    assert set(kinds) == {
        "dynamic_invocation", "file_inclusion", "mass_assignment", "process_exec", "xss_output",
    }
    assert kinds["xss_output"] == STRUCTURAL_SIGNAL_LIMIT - 4


@pytest.mark.parametrize("body", [_RARE + _ECHOES, _ECHOES + _RARE], ids=["first", "last"])
def test_streaming_fallback_keeps_every_sink_kind_past_the_limit(body: str) -> None:
    indexed = _fallback_from_bytes(
        "public/page.php", "php", f"<?php\n{body}".encode(), degradation_reason="test"
    )

    kinds = Counter(sink["kind"] for sink in indexed["security_sinks"])
    assert len(indexed["security_sinks"]) == STRUCTURAL_SIGNAL_LIMIT
    assert "security_sinks" in indexed["truncated_dimensions"]
    assert set(kinds) == {"file_inclusion", "mass_assignment", "xss_output"}
    assert sorted(sink["line"] for sink in indexed["security_sinks"]) == [
        sink["line"] for sink in indexed["security_sinks"]
    ]
