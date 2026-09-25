"""Compiled grammar queries are reused across the files in a large repository."""

import pytest

from assess.lib import treesitter_index


def test_same_language_query_is_compiled_once_for_multiple_files(monkeypatch) -> None:
    if not hasattr(treesitter_index.tree_sitter, "QueryCursor"):
        pytest.skip("Query constructor is only used by tree-sitter 0.25+")
    parser = treesitter_index._get_parser("python")
    assert parser is not None
    query = "(function_definition) @cache_probe"
    roots = [parser.parse(source).root_node for source in (b"def a(): pass\n", b"def b(): pass\n")]
    original = treesitter_index.tree_sitter.Query
    calls = 0

    def counting_query(language, source):
        nonlocal calls
        calls += 1
        return original(language, source)

    monkeypatch.setattr(treesitter_index.tree_sitter, "Query", counting_query)
    first = treesitter_index._ts_query_captures(parser.language, query, roots[0])
    second = treesitter_index._ts_query_captures(parser.language, query, roots[1])

    assert len(first["cache_probe"]) == len(second["cache_probe"]) == 1
    assert calls == 1


def test_invalid_query_keeps_empty_capture_fallback() -> None:
    parser = treesitter_index._get_parser("python")
    assert parser is not None
    root = parser.parse(b"def a(): pass\n").root_node
    assert treesitter_index._ts_query_captures(
        parser.language, "(not_a_python_node) @bad", root
    ) == {}
