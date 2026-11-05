"""A parse tree deeper than Python's call stack still indexes exactly.

Generated and test sources nest expressions thousands deep (a language's own
stack-limit tests do it on purpose). Tree-sitter parses them without
recursion, so the indexer's own walks must not recurse per tree level either:
a walk that does fails with RecursionError and drops the whole file to the
streaming fallback.
"""
from __future__ import annotations

import sys
from typing import Any

import pytest

from assess.lib.treesitter_index import _get_parser, _walk_named_nodes, index_file

DEPTH = sys.getrecursionlimit() * 3


def test_a_php_file_nested_past_the_recursion_limit_indexes_in_tree_sitter_mode() -> None:
    source = (
        b"<?php\nfunction acme($cmd) {\n    return "
        + b"[" * DEPTH + b"system($cmd)" + b"]" * DEPTH
        + b";\n}\n"
    )

    indexed = index_file("tests/stack_limit.php", "php", source)

    assert indexed["analysis_mode"] == "tree_sitter"
    assert indexed["degradation_reason"] is None
    assert [func["name"] for func in indexed["functions"]] == ["acme"]
    assert ("process_exec", "acme", 3) in {
        (sink["kind"], sink["function"], sink["line"]) for sink in indexed["security_sinks"]
    }


def _nested(open_: bytes, close: bytes) -> bytes:
    return open_ * DEPTH + b"1" + close * DEPTH


@pytest.mark.parametrize(
    ("path", "language", "source"),
    [
        pytest.param("src/deep.js", "javascript", b"function acme() {\n  return " + _nested(b"[", b"]") + b";\n}\n", id="javascript"),
        pytest.param("src/deep.ts", "typescript", b"function acme(): number {\n  return " + _nested(b"(", b")") + b";\n}\n", id="typescript"),
        pytest.param("src/deep.c", "c", b"int acme(void) {\n  return " + _nested(b"(", b")") + b";\n}\n", id="c"),
        pytest.param("lib/deep.rb", "ruby", b"def acme\n  " + _nested(b"[", b"]") + b"\nend\n", id="ruby"),
        pytest.param("src/Deep.cs", "csharp", b"class Deep {\n  int Acme() {\n    return " + _nested(b"(", b")") + b";\n  }\n}\n", id="csharp"),
    ],
)
def test_other_grammars_nested_past_the_recursion_limit_index_in_tree_sitter_mode(
    path: str, language: str, source: bytes
) -> None:
    indexed = index_file(path, language, source)

    assert indexed["analysis_mode"] == "tree_sitter"
    assert indexed["total_functions"] == 1


def _recursive_preorder(node: Any) -> list[Any]:
    nodes = [node]
    for child in node.named_children:
        nodes.extend(_recursive_preorder(child))
    return nodes


def test_the_named_node_walk_is_a_preorder() -> None:
    source = b"<?php\nnamespace Acme;\nfunction a($x) { return [$x, b($x), [1, 2]]; }\nclass C { public function d() {} }\n"
    root = _get_parser("php").parse(source).root_node

    assert [(node.type, node.start_byte) for node in _walk_named_nodes(root)] == [
        (node.type, node.start_byte) for node in _recursive_preorder(root)
    ]
