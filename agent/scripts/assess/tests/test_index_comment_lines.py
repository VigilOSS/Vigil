"""A line is commentary only when the grammar puts all of its text in comments.

A leading `*` is a docblock continuation only inside a block comment; outside
one it is a dereference or a multiplication, and the call after it runs. A PHP
`//` comment ends at `?>`, so whatever follows on that line is code.
"""
from __future__ import annotations

from assess.lib.treesitter_index import index_file


def _sinks(indexed: dict) -> set[tuple[str, int, str]]:
    return {(sink["kind"], sink["line"], sink["function"]) for sink in indexed["security_sinks"]}


def test_c_statement_opening_with_a_dereference_is_read() -> None:
    source = b"""#include <stdio.h>
#include <stdlib.h>
void open_pipe(char *cmd, FILE **out) {
  *out = popen(cmd, "r");
}
void crash(char *cmd) {
  * (int *)0 = system(cmd);
}
/*
 * system(docblock);
 */
"""
    indexed = index_file("acme.c", "c", source)

    assert indexed["analysis_status"] == "complete"
    assert {line for _kind, line, _function in _sinks(indexed)} == {4, 7}


def test_javascript_continuation_line_opening_with_an_operator_is_read() -> None:
    source = b"""function scale(a, b) {
  return a
    * eval(b);
}
/**
 * eval(docblock)
 */
function documented() {
  /*
   * eval(inner)
   */
  return 1;
}
"""
    indexed = index_file("acme.js", "javascript", source)

    assert {line for _kind, line, _function in _sinks(indexed)} == {3}


def test_php_code_after_a_line_comment_closed_by_the_tag_is_read() -> None:
    source = b"<?php\n// legacy ?><?php system($_GET['c']);\n"

    indexed = index_file("acme.php", "php", source)

    assert ("process_exec", 2, "<top-level>") in _sinks(indexed)
    assert [source_record["line"] for source_record in indexed["security_sources"]] == [2]
    assert indexed["top_level_segments"] == [{"line_start": 2, "line_end": 2}]
    assert [(entry["kind"], entry["line"]) for entry in indexed["entry_points"]] == [
        ("php_script", 2)
    ]


def test_php_code_after_a_line_comment_closed_by_the_tag_in_a_function_is_read() -> None:
    source = b"""<?php
function run($cmd) {
  // legacy ?><?php system($cmd);
}
/**
 * system($docblock);
 */
"""
    indexed = index_file("acme.php", "php", source)

    assert _sinks(indexed) == {("process_exec", 3, "run")}
