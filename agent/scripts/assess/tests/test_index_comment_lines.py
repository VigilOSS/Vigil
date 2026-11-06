"""A line is commentary only when all of its text is commentary.

A leading `*` is a docblock continuation only inside a block comment; outside
one it is a dereference or a multiplication, and the call after it runs. A PHP
`//` comment ends at `?>`, so whatever follows on that line is code.

The grammar reader answers this off the parse tree and the streaming fallback
off the bytes, and a finding that appears or vanishes with the reader that ran
is a finding nobody can act on, so every fixture here is read by both and the
two are asserted together. Where the line reader cannot answer at all -- it
names no entry point a PHP script's own statements make it -- the degraded
artifact declares that dimension unmeasured instead of publishing `[]` as a
clean result.
"""
from __future__ import annotations

import pytest

from assess.lib import treesitter_index
from assess.lib.treesitter_index import index_file
from assess.lib.treesitter_streaming import (
    STREAMING_SCAN_WINDOW_BYTES,
    streaming_security_fallback,
)

C_PIPE_SOURCE = b"""#include <stdio.h>
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

JAVASCRIPT_SCALE_SOURCE = b"""function scale(a, b) {
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

PHP_TAG_CLOSED_SCRIPT = b"<?php\n// legacy ?><?php system($_GET['c']);\n"

PHP_TAG_CLOSED_FUNCTION = b"""<?php
function run($cmd) {
  // legacy ?><?php system($cmd);
}
/**
 * system($docblock);
 */
"""

PHP_COMMENTED_OUT_QUERY = b"""<?php
/* mysql_query("id=".$_GET['id']); */
/**
 * mysql_query("id=".$_GET['id']);
 */
$total = 1 + 2;
"""

PHP_SIGNAL_FREE_SOURCE = b"<?php\n$total = 1 + 2;\n"

CSS_UNCLOSED_COMMENT = b"""/* note
a { background: url("{{ user_input }}"); }
"""

# The `/*` is string content, so the grammar reader does not blank it and the
# line reader of the uncommented source meets it at a line start.
JAVASCRIPT_UNCLOSED_COMMENT_IN_TEMPLATE = b"""function handle(req, res) {
  const banner = `
/* acme
`;
  res.send(req.query.name);
}
"""

JAVASCRIPT_UNCLOSED_COMMENT_AFTER_A_SINK = b"""eval(first);
/* acme
eval(second);
eval(third);
"""


def _oversized_block_comment_line(*, tail: bytes = b"") -> bytes:
    """One line whose `*/` lands past the first chunk the scanner is fed."""
    return b"/* " + b"x" * (STREAMING_SCAN_WINDOW_BYTES + 4096) + b" */" + tail


def _sinks(indexed: dict) -> set[tuple[str, int, str]]:
    return {(sink["kind"], sink["line"], sink["function"]) for sink in indexed["security_sinks"]}


def _streamed(file_path: str, language: str, source: bytes) -> dict:
    """The degraded artifact the bounded line scanner publishes for *source*."""
    return treesitter_index._fallback_from_bytes(
        file_path, language, source, degradation_reason="forced_for_test"
    )


def _kinded_lines(records: list[dict]) -> set[tuple[str, int]]:
    return {(record["kind"], record["line"]) for record in records}


def test_c_statement_opening_with_a_dereference_is_read() -> None:
    indexed = index_file("acme.c", "c", C_PIPE_SOURCE)

    assert indexed["analysis_status"] == "complete"
    assert {line for _kind, line, _function in _sinks(indexed)} == {4, 7}


def test_the_line_scanner_reads_the_same_c_dereference_line() -> None:
    streamed = _streamed("acme.c", "c", C_PIPE_SOURCE)

    assert _kinded_lines(streamed["security_sinks"]) == {("process_exec", 4), ("process_exec", 7)}


def test_javascript_continuation_line_opening_with_an_operator_is_read() -> None:
    indexed = index_file("acme.js", "javascript", JAVASCRIPT_SCALE_SOURCE)

    assert {line for _kind, line, _function in _sinks(indexed)} == {3}


def test_the_line_scanner_reads_the_same_javascript_continuation_line() -> None:
    streamed = _streamed("acme.js", "javascript", JAVASCRIPT_SCALE_SOURCE)

    assert _kinded_lines(streamed["security_sinks"]) == {("eval_exec", 3)}


def test_php_code_after_a_line_comment_closed_by_the_tag_is_read() -> None:
    indexed = index_file("acme.php", "php", PHP_TAG_CLOSED_SCRIPT)

    assert ("process_exec", 2, "<top-level>") in _sinks(indexed)
    assert [source_record["line"] for source_record in indexed["security_sources"]] == [2]
    assert indexed["top_level_segments"] == [{"line_start": 2, "line_end": 2}]
    assert [(entry["kind"], entry["line"]) for entry in indexed["entry_points"]] == [
        ("php_script", 2)
    ]


def test_the_line_scanner_reads_the_same_php_code_after_a_tag_closed_comment() -> None:
    streamed = _streamed("acme.php", "php", PHP_TAG_CLOSED_SCRIPT)

    assert _kinded_lines(streamed["security_sinks"]) == {("process_exec", 2)}
    assert _kinded_lines(streamed["security_sources"]) == {("http_request_input", 2)}


def test_php_code_after_a_line_comment_closed_by_the_tag_in_a_function_is_read() -> None:
    indexed = index_file("acme.php", "php", PHP_TAG_CLOSED_FUNCTION)

    assert _sinks(indexed) == {("process_exec", 3, "run")}


def test_the_line_scanner_reads_the_same_php_function_line_and_skips_its_docblock() -> None:
    streamed = _streamed("acme.php", "php", PHP_TAG_CLOSED_FUNCTION)

    assert _kinded_lines(streamed["security_sinks"]) == {("process_exec", 3)}


def test_a_commented_out_php_query_is_a_sink_to_neither_reader() -> None:
    indexed = index_file("acme.php", "php", PHP_COMMENTED_OUT_QUERY)
    streamed = _streamed("acme.php", "php", PHP_COMMENTED_OUT_QUERY)

    assert _sinks(indexed) == set()
    assert indexed["security_sources"] == []
    assert streamed["security_sinks"] == []
    assert streamed["security_sources"] == []


def test_a_degraded_artifact_names_the_signal_it_measured_nothing_for() -> None:
    """An empty line-scanner answer is an unmade measurement, not a clean file.

    The grammar reader finds a `php_script` entry point, a sink and a request
    source in `PHP_TAG_CLOSED_SCRIPT`; the line scanner has no entry rule a
    script's own statements can match, so its `entry_points` is silence rather
    than a negative and the artifact declares it unavailable.
    """
    streamed = _streamed("acme.php", "php", PHP_TAG_CLOSED_SCRIPT)

    assert streamed["analysis_status"] == "degraded"
    assert streamed["entry_points"] == []
    assert "entry_points" in streamed["unavailable_dimensions"]
    assert {"security_sinks", "security_sources"}.isdisjoint(
        streamed["unavailable_dimensions"]
    )


def test_a_degraded_artifact_over_signal_free_source_declares_every_dimension_unread() -> None:
    streamed = _streamed("acme.php", "php", PHP_SIGNAL_FREE_SOURCE)

    assert streamed["signal_counts"] == {
        "entry_points": 0,
        "imports": 0,
        "security_sinks": 0,
        "security_sources": 0,
    }
    assert {
        "entry_points",
        "imports",
        "security_sinks",
        "security_sources",
    } <= set(streamed["unavailable_dimensions"])


def test_an_unclosed_css_block_comment_hides_no_source() -> None:
    """An opener the file never closes is not a comment region.

    Reading from it to the end of the file as commentary drops every signal
    below it while the artifact still reports a clean complete read, which is
    the one answer a reader must never give. `_mask_delimited_comments`
    restores an unclosed markup opener verbatim for the same reason; a `/*`
    is the same construct got wrong, so the bytes after it are read as code.
    """
    indexed = index_file("acme.css", "css", CSS_UNCLOSED_COMMENT)
    streamed = _streamed("acme.css", "css", CSS_UNCLOSED_COMMENT)

    assert indexed["analysis_status"] == "complete"
    for observed in (indexed, streamed):
        assert _kinded_lines(observed["security_sources"]) == {("template_input", 2)}


def test_an_unclosed_block_comment_in_a_template_literal_hides_no_source() -> None:
    indexed = index_file("acme.js", "javascript", JAVASCRIPT_UNCLOSED_COMMENT_IN_TEMPLATE)
    streamed = _streamed("acme.js", "javascript", JAVASCRIPT_UNCLOSED_COMMENT_IN_TEMPLATE)

    assert indexed["analysis_status"] == "complete"
    for observed in (indexed, streamed):
        assert _kinded_lines(observed["security_sources"]) == {("http_request_input", 5)}


def test_the_line_scanner_reads_past_an_unclosed_block_comment() -> None:
    streamed = _streamed("acme.js", "javascript", JAVASCRIPT_UNCLOSED_COMMENT_AFTER_A_SINK)

    assert _kinded_lines(streamed["security_sinks"]) == {
        ("eval_exec", 1), ("eval_exec", 3), ("eval_exec", 4)
    }
    assert streamed["artifact_truncated"] is False


def test_restoring_an_unclosed_block_comment_keeps_the_closed_one_above_it() -> None:
    source = b"/* eval(dead); */\n/* acme\neval(live);\n"

    streamed = _streamed("acme.js", "javascript", source)

    assert _kinded_lines(streamed["security_sinks"]) == {("eval_exec", 3)}


def test_a_chunk_fed_scan_declares_the_sinks_an_unclosed_comment_cost_it() -> None:
    """A chunk-fed scan cannot re-read the bytes it already passed.

    `code-index build` feeds a file too large to parse exactly straight from
    the snapshot, so the bytes behind the scan are gone. The retained sink
    before the opener keeps the dimension off `unavailable_dimensions`, which
    means truncation is the only field left to carry the debt.
    """
    streamed = streaming_security_fallback(
        "acme.js",
        "javascript",
        iter([JAVASCRIPT_UNCLOSED_COMMENT_AFTER_A_SINK]),
        degradation_reason="forced_for_test",
    )

    assert _kinded_lines(streamed["security_sinks"]) == {("eval_exec", 1)}
    assert streamed["artifact_truncated"] is True
    assert "security_sinks" in streamed["truncated_dimensions"]


def test_a_block_comment_closed_in_a_later_chunk_of_its_line_hides_no_sink() -> None:
    """A line's `*/` lands wherever the line puts it, not in its first chunk.

    The scanner reads a line in window-sized pieces, so a line longer than one
    carries its close into a later piece. Leaving the block open there reads
    every line below it as commentary.
    """
    source = _oversized_block_comment_line() + b"\neval(second);\neval(third);\n"

    streamed = _streamed("acme.js", "javascript", source)

    assert _kinded_lines(streamed["security_sinks"]) == {
        ("eval_exec", 2), ("eval_exec", 3)
    }


@pytest.mark.parametrize("chunks", [
    pytest.param([b"<?php\n// legacy ?", b"><?php system($cmd);\n"], id="tag-closes-comment"),
    pytest.param([b"<?php\n#", b"[Acme] system($cmd);\n"], id="attribute-not-comment"),
])
def test_a_php_line_read_in_pieces_keeps_the_code_its_tag_puts_back(
    chunks: list[bytes],
) -> None:
    """A `?>` ends a `#`/`//` comment, and `#[` never opened one.

    Both verdicts need bytes a chunk boundary can land in the middle of: the
    closer may be in a later piece, and a `#` alone cannot be told from the
    `#[` of an attribute. Reading either as comment to the end of the line
    drops the code the line really runs.
    """
    source = b"".join(chunks)
    streamed = streaming_security_fallback(
        "acme.php", "php", iter(chunks), degradation_reason="forced_for_test"
    )

    assert _kinded_lines(streamed["security_sinks"]) == {("process_exec", 2)}
    assert _kinded_lines(_streamed("acme.php", "php", source)["security_sinks"]) == {
        ("process_exec", 2)
    }


def test_a_block_comment_close_split_across_two_chunks_still_closes_it() -> None:
    """The `*/` of a line can land either side of a chunk boundary.

    Reading past it leaves the block running to whatever `*/` comes next, and
    the lines between read as comment text on an otherwise clean artifact --
    the one loss nothing on the artifact declares.
    """
    # The banner ends exactly at the boundary, so its `*` closes one chunk
    # and its `/` opens the next.
    banner = b"/* " + b"x" * (STREAMING_SCAN_WINDOW_BYTES - 5) + b" */"
    source = banner + b"\neval(second);\n/* acme */\neval(third);\n"
    assert len(banner) == STREAMING_SCAN_WINDOW_BYTES + 1

    streamed = streaming_security_fallback(
        "acme.js",
        "javascript",
        iter([
            source[:STREAMING_SCAN_WINDOW_BYTES],
            source[STREAMING_SCAN_WINDOW_BYTES:],
        ]),
        degradation_reason="forced_for_test",
    )

    assert _kinded_lines(streamed["security_sinks"]) == {
        ("eval_exec", 2), ("eval_exec", 4)
    }
    assert streamed["artifact_truncated"] is False


def test_code_after_a_block_comment_close_on_an_oversized_line_is_read() -> None:
    """A line holding code anywhere is read whole, however long it is.

    Minified source puts a licence banner and the program it precedes on one
    line; reading the whole line as commentary because its first piece opened
    a comment drops the program.
    """
    source = _oversized_block_comment_line(tail=b" eval(tail);") + b"\n"

    streamed = _streamed("acme.js", "javascript", source)

    assert _kinded_lines(streamed["security_sinks"]) == {("eval_exec", 1)}
