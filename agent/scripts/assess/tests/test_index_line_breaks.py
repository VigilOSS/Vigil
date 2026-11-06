"""Index line numbers follow the snapshot's line count.

The snapshot counts a line at every CR, LF or CRLF and nothing else, and a
callable span is refused past that count. A form feed, vertical tab, NEL or
Unicode line separator inside a string or comment therefore stays on its line,
and a file whose lines end in a bare CR is numbered line by line.
"""
from __future__ import annotations

import pytest

from assess.lib.code_snapshot import capture_regular_file
from assess.lib.treesitter_index import index_file

_SOURCES = {
    "acme.php": (
        "php",
        ["<?php", "$s = 'a{}b';", "system($_GET['c']);", "function f($c) {", "  system($c);", "}"],
        [("f", 4, 6)],
        {("process_exec", 3), ("process_exec", 5)},
    ),
    "acme.py": (
        "python",
        ["import os", "s = 'a{}b'", "os.system(input())", "def f(c):", "    os.system(c)"],
        [("f", 4, 5)],
        {("process_exec", 3), ("process_exec", 5)},
    ),
    "acme.c": (
        "c",
        ["#include <stdlib.h>", "/* a{}b */", "int f(char *c) {", "  return system(c);", "}"],
        [("f", 3, 5)],
        {("process_exec", 4)},
    ),
    "Dockerfile": (
        "dockerfile",
        ["FROM alpine", "# a{}b", "USER app", "RUN curl https://example.com/x | sh"],
        None,
        {("remote_pipe_to_shell", 4)},
    ),
    "acme.sh": (
        "shell",
        ["#!/bin/sh", "# a{}b", "run() {", "  eval \"$1\"", "}"],
        [("run", 3, 5)],
        {("shell_eval", 4)},
    ),
}

_BREAKS = {
    "form_feed": ("\f", "\n"),
    "vertical_tab": ("\v", "\n"),
    "next_line": ("\x85", "\n"),
    "line_separator": (" ", "\n"),
    "paragraph_separator": (" ", "\r\n"),
    "cr_only": ("", "\r"),
}


@pytest.mark.parametrize("name", sorted(_SOURCES))
@pytest.mark.parametrize("variant", sorted(_BREAKS))
def test_index_lines_match_snapshot_line_count(tmp_path, name, variant) -> None:
    language, lines, functions, sinks = _SOURCES[name]
    inner, newline = _BREAKS[variant]
    source = (newline.join(lines).replace("{}", inner) + newline).encode()
    path = tmp_path / name
    path.write_bytes(source)
    captured = capture_regular_file(path, retain_spool=False)

    indexed = index_file(name, language, source)

    assert captured.loc == len(lines)
    assert indexed["total_lines"] == captured.loc
    if functions is not None:
        assert [
            (function["name"], function["line_start"], function["line_end"])
            for function in indexed["functions"]
        ] == functions
    assert sinks <= {(sink["kind"], sink["line"]) for sink in indexed["security_sinks"]}
