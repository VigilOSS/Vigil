"""File scope is a scan scope of its own, in every tree-sitter language.

Module-level code executes when the file is loaded or requested, so a reader
that only walks callable bodies leaves it unread -- and ADR 0015 forbids
reporting that unread scope as a clean negative. These tests pin the
``<top-level>`` scope over files with no callable at all, and the
grammar-labelled content it deliberately does not read (commentary, docstrings,
declarations).
"""
from __future__ import annotations

from assess.lib import treesitter_index
from assess.lib.treesitter_index import index_file


def _line_carrying(needle: str, source: bytes) -> int:
    lines = source.decode().splitlines()
    matches = [number for number, line in enumerate(lines, 1) if needle in line]
    assert len(matches) == 1, f"{needle!r} is not unique in fixture: {matches}"
    return matches[0]


def _sinks(indexed: dict) -> list[tuple[str, str, int]]:
    return [
        (sink["kind"], sink["function"], sink["line"])
        for sink in indexed["security_sinks"]
    ]


# --- 1. Module-level code is read without a callable -------------------------

PYTHON_SETTINGS = b"""import os

DB_HOST = os.environ.get("DB_HOST", "db.example.com")
TIMEOUT = 30
"""


def test_a_constants_module_is_a_measured_file() -> None:
    indexed = index_file("acme/settings.py", "python", PYTHON_SETTINGS)

    assert indexed["total_functions"] == 0
    assert indexed["analysis_status"] == "complete"
    assert indexed["unavailable_dimensions"] == []
    assert ("<top-level>", "os.environ.get") in {
        (call["caller"], call["callee"]) for call in indexed["call_sites"]
    }


PYTHON_SCRIPT = b"""import subprocess
import sys

subprocess.call("rotate " + sys.argv[1], shell=True)
"""


def test_a_module_level_sink_is_reported_without_a_callable() -> None:
    indexed = index_file("acme/rotate.py", "python", PYTHON_SCRIPT)

    assert ("process_exec", "<top-level>", _line_carrying("subprocess.call", PYTHON_SCRIPT)) in _sinks(indexed)
    assert indexed["analysis_status"] == "complete"


PYTHON_DOCSTRING_EXAMPLE = b'''"""Acme backup helpers.

Example::

    os.system("backup " + target)
    eval(expression)
"""

RETENTION_DAYS = 7
'''


def test_a_module_docstring_example_is_not_a_sink() -> None:
    """The docstring is a string the grammar labels; nothing in it executes."""
    indexed = index_file("acme/backup.py", "python", PYTHON_DOCSTRING_EXAMPLE)

    assert indexed["security_sinks"] == []
    assert indexed["call_sites"] == []
    assert indexed["analysis_status"] == "complete"


# --- 2. Declarations hold no executable code ---------------------------------

TYPESCRIPT_TYPES = b"""export interface UserStore {
  find(id: string): Promise<User>;
  exec(query: string): void;
}

export type Loader = { load(path: string): Buffer };
declare function spawn(cmd: string): void;
"""


def test_typescript_declarations_carry_no_call_sites() -> None:
    """A type-only module has no callable and no file-scope entry catalogue, so
    the entry dimension stays unavailable -- but the trio is measured."""
    indexed = index_file("acme/types.ts", "typescript", TYPESCRIPT_TYPES)

    assert indexed["call_sites"] == []
    assert indexed["security_sinks"] == []
    assert indexed["unavailable_dimensions"] == ["entry_points"]


GO_INTERFACE = b"""package store

type Store interface {
	Get(id string) (string, error)
	Exec(query string) error
}
"""


def test_a_go_interface_declaration_carries_no_call_sites() -> None:
    indexed = index_file("store/store.go", "go", GO_INTERFACE)

    assert indexed["call_sites"] == []
    assert indexed["unavailable_dimensions"] == ["entry_points"]


GO_PACKAGE_STATE = b"""package acme

import "os"

var target = os.Getenv("ACME_TARGET")
"""


def test_a_go_package_initializer_is_read() -> None:
    indexed = index_file("acme/state.go", "go", GO_PACKAGE_STATE)

    assert ("<top-level>", "os.Getenv") in {
        (call["caller"], call["callee"]) for call in indexed["call_sites"]
    }


C_MACRO_HEADER = b"""#include <stdio.h>
#define RUN(cmd) system(cmd)
#define FETCH(url) popen(url, "r")
"""


def test_a_c_macro_body_is_read_as_file_scope() -> None:
    """`#` opens a preprocessor directive in C, not a comment. A macro wrapping
    `system` is the wrapper every caller reaches the sink through."""
    indexed = index_file("acme/macros.h", "c", C_MACRO_HEADER)

    assert ("process_exec", "<top-level>", 2) in _sinks(indexed)


C_CONDITIONAL_HEADER = b"""#if defined(__linux__)
#define ACME_PLATFORM "linux"
#endif
"""


def test_a_preprocessor_defined_test_is_not_a_call_site() -> None:
    """Read as file scope, `#if defined(X)` is the preprocessor's operator."""
    indexed = index_file("acme/platform.h", "c", C_CONDITIONAL_HEADER)

    assert indexed["call_sites"] == []
    assert not set(indexed["unavailable_dimensions"]) & treesitter_index.FUNCTION_SCOPED_DIMENSIONS


C_PROTOTYPE_HEADER = b"""#ifndef ACME_API_H
#define ACME_API_H
int run_command(const char *cmd);
#endif
"""


def test_a_header_of_prototypes_is_measured_clean() -> None:
    """A prototype is a declaration the grammar labels, so the readers had no
    executable line left to read: the empty result is the measurement."""
    indexed = index_file("acme/api.h", "c", C_PROTOTYPE_HEADER)

    assert indexed["security_sinks"] == []
    assert indexed["call_sites"] == []
    assert indexed["analysis_status"] == "complete"
    assert indexed["unavailable_dimensions"] == []


JAVA_ONE_LINE_CLASS = b"""class Runner { static { Runtime.getRuntime().exec(System.getenv("CMD")); } }
"""


def test_a_sink_on_a_declaration_header_line_is_unread_signal() -> None:
    """The top-level scope does not read class header lines. When one carries a
    sink the readers never reported, the trio is declared, not claimed clean."""
    indexed = index_file("Runner.java", "java", JAVA_ONE_LINE_CLASS)

    assert indexed["security_sinks"] == []
    assert set(indexed["unavailable_dimensions"]) >= treesitter_index.FUNCTION_SCOPED_DIMENSIONS


def test_the_same_initializer_on_its_own_lines_is_read() -> None:
    source = b"""class Runner {
  static {
    Runtime.getRuntime().exec(System.getenv("CMD"));
  }
}
"""
    indexed = index_file("Runner.java", "java", source)

    assert _sinks(indexed) == [("process_exec", "<top-level>", 3)]


PHP_PAGE_PROSE = b"""<?php require 'header.php'; ?>
<p>Print this page, then eval(uate) the totals by hand.</p>
<?php echo htmlspecialchars($title); ?>
"""


def test_php_inline_html_is_document_text_not_php() -> None:
    """Inline HTML is what the server sends back verbatim; the words in it are
    not PHP, so `Print` and `eval(` in prose are not sinks."""
    indexed = index_file("acme/page.php", "php", PHP_PAGE_PROSE)

    assert _line_carrying("Print this page", PHP_PAGE_PROSE) not in {
        sink["line"] for sink in indexed["security_sinks"]
    }
    assert indexed["analysis_status"] == "complete"
