"""The indexer's fast paths return exactly what the plain readers return.

Each test pins an equivalence the indexer relies on to skip work: the
structural path's bounded source scan runs a sources-only scanner, and the
line readers gate each pattern on a literal every match must contain. The
reference is always the unoptimised reading of the same Acme fixture.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from assess.lib.code_languages import STRUCTURAL_SUPPORTED_LANGUAGES
from assess.lib.treesitter_catalogues import _SINK_DEFINITIONS
from assess.lib.treesitter_common import _gate_literals, _literal_gate, _required_literals
from assess.lib.treesitter_index import _function_scoped_reader_patterns, index_file
from assess.lib.treesitter_streaming import (
    StreamingSecurityScanner,
    _attach_bounded_security_sources,
    _fallback_from_bytes,
)

ACME_PHP_PAGE = b"""<?php
namespace Acme\\Billing;
use Acme\\Models\\Invoice;
use function Acme\\Support\\format_money;
// $_GET['commented'] is not read
# getenv('COMMENTED') is not read either
$invoice = $_GET['invoice'];
$token = getenv('ACME_TOKEN'); system($_POST['cmd']);
include 'acme/header.php';
""" + b"$wide = '" + b"x" * 70_000 + b"' . $_COOKIE['session'];\n" + b"""
final class InvoiceController { use Acme\\Concerns\\Loggable; }
echo $request->input('name');
"""


def test_the_structural_source_scan_reads_what_the_full_fallback_reads() -> None:
    attached = _attach_bounded_security_sources(
        {}, file_path="public/invoice.php", language="php", source=ACME_PHP_PAGE
    )
    full = _fallback_from_bytes(
        "public/invoice.php", "php", ACME_PHP_PAGE, degradation_reason="test"
    )

    assert attached["security_sources"] == full["security_sources"]
    assert attached["signal_counts"]["security_sources"] == full["signal_counts"]["security_sources"]
    assert {source["line"] for source in full["security_sources"]} == {7, 8, 10, 13}


def test_a_sources_only_scanner_keeps_the_source_signal_limit() -> None:
    source = b"".join(b"$a%d = $_GET['k'];\n" % index for index in range(12))
    scanners = [
        StreamingSecurityScanner("public/list.php", "php", signal_limit=5, sources_only=only)
        for only in (False, True)
    ]
    observed = []
    for scanner in scanners:
        scanner.feed(source)
        observed.append(scanner.finish(degradation_reason="test"))

    full, sources_only = observed
    assert sources_only["security_sources"] == full["security_sources"]
    assert sources_only["signal_counts"]["security_sources"] == 12
    assert "security_sources" in sources_only["truncated_dimensions"]
    assert re.search(r"\$_GET", sources_only["security_sources"][0]["snippet"])


@pytest.mark.parametrize(
    "pattern, expected",
    [
        (re.compile(r"(?<!->)(?<!::)\bunlink\s*\("), {"unlink"}),
        # An optional group requires nothing; the literal after it does.
        (re.compile(r"(?:ab)?cde"), {"cde"}),
        # Every branch needs one of its own, or the alternation needs none.
        (re.compile(r"->(?:(?:or)?(?:where|having)Raw|selectRaw)\s*\("), {"where", "having", "selectRaw"}),
        (re.compile(r"\$\w+->(?:query|\w+Raw)\s*\("), {"query", "Raw"}),
        (re.compile(r"(?:ab)+c"), {"ab"}),
        (re.compile(r"\b\w+\s*\("), {"("}),
        (re.compile(r"\b\w+\b"), None),
        # A case-blind str literal is not a substring test.
        (re.compile(r"(?i:exec)\s*\(\s*shell"), {"shell"}),
        (re.compile(r"shell", re.IGNORECASE), None),
        # Bytes compare lowered, matching their ASCII-only case folding.
        (re.compile(rb"(?-i:\bSTDIN\b)|php://stdin", re.IGNORECASE), {b"stdin", b"php://stdin"}),
        (re.compile(rb"\$_(?:GET|POST)\b", re.IGNORECASE), {b"get", b"post"}),
    ],
)
def test_required_literals_are_what_every_match_contains(pattern, expected) -> None:
    assert _required_literals(pattern) == (None if expected is None else frozenset(expected))


def _catalogue_patterns() -> list[re.Pattern]:
    patterns: list[re.Pattern] = [
        compiled
        for language in STRUCTURAL_SUPPORTED_LANGUAGES
        for compiled in _function_scoped_reader_patterns(language)
    ]
    for language in STRUCTURAL_SUPPORTED_LANGUAGES:
        scanner = StreamingSecurityScanner("acme.txt", language)
        patterns.extend(pattern for _kind, pattern, _classes in scanner._sink_patterns)
        patterns.extend(pattern for _kind, pattern in scanner._source_patterns)
        patterns.extend(pattern for _kind, pattern in scanner._entry_patterns)
        patterns.extend(scanner._import_patterns)
    return patterns


def test_no_catalogue_match_lies_on_a_line_its_gate_rejects() -> None:
    # The signal fixtures beside this file are a corpus written to match the
    # catalogues; every line one of them matches must pass that pattern's gate.
    lines = [
        line
        for glob in ("test_*_index_signals.py", "test_*catalogue*.py", "test_indexer_*.py")
        for path in sorted(Path(__file__).parent.glob(glob))
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    checked = 0
    for pattern in _catalogue_patterns():
        literals = _gate_literals(pattern)
        if literals is None:
            continue
        gate = _literal_gate((pattern,))
        for line in lines:
            text = line.encode() if isinstance(pattern.pattern, bytes) else line
            if pattern.search(text):
                checked += 1
                lowered = text.lower() if isinstance(text, bytes) else text
                assert gate.search(lowered), (pattern.pattern, line)
                assert any(literal in lowered for literal in literals)
    assert checked > 500


ACME_C_TOOL = """\
#include <stdio.h>
#define RUN(cmd) system(cmd)
// system("commented out") is not read
static char banner[64];

int acme_copy(char *dst, const char *src, FILE *log) {
    fprintf(log, src); sprintf(dst, "%s", src); memcpy(dst, src, 4);
    char *buf = malloc(16); free(buf); popen(src, "r");
    return printf("%s", dst);
}
"""


def test_sinks_follow_catalogue_order_whatever_lines_the_gate_admits() -> None:
    # The reference reading: every catalogue pattern over every scannable
    # line of each scope, one record per kind and line. C applies no
    # receiver filter, so the reference is exactly the line readers' order.
    indexed = index_file("src/acme_copy.c", "c", ACME_C_TOOL.encode())
    lines = ACME_C_TOOL.splitlines()
    scopes = [
        (function["name"], range(function["line_start"] - 1, function["line_end"]))
        for function in indexed["functions"]
    ] + [("<top-level>", [1])]
    expected: list[tuple[str, int, str]] = []
    for name, indices in scopes:
        seen: set[tuple[str, int]] = set()
        for definition in _SINK_DEFINITIONS:
            for pattern in definition["patterns"].get("c", []):
                for index in indices:
                    if not lines[index].strip() or lines[index].strip().startswith("//"):
                        continue
                    if re.search(pattern, lines[index]) and (definition["kind"], index) not in seen:
                        seen.add((definition["kind"], index))
                        expected.append((definition["kind"], index + 1, name))

    assert [
        (sink["kind"], sink["line"], sink["function"]) for sink in indexed["security_sinks"]
    ] == expected
    assert len({line for _kind, line, _name in expected}) == 4


def test_callables_sharing_a_minified_line_each_read_its_registrations() -> None:
    # One line spans both callables, so the second reads the line-pattern
    # answers the first already computed for it.
    source = (
        b'function outer(){function inner(){return 1}'
        b'module.exports=inner;app.get("/acme",inner)}\n'
    )
    indexed = index_file("dist/acme.min.js", "javascript", source)

    assert [(entry["name"], entry["kind"]) for entry in indexed["entry_points"]] == [
        ("outer", "module_exports"),
        ("inner", "express_route"),
    ]


def test_only_signals_inside_code_that_could_run_open_a_segment() -> None:
    # Both declarations carry a source; the literal table is skipped without
    # walking it when no signal lies inside, and read when one does.
    source = b"""static const char *acme_help[] = {
    "usage: set ACME_HOME, read with getenv(name)",
    "done",
};
static const char *acme_home = getenv("ACME_HOME");
int acme_main(void) { return 0; }
"""
    indexed = index_file("src/acme.c", "c", source)

    assert [source["line"] for source in indexed["security_sources"]] == [2, 5]
    assert indexed["top_level_segments"] == [{"line_start": 5, "line_end": 5}]


def test_lines_framed_in_place_read_like_lines_framed_through_the_buffer() -> None:
    # A whole short line is scanned in place; a line split across chunks or
    # longer than a window goes through the buffer. Both framings, every
    # separator form and a separator split across chunks read the same.
    source = (
        b"<?php\r\n$a = $_GET['a'];\r\n// system($_GET['c']);\rsystem($b);\n"
        b"$wide = '" + b"x" * 150 + b"' . $_POST['p'] . exec($c);\r\n\r\n$e = getenv('ACME');\r"
    )
    observed = []
    for size in (3, 7, 64, len(source)):
        scanner = StreamingSecurityScanner(
            "public/acme.php", "php", window_bytes=64, overlap_bytes=16
        )
        for offset in range(0, len(source), size):
            scanner.feed(source[offset : offset + size])
        observed.append(scanner.finish(degradation_reason="test"))

    assert all(result == observed[0] for result in observed)
    assert observed[0]["total_lines"] == 7
    assert [sink["line"] for sink in observed[0]["security_sinks"]] == [4, 5]
    assert [source["line"] for source in observed[0]["security_sources"]] == [2, 5, 7]
