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
from assess.lib.treesitter_common import _gate_literals, _literal_gate, _required_literals
from assess.lib.treesitter_index import _function_scoped_reader_patterns
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
