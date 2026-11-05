"""The indexer's fast paths return exactly what the plain readers return.

Each test pins an equivalence the indexer relies on to skip work: the
structural path's bounded source scan runs a sources-only scanner, and the
line readers gate each pattern on a literal every match must contain. The
reference is always the unoptimised reading of the same Acme fixture.
"""
from __future__ import annotations

import re

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
