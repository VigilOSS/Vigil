"""A1 / C4a — by-family coverage grid + the --for-dispatch COVERAGE block.

These CLI-side renderers project the pinned ``coverage-readiness/by-family``
payload; they live in ``agent/scripts/assess/lib/coverage_checks.py``. The tests
run in the BACKEND suite (not the assess-CLI suite) only because the backend
conftest is what puts ``agent/scripts`` on ``sys.path`` (via ``import app.main``)
— they still drive the renderers against SYNTHETIC fixture dicts that match the
pinned shape, never a live backend.

Pinned ``coverage-readiness/by-family`` shape:
    {"units": [{"application_unit_id", "host", "port_class", "path_prefix",
                "deep_required", "families": [{"family", "expected_reason",
                "status", "probe_count", "covering_probe_count", "has_finding",
                "finding_id"}]}],
     "totals": {"units", "cells", "covered", "missing_block", "missing_warn",
                "deferred", "with_finding"}}
    status ∈ covered | missing_block | missing_warn | deferred.
"""
from __future__ import annotations

from assess.lib import coverage_checks as cc


def _family(
    family: str,
    status: str,
    *,
    probe_count: int = 0,
    covering_probe_count: int = 0,
    has_finding: bool = False,
    finding_id: int | None = None,
    expected_reason: str = "",
) -> dict:
    return {
        "family": family,
        "expected_reason": expected_reason,
        "status": status,
        "probe_count": probe_count,
        "covering_probe_count": covering_probe_count,
        "has_finding": has_finding,
        "finding_id": finding_id,
    }


def _fixture_payload() -> dict:
    """One unit carrying a covered cell, a finding-linked covered cell, and two
    distinct gap cells (missing_block + a covered-status-but-zero-covering)."""
    return {
        "units": [
            {
                "application_unit_id": 12,
                "host": "app.example.com",
                "port_class": "web",
                "path_prefix": "/api",
                "deep_required": True,
                "families": [
                    _family(
                        "sqli",
                        "covered",
                        expected_reason="param:id",
                        probe_count=3,
                        covering_probe_count=2,
                    ),
                    _family(
                        "bola",
                        "covered",
                        expected_reason="path:id",
                        probe_count=4,
                        covering_probe_count=1,
                        has_finding=True,
                        finding_id=45,
                    ),
                    _family(
                        "ssrf",
                        "missing_block",
                        expected_reason="param:url",
                        probe_count=0,
                        covering_probe_count=0,
                    ),
                    _family(
                        "xss",
                        "missing_warn",
                        expected_reason="param:q",
                        probe_count=1,
                        covering_probe_count=0,
                    ),
                ],
            }
        ],
        "totals": {
            "units": 1,
            "cells": 4,
            "covered": 2,
            "missing_block": 1,
            "missing_warn": 1,
            "deferred": 0,
            "with_finding": 1,
        },
    }


# --------------------------------------------------------------------------- #
# render_family_ledger_text
# --------------------------------------------------------------------------- #


def _line_for(lines: list[str], token: str) -> str:
    matches = [ln for ln in lines if token in ln]
    assert matches, f"no line containing {token!r} in:\n" + "\n".join(lines)
    return matches[0]


def test_family_ledger_gap_cell_is_marked_distinctly():
    lines = cc.render_family_ledger_text(_fixture_payload())
    # A missing_block cell with zero covering probes is a GAP and reads distinctly.
    ssrf = _line_for(lines, "ssrf")
    assert "GAP" in ssrf, ssrf
    assert "MISSING-BLOCK" in ssrf, ssrf
    # A covered cell must NOT carry the GAP marker.
    sqli = _line_for(lines, "sqli")
    assert "GAP" not in sqli, sqli


def test_family_ledger_covered_cell_shows_verdict_and_counts():
    lines = cc.render_family_ledger_text(_fixture_payload())
    sqli = _line_for(lines, "sqli")
    assert "COVERED" in sqli, sqli
    # covering/total probe counts are visible on a covered cell.
    assert "[2/3 covering]" in sqli, sqli


def test_family_ledger_finding_linked_cell_is_flagged():
    lines = cc.render_family_ledger_text(_fixture_payload())
    bola = _line_for(lines, "bola")
    assert "finding#45" in bola, bola
    # The non-finding covered cell is NOT flagged with a finding id.
    sqli = _line_for(lines, "sqli")
    assert "finding#" not in sqli, sqli


def test_family_ledger_three_cell_kinds_render_distinctly():
    """The gap, covered, and finding-linked cells are visibly different lines."""
    lines = cc.render_family_ledger_text(_fixture_payload())
    gap = _line_for(lines, "ssrf")
    covered = _line_for(lines, "sqli")
    finding = _line_for(lines, "bola")
    assert gap != covered != finding
    assert "GAP" in gap and "GAP" not in covered and "GAP" not in finding
    assert "finding#45" in finding and "finding#" not in covered


def test_family_ledger_header_and_totals():
    lines = cc.render_family_ledger_text(_fixture_payload())
    header = _line_for(lines, "unit#12")
    assert "app.example.com" in header
    assert "/api" in header
    assert "deep-required" in header
    totals = _line_for(lines, "totals:")
    assert "2 covered" in totals
    assert "1 missing-block" in totals
    assert "1 with finding" in totals


def test_family_ledger_deferred_cell_is_not_a_gap():
    """A deferred family is a deliberate decision, not an unaddressed gap — it
    must NOT carry the GAP marker even with zero covering probes."""
    payload = {
        "units": [
            {
                "application_unit_id": 7,
                "host": "app.example.com",
                "port_class": "web",
                "path_prefix": "/",
                "deep_required": True,
                "families": [
                    _family("cmdi", "deferred", probe_count=0, covering_probe_count=0),
                ],
            }
        ],
        "totals": {"units": 1, "cells": 1, "covered": 0, "missing_block": 0,
                   "missing_warn": 0, "deferred": 1, "with_finding": 0},
    }
    lines = cc.render_family_ledger_text(payload)
    cmdi = _line_for(lines, "cmdi")
    assert "GAP" not in cmdi, cmdi
    assert "deferred" in cmdi, cmdi
    # And it is not offered as an OPEN gap to a dispatch either.
    block = cc.render_dispatch_coverage_block(payload, host="app.example.com")
    gaps = _line_for(block, "OPEN gaps:")
    assert "cmdi" not in gaps, gaps


def test_family_ledger_empty_units():
    lines = cc.render_family_ledger_text({"units": [], "totals": {}})
    assert any("no application-units" in ln for ln in lines), lines


def test_family_ledger_non_dict_payload():
    lines = cc.render_family_ledger_text(None)  # type: ignore[arg-type]
    assert lines and "unexpected response" in lines[0]


# --------------------------------------------------------------------------- #
# render_dispatch_coverage_block
# --------------------------------------------------------------------------- #


def _two_host_payload() -> dict:
    payload = _fixture_payload()
    # A second application-unit on a DIFFERENT host — must be filtered out when
    # the block is scoped to app.example.com.
    payload["units"].append(
        {
            "application_unit_id": 99,
            "host": "other.example.com",
            "port_class": "web",
            "path_prefix": "/",
            "deep_required": False,
            "families": [_family("idor", "missing_block")],
        }
    )
    return payload


def test_dispatch_block_is_scoped_to_host():
    lines = cc.render_dispatch_coverage_block(
        _two_host_payload(), host="app.example.com"
    )
    text = "\n".join(lines)
    assert text.startswith("COVERAGE: app.example.com")
    # Only the scoped host's unit renders; the other host is filtered out.
    assert "app.example.com" in text
    assert "other.example.com" not in text
    assert "idor" not in text  # the other host's family


def test_dispatch_block_lists_covered_and_open_gaps():
    lines = cc.render_dispatch_coverage_block(
        _two_host_payload(), host="app.example.com"
    )
    covered = _line_for(lines, "covered:")
    gaps = _line_for(lines, "OPEN gaps:")
    # sqli/bola are covered (bola flagged with its finding); ssrf/xss are gaps.
    assert "sqli" in covered
    assert "bola(finding#45)" in covered
    assert "ssrf" in gaps and "xss" in gaps
    assert "ssrf" not in covered


def test_dispatch_block_path_prefix_filter():
    lines = cc.render_dispatch_coverage_block(
        _two_host_payload(), host="app.example.com", path_prefix="/api"
    )
    assert any("OPEN gaps:" in ln for ln in lines)
    # A non-matching prefix yields the empty-scope message, not the unit.
    empty = cc.render_dispatch_coverage_block(
        _two_host_payload(), host="app.example.com", path_prefix="/nope"
    )
    assert any("no recorded coverage expectation" in ln for ln in empty), empty


def test_dispatch_block_unknown_host_is_open_surface():
    lines = cc.render_dispatch_coverage_block(
        _two_host_payload(), host="unmapped.example.com"
    )
    assert lines[0].startswith("COVERAGE: unmapped.example.com")
    assert any("treat the" in ln and "open" in ln for ln in lines), lines


def test_dispatch_block_host_is_case_insensitive():
    lines = cc.render_dispatch_coverage_block(
        _two_host_payload(), host="APP.EXAMPLE.COM"
    )
    assert any("OPEN gaps:" in ln for ln in lines), lines
