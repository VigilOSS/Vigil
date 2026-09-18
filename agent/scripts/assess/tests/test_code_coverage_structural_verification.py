"""The `code-coverage` structural cross-check must not clear a file it skipped.

`_print_structural_verification` compares `functions_analyzed` against
`total_functions`, so it skipped every zero-function file and then printed an
all-clear covering it. A file whose structural index declares its function-scoped
dimensions unavailable was never measured at all: it is the one thing this
section exists to surface, and it was the one thing it hid.
"""
from __future__ import annotations

from assess.commands.code_coverage import (
    FUNCTION_SCOPED_DIMENSIONS,
    _print_structural_verification,
)


def _file(**overrides) -> dict:
    return {
        "file_path": "src/parser.py",
        "classification": "critical",
        "total_functions": 0,
        "structural_unavailable_dimensions": [],
        "cwe_coverage": [],
        **overrides,
    }


def _unscanned(**overrides) -> dict:
    return _file(
        file_path="routes/web.php",
        # Derived, not restated: dropping a dimension from the shared constant
        # must break this fixture rather than leave it pinning a stale list.
        structural_unavailable_dimensions=sorted(
            {*FUNCTION_SCOPED_DIMENSIONS, "entry_points"}
        ),
        **overrides,
    )


def test_an_unscanned_scope_file_is_named_and_never_cleared(capsys) -> None:
    _print_structural_verification([_unscanned()])

    out = capsys.readouterr().out
    assert "routes/web.php" in out
    assert "All indexed files report" not in out


def test_an_unscanned_scope_file_suppresses_the_all_clear_beside_covered_files(
    capsys,
) -> None:
    covered = _file(
        total_functions=2,
        cwe_coverage=[{"family": "injection", "functions_analyzed": 2}],
    )

    _print_structural_verification([covered, _unscanned()])

    out = capsys.readouterr().out
    assert "routes/web.php" in out
    assert "All indexed files report" not in out


def test_fully_covered_measured_files_still_report_the_all_clear(capsys) -> None:
    covered = _file(
        total_functions=2,
        cwe_coverage=[{"family": "injection", "functions_analyzed": 2}],
    )

    _print_structural_verification([covered])

    assert "All indexed files report" in capsys.readouterr().out


def test_a_file_with_nothing_indexed_prints_no_section(capsys) -> None:
    _print_structural_verification([_file()])

    assert capsys.readouterr().out == ""
