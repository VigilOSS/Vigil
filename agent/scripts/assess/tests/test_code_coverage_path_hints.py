"""`code-coverage --cwe-matrix` shows path-suggested families as advisory hints.

A word in a file's path (`Checkout`, `refunds`) points a hunter at workflow
review without making it owed: the matrix columns and their `!` threshold
flags stay the backend's required families, and the hints print beside them.
"""
from __future__ import annotations

from assess.commands.code_coverage import _print_cwe_matrix


def _file(**overrides) -> dict:
    return {
        "file_path": "src/Checkout/Cart/PriceStruct.php",
        "classification": "critical",
        "total_functions": 0,
        "applicable_families": ["algorithmic-dos", "error-handling"],
        "path_suggested_families": ["business-logic", "race-condition"],
        "cwe_coverage": [
            {"family": "algorithmic-dos", "effort": 80},
            {"family": "error-handling", "effort": 80},
        ],
        **overrides,
    }


def test_path_hints_print_beside_the_matrix_and_never_as_owed_columns(capsys) -> None:
    _print_cwe_matrix([_file()])

    out = capsys.readouterr().out
    header = next(line for line in out.splitlines() if line.startswith("File"))
    assert "race-condit" not in header
    assert "0!" not in out
    (hint,) = [line for line in out.splitlines() if "race-condition" in line]
    assert "PriceStruct.php" in hint and "business-logic" in hint


def test_a_recorded_hint_reports_its_effort(capsys) -> None:
    coverage = [*_file()["cwe_coverage"], {"family": "race-condition", "effort": 60}]
    _print_cwe_matrix([_file(cwe_coverage=coverage)])

    (hint,) = [
        line
        for line in capsys.readouterr().out.splitlines()
        if "business-logic" in line
    ]
    assert "race-condition 60" in hint


def test_files_without_hints_print_no_hint_section(capsys) -> None:
    _print_cwe_matrix([_file(path_suggested_families=[])])

    assert "business-logic" not in capsys.readouterr().out
