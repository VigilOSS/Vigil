"""Below-floor families no depth_floor trigger covers are printed, never gated."""
from __future__ import annotations

from assess.commands import code_coverage, transition_phase

_SHORTFALLS = {
    "total": 3,
    "file_count": 2,
    "groups": [
        {"classification": "critical", "family": "ssrf", "threshold": 70, "file_count": 2,
         "sample_file_paths": ["static/js/app.example.js"]},
        {"classification": "high", "family": "file-upload", "threshold": 50, "file_count": 1,
         "sample_file_paths": ["static/js/vendor.example.js"]},
    ],
    "detail": "They do not block. `vigil assess code-dispatch reanalyze ...`",
}


def test_code_coverage_prints_each_group_with_its_paths_and_the_remainder(capsys) -> None:
    code_coverage._print_untriggered_depth_shortfalls({"gate": {"untriggered_depth_shortfalls": _SHORTFALLS}})

    out = capsys.readouterr().out
    assert "3 critical/high famil(ies) on 2 file(s)" in out
    assert "critical ssrf (< 70): 2 file(s): static/js/app.example.js +1 more" in out
    assert "reanalyze" in out


def test_transition_phase_carries_them_as_a_non_blocking_advisory() -> None:
    (item,) = transition_phase._code_readiness_advisories({"untriggered_depth_shortfalls": _SHORTFALLS})

    assert item["kind"] == "code_untriggered_depth_shortfalls"
    assert item["severity"] == "advisory"
    assert "critical ssrf 2" in item["detail"] and "high file-upload 1" in item["detail"]


def test_the_matrix_read_prints_every_row_and_the_summary_names_that_read(capsys) -> None:
    rows = [
        {"file_path": "static/js/app.example.js", "classification": "critical", "family": "ssrf",
         "effort": 10, "threshold": 70},
        {"file_path": "static/js/chunk.example.js", "classification": "critical", "family": "ssrf",
         "effort": 0, "threshold": 70},
        {"file_path": "static/js/vendor.example.js", "classification": "high",
         "family": "file-upload", "effort": 20, "threshold": 50},
    ]
    code_coverage._print_untriggered_depth_shortfalls(
        {"gate": {"untriggered_depth_shortfalls": {**_SHORTFALLS, "rows": rows, "rows_omitted": 0}}}
    )
    listed = capsys.readouterr().out
    for row in rows:
        assert f"{row['file_path']}: {row['family']} {row['effort']} < {row['threshold']}" in listed

    code_coverage._print_untriggered_depth_shortfalls({"gate": {"untriggered_depth_shortfalls": {
        **_SHORTFALLS, "rows_omitted": 3, "full_list": "vigil assess code-coverage --cwe-matrix",
    }}})
    grouped = capsys.readouterr().out
    assert "3 row(s) not listed; every row: vigil assess code-coverage --cwe-matrix" in grouped
