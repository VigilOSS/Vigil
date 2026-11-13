"""code-coverage reads each scope once and reports each advisory once."""
from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest
from _fake_client import StubClient

from assess.commands import check_phase_readiness, code_coverage
from assess.lib.phases import CODE_PHASES


def _args(**fields):
    base = dict(
        engagement_dir=None, repo_id=None, cwe_matrix=False,
        require_gate_pass=False, require_transition_ready=None,
    )
    base.update(fields)
    return SimpleNamespace(**base)


def _offline(monkeypatch, module, tmp_path, client=None, *, code_phase="hunt"):
    (tmp_path / "scope.json").write_text(json.dumps({
        "engagement_type": "offensive", "tracks": {"code": {"phase": code_phase}},
    }), encoding="utf-8")
    if client is not None:
        monkeypatch.setattr(module, "AssessmentClient", client)
    monkeypatch.setattr(module, "load_config", lambda *_a: SimpleNamespace(
        base_url="http://example.test", engagement_key="acme",
        engagement_dir=str(tmp_path),
    ))


def _gap(tier, family, path, effort=10, threshold=50):
    message = f"{tier.capitalize()} file {path}: family '{family}' effort {effort} < {threshold}"
    return {"classification": tier, "family": family, "file_path": path,
            "effort": effort, "threshold": threshold, "message": message}


def _effort_gaps(gaps, *, rows=False, warnings=None):
    """`gate.effort_gaps` as the backend sends it: grouped, rows only on request.

    *warnings* are the lines of the same read's `effort_warnings` that carry the
    shortfalls; by default the per-file messages."""
    groups: dict[tuple[str, str], dict] = {}
    for gap in gaps:
        group = groups.setdefault((gap["classification"], gap["family"]), {
            "classification": gap["classification"], "family": gap["family"],
            "threshold": gap["threshold"], "paths": set(),
        })
        group["paths"].add(gap["file_path"])
    summary = {
        "total": len(gaps),
        "file_count": len({gap["file_path"] for gap in gaps}),
        "groups": [
            {"classification": group["classification"], "family": group["family"],
             "threshold": group["threshold"], "file_count": len(group["paths"]),
             "sample_file_paths": sorted(group["paths"])[:3]}
            for group in groups.values()
        ],
        "rows_omitted": 0 if rows else len(gaps),
        "warnings": list(warnings) if warnings is not None else [gap["message"] for gap in gaps],
    }
    if rows:
        summary["rows"] = list(gaps)
    elif gaps:
        summary["full_list"] = "vigil assess code-coverage --cwe-matrix (GET code/coverage?detail=cwe)"
    return summary


def _gate(gaps, integrity=(), *, rows=False, other=()):
    return {
        "passed": True, "reasons": [],
        "effort_warnings": [*other, *(gap["message"] for gap in gaps)],
        "effort_gaps": _effort_gaps(gaps, rows=rows),
        "coverage_integrity": list(integrity),
    }


def test_repo_scoped_table_counts_only_that_repos_skip_debt(monkeypatch, tmp_path, capsys):
    requested: list[str] = []

    class _Client(StubClient):
        def get(self, path):
            requested.append(path)
            if path.startswith("code/coverage"):
                return {"total_files": 2, "by_classification": {"skip": {"count": 2, "analyzed": 0}},
                        "by_status": {}, "gate": _gate([])}
            return {"target_phase": "verify-variant", "transition_ready": False, "blockers": [],
                    "structural_debt_count": 7,
                    "structural_debt": [
                        {"repo_id": 1 if i < 2 else 2, "file_path": f"acme/f{i}.py",
                         "classification": "skip", "structural_analysis_status": "unsupported",
                         "structural_artifact_truncated": False}
                        for i in range(7)]}

    _offline(monkeypatch, code_coverage, tmp_path, _Client)
    code_coverage.run(_args(engagement_dir=tmp_path, repo_id="1"))
    out = capsys.readouterr().out
    skip_line = next(line for line in out.splitlines() if line.strip().startswith("skip"))
    assert "structural debt: 2" in skip_line
    # The repo table and the engagement-wide gate are different scopes, so both are read
    # and the output says which is which.
    assert requested == [
        "code/coverage?repo_id=1",
        "code/readiness?target_phase=verify-variant&include_debt_paths=true",
    ]
    assert "engagement-wide" in out
    assert "structural debt: 7 file(s)" in out


def test_default_view_groups_effort_gaps_and_lists_each_advisory_once(
    monkeypatch, tmp_path, capsys
):
    gaps = [
        _gap("high", "ssrf", "acme/a.py"), _gap("high", "ssrf", "acme/b.py"),
        _gap("high", "ssrf", "acme/c.py"), _gap("high", "ssrf", "acme/d.py"),
        _gap("medium", "error-handling", "acme/a.py", threshold=30),
    ]
    integrity = [{"file_path": "acme/e.py", "classification": "critical",
                  "warnings": ["effort=80 with 0 source-review receipts"]}]
    structural = "acme/README has no structural parser; direct source review required"
    missing = "High file acme/f.py: analyzed but missing CWE coverage data"
    coverage = {"total_files": 5, "by_status": {},
                "gate": _gate(gaps, integrity, other=[missing])}
    readiness = {
        "target_phase": "hunt", "transition_ready": True, "blockers": [],
        "quality_gate": {"passed": False, "warnings": [
            structural, *(gap["message"] for gap in gaps),
            "acme/e.py: effort=80 with 0 source-review receipts",
        ]},
        "coverage": coverage,
    }

    class _Client(StubClient):
        def get(self, path):
            return readiness

    _offline(monkeypatch, code_coverage, tmp_path, _Client)
    code_coverage.run(_args(engagement_dir=tmp_path, require_transition_ready="hunt"))
    out = capsys.readouterr().out
    assert out.count(structural) == 1
    for gap in gaps:
        assert gap["message"] not in out
    assert "high x ssrf: 4 file(s) — acme/a.py, acme/b.py, acme/c.py +1 more" in out
    assert "medium x error-handling: 1 file(s) — acme/a.py" in out
    assert "critical: 1 file(s) — acme/e.py" in out
    # The one effort warning that is not a family gap is still listed, once.
    assert out.count(missing) == 1
    assert "Effort below tier threshold: 5 family gap(s) across 4 file(s)" in out
    assert "--cwe-matrix" in out


def test_cwe_matrix_lists_every_advisory_and_thin_callable_claims(capsys):
    gaps = [_gap("high", "ssrf", f"acme/{i}.py") for i in range(5)]
    code_coverage._print_review_quality({"gate": _gate(gaps, rows=True)}, full=True)
    out = capsys.readouterr().out
    assert all(gap["message"] in out for gap in gaps)

    code_coverage._print_cwe_matrix([{
        "file_path": "acme/parser.py", "classification": "high", "total_functions": 20,
        "applicable_families": ["ssrf"],
        "cwe_coverage": [{"family": "ssrf", "effort": 60, "functions_analyzed": 20}],
        "analysis_effort": {"distinct_structural_callables_reviewed": 2},
    }])
    assert "functions_analyzed=20 claimed, 2 structurally bound callable(s) recorded (ratio=0.10)" in (
        capsys.readouterr().out
    )


def test_skip_closed_files_are_not_sent_back_to_the_queue(capsys):
    code_coverage._print_analysis_status({
        "by_status": {"analyzed": 1, "classified": 1},
        "confidence": {
            "skip_reasons": {"generated-code": 1}, "classified_accounted_skips": 1,
        },
    })
    out = capsys.readouterr().out
    assert "closed `skipped`" in out
    assert "code-dispatch queue" not in out


def test_unreviewed_classified_files_beside_skips_are_still_sent_to_the_queue(capsys):
    code_coverage._print_analysis_status({
        "by_status": {"classified": 5},
        "confidence": {
            "skip_reasons": {"generated-code": 2}, "classified_accounted_skips": 2,
        },
    })
    out = capsys.readouterr().out
    assert "NOTE: 2 classified file(s) are closed `skipped`" in out
    assert "NOTE: 3 classified file(s)" in out and "code-dispatch queue" in out


def test_skip_split_reads_the_classified_buckets_own_accounted_skips(capsys):
    # Skip reasons also count files outside the `classified` bucket (retired,
    # reclassified, or closed without a proven claim); the split must not.
    code_coverage._print_analysis_status({
        "by_status": {"classified": 5, "pending": 2},
        "confidence": {
            "skip_reasons": {"generated-code": 4}, "classified_accounted_skips": 1,
        },
    })
    out = capsys.readouterr().out
    assert "NOTE: 1 classified file(s) are closed `skipped`" in out
    assert "NOTE: 4 classified file(s) have neither" in out


def _phase_readiness(monkeypatch, tmp_path, capsys, tracks, phase):
    (tmp_path / "scope.json").write_text(json.dumps({
        "engagement_type": "offensive", "tracks": tracks,
    }), encoding="utf-8")
    monkeypatch.setattr(check_phase_readiness, "load_config", lambda *_: SimpleNamespace(
        engagement_dir=str(tmp_path), engagement_key="acme", base_url="http://unused"))
    requested: list[str] = []

    class _Client(StubClient):
        def get(self, path):
            requested.append(path)
            return {"report_readiness": {"ready": True, "blockers": []}, "intel": {}}

        def get_engagement(self, path):
            return {}

    monkeypatch.setattr(check_phase_readiness, "AssessmentClient", _Client)
    code = 0
    try:
        check_phase_readiness.run(SimpleNamespace(
            engagement_dir=tmp_path, phase=phase, as_json=False, by_app_unit=False,
            depth=False, strict=False, strict_deep=False, include_intel=False,
            by_host=False, auto_redispatch=False, verbose=False,
        ))
    except SystemExit as exc:
        code = exc.code
    captured = capsys.readouterr()
    return code, requested, captured.out + captured.err


def test_completed_code_track_redirect_names_no_earlier_gate(monkeypatch, tmp_path, capsys):
    code, _requested, output = _phase_readiness(
        monkeypatch, tmp_path, capsys, {"code": {"phase": "complete"}}, "verify"
    )
    assert code == 1
    assert "--require-transition-ready classify-map" not in output
    assert "the code track is complete" in output


def test_report_redirect_also_names_the_terminal_code_gate(monkeypatch, tmp_path, capsys):
    _code, _requested, output = _phase_readiness(
        monkeypatch, tmp_path, capsys, {"code": {"phase": "hunt"}}, "report"
    )
    assert "--require-transition-ready verify-variant" in output
    assert "--require-transition-ready complete" in output


@pytest.mark.parametrize("tracks", [
    {"web": {"phase": "report"}},
    {"web": {"phase": "report"}, "code": {"phase": "fuzz"}},
])
def test_complete_reads_the_web_terminal_gate(monkeypatch, tmp_path, capsys, tracks):
    code, requested, output = _phase_readiness(monkeypatch, tmp_path, capsys, tracks, "complete")
    assert requested[0] == "phase-readiness?phase=report"
    assert code == 0, output
    assert "is a code phase" not in output
    if "code" in tracks:
        assert "--require-transition-ready complete" in output


@pytest.mark.parametrize("payload", [{}, {"gate": None}])
def test_grouped_review_quality_renders_the_unavailable_verdict(payload, capsys):
    code_coverage._print_review_quality(payload, full=False)
    assert "Review-quality metadata is unavailable" in capsys.readouterr().out


@pytest.mark.parametrize("phase", [*CODE_PHASES, "complete", "report", "recon"])
@pytest.mark.parametrize("code_phase", [None, *CODE_PHASES, "complete"])
def test_readiness_pointer_names_only_accepted_readiness_targets(phase, code_phase):
    pointer = check_phase_readiness._code_readiness_pointer(code_phase, phase)
    named = re.findall(r"--require-transition-ready (\S+?)`", pointer)
    assert named, pointer
    assert set(named) <= set(code_coverage.READINESS_TARGETS), (phase, code_phase, pointer)


@pytest.mark.parametrize(("code_phase", "phase"), [
    ("fuzz", "complete"), ("complete", "recon"), ("hunt", "report"),
])
def test_terminal_readiness_pointer_names_the_deliverable_qc_gates(code_phase, phase):
    """`complete` also waits on the review verdicts `transition-phase` checks,
    which the code readiness command does not read."""
    pointer = check_phase_readiness._code_readiness_pointer(code_phase, phase)
    assert "submission_qc_verdict" in pointer and "report_qc_verdict" in pointer, pointer


def test_non_terminal_readiness_pointer_names_no_qc_gate():
    pointer = check_phase_readiness._code_readiness_pointer("hunt", "verify-variant")
    assert "qc_verdict" not in pointer, pointer


def _depth_advisory(path, *, signal=1, findings=0):
    return {"file_id": 1, "file_path": path, "classification": "high", "passes": 1,
            "dispatches": 1, "signal_passes": signal, "findings": findings}


def test_depth_advisories_render_as_a_pointer_and_never_fail_the_gate(capsys):
    gate = dict(_gate([]), depth_advisories=[
        _depth_advisory("acme/auth.py"), _depth_advisory("acme/views.py", signal=0, findings=1),
    ])
    code_coverage._print_review_quality({"gate": gate}, full=False)
    code_coverage._print_depth_advisories({"gate": gate}, full=False)
    out = capsys.readouterr().out
    assert "Review Quality: PASS" in out
    assert "Depth Advisories: 2 critical/high file(s)" in out
    assert "acme/auth.py (high): 1 wide pass(es), 1 with signal, 0 finding(s)" in out
    assert "acme/views.py (high): 1 wide pass(es), 0 with signal, 1 finding(s)" in out
    assert "code-dispatch reanalyze" in out
    assert code_coverage._review_quality({"gate": gate}) == (True, [])


def test_depth_advisories_preview_points_at_the_full_list(capsys):
    gate = dict(_gate([]), depth_advisories=[_depth_advisory(f"acme/{i}.py") for i in range(12)])
    code_coverage._print_depth_advisories({"gate": gate}, full=False)
    out = capsys.readouterr().out
    assert "acme/9.py" in out and "acme/10.py" not in out
    assert "+2 more" in out and "--cwe-matrix" in out
    code_coverage._print_depth_advisories({"gate": gate}, full=True)
    assert "acme/11.py" in capsys.readouterr().out


def test_no_depth_advisories_prints_nothing(capsys):
    code_coverage._print_depth_advisories({"gate": _gate([])}, full=False)
    assert capsys.readouterr().out == ""


def test_cwe_matrix_names_each_files_review_depth(capsys):
    code_coverage._print_cwe_matrix([
        {"file_path": "acme/parser.py", "classification": "high", "applicable_families": ["ssrf"],
         "cwe_coverage": [{"family": "ssrf", "effort": 60}],
         "review_depth": {"depth": "wide_only", "passes": 2, "deep_passes": 0,
                          "dispatches": 2, "signal_passes": 1}},
        {"file_path": "acme/auth.py", "classification": "critical", "applicable_families": ["ssrf"],
         "cwe_coverage": [{"family": "ssrf", "effort": 80}],
         "review_depth": {"depth": "deep", "passes": 2, "deep_passes": 1,
                          "dispatches": 2, "signal_passes": 0}},
    ])
    out = capsys.readouterr().out
    assert "Review Depth (pointer, not coverage): deep=1 wide_only=1 none=0" in out
    assert "acme/parser.py (high): wide_only — 2 pass(es), 0 deep, 2 dispatch(es), 1 with signal" in out
    assert "acme/auth.py (critical): deep" not in out


def _grouped_effort_lines(gaps):
    """The default view's `effort_warnings` shortfall lines, worded as the backend
    folds them (`code_analysis._grouped_effort_warnings`)."""
    summary = _effort_gaps(gaps)
    lines = [
        f"Effort below tier threshold: {summary['total']} family gap(s) across "
        f"{summary['file_count']} file(s) in {len(summary['groups'])} tier x family group(s); "
        "every per-file gap: vigil assess code-coverage --cwe-matrix (GET code/coverage?detail=cwe)"
    ]
    for group in summary["groups"]:
        lines.append(
            f"Effort below tier threshold — {group['classification'].capitalize()} x "
            f"{group['family']} (threshold {group['threshold']}): {group['file_count']} file(s), "
            "e.g. sample"
        )
    return lines


def test_default_view_prints_the_backend_s_grouped_effort_lines_once(capsys):
    gaps = [_gap("high", "ssrf", "acme/a.py"), _gap("high", "ssrf", "acme/b.py")]
    gate = {**_gate([]), "effort_warnings": _grouped_effort_lines(gaps),
            "effort_gaps": _effort_gaps(gaps, warnings=_grouped_effort_lines(gaps))}

    code_coverage._print_review_quality({"gate": gate}, full=False)

    out = capsys.readouterr().out
    assert "high x ssrf: 2 file(s) — acme/a.py, acme/b.py" in out
    # The groups are rendered from `effort_gaps`; the same groups worded as
    # warnings are not listed a second time.
    assert "Effort below tier threshold —" not in out
    assert out.count("Effort below tier threshold") == 1


def test_readiness_does_not_repeat_grouped_effort_lines_beside_the_cwe_matrix(capsys):
    gaps = [_gap("high", "ssrf", "acme/a.py")]
    structural = "acme/README has no structural parser; direct source review required"
    code_coverage._print_transition_readiness(
        "hunt",
        {"target_phase": "hunt", "transition_ready": True, "blockers": [],
         "quality_gate": {"passed": False,
                          "warnings": [structural, *_grouped_effort_lines(gaps)],
                          "effort_gap_warnings": _grouped_effort_lines(gaps)}},
        reported_quality=[gap["message"] for gap in gaps],
    )

    out = capsys.readouterr().out
    assert "Effort below tier threshold" not in out
    assert out.count(structural) == 1


def test_effort_gap_lines_are_told_apart_by_the_structured_field_not_their_wording(capsys):
    """However the backend words a shortfall line, `effort_gaps.warnings` names it."""
    gaps = [_gap("high", "ssrf", "acme/a.py")]
    reworded = ["Acme shortfall summary: 1 gap", "Acme shortfall group: high x ssrf"]
    lookalike = "Effort below tier threshold is not computed for acme/vendored.py"
    gate = {**_gate([], other=[lookalike]), "effort_warnings": [lookalike, *reworded],
            "effort_gaps": _effort_gaps(gaps, warnings=reworded)}

    code_coverage._print_review_quality({"gate": gate}, full=False)
    out = capsys.readouterr().out
    assert "high x ssrf: 1 file(s) — acme/a.py" in out
    assert all(line not in out for line in reworded)
    assert out.count(lookalike) == 1

    code_coverage._print_transition_readiness(
        "hunt",
        {"target_phase": "hunt", "transition_ready": True, "blockers": [],
         "quality_gate": {"passed": False, "warnings": [lookalike, *reworded],
                          "effort_gap_warnings": reworded}},
        reported_quality=[gap["message"] for gap in gaps],
    )
    out = capsys.readouterr().out
    assert all(line not in out for line in reworded)
    assert out.count(lookalike) == 1


def test_unrecorded_context_tags_render_as_a_pointer_naming_the_full_list(capsys):
    gate = dict(_gate([]), context_tags_unrecorded={
        "count": 12, "by_classification": {"critical": 2, "medium": 10},
        "sample_paths": [f"acme/{i}.py" for i in range(10)], "omitted": 2,
        "full_list": "vigil assess fetch 'code/files?context_tags_recorded=false&limit=10000'",
        "paging": "while has_more is true, read the next page with offset",
        "fix": "re-classify each file with its context_tags",
    })

    code_coverage._print_context_tags_unrecorded({"gate": gate})

    out = capsys.readouterr().out
    assert "12 classified file(s)" in out and "critical 2" in out
    assert "acme/9.py" in out and "+2 more" in out
    assert "context_tags_recorded=false" in out and "re-classify" in out
    assert "while has_more is true" in out
    assert code_coverage._review_quality({"gate": gate}) == (True, [])


def test_client_bundle_advisories_render_as_pointers_naming_the_full_lists(capsys):
    gate = dict(
        _gate([]),
        optional_families={
            "files": 12, "by_family": {"ssrf": 12, "file-upload": 3},
            "sample_paths": [f"web/{i}.js" for i in range(10)], "omitted": 2,
            "detail": "never measured",
            "full_list": "vigil assess fetch 'code/files?context_tag=client-bundle&limit=10000'",
        },
        client_bundle_conflicts={
            "count": 1, "sample": [{"file_path": "api/app.py", "signals": ["language python"]}],
            "omitted": 0,
            "full_list": "vigil assess fetch 'code/files?client_bundle_conflict=true&limit=10000'",
            "fix": "re-classify it without the tag",
        },
    )

    code_coverage._print_client_bundle_advisories({"gate": gate})

    out = capsys.readouterr().out
    assert "12 client-bundle file(s)" in out and "ssrf 12" in out and "+2 more" in out
    assert "context_tag=client-bundle" in out
    assert "api/app.py: language python" in out and "client_bundle_conflict=true" in out
    assert code_coverage._review_quality({"gate": gate}) == (True, [])


def test_a_file_counting_blocker_prints_its_sample_paths_and_full_list(capsys):
    code_coverage._print_transition_readiness(
        "verify-variant",
        {"target_phase": "verify-variant", "transition_ready": False, "blockers": [{
            "code": "admitted_files_unaccounted", "repo_id": 3, "overrideable": False,
            "message": "Repository has 12 admitted file(s) without a current terminal review.",
            "sample_paths": [f"src/acme_{i}.py" for i in range(10)], "omitted": 2,
            "full_list": "vigil assess fetch 'code/files?accounting=unaccounted&repo_id=3&limit=10000'",
        }]},
    )

    out = capsys.readouterr().out
    assert "src/acme_9.py" in out and "(+2 more)" in out
    assert "accounting=unaccounted&repo_id=3" in out
