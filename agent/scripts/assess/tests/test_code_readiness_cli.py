"""CLI contract tests for the backend-owned code transition readiness gate."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[4]


def _load_module(name: str):
    scripts_root = _REPO_ROOT / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    path = scripts_root / "assess" / "commands" / "code_coverage.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _args(target: str | None):
    return SimpleNamespace(
        engagement_dir=Path("/tmp/eng"),
        repo_id=None,
        cwe_matrix=False,
        require_gate_pass=False,
        require_transition_ready=target,
    )


def _coverage():
    return {
        "total_files": 1,
        "by_classification": {},
        "by_status": {},
        "findings_summary": {},
        "confidence": {},
        "gate": {"passed": False, "reasons": ["effort below target"]},
    }


def test_default_coverage_shows_next_hard_gate_and_bounded_debt(
    monkeypatch, tmp_path, capsys
):
    module = _load_module("test_code_readiness_default_next_gate")
    (tmp_path / "scope.json").write_text(
        '{"engagement_type":"code","current_phase":"hunt"}', encoding="utf-8"
    )
    requested = []

    class _Client:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, path):
            requested.append(path)
            if path == "code/coverage":
                return _coverage()
            return {
                "target_phase": "verify-variant", "transition_ready": False,
                "blockers": [{"code": "structural_analysis_debt_unreviewed", "message": "3 files", "repo_id": 7}],
                "structural_debt_count": 15,
                "structural_debt": [
                    {"repo_id": 7, "file_path": f"src/{i}.py",
                     "classification": "skip" if i < 2 else "high",
                     "structural_analysis_status": "unsupported" if i < 2 else "degraded",
                     "structural_artifact_truncated": i == 2}
                    for i in range(15)
                ],
            }

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module, "load_config", lambda *_args: SimpleNamespace(
            base_url="http://example.test", engagement_key="eng-code",
            engagement_dir=str(tmp_path),
        ),
    )
    module.run(_args(None))
    out = capsys.readouterr().out
    assert "Next hard gate (verify-variant): BLOCKED" in out
    assert "structural debt: 15 file(s)" in out
    assert out.index("Next hard gate (verify-variant)") < out.index("Review Quality:")
    assert "skip=2" in out and "high=13" in out
    assert "unsupported=2" in out and "degraded=13" in out
    assert "src/0.py" in out and "classification=skip" in out
    assert "showing 10 of 15" in out and "src/14.py" not in out
    assert "code/readiness?target_phase=verify-variant&include_debt_paths=true" in requested[-1]
    assert requested == [
        "code/coverage",
        "code/readiness?target_phase=verify-variant&include_debt_paths=true",
    ]


def test_readiness_fetch_includes_debt_paths_for_bounded_default_preview():
    module = _load_module("test_code_readiness_debt_path_query")
    assert module._readiness_endpoint("verify-variant") == (
        "code/readiness?target_phase=verify-variant&include_debt_paths=true"
    )


def test_skip_classification_reports_review_and_structural_debt_counts(capsys):
    module = _load_module("test_code_readiness_skip_debt_row")
    module._print_coverage(
        {
            "total_files": 4,
            "by_classification": {"skip": {"count": 4, "analyzed": 1}},
        },
        structural_debt_by_classification={"skip": 3},
    )
    assert "4 files |    1 reviewed | structural debt: 3" in capsys.readouterr().out


def test_code_coverage_can_require_target_transition_readiness(monkeypatch, capsys):
    module = _load_module("test_code_readiness_cli_blocks")
    requested: list[str] = []

    class _Client:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, path: str):
            requested.append(path)
            if path == "code/coverage":
                return _coverage()
            return {
                "target_phase": "hunt",
                "transition_ready": False,
                "blockers": [{
                    "code": "threat_model_stale",
                    "message": "Repository 7 threat model is not current",
                    "overrideable": False,
                    "repo_id": 7,
                }],
                "quality_gate": {"passed": False, "warnings": ["effort below target"]},
            }

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng-code",
        ),
    )

    with pytest.raises(SystemExit) as exc:
        module.run(_args("hunt"))

    assert exc.value.code == 1
    assert requested == [
        "code/coverage",
        "code/readiness?target_phase=hunt&include_debt_paths=true",
    ]
    output = capsys.readouterr().out
    assert "Transition Readiness (hunt): BLOCKED" in output
    assert "threat_model_stale" in output
    assert "Repository 7 threat model is not current" in output


def test_quality_failure_does_not_fail_transition_readiness_requirement(monkeypatch, capsys):
    module = _load_module("test_code_readiness_cli_quality_separate")

    class _Client:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, path: str):
            if path == "code/coverage":
                return _coverage()
            return {
                "target_phase": "verify-variant",
                "transition_ready": True,
                "blockers": [],
                "quality_gate": {"passed": False, "warnings": ["effort below target"]},
            }

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng-code",
        ),
    )

    module.run(_args("verify-variant"))

    output = capsys.readouterr().out
    assert "Transition Readiness (verify-variant): READY" in output
    assert "Review Quality: NEEDS ATTENTION" in output


def test_structural_gate_failure_does_not_fail_quality_only_requirement(monkeypatch, capsys):
    module = _load_module("test_code_quality_cli_structural_separate")
    args = _args(None)
    args.require_gate_pass = True

    class _Client:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, path: str):
            assert path == "code/coverage"
            return {
                "total_files": 1,
                "gate": {
                    "passed": False,
                    "reasons": ["pending queue items remain"],
                    "effort_warnings": [],
                    "coverage_integrity": [],
                },
            }

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng-code",
        ),
    )

    module.run(args)

    assert "Review Quality: PASS" in capsys.readouterr().out


def test_cwe_matrix_does_not_bypass_transition_readiness(monkeypatch):
    module = _load_module("test_code_readiness_cli_cwe_matrix")
    args = _args("hunt")
    args.cwe_matrix = True
    rendered: list[bool] = []

    class _Client:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, path: str):
            assert path == "code/readiness?target_phase=hunt&include_debt_paths=true"
            return {
                "target_phase": "hunt",
                "transition_ready": False,
                "blockers": [{
                    "code": "structural_index_stale",
                    "message": "Repository 7 index is stale",
                    "overrideable": False,
                }],
                "quality_gate": {"passed": True, "warnings": []},
            }

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(module, "_run_cwe_matrix", lambda *_args: rendered.append(True))
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng-code",
        ),
    )

    with pytest.raises(SystemExit) as exc:
        module.run(args)

    assert exc.value.code == 1
    assert rendered == [True]
