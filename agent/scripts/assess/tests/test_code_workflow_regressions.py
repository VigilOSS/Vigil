"""Regressions found by the deterministic sample_repository code-workflow trial."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess import cli
from assess.commands import code_coverage, code_dispatch, code_ingest, host_exec


def _host_exec_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    host_exec.register(subparsers)
    return parser


def test_host_exec_from_json_reaches_handler_without_sentinel(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    request_path = tmp_path / "request.json"
    request_path.write_text(
        json.dumps(
            {
                "command": ["printf", "ok"],
                "tool": "printf",
                "intent": "exercise host-exec JSON parsing",
                "technique": "T0000",
                "phase": "verify",
            }
        ),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def fake_run(args: argparse.Namespace) -> None:
        captured.update(
            root_command=args.command,
            exec_argv=args.exec_argv,
            from_json=args.from_json,
        )

    monkeypatch.setattr(host_exec, "run", fake_run)

    cli.main(["host-exec", "--from-json", str(request_path)])

    assert captured == {
        "root_command": "host-exec",
        "exec_argv": [],
        "from_json": str(request_path),
    }


def test_host_exec_parser_keeps_cli_command_argv_separate_from_root_command() -> None:
    args = _host_exec_parser().parse_args(["host-exec", "printf", "ok"])

    assert args.command == "host-exec"
    assert args.exec_argv == ["printf", "ok"]


def test_host_exec_rejects_retired_aggregate_rate_override_flag(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        _host_exec_parser().parse_args(
            ["host-exec", "--rate-override-reason", "approved", "printf", "ok"]
        )

    assert exc.value.code == 2
    assert "unrecognized arguments: --rate-override-reason" in capsys.readouterr().err


@pytest.mark.parametrize("json_key", ["command", "argv"])
def test_host_exec_from_json_command_aliases_preserve_root_command(json_key: str) -> None:
    args = _host_exec_parser().parse_args(["host-exec", "--from-json", "request.json"])

    host_exec._merge_from_json(args, {json_key: ["printf", "ok"]})

    assert args.command == "host-exec"
    assert host_exec._resolve_argv(args) == ["printf", "ok"]


def test_host_exec_resolve_argv_retains_programmatic_command_namespace_compatibility() -> None:
    args = SimpleNamespace(command=["printf", "ok"])

    assert host_exec._resolve_argv(args) == ["printf", "ok"]


def test_code_dispatch_fetch_filters_parse_without_double_dash(monkeypatch):
    captured: dict[str, object] = {}

    def fake_run(args) -> None:
        captured["action"] = args.action
        captured["extra"] = args.extra

    monkeypatch.setattr(code_dispatch, "run", fake_run)

    cli.main([
        "code-dispatch",
        "fetch",
        "2",
        "code-vuln-hunter",
        "--repo-id",
        "1",
        "--batch-theme",
        "http-client-core",
    ])

    assert captured == {
        "action": "fetch",
        "extra": [
            "2",
            "code-vuln-hunter",
            "--repo-id",
            "1",
            "--batch-theme",
            "http-client-core",
        ],
    }


def test_code_dispatch_done_options_parse_without_double_dash(monkeypatch):
    captured: dict[str, object] = {}

    def fake_run(args) -> None:
        captured["action"] = args.action
        captured["extra"] = args.extra

    monkeypatch.setattr(code_dispatch, "run", fake_run)

    cli.main([
        "code-dispatch",
        "done",
        "42",
        "code-vuln-hunter",
        "lease-42",
        "skipped",
        "coverage.json",
        "unsupported structural parser",
        "--skip-reason",
        "out-of-scope-language",
        "--dry-run",
    ])

    assert captured == {
        "action": "done",
        "extra": [
            "42",
            "code-vuln-hunter",
            "lease-42",
            "skipped",
            "coverage.json",
            "unsupported structural parser",
            "--skip-reason",
            "out-of-scope-language",
            "--dry-run",
        ],
    }


def test_code_dispatch_done_rejects_unknown_flag_before_backend_mutation(
    monkeypatch, tmp_path, capsys,
):
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(
        json.dumps([{"family": "error-handling", "effort": 50}]),
        encoding="utf-8",
    )
    posts: list[tuple[str, dict]] = []

    class FakeClient:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, endpoint: str, payload: dict):
            posts.append((endpoint, payload))
            return {"updated": 1}

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        code_dispatch,
        "load_config",
        lambda *_args: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    with pytest.raises(SystemExit) as exc:
        code_dispatch.run(SimpleNamespace(
            action="done",
            extra=[
                "42",
                "code-vuln-hunter",
                "lease-42",
                "clean",
                str(coverage_path),
                "reviewed cleanup paths",
                "--dryrun",
            ],
            engagement_dir=tmp_path,
        ))

    assert exc.value.code == 1
    assert posts == []
    assert "unknown code-dispatch done option: --dryrun" in capsys.readouterr().err.lower()


@pytest.mark.parametrize(
    ("options", "message"),
    [
        (["--dry-run", "--dry-run"], "--dry-run was specified more than once"),
        (
            ["--skip-reason", "generated-code", "--skip-reason", "test-fixture"],
            "--skip-reason was specified more than once",
        ),
        (["--skip-reason"], "--skip-reason requires a value"),
        (["--skip-reason", ""], "--skip-reason requires a value"),
        (["--skip-reason", "--dry-run"], "--skip-reason requires a value"),
    ],
)
def test_code_dispatch_done_rejects_duplicate_or_malformed_options_before_backend(
    monkeypatch, tmp_path, capsys, options, message,
):
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text("[]", encoding="utf-8")

    class ForbiddenClient:
        def __init__(self, *_args, **_kwargs) -> None:
            raise AssertionError("invalid options must fail before client construction")

    monkeypatch.setattr(code_dispatch, "AssessmentClient", ForbiddenClient)
    monkeypatch.setattr(
        code_dispatch,
        "load_config",
        lambda *_args: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    with pytest.raises(SystemExit) as exc:
        code_dispatch.run(SimpleNamespace(
            action="done",
            extra=[
                "42",
                "code-vuln-hunter",
                "lease-42",
                "clean",
                str(coverage_path),
                "free form notes stay valid",
                *options,
            ],
            engagement_dir=tmp_path,
        ))

    assert exc.value.code == 1
    assert message in capsys.readouterr().err


def test_code_dispatch_stats_prints_one_backend_total(monkeypatch, capsys):
    class FakeClient:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, endpoint: str):
            assert endpoint == "code/analysis-queue/stats"
            return {
                "pending": 1,
                "processing": 2,
                "done": 3,
                "error": 4,
                "needs_context": 5,
                "total": 15,
                "historical_total": 18,
                "superseded_history": 3,
            }

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)

    code_dispatch._stats(SimpleNamespace(base_url="http://example.test", engagement_key="eng"))

    output = capsys.readouterr().out
    assert output.count("=== Code Analysis Queue Stats ===") == 1
    assert output.count("  total: 15") == 1
    assert output.count("  historical_total: 18") == 1
    assert output.count("  superseded_history: 3") == 1


def test_code_coverage_prints_review_quality_once_with_readiness(monkeypatch, capsys):
    coverage = {
        "total_files": 1,
        "gate": {
            "passed": True,
            "effort_warnings": [],
            "coverage_integrity": [],
        },
    }
    readiness = {
        "target_phase": "hunt",
        "transition_ready": True,
        "blockers": [],
        "quality_gate": {"passed": True, "warnings": []},
    }

    class FakeClient:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, endpoint: str):
            if endpoint == "code/coverage":
                return coverage
            assert endpoint == "code/readiness?target_phase=hunt&include_debt_paths=true"
            return readiness

    monkeypatch.setattr(code_coverage, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        code_coverage,
        "load_config",
        lambda *_args: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    code_coverage.run(SimpleNamespace(
        engagement_dir=Path("/tmp/eng"),
        repo_id=None,
        cwe_matrix=False,
        require_gate_pass=False,
        require_transition_ready="hunt",
    ))

    assert capsys.readouterr().out.count("Review Quality: PASS") == 1


def test_code_coverage_preserves_readiness_specific_advisories(capsys):
    code_coverage._print_transition_readiness(
        "hunt",
        {
            "target_phase": "hunt",
            "transition_ready": True,
            "blockers": [],
            "quality_gate": {
                "passed": False,
                "warnings": ["README has no structural parser; direct source review required"],
            },
        },
    )

    output = capsys.readouterr().out
    assert "Readiness Advisories: NEEDS ATTENTION" in output
    assert "README has no structural parser" in output


def test_code_coverage_combined_quality_and_readiness_flags_report_both_before_exit(
    monkeypatch, capsys,
):
    requested: list[str] = []

    class FakeClient:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, endpoint: str):
            requested.append(endpoint)
            if endpoint == "code/coverage?detail=cwe":
                return {
                    "total_files": 1,
                    "files": [{
                        "file_path": "sample_repository.c",
                        "classification": "critical",
                        "applicable_families": ["error-handling"],
                        "cwe_coverage": [{"family": "error-handling", "effort": 10}],
                    }],
                    "gate": {
                        "passed": False,
                        "effort_warnings": ["sample_repository.c error-handling effort below target"],
                        "coverage_integrity": [],
                    },
                }
            assert endpoint == "code/readiness?target_phase=verify-variant&include_debt_paths=true"
            return {
                "target_phase": "verify-variant",
                "transition_ready": False,
                "blockers": [{
                    "code": "queue_pending",
                    "message": "One admitted file remains pending",
                    "overrideable": False,
                }],
                "quality_gate": {
                    "passed": False,
                    "warnings": ["sample_repository.c error-handling effort below target"],
                },
            }

    monkeypatch.setattr(code_coverage, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        code_coverage,
        "load_config",
        lambda *_args: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    with pytest.raises(SystemExit) as exc:
        code_coverage.run(SimpleNamespace(
            engagement_dir=Path("/tmp/eng"),
            repo_id=None,
            cwe_matrix=True,
            require_gate_pass=True,
            require_transition_ready="verify-variant",
        ))

    assert exc.value.code == 1
    assert requested == [
        "code/coverage?detail=cwe",
        "code/readiness?target_phase=verify-variant&include_debt_paths=true",
    ]
    output = capsys.readouterr().out
    assert "Review Quality: NEEDS ATTENTION" in output
    assert "sample_repository.c error-handling effort below target" in output
    assert "Transition Readiness (verify-variant): BLOCKED" in output
    assert "queue_pending" in output


def test_code_ingest_summary_matches_registered_admitted_file_count(monkeypatch, tmp_path, capsys):
    repo_path = tmp_path / "sample_repository-like"
    repo_path.mkdir()
    (repo_path / "sample_repository.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (repo_path / "README").write_text("build instructions\n", encoding="utf-8")
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, endpoint: str, payload: dict):
            if endpoint == "code/repos/refresh/start":
                captured["repo_payload"] = payload
                return {"repo_id": 7, "refresh_token": "refresh-7"}
            if endpoint == "code/repos/7/refresh/files":
                return {"staged": len(payload["files"])}
            if endpoint == "code/repos/7/refresh/commit":
                return {
                    "repo_id": 7,
                    "repo_generation": 1,
                    "repo_role": "analysis",
                    "source_manifest_version": "v2",
                    "source_manifest_digest": "d" * 64,
                    "retired": 0,
                }
            if endpoint == "code/repos/7/lsp-config":
                return {
                    "id": 7,
                    "active_generation": payload["repo_generation"],
                    "source_manifest_digest": payload["source_manifest_digest"],
                    "lsp_config": payload["lsp_config"],
                }
            raise AssertionError(f"Unexpected endpoint: {endpoint}")

    monkeypatch.setattr(code_ingest, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        code_ingest,
        "load_config",
        lambda *_args: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(
        code_ingest,
        "_setup_ctags",
        lambda *_args, **kwargs: {
            "available": False,
            "tags_path": "",
            "universal": False,
            "repo_generation": kwargs["repo_generation"],
            "source_manifest_digest": kwargs["source_manifest_digest"],
        },
    )

    code_ingest.run(SimpleNamespace(
        repo_path=str(repo_path),
        name="sample_repository-like",
        language=None,
        default_language_for_unknown=None,
        repo_key=None,
        include_minified=False,
        include_skipped=False,
        include_path=[],
        max_included_skipped_bytes=2_000_000,
        skipped_manifest=None,
        dry_run=False,
        engagement_dir=engagement_dir,
    ))

    registered = captured["repo_payload"]
    assert isinstance(registered, dict)
    summary = capsys.readouterr().out
    match = re.search(r"^Analyzable files: (\d+)$", summary, re.MULTILINE)
    assert match is not None
    assert int(match.group(1)) == registered["analyzable_files"] == 2
