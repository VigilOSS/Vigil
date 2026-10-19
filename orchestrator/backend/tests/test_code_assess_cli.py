from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def _file_page(rows: list[dict], *, offset: int = 0, total: int | None = None) -> dict:
    count = len(rows)
    page_total = offset + count if total is None else total
    return {
        "total": page_total,
        "offset": offset,
        "count": count,
        "has_more": offset + count < page_total,
        "items": rows,
    }


def _load_assess_module(module_filename: str, module_name: str):
    repo_root = Path(__file__).resolve().parents[3]
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = repo_root / "agent" / "scripts" / "assess" / "commands" / module_filename
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_code_coverage_module():
    return _load_assess_module("code_coverage.py", "test_code_coverage_command")


def _load_code_size_summary_module():
    return _load_assess_module("code_size_summary.py", "test_code_size_summary_command")


def _load_code_ingest_module():
    return _load_assess_module("code_ingest.py", "test_code_ingest_command")


def _load_code_classify_module():
    return _load_assess_module("code_classify.py", "test_code_classify_command")


def _load_code_dispatch_module():
    return _load_assess_module("code_dispatch.py", "test_code_dispatch_command")


def _load_code_record_analysis_module():
    return _load_assess_module("code_record_analysis.py", "test_code_record_analysis_command")


def _load_code_record_group_module():
    return _load_assess_module("code_record.py", "test_code_record_group_command")


def _load_code_record_variant_check_module():
    return _load_assess_module(
        "code_record_variant_check.py",
        "test_code_record_variant_check_command",
    )


def _load_code_record_fuzz_decision_module():
    return _load_assess_module(
        "code_record_fuzz_decision.py",
        "test_code_record_fuzz_decision_command",
    )


def _load_code_record_fuzz_campaign_module():
    return _load_assess_module(
        "code_record_fuzz_campaign.py",
        "test_code_record_fuzz_campaign_command",
    )


@pytest.mark.parametrize("kind", ["fuzz-decision", "fuzz-campaign"])
def test_code_record_registers_durable_fuzz_completion_verbs(kind):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    _load_code_record_group_module().register(subparsers)

    args = parser.parse_args(["code-record", kind, "receipt.json"])

    assert callable(args.func)


def _variant_check_payload() -> dict[str, object]:
    return {
        "dispatch_id": 17,
        "file_id": 42,
        "repo_id": 7,
        "repo_generation": 3,
        "source_manifest_digest": "a" * 64,
        "file_sha256": "b" * 64,
        "parent_finding_slugs": ["CH-001", "CH-004"],
        "status": "completed",
        "evidence_ref": "artifacts/variant-checks/src_parser_c.json",
        "rationale": "Checked each parent pattern against every candidate match in this file.",
    }


def _fuzz_decision_payload() -> dict[str, object]:
    return {
        "repo_id": 7,
        "repo_generation": 3,
        "source_manifest_digest": "a" * 64,
        "decision": "required",
        "target_ids": ["parser-reset-state-sequence"],
        "evidence_ref": "tools/fuzz-state/applicability.json",
        "rationale": "The current native parser accepts attacker-controlled state sequences.",
    }


def _fuzz_campaign_payload() -> dict[str, object]:
    return {
        "dispatch_id": 17,
        "repo_id": 7,
        "repo_generation": 3,
        "source_manifest_digest": "a" * 64,
        "target_id": "parser-reset-state-sequence",
        "covered_finding_slugs": ["VF-003"],
        "engine": "libfuzzer",
        "sanitizers": ["address", "undefined"],
        "run_budget_seconds": 60,
        "executions": 25000,
        "outcome": "completed_no_crash",
        "crash_count": 0,
        "triage_summary": "No sanitizer crash observed during the bounded campaign.",
        "evidence_ref": "tools/fuzz-state/campaign.json",
        "rationale": "Built the real parser entrypoint and exercised reset/continue sequences.",
    }


def _load_code_index_module():
    return _load_assess_module("code_index.py", "test_code_index_command")


def _load_verify_finding_module():
    return _load_assess_module("verify_finding.py", "test_verify_finding_command")


def _load_contract_module():
    return _load_assess_module("contract.py", "test_contract_command")


def _load_post_module():
    return _load_assess_module("post.py", "test_post_command")


def _load_record_finding_module():
    return _load_assess_module("record_finding.py", "test_record_finding_command")


def _load_update_finding_module():
    return _load_assess_module("update_finding.py", "test_update_finding_command")


def _load_list_findings_module():
    return _load_assess_module("list_findings.py", "test_list_findings_command")


def _load_cli_module():
    repo_root = Path(__file__).resolve().parents[3]
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    import assess.cli as cli_module

    return cli_module


# Derived from the action registry rather than restated: a hand-kept roster
# silently stops covering the next action added, which is exactly how `list`
# shipped without an entry here.
@pytest.mark.parametrize(
    "action", sorted(_load_code_dispatch_module()._ACTION_HELP)
)
def test_code_dispatch_action_help_is_explicit(action, capsys):
    module = _load_code_dispatch_module()

    with pytest.raises(SystemExit) as excinfo:
        module.maybe_print_action_help([action, "--help"])

    assert excinfo.value.code == 0
    assert f"Usage: vigil assess code-dispatch {action}" in capsys.readouterr().out


def test_code_dispatch_action_help_routes_before_remainder_parsing(capsys):
    cli_module = _load_cli_module()

    with pytest.raises(SystemExit) as excinfo:
        cli_module.main(["code-dispatch", "requeue-triggers", "--help"])

    captured = capsys.readouterr()
    assert excinfo.value.code == 0
    assert "Usage: vigil assess code-dispatch requeue-triggers" in captured.out
    assert "Triggers JSON file not found" not in captured.err


@pytest.mark.parametrize("extra", ([], ["--help"]))
def test_code_dispatch_unknown_action_fails_before_engagement_resolution(extra, capsys):
    cli_module = _load_cli_module()

    with pytest.raises(SystemExit) as excinfo:
        cli_module.main(["code-dispatch", "unknown-action", *extra])

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "invalid choice: 'unknown-action'" in captured.err
    assert "Cannot resolve engagement directory" not in captured.err


def _mock_ingest_git(module, monkeypatch) -> None:
    monkeypatch.setattr(
        module,
        "_prepare_git_source",
        lambda _repo_path, _status_timeout: (
            "/trusted/git",
            {"head": "a" * 40, "branch": "main", "dirty": False},
        ),
    )
    monkeypatch.setattr(module, "_git_commit_count", lambda _repo_path: 0)
    monkeypatch.setattr(module, "_git_churn_scores", lambda _repo_path: {})
    monkeypatch.setattr(module, "_git_security_files", lambda _repo_path, _history: set())
    monkeypatch.setattr(
        module,
        "_git_provenance",
        lambda *_args: {"head": "a" * 40, "branch": "main", "dirty": False},
    )


def _bound_ingest_commit() -> dict[str, object]:
    return {
        "repo_id": 7,
        "repo_generation": 1,
        "source_manifest_version": "v1",
        "source_manifest_digest": "d" * 64,
        "retired": 0,
        "repo_role": "analysis",
    }


def _bound_lsp_publish(payload: dict[str, object]) -> dict[str, object]:
    return {
        "id": 7,
        "active_generation": 1,
        "source_manifest_digest": "d" * 64,
        "lsp_config": payload["lsp_config"],
    }


@pytest.mark.parametrize(
    ("malformed_endpoint", "operation"),
    [
        ("code/repos/7/refresh/files", "stage code repository files"),
        ("code/repos/7/lsp-config", "publish code repository LSP config"),
    ],
    ids=["staged-files", "lsp-config"],
)
def test_code_ingest_rejects_unbound_success_acknowledgements(
    malformed_endpoint, operation, monkeypatch, tmp_path
):
    module = _load_code_ingest_module()
    from assess.lib.client import AssessError

    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    _mock_ingest_git(module, monkeypatch)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda _engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path / "engagement"),
        ),
    )
    lsp_ctags = {
        "available": False,
        "tags_path": "",
        "universal": False,
        "repo_generation": 1,
        "source_manifest_digest": "d" * 64,
    }
    monkeypatch.setattr(module, "_setup_ctags", lambda *_args, **_kwargs: lsp_ctags)

    class FakeClient:
        def __init__(self, *_args):
            pass

        def post(self, endpoint, payload):
            if endpoint == "code/repos/refresh/start":
                return {"repo_id": 7, "refresh_token": "refresh-7"}
            if endpoint == "code/repos/7/refresh/files":
                if endpoint == malformed_endpoint:
                    return {"message": "accepted"}
                return {"staged": len(payload["files"])}
            if endpoint == "code/repos/7/refresh/commit":
                return _bound_ingest_commit()
            if endpoint == "code/repos/7/lsp-config":
                if endpoint == malformed_endpoint:
                    return {"id": 7}
                return {
                    "id": 7,
                    "active_generation": 1,
                    "source_manifest_digest": "d" * 64,
                    "lsp_config": {"ctags": lsp_ctags},
                }
            raise AssertionError(f"Unexpected endpoint: {endpoint}")

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(AssessError, match=operation) as exc:
        module.run(
            SimpleNamespace(
                repo_path=str(repo_path),
                name="demo",
                language=None,
                repo_key=None,
                engagement_dir=tmp_path / "engagement",
            )
        )

    assert "do not retry automatically" in str(exc.value)


def test_code_coverage_is_informational_by_default(monkeypatch, capsys):
    module = _load_code_coverage_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            return {
                "total_files": 1,
                "by_classification": {"critical": {"count": 1, "analyzed": 0}},
                "function_level": {"total_contexts": 1, "analyzed": 0, "needs_context": 1, "pending": 0},
                "gate": {
                    "passed": False,
                    "reasons": ["Critical files not fully analyzed: 0/1"],
                    "effort_warnings": [],
                    "coverage_integrity": [],
                },
            }

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(engagement_dir=Path("/tmp/eng"), repo_id=None, require_gate_pass=False))
    output = capsys.readouterr().out
    assert "Review Quality: PASS" in output


def test_code_coverage_can_enforce_review_quality_failures(monkeypatch):
    module = _load_code_coverage_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            return {
                "gate": {
                    "passed": False,
                    "reasons": ["effort below target"],
                    "effort_warnings": ["effort below target"],
                    "coverage_integrity": [],
                }
            }

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(engagement_dir=Path("/tmp/eng"), repo_id=None, require_gate_pass=True))
    assert excinfo.value.code == 1


def test_code_coverage_quality_flattens_integrity_warnings():
    module = _load_code_coverage_module()

    passed, warnings = module._review_quality({
        "gate": {
            "passed": False,
            "reasons": ["structural blocker must not leak"],
            "effort_warnings": ["effort below target"],
            "coverage_integrity": [
                {"file_path": "src/parser.py", "warnings": ["claimed count exceeds index"]}
            ],
        }
    })

    assert passed is False
    assert warnings == [
        "effort below target",
        "src/parser.py: claimed count exceeds index",
    ]


def test_code_coverage_quality_ignores_structural_gate_failure():
    module = _load_code_coverage_module()

    passed, warnings = module._review_quality({
        "gate": {
            "passed": False,
            "reasons": ["pending queue items remain"],
            "effort_warnings": [],
            "coverage_integrity": [],
        }
    })

    assert passed is True
    assert warnings == []


def test_code_coverage_cwe_matrix_quality_flag_ignores_structural_gate(monkeypatch):
    module = _load_code_coverage_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            return {
                "gate": {
                    "passed": False,
                    "reasons": ["pending queue items remain"],
                    "effort_warnings": [],
                    "coverage_integrity": [],
                },
                "files": [
                    {
                        "file_path": "src/parser.py",
                        "classification": "critical",
                        "applicable_families": ["ssrf"],
                        "cwe_coverage": [{"family": "ssrf", "effort": 95}],
                    }
                ],
            }

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=Path("/tmp/eng"),
            repo_id=None,
            require_gate_pass=True,
            cwe_matrix=True,
            require_transition_ready=None,
        )
    )


def test_code_size_summary_uses_backend_code_files(monkeypatch, capsys):
    module = _load_code_size_summary_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key
            self.calls: list[str] = []

        def get(self, endpoint: str):
            self.calls.append(endpoint)
            return _file_page([
                {
                    "id": 1,
                    "repo_id": 10,
                    "file_path": "src/auth/session.py",
                    "classification": "critical",
                    "analysis_status": "analyzed",
                    "language": "python",
                    "loc": 1500,
                },
                {
                    "id": 2,
                    "repo_id": 10,
                    "file_path": "node_modules/lib/index.js",
                    "classification": "skip",
                    "analysis_status": "skipped",
                    "language": "javascript",
                    "loc": 300,
                    "skip_reason": "vendor",
                },
                {
                    "id": 3,
                    "repo_id": 10,
                    "file_path": "src/generated/api.pb.go",
                    "classification": "low",
                    "analysis_status": "unclassified",
                    "language": "go",
                    "loc": 800,
                },
            ])

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=Path("/tmp/eng"),
            repo_id=None,
            large_threshold=1000,
            top=10,
            json=False,
        )
    )

    output = capsys.readouterr().out
    assert "total_files: 3" in output
    assert "app_owned|files=1|loc=1500" in output
    assert "vendor|files=1|loc=300" in output
    assert "generated|files=1|loc=800" in output
    assert "1500|critical|app_owned|analyzed|src/auth/session.py" in output


def test_code_ingest_repo_key_uses_name_and_canonical_path_hash():
    module = _load_code_ingest_module()

    first = module._repo_key_for_path("Demo Repo", "/tmp/source/demo")
    second = module._repo_key_for_path("Demo Repo", "/tmp/other/demo")
    repeat = module._repo_key_for_path("Demo Repo", "/tmp/source/demo")

    assert first.startswith("demo-repo-")
    assert repeat == first
    assert second != first


def test_code_ingest_header_snippet_is_capped(tmp_path):
    module = _load_code_ingest_module()

    css_file = tmp_path / "style.css"
    css_file.write_text("data:" + ("A" * 9000) + "\nbody { color: red; }\n", encoding="utf-8")

    snippet = module._read_header(str(css_file))

    assert len(snippet) == 8192
    assert snippet.startswith("data:")


def test_code_ingest_skips_named_pipes(monkeypatch, tmp_path):
    module = _load_code_ingest_module()

    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    os.mkfifo(repo_path / "blocked.py")
    _mock_ingest_git(module, monkeypatch)

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path / "engagement"),
        ),
    )
    monkeypatch.setattr(module, "_count_lines", lambda filepath: 1)
    monkeypatch.setattr(module, "_sha256_file", lambda filepath: f"sha:{Path(filepath).name}")
    monkeypatch.setattr(module, "_read_header", lambda filepath: f"header:{Path(filepath).name}")
    monkeypatch.setattr(module, "_setup_ctags", lambda *args, **kwargs: {"available": False, **kwargs})

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict):
            if endpoint == "code/repos/refresh/start":
                captured["repo_payload"] = payload
                return {"repo_id": 7, "refresh_token": "refresh-7"}
            if endpoint == "code/repos/7/refresh/files":
                captured["files_payload"] = payload
                return {"staged": len(payload["files"])}
            if endpoint == "code/repos/7/refresh/commit":
                assert payload == {"refresh_token": "refresh-7", "manifest_complete": True}
                return _bound_ingest_commit()
            if endpoint == "code/repos/7/lsp-config":
                assert payload["repo_generation"] == 1
                assert payload["source_manifest_digest"] == "d" * 64
                assert payload["lsp_config"]["ctags"]["repo_generation"] == 1
                return _bound_lsp_publish(payload)
            raise AssertionError(f"Unexpected endpoint: {endpoint}")

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            repo_path=str(repo_path),
            name="demo",
            language=None,
            repo_key=None,
            engagement_dir=tmp_path / "engagement",
        )
    )

    repo_payload = captured["repo_payload"]
    assert repo_payload["total_files"] == 2
    assert repo_payload["analyzable_files"] == 1

    files_payload = captured["files_payload"]
    assert files_payload["refresh_token"] == "refresh-7"
    assert [entry["file_path"] for entry in files_payload["files"]] == ["app.py"]


def test_code_ingest_dry_run_reports_refresh_delta_without_staging(monkeypatch, tmp_path, capsys):
    module = _load_code_ingest_module()
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text("print('changed')\n", encoding="utf-8")
    _mock_ingest_git(module, monkeypatch)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path / "engagement")
        ),
    )
    monkeypatch.setattr(module, "_setup_ctags", lambda *args, **kwargs: {"available": False, **kwargs})
    posted: list[str] = []

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass
        def post(self, endpoint, payload):
            posted.append(endpoint)
            assert endpoint == "code/repos/refresh/preview"
            return {"added": ["app.py"], "changed": [], "renamed": [], "removed": ["old.py"]}
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    module.run(
        SimpleNamespace(
            repo_path=str(repo_path), name="demo", language=None, repo_key=None,
            engagement_dir=tmp_path / "engagement", dry_run=True,
        )
    )
    assert posted == ["code/repos/refresh/preview"]
    output = capsys.readouterr().out
    assert '"added"' in output
    assert '"removed"' in output


def test_code_ingest_commits_complete_empty_manifest(monkeypatch, tmp_path):
    module = _load_code_ingest_module()
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    _mock_ingest_git(module, monkeypatch)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path / "engagement")
        ),
    )
    monkeypatch.setattr(module, "_setup_ctags", lambda *args, **kwargs: {"available": False, **kwargs})
    posted: list[tuple[str, dict]] = []

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass
        def post(self, endpoint, payload):
            posted.append((endpoint, payload))
            if endpoint == "code/repos/refresh/start":
                assert payload["total_files"] == 0
                assert payload["analyzable_files"] == 0
                return {"repo_id": 7, "refresh_token": "refresh-7"}
            if endpoint == "code/repos/7/refresh/commit":
                assert payload == {"refresh_token": "refresh-7", "manifest_complete": True}
                return _bound_ingest_commit()
            if endpoint == "code/repos/7/lsp-config":
                assert payload["repo_generation"] == 1
                assert payload["source_manifest_digest"] == "d" * 64
                return _bound_lsp_publish(payload)
            raise AssertionError(f"Unexpected endpoint: {endpoint}")
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    module.run(
        SimpleNamespace(
            repo_path=str(repo_path), name="demo", language=None, repo_key=None,
            engagement_dir=tmp_path / "engagement", dry_run=False,
        )
    )
    assert [endpoint for endpoint, _ in posted] == [
        "code/repos/refresh/start",
        "code/repos/7/refresh/commit",
        "code/repos/7/lsp-config",
    ]


def test_code_index_walk_repo_skips_named_pipes(tmp_path):
    module = _load_code_index_module()

    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    os.mkfifo(repo_path / "blocked.py")

    files = module._walk_repo(str(repo_path))

    assert files == [{"file_path": "main.py", "language": "python"}]


def test_code_index_default_output_uses_engagement_analysis_state(monkeypatch, tmp_path):
    module = _load_code_index_module()
    from assess.lib.code_snapshot import SnapshotBuilder, capture_regular_file

    raw = b"print('ok')\n"
    origin = tmp_path / "origin"
    origin.mkdir()
    origin_file = origin / "main.py"
    origin_file.write_bytes(raw)
    builder = SnapshotBuilder(tmp_path / "snapshots", "demo-repo")
    builder.add("main.py", capture_regular_file(origin_file), language="python")
    sealed = builder.finish(
        repo_key="demo-repo",
        repo_name="demo",
        source_origin_path=str(origin),
        git={"head": "", "branch": "", "dirty": None},
    )
    repo_path = sealed.source_path
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text("{}", encoding="utf-8")

    monkeypatch.setitem(sys.modules, "tree_sitter", SimpleNamespace())
    monkeypatch.setattr(
        module,
        "index_file",
        lambda _path, language, source=None, **_kwargs: {
            "language": language,
            "structural_index_available": True,
            "analysis_status": "complete",
            "analysis_mode": "tree_sitter",
            "degradation_reason": None,
            "source_size": len(source),
            "bytes_scanned": len(source),
            "unavailable_dimensions": [],
            "artifact_truncated": False,
            "truncated_dimensions": [],
            "signal_counts": {
                "entry_points": 0,
                "imports": 0,
                "security_sinks": 0,
                "security_sources": 0,
            },
            "total_lines": 1,
            "total_functions": 1,
            "total_exports": 0,
            "functions": [
                {
                    "name": "main",
                    "qualified_name": "main",
                    "line_start": 1,
                    "line_end": 1,
                }
            ],
            "entry_points": [],
            "security_sinks": [],
            "security_sources": [],
            "call_sites": [],
            "imports": [],
            "import_targets": [],
            "exports": [],
            "classes": [],
        },
    )

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def get(self, endpoint):
            if endpoint == "code/repos/7":
                return {
                    "id": 7,
                    "repo_key": "demo-repo",
                    "repo_path": str(repo_path.resolve()),
                    "active_generation": 2,
                    "source_manifest_digest": "e" * 64,
                }
            if endpoint == "code/files?limit=5000&offset=0&repo_id=7":
                return _file_page([
                    {
                        "id": 11,
                        "repo_id": 7,
                        "file_path": "main.py",
                        "file_hash": hashlib.sha256(raw).hexdigest(),
                        "language": "python",
                    }
                ])
            raise AssertionError(endpoint)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    module.run(
        SimpleNamespace(
            repo_path=str(repo_path),
            repo_id=7,
            repo_key=None,
            repo_name=None,
            output_dir=None,
            file_list=None,
            engagement_dir=str(engagement_dir),
        )
    )

    manifest_path = engagement_dir / "tools" / "analysis-state" / "structural-index-manifest.json"
    assert manifest_path.is_file()
    assert not (repo_path / ".code-index").exists()


def test_git_security_history_args_limits_large_repos():
    module = _load_code_ingest_module()

    assert module._git_security_history_args(60_000) == [f"--since={module._GIT_SECURITY_LOOKBACK}"]
    assert module._git_security_history_args(500) == ["--all"]
    assert module._git_security_history_args(None) == ["--all"]


def test_should_descend_skipped_dir_honors_nested_glob_includes():
    """`--include-path '**/vendor/foo.min.js'` must let the walker descend
    into nested 'src/vendor', not just a top-level 'vendor'. Regression for
    PR 14 Codex P2."""
    module = _load_code_ingest_module()

    assert "vendor" in module.SKIP_DIRS, "vendor must remain a skipped dir for this test"

    args = SimpleNamespace(
        include_path=["**/vendor/foo.min.js"],
        include_minified=False,
        include_skipped=False,
    )
    assert module._should_descend_skipped_dir("src/vendor", "vendor", args) is True
    assert module._should_descend_skipped_dir("apps/web/src/vendor", "vendor", args) is True

    # Pattern targets a descendant of the skipped dir (file is several
    # segments below vendor). The walker must still descend into the
    # vendor directory so it can keep going.
    deep_args = SimpleNamespace(
        include_path=["**/vendor/generated/foo.js"],
        include_minified=False,
        include_skipped=False,
    )
    assert module._should_descend_skipped_dir("packages/app/vendor", "vendor", deep_args) is True

    # Top-level vendor was already covered by the prefix path; confirm it
    # still works.
    assert module._should_descend_skipped_dir("vendor", "vendor", args) is True

    # An unrelated skip dir should still be pruned when the pattern names
    # a different dirname.
    assert module._should_descend_skipped_dir("src/node_modules", "node_modules", args) is False

    # Pattern that does not name the skipped dir as a segment must not
    # force descent (otherwise we would defeat the skip list).
    bare_glob = SimpleNamespace(
        include_path=["**/*.js"],
        include_minified=False,
        include_skipped=False,
    )
    assert module._should_descend_skipped_dir("src/vendor", "vendor", bare_glob) is False


def test_git_security_files_parses_streamed_output(monkeypatch, tmp_path):
    module = _load_code_ingest_module()

    captured: dict[str, object] = {}

    def fake_run(cmd, stdout, stderr, text, timeout, env, check):
        captured["cmd"] = cmd
        captured["env"] = env
        captured["timeout"] = timeout
        assert check is False
        stdout.write("commit:abc123\nsrc/auth.py\nsrc/http.py\n\ncommit:def456\nsrc/auth.py\n")
        stdout.flush()
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    files = module._git_security_files(str(tmp_path), [f"--since={module._GIT_SECURITY_LOOKBACK}"])

    assert files == {"src/auth.py", "src/http.py"}
    assert captured["cmd"][-5:] == [
        "log",
        f"--since={module._GIT_SECURITY_LOOKBACK}",
        "--grep=CVE\\|security\\|vulnerability\\|fix.*vuln\\|buffer.overflow\\|use.after.free",
        "--format=commit:%H",
        "--name-only",
    ]


def test_git_churn_scores_warns_on_timeout(monkeypatch, capsys, tmp_path):
    module = _load_code_ingest_module()

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git log", timeout=module._GIT_LOG_TIMEOUT_SECONDS)

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    assert module._git_churn_scores(str(tmp_path)) == {}
    assert "git churn scan timed out" in capsys.readouterr().err


def test_code_ingest_limits_security_scan_for_large_histories(monkeypatch, capsys, tmp_path):
    module = _load_code_ingest_module()

    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (repo_path / ".git").mkdir()
    _mock_ingest_git(module, monkeypatch)

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path / "engagement"),
        ),
    )
    monkeypatch.setattr(module, "_git_commit_count", lambda repo_path: 60_000)
    monkeypatch.setattr(module, "_git_churn_scores", lambda repo_path: {})

    captured: dict[str, object] = {}

    def fake_security_files(repo_path, history_args):
        captured["history_args"] = history_args
        return set()

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict):
            if endpoint == "code/repos/refresh/start":
                return {"repo_id": 7, "refresh_token": "refresh-7"}
            if endpoint == "code/repos/7/refresh/files":
                return {"staged": len(payload["files"])}
            if endpoint == "code/repos/7/refresh/commit":
                return _bound_ingest_commit()
            if endpoint == "code/repos/7/lsp-config":
                assert payload["repo_generation"] == 1
                assert payload["source_manifest_digest"] == "d" * 64
                return _bound_lsp_publish(payload)
            raise AssertionError(f"Unexpected endpoint: {endpoint}")

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "_git_security_files", fake_security_files)
    monkeypatch.setattr(module, "_setup_ctags", lambda *args, **kwargs: {"available": False, **kwargs})
    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            repo_path=str(repo_path),
            name="demo",
            language=None,
            repo_key=None,
            engagement_dir=tmp_path / "engagement",
        )
    )

    assert captured["history_args"] == [f"--since={module._GIT_SECURITY_LOOKBACK}"]
    assert "limiting security scan to current branch over the last" in capsys.readouterr().err


def test_code_classify_resolves_file_path_to_file_id(monkeypatch, tmp_path):
    module = _load_code_classify_module()

    payload_path = tmp_path / "classifications.json"
    payload_path.write_text(
        json.dumps([
            {
                "file_path": "src/parser.py",
                "classification": "critical",
                "role": "parser",
                "slot_types": ["NETWORK-INPUT"],
                "analysis_priority": 95,
            }
        ]),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "code/files?limit=10000&offset=0"
            return _file_page([{"id": 42, "repo_id": 7, "file_path": "src/parser.py"}])

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"updated": 1, "total": 1}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(engagement_dir=tmp_path, classifications_json=str(payload_path)))

    assert captured["endpoint"] == "code/files/bulk-classify"
    posted = captured["payload"]["classifications"][0]
    assert posted["file_id"] == 42
    assert "file_path" not in posted


def test_code_classify_resolves_file_path_from_later_pages(monkeypatch, tmp_path):
    module = _load_code_classify_module()
    monkeypatch.setattr(module, "_CODE_FILE_LOOKUP_PAGE_SIZE", 2)

    payload_path = tmp_path / "classifications.json"
    payload_path.write_text(
        json.dumps(
            [
                {
                    "file_path": "src/routes.py",
                    "classification": "high",
                    "role": "handler",
                    "slot_types": ["NETWORK-INPUT"],
                    "analysis_priority": 75,
                }
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    captured: dict[str, object] = {"requests": []}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            captured["requests"].append(endpoint)
            if endpoint == "code/files?limit=2&offset=0":
                return _file_page([
                    {"id": 40, "repo_id": 7, "file_path": "src/parser.py"},
                    {"id": 41, "repo_id": 7, "file_path": "src/helpers.py"},
                ], total=3)
            if endpoint == "code/files?limit=2&offset=2":
                return _file_page(
                    [{"id": 42, "repo_id": 7, "file_path": "src/routes.py"}],
                    offset=2,
                    total=3,
                )
            raise AssertionError(f"Unexpected endpoint: {endpoint}")

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"updated": 1, "total": 1}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(engagement_dir=tmp_path, classifications_json=str(payload_path)))

    assert captured["requests"] == [
        "code/files?limit=2&offset=0",
        "code/files?limit=2&offset=2",
    ]
    posted = captured["payload"]["classifications"][0]
    assert posted["file_id"] == 42


def test_verify_finding_posts_verification_payload(monkeypatch, tmp_path, capsys):
    module = _load_verify_finding_module()

    payload_path = tmp_path / "verify.json"
    payload_path.write_text(
        json.dumps(
            {
                "verification_status": "false_positive",
                "reason_code": "check-2-guard",
                "reason_text": "Guard proves the path is unreachable.",
                "artifact_ref": "tools/analysis-state/code-verification/VA-001.json",
                "counter_check": {
                    "method": "Trace the guarded source path.",
                    "expected_result": "The input reaches unsafe arithmetic.",
                    "observed_result": "The guard rejects it first.",
                    "falsified_claim": "Attacker input reaches the arithmetic.",
                    "completed": True,
                    "proof_receipt_ids": [17],
                },
                "details": {
                    "kill_check": 2,
                    "kill_reason": "Guard proves the path is unreachable.",
                    "evidence": "validate_header_length() rejects the input before arithmetic.",
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {
                "finding": {
                    "slug": "VA-001",
                    "title": "Suppressed parser finding",
                    "severity": "medium",
                    "workflow_status": "false_positive",
                    "verification_status": "false_positive",
                    "notes": "Killed by verifier.",
                },
                "transition": {"action": "verified_false_positive"},
            }

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=tmp_path,
            finding_slug="VA-001",
            payload_file=str(payload_path),
            inline_payload=None,
        )
    )

    assert captured["endpoint"] == "findings/VA-001/verify"
    assert captured["payload"]["verification_status"] == "false_positive"
    assert captured["payload"]["counter_check"]["completed"] is True
    assert "\"verified_false_positive\"" in capsys.readouterr().out


def test_verify_finding_narrative_relative_path_resolves_under_engagement_dir(
    monkeypatch, tmp_path, capsys
):
    """A relative --narrative path is resolved under the engagement root (how the
    artifact endpoint resolves it), NOT the caller's CWD — so the supported
    ``--engagement-dir … --narrative notes/debate.md`` flow is accepted, while a
    genuinely-missing path is still rejected fast before any POST.
    """
    module = _load_verify_finding_module()

    # Narrative lives under the engagement dir, not the test's CWD.
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "debate.md").write_text("# debate\n", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    posts: list[str] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            pass

        def get(self, endpoint: str):
            assert endpoint == "findings/VA-001"
            return {
                "slug": "VA-001",
                "canonical_location": "https://target.example/search?q",
                "provenance": {},
            }

        def post(self, endpoint: str, payload: dict):
            posts.append(endpoint)
            if endpoint == "findings/VA-001/verify":
                return {"finding": {"slug": "VA-001"}}
            return {"id": 1, "relative_path": payload.get("path")}

        def close(self) -> None:
            return None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    plan_file = tmp_path / "next-test.json"
    plan_file.write_text(json.dumps({
        "hypothesis": "The search parameter reaches the query unescaped.",
        "confirm_if": "A quote in q changes the result set.",
        "falsify_if": "q is bound as a parameter.",
        "route_hint": "live",
    }), encoding="utf-8")

    args = SimpleNamespace(
        engagement_dir=tmp_path,
        finding_slug="VA-001",
        payload=None,
        inline_payload=None,
        verification_status="pending_runtime_proof",
        reason_text="Strong but awaiting runtime proof.",
        reason_code="",
        new_severity=None,
        evidence_ref="",
        artifact_ref="",
        narrative="notes/debate.md",  # relative — exists under engagement dir only
        notes="",
        source_name="vulnerability-analyst",
        details_inline=None,
        provenance_inline=None,
        proof_receipt_ids=None,
        counter_check_file=None,
        severity_variance_file=None,
        next_test_file=str(plan_file),
    )

    module.run(args)
    # Resolved under the engagement dir → both the verify and the artifact POST fire.
    assert posts == ["findings/VA-001/verify", "artifacts"]

    # A genuinely-missing relative path is rejected before ANY POST.
    posts.clear()
    args.narrative = "notes/missing.md"
    with pytest.raises(SystemExit):
        module.run(args)
    assert posts == []


def test_code_dispatch_queue_flattens_batch_wrappers_and_resolves_paths(monkeypatch, tmp_path, capsys):
    module = _load_code_dispatch_module()

    queue_path = tmp_path / "queue.json"
    queue_path.write_text(
        json.dumps(
            [
                {
                    "batch_theme": "auth-module",
                    "priority": 91,
                    "slot_types": ["NETWORK-INPUT"],
                    "guidance_hypotheses": ["Check auth boundary first"],
                    "files": [
                        "src/parser.py",
                        "src/helpers/*.py",
                    ],
                },
                {
                    "items": [
                        {
                            "file_path": "src/routes.py",
                            "priority": 70,
                            "guidance_hypotheses": ["Trace request handlers"],
                        }
                    ]
                },
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path)),
    )

    def fake_snapshot(engagement_dir: str, category: str, label: str, payload, source_path=None, metadata=None):
        path = tmp_path / f"{category}-{label}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    monkeypatch.setattr(module, "write_json_snapshot", fake_snapshot)

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "code/files?limit=10000&offset=0"
            return _file_page([
                {"id": 10, "repo_id": 1, "file_path": "src/parser.py"},
                {"id": 11, "repo_id": 1, "file_path": "src/helpers/auth.py"},
                {"id": 12, "repo_id": 1, "file_path": "src/routes.py"},
            ])

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"inserted": len(payload["items"])}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(action="queue", extra=[str(queue_path)], engagement_dir=tmp_path))

    assert captured["endpoint"] == "code/analysis-queue"
    assert captured["payload"]["mode"] == "initial"
    assert captured["payload"]["items"] == [
        {
            "file_id": 10,
            "priority": 91,
            "batch_theme": "auth-module",
            "slot_types": ["NETWORK-INPUT"],
            "guidance_hypotheses": ["Check auth boundary first"],
        },
        {
            "file_id": 11,
            "priority": 91,
            "batch_theme": "auth-module",
            "slot_types": ["NETWORK-INPUT"],
            "guidance_hypotheses": ["Check auth boundary first"],
        },
        {
            "file_id": 12,
            "priority": 70,
            "batch_theme": "",
            "slot_types": [],
            "guidance_hypotheses": ["Trace request handlers"],
        },
    ]
    assert (
        "Queue outcomes: inserted=3, updated=0, already-active=0, conflicts=0"
        in capsys.readouterr().out
    )


def test_code_dispatch_queue_resolves_file_path_from_later_pages(monkeypatch, tmp_path):
    module = _load_code_dispatch_module()
    monkeypatch.setattr(module, "_CODE_FILE_LOOKUP_PAGE_SIZE", 2)

    queue_path = tmp_path / "queue.json"
    queue_path.write_text(
        json.dumps(
            [
                {
                    "file_path": "src/routes.py",
                    "priority": 70,
                    "guidance_hypotheses": ["Trace request handlers"],
                }
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    def fake_snapshot(engagement_dir: str, category: str, label: str, payload, source_path=None, metadata=None):
        path = tmp_path / f"{category}-{label}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    monkeypatch.setattr(module, "write_json_snapshot", fake_snapshot)

    captured: dict[str, object] = {"requests": []}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            captured["requests"].append(endpoint)
            if endpoint == "code/files?limit=2&offset=0":
                return _file_page([
                    {"id": 10, "repo_id": 1, "file_path": "src/parser.py"},
                    {"id": 11, "repo_id": 1, "file_path": "src/helpers/auth.py"},
                ], total=3)
            if endpoint == "code/files?limit=2&offset=2":
                return _file_page(
                    [{"id": 12, "repo_id": 1, "file_path": "src/routes.py"}],
                    offset=2,
                    total=3,
                )
            raise AssertionError(f"Unexpected endpoint: {endpoint}")

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"inserted": len(payload["items"])}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(action="queue", extra=[str(queue_path)], engagement_dir=tmp_path))

    assert captured["requests"] == [
        "code/files?limit=2&offset=0",
        "code/files?limit=2&offset=2",
    ]
    assert captured["payload"]["items"] == [
        {
            "file_id": 12,
            "priority": 70,
            "batch_theme": "",
            "slot_types": [],
            "guidance_hypotheses": ["Trace request handlers"],
        }
    ]


def test_code_dispatch_requeue_triggers_reports_partial_failures(monkeypatch, tmp_path, capsys):
    module = _load_code_dispatch_module()

    triggers_path = tmp_path / "triggers.json"
    triggers_path.write_text(
        json.dumps(
            [
                {
                    "file_path": "src/parser.py",
                    "repo_id": 7,
                    "reason": "shared helper",
                    "vuln_class": "web-app-injection",
                },
                {"file_path": "src/missing.py", "reason": "missing target", "vuln_class": "ssrf"},
                {"file_path": "src/shared.py", "reason": "ambiguous target", "vuln_class": "xss"},
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    def fake_snapshot(engagement_dir: str, category: str, label: str, payload, source_path=None, metadata=None):
        path = tmp_path / f"{category}-{label}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    monkeypatch.setattr(module, "write_json_snapshot", fake_snapshot)

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {
                "input_trigger_count": 3,
                "target_count": 1,
                "inserted": 1,
                "already_queued": 0,
                "already_completed": 0,
                "blocked": 0,
                "reopened_terminal_files": 0,
                "outcomes": [],
                "inputs": [],
                "not_found": ["src/missing.py"],
                "ambiguous": ["src/shared.py"],
            }

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    # An unresolved or ambiguous selector is a partial application, so the command
    # must not report success: the caller has to know which inputs never landed
    # before it decides whether to retry.
    with pytest.raises(SystemExit) as exc:
        module.run(
            SimpleNamespace(
                action="requeue-triggers", extra=[str(triggers_path)], engagement_dir=tmp_path
            )
        )
    assert exc.value.code == 1

    assert captured["endpoint"] == "code/analysis-queue/requeue"
    assert captured["payload"]["items"][0]["trigger_context"]["source"] == "cross_file_trigger"
    assert captured["payload"]["items"][0]["repo_id"] == 7
    assert "repo_id" not in captured["payload"]["items"][0]["trigger_context"]
    captured_output = capsys.readouterr()
    # Inputs and targets are counted separately because they cannot be the same
    # number: three trigger rows here name one target file.
    assert "Requeued 3 trigger input(s) across 1 target(s)" in captured_output.out
    assert "not found: src/missing.py" in captured_output.err
    assert "ambiguous without repo_id: src/shared.py" in captured_output.err


def test_code_dispatch_queue_rejects_obsolete_context_id(monkeypatch, tmp_path):
    module = _load_code_dispatch_module()

    queue_path = tmp_path / "queue.json"
    queue_path.write_text(
        json.dumps(
            [
                {
                    "file_id": 10,
                    "context_id": 77,
                    "priority": 91,
                    "batch_theme": "auth-module",
                    "slot_types": ["NETWORK-INPUT"],
                }
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path)),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(action="queue", extra=[str(queue_path)], engagement_dir=tmp_path))

    assert excinfo.value.code == 1


def test_code_dispatch_done_requires_single_item_and_posts_cwe_coverage(monkeypatch, tmp_path):
    module = _load_code_dispatch_module()

    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(
        json.dumps([{"family": "web-app-injection", "effort": 85}]),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    def fake_snapshot(engagement_dir: str, category: str, label: str, payload, source_path=None, metadata=None):
        path = tmp_path / f"{category}-{label}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    monkeypatch.setattr(module, "write_json_snapshot", fake_snapshot)

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"updated": 1}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            action="done",
            extra=["42", "code-vuln-hunter", "lease-42", "clean", str(coverage_path), "Reviewed"],
            engagement_dir=tmp_path,
        )
    )

    assert captured["endpoint"] == "code/analysis-queue/done"
    assert captured["payload"] == {
        "item_ids": [42],
        "agent_name": "code-vuln-hunter",
        "lease_token": "lease-42",
        "disposition": "clean",
        "notes": "Reviewed",
        "cwe_coverage": [{"family": "web-app-injection", "effort": 85}],
    }

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                action="done",
                extra=["42,43", "code-vuln-hunter", "lease-42", "clean", str(coverage_path)],
                engagement_dir=tmp_path,
            )
        )
    assert excinfo.value.code == 1


def test_code_dispatch_fetch_posts_atomic_lane_filters(monkeypatch, tmp_path):
    module = _load_code_dispatch_module()
    ids_path = tmp_path / "queue-ids.json"
    ids_path.write_text(json.dumps([9, 4, 9]), encoding="utf-8")
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(
        module,
        "write_json_snapshot",
        lambda *args, **kwargs: tmp_path / "fetch.json",
    )
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            pass

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return []

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    module.run(
        SimpleNamespace(
            action="fetch",
            extra=[
                "5",
                "lane-agent",
                "--repo-id",
                "12",
                "--classification",
                "high",
                "--batch-theme",
                "auth-boundary",
                "--ids-file",
                str(ids_path),
            ],
            engagement_dir=tmp_path,
        )
    )

    assert captured == {
        "endpoint": "code/analysis-queue/fetch",
        "payload": {
            "limit": 5,
            "agent_name": "lane-agent",
            "repo_id": 12,
            "classification": "high",
            "batch_theme": "auth-boundary",
            "item_ids": [4, 9],
        },
    }


def test_code_dispatch_ids_file_accepts_process_substitution_descriptor():
    module = _load_code_dispatch_module()
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"[7, 8, 7]\n")
        os.close(write_fd)
        write_fd = -1

        assert module._ids_from_file(f"/dev/fd/{read_fd}") == [7, 8]
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)


@pytest.mark.parametrize("payload", ["[true]", "[1.5]", '[\"1\"]', "[0]", "[-1]"])
def test_code_dispatch_ids_file_rejects_non_strict_positive_json_ids(
    payload, tmp_path
):
    module = _load_code_dispatch_module()
    ids_path = tmp_path / "queue-ids.json"
    ids_path.write_text(payload, encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        module._ids_from_file(str(ids_path))

    assert excinfo.value.code == 1


def test_code_dispatch_ids_file_handles_json_integer_digit_limit(tmp_path):
    module = _load_code_dispatch_module()
    ids_path = tmp_path / "queue-ids.json"
    ids_path.write_text(f"[{'9' * 5000}]", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        module._ids_from_file(str(ids_path))

    assert excinfo.value.code == 1


def test_code_dispatch_resolve_triggers_posts_terminal_resolution(monkeypatch, tmp_path):
    module = _load_code_dispatch_module()

    triggers_path = tmp_path / "triggers.json"
    triggers_path.write_text(
        json.dumps(
            [
                {
                    "file_path": "bin/StorageService.dll",
                    "vuln_class": "web-app-injection",
                    "repo_id": 7,
                }
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    def fake_snapshot(engagement_dir: str, category: str, label: str, payload, source_path=None, metadata=None):
        path = tmp_path / f"{category}-{label}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    monkeypatch.setattr(module, "write_json_snapshot", fake_snapshot)

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"resolved": 1, "total": 1}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            action="resolve-triggers",
            extra=[
                str(triggers_path),
                "external_context_unavailable",
                "source",
                "not",
                "provided",
            ],
            engagement_dir=tmp_path,
        )
    )

    assert captured["endpoint"] == "code/triggers/resolve"
    assert captured["payload"] == {
        "items": [
            {
                "file_path": "bin/StorageService.dll",
                "repo_id": 7,
                "vuln_class": "web-app-injection",
            }
        ],
        "resolution_status": "external_context_unavailable",
        "resolution_note": "source not provided",
    }


def test_code_record_analysis_rejects_bad_nested_payloads_before_post(tmp_path, capsys):
    module = _load_code_record_analysis_module()

    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(
        json.dumps(
            [
                {
                    "queue_item_id": 101,
                    "agent_name": "code-vuln-hunter",
                    "lease_token": "lease-101",
                    "file_id": 1,
                    "disposition": "clean",
                    "cwe_coverage": {"cwe_coverage": [{"family": "ssrf", "effort": 80}]},
                }
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(analysis_json=str(analysis_path), engagement_dir=tmp_path))

    assert excinfo.value.code == 1
    assert "cwe_coverage must be a JSON array" in capsys.readouterr().err


def test_code_record_analysis_accepts_index_callable_span_names():
    module = _load_code_record_analysis_module()
    result = {
        "disposition": "clean",
        "callable_refs": [{
            "file_id": 7,
            "name": "run",
            "qualified_name": "Handler.run",
            "line_start": 12,
            "line_end": 18,
        }],
    }

    module._validate_source_receipt(0, result)

    assert result["callable_refs"][0] == {
        "file_id": 7,
        "name": "run",
        "qualified_name": "Handler.run",
        "start_line": 12,
        "end_line": 18,
    }


def test_code_record_analysis_rejects_invalid_supersedes_before_backend(
    monkeypatch, tmp_path, capsys
):
    module = _load_code_record_analysis_module()
    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(
        json.dumps({
            "queue_item_id": 101,
            "agent_name": "code-vuln-hunter",
            "lease_token": "lease-101",
            "disposition": "clean",
            "reviewed_spans": [{"file_id": 7, "start_line": 1, "end_line": 1}],
            "supersedes": True,
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must reject before backend")),
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(analysis_json=str(analysis_path), engagement_dir=tmp_path)
        )

    assert excinfo.value.code == 1
    assert "supersedes must be a positive integer analysis-result ID" in capsys.readouterr().err


def test_code_record_analysis_supersede_targets_a_completed_queue_item(
    monkeypatch, tmp_path
):
    module = _load_code_record_analysis_module()
    analysis_path = tmp_path / "correction.json"
    analysis_path.write_text(
        json.dumps({
            "queue_item_id": 51,
            "agent_name": "original-reviewer",
            "lease_token": "original-lease",
            "disposition": "clean",
            "reviewed_spans": [{"file_id": 7, "start_line": 1, "end_line": 1}],
            "evidence": "Corrected source evidence.",
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args: SimpleNamespace(base_url="http://example.test", engagement_key="eng", engagement_dir=tmp_path),
    )
    snapshots = iter((tmp_path / "submit.json", tmp_path / "response.json"))
    monkeypatch.setattr(
        module,
        "write_json_snapshot",
        lambda *_args, **_kwargs: next(snapshots),
    )
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, *_args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, endpoint):
            captured["get"] = endpoint
            return [{"id": 77, "queue_item_id": 51}]

        def post(self, endpoint, payload):
            captured["post"] = (endpoint, payload)
            return {
                **payload,
                "id": 88,
                "supersedes": 77,
                "receipt_kind": "file",
                "receipt_binding_status": "source_span",
                "callable_refs": [],
                "reviewed_spans": [
                    {
                        "file_id": 7,
                        "file_path": "src/parser.py",
                        "start_line": 1,
                        "end_line": 1,
                        "label": "",
                    }
                ],
            }

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            analysis_json=str(analysis_path),
            engagement_dir=tmp_path,
            supersede=51,
        )
    )

    assert captured["get"] == "code/analysis-results?queue_item_id=51"
    endpoint, submitted = captured["post"]
    assert endpoint == "code/analysis-results"
    assert submitted["queue_item_id"] == 51
    assert submitted["supersedes"] == 77


def test_code_record_analysis_requires_grouped_source_receipt_before_post(
    monkeypatch, tmp_path, capsys
):
    module = _load_code_record_analysis_module()
    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(
        json.dumps(
            {
                "queue_item_id": 101,
                "agent_name": "code-vuln-hunter",
                "lease_token": "lease-101",
                "disposition": "clean",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must reject before backend")),
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(analysis_json=str(analysis_path), engagement_dir=tmp_path)
        )

    assert excinfo.value.code == 1
    assert "callable_refs or reviewed_spans" in capsys.readouterr().err


def test_code_record_analysis_rejects_legacy_function_name_before_post(
    monkeypatch, tmp_path, capsys
):
    module = _load_code_record_analysis_module()
    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(
        json.dumps(
            {
                "queue_item_id": 101,
                "agent_name": "code-vuln-hunter",
                "lease_token": "lease-101",
                "disposition": "clean",
                "reviewed_spans": [
                    {"file_id": 7, "start_line": 1, "end_line": 1}
                ],
                "function_name": "legacy-name-is-not-a-write-contract",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must reject before backend")),
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(analysis_json=str(analysis_path), engagement_dir=tmp_path)
        )

    assert excinfo.value.code == 1
    assert "function_name is historical read/filter data" in capsys.readouterr().err


def test_code_record_registers_variant_check_leaf():
    module = _load_code_record_group_module()
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    module.register(subparsers)

    args = parser.parse_args(["code-record", "variant-check", "receipt.json"])

    assert args.code_record_kind == "variant-check"
    assert args.receipt_json == "receipt.json"


def test_code_record_variant_parent_cap_mirrors_backend():
    from app.services import code_analysis

    module = _load_code_record_variant_check_module()

    assert module.MAX_VARIANT_PARENT_FINDINGS == code_analysis.MAX_VARIANT_PARENT_FINDINGS


@pytest.mark.parametrize("input_mode", ["file", "stdin"])
def test_code_record_variant_check_posts_exact_receipt_and_prints_backend_record(
    input_mode,
    monkeypatch,
    tmp_path,
    capsys,
):
    module = _load_code_record_variant_check_module()
    payload = _variant_check_payload()
    receipt = {
        "id": 91,
        **payload,
        "current_file_id": payload["file_id"],
        "file_path": "src/parser.c",
        "language": "c",
        "classification": "critical",
        "role": "parser",
        "slot_types": ["NETWORK-INPUT"],
        "parent_finding_set_digest": "c" * 64,
        "variant_input_digest": "d" * 64,
        "receipt_fingerprint": "e" * 64,
        "created_at": "2026-08-05T12:00:00Z",
        "current": True,
    }
    posted: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
        ),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            assert base_url == "http://example.test"
            assert engagement_key == "eng"

        def post(self, endpoint: str, body: dict[str, object]):
            posted.append((endpoint, body))
            return receipt

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    if input_mode == "file":
        receipt_path = tmp_path / "variant-check.json"
        receipt_path.write_text(json.dumps(payload), encoding="utf-8")
        source = str(receipt_path)
    else:
        source = "-"
        monkeypatch.setattr(module.sys, "stdin", io.StringIO(json.dumps(payload)))

    module.run(SimpleNamespace(receipt_json=source, engagement_dir=tmp_path))

    assert posted == [("code/variant-checks", payload)]
    assert json.loads(capsys.readouterr().out) == receipt


@pytest.mark.parametrize(
    ("mutate", "error_fragment"),
    [
        (lambda payload: payload.pop("dispatch_id"), "missing required fields: dispatch_id"),
        (lambda payload: payload.__setitem__("unexpected", True), "unknown fields: unexpected"),
        (lambda payload: payload.__setitem__("file_id", True), "file_id must be an integer"),
        (lambda payload: payload.__setitem__("repo_generation", 0), "repo_generation must be at least 1"),
        (
            lambda payload: payload.__setitem__("source_manifest_digest", "A" * 64),
            "source_manifest_digest must be a lowercase SHA-256 digest",
        ),
        (
            lambda payload: payload.__setitem__("parent_finding_slugs", ["CH-004", "CH-001"]),
            "parent_finding_slugs must be sorted",
        ),
        (
            lambda payload: payload.__setitem__("parent_finding_slugs", ["CH-001", "CH-001"]),
            "parent_finding_slugs must not contain duplicates",
        ),
        (
            lambda payload: payload.__setitem__("parent_finding_slugs", [" CH-001"]),
            "parent_finding_slugs entries must not have leading or trailing whitespace",
        ),
        (
            lambda payload: payload.__setitem__("parent_finding_slugs", ["CH-\u0001"]),
            "parent_finding_slugs entries must not contain control characters",
        ),
        (
            lambda payload: payload.__setitem__(
                "parent_finding_slugs",
                [f"CH-{index:04d}" for index in range(1, 1002)],
            ),
            "parent_finding_slugs must contain at most 1000 entries",
        ),
        (lambda payload: payload.__setitem__("status", "clean"), "status must be 'completed'"),
        (lambda payload: payload.__setitem__("evidence_ref", ""), "evidence_ref must be 1 to 4096 characters"),
        (
            lambda payload: payload.__setitem__("evidence_ref", " artifacts/check.json "),
            "evidence_ref must not have leading or trailing whitespace",
        ),
        (lambda payload: payload.__setitem__("rationale", "x" * 20001), "rationale must be 1 to 20000 characters"),
        (
            lambda payload: payload.__setitem__("rationale", "   "),
            "rationale must not have leading or trailing whitespace",
        ),
    ],
)
def test_code_record_variant_check_rejects_schema_drift_before_post(
    mutate,
    error_fragment,
    monkeypatch,
    tmp_path,
    capsys,
):
    module = _load_code_record_variant_check_module()
    payload = _variant_check_payload()
    mutate(payload)
    receipt_path = tmp_path / "invalid.json"
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(
        module,
        "load_config",
        lambda _engagement_dir: pytest.fail("invalid input reached configuration or POST"),
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(receipt_json=str(receipt_path), engagement_dir=tmp_path))

    assert excinfo.value.code == 1
    assert error_fragment in capsys.readouterr().err


@pytest.mark.parametrize(
    ("raw", "error_fragment"),
    [
        ("", "receipt input is empty"),
        ("{not-json", "receipt input is not valid JSON"),
        ("[]", "receipt input must contain one JSON object"),
        ('{"dispatch_id": 1, "dispatch_id": 2}', "duplicate JSON field: dispatch_id"),
    ],
)
def test_code_record_variant_check_rejects_invalid_json_input(
    raw,
    error_fragment,
    monkeypatch,
    tmp_path,
    capsys,
):
    module = _load_code_record_variant_check_module()
    receipt_path = tmp_path / "invalid.json"
    receipt_path.write_text(raw, encoding="utf-8")
    monkeypatch.setattr(
        module,
        "load_config",
        lambda _engagement_dir: pytest.fail("invalid input reached configuration or POST"),
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(receipt_json=str(receipt_path), engagement_dir=tmp_path))

    assert excinfo.value.code == 1
    assert error_fragment in capsys.readouterr().err


@pytest.mark.parametrize("input_mode", ["file", "stdin"])
def test_code_record_variant_check_bounds_file_and_stdin_before_json_parse(
    input_mode,
    monkeypatch,
    tmp_path,
    capsys,
):
    module = _load_code_record_variant_check_module()
    monkeypatch.setattr(module, "MAX_JSON_ARTIFACT_BYTES", 32)
    if input_mode == "file":
        receipt_path = tmp_path / "oversized.json"
        receipt_path.write_text("x" * 33, encoding="utf-8")
        source = str(receipt_path)
    else:
        source = "-"
        monkeypatch.setattr(module.sys, "stdin", io.StringIO("x" * 33))

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(receipt_json=source, engagement_dir=tmp_path))

    assert excinfo.value.code == 1
    assert "exceeds 32 bytes" in capsys.readouterr().err


def test_code_record_variant_check_does_not_accept_inline_json(monkeypatch, tmp_path, capsys):
    module = _load_code_record_variant_check_module()
    inline = json.dumps(_variant_check_payload())
    monkeypatch.setattr(
        module,
        "load_config",
        lambda _engagement_dir: pytest.fail("inline JSON reached configuration or POST"),
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(receipt_json=inline, engagement_dir=tmp_path))

    assert excinfo.value.code == 1
    assert "could not read receipt file" in capsys.readouterr().err


def test_code_record_variant_check_rejects_non_object_backend_response(
    monkeypatch,
    tmp_path,
    capsys,
):
    module = _load_code_record_variant_check_module()
    receipt_path = tmp_path / "variant-check.json"
    receipt_path.write_text(json.dumps(_variant_check_payload()), encoding="utf-8")
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
        ),
    )

    class FakeClient:
        def __init__(self, _base_url: str, _engagement_key: str) -> None:
            pass

        def post(self, _endpoint: str, _body: dict[str, object]):
            return []

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(receipt_json=str(receipt_path), engagement_dir=tmp_path))

    assert excinfo.value.code == 1
    assert "backend response must be a JSON object" in capsys.readouterr().err


def test_code_record_analysis_validates_whole_batch_before_any_post(monkeypatch, tmp_path):
    module = _load_code_record_analysis_module()

    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(
        json.dumps(
            [
                {"queue_item_id": 201, "file_id": 1, "agent_name": "hunter", "lease_token": "lease-201", "disposition": "clean"},
                {
                    "queue_item_id": 202,
                    "agent_name": "hunter",
                    "lease_token": "lease-202",
                    "file_id": 2,
                    "disposition": "clean",
                    "cross_file_triggers": [{"file_path": "src/missing.py", "vuln_class": "ssrf"}],
                },
            ]
        ),
        encoding="utf-8",
    )

    posted: list[dict] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict):
            posted.append(payload)
            return {"id": len(posted)}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(analysis_json=str(analysis_path), engagement_dir=tmp_path))

    assert excinfo.value.code == 1
    assert posted == []


def test_code_dispatch_reset_stale_rejects_zero_before_backend(monkeypatch, tmp_path, capsys):
    module = _load_code_dispatch_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    class FakeClient:
        def __init__(self, *_args, **_kwargs) -> None:
            raise AssertionError("reset-stale 0 must not call the backend")
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(action="reset-stale", extra=["0"], engagement_dir=tmp_path))

    assert excinfo.value.code == 1
    assert "minutes >= 1" in capsys.readouterr().err


def test_post_accepts_inline_json_payload(monkeypatch, capsys):
    module = _load_post_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"id": 7, "credential_key": payload["credential_key"]}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=Path("/tmp/eng"),
            endpoint="credentials",
            payload='{"credential_key":"demo","kind":"token","principal":"api-user"}',
            inline_payload=None,
        )
    )

    assert captured["endpoint"] == "credentials"
    assert captured["payload"] == {
        "credential_key": "demo",
        "kind": "token",
        "principal": "api-user",
    }
    assert '"credential_key": "demo"' in capsys.readouterr().out.lower()


def test_post_rejects_malformed_durable_receipt_without_retrying(monkeypatch, capsys):
    module = _load_post_module()
    from assess.lib.client import AssessError

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    class FakeClient:
        calls = 0

        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict):
            type(self).calls += 1
            return {"id": 7, "credential_key": "a-different-row"}

        def close(self) -> None:
            return None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(AssessError, match="do not retry automatically"):
        module.run(
            SimpleNamespace(
                engagement_dir=Path("/tmp/eng"),
                endpoint="credentials",
                payload='{"credential_key":"demo","kind":"token","principal":"api-user"}',
                inline_payload=None,
            )
        )

    assert FakeClient.calls == 1
    assert capsys.readouterr().out == ""


def test_post_rejects_endpoint_without_owned_response_contract(monkeypatch, capsys):
    module = _load_post_module()
    monkeypatch.setattr(
        module,
        "load_config",
        lambda _engagement_dir: (_ for _ in ()).throw(
            AssertionError("unsupported endpoint must be rejected before config resolution")
        ),
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir="/tmp/eng",
                endpoint="future-untyped-endpoint",
                payload='{"value":"demo"}',
                inline_payload=None,
            )
        )

    assert excinfo.value.code == 1
    assert "no durable response contract" in capsys.readouterr().err


def test_post_rejects_raw_finding_creation_and_points_to_helper(capsys):
    module = _load_post_module()

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=Path("/tmp/eng"),
                endpoint="findings",
                payload='{"title":"Inline finding"}',
                inline_payload=None,
            )
        )

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "finding record" in err
    assert "vigil assess contract finding record" in err


def test_post_rejects_raw_verify_endpoint_and_points_to_helper(capsys):
    module = _load_post_module()

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=Path("/tmp/eng"),
                endpoint="findings/VA-001/verify",
                payload='{"verification_status":"confirmed","reason_text":"reproduced"}',
                inline_payload=None,
            )
        )

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "finding verify" in err
    assert "finding verify --status false_positive" in err
    assert "vigil assess contract finding verify" in err


def test_raw_finding_patch_is_rejected_and_points_to_helper():
    """A raw PATCH to findings/{slug} is rejected and points operators at the
    typed update-finding verb (reset-finding folded into
    ``update-finding --status draft`` in the 2026-07 CLI consolidation).

    The generic ``patch`` verb was removed in WS5, but the ``_RAW_ENDPOINT_RULES``
    redirect survives as the client-layer guard, so this asserts the guard
    directly (mirrors test_coverage_probe_cli_sync's redirect test)."""
    from assess.lib import contracts

    error = contracts.raw_endpoint_error(
        "PATCH", "findings/VA-001", {"workflow_status": "draft"}
    )
    assert error is not None
    assert "finding update" in error
    assert "finding update <slug> --status draft" in error
    assert "vigil assess contract finding update" in error


def test_contract_prints_record_finding_contract(capsys):
    module = _load_contract_module()

    module.run(SimpleNamespace(name="finding", variant=["record"]))

    out = capsys.readouterr().out
    assert "Command: finding record" in out
    assert "Schema: finding-record.schema.json" in out
    assert "Helper defaults:" in out
    assert "workflow_status = active" in out
    assert "verification_status = unreviewed" in out
    assert "Examples:" in out


def test_contract_update_finding_documents_reopen_fold(capsys):
    # reset-finding folded into update-finding --status draft (2026-07 CLI
    # consolidation); the update-finding contract documents the reopen flow.
    module = _load_contract_module()

    module.run(SimpleNamespace(name="finding", variant=["update"]))

    out = capsys.readouterr().out
    assert "Command: finding update" in out
    assert "--status draft" in out
    assert "reopen" in out.lower()


def test_contract_prints_code_record_analysis_contract(capsys):
    # code-record-analysis folded into `code-record analysis` (two-token verb).
    module = _load_contract_module()

    module.run(SimpleNamespace(name="code-record", variant="analysis"))

    out = capsys.readouterr().out
    assert "Command: code-record analysis" in out
    assert "Schema: code-analysis-result.schema.json" in out
    assert "queue_item_id" in out
    assert "file_id = derived by the backend from queue_item_id" in out
    assert "receipt_kind" in out
    assert "callable_refs" in out
    assert "sealed callable registry publication" in out
    assert "whole-file reviewed span" in out
    for incomplete_dimension in ("truncated", "unavailable", "unsupported"):
        assert incomplete_dimension in out
    assert "file_id-only result -> include queue_item_id" in out


def test_contract_prints_code_record_variant_check_contract(capsys):
    module = _load_contract_module()

    module.run(SimpleNamespace(name="code-record", variant=["variant-check"]))

    out = capsys.readouterr().out
    assert "Command: code-record variant-check" in out
    assert "dispatch_id" in out
    assert "parent_finding_slugs" in out
    assert "source_manifest_digest" in out
    assert "vigil assess code-record variant-check -" in out
    assert "one receipt per checked file" in out.lower()
    assert "at most 1000" in out


def test_contract_prints_record_intel_variant_contract(capsys):
    module = _load_contract_module()

    module.run(SimpleNamespace(name="intel", variant=["record", "tech-component"]))

    out = capsys.readouterr().out
    assert "Command: intel record tech-component" in out
    assert "Schema: intel-tech-component.schema.json" in out
    assert "Required top-level fields:" in out
    assert "component" in out
    assert "source -> use source_name" in out


def test_verify_finding_help_is_rendered_from_contract_registry(capsys):
    cli = _load_cli_module()

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["finding", "verify", "--help"])

    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "vigil assess finding verify <slug> --status confirmed --reason" in out
    assert "vigil assess contract finding verify" in out
    assert "Contract:" not in out


def test_update_finding_help_shows_payload_file_usage(capsys):
    cli = _load_cli_module()

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["finding", "update", "--help"])

    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "vigil assess finding update <slug> --payload-file" in out


def test_verify_finding_builds_false_positive_payload_from_flags(monkeypatch, tmp_path, capsys):
    # kill-finding folded into the proof-backed false-positive verification flow.
    module = _load_verify_finding_module()
    counter_check_path = tmp_path / "counter-check.json"
    counter_check_path.write_text(
        json.dumps(
            {
                "method": "Trace the guarded source path.",
                "expected_result": "The input reaches unsafe arithmetic.",
                "observed_result": "validate_length() rejects it first.",
                "falsified_claim": "Attacker input reaches the arithmetic.",
                "completed": True,
                "proof_receipt_ids": [17],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "findings/VA-001"
            return {
                "slug": "VA-001",
                "canonical_location": "https://target.example/search?q",
                "provenance": {},
            }

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"finding": {"slug": "VA-001", "title": "Parser issue"}}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=tmp_path,
            finding_slug="VA-001",
            payload_file=None,
            inline_payload=None,
            verification_status="false_positive",
            reason_text="Guard blocks the path",
            reason_code="manual-kill",
            new_severity=None,
            narrative="",
            evidence_ref="findings.md",
            artifact_ref="audit.json",
            notes="Rechecked manually",
            source_name="operator",
            details_inline=None,
            provenance_inline='{"reviewed_by":"operator"}',
            proof_receipt_ids=None,
            counter_check_file=str(counter_check_path),
            severity_variance_file=None,
        )
    )

    assert captured["endpoint"] == "findings/VA-001/verify"
    assert captured["payload"]["verification_status"] == "false_positive"
    assert captured["payload"]["counter_check"]["completed"] is True
    assert captured["payload"]["counter_check"]["proof_receipt_ids"] == [17]
    assert "VA-001" in capsys.readouterr().out


def test_record_finding_reports_normalized_contract_errors_before_backend(monkeypatch, tmp_path, capsys):
    module = _load_record_finding_module()

    monkeypatch.setattr(module, "next_finding_id", lambda base_url, engagement_key, agent_name: "CH-001")

    payload_path = tmp_path / "finding.json"
    payload_path.write_text(
        json.dumps(
            {
                "title": "Legacy payload",
                "severity": "high",
                "status": "confirmed",
                "confidence": "high",
                "description": "stale prompt field",
                "details": {},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            raise AssertionError("record-finding should fail before contacting the backend")
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=tmp_path,
                agent_name="code-vuln-hunter",
                json_file=str(payload_path),
            )
        )

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "finding payload invalid after helper defaults" in err
    assert "payload.status is not allowed" in err
    assert "payload.confidence is not allowed" in err
    assert "payload.description is not allowed" in err
    assert "payload.details.evidence is required" in err
    assert "payload.details.impact is required" in err
    assert "workflow_status = active" in err
    assert "vigil assess contract finding record" in err


def test_update_finding_patches_by_slug_from_flags(monkeypatch, tmp_path):
    module = _load_update_finding_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "findings/VA-002"
            return {"slug": "VA-002", "row_version": 4}

        def patch(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"finding": {"slug": "VA-002", "title": "Updated"}}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=tmp_path,
            finding_slug="VA-002",
            payload=None,
            inline_payload=None,
            title=None,
            severity="low",
            workflow_status="active",
            defect_family=None,
            root_cause_key=None,
            auth_context=None,
            canonical_location=None,
            summary=None,
            evidence_ref="findings.md",
            notes="Manual review lowered impact",
            source_name="operator",
            reason_code="manual-override",
            reason_text="Reproduced with lower impact",
            artifact_ref="review.json",
            details_inline='{"impact":"limited"}',
            provenance_inline='{"reviewed_by":"operator"}',
        )
    )

    assert captured["endpoint"] == "findings/VA-002"
    assert captured["payload"]["workflow_status"] == "active"
    assert captured["payload"]["severity"] == "low"
    assert captured["payload"]["details"] == {"impact": "limited"}
    assert captured["payload"]["expected_row_version"] == 4


def test_update_finding_reopens_to_draft(monkeypatch, tmp_path):
    # reset-finding folded into `update-finding --status draft` (2026-07 CLI
    # consolidation): reopening for re-triage is a workflow_status patch.
    module = _load_update_finding_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "findings/VA-003"
            return {"slug": "VA-003", "row_version": 7}

        def patch(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {"finding": {"slug": "VA-003", "title": "Reset"}}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=tmp_path,
            finding_slug="VA-003",
            inline_payload=None,
            payload_file=None,
            title=None,
            severity=None,
            workflow_status="draft",
            submission_status=None,
            defect_family=None,
            root_cause_key=None,
            auth_context=None,
            canonical_location=None,
            summary=None,
            evidence_ref=None,
            notes="Undoing prior false positive",
            source_name="operator",
            reason_code="retriage",
            reason_text="Needs another review pass",
            artifact_ref="review.json",
            expected_row_version=None,
            details_inline=None,
            provenance_inline='{"reviewed_by":"operator"}',
            notes_replace=False,
            details_replace=False,
            evidence_type=None,
        )
    )

    assert captured["endpoint"] == "findings/VA-003"
    assert captured["payload"]["workflow_status"] == "draft"
    assert captured["payload"]["reason_text"] == "Needs another review pass"


def test_list_findings_pushes_status_and_severity_to_backend(monkeypatch, capsys):
    module = _load_list_findings_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "findings?severity=high&workflow_status=active&limit=101&offset=0"
            return [
                {
                    "slug": "ACTIVE-001",
                    "severity": "high",
                    "workflow_status": "active",
                    "verification_status": "unreviewed",
                    "title": "Live issue",
                    "summary": "",
                    "canonical_location": "",
                    "source_name": "vulnerability-analyst",
                },
            ]

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=Path("/tmp/eng"),
            severity="high",
            workflow_status="active",
            verification_status=None,
            source_name=None,
            slug=None,
            search=None,
            holding=False,
            limit=100,
            offset=0,
            all=False,
            json=False,
        )
    )

    output = capsys.readouterr().out
    assert "ACTIVE-001" in output
    assert "DRAFT-001" not in output


def test_code_dispatch_done_supports_dry_run(monkeypatch, tmp_path, capsys):
    module = _load_code_dispatch_module()
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(json.dumps([{"family": "ssrf", "effort": 80}]), encoding="utf-8")

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            raise AssertionError("dry-run should not create a client")
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=tmp_path,
            action="done",
            extra=["42", "code-vuln-hunter", "lease-42", "clean", str(coverage_path), "--dry-run"],
        )
    )

    output = capsys.readouterr().out
    assert "Dry run only" in output
    assert '"endpoint": "code/analysis-queue/done"' in output


def test_code_dispatch_done_rejects_invalid_disposition(monkeypatch, tmp_path, capsys):
    module = _load_code_dispatch_module()
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(json.dumps([{"family": "ssrf", "effort": 80}]), encoding="utf-8")

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=tmp_path,
                action="done",
                extra=["42", "code-vuln-hunter", "lease-42", "done", str(coverage_path)],
            )
        )

    assert excinfo.value.code == 1
    assert "expected one of: clean, finding, suspicious" in capsys.readouterr().err


def test_code_classify_rejects_slot_types_json_field(tmp_path, capsys):
    module = _load_code_classify_module()
    payload_path = tmp_path / "classify.json"
    payload_path.write_text(
        json.dumps(
            [
                {
                    "file_id": 7,
                    "classification": "high",
                    "slot_types_json": ["NETWORK-INPUT"],
                }
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=tmp_path,
                classifications_json=str(payload_path),
            )
        )

    assert excinfo.value.code == 1
    assert "use 'slot_types' instead" in capsys.readouterr().err


def test_code_classify_reports_all_validation_errors(tmp_path, capsys):
    module = _load_code_classify_module()
    payload_path = tmp_path / "classify.json"
    payload_path.write_text(
        json.dumps(
            [
                {
                    "file_id": 7,
                    "classification": "high",
                    "slot_types": [],
                },
                {
                    "file_id": 8,
                    "classification": "critical",
                    "slot_types": ["NETWORK_INPUT"],
                },
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=tmp_path,
                classifications_json=str(payload_path),
            )
        )

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "Item 0" in err
    assert "slot_types" in err
    assert "Item 1" in err
    assert "NETWORK_INPUT" in err


def test_code_classify_accepts_exec_policy_and_priority_band():
    module = _load_code_classify_module()

    errors = module._validate_classification_payload(
        [
            {
                "file_id": 7,
                "classification": "high",
                "slot_types": ["EXEC-POLICY"],
                "analysis_priority": 79,
            }
        ]
    )

    assert errors == []


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            {"file_id": 7, "classification": "low", "slot_types": []},
            "missing required field 'analysis_priority'",
        ),
        (
            {
                "file_id": 7,
                "classification": "high",
                "slot_types": ["NETWORK-INPUT"],
                "analysis_priority": 80,
            },
            "must be between 50 and 79",
        ),
        (
            {
                "file_id": 7,
                "classification": "skip",
                "slot_types": [],
                "analysis_priority": 1,
            },
            "must be 0",
        ),
        (
            {
                "file_id": 7,
                "classification": "high",
                "slot_types": ["NETWORK-INPUT"],
                "analysis_priority": "70",
            },
            "must be an integer",
        ),
    ],
)
def test_code_classify_validates_required_strict_priority_band(payload, expected):
    module = _load_code_classify_module()

    errors = module._validate_classification_payload([payload])

    assert any(expected in error for error in errors)


@pytest.mark.parametrize("priority", [True, 70.5, "70"])
def test_code_dispatch_queue_requires_strict_integer_priority(
    monkeypatch, tmp_path, priority
):
    module = _load_code_dispatch_module()
    monkeypatch.setattr(module, "_fetch_code_files", lambda cfg: [])
    cfg = SimpleNamespace()

    with pytest.raises(SystemExit) as excinfo:
        module._normalize_queue_items(
            cfg,
            [{"file_id": 7, "priority": priority}],
        )

    assert excinfo.value.code == 1


@pytest.mark.parametrize(
    "module_loader",
    [_load_code_classify_module, _load_code_dispatch_module],
    ids=["classify", "dispatch"],
)
@pytest.mark.parametrize("invalid_file_id", [True, 1.5, "1"])
def test_code_commands_reject_non_integer_file_ids(
    module_loader, invalid_file_id, capsys
):
    module = module_loader()
    resolver = (
        module._resolve_matching_file_ids
        if module_loader is _load_code_classify_module
        else module._resolve_queue_file_ids
    )

    with pytest.raises(SystemExit) as excinfo:
        resolver({"file_id": invalid_file_id}, [])

    assert excinfo.value.code == 1
    assert "file_id" in capsys.readouterr().err


@pytest.mark.parametrize(
    "module_loader",
    [_load_code_classify_module, _load_code_dispatch_module],
    ids=["classify", "dispatch"],
)
@pytest.mark.parametrize("invalid_repo_id", [True, 1.5, "1"])
def test_code_commands_reject_non_integer_repo_ids(
    module_loader, invalid_repo_id, capsys
):
    module = module_loader()
    resolver = (
        module._resolve_matching_file_ids
        if module_loader is _load_code_classify_module
        else module._resolve_queue_file_ids
    )

    with pytest.raises(SystemExit) as excinfo:
        resolver(
            {"file_path": "src/parser.c", "repo_id": invalid_repo_id},
            [{"id": 7, "repo_id": 1, "file_path": "src/parser.c"}],
        )

    assert excinfo.value.code == 1
    assert "repo_id" in capsys.readouterr().err


def test_cli_main_prints_assesserror_without_traceback(monkeypatch, capsys):
    cli_module = _load_cli_module()
    from assess.commands import fetch as fetch_command
    from assess.lib.client import AssessError

    monkeypatch.setattr(
        fetch_command,
        "run",
        lambda args: (_ for _ in ()).throw(AssessError('HTTP 422:\n{"detail":"bad"}')),
    )

    with pytest.raises(SystemExit) as excinfo:
        cli_module.main(["fetch", "summary"])

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "ERROR: HTTP 422" in err
    assert "Traceback" not in err


def test_cli_registers_check_phase_readiness(monkeypatch):
    cli_module = _load_cli_module()
    from assess.commands import check_phase_readiness as command

    called: dict[str, object] = {}

    def fake_run(args):
        called["engagement_dir"] = args.engagement_dir
        called["phase"] = args.phase

    monkeypatch.setattr(command, "run", fake_run)

    cli_module.main(["--engagement-dir", "/tmp/eng", "check-phase-readiness", "--phase", "report"])
    assert called["engagement_dir"] == "/tmp/eng"
    assert called["phase"] == "report"


def _load_code_audit_module():
    repo_root = Path(__file__).resolve().parents[3]
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = repo_root / "agent" / "scripts" / "assess" / "lib" / "code_audit.py"
    spec = importlib.util.spec_from_file_location("test_code_audit", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ctags_handles_missing_binary(tmp_path, monkeypatch):
    module = _load_code_ingest_module()

    # Make ctags unfindable
    monkeypatch.setattr(module, "_resolve_trusted_tool", lambda *args, **kwargs: None)

    result = module._setup_ctags(
        str(tmp_path),
        tmp_path / "ctags",
        [],
        repo_generation=1,
        source_manifest_digest="d" * 64,
    )
    assert result["available"] is False


def test_code_audit_write_snapshot_creates_manifest_and_keeps_metadata(tmp_path):
    module = _load_code_audit_module()

    engagement_dir = tmp_path / "engagement"
    snapshot = module.write_json_snapshot(
        str(engagement_dir),
        category="code-contexts-submit",
        label="module 1 batch",
        payload={"contexts": 1},
        source_path="/tmp/input.json",
        metadata={"command": "code-record-contexts", "count": 1},
    )

    assert snapshot.is_file()
    assert snapshot.name.endswith("-code-contexts-submit-module-1-batch.json")

    manifest_path = engagement_dir / "tools" / "analysis-state" / module.MANIFEST_FILENAME
    assert manifest_path.is_file()
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o644
    manifest = json.loads(manifest_path.read_text())
    assert manifest["artifact_count"] == 1
    entry = manifest["entries"][0]
    assert entry["name"] == snapshot.name
    assert entry["kind"] == "code-contexts-submit"
    assert entry["label"] == "module 1 batch"
    assert entry["source_path"] == "/tmp/input.json"
    assert entry["metadata"]["command"] == "code-record-contexts"


def test_code_audit_same_second_snapshots_never_overwrite(tmp_path, monkeypatch):
    module = _load_code_audit_module()
    monkeypatch.setattr(module, "_timestamp_slug", lambda: "20260806T040136000000Z")
    engagement_dir = tmp_path / "engagement"

    first = module.write_json_snapshot(
        str(engagement_dir),
        category="code-queue-done",
        label="clean result",
        payload={"item": 3},
        source_path="queue-3.json",
        metadata={"sequence": 1},
    )
    second = module.write_json_snapshot(
        str(engagement_dir),
        category="code-queue-done",
        label="clean result",
        payload={"item": 4},
        source_path="queue-4.json",
        metadata={"sequence": 2},
    )

    assert first != second
    assert json.loads(first.read_text(encoding="utf-8")) == {"item": 3}
    assert json.loads(second.read_text(encoding="utf-8")) == {"item": 4}
    module.rebuild_manifest(str(engagement_dir))
    manifest = json.loads(
        (engagement_dir / "tools" / "analysis-state" / "artifact-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert {entry["name"] for entry in manifest["entries"]} == {
        first.name,
        second.name,
    }
    by_name = {entry["name"]: entry for entry in manifest["entries"]}
    assert by_name[first.name]["kind"] == "code-queue-done"
    assert by_name[first.name]["label"] == "clean result"
    assert by_name[first.name]["source_path"] == "queue-3.json"
    assert by_name[first.name]["metadata"] == {"sequence": 1}
    assert by_name[second.name]["kind"] == "code-queue-done"
    assert by_name[second.name]["label"] == "clean result"
    assert by_name[second.name]["source_path"] == "queue-4.json"
    assert by_name[second.name]["metadata"] == {"sequence": 2}


def test_code_audit_manifest_ignores_legacy_noncanonical_files(tmp_path):
    module = _load_code_audit_module()

    engagement_dir = tmp_path / "engagement"
    state_dir = engagement_dir / "tools" / "analysis-state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "module15_contexts.json").write_text('{"contexts": []}\n', encoding="utf-8")
    (state_dir / "finding-verification-pass-1.md").write_text("# verification\n", encoding="utf-8")

    module.write_json_snapshot(
        str(engagement_dir),
        category="code-analysis-submit",
        label="batch one",
        payload={"results": 1},
    )

    manifest = json.loads((state_dir / "artifact-manifest.json").read_text())
    assert manifest["artifact_count"] == 1
    assert manifest["entries"][0]["kind"] == "code-analysis-submit"


@pytest.mark.parametrize(
    ("loader", "payload_factory", "argument_name", "endpoint"),
    [
        (_load_code_record_fuzz_decision_module, _fuzz_decision_payload, "decision_json", "code/fuzz/decision"),
        (_load_code_record_fuzz_campaign_module, _fuzz_campaign_payload, "receipt_json", "code/fuzz/campaign-receipts"),
    ],
)
def test_code_record_fuzz_completion_posts_exact_strict_json(
    loader, payload_factory, argument_name, endpoint, monkeypatch, tmp_path, capsys
):
    module = loader()
    payload = payload_factory()
    source = tmp_path / "record.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    posted = []
    backend_record = {"id": 91, **payload, "current": True}
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test", engagement_key="eng"
        ),
    )

    class FakeClient:
        def __init__(self, base_url, engagement_key):
            assert (base_url, engagement_key) == ("http://example.test", "eng")

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def post(self, actual_endpoint, body):
            posted.append((actual_endpoint, body))
            return backend_record

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    module.run(
        SimpleNamespace(**{argument_name: str(source)}, engagement_dir=tmp_path)
    )

    assert posted == [(endpoint, payload)]
    assert json.loads(capsys.readouterr().out) == backend_record


@pytest.mark.parametrize(
    ("loader", "payload_factory", "argument_name", "mutation", "message"),
    [
        (
            _load_code_record_fuzz_decision_module,
            _fuzz_decision_payload,
            "decision_json",
            lambda payload: payload.__setitem__("target_ids", ["z", "a"]),
            "target_ids must be sorted and unique",
        ),
        (
            _load_code_record_fuzz_decision_module,
            _fuzz_decision_payload,
            "decision_json",
            lambda payload: payload.__setitem__("target_ids", []),
            "required decisions must declare at least one target_id",
        ),
        (
            _load_code_record_fuzz_campaign_module,
            _fuzz_campaign_payload,
            "receipt_json",
            lambda payload: payload.__setitem__("crash_count", 1),
            "completed_no_crash requires crash_count=0",
        ),
    ],
)
def test_code_record_fuzz_completion_rejects_false_or_ambiguous_receipts(
    loader,
    payload_factory,
    argument_name,
    mutation,
    message,
    tmp_path,
    capsys,
):
    module = loader()
    payload = payload_factory()
    mutation(payload)
    source = tmp_path / "invalid.json"
    source.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SystemExit):
        module.run(
            SimpleNamespace(**{argument_name: str(source)}, engagement_dir=tmp_path)
        )

    assert message in capsys.readouterr().err
