from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import sys

import pytest


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


def _load_reset_finding_module():
    return _load_assess_module("reset_finding.py", "test_reset_finding_command")


def _load_kill_finding_module():
    return _load_assess_module("kill_finding.py", "test_kill_finding_command")


def _load_list_findings_module():
    return _load_assess_module("list_findings.py", "test_list_findings_command")


def _load_cli_module():
    repo_root = Path(__file__).resolve().parents[3]
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    import assess.cli as cli_module

    return cli_module


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
                "gate": {"passed": False, "reasons": ["Critical files not fully analyzed: 0/1"]},
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
    assert "Coverage Gate: FAIL" in output


def test_code_coverage_can_enforce_gate_failures(monkeypatch):
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
            return {"gate": {"passed": False, "reasons": ["blocked"]}}

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


def test_code_coverage_cwe_matrix_coerces_non_numeric_effort_values():
    module = _load_code_coverage_module()

    has_gap = module._check_effort_gaps(
        [
            {
                "classification": "critical",
                "applicable_families": ["ssrf"],
                "cwe_coverage": [{"family": "ssrf", "effort": "unknown"}],
            }
        ]
    )

    assert has_gap is True


def test_code_coverage_cwe_matrix_treats_not_applicable_as_satisfied():
    module = _load_code_coverage_module()

    has_gap = module._check_effort_gaps(
        [
            {
                "classification": "critical",
                "applicable_families": ["ai-ml-security"],
                "cwe_coverage": [
                    {
                        "family": "ai-ml-security",
                        "effort": 0,
                        "disposition": "not_applicable",
                    }
                ],
            }
        ]
    )

    assert has_gap is False


def test_code_coverage_cwe_matrix_require_gate_pass_honors_backend_gate(monkeypatch):
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
                "gate": {"passed": False, "reasons": ["pending queue items remain"]},
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

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=Path("/tmp/eng"),
                repo_id=None,
                require_gate_pass=True,
                cwe_matrix=True,
            )
        )
    assert excinfo.value.code == 1


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
            return [
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
    monkeypatch.setattr(module, "_setup_ctags", lambda repo_path: {"available": False})

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
                return {"inserted": 1, "changed": 0, "deleted": 0, "renamed": 0}
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
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path / "engagement")
        ),
    )
    monkeypatch.setattr(module, "_setup_ctags", lambda repo_path: {"available": False})
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
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path / "engagement")
        ),
    )
    monkeypatch.setattr(module, "_setup_ctags", lambda repo_path: {"available": False})
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
                return {"inserted": 0, "changed": 0, "deleted": 2, "renamed": 0}
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

    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text("{}", encoding="utf-8")

    monkeypatch.setitem(sys.modules, "tree_sitter", SimpleNamespace())
    monkeypatch.setattr(
        module,
        "_walk_repo",
        lambda _repo_path: [{"file_path": "main.py", "language": "python"}],
    )
    monkeypatch.setattr(
        module,
        "index_file",
        lambda _path, _lang: {
            "total_functions": 1,
            "entry_points": [],
            "security_sinks": [],
            "exports": [],
        },
    )

    module.run(
        SimpleNamespace(
            repo_path=str(repo_path),
            repo_id="demo",
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

    def fake_run(cmd, stdout, stderr, text, cwd, timeout):
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        captured["timeout"] = timeout
        stdout.write("commit:abc123\nsrc/auth.py\nsrc/http.py\n\ncommit:def456\nsrc/auth.py\n")
        stdout.flush()
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    files = module._git_security_files(str(tmp_path), [f"--since={module._GIT_SECURITY_LOOKBACK}"])

    assert files == {"src/auth.py", "src/http.py"}
    assert captured["cmd"] == [
        "git",
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
                return {"inserted": 1, "changed": 0, "deleted": 0, "renamed": 0}
            raise AssertionError(f"Unexpected endpoint: {endpoint}")

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "_git_security_files", fake_security_files)
    monkeypatch.setattr(module, "_setup_ctags", lambda repo_path: {"available": False})
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
            return [{"id": 42, "repo_id": 7, "file_path": "src/parser.py"}]

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
                return [
                    {"id": 40, "repo_id": 7, "file_path": "src/parser.py"},
                    {"id": 41, "repo_id": 7, "file_path": "src/helpers.py"},
                ]
            if endpoint == "code/files?limit=2&offset=2":
                return [{"id": 42, "repo_id": 7, "file_path": "src/routes.py"}]
            raise AssertionError(f"Unexpected endpoint: {endpoint}")

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
                "disposition": "false_positive",
                "reason_code": "check-2-guard",
                "reason_text": "Guard proves the path is unreachable.",
                "artifact_ref": "tools/analysis-state/code-verification/VA-001.json",
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
                    "verification_state": "verified",
                    "verification_disposition": "false_positive",
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
    assert captured["payload"]["disposition"] == "false_positive"
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

        def post(self, endpoint: str, payload: dict):
            posts.append(endpoint)
            return {"slug": "VA-001"}

        def close(self) -> None:
            return None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    args = SimpleNamespace(
        engagement_dir=tmp_path,
        finding_slug="VA-001",
        payload=None,
        inline_payload=None,
        disposition="pending_runtime_proof",
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
        kill_reason=None,
        kill_check=None,
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
            return [
                {"id": 10, "repo_id": 1, "file_path": "src/parser.py"},
                {"id": 11, "repo_id": 1, "file_path": "src/helpers/auth.py"},
                {"id": 12, "repo_id": 1, "file_path": "src/routes.py"},
            ]

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
    assert "Queued 3 analysis item(s)" in capsys.readouterr().out


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
                return [
                    {"id": 10, "repo_id": 1, "file_path": "src/parser.py"},
                    {"id": 11, "repo_id": 1, "file_path": "src/helpers/auth.py"},
                ]
            if endpoint == "code/files?limit=2&offset=2":
                return [{"id": 12, "repo_id": 1, "file_path": "src/routes.py"}]
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
                "inserted": 1,
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

    module.run(SimpleNamespace(action="requeue-triggers", extra=[str(triggers_path)], engagement_dir=tmp_path))

    assert captured["endpoint"] == "code/analysis-queue/requeue"
    assert captured["payload"]["items"][0]["trigger_context"]["source"] == "cross_file_trigger"
    assert captured["payload"]["items"][0]["repo_id"] == 7
    assert "repo_id" not in captured["payload"]["items"][0]["trigger_context"]
    output = capsys.readouterr().out
    assert "Requeued 1 trigger item(s)" in output
    assert "Not found: src/missing.py" in output
    assert "Ambiguous without repo_id: src/shared.py" in output


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
            return {"ok": True}

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
    assert '"ok": true' in capsys.readouterr().out.lower()


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
    assert "record-finding" in err
    assert "vigil assess contract record-finding" in err


def test_post_rejects_raw_verify_endpoint_and_points_to_helper(capsys):
    module = _load_post_module()

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=Path("/tmp/eng"),
                endpoint="findings/VA-001/verify",
                payload='{"disposition":"confirmed","reason_text":"reproduced"}',
                inline_payload=None,
            )
        )

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "verify-finding" in err
    assert "kill-finding" in err
    assert "vigil assess contract verify-finding" in err


def test_raw_finding_patch_is_rejected_and_points_to_helper():
    """A raw PATCH to findings/{slug} is rejected and points operators at the
    typed update-finding / reset-finding verbs.

    The generic ``patch`` verb was removed in WS5, but the ``_RAW_ENDPOINT_RULES``
    redirect survives as the client-layer guard, so this asserts the guard
    directly (mirrors test_coverage_probe_cli_sync's redirect test)."""
    from assess.lib import contracts

    error = contracts.raw_endpoint_error(
        "PATCH", "findings/VA-001", {"workflow_status": "draft"}
    )
    assert error is not None
    assert "update-finding" in error
    assert "reset-finding" in error
    assert "vigil assess contract update-finding" in error
    assert "vigil assess contract reset-finding" in error


def test_contract_prints_record_finding_contract(capsys):
    module = _load_contract_module()

    module.run(SimpleNamespace(name="record-finding"))

    out = capsys.readouterr().out
    assert "Command: record-finding" in out
    assert "Schema: finding-record.schema.json" in out
    assert "Helper defaults:" in out
    assert "workflow_status = active" in out
    assert "verification_state = unreviewed" in out
    assert "verification_disposition = none" in out
    assert "Examples:" in out


def test_contract_prints_reset_finding_contract(capsys):
    module = _load_contract_module()

    module.run(SimpleNamespace(name="reset-finding"))

    out = capsys.readouterr().out
    assert "Command: reset-finding" in out
    assert "reopen" in out.lower()
    assert "vigil assess reset-finding <slug>" in out


def test_contract_prints_code_record_analysis_contract(capsys):
    module = _load_contract_module()

    module.run(SimpleNamespace(name="code-record-analysis"))

    out = capsys.readouterr().out
    assert "Command: code-record-analysis" in out
    assert "Schema: code-analysis-result.schema.json" in out
    assert "queue_item_id" in out
    assert "file_id = derived by the backend from queue_item_id" in out
    assert "file_id-only result -> include queue_item_id" in out


def test_contract_prints_record_intel_variant_contract(capsys):
    module = _load_contract_module()

    module.run(SimpleNamespace(name="record-intel", variant="tech-component"))

    out = capsys.readouterr().out
    assert "Command: record-intel tech-component" in out
    assert "Schema: intel-tech-component.schema.json" in out
    assert "Required top-level fields:" in out
    assert "component" in out
    assert "source -> use source_name" in out


def test_verify_finding_help_is_rendered_from_contract_registry(capsys):
    cli = _load_cli_module()

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["verify-finding", "--help"])

    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "vigil assess verify-finding <slug> --disposition confirmed --reason" in out
    assert "vigil assess contract verify-finding" in out
    assert "Contract:" not in out


def test_update_finding_help_drops_patch_finding_alias(capsys):
    cli = _load_cli_module()

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["update-finding", "--help"])

    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "vigil assess update-finding <slug> --inline" in out
    assert "patch-finding" not in out


def test_kill_finding_builds_false_positive_payload_from_flags(monkeypatch, tmp_path, capsys):
    module = _load_kill_finding_module()

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
            payload=None,
            inline_payload=None,
            reason_text="Guard blocks the path",
            reason_code="manual-kill",
            kill_reason="validate_length() enforces an 8KB cap",
            kill_check=2,
            evidence_ref="findings.md",
            artifact_ref="audit.json",
            notes="Rechecked manually",
            source_name="operator",
            details_inline=None,
            provenance_inline='{"reviewed_by":"operator"}',
        )
    )

    assert captured["endpoint"] == "findings/VA-001/verify"
    assert captured["payload"]["disposition"] == "false_positive"
    assert captured["payload"]["details"]["kill_reason"] == "validate_length() enforces an 8KB cap"
    assert captured["payload"]["details"]["kill_check"] == 2
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
    assert "vigil assess contract record-finding" in err


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


def test_reset_finding_reopens_to_draft(monkeypatch, tmp_path):
    module = _load_reset_finding_module()

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
            workflow_status="draft",
            severity=None,
            reason_text="Needs another review pass",
            reason_code="retriage",
            artifact_ref="review.json",
            notes="Undoing prior false positive",
            source_name="operator",
            provenance_inline='{"reviewed_by":"operator"}',
        )
    )

    assert captured["endpoint"] == "findings/VA-003"
    assert captured["payload"]["workflow_status"] == "draft"
    assert captured["payload"]["reason_text"] == "Needs another review pass"


def test_list_findings_filters_by_status_and_severity(monkeypatch, capsys):
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
            assert endpoint == "findings?severity=high&workflow_status=active&limit=100&offset=0"
            return [
                {
                    "slug": "ACTIVE-001",
                    "severity": "high",
                    "workflow_status": "active",
                    "verification_state": "unreviewed",
                    "verification_disposition": "none",
                    "title": "Live issue",
                    "summary": "",
                    "canonical_location": "",
                    "source_name": "vulnerability-analyst",
                },
                {
                    "slug": "DRAFT-001",
                    "severity": "high",
                    "workflow_status": "draft",
                    "verification_state": "unreviewed",
                    "verification_disposition": "none",
                    "title": "Needs work",
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
            verification_state=None,
            verification_disposition=None,
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
    monkeypatch.setattr(module, "_which", lambda binary: None)

    result = module._setup_ctags(str(tmp_path))
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
    manifest = json.loads(manifest_path.read_text())
    assert manifest["artifact_count"] == 1
    entry = manifest["entries"][0]
    assert entry["name"] == snapshot.name
    assert entry["kind"] == "code-contexts-submit"
    assert entry["label"] == "module 1 batch"
    assert entry["source_path"] == "/tmp/input.json"
    assert entry["metadata"]["command"] == "code-record-contexts"


def test_code_audit_manifest_ignores_legacy_noncanonical_files(tmp_path):
    module = _load_code_audit_module()

    engagement_dir = tmp_path / "engagement"
    state_dir = engagement_dir / "tools" / "analysis-state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "module15_contexts.json").write_text('{"contexts": []}\n', encoding="utf-8")
    (state_dir / "finding-verification-wave-1.md").write_text("# verification\n", encoding="utf-8")

    module.write_json_snapshot(
        str(engagement_dir),
        category="code-analysis-submit",
        label="batch one",
        payload={"results": 1},
    )

    manifest = json.loads((state_dir / "artifact-manifest.json").read_text())
    assert manifest["artifact_count"] == 1
    assert manifest["entries"][0]["kind"] == "code-analysis-submit"
