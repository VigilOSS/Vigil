from __future__ import annotations

import argparse
import errno
import hashlib
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_ingest
from assess.lib.client import AssessError
from assess.lib.code_snapshot import RootedSourceTree


def _args(repo: Path, engagement: Path, **overrides) -> SimpleNamespace:
    values = dict(
        repo_path=str(repo), name="demo", language=None,
        default_language_for_unknown=None, repo_key="demo-repo",
        include_minified=False, include_skipped=False, include_path=[],
        exclude_path=[], policy_preset="application",
        max_included_skipped_bytes=2_000_000, skipped_manifest=None,
        dry_run=False, engagement_dir=str(engagement),
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def test_git_status_timeout_can_be_configured_without_skipping_provenance(monkeypatch):
    parser = argparse.ArgumentParser()
    code_ingest.register(parser.add_subparsers(dest="command"))
    parsed = parser.parse_known_args([
        "code-ingest", "/repo", "--git-status-timeout", "300",
    ])[0]
    assert getattr(parsed, "git_status_timeout", None) == 300
    calls = []

    def run_git(_repo, _binary, arguments, **options):
        calls.append((arguments, options["timeout"]))
        output = "true\n" if arguments[-1] == "--is-inside-work-tree" else "main\n"
        if arguments[0] == "status":
            output = "?? untracked.txt\0"
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(code_ingest, "_run_git", run_git)
    result = code_ingest._git_provenance("/repo", "/trusted/git", parsed.git_status_timeout)
    assert result["dirty"] is True
    assert calls[-1] == (["status", "--porcelain=v1", "-z", "--untracked-files=all", "--", "."], 300)
    code_ingest._verify_git_provenance("/repo", "/trusted/git", result, 300)
    assert len([call for call in calls if call[0][0] == "status"]) == 2


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "bad"])
def test_git_status_timeout_rejects_nonpositive_or_nonfinite_values(value):
    parser = argparse.ArgumentParser()
    code_ingest.register(parser.add_subparsers(dest="command"))
    with pytest.raises(SystemExit) as error:
        parser.parse_args(["code-ingest", "/repo", "--git-status-timeout", value])
    assert error.value.code == 2


def test_git_status_timeout_keeps_provenance_fail_closed_with_useful_error(monkeypatch):
    def run_git(_repo, _binary, arguments, **options):
        if arguments[0] == "status":
            raise subprocess.TimeoutExpired(arguments, options["timeout"])
        output = "true\n" if arguments[-1] == "--is-inside-work-tree" else "main\n"
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(code_ingest, "_run_git", run_git)
    with pytest.raises(ValueError, match="--git-status-timeout"):
        code_ingest._git_provenance("/repo", "/trusted/git")


@pytest.mark.parametrize("pattern", ["generated", "generated/**", "**/generated/**"])
def test_explicit_excludes_override_includes_and_remain_in_manifest(tmp_path, pattern):
    repo = tmp_path / "repo"
    (repo / "generated").mkdir(parents=True)
    (repo / "main.py").write_bytes(b"main\n")
    (repo / "generated" / "copy.py").write_bytes(b"copy\n")
    args = _args(repo, tmp_path / "engagement", include_path=["generated/**"], exclude_path=[pattern])
    with RootedSourceTree(repo) as tree:
        admitted = list(code_ingest._admitted_source_paths(tree, args, tmp_path / "snapshots"))
        assert admitted == ["main.py"]
        excluded = code_ingest._collect_excluded_records(tree, args, tmp_path / "snapshots")
        record = next(row for row in excluded if row["path"] == "generated/copy.py")
        assert record["reason"] == f"exclude_path:{pattern}"
        assert record["sha256"] == hashlib.sha256(b"copy\n").hexdigest()
        captured = tree.capture("main.py", retain_spool=False)
        expected = {"main.py": (captured.sha256, captured.size, captured.executable)}
        code_ingest._verify_source_inventory(tree, args, tmp_path / "snapshots", expected, excluded)


def test_repeatable_exclude_path_is_a_registered_option():
    parser = argparse.ArgumentParser()
    code_ingest.register(parser.add_subparsers(dest="command"))
    parsed = parser.parse_known_args([
        "code-ingest", "/repo", "--exclude-path", "generated/**", "--exclude-path", "copies/**",
    ])[0]
    assert getattr(parsed, "exclude_path", None) == ["generated/**", "copies/**"]


def test_ctags_large_selection_has_bounded_argv_and_exact_safe_file_list(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    names = [f"source {number}.py" for number in range(30)] + ["--options=evil.ctags"]
    selected = []
    for name in names:
        (repo / name).write_bytes(b"source\n")
        selected.append({"file_path": name, "source_sha256": hashlib.sha256(b"source\n").hexdigest()})
    inputs = []
    monkeypatch.setattr(code_ingest, "_resolve_trusted_tool", lambda *_args, **_kwargs: "/trusted/ctags")

    def run(command, **options):
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="Universal Ctags", stderr="")
        if len(command) > 12:
            raise OSError(errno.E2BIG, "Argument list too long")
        assert command[command.index("-L") + 1] == "-"
        inputs.extend(options["input"].decode().splitlines())
        Path(command[command.index("-f") + 1]).write_bytes(b"tag\tfile\t1\n")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(code_ingest.subprocess, "run", run)
    result = code_ingest._setup_ctags(repo, tmp_path / "tags", selected, repo_generation=1, source_manifest_digest="a" * 64)
    assert result["available"] is True
    assert inputs == [f"./{name}" for name in names]


@pytest.mark.parametrize("name", ["line\nbreak.py", "carriage\rreturn.py", "trailing.py ", "trailing.py\t"])
def test_ctags_unrepresentable_file_list_name_is_explicit_and_never_split(monkeypatch, tmp_path, capsys, name):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / name).write_bytes(b"source\n")
    monkeypatch.setattr(code_ingest, "_resolve_trusted_tool", lambda *_args, **_kwargs: "/trusted/ctags")
    calls = []

    def run(command, **options):
        calls.append(command)
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="Universal Ctags", stderr="")
        Path(command[command.index("-f") + 1]).write_bytes(b"tag\tfile\t1\n")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(code_ingest.subprocess, "run", run)
    result = code_ingest._setup_ctags(repo, tmp_path / "tags", [
        {"file_path": name, "source_sha256": hashlib.sha256(b"source\n").hexdigest()},
    ], repo_generation=1, source_manifest_digest="a" * 64)
    assert result["available"] is False
    assert "file list" in capsys.readouterr().err
    assert not any("-f" in command for command in calls)


def test_ingest_commit_budget_scales_without_retrying_large_publication(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    for number in range(600):
        (repo / f"file{number}.py").write_bytes(b"source\n")
    engagement = tmp_path / "engagement"
    engagement.mkdir()
    monkeypatch.setattr(code_ingest, "load_config", lambda *_: SimpleNamespace(
        base_url="http://example.test", engagement_key="eng", engagement_dir=str(engagement),
    ))
    monkeypatch.setattr(code_ingest, "_setup_ctags", lambda *_args, **kwargs: {"available": False, **kwargs})
    commits = []

    class Client:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, endpoint, payload, **options):
            if endpoint == "code/repos/refresh/start":
                return {"repo_id": 7, "refresh_token": "token"}
            if endpoint.endswith("/refresh/files"):
                return {"staged": len(payload["files"])}
            if endpoint.endswith("/refresh/commit"):
                commits.append(options)
                if options.get("read_timeout", 10) <= 10:
                    raise AssessError("publication timed out at the default response budget")
                return {"repo_id": 7, "repo_generation": 1, "source_manifest_digest": "a" * 64, "retired": 0, "repo_role": "analysis"}
            if endpoint.endswith("/lsp-config"):
                return {"id": 7, "active_generation": 1, "source_manifest_digest": "a" * 64, "lsp_config": payload["lsp_config"]}
            pytest.fail(endpoint)

    monkeypatch.setattr(code_ingest, "AssessmentClient", Client)
    code_ingest.run(_args(repo, engagement))
    assert len(commits) == 1
    assert commits[0]["read_timeout"] > 10


def test_dry_run_reports_full_hashing_progress_and_preserves_content_comparison(monkeypatch, tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    for number in range(3):
        (repo / f"file{number}.py").write_bytes(b"source\n")
    engagement = tmp_path / "engagement"
    engagement.mkdir()
    monkeypatch.setattr(code_ingest, "load_config", lambda *_: SimpleNamespace(
        base_url="http://example.test", engagement_key="eng", engagement_dir=str(engagement),
    ))
    monkeypatch.setattr(code_ingest, "_SCAN_PROGRESS_FILES", 2, raising=False)

    class Client:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, endpoint, payload):
            assert endpoint == "code/repos/refresh/preview"
            assert len(payload["files"]) == 3
            assert all(row["file_hash"] == hashlib.sha256(b"source\n").hexdigest() for row in payload["files"])
            return {"added": [row["file_path"] for row in payload["files"]]}

    monkeypatch.setattr(code_ingest, "AssessmentClient", Client)
    code_ingest.run(_args(repo, engagement, dry_run=True))
    output = capsys.readouterr()
    assert "dry-run reads and hashes" in output.err
    assert "Captured 2 source files (14 bytes)" in output.err
    assert "Verified 2 source files (14 bytes)" in output.err
    assert not (engagement / "tools").exists()
