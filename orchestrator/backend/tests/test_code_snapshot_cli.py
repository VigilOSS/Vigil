from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import select
import signal
import stat
import sys
import tracemalloc
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_ROOT = REPO_ROOT / "agent" / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))


def _load_command(filename: str, name: str):
    path = SCRIPTS_ROOT / "assess" / "commands" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_code_index_routes_exact_parsing_through_process_boundary() -> None:
    module = _load_command("code_index.py", "test_code_index_parser_boundary")

    assert module.index_file.__module__ == "assess.lib.parser_boundary"


def _ingest_args(repo: Path, engagement: Path, *, dry_run: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        repo_path=str(repo),
        name="demo",
        language=None,
        default_language_for_unknown=None,
        repo_key="demo-repo",
        include_minified=False,
        include_skipped=False,
        include_path=[],
        max_included_skipped_bytes=2_000_000,
        skipped_manifest=None,
        dry_run=dry_run,
        engagement_dir=str(engagement),
    )


def _lsp_publish_response(payload: dict[str, object]) -> dict[str, object]:
    return {
        "id": 7,
        "active_generation": payload["repo_generation"],
        "source_manifest_digest": payload["source_manifest_digest"],
        "lsp_config": payload["lsp_config"],
    }


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


@pytest.mark.parametrize(
    ("start_response", "commit_response"),
    [
        (
            {"repo_id": True, "refresh_token": "refresh-7"},
            None,
        ),
        (
            {"repo_id": 7, "refresh_token": "refresh-7"},
            {"repo_id": 8, "repo_generation": 1, "source_manifest_digest": "d" * 64},
        ),
        (
            {"repo_id": 7, "refresh_token": "refresh-7"},
            {"repo_id": 7, "repo_generation": True, "source_manifest_digest": "d" * 64},
        ),
        (
            {"repo_id": 7, "refresh_token": "refresh-7"},
            {"repo_id": 7, "repo_generation": 1, "source_manifest_digest": "z" * 64},
        ),
        (
            {"repo_id": 7, "refresh_token": "refresh-7"},
            {
                "repo_id": 7,
                "repo_generation": 1,
                "source_manifest_digest": "d" * 64,
                "deleted": 0,
            },
        ),
        (
            {"repo_id": 7, "refresh_token": "refresh-7"},
            {"repo_id": 7, "repo_generation": 1, "source_manifest_digest": "d" * 64},
        ),
    ],
    ids=[
        "bool-start-id",
        "wrong-commit-repo",
        "bool-generation",
        "nonhex-digest",
        "retired-deleted-alias",
        "missing-retired-count",
    ],
)
def test_code_ingest_rejects_noncanonical_refresh_receipts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    start_response: dict[str, object],
    commit_response: dict[str, object] | None,
) -> None:
    from assess.lib.client import AssessError

    module = _load_command("code_ingest.py", "test_code_ingest_refresh_receipts")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("print('safe')\n", encoding="utf-8")
    engagement = tmp_path / "engagement"
    engagement.mkdir()
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement),
        ),
    )
    monkeypatch.setattr(
        module,
        "_setup_ctags",
        lambda *_args, **kwargs: {"available": False, **kwargs},
    )

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def post(self, endpoint: str, payload: dict):
            if endpoint == "code/repos/refresh/start":
                return start_response
            if endpoint == "code/repos/7/refresh/files":
                return {"staged": len(payload["files"])}
            if endpoint == "code/repos/7/refresh/commit":
                assert commit_response is not None
                return commit_response
            pytest.fail(f"invalid receipt was accepted before {endpoint}")

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(AssessError, match="code repository refresh.*may have committed") as exc:
        module.run(_ingest_args(repo, engagement))

    assert "do not retry automatically" in str(exc.value)


def _sealed_snapshot(
    tmp_path: Path,
    files: dict[str, bytes],
    *,
    repo_key: str = "demo-repo",
) -> tuple[Path, dict]:
    from assess.lib.code_snapshot import SnapshotBuilder, capture_regular_file

    origin = tmp_path / f"{repo_key}-origin"
    origin.mkdir()
    builder = SnapshotBuilder(tmp_path / "snapshots", repo_key)
    for rel_path, raw in files.items():
        path = origin / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        language = {
            ".h": "c",
            ".py": "python",
            ".md": "markdown",
            ".json": "json",
        }.get(path.suffix, "")
        builder.add(rel_path, capture_regular_file(path), language=language)
    sealed = builder.finish(
        repo_key=repo_key,
        repo_name="demo",
        source_origin_path=str(origin.resolve()),
        git={"head": "", "branch": "", "dirty": None},
    )
    manifest = json.loads(sealed.manifest_path.read_text(encoding="utf-8"))
    return sealed.source_path, manifest


def _structural_identity(
    source_manifest: dict,
    backend_rows: list[dict],
    *,
    repo_id: int = 7,
    generation: int = 4,
    source_manifest_digest: str,
) -> str:
    from assess.lib.code_structural_identity import (
        bind_structural_inputs,
        structural_input_digest,
    )

    bound = bind_structural_inputs(
        source_manifest["files"],
        {str(row["file_path"]): row for row in backend_rows},
        repo_id=repo_id,
    )
    return structural_input_digest(
        bound,
        repo_id=repo_id,
        repo_generation=generation,
        source_manifest_digest=source_manifest_digest,
    )


def _legacy_v3_aggregate(*, repo_id: int = 999) -> dict:
    source_digest = "a" * 64
    input_digest = "b" * 64
    repo_generation = 4
    return {
        "schema": "structural-index-aggregate/v3",
        "updated_at": "2026-08-05T17:00:00Z",
        "repos": {
            str(repo_id): {
                "repo_id": repo_id,
                "repo_key": "stale-repo",
                "repo_generation": repo_generation,
                "source_manifest_digest": source_digest,
                "structural_input_digest": input_digest,
                "manifest_path": (
                    f"structural-index/{repo_id}/{repo_generation}/v4/"
                    f"{source_digest}/{input_digest}/manifest.json"
                ),
                "degraded_files": 1,
                "degraded_file_paths": ["legacy.c"],
                "artifact_truncated_files": 1,
                "artifact_truncated_file_paths": ["legacy.c"],
                "analysis_status_counts": {
                    "complete": 0,
                    "degraded": 1,
                    "unsupported": 0,
                },
            }
        },
    }


def _restore_tree_writable(path: Path) -> None:
    if not path.exists():
        return
    for root, directories, files in os.walk(path, topdown=False, followlinks=False):
        for filename in files:
            file_path = Path(root) / filename
            if file_path.is_symlink():
                continue
            os.chmod(file_path, 0o600, follow_symlinks=False)
        for dirname in directories:
            os.chmod(Path(root) / dirname, 0o700, follow_symlinks=False)
    os.chmod(path, 0o700, follow_symlinks=False)


def _fork_call_outcome(action: Callable[[], object], *, timeout: float = 1.0) -> bytes:
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - assertions run in the parent process
        os.close(read_fd)
        try:
            action()
        except ValueError:
            outcome = b"value-error"
        except Exception:
            outcome = b"unexpected-error"
        else:
            outcome = b"completed"
        os.write(write_fd, outcome)
        os.close(write_fd)
        os._exit(0)

    os.close(write_fd)
    ready, _, _ = select.select([read_fd], [], [], timeout)
    if not ready:
        os.kill(child_pid, signal.SIGKILL)
        os.waitpid(child_pid, 0)
        os.close(read_fd)
        return b"blocked"
    outcome = os.read(read_fd, 64)
    os.close(read_fd)
    _, child_status = os.waitpid(child_pid, 0)
    assert os.WIFEXITED(child_status)
    return outcome


def test_snapshot_validation_rejects_legacy_v1_manifest(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    from assess.lib.code_snapshot import validate_snapshot

    raw = b"print('legacy')\n"
    files = [
        {
            "file_path": "main.py",
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
            "loc": 1,
            "language": "python",
            "executable": False,
        }
    ]
    digest = hashlib.sha256(
        json.dumps(
            {"schema": "code-source-manifest/v1", "files": files},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    snapshot_root = tmp_path / digest
    source = snapshot_root / "source"
    source.mkdir(parents=True)
    (source / "main.py").write_bytes(raw)
    manifest = {
        "schema": "code-source-manifest/v1",
        "source_path": str(source.resolve()),
        "snapshot_digest": digest,
        "files": files,
    }
    manifest_path = snapshot_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    os.chmod(source / "main.py", 0o444)
    os.chmod(manifest_path, 0o444)
    os.chmod(source, 0o555)
    os.chmod(snapshot_root, 0o555)
    request.addfinalizer(lambda: _restore_tree_writable(snapshot_root))

    with pytest.raises(ValueError, match="unsupported sealed snapshot manifest"):
        validate_snapshot(snapshot_root, expected_digest=digest)


def test_snapshot_validation_rejects_non_object_manifest_cleanly(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    from assess.lib.code_snapshot import validate_snapshot

    snapshot_root = tmp_path / ("a" * 64)
    source = snapshot_root / "source"
    source.mkdir(parents=True)
    manifest_path = snapshot_root / "manifest.json"
    manifest_path.write_text("[]", encoding="utf-8")
    os.chmod(manifest_path, 0o444)
    os.chmod(source, 0o555)
    os.chmod(snapshot_root, 0o555)
    request.addfinalizer(lambda: _restore_tree_writable(snapshot_root))

    with pytest.raises(ValueError, match="manifest must contain a JSON object"):
        validate_snapshot(snapshot_root)


def test_skipped_projection_retries_short_writes_before_atomic_publish(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_command("code_ingest.py", "test_skipped_projection_short_write")
    real_write = module.os.write
    write_calls = 0

    def short_write(fd: int, data: bytes | memoryview) -> int:
        nonlocal write_calls
        write_calls += 1
        chunk = bytes(data[: max(1, len(data) // 2)])
        return real_write(fd, chunk)

    monkeypatch.setattr(module.os, "write", short_write)
    output = module._write_skipped_manifest(
        SimpleNamespace(
            skipped_manifest=str(tmp_path / "skipped"),
            include_minified=False,
            include_skipped=False,
            include_path=[],
            max_included_skipped_bytes=2_000_000,
        ),
        cfg=SimpleNamespace(engagement_dir=str(tmp_path)),
        repo_id=7,
        repo_key="demo-repo",
        repo_name="Demo",
        repo_path="/tmp/demo-origin",
        repo_generation=3,
        source_manifest_digest="a" * 64,
        snapshot_digest="b" * 64,
        snapshot_manifest_path="/tmp/demo-snapshot/manifest.json",
        records=[
            {
                "path": "vendor/library.php",
                "kind": "file",
                "reason": "skipped_dir:vendor",
                "size": 10,
                "sha256": "c" * 64,
                "language": "php",
            }
        ],
    )

    assert output is not None
    payload = json.loads(Path(output).read_text(encoding="utf-8"))
    assert payload["schema"] == "code-exclusion-manifest/v1"
    assert payload["excluded_entries"][0]["path"] == "vendor/library.php"
    assert write_calls > 1


def test_trusted_tool_resolution_ignores_repo_relative_and_empty_path_entries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_trusted_resolution")
    repo = tmp_path / "repo"
    repo.mkdir()
    malicious = repo / "git"
    malicious.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    malicious.chmod(0o755)
    trusted_dir = tmp_path / "trusted-bin"
    trusted_dir.mkdir()
    trusted = trusted_dir / "git"
    trusted.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    trusted.chmod(0o755)
    monkeypatch.setenv("PATH", f"{repo}{os.pathsep}{os.pathsep}.{os.pathsep}{trusted_dir}")

    resolver = getattr(module, "_resolve_trusted_tool", None)
    assert callable(resolver), "code-ingest must resolve tools without shell/which lookup"
    assert resolver("git", source_root=repo) == str(trusted.resolve())


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("native.hh", "cpp"),
        ("module.mjs", "javascript"),
        ("legacy.cjs", "javascript"),
        ("config.mts", "typescript"),
        ("legacy.cts", "typescript"),
        ("Dockerfile.prod", "dockerfile"),
    ],
)
def test_ingest_language_detection_matches_structural_index(
    filename: str,
    expected: str,
) -> None:
    module = _load_command("code_ingest.py", f"test_ingest_language_{expected}_{filename}")
    from assess.lib.treesitter_index import language_for_file

    assert module._detect_language(filename) == expected
    assert language_for_file(filename) == expected


@pytest.mark.parametrize(
    "filename",
    ["profile.blade.php", "resources/views/home/default.blade.php"],
)
def test_ingest_classifies_blade_templates_ahead_of_the_php_suffix(filename: str) -> None:
    module = _load_command("code_ingest.py", f"test_ingest_language_{filename}")
    from assess.lib.code_languages import canonical_backend_language, detect_language
    from assess.lib.treesitter_index import language_for_file

    assert module._detect_language(filename) == "blade"
    assert detect_language(filename) == "blade"
    assert canonical_backend_language("blade") == "blade"
    assert language_for_file(filename) == "blade"
    # The single-suffix rule still owns every other `.php` file.
    assert module._detect_language("app/Http/Controllers/UserController.php") == "php"


@pytest.mark.parametrize("filename", ["Inspect.ps1", "Module.PSM1", "Data.psd1"])
def test_ingest_classifies_powershell_extensions(filename: str) -> None:
    module = _load_command("code_ingest.py", f"test_ingest_language_{filename}")
    from assess.lib.code_languages import canonical_backend_language, detect_language
    from assess.lib.treesitter_index import language_for_file

    assert module._detect_language(filename) == "powershell"
    assert detect_language(filename) == "powershell"
    assert canonical_backend_language("powershell") == "powershell"
    # PowerShell now has a lightweight extractor, so ingest classification and
    # the structural index agree; the backend must still accept the language,
    # which is what a `.ps1` 400ing `code-index sync` for a whole repository cost.
    assert language_for_file(filename) == "powershell"


def test_git_provenance_uses_safe_flags_and_strips_case_insensitive_git_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_git_provenance")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").write_text("gitdir: /trusted/worktree-meta\n", encoding="utf-8")
    git = tmp_path / "trusted-git"
    git.write_text("", encoding="utf-8")
    git.chmod(0o755)
    monkeypatch.setenv("GIT_DIR", str(repo / "attacker"))
    monkeypatch.setenv("git_work_tree", str(repo / "attacker-worktree"))

    calls: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(command, **kwargs):
        calls.append((list(command), dict(kwargs["env"])))
        tail = command[-3:]
        if "--is-inside-work-tree" in command:
            return SimpleNamespace(returncode=0, stdout="true\n", stderr="")
        if tail[-2:] == ["--verify", "HEAD^{commit}"]:
            return SimpleNamespace(returncode=0, stdout=f"{'a' * 40}\n", stderr="")
        if "symbolic-ref" in command:
            return SimpleNamespace(returncode=0, stdout="main\n", stderr="")
        if "status" in command:
            return SimpleNamespace(returncode=0, stdout=" M main.py\n", stderr="")
        raise AssertionError(command)

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    provenance_fn = getattr(module, "_git_provenance", None)
    assert callable(provenance_fn), "code-ingest must capture trusted Git provenance"
    provenance = provenance_fn(str(repo), str(git))

    assert provenance == {"head": "a" * 40, "branch": "main", "dirty": True}
    assert calls
    for command, environment in calls:
        assert command[0] == str(git.resolve())
        assert command[1:3] == ["-C", str(repo.resolve())]
        assert "--no-pager" in command
        assert "--no-optional-locks" in command
        assert {
            key: value for key, value in environment.items() if key.upper().startswith("GIT_")
        } == {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    assert any(command[-3:] == ["rev-parse", "--verify", "HEAD^{commit}"] for command, _ in calls)
    assert any(
        command[-6:] == ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--", "."]
        for command, _ in calls
    )


def test_capture_reads_once_with_no_follow_and_rejects_a_mutation_race(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_single_read")
    path = tmp_path / "main.py"
    path.write_bytes(b"print('safe')\n")
    capture = getattr(module, "_capture_regular_file", None)
    assert callable(capture), "code-ingest must own one no-follow source read"

    real_open = module.os.open
    source_open_flags: list[int] = []

    def tracked_open(name, flags, *args):
        if Path(name) == path:
            source_open_flags.append(flags)
        return real_open(name, flags, *args)

    monkeypatch.setattr(module.os, "open", tracked_open)
    record = capture(path)
    captured_bytes = record.read_bounded(1024)
    assert len(source_open_flags) == 1
    assert source_open_flags[0] & os.O_NOFOLLOW
    assert captured_bytes == b"print('safe')\n"
    assert record.sha256 == hashlib.sha256(captured_bytes).hexdigest()
    assert record.loc == 1
    assert record.header == "print('safe')\n"
    record.close()

    real_read = module.os.read
    mutated = False

    def racing_read(fd: int, size: int) -> bytes:
        nonlocal mutated
        chunk = real_read(fd, size)
        if chunk and not mutated:
            mutated = True
            path.write_bytes(b"print('changed')\n")
        return chunk

    monkeypatch.setattr(module.os, "read", racing_read)
    race_error = getattr(module, "SourceSnapshotRaceError", RuntimeError)
    with pytest.raises(race_error, match="changed while being sealed"):
        capture(path)


def test_rooted_capture_rejects_an_ancestor_swapped_to_an_outside_symlink(tmp_path: Path) -> None:
    from assess.lib.code_snapshot import RootedSourceTree

    source = tmp_path / "source"
    nested = source / "nested"
    nested.mkdir(parents=True)
    (nested / "main.py").write_text("print('safe')\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "main.py").write_text("print('escaped')\n", encoding="utf-8")

    with RootedSourceTree(source) as tree:
        nested.rename(source / "original-nested")
        nested.symlink_to(outside, target_is_directory=True)
        with pytest.raises((OSError, ValueError)):
            tree.capture("nested/main.py")
        with pytest.raises((OSError, ValueError)):
            list(tree.walk("nested"))


def test_snapshot_builder_rejects_unsafe_repo_key_before_creating_artifacts(
    tmp_path: Path,
) -> None:
    from assess.lib.code_snapshot import SnapshotBuilder

    snapshots = tmp_path / "snapshots"

    with pytest.raises(ValueError, match="repo_key"):
        SnapshotBuilder(snapshots, "../escape")

    assert not snapshots.exists()


def test_code_ingest_git_marker_without_trusted_git_fails_before_config_or_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_requires_marker")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / "main.py").write_text("print('safe')\n", encoding="utf-8")
    engagement = tmp_path / "engagement"
    monkeypatch.setenv("PATH", f"{repo}{os.pathsep}{os.pathsep}.")
    monkeypatch.setattr(module, "load_config", lambda *_: pytest.fail("config loaded before Git validation"))

    with pytest.raises(SystemExit) as excinfo:
        module.run(_ingest_args(repo, engagement))

    assert excinfo.value.code == 1
    assert not engagement.exists()


@pytest.mark.parametrize(
    "repo_key",
    ["/tmp/escape", "../escape", "nested/escape", r"nested\escape", ".", ".."],
)
def test_code_ingest_rejects_repo_keys_that_are_not_one_safe_path_component(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo_key: str
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_unsafe_repo_key")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("print('safe')\n", encoding="utf-8")
    engagement = tmp_path / "engagement"
    args = _ingest_args(repo, engagement)
    args.repo_key = repo_key
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: pytest.fail("config loaded for an unsafe repository key"),
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(args)

    assert excinfo.value.code == 1
    assert not engagement.exists()


@pytest.mark.parametrize("repo_name", ["../Escape Repo", "/tmp/escape", r"nested\escape"])
def test_code_ingest_derived_repo_key_normalizes_unsafe_name_characters(
    tmp_path: Path, repo_name: str
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_safe_derived_repo_key")

    repo_key = module._repo_key_for_path(repo_name, str(tmp_path / "repo"))

    assert repo_key not in {".", ".."}
    assert "/" not in repo_key
    assert "\\" not in repo_key
    assert repo_key.endswith(hashlib.sha256(str((tmp_path / "repo").resolve()).encode()).hexdigest()[:12])


def test_code_ingest_derived_repo_key_respects_portable_component_limit(
    tmp_path: Path,
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_bounded_derived_repo_key")
    repo_path = tmp_path / "repo"

    repo_key = module._repo_key_for_path("a" * 300, str(repo_path))

    path_hash = hashlib.sha256(str(repo_path.resolve()).encode()).hexdigest()[:12]
    assert len(os.fsencode(repo_key)) == 255
    assert repo_key.endswith(f"-{path_hash}")


def test_code_ingest_plain_directory_uses_canonical_directory_provenance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_directory")
    repo = tmp_path / "real-repo"
    repo.mkdir()
    (repo / "main.py").write_text("print('safe')\n", encoding="utf-8")
    alias = tmp_path / "repo-alias"
    alias.symlink_to(repo, target_is_directory=True)
    engagement = tmp_path / "engagement"
    engagement.mkdir()
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement),
        ),
    )
    monkeypatch.setattr(module, "_setup_ctags", lambda *args, **kwargs: {"available": False, **kwargs})
    captured: dict[str, dict] = {}

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def post(self, endpoint: str, payload: dict):
            if endpoint == "code/repos/refresh/start":
                captured["start"] = payload
                return {"repo_id": 7, "refresh_token": "refresh-7"}
            if endpoint == "code/repos/7/refresh/files":
                return {"staged": len(payload["files"])}
            if endpoint == "code/repos/7/refresh/commit":
                return {
                    "repo_id": 7,
                    "repo_generation": 1,
                    "source_manifest_digest": "d" * 64,
                    "retired": 0,
                    "repo_role": "analysis",
                }
            if endpoint == "code/repos/7/lsp-config":
                assert payload["repo_generation"] == 1
                assert payload["source_manifest_digest"] == "d" * 64
                assert payload["lsp_config"]["ctags"]["repo_generation"] == 1
                return _lsp_publish_response(payload)
            raise AssertionError(endpoint)

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    module.run(_ingest_args(alias, engagement))

    start = captured["start"]
    assert start["source_kind"] == "directory"
    assert start["source_origin_path"] == str(repo.resolve())
    assert start["commit_hash"] == ""
    assert start["branch"] == ""
    assert start["worktree_dirty"] is None


def test_code_ingest_authenticates_complete_exclusion_accounting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_exclusions")
    repo = tmp_path / "repo"
    vendor = repo / "vendor" / "nested"
    vendor.mkdir(parents=True)
    (repo / "main.py").write_text("print('safe')\n", encoding="utf-8")
    (repo / "vendor" / "library.php").write_text("<?php echo 1;\n", encoding="utf-8")
    (vendor / "bundle.js").write_text("export const safe = true;\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    (repo / "outside-link").symlink_to(outside)
    (vendor / "nested-link").symlink_to(outside)
    engagement = tmp_path / "engagement"
    engagement.mkdir()
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement),
        ),
    )
    monkeypatch.setattr(
        module,
        "_setup_ctags",
        lambda *_args, **kwargs: {"available": False, **kwargs},
    )
    captured: dict[str, dict] = {}

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def post(self, endpoint: str, payload: dict):
            if endpoint == "code/repos/refresh/start":
                captured["start"] = payload
                return {"repo_id": 7, "refresh_token": "refresh-7"}
            if endpoint == "code/repos/7/refresh/files":
                return {"staged": len(payload["files"])}
            if endpoint == "code/repos/7/refresh/commit":
                return {
                    "repo_id": 7,
                    "repo_generation": 3,
                    "source_manifest_digest": "d" * 64,
                    "retired": 0,
                    "repo_role": "analysis",
                }
            if endpoint == "code/repos/7/lsp-config":
                return _lsp_publish_response(payload)
            raise AssertionError(endpoint)

        def patch(self, endpoint: str, _payload: dict):
            assert endpoint == "code/repos/7"
            return {"id": 7}

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    module.run(_ingest_args(repo, engagement))

    start = captured["start"]
    assert start["total_files"] == 5
    sealed = json.loads(
        Path(start["snapshot_manifest_path"]).read_text(encoding="utf-8")
    )
    exclusions = {
        (record["path"], record["kind"]): record
        for record in sealed["excluded_entries"]
    }
    assert ("vendor", "directory") in exclusions
    assert ("vendor/library.php", "file") in exclusions
    assert ("vendor/nested/bundle.js", "file") in exclusions
    assert ("outside-link", "symlink") in exclusions
    assert ("vendor/nested/nested-link", "symlink") in exclusions
    assert exclusions[("vendor/library.php", "file")]["sha256"] == hashlib.sha256(
        b"<?php echo 1;\n"
    ).hexdigest()

    audit_paths = list(
        (engagement / "tools" / "analysis-state" / "skipped-artifacts").rglob("*.json")
    )
    assert len(audit_paths) == 1
    assert audit_paths[0].relative_to(
        engagement / "tools" / "analysis-state" / "skipped-artifacts"
    ).as_posix() == f"7/3/{'d' * 64}-{start['snapshot_digest']}.json"
    audit = json.loads(audit_paths[0].read_text(encoding="utf-8"))
    assert audit["repo_id"] == 7
    assert audit["repo_generation"] == 3
    assert audit["source_manifest_digest"] == "d" * 64
    assert audit["snapshot_digest"] == start["snapshot_digest"]
    assert audit["excluded_entries"] == sealed["excluded_entries"]


def test_targeted_include_does_not_admit_siblings_from_a_skipped_directory(
    tmp_path: Path,
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_targeted_include")
    repo = tmp_path / "repo"
    vendor = repo / "vendor"
    vendor.mkdir(parents=True)
    (repo / "main.py").write_text("print('safe')\n", encoding="utf-8")
    (vendor / "review-me.php").write_text("<?php echo 1;\n", encoding="utf-8")
    (vendor / "unrelated.php").write_text("<?php echo 2;\n", encoding="utf-8")
    args = _ingest_args(repo, tmp_path / "engagement")
    args.include_path = ["**/vendor/review-me.php"]

    with module.RootedSourceTree(repo) as source_tree:
        admitted = list(
            module._admitted_source_paths(source_tree, args, tmp_path / "snapshots")
        )
        excluded = module._collect_excluded_records(
            source_tree, args, tmp_path / "snapshots"
        )

    assert admitted == ["main.py", "vendor/review-me.php"]
    assert {
        (record["path"], record["reason"])
        for record in excluded
        if record["kind"] == "file"
    } == {("vendor/unrelated.php", "skipped_dir:vendor")}


def test_code_ingest_accepts_git_file_and_publishes_read_only_content_addressed_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_publish")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").write_text("gitdir: /trusted/worktree-meta\n", encoding="utf-8")
    (repo / "main.py").write_text("print('safe')\n", encoding="utf-8")
    (repo / "main.py").chmod(0o755)
    (repo / "outside.py").symlink_to(tmp_path / "outside.py")
    (tmp_path / "outside.py").write_text("print('outside')\n", encoding="utf-8")
    engagement = tmp_path / "engagement"
    engagement.mkdir()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement),
        ),
    )
    monkeypatch.setattr(
        module,
        "_prepare_git_source",
        lambda *_: ("/trusted/git", {"head": "a" * 40, "branch": "main", "dirty": True}),
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "_git_provenance",
        lambda *_: {"head": "a" * 40, "branch": "main", "dirty": True},
    )

    posted: list[tuple[str, dict]] = []

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def post(self, endpoint: str, payload: dict):
            posted.append((endpoint, payload))
            if endpoint == "code/repos/refresh/start":
                return {"repo_id": 7, "refresh_token": "refresh-7"}
            if endpoint == "code/repos/7/refresh/files":
                return {"staged": len(payload["files"])}
            if endpoint == "code/repos/7/refresh/commit":
                return {
                    "repo_id": 7,
                    "repo_generation": 4,
                    "source_manifest_version": "code-source-manifest/v1",
                    "source_manifest_digest": "e" * 64,
                    "retired": 0,
                    "repo_role": "analysis",
                }
            if endpoint == "code/repos/7/lsp-config":
                assert payload["repo_generation"] == 4
                assert payload["source_manifest_digest"] == "e" * 64
                return _lsp_publish_response(payload)
            raise AssertionError(endpoint)

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    ctags_call: dict[str, object] = {}

    def fake_ctags(source_path, output_dir, selected_files, *, repo_generation, source_manifest_digest):
        ctags_call["selected_files"] = selected_files
        ctags_call["output_dir"] = Path(output_dir)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        tags = output_dir / "tags"
        tags.write_text("main\tmain.py\t1\n", encoding="utf-8")
        return {
            "available": True,
            "tags_path": str(tags),
            "repo_generation": repo_generation,
            "source_manifest_digest": source_manifest_digest,
        }

    monkeypatch.setattr(module, "_setup_ctags", fake_ctags)
    module.run(_ingest_args(repo, engagement))

    start = posted[0][1]
    sealed_source = Path(start["repo_path"])
    assert sealed_source.is_dir()
    assert sealed_source != repo
    assert sealed_source.readlink() if sealed_source.is_symlink() else sealed_source == sealed_source.resolve()
    assert sealed_source.relative_to(
        engagement / "tools" / "analysis-state" / "code-snapshots" / "demo-repo"
    )
    assert sealed_source.name == "source"
    assert sealed_source.parent.name == start["snapshot_digest"]
    assert start["source_origin_path"] == str(repo.resolve())
    assert start["source_kind"] == "git"
    assert start["source_snapshot_quality"] == "verified"
    assert start["worktree_dirty"] is True
    assert (sealed_source / "main.py").read_bytes() == b"print('safe')\n"
    assert not (sealed_source / ".git").exists()
    assert not (sealed_source / "outside.py").exists()
    assert stat.S_IMODE((sealed_source / "main.py").stat().st_mode) == 0o555
    manifest = json.loads(Path(start["snapshot_manifest_path"]).read_text(encoding="utf-8"))
    assert "source_manifest_digest" not in start
    assert manifest["snapshot_digest"] == start["snapshot_digest"]
    assert manifest["git"] == {"head": "a" * 40, "branch": "main", "dirty": True}
    assert manifest["files"][0]["executable"] is True
    assert posted[-1][0] == "code/repos/7/lsp-config"
    assert posted[-1][1]["repo_generation"] == 4
    assert posted[-1][1]["source_manifest_digest"] == "e" * 64
    lsp = posted[-1][1]["lsp_config"]["ctags"]
    assert lsp["repo_generation"] == 4
    assert lsp["source_manifest_digest"] == "e" * 64
    assert not Path(lsp["tags_path"]).is_relative_to(sealed_source)
    assert ctags_call["selected_files"] == [
        {
            "file_path": "main.py",
            "source_sha256": hashlib.sha256(b"print('safe')\n").hexdigest(),
        }
    ]
    assert ctags_call["output_dir"] == (
        engagement / "tools" / "analysis-state" / "ctags" / "demo-repo" / f"4-{'e' * 12}"
    )


@pytest.mark.parametrize(
    ("current_provenance", "published_snapshots"),
    [
        (
            [{"head": "a" * 40, "branch": "main", "dirty": True}],
            0,
        ),
        (
            [
                {"head": "a" * 40, "branch": "main", "dirty": False},
                {"head": "a" * 40, "branch": "release", "dirty": False},
            ],
            1,
        ),
        (
            [
                {"head": "a" * 40, "branch": "main", "dirty": False},
                {"head": "b" * 40, "branch": "main", "dirty": False},
            ],
            1,
        ),
    ],
    ids=["dirty-after-initial-status", "same-head-branch-switch", "head-switch"],
)
def test_code_ingest_rechecks_full_git_provenance_before_publish_or_backend(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    current_provenance: list[dict[str, object]],
    published_snapshots: int,
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_provenance_recheck")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / "main.py").write_text("print('safe')\n", encoding="utf-8")
    engagement = tmp_path / "engagement"
    monkeypatch.setattr(
        module,
        "_prepare_git_source",
        lambda *_: ("/trusted/git", {"head": "a" * 40, "branch": "main", "dirty": False}),
        raising=False,
    )
    provenance = iter(current_provenance)
    monkeypatch.setattr(module, "_git_provenance", lambda *_: next(provenance))
    monkeypatch.setattr(module, "_git_commit_count", lambda *_: 0)
    monkeypatch.setattr(module, "_git_churn_scores", lambda *_: {})
    monkeypatch.setattr(module, "_git_security_files", lambda *_: set())
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement),
        ),
    )

    class ForbiddenClient:
        def __init__(self, *_args, **_kwargs):
            pytest.fail("backend contacted after Git provenance changed")

    monkeypatch.setattr(module, "AssessmentClient", ForbiddenClient)
    with pytest.raises(SystemExit) as excinfo:
        module.run(_ingest_args(repo, engagement))
    assert excinfo.value.code == 1
    snapshots = engagement / "tools" / "analysis-state" / "code-snapshots" / "demo-repo"
    assert len([path for path in snapshots.iterdir() if not path.name.startswith(".")]) == published_snapshots


def test_code_ingest_rewalk_rejects_file_added_after_first_capture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_rewalk")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("print('safe')\n", encoding="utf-8")
    engagement = tmp_path / "engagement"
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement),
        ),
    )
    real_capture = module.RootedSourceTree.capture
    added = False

    def capture_then_add(tree, rel_path, **kwargs):
        nonlocal added
        captured = real_capture(tree, rel_path, **kwargs)
        if Path(rel_path).name == "main.py" and not added:
            added = True
            (repo / "new.py").write_text("print('new')\n", encoding="utf-8")
        return captured

    monkeypatch.setattr(module.RootedSourceTree, "capture", capture_then_add)

    class ForbiddenClient:
        def __init__(self, *_args, **_kwargs):
            pytest.fail("backend contacted for a mixed source inventory")

    monkeypatch.setattr(module, "AssessmentClient", ForbiddenClient)
    with pytest.raises(SystemExit) as excinfo:
        module.run(_ingest_args(repo, engagement))
    assert excinfo.value.code == 1


def test_ctags_uses_only_manifest_selected_explicit_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_ctags_files")
    source = tmp_path / "source"
    source.mkdir()
    main = source / "main.py"
    main.write_text("print('main')\n", encoding="utf-8")
    (source / ".ctags").write_text("--recurse=yes\n", encoding="utf-8")
    ignored = source / "ignored.py"
    ignored.write_text("print('ignored')\n", encoding="utf-8")
    selected = [
        {
            "file_path": "main.py",
            "source_sha256": hashlib.sha256(main.read_bytes()).hexdigest(),
        }
    ]
    commands: list[list[str]] = []
    monkeypatch.setattr(module, "_resolve_trusted_tool", lambda *_args, **_kwargs: "/trusted/ctags")

    def fake_run(command, **_kwargs):
        commands.append(list(command))
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="Universal Ctags\n", stderr="")
        output = Path(command[command.index("-f") + 1])
        output.write_text("main\tmain.py\t1\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    result = module._setup_ctags(
        source,
        tmp_path / "ctags",
        selected,
        repo_generation=2,
        source_manifest_digest="d" * 64,
    )
    generation_command = commands[-1]
    assert result["available"] is True
    assert "-R" not in generation_command
    assert "./main.py" in generation_command
    assert "ignored.py" not in generation_command


def test_ctags_prefixes_dash_leading_source_names_so_they_cannot_inject_options(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_ctags_dash_filename")
    source = tmp_path / "source"
    source.mkdir()
    attacker_options = source / "--options=evil.ctags"
    attacker_options.write_text("--recurse=yes\n", encoding="utf-8")
    selected = [
        {
            "file_path": attacker_options.name,
            "source_sha256": hashlib.sha256(attacker_options.read_bytes()).hexdigest(),
        }
    ]
    commands: list[list[str]] = []
    monkeypatch.setattr(module, "_resolve_trusted_tool", lambda *_args, **_kwargs: "/trusted/ctags")

    def fake_run(command, **_kwargs):
        commands.append(list(command))
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="Universal Ctags\n", stderr="")
        output = Path(command[command.index("-f") + 1])
        output.write_text("", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    result = module._setup_ctags(
        source,
        tmp_path / "ctags",
        selected,
        repo_generation=2,
        source_manifest_digest="d" * 64,
    )

    generation_command = commands[-1]
    assert result["available"] is True
    assert "./--options=evil.ctags" in generation_command
    assert "--options=evil.ctags" not in generation_command


def test_ctags_uses_random_regular_tempfile_and_cannot_clobber_predictable_symlink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_ctags_tempfile")
    source = tmp_path / "source"
    source.mkdir()
    main = source / "main.py"
    main.write_text("print('main')\n", encoding="utf-8")
    output = tmp_path / "ctags"
    output.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("do not overwrite\n", encoding="utf-8")
    predictable = output / f".tags-{os.getpid()}.tmp"
    predictable.symlink_to(victim)
    selected = [
        {
            "file_path": "main.py",
            "source_sha256": hashlib.sha256(main.read_bytes()).hexdigest(),
        }
    ]
    generation: dict[str, object] = {}
    monkeypatch.setattr(module, "_resolve_trusted_tool", lambda *_args, **_kwargs: "/trusted/ctags")
    monkeypatch.setenv("CTAGS", "--recurse=yes")
    monkeypatch.setenv("ctags_options", "--output=attacker-tags")

    def fake_run(command, **kwargs):
        assert command[1] == "--options=NONE"
        assert kwargs.get("cwd") == str(source.resolve())
        assert not [
            key
            for key in kwargs["env"]
            if key.upper() == "CTAGS" or key.upper().startswith("CTAGS_")
        ]
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="Universal Ctags\n", stderr="")
        destination = Path(command[command.index("-f") + 1])
        generation["destination"] = destination
        generation["cwd"] = kwargs.get("cwd")
        assert destination.is_file()
        assert not destination.is_symlink()
        destination.write_text("main\tmain.py\t1\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    result = module._setup_ctags(
        source,
        output,
        selected,
        repo_generation=2,
        source_manifest_digest="d" * 64,
    )

    assert result["available"] is True
    assert victim.read_text(encoding="utf-8") == "do not overwrite\n"
    assert predictable.is_symlink()
    assert generation["destination"] != predictable
    assert generation["cwd"] == str(source.resolve())


def test_ctags_source_verification_hashes_sparse_files_without_materializing_them(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_command("code_ingest.py", "test_streamed_ctags_verification")
    from assess.lib.code_snapshot import capture_regular_file

    source = tmp_path / "source"
    source.mkdir()
    huge = source / "main.py"
    with huge.open("wb") as handle:
        handle.seek(32 * 1024 * 1024 - 1)
        handle.write(b"\n")
    source_sha = capture_regular_file(huge, retain_spool=False).sha256
    output = tmp_path / "ctags"
    monkeypatch.setattr(module, "_resolve_trusted_tool", lambda *_args, **_kwargs: "/trusted/ctags")

    def fake_run(command, **_kwargs):
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="Universal Ctags\n", stderr="")
        destination = Path(command[command.index("-f") + 1])
        destination.write_text("main\tmain.py\t1\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    tracemalloc.start()
    result = module._setup_ctags(
        source,
        output,
        [{"file_path": "main.py", "source_sha256": source_sha}],
        repo_generation=2,
        source_manifest_digest="d" * 64,
    )
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert result["available"] is True
    assert peak < 8 * 1024 * 1024


def test_snapshot_publish_revalidates_after_final_root_is_sealed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import assess.lib.code_snapshot as module

    origin = tmp_path / "origin"
    origin.mkdir()
    main = origin / "main.py"
    main.write_text("print('safe')\n", encoding="utf-8")
    real_validate = module.validate_snapshot
    observed_modes: list[int] = []

    def validate_after_seal(path: Path, **kwargs):
        observed_modes.append(stat.S_IMODE(path.lstat().st_mode))
        return real_validate(path, **kwargs)

    monkeypatch.setattr(module, "validate_snapshot", validate_after_seal)
    builder = module.SnapshotBuilder(tmp_path / "snapshots", "demo")
    builder.add("main.py", module.capture_regular_file(main), language="python")
    builder.finish(
        repo_key="demo",
        repo_name="demo",
        source_origin_path=str(origin),
        git={"head": "", "branch": "", "dirty": None},
    )

    assert observed_modes == [0o555]


def test_snapshot_identity_authenticates_provenance_and_reuses_only_exact_identity(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    from assess.lib.code_snapshot import SnapshotBuilder, capture_regular_file

    origin = tmp_path / "origin"
    origin.mkdir()
    main = origin / "main.py"
    main.write_text("print('safe')\n", encoding="utf-8")
    roots = tmp_path / "snapshots"
    request.addfinalizer(lambda: _restore_tree_writable(roots))

    def seal(*, head: str, source_origin: Path = origin):
        builder = SnapshotBuilder(roots, "demo")
        builder.add("main.py", capture_regular_file(main), language="python")
        return builder.finish(
            repo_key="demo",
            repo_name="Demo",
            source_origin_path=str(source_origin.resolve()),
            git={"head": head, "branch": "main", "dirty": False},
            excluded_entries=[],
        )

    first = seal(head="a" * 40)
    exact_reuse = seal(head="a" * 40)
    empty_commit = seal(head="b" * 40)
    other_origin = tmp_path / "other-origin"
    other_origin.mkdir()
    different_origin = seal(head="b" * 40, source_origin=other_origin)

    assert exact_reuse.reused is True
    assert exact_reuse.snapshot_digest == first.snapshot_digest
    assert empty_commit.snapshot_digest != first.snapshot_digest
    assert different_origin.snapshot_digest != empty_commit.snapshot_digest
    empty_manifest = json.loads(empty_commit.manifest_path.read_text(encoding="utf-8"))
    assert empty_manifest["git"]["head"] == "b" * 40
    assert empty_manifest["source_origin_path"] == str(origin.resolve())


def test_reused_snapshot_rejects_extra_symlink_and_permission_drift(tmp_path: Path) -> None:
    from assess.lib.code_snapshot import SnapshotBuilder, capture_regular_file

    origin = tmp_path / "origin"
    origin.mkdir()
    main = origin / "main.py"
    main.write_text("print('safe')\n", encoding="utf-8")
    roots = tmp_path / "snapshots"
    first = SnapshotBuilder(roots, "demo")
    first.add("main.py", capture_regular_file(main), language="python")
    sealed = first.finish(
        repo_key="demo",
        repo_name="demo",
        source_origin_path=str(origin),
        git={"head": "", "branch": "", "dirty": None},
    )
    os.chmod(sealed.source_path, 0o755)
    (sealed.source_path / "extra.py").symlink_to(main)

    repeat = SnapshotBuilder(roots, "demo")
    repeat.add("main.py", capture_regular_file(main), language="python")
    with pytest.raises(ValueError, match="snapshot"):
        repeat.finish(
            repo_key="demo",
            repo_name="demo",
            source_origin_path=str(origin),
            git={"head": "", "branch": "", "dirty": None},
        )


def test_code_ingest_dry_run_creates_no_local_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_ingest.py", "test_sealed_ingest_dry_run")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / "main.py").write_text("print('safe')\n", encoding="utf-8")
    engagement = tmp_path / "engagement"
    engagement.mkdir()
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement),
        ),
    )
    monkeypatch.setattr(
        module,
        "_prepare_git_source",
        lambda *_: ("/trusted/git", {"head": "a" * 40, "branch": "main", "dirty": False}),
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "_git_provenance",
        lambda *_: {"head": "a" * 40, "branch": "main", "dirty": False},
    )

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def post(self, endpoint: str, _payload: dict):
            assert endpoint == "code/repos/refresh/preview"
            return {"added": ["main.py"], "changed": [], "renamed": [], "removed": []}

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    module.run(_ingest_args(repo, engagement, dry_run=True))
    assert not (engagement / "tools").exists()


def test_code_ingest_closes_capture_spool_on_record_build_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_command("code_ingest.py", "test_ingest_capture_cleanup")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("print('safe')\n", encoding="utf-8")
    engagement = tmp_path / "engagement"
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement),
        ),
    )
    captured_spools: list[object] = []
    real_capture = module.RootedSourceTree.capture

    def tracked_capture(tree, rel_path, **kwargs):
        captured = real_capture(tree, rel_path, **kwargs)
        if kwargs.get("retain_spool"):
            captured_spools.append(captured.spool)
        return captured

    monkeypatch.setattr(module.RootedSourceTree, "capture", tracked_capture)
    monkeypatch.setattr(
        module,
        "_detect_language",
        lambda _filename: (_ for _ in ()).throw(RuntimeError("record build failed")),
    )

    with pytest.raises(RuntimeError, match="record build failed"):
        module.run(_ingest_args(repo, engagement))

    assert captured_spools
    assert all(spool.closed for spool in captured_spools)


def test_code_index_build_emits_generation_scoped_v6_and_preserves_v4_history(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    module = _load_command("code_index.py", "test_sealed_code_index_v6")
    server_digest = "d" * 64
    raw = b"print('sealed')\n"
    notes = b"# Security notes\n"
    source, source_manifest = _sealed_snapshot(
        tmp_path,
        {"main.py": raw, "notes.md": notes},
    )
    output = tmp_path / "analysis-state"
    request.addfinalizer(
        lambda: _restore_tree_writable(output / "structural-index" / "history")
    )
    backend_rows = [
        {
            "id": file_id,
            "repo_id": 7,
            "file_path": rel_path,
            "file_hash": hashlib.sha256(content).hexdigest(),
            "language": language,
        }
        for file_id, (rel_path, content, language) in enumerate(
            (("main.py", raw, "python"), ("notes.md", notes, "markdown")),
            start=11,
        )
    ]
    input_digest = _structural_identity(
        source_manifest,
        backend_rows,
        source_manifest_digest=server_digest,
    )
    legacy_manifest_path = (
        output
        / "structural-index"
        / "7"
        / "4"
        / "v4"
        / server_digest
        / input_digest
        / "manifest.json"
    )
    legacy_manifest_path.parent.mkdir(parents=True)
    legacy_bytes = b'{"schema":"structural-index/v4","historical":true}\n'
    legacy_manifest_path.write_bytes(legacy_bytes)
    aggregate_path = output / "structural-index-manifest.json"
    legacy_aggregate_bytes = (
        json.dumps(_legacy_v3_aggregate(), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    aggregate_path.write_bytes(legacy_aggregate_bytes)
    archive_path = (
        output
        / "structural-index"
        / "history"
        / "aggregates"
        / "v3"
        / f"{hashlib.sha256(legacy_aggregate_bytes).hexdigest()}.json"
    )

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def get(self, endpoint: str):
            if endpoint == "code/repos/7":
                return {
                    "id": 7,
                    "repo_key": "demo-repo",
                    "repo_path": str(source.resolve()),
                    "active_generation": 4,
                    "source_manifest_digest": server_digest,
                }
            if endpoint == "code/files?limit=5000&offset=0&repo_id=7":
                return _file_page([dict(row) for row in backend_rows])
            raise AssertionError(endpoint)

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient, raising=False)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
        raising=False,
    )
    monkeypatch.setitem(sys.modules, "tree_sitter", SimpleNamespace())
    parsed: list[bytes | None] = []
    parser_fails = False
    parser_cancelled = False

    def fake_index(path, language, source=None, *, result_validator=None):
        assert callable(result_validator)
        if parser_cancelled:
            raise KeyboardInterrupt
        if parser_fails:
            raise RuntimeError("parser interrupted before aggregate archival")
        parsed.append(source)
        return {
            "file_path": path,
            "language": language,
            "total_functions": 1,
            "total_exports": 0,
            "total_lines": 1,
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
        }

    monkeypatch.setattr(module, "index_file", fake_index)
    args = SimpleNamespace(
        repo_path=str(source),
        repo_id=7,
        repo_key=None,
        repo_name=None,
        output_dir=str(output),
        file_list=None,
        engagement_dir=str(tmp_path),
    )

    parser_cancelled = True
    with pytest.raises(KeyboardInterrupt):
        module.run(args)
    parser_cancelled = False
    assert not list(output.rglob(f".{input_digest}.stage-*"))

    parser_fails = True
    with pytest.raises(SystemExit) as excinfo:
        module.run(args)
    assert excinfo.value.code == 1
    parser_fails = False
    assert aggregate_path.read_bytes() == legacy_aggregate_bytes
    assert archive_path.exists() is False
    assert not [
        path
        for path in (output / "structural-index").rglob("manifest.json")
        if "v6" in path.parts
    ]

    identity_parent = (
        output
        / "structural-index"
        / "7"
        / "4"
        / "v6"
        / server_digest
    )
    final_dir = identity_parent / input_digest
    chain_paths: list[Path] = []
    chain_path = identity_parent
    while True:
        chain_paths.append(chain_path)
        if chain_path == output:
            break
        chain_path = chain_path.parent
    real_publish_aggregate = module._publish_aggregate
    real_os_fsync = module.os.fsync
    real_fsync_directory = module._fsync_directory_strict
    real_os_rename = module.os.rename
    identity_parent.rmdir()
    identity_parent.parent.rmdir()

    for collision in ("symlink", "regular-file"):
        unsafe_component = identity_parent.parent
        outside_directory = tmp_path / f"outside-structural-{collision}"
        outside_directory.mkdir()
        if collision == "symlink":
            unsafe_component.symlink_to(outside_directory, target_is_directory=True)
        else:
            unsafe_component.write_text("not a directory", encoding="utf-8")
        publish_entered = False

        def reject_publish_through_unsafe_chain(*_args, **_kwargs):
            nonlocal publish_entered
            publish_entered = True
            raise OSError("aggregate publication followed an unsafe directory component")

        monkeypatch.setattr(
            module,
            "_publish_aggregate",
            reject_publish_through_unsafe_chain,
        )
        with pytest.raises(SystemExit) as excinfo:
            module.run(args)
        assert excinfo.value.code == 1
        assert publish_entered is False
        assert aggregate_path.read_bytes() == legacy_aggregate_bytes
        assert archive_path.exists() is False
        assert not any(outside_directory.iterdir())
        unsafe_component.unlink()
        outside_directory.rmdir()
        monkeypatch.setattr(module, "_publish_aggregate", real_publish_aggregate)

    for failure_kind in ("staged-file", "directory-enotsup", "directory-eacces"):
        publish_entered = False

        def reject_publish(*_args, **_kwargs):
            nonlocal publish_entered
            publish_entered = True
            raise OSError("aggregate publication reached before durable generation")

        monkeypatch.setattr(module, "_publish_aggregate", reject_publish)
        if failure_kind == "staged-file":

            def fail_regular_fsync(fd: int) -> None:
                if stat.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError("staged generation file fsync interrupted")
                real_os_fsync(fd)

            monkeypatch.setattr(module.os, "fsync", fail_regular_fsync)
        else:
            failure_errno = (
                module.errno.ENOTSUP
                if failure_kind == "directory-enotsup"
                else module.errno.EACCES
            )

            def fail_directory_fsync(fd: int) -> None:
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise OSError(
                        failure_errno,
                        "structural directory fsync unsupported or denied",
                    )
                real_os_fsync(fd)

            monkeypatch.setattr(module.os, "fsync", fail_directory_fsync)

        with pytest.raises(SystemExit) as excinfo:
            module.run(args)
        assert excinfo.value.code == 1
        assert publish_entered is False
        assert aggregate_path.read_bytes() == legacy_aggregate_bytes
        assert archive_path.exists() is False
        assert not [
            path
            for path in (output / "structural-index").rglob("manifest.json")
            if "v6" in path.parts
        ]
        monkeypatch.setattr(module.os, "fsync", real_os_fsync)
        monkeypatch.setattr(module, "_fsync_directory_strict", real_fsync_directory)
        monkeypatch.setattr(module, "_publish_aggregate", real_publish_aggregate)

    publish_entered = False

    def reject_publish_after_rename_failure(*_args, **_kwargs):
        nonlocal publish_entered
        publish_entered = True
        raise OSError("aggregate publication reached after failed generation rename")

    def fail_generation_rename(source_dir, destination_dir) -> None:
        if Path(destination_dir) == final_dir:
            raise OSError("structural generation rename interrupted")
        real_os_rename(source_dir, destination_dir)

    monkeypatch.setattr(module, "_publish_aggregate", reject_publish_after_rename_failure)
    monkeypatch.setattr(module.os, "rename", fail_generation_rename)
    with pytest.raises(SystemExit) as excinfo:
        module.run(args)
    assert excinfo.value.code == 1
    assert publish_entered is False
    assert aggregate_path.read_bytes() == legacy_aggregate_bytes
    assert archive_path.exists() is False
    assert final_dir.exists() is False
    monkeypatch.setattr(module.os, "rename", real_os_rename)
    monkeypatch.setattr(module, "_publish_aggregate", real_publish_aggregate)

    publish_entered = False
    promotion_events: list[tuple[str, object]] = []

    def reject_publish_after_parent_fsync(*_args, **_kwargs):
        nonlocal publish_entered
        publish_entered = True
        raise OSError("aggregate publication reached before rename-parent fsync")

    def fail_rename_parent_fsync(path: Path) -> None:
        promotion_events.append(("fsync-directory", path))
        if path == identity_parent and final_dir.exists():
            raise OSError("structural generation rename-parent fsync interrupted")
        real_fsync_directory(path)

    def observed_promotion_fsync(fd: int) -> None:
        descriptor_type = "regular" if stat.S_ISREG(os.fstat(fd).st_mode) else "directory"
        promotion_events.append(("fsync", descriptor_type))
        real_os_fsync(fd)

    def observed_promotion_rename(source_dir, destination_dir) -> None:
        promotion_events.append(
            ("rename", (Path(source_dir), Path(destination_dir)))
        )
        real_os_rename(source_dir, destination_dir)

    monkeypatch.setattr(module, "_publish_aggregate", reject_publish_after_parent_fsync)
    monkeypatch.setattr(module, "_fsync_directory_strict", fail_rename_parent_fsync)
    monkeypatch.setattr(module.os, "fsync", observed_promotion_fsync)
    monkeypatch.setattr(module.os, "rename", observed_promotion_rename)
    with pytest.raises(SystemExit) as excinfo:
        module.run(args)
    assert excinfo.value.code == 1
    assert publish_entered is False
    assert aggregate_path.read_bytes() == legacy_aggregate_bytes
    assert archive_path.exists() is False
    assert (final_dir / "manifest.json").exists()
    rename_position = next(
        index for index, event in enumerate(promotion_events) if event[0] == "rename"
    )
    assert sum(
        event == ("fsync", "regular")
        for event in promotion_events[:rename_position]
    ) >= 3
    for chain_path in chain_paths:
        assert ("fsync-directory", chain_path) in promotion_events[:rename_position]
    assert any(
        event[0] == "fsync-directory"
        and isinstance(event[1], Path)
        and event[1].name == "files"
        and event[1].parent.name.startswith(f".{input_digest}.stage-")
        for event in promotion_events[:rename_position]
    )
    assert any(
        event[0] == "fsync-directory"
        and isinstance(event[1], Path)
        and event[1].name.startswith(f".{input_digest}.stage-")
        for event in promotion_events[:rename_position]
    )
    assert ("fsync-directory", final_dir) in promotion_events[rename_position + 1 :]
    assert ("fsync-directory", identity_parent) in promotion_events[rename_position + 1 :]
    monkeypatch.setattr(module.os, "fsync", real_os_fsync)
    monkeypatch.setattr(module.os, "rename", real_os_rename)
    monkeypatch.setattr(module, "_fsync_directory_strict", real_fsync_directory)
    monkeypatch.setattr(module, "_publish_aggregate", real_publish_aggregate)

    durability_events: list[tuple[str, object]] = []

    def observed_fsync(fd: int) -> None:
        descriptor_type = "regular" if stat.S_ISREG(os.fstat(fd).st_mode) else "directory"
        durability_events.append(("fsync", descriptor_type))
        real_os_fsync(fd)

    def observed_fsync_directory(path: Path) -> None:
        durability_events.append(("fsync-directory", path))
        real_fsync_directory(path)

    def observed_rename(source_dir, destination_dir) -> None:
        durability_events.append(
            ("rename", (Path(source_dir), Path(destination_dir)))
        )
        real_os_rename(source_dir, destination_dir)

    def observed_publish(*publish_args, **publish_kwargs):
        durability_events.append(("publish", aggregate_path))
        return real_publish_aggregate(*publish_args, **publish_kwargs)

    monkeypatch.setattr(module.os, "fsync", observed_fsync)
    monkeypatch.setattr(module, "_fsync_directory_strict", observed_fsync_directory)
    monkeypatch.setattr(module.os, "rename", observed_rename)
    monkeypatch.setattr(module, "_publish_aggregate", observed_publish)

    real_atomic_json = module._atomic_json
    monkeypatch.setattr(
        module,
        "_atomic_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("canonical aggregate publish interrupted")
        ),
    )
    with pytest.raises(SystemExit) as excinfo:
        module.run(args)
    assert excinfo.value.code == 1
    assert aggregate_path.read_bytes() == legacy_aggregate_bytes
    assert archive_path.read_bytes() == legacy_aggregate_bytes
    publish_position = next(
        index for index, event in enumerate(durability_events) if event[0] == "publish"
    )
    assert not any(event[0] == "rename" for event in durability_events[:publish_position])
    assert sum(
        event == ("fsync", "regular")
        for event in durability_events[:publish_position]
    ) >= 3
    for chain_path in chain_paths:
        assert ("fsync-directory", chain_path) in durability_events[:publish_position]
    assert ("fsync-directory", final_dir) in durability_events[:publish_position]
    archive_stat = archive_path.stat()
    for retained_directory in (
        archive_path.parent,
        archive_path.parent.parent,
        archive_path.parent.parent.parent,
    ):
        os.chmod(retained_directory, 0o555)

    manifests = [
        path
        for path in (output / "structural-index").rglob("manifest.json")
        if "v6" in path.parts
    ]
    assert len(manifests) == 1
    v6_manifest_bytes = manifests[0].read_bytes()
    tampered = json.loads(v6_manifest_bytes)
    tampered["total_functions"] = int(tampered["total_functions"]) + 1
    os.chmod(manifests[0], 0o644)
    manifests[0].write_text(json.dumps(tampered), encoding="utf-8")
    os.chmod(manifests[0], 0o444)

    monkeypatch.setattr(module, "_atomic_json", real_atomic_json)
    with pytest.raises(SystemExit) as excinfo:
        module.run(args)
    assert excinfo.value.code == 1
    assert aggregate_path.read_bytes() == legacy_aggregate_bytes
    assert archive_path.read_bytes() == legacy_aggregate_bytes
    assert archive_path.stat().st_ino == archive_stat.st_ino
    assert archive_path.stat().st_mtime_ns == archive_stat.st_mtime_ns

    os.chmod(manifests[0], 0o644)
    manifests[0].write_bytes(v6_manifest_bytes)
    os.chmod(manifests[0], 0o444)
    module.run(args)
    durability_events.clear()
    module.run(args)

    retained_publish_position = next(
        index for index, event in enumerate(durability_events) if event[0] == "publish"
    )
    assert not any(
        event[0] == "rename" for event in durability_events[:retained_publish_position]
    )
    assert sum(
        event == ("fsync", "regular")
        for event in durability_events[:retained_publish_position]
    ) >= 3
    for chain_path in chain_paths:
        assert (
            "fsync-directory",
            chain_path,
        ) in durability_events[:retained_publish_position]
    assert (
        "fsync-directory",
        final_dir,
    ) in durability_events[:retained_publish_position]

    assert len(manifests) == 1
    assert aggregate_path.read_bytes() != legacy_aggregate_bytes
    assert archive_path.read_bytes() == legacy_aggregate_bytes
    assert archive_path.stat().st_ino == archive_stat.st_ino
    assert archive_path.stat().st_mtime_ns == archive_stat.st_mtime_ns
    assert legacy_manifest_path.read_bytes() == legacy_bytes
    assert len(list((output / "structural-index").rglob("manifest.json"))) == 2
    built = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert built["structural_input_digest"] == input_digest
    assert legacy_manifest_path.relative_to(output / "structural-index").parts == (
        "7",
        "4",
        "v4",
        server_digest,
        input_digest,
        "manifest.json",
    )
    assert manifests[0].relative_to(output / "structural-index").parts == (
        "7",
        "4",
        "v6",
        server_digest,
        input_digest,
        "manifest.json",
    )
    assert built["schema"] == "structural-index/v6"
    assert built["repo_id"] == 7
    assert built["repo_generation"] == 4
    assert built["source_manifest_digest"] == server_digest
    assert built["snapshot_digest"] == source_manifest["snapshot_digest"]
    assert set(built["files"]) == {"main.py", "notes.md"}
    assert built["files"]["main.py"]["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert parsed == [raw, raw, raw, raw, raw, raw, raw, raw, raw]
    assert built["path_to_index"] == {
        path: binding["index_path"] for path, binding in built["files"].items()
    }
    unsupported_path = output / "structural-index" / built["path_to_index"]["notes.md"]
    unsupported = json.loads(unsupported_path.read_text(encoding="utf-8"))
    assert unsupported["structural_index_available"] is False
    assert unsupported["analysis_status"] == "unsupported"
    assert unsupported["analysis_mode"] == "none"
    assert unsupported["degradation_reason"] == "unsupported_language"
    assert unsupported["unavailable_dimensions"]
    assert unsupported["total_functions"] == 0
    assert unsupported["source_sha256"] == hashlib.sha256(notes).hexdigest()
    assert f"/7/4/v6/{server_digest}/{built['structural_input_digest']}/" in (
        f"/{manifests[0].relative_to(output / 'structural-index')}/"
    )
    aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    assert aggregate["schema"] == "structural-index-aggregate/v4"
    assert set(aggregate["repos"]) == {"7"}

    sync_module = _load_command("code_index_sync.py", "test_sealed_code_index_unsupported_sync")

    class SyncClient:
        def get(self, endpoint: str):
            assert endpoint == "code/files?limit=5000&offset=0&repo_id=7"
            return _file_page([
                {
                    "id": file_id,
                    "repo_id": 7,
                    "file_path": rel_path,
                    "file_hash": hashlib.sha256(content).hexdigest(),
                    "language": language,
                }
                for file_id, (rel_path, content, language) in enumerate(
                    (("main.py", raw, "python"), ("notes.md", notes, "markdown")),
                    start=11,
                )
            ])

    sync_manifest = {**built, "_resolved_manifest_path": str(manifests[0])}
    prepared = sync_module._prepare_repo_payload(
        SyncClient(),
        {
            "id": 7,
            "repo_key": "demo-repo",
            "repo_path": str(source.resolve()),
            "active_generation": 4,
            "source_manifest_digest": server_digest,
        },
        sync_manifest,
        output / "structural-index",
    )
    assert prepared["structural_index_schema"] == "structural-index/v6"
    unsupported_update = next(item for item in prepared["updates"] if item["file_id"] == 12)
    assert unsupported_update["structural_analysis_status"] == "unsupported"
    assert unsupported_update["structural_analysis_mode"] == "none"
    assert unsupported_update["structural_degradation_reason"] == "unsupported_language"
    assert unsupported_update["structural_unavailable_dimensions"]


def test_code_index_language_correction_creates_a_new_immutable_identity_and_only_current_syncs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_command("code_index.py", "test_code_index_language_identity")
    sync_module = _load_command(
        "code_index_sync.py",
        "test_code_index_language_identity_sync",
    )
    server_digest = "d" * 64
    raw = b"class Demo { public: int value; };\n"
    source, source_manifest = _sealed_snapshot(tmp_path, {"include/demo.h": raw})
    assert source_manifest["files"][0]["language"] == "c"
    source_sha = hashlib.sha256(raw).hexdigest()
    output = tmp_path / "analysis-state"
    current_language = "c"

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def get(self, endpoint: str):
            if endpoint == "code/repos/7":
                return {
                    "id": 7,
                    "repo_key": "demo-repo",
                    "repo_path": str(source.resolve()),
                    "active_generation": 4,
                    "source_manifest_digest": server_digest,
                }
            if endpoint == "code/files?limit=5000&offset=0&repo_id=7":
                return _file_page([
                    {
                        "id": 11,
                        "repo_id": 7,
                        "file_path": "include/demo.h",
                        "file_hash": source_sha,
                        "language": current_language,
                    }
                ])
            raise AssertionError(endpoint)

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    parsed_languages: list[str] = []

    def fake_index(_path, language, source=None, **_kwargs):
        parsed_languages.append(language)
        return {
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
            "total_functions": 0,
            "total_exports": 0,
            "total_lines": 1,
            "functions": [],
            "entry_points": [],
            "security_sinks": [],
            "security_sources": [],
            "call_sites": [],
            "imports": [],
            "import_targets": [],
            "exports": [],
            "classes": [],
        }

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )
    monkeypatch.setattr(module, "index_file", fake_index)
    args = SimpleNamespace(
        repo_path=str(source),
        repo_id=7,
        repo_key=None,
        repo_name=None,
        output_dir=str(output),
        file_list=None,
        engagement_dir=str(tmp_path),
    )

    module.run(args)
    first_aggregate = json.loads(
        (output / "structural-index-manifest.json").read_text(encoding="utf-8")
    )
    first_manifest_path = output / first_aggregate["repos"]["7"]["manifest_path"]
    first_manifest = json.loads(first_manifest_path.read_text(encoding="utf-8"))

    current_language = "cpp"
    module.run(args)
    aggregate = json.loads(
        (output / "structural-index-manifest.json").read_text(encoding="utf-8")
    )
    current_manifest_path = output / aggregate["repos"]["7"]["manifest_path"]
    current_manifest = json.loads(current_manifest_path.read_text(encoding="utf-8"))

    current_language = "c++"
    module.run(args)
    alias_aggregate = json.loads(
        (output / "structural-index-manifest.json").read_text(encoding="utf-8")
    )

    assert parsed_languages == ["c", "cpp", "cpp"]
    assert first_manifest_path != current_manifest_path
    assert output / alias_aggregate["repos"]["7"]["manifest_path"] == current_manifest_path
    assert len(list((output / "structural-index").rglob("manifest.json"))) == 2
    assert first_manifest_path.is_file()
    assert current_manifest_path.is_file()
    assert first_manifest["structural_input_digest"] != current_manifest[
        "structural_input_digest"
    ]
    assert first_manifest["files"]["include/demo.h"]["language"] == "c"
    assert current_manifest["files"]["include/demo.h"]["language"] == "cpp"
    assert aggregate["repos"]["7"]["structural_input_digest"] == current_manifest[
        "structural_input_digest"
    ]
    current_artifact = json.loads(
        (
            output
            / "structural-index"
            / current_manifest["path_to_index"]["include/demo.h"]
        ).read_text(encoding="utf-8")
    )
    assert current_artifact["language"] == "cpp"
    assert current_artifact["structural_input_digest"] == current_manifest[
        "structural_input_digest"
    ]

    backend_repo = {
        "id": 7,
        "repo_key": "demo-repo",
        "repo_path": str(source.resolve()),
        "active_generation": 4,
        "source_manifest_digest": server_digest,
    }
    with pytest.raises(ValueError, match="language"):
        sync_module._prepare_repo_payload(
            FakeClient(),
            backend_repo,
            {**first_manifest, "_resolved_manifest_path": str(first_manifest_path)},
            output / "structural-index",
        )

    prepared = sync_module._prepare_repo_payload(
        FakeClient(),
        backend_repo,
        {**current_manifest, "_resolved_manifest_path": str(current_manifest_path)},
        output / "structural-index",
    )
    assert prepared["structural_input_digest"] == current_manifest[
        "structural_input_digest"
    ]
    assert [update["file_id"] for update in prepared["updates"]] == [11]
    assert [update["indexed_language"] for update in prepared["updates"]] == ["cpp"]


def test_code_index_explicit_unknown_backend_language_never_falls_back_to_filename(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_command("code_index.py", "test_code_index_explicit_unknown_language")
    sync_module = _load_command(
        "code_index_sync.py",
        "test_code_index_explicit_unknown_language_sync",
    )
    raw = b"int demo(void);\n"
    source, source_manifest = _sealed_snapshot(tmp_path, {"include/demo.h": raw})
    assert source_manifest["files"][0]["language"] == "c"
    source_sha = hashlib.sha256(raw).hexdigest()
    output = tmp_path / "analysis-state"

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def get(self, endpoint: str):
            if endpoint == "code/repos/7":
                return {
                    "id": 7,
                    "repo_key": "demo-repo",
                    "repo_path": str(source.resolve()),
                    "active_generation": 4,
                    "source_manifest_digest": "d" * 64,
                }
            if endpoint == "code/files?limit=5000&offset=0&repo_id=7":
                return _file_page([
                    {
                        "id": 11,
                        "repo_id": 7,
                        "file_path": "include/demo.h",
                        "file_hash": source_sha,
                        "language": "",
                    }
                ])
            raise AssertionError(endpoint)

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )
    monkeypatch.setattr(
        module,
        "index_file",
        lambda *_args, **_kwargs: pytest.fail("explicit unknown language reached a parser"),
    )

    module.run(
        SimpleNamespace(
            repo_path=str(source),
            repo_id=7,
            repo_key=None,
            repo_name=None,
            output_dir=str(output),
            file_list=None,
            engagement_dir=str(tmp_path),
        )
    )

    manifest_path = next((output / "structural-index").rglob("manifest.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    binding = manifest["files"]["include/demo.h"]
    artifact = json.loads(
        (output / "structural-index" / binding["index_path"]).read_text(encoding="utf-8")
    )
    assert binding["language"] == ""
    assert artifact["language"] == ""
    assert artifact["analysis_status"] == "unsupported"
    prepared = sync_module._prepare_repo_payload(
        FakeClient(),
        {
            "id": 7,
            "repo_key": "demo-repo",
            "repo_path": str(source.resolve()),
            "active_generation": 4,
            "source_manifest_digest": "d" * 64,
        },
        {**manifest, "_resolved_manifest_path": str(manifest_path)},
        output / "structural-index",
    )
    assert prepared["updates"][0]["indexed_language"] == ""


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        ("incomplete", "inventories differ"),
        ("path", "inventories differ"),
        ("hash", "source hash differs"),
        ("generation", "changed during structural indexing"),
        ("unknown-language", "unsupported backend language"),
    ],
)
def test_code_index_build_rejects_untrusted_backend_inventory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    failure: str,
    expected: str,
) -> None:
    module = _load_command("code_index.py", f"test_code_index_inventory_{failure}")
    raw = b"int demo(void);\n"
    source, _source_manifest = _sealed_snapshot(tmp_path, {"include/demo.h": raw})
    source_sha = hashlib.sha256(raw).hexdigest()
    repo_reads = 0

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def get(self, endpoint: str):
            nonlocal repo_reads
            if endpoint == "code/repos/7":
                repo_reads += 1
                generation = 5 if failure == "generation" and repo_reads > 1 else 4
                return {
                    "id": 7,
                    "repo_key": "demo-repo",
                    "repo_path": str(source.resolve()),
                    "active_generation": generation,
                    "source_manifest_digest": "d" * 64,
                }
            if endpoint == "code/files?limit=5000&offset=0&repo_id=7":
                if failure == "incomplete":
                    return _file_page([])
                return _file_page([
                    {
                        "id": 11,
                        "repo_id": 7,
                        "file_path": (
                            "include/other.h" if failure == "path" else "include/demo.h"
                        ),
                        "file_hash": "a" * 64 if failure == "hash" else source_sha,
                        "language": "brainfuck" if failure == "unknown-language" else "c",
                    }
                ])
            raise AssertionError(endpoint)

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )
    def fake_index(path, language, source=None, **_kwargs):
        if failure != "generation":
            pytest.fail("untrusted inventory reached the parser")
        return module._unsupported_index(path, language, source_size=len(source))

    monkeypatch.setattr(module, "index_file", fake_index)

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                repo_path=str(source),
                repo_id=7,
                repo_key=None,
                repo_name=None,
                output_dir=str(tmp_path / "analysis-state"),
                file_list=None,
                engagement_dir=str(tmp_path),
            )
        )

    assert excinfo.value.code == 1
    assert expected in capsys.readouterr().err
    assert not (tmp_path / "analysis-state" / "structural-index-manifest.json").exists()


def test_snapshot_validation_rejects_an_ancestor_swapped_after_root_is_pinned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from assess.lib import code_snapshot as module

    raw = b"print('sealed')\n"
    source, manifest = _sealed_snapshot(tmp_path, {"nested/main.py": raw})
    detached = tmp_path / "detached-validation-nested"
    outside = tmp_path / "outside-validation"
    outside.mkdir()
    (outside / "main.py").write_bytes(raw)
    original_capture = module.RootedSourceTree.capture
    swapped = False

    def capture_after_swap(self, rel_path, **kwargs):
        nonlocal swapped
        if not swapped:
            swapped = True
            os.chmod(source, 0o755)
            (source / "nested").rename(detached)
            (source / "nested").symlink_to(outside, target_is_directory=True)
            os.chmod(source, 0o555)
        return original_capture(self, rel_path, **kwargs)

    monkeypatch.setattr(module.RootedSourceTree, "capture", capture_after_swap)
    try:
        with pytest.raises((OSError, module.SourceSnapshotRaceError, ValueError)):
            module.validate_snapshot(source.parent, expected_digest=manifest["snapshot_digest"])
    finally:
        if (source / "nested").is_symlink():
            os.chmod(source, 0o755)
            (source / "nested").unlink()
            detached.rename(source / "nested")
            os.chmod(source, 0o555)


def test_code_index_build_rejects_an_ancestor_swapped_after_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from assess.lib.code_snapshot import RootedSourceTree

    module = _load_command("code_index.py", "test_code_index_ancestor_swap")
    raw = b"print('sealed')\n"
    source, source_manifest = _sealed_snapshot(tmp_path, {"nested/main.py": raw})
    output = tmp_path / "analysis-state"
    detached = tmp_path / "detached-index-nested"
    outside = tmp_path / "outside-index"
    outside.mkdir()
    (outside / "main.py").write_bytes(raw)

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def get(self, endpoint: str):
            if endpoint == "code/repos/7":
                return {
                    "id": 7,
                    "repo_key": "demo-repo",
                    "repo_path": str(source.resolve()),
                    "active_generation": 4,
                    "source_manifest_digest": "d" * 64,
                }
            if endpoint == "code/files?limit=5000&offset=0&repo_id=7":
                return _file_page([
                    {
                        "id": 11,
                        "repo_id": 7,
                        "file_path": "nested/main.py",
                        "file_hash": hashlib.sha256(raw).hexdigest(),
                        "language": "python",
                    }
                ])
            raise AssertionError(endpoint)

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )
    monkeypatch.setattr(module, "validate_snapshot", lambda *_args, **_kwargs: source_manifest)
    original_capture = RootedSourceTree.capture
    swapped = False

    def capture_after_swap(self, rel_path, **kwargs):
        nonlocal swapped
        if not swapped:
            swapped = True
            os.chmod(source, 0o755)
            (source / "nested").rename(detached)
            (source / "nested").symlink_to(outside, target_is_directory=True)
            os.chmod(source, 0o555)
        return original_capture(self, rel_path, **kwargs)

    monkeypatch.setattr(RootedSourceTree, "capture", capture_after_swap)
    try:
        with pytest.raises(SystemExit) as excinfo:
            module.run(
                SimpleNamespace(
                    repo_path=str(source),
                    repo_id=7,
                    repo_key=None,
                    repo_name=None,
                    output_dir=str(output),
                    file_list=None,
                    engagement_dir=str(tmp_path),
                )
            )
        assert excinfo.value.code == 1
        assert not (output / "structural-index-manifest.json").exists()
    finally:
        if (source / "nested").is_symlink():
            os.chmod(source, 0o755)
            (source / "nested").unlink()
            detached.rename(source / "nested")
            os.chmod(source, 0o555)


def test_code_index_rejects_snapshot_with_an_unexpected_file(tmp_path: Path) -> None:
    module = _load_command("code_index.py", "test_sealed_code_index_validation")
    source, _manifest = _sealed_snapshot(tmp_path, {"main.py": b"print('sealed')\n"})
    os.chmod(source, 0o755)
    (source / "unexpected.py").write_text("print('unexpected')\n", encoding="utf-8")
    os.chmod(source / "unexpected.py", 0o444)
    os.chmod(source, 0o555)

    with pytest.raises(ValueError, match="unexpected path"):
        module._load_snapshot(source.resolve())


def test_code_index_rejects_partial_file_list_for_authoritative_generation(
    tmp_path: Path,
) -> None:
    module = _load_command("code_index.py", "test_sealed_code_index_partial")
    _source, manifest = _sealed_snapshot(
        tmp_path,
        {"main.py": b"print('sealed')\n", "notes.md": b"# Notes\n"},
    )
    subset = tmp_path / "subset.json"
    subset.write_text(json.dumps([{"file_path": "main.py"}]), encoding="utf-8")

    with pytest.raises(ValueError, match="partial structural generations are not publishable"):
        module._select_files(manifest, str(subset))

    conflicting = tmp_path / "conflicting.json"
    conflicting.write_text(
        json.dumps(
            [
                {"file_path": "main.py", "language": "javascript"},
                {"file_path": "notes.md"},
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="cannot override authoritative languages"):
        module._select_files(manifest, str(conflicting))


@pytest.mark.parametrize(
    "aggregate",
    [
        {"schema": "structural-index-aggregate/v1", "repos": {"1": {}}},
        {"schema": "structural-index-aggregate/v2", "repos": []},
        {"schema": "structural-index-aggregate/v3", "repos": []},
        {"schema": "structural-index-aggregate/v4", "repos": []},
        {"schema": "structural-index-aggregate/v99", "repos": {}},
    ],
)
def test_code_index_publish_fails_closed_on_unknown_or_malformed_aggregate(
    tmp_path: Path, aggregate: dict
) -> None:
    module = _load_command("code_index.py", "test_sealed_code_index_bad_aggregate")
    aggregate_path = tmp_path / "structural-index-manifest.json"
    original = json.dumps(aggregate).encode("utf-8")
    aggregate_path.write_bytes(original)
    manifest_path = tmp_path / "structural-index" / "7" / "4" / ("d" * 64) / "manifest.json"
    manifest = {
        "repo_key": "demo-repo",
        "repo_generation": 4,
        "source_manifest_digest": "d" * 64,
    }

    with pytest.raises(ValueError, match="aggregate"):
        module._publish_aggregate(tmp_path, 7, manifest_path, manifest)

    assert aggregate_path.read_bytes() == original
    assert not (tmp_path / "structural-index" / "history").exists()


@pytest.mark.parametrize(
    "corruption",
    [
        "top-level-extra-field",
        "missing-updated-at",
        "invalid-updated-at",
        "empty-repos",
        "noncanonical-repo-map-key",
        "summary-not-object",
        "summary-extra-field",
        "summary-missing-field",
        "mismatched-repo-id",
        "repo-id-overflow",
        "unsafe-repo-key",
        "invalid-generation",
        "generation-overflow",
        "invalid-source-digest",
        "invalid-input-digest",
        "misbound-manifest-path",
        "negative-degraded-count",
        "degraded-path-count-mismatch",
        "unsafe-degraded-path",
        "invalid-truncated-paths",
        "invalid-status-keys",
        "invalid-status-count",
        "status-count-overflow",
        "degraded-status-mismatch",
        "truncated-count-exceeds-total",
    ],
)
def test_code_index_publish_rejects_corrupt_known_v3_summary_without_archiving(
    tmp_path: Path,
    corruption: str,
) -> None:
    module = _load_command("code_index.py", f"test_sealed_code_index_corrupt_v3_{corruption}")
    aggregate = _legacy_v3_aggregate()
    summary = aggregate["repos"]["999"]
    if corruption == "top-level-extra-field":
        aggregate["unexpected"] = True
    elif corruption == "missing-updated-at":
        aggregate.pop("updated_at")
    elif corruption == "invalid-updated-at":
        aggregate["updated_at"] = "yesterday"
    elif corruption == "empty-repos":
        aggregate["repos"] = {}
    elif corruption == "noncanonical-repo-map-key":
        aggregate["repos"]["0999"] = aggregate["repos"].pop("999")
    elif corruption == "summary-not-object":
        aggregate["repos"]["999"] = []
    elif corruption == "summary-extra-field":
        summary["unexpected"] = True
    elif corruption == "summary-missing-field":
        summary.pop("repo_key")
    elif corruption == "mismatched-repo-id":
        summary["repo_id"] = 998
    elif corruption == "repo-id-overflow":
        repo_id = 2**63
        aggregate["repos"][str(repo_id)] = aggregate["repos"].pop("999")
        summary["repo_id"] = repo_id
        summary["manifest_path"] = summary["manifest_path"].replace(
            "structural-index/999/", f"structural-index/{repo_id}/"
        )
    elif corruption == "unsafe-repo-key":
        summary["repo_key"] = "../stale-repo"
    elif corruption == "invalid-generation":
        summary["repo_generation"] = 0
    elif corruption == "generation-overflow":
        generation = 2**63
        summary["repo_generation"] = generation
        summary["manifest_path"] = summary["manifest_path"].replace(
            "/4/v4/", f"/{generation}/v4/"
        )
    elif corruption == "invalid-source-digest":
        summary["source_manifest_digest"] = "g" * 64
    elif corruption == "invalid-input-digest":
        summary["structural_input_digest"] = "B" * 64
    elif corruption == "misbound-manifest-path":
        summary["manifest_path"] = "/tmp/stale/manifest.json"
    elif corruption == "negative-degraded-count":
        summary["degraded_files"] = -1
    elif corruption == "degraded-path-count-mismatch":
        summary["degraded_file_paths"] = []
    elif corruption == "unsafe-degraded-path":
        summary["degraded_file_paths"] = ["../legacy.c"]
    elif corruption == "invalid-truncated-paths":
        summary["artifact_truncated_file_paths"] = ["legacy.c", "legacy.c"]
        summary["artifact_truncated_files"] = 2
    elif corruption == "invalid-status-keys":
        summary["analysis_status_counts"]["pending"] = 0
    elif corruption == "invalid-status-count":
        summary["analysis_status_counts"]["complete"] = True
    elif corruption == "status-count-overflow":
        summary["analysis_status_counts"]["complete"] = 2**63
    elif corruption == "degraded-status-mismatch":
        summary["analysis_status_counts"]["degraded"] = 0
    elif corruption == "truncated-count-exceeds-total":
        summary["artifact_truncated_files"] = 2
        summary["artifact_truncated_file_paths"] = ["legacy.c", "other.c"]
    else:  # pragma: no cover - the parameter roster is exhaustive
        raise AssertionError(corruption)

    aggregate_path = tmp_path / "structural-index-manifest.json"
    original = (json.dumps(aggregate, sort_keys=True) + "\n").encode("utf-8")
    aggregate_path.write_bytes(original)
    manifest_path = (
        tmp_path
        / "structural-index"
        / "7"
        / "4"
        / "v6"
        / ("d" * 64)
        / ("e" * 64)
        / "manifest.json"
    )
    manifest = {
        "repo_key": "demo-repo",
        "repo_generation": 4,
        "source_manifest_digest": "d" * 64,
        "structural_input_digest": "e" * 64,
        "degraded_files": 0,
        "degraded_file_paths": [],
        "artifact_truncated_files": 0,
        "artifact_truncated_file_paths": [],
        "analysis_status_counts": {"complete": 1, "degraded": 0, "unsupported": 0},
    }

    with pytest.raises(ValueError, match="legacy structural index aggregate"):
        module._publish_aggregate(tmp_path, 7, manifest_path, manifest)

    assert aggregate_path.read_bytes() == original
    assert not (tmp_path / "structural-index" / "history").exists()


@pytest.mark.parametrize("duplicate", ["top-level", "repo-summary"])
def test_code_index_publish_rejects_duplicate_legacy_v3_object_keys(
    tmp_path: Path,
    duplicate: str,
) -> None:
    module = _load_command("code_index.py", f"test_sealed_code_index_duplicate_v3_{duplicate}")
    aggregate_text = json.dumps(_legacy_v3_aggregate(), indent=2, sort_keys=True) + "\n"
    if duplicate == "top-level":
        aggregate_text = aggregate_text.replace(
            '"schema": "structural-index-aggregate/v3",',
            '"schema": "structural-index-aggregate/v3",\n'
            '  "schema": "structural-index-aggregate/v3",',
            1,
        )
    else:
        aggregate_text = aggregate_text.replace(
            '"repo_key": "stale-repo",',
            '"repo_key": "stale-repo",\n'
            '      "repo_key": "stale-repo",',
            1,
        )
    aggregate_bytes = aggregate_text.encode("utf-8")
    aggregate_path = tmp_path / "structural-index-manifest.json"
    aggregate_path.write_bytes(aggregate_bytes)
    manifest_path = (
        tmp_path
        / "structural-index"
        / "7"
        / "4"
        / "v6"
        / ("d" * 64)
        / ("e" * 64)
        / "manifest.json"
    )
    manifest = {
        "repo_key": "demo-repo",
        "repo_generation": 4,
        "source_manifest_digest": "d" * 64,
        "structural_input_digest": "e" * 64,
        "degraded_files": 0,
        "degraded_file_paths": [],
        "artifact_truncated_files": 0,
        "artifact_truncated_file_paths": [],
        "analysis_status_counts": {"complete": 1, "degraded": 0, "unsupported": 0},
    }

    with pytest.raises(ValueError, match="duplicate JSON object key"):
        module._publish_aggregate(tmp_path, 7, manifest_path, manifest)

    assert aggregate_path.read_bytes() == aggregate_bytes
    assert not (tmp_path / "structural-index" / "history").exists()


@pytest.mark.skipif(
    not hasattr(os, "fork") or not hasattr(os, "mkfifo"),
    reason="structural aggregate publication requires POSIX filesystem primitives",
)
@pytest.mark.parametrize("collision", ["canonical", "archive"])
def test_code_index_publish_rejects_fifo_collision_without_blocking(
    tmp_path: Path,
    collision: str,
) -> None:
    module = _load_command("code_index.py", f"test_sealed_code_index_fifo_{collision}")
    aggregate_path = tmp_path / "structural-index-manifest.json"
    aggregate_bytes = (
        json.dumps(_legacy_v3_aggregate(), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if collision == "canonical":
        os.mkfifo(aggregate_path)
    else:
        aggregate_path.write_bytes(aggregate_bytes)
        archive_path = (
            tmp_path
            / "structural-index"
            / "history"
            / "aggregates"
            / "v3"
            / f"{hashlib.sha256(aggregate_bytes).hexdigest()}.json"
        )
        archive_path.parent.mkdir(parents=True)
        os.mkfifo(archive_path)

    manifest_path = (
        tmp_path
        / "structural-index"
        / "7"
        / "4"
        / "v6"
        / ("d" * 64)
        / ("e" * 64)
        / "manifest.json"
    )
    manifest = {
        "repo_key": "demo-repo",
        "repo_generation": 4,
        "source_manifest_digest": "d" * 64,
        "structural_input_digest": "e" * 64,
        "degraded_files": 0,
        "degraded_file_paths": [],
        "artifact_truncated_files": 0,
        "artifact_truncated_file_paths": [],
        "analysis_status_counts": {"complete": 1, "degraded": 0, "unsupported": 0},
    }

    outcome = _fork_call_outcome(
        lambda: module._publish_aggregate(tmp_path, 7, manifest_path, manifest)
    )

    assert outcome != b"blocked", f"structural aggregate publication blocked on {collision} FIFO"
    assert outcome == b"value-error"
    if collision == "canonical":
        assert stat.S_ISFIFO(aggregate_path.lstat().st_mode)
    else:
        assert aggregate_path.read_bytes() == aggregate_bytes
        assert stat.S_ISFIFO(archive_path.lstat().st_mode)


@pytest.mark.skipif(
    not hasattr(os, "fork") or not hasattr(os, "mkfifo"),
    reason="structural aggregate publication requires POSIX filesystem primitives",
)
@pytest.mark.parametrize("collision", ["fifo", "symlink"])
def test_code_index_publish_rejects_unsafe_lock_nodes_without_blocking(
    tmp_path: Path,
    collision: str,
) -> None:
    module = _load_command("code_index.py", f"test_sealed_code_index_lock_{collision}")
    aggregate_path = tmp_path / "structural-index-manifest.json"
    aggregate_bytes = (
        json.dumps(_legacy_v3_aggregate(), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    aggregate_path.write_bytes(aggregate_bytes)
    lock_path = tmp_path / ".structural-index.lock"
    if collision == "fifo":
        os.mkfifo(lock_path)
    else:
        outside_lock = tmp_path / "outside.lock"
        outside_lock.write_bytes(b"outside-lock-sentinel")
        lock_path.symlink_to(outside_lock)
    manifest_path = (
        tmp_path
        / "structural-index"
        / "7"
        / "4"
        / "v6"
        / ("d" * 64)
        / ("e" * 64)
        / "manifest.json"
    )
    manifest = {
        "repo_key": "demo-repo",
        "repo_generation": 4,
        "source_manifest_digest": "d" * 64,
        "structural_input_digest": "e" * 64,
        "degraded_files": 0,
        "degraded_file_paths": [],
        "artifact_truncated_files": 0,
        "artifact_truncated_file_paths": [],
        "analysis_status_counts": {"complete": 1, "degraded": 0, "unsupported": 0},
    }
    outcome = _fork_call_outcome(
        lambda: module._publish_aggregate(tmp_path, 7, manifest_path, manifest)
    )

    assert outcome != b"blocked", f"structural aggregate publication blocked on lock {collision}"
    assert outcome == b"value-error"
    assert aggregate_path.read_bytes() == aggregate_bytes
    assert not (tmp_path / "structural-index" / "history").exists()
    if collision == "fifo":
        assert stat.S_ISFIFO(lock_path.lstat().st_mode)
    else:
        assert lock_path.is_symlink()
        assert outside_lock.read_bytes() == b"outside-lock-sentinel"


@pytest.mark.skipif(
    not hasattr(os, "fork") or not hasattr(os, "mkfifo"),
    reason="structural aggregate publication requires POSIX filesystem primitives",
)
@pytest.mark.parametrize("collision", ["manifest", "artifact"])
def test_code_index_retry_rejects_retained_v5_fifo_without_blocking(
    tmp_path: Path,
    request: pytest.FixtureRequest,
    collision: str,
) -> None:
    module = _load_command("code_index.py", f"test_sealed_code_index_retained_fifo_{collision}")
    structural_root = tmp_path / "structural-index"
    final_dir = (
        structural_root
        / "7"
        / "4"
        / "v6"
        / ("d" * 64)
        / ("e" * 64)
    )
    files_dir = final_dir / "files"
    files_dir.mkdir(parents=True)
    request.addfinalizer(lambda: _restore_tree_writable(structural_root))
    artifact_path = files_dir / "artifact.json"
    artifact_bytes = b'{"schema":"structural-index-file/v1"}\n'
    artifact_path.write_bytes(artifact_bytes)
    expected = {
        "files": {
            "legacy.c": {
                "index_path": str(artifact_path.relative_to(structural_root)),
                "index_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            }
        }
    }
    manifest_path = final_dir / "manifest.json"
    manifest_path.write_text(json.dumps(expected), encoding="utf-8")
    target = manifest_path if collision == "manifest" else artifact_path
    target.unlink()
    os.mkfifo(target)
    for regular_file in (manifest_path, artifact_path):
        if regular_file != target:
            os.chmod(regular_file, 0o444)
    os.chmod(files_dir, 0o555)
    os.chmod(final_dir, 0o555)

    aggregate_path = tmp_path / "structural-index-manifest.json"
    aggregate_bytes = (
        json.dumps(_legacy_v3_aggregate(), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    aggregate_path.write_bytes(aggregate_bytes)
    outcome = _fork_call_outcome(
        lambda: module._validate_existing_generation(final_dir, expected, structural_root)
    )

    assert outcome != b"blocked", f"retained v5 validation blocked on {collision} FIFO"
    assert outcome == b"value-error"
    assert aggregate_path.read_bytes() == aggregate_bytes
    assert stat.S_ISFIFO(target.lstat().st_mode)


@pytest.mark.parametrize("corruption", ["extra-field", "duplicate-key"])
def test_code_index_retry_rejects_retained_v5_manifest_shape_drift(
    tmp_path: Path,
    request: pytest.FixtureRequest,
    corruption: str,
) -> None:
    module = _load_command("code_index.py", f"test_sealed_code_index_v5_shape_{corruption}")
    structural_root = tmp_path / "structural-index"
    final_dir = (
        structural_root
        / "7"
        / "4"
        / "v6"
        / ("d" * 64)
        / ("e" * 64)
    )
    files_dir = final_dir / "files"
    files_dir.mkdir(parents=True)
    request.addfinalizer(lambda: _restore_tree_writable(structural_root))
    expected = {
        "schema": "structural-index/v6",
        "indexed_at": "2026-08-05T17:00:00Z",
        "files": {},
    }
    if corruption == "extra-field":
        existing = {**expected, "unexpected_untrusted_field": True}
        manifest_bytes = json.dumps(existing).encode("utf-8")
    else:
        manifest_bytes = (
            b'{"schema":"attacker-schema","schema":"structural-index/v6",'
            b'"indexed_at":"2026-08-05T16:00:00Z","files":{}}'
        )
    manifest_path = final_dir / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    os.chmod(manifest_path, 0o444)
    os.chmod(files_dir, 0o555)
    os.chmod(final_dir, 0o555)
    aggregate_path = tmp_path / "structural-index-manifest.json"
    aggregate_bytes = (
        json.dumps(_legacy_v3_aggregate(), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    aggregate_path.write_bytes(aggregate_bytes)

    with pytest.raises(ValueError, match="manifest|duplicate|conflicts"):
        module._validate_existing_generation(final_dir, expected, structural_root)

    assert aggregate_path.read_bytes() == aggregate_bytes


def test_code_index_publish_rejects_group_writable_legacy_archive_directory(
    tmp_path: Path,
) -> None:
    module = _load_command("code_index.py", "test_sealed_code_index_writable_archive_dir")
    aggregate_path = tmp_path / "structural-index-manifest.json"
    aggregate_bytes = (
        json.dumps(_legacy_v3_aggregate(), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    aggregate_path.write_bytes(aggregate_bytes)
    archive_dir = tmp_path / "structural-index" / "history" / "aggregates" / "v3"
    archive_dir.mkdir(parents=True)
    os.chmod(archive_dir, 0o777)
    manifest_path = (
        tmp_path
        / "structural-index"
        / "7"
        / "4"
        / "v6"
        / ("d" * 64)
        / ("e" * 64)
        / "manifest.json"
    )
    manifest = {
        "repo_key": "demo-repo",
        "repo_generation": 4,
        "source_manifest_digest": "d" * 64,
        "structural_input_digest": "e" * 64,
        "degraded_files": 0,
        "degraded_file_paths": [],
        "artifact_truncated_files": 0,
        "artifact_truncated_file_paths": [],
        "analysis_status_counts": {"complete": 1, "degraded": 0, "unsupported": 0},
    }

    with pytest.raises(ValueError, match="archive directory"):
        module._publish_aggregate(tmp_path, 7, manifest_path, manifest)

    assert aggregate_path.read_bytes() == aggregate_bytes
    assert not list(archive_dir.iterdir())


@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b"[]",
        b'{"schema":"structural-index-aggregate/v3"}',
    ],
)
def test_code_index_publish_fails_closed_on_unreadable_legacy_aggregate(
    tmp_path: Path, raw: bytes
) -> None:
    module = _load_command("code_index.py", "test_sealed_code_index_malformed_aggregate")
    aggregate_path = tmp_path / "structural-index-manifest.json"
    aggregate_path.write_bytes(raw)
    manifest_path = tmp_path / "structural-index" / "7" / "4" / ("d" * 64) / "manifest.json"
    manifest = {
        "repo_key": "demo-repo",
        "repo_generation": 4,
        "source_manifest_digest": "d" * 64,
    }

    with pytest.raises(ValueError, match="aggregate"):
        module._publish_aggregate(tmp_path, 7, manifest_path, manifest)

    assert aggregate_path.read_bytes() == raw
    assert not (tmp_path / "structural-index" / "history").exists()


@pytest.mark.parametrize(
    ("legacy_kind", "expected_error"),
    [
        ("aggregate", "structural index aggregate must use structural-index-aggregate/v4"),
        ("manifest", "repo 7 manifest is not structural-index/v6"),
    ],
)
def test_code_index_sync_rejects_legacy_contracts_before_backend_access(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    legacy_kind: str,
    expected_error: str,
) -> None:
    module = _load_command("code_index_sync.py", f"test_sync_legacy_{legacy_kind}")
    top_path = tmp_path / "structural-index-manifest.json"
    if legacy_kind == "aggregate":
        top = {"schema": "structural-index-aggregate/v3", "repos": {}}
    else:
        manifest_path = tmp_path / "structural-index" / "legacy-v4" / "manifest.json"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text(
            json.dumps({"schema": "structural-index/v4"}), encoding="utf-8"
        )
        top = {
            "schema": "structural-index-aggregate/v4",
            "repos": {
                "7": {
                    "manifest_path": str(manifest_path.relative_to(tmp_path)),
                }
            },
        }
    top_path.write_text(json.dumps(top), encoding="utf-8")
    client_opened = False

    class NeverClient:
        def __init__(self, *_args, **_kwargs):
            nonlocal client_opened
            client_opened = True

    monkeypatch.setattr(module, "AssessmentClient", NeverClient)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    args = SimpleNamespace(
        manifest=str(top_path),
        index_dir=str(tmp_path / "structural-index"),
        repo_id=None,
        repo_key=None,
        engagement_dir=str(tmp_path),
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(args)

    assert excinfo.value.code == 1
    assert expected_error in capsys.readouterr().err
    assert client_opened is False


def test_code_index_sync_rejects_source_path_traversal(tmp_path: Path) -> None:
    module = _load_command("code_index_sync.py", "test_sealed_code_index_sync_traversal")
    digest = "d" * 64
    raw = b"print('escaped')\n"
    source, source_manifest = _sealed_snapshot(tmp_path, {"main.py": b"print('safe')\n"})
    os.chmod(source.parent, 0o755)
    escaped = source.parent / "escaped.py"
    escaped.write_bytes(raw)
    os.chmod(escaped, 0o444)
    os.chmod(source.parent, 0o555)
    source_sha = hashlib.sha256(raw).hexdigest()
    index_root = tmp_path / "structural-index"
    index_file = index_root / "7" / "4" / digest / "files" / "escaped.json"
    index_file.parent.mkdir(parents=True)
    index_payload = {
        "file_path": "../escaped.py",
        "repo_id": 7,
        "repo_generation": 4,
        "source_manifest_digest": digest,
        "source_sha256": source_sha,
        "total_functions": 1,
        "entry_points": [],
        "security_sinks": [],
        "exports": [],
    }
    index_file.write_text(json.dumps(index_payload), encoding="utf-8")
    manifest = {
        "schema": "structural-index/v6",
        "repo_id": 7,
        "repo_key": "demo-repo",
        "repo_generation": 4,
        "source_manifest_digest": digest,
        "source_path": str(source.resolve()),
        "source_snapshot_manifest_path": str(source.parent / "manifest.json"),
        "snapshot_digest": source_manifest["snapshot_digest"],
        "_resolved_manifest_path": str(index_file.parent.parent / "manifest.json"),
        "files": {
            "../escaped.py": {
                "index_path": str(index_file.relative_to(index_root)),
                "source_sha256": source_sha,
                "index_sha256": hashlib.sha256(index_file.read_bytes()).hexdigest(),
            }
        },
        "path_to_index": {
            "../escaped.py": str(index_file.relative_to(index_root)),
        },
    }

    class FakeClient:
        def get(self, endpoint: str):
            assert endpoint == "code/files?limit=5000&offset=0&repo_id=7"
            return _file_page([
                {
                    "id": 11,
                    "repo_id": 7,
                    "file_path": "../escaped.py",
                    "file_hash": source_sha,
                }
            ])

    backend_repo = {
        "id": 7,
        "repo_key": "demo-repo",
        "repo_path": str(source.resolve()),
        "active_generation": 4,
        "source_manifest_digest": digest,
    }
    with pytest.raises(ValueError, match="unsafe source file path"):
        module._prepare_repo_payload(FakeClient(), backend_repo, manifest, index_root)


def test_code_index_sync_validates_all_files_before_bound_cas_post(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    module = _load_command("code_index_sync.py", "test_sealed_code_index_sync")
    digest = "d" * 64
    raw = b"print('sealed')\n"
    source, source_manifest = _sealed_snapshot(tmp_path, {"main.py": raw})
    request.addfinalizer(lambda: _restore_tree_writable(source.parent))
    source_sha = hashlib.sha256(raw).hexdigest()
    backend_row = {
        "id": 11,
        "repo_id": 7,
        "file_path": "main.py",
        "file_hash": source_sha,
        "language": "python",
    }
    input_digest = _structural_identity(
        source_manifest,
        [backend_row],
        source_manifest_digest=digest,
    )
    index_root = tmp_path / "structural-index"
    index_file = (
        index_root / "7" / "4" / "v6" / digest / input_digest / "files" / "main.json"
    )
    index_file.parent.mkdir(parents=True)
    index_payload = {
        "file_path": "main.py",
        "language": "python",
        "repo_id": 7,
        "repo_generation": 4,
        "source_manifest_digest": digest,
        "structural_input_digest": input_digest,
        "source_sha256": source_sha,
        "total_functions": 1,
        "total_exports": 0,
        "total_lines": 1,
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
        "structural_index_available": True,
        "analysis_status": "complete",
        "analysis_mode": "tree_sitter",
        "degradation_reason": None,
        "source_size": len(raw),
        "bytes_scanned": len(raw),
        "unavailable_dimensions": [],
        "artifact_truncated": False,
        "truncated_dimensions": [],
        "signal_counts": {
            "entry_points": 0,
            "imports": 0,
            "security_sinks": 0,
            "security_sources": 0,
        },
    }
    index_file.write_text(json.dumps(index_payload), encoding="utf-8")
    index_sha = hashlib.sha256(index_file.read_bytes()).hexdigest()
    manifest = {
        "schema": "structural-index/v6",
        "repo_id": 7,
        "repo_key": "demo-repo",
        "repo_generation": 4,
        "source_manifest_digest": digest,
        "structural_input_digest": input_digest,
        "source_path": str(source.resolve()),
        "source_snapshot_manifest_path": str(source.parent / "manifest.json"),
        "snapshot_digest": source_manifest["snapshot_digest"],
        "manifest_path": str(index_file.parent.parent / "manifest.json"),
        "files": {
            "main.py": {
                "index_path": str(index_file.relative_to(index_root)),
                "source_sha256": source_sha,
                "language": "python",
                "index_sha256": index_sha,
                "analysis_status": "complete",
                "analysis_mode": "tree_sitter",
                "artifact_truncated": False,
            }
        },
        "path_to_index": {
            "main.py": str(index_file.relative_to(index_root)),
        },
        "degraded_files": 0,
        "degraded_file_paths": [],
        "artifact_truncated_files": 0,
        "artifact_truncated_file_paths": [],
        "analysis_status_counts": {"complete": 1, "degraded": 0, "unsupported": 0},
    }
    manifest_path = index_file.parent.parent / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    top = tmp_path / "structural-index-manifest.json"
    top.write_text(
        json.dumps(
            {
                "schema": "structural-index-aggregate/v4",
                "repos": {
                    "7": {
                        "repo_id": 7,
                        "repo_generation": 4,
                        "source_manifest_digest": digest,
                        "structural_input_digest": input_digest,
                        "manifest_path": str(manifest_path.relative_to(tmp_path)),
                        "degraded_files": 0,
                        "degraded_file_paths": [],
                        "artifact_truncated_files": 0,
                        "artifact_truncated_file_paths": [],
                        "analysis_status_counts": {
                            "complete": 1,
                            "degraded": 0,
                            "unsupported": 0,
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    posted: list[tuple[str, dict]] = []
    include_extra_backend_file = False

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def get(self, endpoint: str):
            if endpoint == "code/repos":
                return [
                    {
                        "id": 7,
                        "repo_key": "demo-repo",
                        "repo_path": str(source.resolve()),
                        "active_generation": 4,
                        "source_manifest_digest": digest,
                    }
                ]
            if endpoint == "code/files?limit=5000&offset=0&repo_id=7":
                rows = [
                    dict(backend_row)
                ]
                if include_extra_backend_file:
                    rows.append(
                        {
                            "id": 12,
                            "repo_id": 7,
                            "file_path": "unbound.py",
                            "file_hash": "a" * 64,
                            "language": "python",
                        }
                    )
                return _file_page(rows)
            raise AssertionError(endpoint)

        def post(self, endpoint: str, payload: dict, **_kwargs):
            posted.append((endpoint, payload))
            return {
                key: payload[key]
                for key in (
                    "repo_id",
                    "repo_generation",
                    "source_manifest_digest",
                    "structural_input_digest",
                    "structural_index_schema",
                )
            } | {"updated": len(payload["updates"])}

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    args = SimpleNamespace(
        manifest=str(top),
        index_dir=str(index_root),
        repo_id=7,
        repo_key=None,
        engagement_dir=str(tmp_path),
    )
    module.run(args)

    assert posted == [
        (
            "code/files/bulk-structural-metadata",
            {
                "repo_id": 7,
                "repo_generation": 4,
                "source_manifest_digest": digest,
                "structural_index_schema": "structural-index/v6",
                "structural_input_digest": input_digest,
                "structural_index_manifest_path": str(manifest_path.resolve()),
                "degraded_files": 0,
                "degraded_file_paths": [],
                "artifact_truncated_files": 0,
                "artifact_truncated_file_paths": [],
                "analysis_status_counts": {
                    "complete": 1,
                    "degraded": 0,
                    "unsupported": 0,
                },
                "updates": [
                    {
                        "file_id": 11,
                        "source_sha256": hashlib.sha256(raw).hexdigest(),
                        "indexed_language": "python",
                        "total_functions": 1,
                        "total_entry_points": 0,
                        "total_sinks": 0,
                        "total_exports": 0,
                        "callables": [
                            {
                                "name": "main",
                                "qualified_name": "main",
                                "start_line": 1,
                                "end_line": 1,
                            }
                        ],
                        "structural_analysis_status": "complete",
                        "structural_analysis_mode": "tree_sitter",
                        "structural_degradation_reason": None,
                        "structural_source_size": len(raw),
                        "structural_bytes_scanned": len(raw),
                        "structural_unavailable_dimensions": [],
                        "structural_artifact_truncated": False,
                        "structural_truncated_dimensions": [],
                        "structural_signal_counts": {
                            "entry_points": 0,
                            "imports": 0,
                            "security_sinks": 0,
                            "security_sources": 0,
                        },
                    }
                ],
            },
        )
    ]

    tampered_manifest = {
        **manifest,
        "_resolved_manifest_path": str(manifest_path),
        "path_to_index": {"main.py": "7/4/wrong.json"},
    }
    backend_repo = {
        "id": 7,
        "repo_key": "demo-repo",
        "repo_path": str(source.resolve()),
        "active_generation": 4,
        "source_manifest_digest": digest,
    }
    with pytest.raises(ValueError, match="path_to_index"):
        module._prepare_repo_payload(FakeClient(), backend_repo, tampered_manifest, index_root)

    include_extra_backend_file = True
    posted.clear()
    with pytest.raises(SystemExit) as excinfo:
        module.run(args)
    assert excinfo.value.code == 1
    assert posted == []
    include_extra_backend_file = False

    outside = tmp_path / "outside-main.py"
    os.chmod(source, 0o755)
    (source / "main.py").rename(outside)
    (source / "main.py").symlink_to(outside)
    os.chmod(source, 0o555)
    posted.clear()
    with pytest.raises(SystemExit) as excinfo:
        module.run(args)
    assert excinfo.value.code == 1
    assert posted == []


def test_code_index_sync_ancestor_swap_fails_before_any_post(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from assess.lib.code_snapshot import RootedSourceTree

    module = _load_command("code_index_sync.py", "test_sync_ancestor_swap")
    digest = "d" * 64
    raw = b"print('sealed')\n"
    source, source_manifest = _sealed_snapshot(tmp_path, {"nested/main.py": raw})
    source_sha = hashlib.sha256(raw).hexdigest()
    backend_row = {
        "id": 11,
        "repo_id": 7,
        "file_path": "nested/main.py",
        "file_hash": source_sha,
        "language": "python",
    }
    input_digest = _structural_identity(
        source_manifest,
        [backend_row],
        source_manifest_digest=digest,
    )
    index_root = tmp_path / "structural-index"
    artifact_path = (
        index_root / "7" / "4" / "v6" / digest / input_digest / "files" / "main.json"
    )
    artifact_path.parent.mkdir(parents=True)
    artifact = {
        "file_path": "nested/main.py",
        "language": "python",
        "repo_id": 7,
        "repo_generation": 4,
        "source_manifest_digest": digest,
        "structural_input_digest": input_digest,
        "source_sha256": source_sha,
        "total_functions": 0,
        "total_exports": 0,
        "total_lines": 1,
        "functions": [],
        "entry_points": [],
        "security_sinks": [],
        "security_sources": [],
        "call_sites": [],
        "imports": [],
        "import_targets": [],
        "exports": [],
        "classes": [],
        "structural_index_available": True,
        "analysis_status": "complete",
        "analysis_mode": "tree_sitter",
        "degradation_reason": None,
        "source_size": len(raw),
        "bytes_scanned": len(raw),
        "unavailable_dimensions": [],
        "artifact_truncated": False,
        "truncated_dimensions": [],
        "signal_counts": {
            "entry_points": 0,
            "imports": 0,
            "security_sinks": 0,
            "security_sources": 0,
        },
    }
    artifact_bytes = json.dumps(artifact).encode()
    artifact_path.write_bytes(artifact_bytes)
    manifest_path = artifact_path.parent.parent / "manifest.json"
    index_rel = str(artifact_path.relative_to(index_root))
    manifest = {
        "schema": "structural-index/v6",
        "repo_id": 7,
        "repo_key": "demo-repo",
        "repo_generation": 4,
        "source_manifest_digest": digest,
        "structural_input_digest": input_digest,
        "source_path": str(source.resolve()),
        "source_snapshot_manifest_path": str(source.parent / "manifest.json"),
        "snapshot_digest": source_manifest["snapshot_digest"],
        "manifest_path": str(manifest_path),
        "files": {
            "nested/main.py": {
                "index_path": index_rel,
                "source_sha256": source_sha,
                "language": "python",
                "index_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                "analysis_status": "complete",
                "analysis_mode": "tree_sitter",
                "artifact_truncated": False,
            }
        },
        "path_to_index": {"nested/main.py": index_rel},
        "degraded_files": 0,
        "degraded_file_paths": [],
        "artifact_truncated_files": 0,
        "artifact_truncated_file_paths": [],
        "analysis_status_counts": {"complete": 1, "degraded": 0, "unsupported": 0},
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    top = tmp_path / "structural-index-manifest.json"
    top.write_text(
        json.dumps(
            {
                "schema": "structural-index-aggregate/v4",
                "repos": {
                    "7": {
                        "repo_id": 7,
                        "repo_generation": 4,
                        "source_manifest_digest": digest,
                        "structural_input_digest": input_digest,
                        "manifest_path": str(manifest_path.relative_to(tmp_path)),
                        "degraded_files": 0,
                        "degraded_file_paths": [],
                        "artifact_truncated_files": 0,
                        "artifact_truncated_file_paths": [],
                        "analysis_status_counts": {
                            "complete": 1,
                            "degraded": 0,
                            "unsupported": 0,
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    posted: list[tuple[str, dict]] = []

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def get(self, endpoint: str):
            if endpoint == "code/repos":
                return [
                    {
                        "id": 7,
                        "repo_key": "demo-repo",
                        "repo_path": str(source.resolve()),
                        "active_generation": 4,
                        "source_manifest_digest": digest,
                    }
                ]
            if endpoint == "code/files?limit=5000&offset=0&repo_id=7":
                return _file_page([dict(backend_row)])
            raise AssertionError(endpoint)

        def post(self, endpoint: str, payload: dict):
            posted.append((endpoint, payload))
            return {
                key: payload[key]
                for key in (
                    "repo_id",
                    "repo_generation",
                    "source_manifest_digest",
                    "structural_input_digest",
                    "structural_index_schema",
                )
            } | {"updated": len(payload["updates"])}

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "validate_snapshot", lambda *_args, **_kwargs: source_manifest)
    original_capture = RootedSourceTree.capture
    detached = tmp_path / "detached-sync-nested"
    outside = tmp_path / "outside-sync"
    outside.mkdir()
    (outside / "main.py").write_bytes(raw)
    swapped = False

    def capture_after_swap(self, rel_path, **kwargs):
        nonlocal swapped
        if not swapped:
            swapped = True
            os.chmod(source, 0o755)
            (source / "nested").rename(detached)
            (source / "nested").symlink_to(outside, target_is_directory=True)
            os.chmod(source, 0o555)
        return original_capture(self, rel_path, **kwargs)

    monkeypatch.setattr(RootedSourceTree, "capture", capture_after_swap)
    try:
        with pytest.raises(SystemExit) as excinfo:
            module.run(
                SimpleNamespace(
                    manifest=str(top),
                    index_dir=str(index_root),
                    repo_id=7,
                    repo_key=None,
                    engagement_dir=str(tmp_path),
                )
            )
        assert excinfo.value.code == 1
        assert posted == []
    finally:
        if (source / "nested").is_symlink():
            os.chmod(source, 0o755)
            (source / "nested").unlink()
            detached.rename(source / "nested")
            os.chmod(source, 0o555)


def test_code_index_sync_uses_observed_signal_counts_when_artifact_lists_are_capped(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    module = _load_command("code_index_sync.py", "test_sync_observed_signal_counts")
    digest = "d" * 64
    raw = b"print('sealed')\n"
    source, source_manifest = _sealed_snapshot(tmp_path, {"main.py": raw})
    request.addfinalizer(lambda: _restore_tree_writable(source.parent))
    source_sha = hashlib.sha256(raw).hexdigest()
    backend_row = {
        "id": 11,
        "repo_id": 7,
        "file_path": "main.py",
        "file_hash": source_sha,
        "language": "python",
    }
    input_digest = _structural_identity(
        source_manifest,
        [backend_row],
        source_manifest_digest=digest,
    )
    index_root = tmp_path / "structural-index"
    artifact_path = (
        index_root / "7" / "4" / "v6" / digest / input_digest / "files" / "main.json"
    )
    artifact_path.parent.mkdir(parents=True)
    artifact = {
        "file_path": "main.py",
        "language": "python",
        "repo_id": 7,
        "repo_generation": 4,
        "source_manifest_digest": digest,
        "structural_input_digest": input_digest,
        "source_sha256": source_sha,
        "total_functions": 1,
        "total_lines": 1,
        "functions": [],
        "entry_points": [{"name": "a"}, {"name": "b"}],
        "security_sinks": [{"kind": "eval_exec"}, {"kind": "process_exec"}],
        "security_sources": [],
        "call_sites": [],
        "imports": [],
        "import_targets": [],
        "total_exports": 5,
        "exports": [{"name": "one"}, {"name": "two"}],
        "classes": [],
        "structural_index_available": True,
        "analysis_status": "degraded",
        "analysis_mode": "tree_sitter",
        "degradation_reason": "artifact_signal_limit",
        "source_size": len(raw),
        "bytes_scanned": len(raw),
        "unavailable_dimensions": [],
        "artifact_truncated": True,
        "truncated_dimensions": [
            "entry_points",
            "exports",
            "functions",
            "security_sinks",
        ],
        "signal_counts": {
            "entry_points": 5,
            "imports": 0,
            "security_sinks": 4,
            "security_sources": 0,
        },
    }
    artifact_bytes = json.dumps(artifact).encode()
    artifact_path.write_bytes(artifact_bytes)
    index_rel = str(artifact_path.relative_to(index_root))
    manifest = {
        "schema": "structural-index/v6",
        "repo_id": 7,
        "repo_key": "demo-repo",
        "repo_generation": 4,
        "source_manifest_digest": digest,
        "structural_input_digest": input_digest,
        "source_path": str(source.resolve()),
        "source_snapshot_manifest_path": str(source.parent / "manifest.json"),
        "snapshot_digest": source_manifest["snapshot_digest"],
        "_resolved_manifest_path": str(artifact_path.parent.parent / "manifest.json"),
        "manifest_path": str(artifact_path.parent.parent / "manifest.json"),
        "files": {
            "main.py": {
                "index_path": index_rel,
                "source_sha256": source_sha,
                "language": "python",
                "index_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                "analysis_status": "degraded",
                "analysis_mode": "tree_sitter",
                "artifact_truncated": True,
            }
        },
        "path_to_index": {"main.py": index_rel},
        "degraded_files": 1,
        "degraded_file_paths": ["main.py"],
        "artifact_truncated_files": 1,
        "artifact_truncated_file_paths": ["main.py"],
        "analysis_status_counts": {"complete": 0, "degraded": 1, "unsupported": 0},
    }

    class FakeClient:
        def get(self, endpoint: str):
            assert endpoint == "code/files?limit=5000&offset=0&repo_id=7"
            return _file_page([dict(backend_row)])

    payload = module._prepare_repo_payload(
        FakeClient(),
        {
            "id": 7,
            "repo_key": "demo-repo",
            "repo_path": str(source.resolve()),
            "active_generation": 4,
            "source_manifest_digest": digest,
        },
        manifest,
        index_root,
    )

    assert payload["updates"][0]["total_entry_points"] == 5
    assert payload["updates"][0]["total_sinks"] == 4
    assert payload["updates"][0]["total_exports"] == 5
    assert len(artifact["entry_points"]) == 2
    assert len(artifact["security_sinks"]) == 2


def _structural_metadata_artifact() -> dict[str, object]:
    return {
        "total_functions": 0,
        "total_exports": 0,
        "functions": [],
        "entry_points": [],
        "security_sinks": [],
        "security_sources": [],
        "call_sites": [],
        "imports": [],
        "import_targets": [],
        "exports": [],
        "classes": [],
        "structural_index_available": True,
        "analysis_status": "complete",
        "analysis_mode": "tree_sitter",
        "degradation_reason": None,
        "source_size": 12,
        "bytes_scanned": 12,
        "unavailable_dimensions": [],
        "artifact_truncated": False,
        "truncated_dimensions": [],
        "signal_counts": {
            "entry_points": 0,
            "imports": 0,
            "security_sinks": 0,
            "security_sources": 0,
        },
    }


def test_code_index_sync_rejects_complete_callable_registry_shortfall() -> None:
    module = _load_command("code_index_sync.py", "test_sync_callable_shortfall")
    artifact = _structural_metadata_artifact()
    artifact["total_functions"] = 1

    with pytest.raises(ValueError, match="function total must match retained callables"):
        module._validated_structural_metadata(
            artifact,
            rel_path="main.py",
            source_size=12,
        )


@pytest.mark.parametrize(
    ("dimension", "record"),
    [
        ("imports", "os"),
        ("security_sources", {"kind": "request_input"}),
    ],
)
def test_code_index_sync_rejects_signal_counts_below_every_retained_dimension(
    dimension: str,
    record: object,
) -> None:
    module = _load_command("code_index_sync.py", f"test_sync_undercount_{dimension}")
    artifact = _structural_metadata_artifact()
    artifact[dimension] = [record]

    with pytest.raises(ValueError, match="undercount retained records"):
        module._validated_structural_metadata(
            artifact,
            rel_path="main.py",
            source_size=12,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("total_functions", 1),
        ("functions", [{"name": "hidden"}]),
        ("classes", [{"name": "Hidden"}]),
        ("exports", ["hidden"]),
        ("imports", ["os"]),
        (
            "signal_counts",
            {
                "entry_points": 0,
                "imports": 0,
                "security_sinks": 0,
                "security_sources": 1,
            },
        ),
    ],
)
def test_code_index_sync_rejects_unsupported_artifacts_with_any_signal(
    field: str,
    value: object,
) -> None:
    module = _load_command("code_index_sync.py", f"test_sync_unsupported_{field}")
    artifact = _structural_metadata_artifact()
    artifact.update(
        {
            "structural_index_available": False,
            "analysis_status": "unsupported",
            "analysis_mode": "none",
            "degradation_reason": "unsupported_language",
            "unavailable_dimensions": ["functions"],
        }
    )
    artifact[field] = value

    with pytest.raises(ValueError, match="unsupported structural analysis contains signals"):
        module._validated_structural_metadata(
            artifact,
            rel_path="notes.md",
            source_size=12,
        )


@pytest.mark.parametrize(
    ("dimension", "field", "value"),
    [
        ("functions", "total_functions", 1),
        ("functions", "functions", [{"name": "hidden"}]),
        ("exports", "exports", ["public_api"]),
        ("entry_points", "signal_counts", {"entry_points": 1}),
        ("imports", "signal_counts", {"imports": 1}),
        ("security_sinks", "signal_counts", {"security_sinks": 1}),
        ("security_sources", "signal_counts", {"security_sources": 1}),
        ("call_sites", "call_sites", [{"name": "hidden"}]),
        ("classes", "classes", [{"name": "Hidden"}]),
    ],
)
def test_code_index_sync_rejects_signals_for_unavailable_dimensions(
    dimension: str,
    field: str,
    value: object,
) -> None:
    module = _load_command("code_index_sync.py", f"test_sync_unavailable_{dimension}")
    artifact = _structural_metadata_artifact()
    artifact.update(
        {
            "analysis_status": "degraded",
            "analysis_mode": "streaming_security_fallback",
            "degradation_reason": "tree_sitter_resource_limit",
            "structural_index_available": False,
            "unavailable_dimensions": sorted(
                {"call_sites", "classes", "dataflow", "exports", "functions", dimension}
            ),
        }
    )
    if field == "signal_counts":
        artifact["signal_counts"].update(value)
    else:
        artifact[field] = value
        if field == "exports":
            artifact["total_exports"] = len(value)

    with pytest.raises(ValueError, match="unavailable structural dimension contains signals"):
        module._validated_structural_metadata(
            artifact,
            rel_path="large.py",
            source_size=12,
        )


def test_code_index_producer_rejects_streaming_fallback_without_a_reason() -> None:
    module = _load_command("code_index.py", "test_build_missing_fallback_reason")
    artifact = _structural_metadata_artifact()
    artifact.update(
        {
            "analysis_status": "degraded",
            "analysis_mode": "streaming_security_fallback",
            "degradation_reason": None,
            "structural_index_available": False,
            "unavailable_dimensions": [
                "call_sites",
                "classes",
                "dataflow",
                "exports",
                "functions",
            ],
        }
    )

    with pytest.raises(ValueError, match="streaming fallback debt is incomplete"):
        module._validate_analysis_artifact(
            artifact,
            rel_path="large.py",
            source_size=12,
        )


@pytest.mark.parametrize(
    ("filename", "validator_name"),
    [
        ("code_index.py", "_validate_analysis_artifact"),
        ("code_index_sync.py", "_validated_structural_metadata"),
    ],
)
@pytest.mark.parametrize(
    "missing_dimension",
    ["call_sites", "classes", "dataflow", "exports", "functions"],
)
def test_streaming_fallback_requires_every_baseline_unavailable_dimension(
    filename: str,
    validator_name: str,
    missing_dimension: str,
) -> None:
    module = _load_command(filename, f"test_fallback_baseline_{filename}_{missing_dimension}")
    artifact = _structural_metadata_artifact()
    baseline = {"call_sites", "classes", "dataflow", "exports", "functions"}
    artifact.update(
        {
            "analysis_status": "degraded",
            "analysis_mode": "streaming_security_fallback",
            "degradation_reason": "tree_sitter_resource_limit",
            "structural_index_available": False,
            "unavailable_dimensions": sorted(baseline - {missing_dimension}),
        }
    )

    with pytest.raises(ValueError, match="streaming fallback debt is incomplete"):
        getattr(module, validator_name)(
            artifact,
            rel_path="large.py",
            source_size=12,
        )


def test_code_record_threat_model_requires_and_posts_snapshot_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_record_threat_model.py", "test_bound_threat_model")
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    module.register(subparsers)
    with pytest.raises(SystemExit):
        parser.parse_args(["threat-model", "7", str(tmp_path / "threat.json")])

    threat = tmp_path / "threat.json"
    threat.write_text('{"targets": ["parser"]}', encoding="utf-8")
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def post(self, endpoint: str, payload: dict):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {
                "id": 7,
                "active_generation": 4,
                "threat_model_generation": 4,
                "source_manifest_digest": "d" * 64,
                "threat_model": {"targets": ["parser"]},
            }

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )
    module.run(
        SimpleNamespace(
            repo_id="7",
            repo_generation=4,
            source_manifest_digest="d" * 64,
            threat_model_json=str(threat),
            engagement_dir=str(tmp_path),
        )
    )
    assert captured == {
        "endpoint": "code/threat-model",
        "payload": {
            "repo_id": 7,
            "repo_generation": 4,
            "source_manifest_digest": "d" * 64,
            "threat_model": {"targets": ["parser"]},
        },
    }


def test_code_record_threat_model_rejects_uppercase_digest_before_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_command("code_record_threat_model.py", "test_lowercase_threat_model_digest")
    threat = tmp_path / "threat.json"
    threat.write_text('{"targets": ["parser"]}', encoding="utf-8")
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: pytest.fail("backend config loaded for an invalid digest"),
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                repo_id="7",
                repo_generation=4,
                source_manifest_digest="D" * 64,
                threat_model_json=str(threat),
                engagement_dir=str(tmp_path),
            )
        )

    assert excinfo.value.code == 1


def test_large_capture_uses_bounded_memory_and_snapshot_consumes_disk_spool(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import assess.lib.code_snapshot as module

    origin = tmp_path / "origin.bin"
    with origin.open("wb") as handle:
        handle.seek(32 * 1024 * 1024 - 1)
        handle.write(b"\n")

    real_temporary_file = module.tempfile.TemporaryFile
    spools: list[object] = []

    def tracked_temporary_file(*args, **kwargs):
        handle = real_temporary_file(*args, **kwargs)
        spools.append(handle)
        return handle

    monkeypatch.setattr(module.tempfile, "TemporaryFile", tracked_temporary_file)
    tracemalloc.start()
    captured = module.capture_regular_file(origin)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert captured.size == 32 * 1024 * 1024
    assert captured.loc == 1
    assert peak < 8 * 1024 * 1024
    assert len(spools) == 1
    assert spools[0].closed is False

    original_sha = captured.sha256
    origin.write_bytes(b"attacker replacement\n")
    builder = module.SnapshotBuilder(tmp_path / "snapshots", "demo")
    builder.add("origin.bin", captured, language="")
    assert spools[0].closed is True
    sealed = builder.finish(
        repo_key="demo",
        repo_name="demo",
        source_origin_path=str(tmp_path),
        git={"head": "", "branch": "", "dirty": None},
    )
    assert module.capture_regular_file(
        sealed.source_path / "origin.bin", retain_spool=False
    ).sha256 == original_sha


def test_snapshot_builder_closes_capture_spool_when_copy_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import assess.lib.code_snapshot as module

    origin = tmp_path / "main.py"
    origin.write_text("print('safe')\n", encoding="utf-8")
    captured = module.capture_regular_file(origin)
    spool = captured.spool
    builder = module.SnapshotBuilder(tmp_path / "snapshots", "demo")

    def fail_copy(_fd: int) -> None:
        raise OSError("injected copy failure")

    monkeypatch.setattr(captured, "copy_to_fd", fail_copy)
    with pytest.raises(OSError, match="injected copy failure"):
        builder.add("main.py", captured, language="python")

    assert spool.closed is True
    builder.abort()


def test_snapshot_builder_closes_capture_spool_when_path_is_rejected(
    tmp_path: Path,
) -> None:
    import assess.lib.code_snapshot as module

    origin = tmp_path / "main.py"
    origin.write_text("print('safe')\n", encoding="utf-8")
    captured = module.capture_regular_file(origin)
    spool = captured.spool
    builder = module.SnapshotBuilder(tmp_path / "snapshots", "demo")

    with pytest.raises(ValueError, match="unsafe snapshot path"):
        builder.add("../escape.py", captured, language="python")

    assert spool.closed is True
    builder.abort()


def test_streamed_capture_preserves_splitlines_and_header_across_chunk_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import assess.lib.code_snapshot as module

    raw = b"alpha\r\nbeta\rgamma\n\nlast"
    origin = tmp_path / "mixed-newlines.txt"
    origin.write_bytes(raw)
    monkeypatch.setattr(module, "_READ_CHUNK_SIZE", 3)

    captured = module.capture_regular_file(origin)
    try:
        assert captured.loc == len(raw.splitlines())
        assert captured.header == raw.decode("utf-8")
        assert captured.read_bounded(1024) == raw
    finally:
        captured.close()


@pytest.mark.parametrize(
    ("bom", "encoding"),
    [(b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")],
)
def test_streamed_capture_recognizes_utf16_header_and_line_count(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    bom: bytes,
    encoding: str,
) -> None:
    import assess.lib.code_snapshot as module

    text = "Write-Output 'one'\r\nWrite-Output 'two'\nlast"
    origin = tmp_path / "Inspect.ps1"
    origin.write_bytes(bom + text.encode(encoding))
    monkeypatch.setattr(module, "_READ_CHUNK_SIZE", 3)

    captured = module.capture_regular_file(origin)
    try:
        assert captured.header == text
        assert captured.loc == 3
    finally:
        captured.close()


def test_exclusion_hash_accounting_streams_sparse_files_without_materializing_them(
    tmp_path: Path,
) -> None:
    module = _load_command("code_ingest.py", "test_streamed_exclusion_accounting")
    source = tmp_path / "source"
    vendor = source / "vendor"
    vendor.mkdir(parents=True)
    huge = vendor / "generated.bin"
    with huge.open("wb") as handle:
        handle.seek(32 * 1024 * 1024 - 1)
        handle.write(b"x")
    args = SimpleNamespace(
        include_minified=False,
        include_skipped=False,
        include_path=[],
        max_included_skipped_bytes=2_000_000,
    )

    tracemalloc.start()
    with module.RootedSourceTree(source) as tree:
        records = module._collect_excluded_records(tree, args, tmp_path / "snapshots")
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    generated = next(item for item in records if item["path"] == "vendor/generated.bin")
    assert generated["size"] == 32 * 1024 * 1024
    assert len(str(generated["sha256"])) == 64
    assert peak < 8 * 1024 * 1024


def test_snapshot_validation_hashes_sparse_source_without_materializing_it(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    from assess.lib.code_snapshot import validate_snapshot

    raw_path = tmp_path / "raw.bin"
    with raw_path.open("wb") as handle:
        handle.seek(32 * 1024 * 1024 - 1)
        handle.write(b"\n")
    source, manifest = _sealed_snapshot(tmp_path, {"large.bin": raw_path.read_bytes()})
    request.addfinalizer(lambda: _restore_tree_writable(source.parent))

    tracemalloc.start()
    validated = validate_snapshot(source.parent, expected_digest=manifest["snapshot_digest"])
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert validated["snapshot_digest"] == manifest["snapshot_digest"]
    assert peak < 8 * 1024 * 1024


def test_code_index_large_file_fallback_scans_every_byte_and_surfaces_debt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_command("code_index.py", "test_streaming_code_index_fallback")
    server_digest = "d" * 64
    prefix = b" " * (64 * 1024 - 3)
    raw = b"".join(
        (
            prefix,
            b"eval(request.args['command'])\r\n",
            b"requests.get(request.args['url'])\n",
            b"@app.get('/admin')\n",
            b"import subprocess\n",
        )
    )
    source, _source_manifest = _sealed_snapshot(tmp_path, {"main.py": raw})
    output = tmp_path / "analysis-state"

    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def get(self, endpoint: str):
            if endpoint == "code/repos/7":
                return {
                    "id": 7,
                    "repo_key": "demo-repo",
                    "repo_path": str(source.resolve()),
                    "active_generation": 4,
                    "source_manifest_digest": server_digest,
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

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )
    monkeypatch.setitem(sys.modules, "tree_sitter", SimpleNamespace())

    def should_not_materialize(*_args, **_kwargs):
        raise AssertionError("oversized input reached Tree-sitter")

    monkeypatch.setattr(module, "index_file", should_not_materialize)
    module.run(
        SimpleNamespace(
            repo_path=str(source),
            repo_id=7,
            repo_key=None,
            repo_name=None,
            output_dir=str(output),
            file_list=None,
            max_tree_sitter_bytes=32,
            engagement_dir=str(tmp_path),
        )
    )

    manifest_path = next((output / "structural-index").rglob("manifest.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact_path = output / "structural-index" / manifest["path_to_index"]["main.py"]
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert artifact["structural_index_available"] is False
    assert artifact["analysis_status"] == "degraded"
    assert artifact["analysis_mode"] == "streaming_security_fallback"
    assert artifact["degradation_reason"] == "tree_sitter_resource_limit"
    assert artifact["source_size"] == len(raw)
    assert artifact["bytes_scanned"] == len(raw)
    assert artifact["unavailable_dimensions"] == [
        "call_sites",
        "classes",
        "dataflow",
        "exports",
        "functions",
    ]
    assert any(item["kind"] == "eval_exec" and item["line"] == 1 for item in artifact["security_sinks"])
    assert any(item["kind"] == "url_fetch" and item["line"] == 2 for item in artifact["security_sinks"])
    assert any(item["line"] == 1 for item in artifact["security_sources"])
    assert any(item["line"] == 3 for item in artifact["entry_points"])
    assert any(item["line"] == 4 for item in artifact["import_targets"])
    assert artifact["signal_counts"]["security_sinks"] >= 2
    assert manifest["degraded_files"] == 1
    assert manifest["degraded_file_paths"] == ["main.py"]
    aggregate = json.loads(
        (output / "structural-index-manifest.json").read_text(encoding="utf-8")
    )
    assert aggregate["repos"]["7"]["degraded_files"] == 1
    assert aggregate["repos"]["7"]["degraded_file_paths"] == ["main.py"]


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        ("runtime", "tree_sitter_unavailable"),
        ("grammar", "tree_sitter_grammar_unavailable"),
        ("parse", "tree_sitter_parse_error"),
    ],
)
def test_tree_sitter_failure_paths_emit_streaming_signal_debt(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    reason: str,
) -> None:
    from assess.lib import treesitter_index as module

    monkeypatch.setattr(module, "_TS_AVAILABLE", failure != "runtime")
    if failure == "grammar":
        monkeypatch.setattr(module, "_get_parser", lambda _language: None)
    elif failure == "parse":
        class BrokenParser:
            def parse(self, _source):
                raise RuntimeError("parser exploded")

        monkeypatch.setattr(module, "_get_parser", lambda _language: BrokenParser())

    indexed = module.index_file(
        "main.py",
        "python",
        source=b"value = request.args['cmd']\neval(value)\n",
    )

    assert indexed["structural_index_available"] is False
    assert indexed["analysis_status"] == "degraded"
    assert indexed["analysis_mode"] == "streaming_security_fallback"
    assert indexed["degradation_reason"] == reason
    assert indexed["bytes_scanned"] == len(b"value = request.args['cmd']\neval(value)\n")
    assert indexed["security_sources"][0]["line"] == 1
    assert indexed["security_sinks"][0]["line"] == 2


def test_tree_sitter_error_nodes_never_advertise_structural_completeness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from assess.lib import treesitter_index as module

    class ErrorTreeParser:
        def parse(self, _source):
            return SimpleNamespace(root_node=SimpleNamespace(has_error=True))

    monkeypatch.setattr(module, "_TS_AVAILABLE", True)
    monkeypatch.setattr(module, "_get_parser", lambda _language: ErrorTreeParser())
    monkeypatch.setattr(module, "_extract_functions_ts", lambda *_args: [])
    monkeypatch.setattr(module, "_extract_classes_ts", lambda *_args: [])
    monkeypatch.setattr(module, "_extract_imports_ts", lambda *_args: [])

    source = b"const broken = (value) => { eval(value);\n"
    indexed = module.index_file("bundle.js", "javascript", source=source)

    assert indexed["structural_index_available"] is False
    assert indexed["analysis_status"] == "degraded"
    assert indexed["analysis_mode"] == "streaming_security_fallback"
    assert indexed["degradation_reason"] == "tree_sitter_syntax_error"
    assert indexed["bytes_scanned"] == len(source)
    assert indexed["security_sinks"]


def test_javascript_complete_index_never_augments_ast_with_line_regex_callables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from assess.lib import treesitter_index as module

    class Parser:
        def parse(self, _source):
            return SimpleNamespace(
                root_node=SimpleNamespace(has_error=False, named_children=[])
            )

    monkeypatch.setattr(module, "_TS_AVAILABLE", True)
    monkeypatch.setattr(module, "_get_parser", lambda _language: Parser())
    monkeypatch.setattr(module, "_extract_functions_ts", lambda *_args: [])
    monkeypatch.setattr(module, "_extract_classes_ts", lambda *_args: [])
    monkeypatch.setattr(module, "_extract_imports_ts", lambda *_args: [])
    assert not hasattr(module, "_detect_arrow_functions")
    monkeypatch.setattr(module, "_detect_entry_points", lambda *_args: [])
    monkeypatch.setattr(module, "_detect_top_level_entry_points", lambda *_args: [])
    monkeypatch.setattr(module, "_detect_sinks", lambda *_args: [])
    monkeypatch.setattr(module, "_detect_call_sites", lambda *_args: [])
    monkeypatch.setattr(module, "_detect_exports", lambda *_args: [])

    indexed = module.index_file(
        "bundle.js",
        "javascript",
        source=b"const parsedByAst = value => value;\n",
    )

    # No callable means no span was ever handed to the sink reader, so the file
    # declares that debt instead of claiming a clean read it never made.
    assert indexed["analysis_status"] == "degraded"
    assert indexed["functions"] == []


def test_javascript_index_extracts_every_common_assigned_callable_with_exact_spans() -> None:
    from assess.lib.treesitter_index import index_file

    source = (
        b"const first=(x)=>{return eval(x)}; const second = y => fetch(y);\n"
        b"Portal.prototype.open = function(url){ return fetch(url); };\n"
        b'Object.defineProperty(Portal.prototype, "render", '
        b"{value: function(html){ node.innerHTML=html; }});\n"
        b"items.map(x => eval(x));\n"
    )

    indexed = index_file("bundle.js", "javascript", source=source)

    functions = {item["qualified_name"]: item for item in indexed["functions"]}
    assert {"first", "second", "Portal.open", "Portal.render"} <= set(functions)
    assert any(name.startswith("<anonymous@4:") for name in functions)
    for function in functions.values():
        assert function["source_span"]["end_byte"] > function["source_span"]["start_byte"]
        assert function["body_span"]["end_byte"] > function["body_span"]["start_byte"]


def test_javascript_sink_attribution_uses_callable_body_span_on_minified_lines() -> None:
    from assess.lib.treesitter_index import index_file

    indexed = index_file(
        "bundle.js",
        "javascript",
        source=b"const evaluate=x=>eval(x); const retrieve=url=>fetch(url);\n",
    )

    sinks = {(item["kind"], item["function"]) for item in indexed["security_sinks"]}
    assert sinks == {("eval_exec", "evaluate"), ("url_fetch", "retrieve")}
    assert indexed["signal_counts"]["security_sinks"] == 2


def test_lightweight_extractor_failure_emits_streaming_signal_debt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from assess.lib import treesitter_index as module

    monkeypatch.setattr(
        module,
        "_index_lightweight",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("extractor exploded")),
    )
    raw = b"RUN curl https://example.test/install.sh | sh\n"
    indexed = module.index_file("Dockerfile", "dockerfile", source=raw)

    assert indexed["structural_index_available"] is False
    assert indexed["analysis_status"] == "degraded"
    assert indexed["analysis_mode"] == "streaming_security_fallback"
    assert indexed["degradation_reason"] == "lightweight_extractor_error"
    assert indexed["bytes_scanned"] == len(raw)
    assert indexed["security_sinks"]


def test_streaming_fallback_keeps_c_preprocessor_imports() -> None:
    from assess.lib.treesitter_index import streaming_security_fallback

    indexed = streaming_security_fallback(
        "main.c",
        "c",
        [b"#include <stdio.h>\r\nint main(void) { return 0; }\n"],
        degradation_reason="tree_sitter_resource_limit",
    )

    assert indexed["import_targets"] == [
        {
            "raw": "#include <stdio.h>",
            "resolved": "",
            "line": 1,
            "detection": "heuristic_streaming",
        }
    ]


def test_streaming_fallback_scans_c_dereference_lines() -> None:
    from assess.lib.treesitter_index import streaming_security_fallback

    indexed = streaming_security_fallback(
        "main.c",
        "c",
        [b"*ptr = getenv(\"COMMAND\"); system(*ptr);\n"],
        degradation_reason="tree_sitter_resource_limit",
    )

    assert any(item["line"] == 1 for item in indexed["security_sources"])
    assert any(
        item["kind"] == "process_exec" and item["line"] == 1
        for item in indexed["security_sinks"]
    )


def test_streaming_fallback_caps_retained_records_but_keeps_full_counts() -> None:
    from assess.lib.treesitter_index import StreamingSecurityScanner

    scanner = StreamingSecurityScanner("main.py", "python", signal_limit=2)
    scanner.feed(b"eval(a)\neval(b)\neval(c)\neval(d)\n")
    indexed = scanner.finish(degradation_reason="tree_sitter_resource_limit")

    assert len(indexed["security_sinks"]) == 2
    assert indexed["signal_counts"]["security_sinks"] == 4
    assert indexed["artifact_truncated"] is True
    assert indexed["truncated_dimensions"] == ["security_sinks"]
    assert indexed["analysis_status"] == "degraded"


def test_full_parser_signal_cap_is_explicit_debt_without_losing_availability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from assess.lib import treesitter_index as module

    monkeypatch.setattr(module, "STRUCTURAL_SIGNAL_LIMIT", 2)
    indexed = module._complete_index_metadata(
        {
            "entry_points": [
                {"name": str(index), "line": index, "kind": "route", "annotation": ""}
                for index in range(3)
            ],
            "security_sinks": [],
            "security_sources": [],
            "imports": [],
            "import_targets": [],
            "functions": [],
            "classes": [],
            "call_sites": [],
            "exports": [{"name": str(index)} for index in range(3)],
        },
        source_size=100,
        analysis_mode="tree_sitter",
        unscanned_dimensions=set(),
    )

    assert indexed["structural_index_available"] is True
    assert indexed["analysis_status"] == "degraded"
    assert indexed["analysis_mode"] == "tree_sitter"
    assert indexed["degradation_reason"] == "artifact_signal_limit"
    assert indexed["unavailable_dimensions"] == []
    assert indexed["artifact_truncated"] is True
    assert indexed["truncated_dimensions"] == ["entry_points", "exports"]
    assert len(indexed["entry_points"]) == 2
    assert indexed["signal_counts"]["entry_points"] == 3
    assert len(indexed["exports"]) == 2
    assert indexed["total_exports"] == 3


def test_code_index_rejects_export_total_below_retained_records() -> None:
    module = _load_command("code_index.py", "test_index_export_total")
    artifact = _structural_metadata_artifact()
    artifact["exports"] = [{"name": "one"}, {"name": "two"}]
    artifact["total_exports"] = 1

    with pytest.raises(ValueError, match="export total undercounts retained records"):
        module._validate_analysis_artifact(
            artifact,
            rel_path="main.py",
            source_size=12,
        )


def test_exact_parser_attaches_bounded_security_source_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from assess.lib import treesitter_index as module

    class Parser:
        def parse(self, _source):
            return SimpleNamespace(root_node=SimpleNamespace(named_children=[]))

    monkeypatch.setattr(module, "_TS_AVAILABLE", True)
    monkeypatch.setattr(module, "_get_parser", lambda _language: Parser())
    monkeypatch.setattr(module, "_extract_functions_ts", lambda *_args: [])
    monkeypatch.setattr(module, "_extract_classes_ts", lambda *_args: [])
    monkeypatch.setattr(module, "_extract_imports_ts", lambda *_args: [])
    monkeypatch.setattr(module, "_detect_entry_points", lambda *_args: [])
    monkeypatch.setattr(module, "_detect_sinks", lambda *_args: [])
    monkeypatch.setattr(module, "_detect_call_sites", lambda *_args: [])
    monkeypatch.setattr(module, "_detect_exports", lambda *_args: [])

    indexed = module.index_file(
        "main.py",
        "python",
        source=b"value = request.args['command']\n",
    )

    # Sources are a whole-file scan, so they survive a file with no callable --
    # which is separately declared as an unscanned function scope.
    assert indexed["analysis_status"] == "degraded"
    assert indexed["analysis_mode"] == "tree_sitter"
    assert indexed["signal_counts"]["security_sources"] == 1
    assert indexed["security_sources"][0]["line"] == 1


def test_lightweight_parser_attaches_bounded_security_source_detection() -> None:
    from assess.lib.treesitter_index import index_file

    indexed = index_file(
        "deploy.sh",
        "shell",
        source=b"#!/bin/sh\nprintf '%s' \"$1\"\n",
    )

    assert indexed["analysis_status"] == "complete"
    assert indexed["analysis_mode"] == "lightweight_regex"
    assert indexed["signal_counts"]["security_sources"] == 1
    assert indexed["security_sources"][0]["line"] == 2


def test_structural_json_read_rejects_oversize_before_unbounded_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_command("code_index.py", "test_bounded_structural_json")
    artifact = tmp_path / "aggregate.json"
    artifact.write_text(json.dumps({"padding": "x" * 128}), encoding="utf-8")
    monkeypatch.setattr(module, "MAX_JSON_ARTIFACT_BYTES", 32, raising=False)

    with pytest.raises(ValueError, match="exceeds 32 bytes"):
        module._load_json(artifact, label="hostile aggregate")
