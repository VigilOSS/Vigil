from pathlib import Path
from types import SimpleNamespace

import pytest

from vigil_cli import paths


def test_cached_source_clones_the_installed_release_tag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def run(argv: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append((argv, kwargs))
        destination = Path(argv[-1])
        (destination / "agent").mkdir(parents=True)
        (destination / "orchestrator").mkdir()
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(paths, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(paths, "__version__", "1.0.0", raising=False)
    monkeypatch.setattr(paths, "shutil_which", lambda _command: "/usr/bin/git")
    monkeypatch.setattr(paths, "get_config_value", lambda *_args: None)
    monkeypatch.setattr(paths.subprocess, "run", run)

    resolved = paths._ensure_cached_source()

    expected = paths._source_cache_path(tmp_path, paths.DEFAULT_SOURCE_REPO, "v1.0.0")
    assert resolved == expected.resolve()
    argv, kwargs = calls[0]
    assert argv[:-1] == [
        "git",
        "clone",
        "--depth",
        "1",
        "--branch",
        "v1.0.0",
        "--single-branch",
        paths.DEFAULT_SOURCE_REPO,
    ]
    assert kwargs["timeout"] == paths.SOURCE_CLONE_TIMEOUT_SECONDS
    assert Path(argv[-1]).name == "source"
    assert Path(argv[-1]).parent.name.startswith(".source-cache-")


def test_cached_source_reuses_versioned_checkout_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cached = paths._source_cache_path(tmp_path, paths.DEFAULT_SOURCE_REPO, "v1.0.0")
    (cached / "agent").mkdir(parents=True)
    (cached / "orchestrator").mkdir()
    monkeypatch.setattr(paths, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(paths, "__version__", "1.0.0", raising=False)
    monkeypatch.setattr(paths, "shutil_which", lambda _command: "/usr/bin/git")
    monkeypatch.setattr(paths, "get_config_value", lambda *_args: None)
    monkeypatch.setattr(
        paths.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("an immutable cached release must not pull"),
    )

    assert paths._ensure_cached_source() == cached.resolve()


def test_cached_source_ref_can_be_explicitly_overridden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def run(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(argv)
        destination = Path(argv[-1])
        (destination / "agent").mkdir(parents=True)
        (destination / "orchestrator").mkdir()
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(paths, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(paths, "__version__", "1.0.0", raising=False)
    monkeypatch.setattr(paths, "shutil_which", lambda _command: "/usr/bin/git")
    monkeypatch.setattr(
        paths,
        "get_config_value",
        lambda key, default=None: "release-candidate" if key == "source.ref" else default,
    )
    monkeypatch.setattr(paths.subprocess, "run", run)

    paths._ensure_cached_source()

    assert calls[0][calls[0].index("--branch") + 1] == "release-candidate"
    assert Path(calls[0][-1]).name == "source"


def test_cached_source_failed_clone_does_not_poison_future_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def run(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        destination = Path(argv[-1])
        destination.mkdir(parents=True)
        (destination / "partial-download").write_text("incomplete", encoding="utf-8")
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(paths, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(paths, "__version__", "1.0.0", raising=False)
    monkeypatch.setattr(paths, "shutil_which", lambda _command: "/usr/bin/git")
    monkeypatch.setattr(paths, "get_config_value", lambda *_args: None)
    monkeypatch.setattr(paths.subprocess, "run", run)

    assert paths._ensure_cached_source() is None
    expected = paths._source_cache_path(tmp_path, paths.DEFAULT_SOURCE_REPO, "v1.0.0")
    assert not expected.exists()
    assert "source sync failed for v1.0.0" in capsys.readouterr().err


def test_cached_source_timeout_is_reported_and_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def run(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        destination = Path(argv[-1])
        destination.mkdir(parents=True)
        raise paths.subprocess.TimeoutExpired(argv, paths.SOURCE_CLONE_TIMEOUT_SECONDS)

    monkeypatch.setattr(paths, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(paths, "__version__", "1.0.0", raising=False)
    monkeypatch.setattr(paths, "shutil_which", lambda _command: "/usr/bin/git")
    monkeypatch.setattr(paths, "get_config_value", lambda *_args: None)
    monkeypatch.setattr(paths.subprocess, "run", run)

    assert paths._ensure_cached_source() is None
    expected = paths._source_cache_path(tmp_path, paths.DEFAULT_SOURCE_REPO, "v1.0.0")
    assert not expected.exists()
    assert "timed out" in capsys.readouterr().err


def test_source_cache_identity_binds_repository_and_unsanitized_ref(tmp_path: Path) -> None:
    default = paths._source_cache_path(tmp_path, "https://example.test/acme/vigil.git", "v1.0.0")
    fork = paths._source_cache_path(tmp_path, "https://example.test/fork/vigil.git", "v1.0.0")
    slash = paths._source_cache_path(tmp_path, "https://example.test/acme/vigil.git", "feature/x")
    dash = paths._source_cache_path(tmp_path, "https://example.test/acme/vigil.git", "feature-x")

    assert default != fork
    assert slash != dash
    assert default.name.startswith("source-v1.0.0-")


def test_same_release_ref_from_two_repositories_uses_distinct_caches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def run(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        destination = Path(argv[-1])
        (destination / "agent").mkdir(parents=True)
        (destination / "orchestrator").mkdir()
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(paths, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(paths, "__version__", "1.0.0", raising=False)
    monkeypatch.setattr(paths, "shutil_which", lambda _command: "/usr/bin/git")
    monkeypatch.setattr(paths, "get_config_value", lambda *_args: None)
    monkeypatch.setattr(paths.subprocess, "run", run)

    monkeypatch.setenv("VIGIL_SOURCE_REPO", "https://example.test/acme/vigil.git")
    first = paths._ensure_cached_source()
    monkeypatch.setenv("VIGIL_SOURCE_REPO", "https://example.test/fork/vigil.git")
    second = paths._ensure_cached_source()

    assert first is not None and second is not None
    assert first != second
    assert first.is_dir() and second.is_dir()
