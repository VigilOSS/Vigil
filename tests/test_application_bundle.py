from __future__ import annotations

import hashlib
import json
from pathlib import Path
import os
import subprocess
import sys

import pytest

from vigil_cli import application


def _bundle(tmp_path, monkeypatch):
    package = tmp_path / "installed" / "vigil_cli"
    bundle = package / "_bundle"
    files = {
        "agent/AGENTS.md": b"synthetic release prompt\n",
        "agent/scripts/hook.sh": b"#!/bin/sh\nexit 0\n",
        "orchestrator/backend/app/main.py": b"# synthetic backend\n",
        "cli/vigil_cli/__init__.py": b"# synthetic CLI\n",
    }
    for name, payload in files.items():
        path = bundle / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    inventory = {"files": {name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()},
                 "executables": ["agent/scripts/hook.sh"]}
    metadata = {"schema_version": 1, "version": "1.1.0", **inventory,
                "content_sha256": hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    (bundle / "bundle.json").write_text(json.dumps(metadata))
    monkeypatch.setattr(application, "__file__", str(package / "application.py"))
    monkeypatch.delenv("VIGIL_APPLICATION_DIR", raising=False)
    monkeypatch.setenv("VIGIL_APPLICATION_CACHE", str(tmp_path / "cache"))
    return bundle, metadata


def test_packaged_release_materializes_atomically_with_verified_modes(tmp_path, monkeypatch):
    bundle, metadata = _bundle(tmp_path, monkeypatch)
    resolved = application.resolve_application_root()
    assert resolved == tmp_path / "cache" / f"1.1.0-{metadata['content_sha256']}"
    assert (resolved / "agent/AGENTS.md").read_bytes() == (bundle / "agent/AGENTS.md").read_bytes()
    assert (resolved / "agent/scripts/hook.sh").stat().st_mode & 0o777 == 0o755
    assert (resolved / "agent/AGENTS.md").stat().st_mode & 0o777 == 0o644
    assert application.resolve_application_root() == resolved
    assert (resolved / "bin/vigil").is_file()


@pytest.mark.parametrize("kind", ["content", "digest", "traversal", "symlink", "unlisted"])
def test_invalid_packaged_release_never_materializes(tmp_path, monkeypatch, kind):
    bundle, metadata = _bundle(tmp_path, monkeypatch)
    if kind == "content":
        (bundle / "agent/AGENTS.md").write_text("tampered")
    elif kind == "digest":
        metadata["content_sha256"] = "0" * 64
    elif kind == "traversal":
        metadata["files"]["../outside"] = "0" * 64
    elif kind == "symlink":
        path = bundle / "agent/AGENTS.md"
        path.unlink()
        path.symlink_to(bundle / "cli/vigil_cli/__init__.py")
    else:
        (bundle / "private-canary.txt").write_text("do not ship")
    (bundle / "bundle.json").write_text(json.dumps(metadata))
    with pytest.raises((OSError, SystemExit, ValueError), match="bundle|application|symbolic"):
        application.resolve_application_root()
    assert not (tmp_path / "cache").exists() or not list((tmp_path / "cache").glob("1.1.0-*"))


def test_tampered_application_cache_fails_without_overwriting_retained_assets(tmp_path, monkeypatch):
    _bundle(tmp_path, monkeypatch)
    resolved = application.resolve_application_root()
    prompt = resolved / "agent/AGENTS.md"
    prompt.write_text("changed cache bytes")
    with pytest.raises((OSError, SystemExit, ValueError), match="bundle|application"):
        application.resolve_application_root()
    assert prompt.read_text() == "changed cache bytes"


def test_retained_cli_reports_its_release_version_independently_of_installed_distribution(tmp_path):
    release = tmp_path / "release"
    package = release / "cli" / "vigil_cli"
    package.mkdir(parents=True)
    source = Path(application.__file__).parent / "__init__.py"
    (package / "__init__.py").write_bytes(source.read_bytes())
    (release / "bundle.json").write_text(json.dumps({"version": "1.1.0"}))
    result = subprocess.run(
        [sys.executable, "-c", "import vigil_cli; print(vigil_cli.__version__)"],
        cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(release / "cli")},
        text=True, capture_output=True, check=True,
    )
    assert result.stdout.strip() == "1.1.0"


@pytest.mark.parametrize("mutation", ["content", "mode"])
def test_materialized_helper_integrity_is_verified(tmp_path, monkeypatch, mutation):
    _bundle(tmp_path, monkeypatch)
    root = application.resolve_application_root()
    helper = root / "bin" / "vigil"
    if mutation == "content":
        helper.write_text("#!/bin/sh\nexit 0\n")
    else:
        helper.chmod(0o644)
    with pytest.raises(ValueError, match="helper|launcher"):
        application.resolve_application_root()


def test_retained_helper_uses_compatible_python_after_tool_interpreter_removal(tmp_path, monkeypatch):
    _bundle(tmp_path, monkeypatch)
    real_python = sys.executable
    monkeypatch.setattr(sys, "executable", str(tmp_path / "removed-tool-python"))
    root = application.resolve_application_root()
    binaries = tmp_path / "bin"
    binaries.mkdir()
    uv = binaries / "uv"
    uv.write_text(f"#!{real_python}\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n")
    uv.chmod(0o755)
    incompatible = binaries / "python3"
    incompatible.write_text("#!/bin/sh\nexit 93\n")
    incompatible.chmod(0o755)
    result = subprocess.run([str(root / "bin/vigil"), "--version"],
        env={**os.environ, "PATH": str(binaries)}, text=True, capture_output=True)
    assert result.returncode == 0
    argv = json.loads(result.stdout)
    assert argv[:5] == ["run", "--no-project", "--python", ">=3.11", "--with"]
    assert argv[-1] == "--version"


def test_self_consistent_cache_for_another_release_is_not_reused(tmp_path, monkeypatch):
    _bundle(tmp_path, monkeypatch)
    root = application.resolve_application_root()
    path = root / "bundle.json"
    metadata = json.loads(path.read_text())
    metadata["version"] = "1.2.0"
    changed_bytes = json.dumps(metadata)
    path.write_text(changed_bytes)
    with pytest.raises(ValueError, match="requested|identity|release"):
        application.resolve_application_root()
    assert path.read_text() == changed_bytes


def test_cache_detachment_before_reuse_does_not_return_an_unattached_release(tmp_path, monkeypatch):
    _bundle(tmp_path, monkeypatch)
    root = application.resolve_application_root()
    cache = root.parent
    detached = tmp_path / "retained-cache"
    validate = application.validate_bundle
    moved = False

    def relocate_after_validation(path, **kwargs):
        nonlocal moved
        metadata = validate(path, **kwargs)
        if kwargs.get("materialized") and path.name == root.name and not moved:
            moved = True
            cache.rename(detached)
            cache.mkdir()
        return metadata

    monkeypatch.setattr(application, "validate_bundle", relocate_after_validation)
    with pytest.raises(OSError, match="replaced directory"):
        application.resolve_application_root()
    assert moved
    assert (detached / root.name / "agent/AGENTS.md").is_file()
    assert list(cache.iterdir()) == []


def test_materialized_cache_survives_bytecode_written_by_its_own_imports(tmp_path, monkeypatch):
    _bundle(tmp_path, monkeypatch)
    root = application.resolve_application_root()
    subprocess.run(
        [sys.executable, "-c", "import vigil_cli"],
        cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(root / "cli"), "PYTHONDONTWRITEBYTECODE": ""},
        check=True,
    )
    assert list((root / "cli/vigil_cli/__pycache__").glob("*.pyc"))
    assert application.resolve_application_root() == root


@pytest.mark.parametrize("xdg", ["symlink", "empty", "relative"])
def test_application_cache_location_tolerates_common_home_layouts(tmp_path, monkeypatch, xdg):
    bundle, metadata = _bundle(tmp_path, monkeypatch)
    monkeypatch.delenv("VIGIL_APPLICATION_CACHE")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)
    expected = home / ".cache"
    if xdg == "symlink":
        # Dotfile setups commonly link the cache to another disk.
        expected = tmp_path / "other-disk"
        expected.mkdir()
        (home / ".cache").symlink_to(expected)
        monkeypatch.setenv("XDG_CACHE_HOME", str(home / ".cache"))
    else:
        monkeypatch.setenv("XDG_CACHE_HOME", "" if xdg == "empty" else "relative-cache")
    root = application.resolve_application_root()
    assert root == expected.resolve() / "vigil/applications" / f"1.1.0-{metadata['content_sha256']}"
