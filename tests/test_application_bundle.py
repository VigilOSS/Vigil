from __future__ import annotations

import contextlib
import hashlib
import json
from pathlib import Path
import os
import py_compile
import subprocess
import sys
import time
from unittest import mock

import pytest

from vigil_cli import application


# The CLI sources, for a process that imports them on its own.
_CLI_SOURCES = Path(application.__file__).resolve().parents[1]


def _release(tmp_path, monkeypatch, files, executables=()):
    package = tmp_path / "installed" / "vigil_cli"
    bundle = package / "_bundle"
    for name, payload in files.items():
        path = bundle / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    inventory = {"files": {name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()},
                 "executables": sorted(executables)}
    metadata = {"schema_version": 1, "version": "1.1.0", **inventory,
                "content_sha256": hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    (bundle / "bundle.json").write_text(json.dumps(metadata))
    monkeypatch.setattr(application, "__file__", str(package / "application.py"))
    monkeypatch.delenv("VIGIL_APPLICATION_DIR", raising=False)
    monkeypatch.setenv("VIGIL_APPLICATION_CACHE", str(tmp_path / "cache"))
    return bundle, metadata


def _bundle(tmp_path, monkeypatch):
    return _release(tmp_path, monkeypatch, {
        "agent/AGENTS.md": b"synthetic release prompt\n",
        "agent/scripts/hook.sh": b"#!/bin/sh\nexit 0\n",
        "orchestrator/backend/app/main.py": b"# synthetic backend\n",
        "cli/vigil_cli/__init__.py": b"# synthetic CLI\n",
    }, ["agent/scripts/hook.sh"])


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


@pytest.mark.parametrize("name", [
    # CPython writes bytecode to `<name>.pyc.<id>` and renames it into place, so a
    # concurrent import leaves that temporary name visible to validation.
    "agent/scripts/assess/__pycache__/client.cpython-314.pyc.4389274",
    "agent/scripts/assess/__pycache__/client.cpython-314.opt-1.pyc",
    "agent/scripts/assess/lib/__pycache__/.nfs000000001",
])
def test_materialized_cache_ignores_any_bytecode_cache_entry(tmp_path, monkeypatch, name):
    _bundle(tmp_path, monkeypatch)
    root = application.resolve_application_root()
    entry = root / name
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_bytes(b"bytecode in flight")
    assert application.resolve_application_root() == root


@pytest.mark.parametrize("mutation", ["file-mode", "missing", "fifo", "cache-symlink", "nested-symlink", "unlisted-nested"])
def test_materialized_release_refuses_every_inventory_drift(tmp_path, monkeypatch, mutation):
    _bundle(tmp_path, monkeypatch)
    root = application.resolve_application_root()
    if mutation == "file-mode":
        (root / "agent/AGENTS.md").chmod(0o600)
        expected = "Application bundle mode mismatch: agent/AGENTS.md"
    elif mutation == "missing":
        (root / "orchestrator/backend/app/main.py").unlink()
        expected = "Application bundle contains missing or unlisted files"
    elif mutation == "fifo":
        os.mkfifo(root / "agent/scripts/acme.fifo")
        expected = f"Invalid application bundle entry: {root / 'agent/scripts/acme.fifo'}"
    elif mutation == "cache-symlink":
        cache = root / "agent/scripts/__pycache__"
        cache.mkdir()
        (cache / "hook.pyc").symlink_to(root / "agent/AGENTS.md")
        expected = f"Symbolic link in application bundle: {cache / 'hook.pyc'}"
    elif mutation == "nested-symlink":
        (root / "agent/scripts/linked").symlink_to(root / "agent")
        expected = f"Symbolic link in application bundle: {root / 'agent/scripts/linked'}"
    else:
        (root / "orchestrator/backend/app/acme-notes.md").write_text("not in the release")
        expected = "Application bundle contains missing or unlisted files"
    with pytest.raises(ValueError) as refused:
        application.validate_bundle(root, materialized=True)
    assert str(refused.value) == expected


def test_materialized_release_validates_to_its_metadata(tmp_path, monkeypatch):
    _, metadata = _bundle(tmp_path, monkeypatch)
    root = application.resolve_application_root()
    assert application.validate_bundle(root, materialized=True) == metadata
    with pytest.raises(ValueError, match="^Application helper launcher content mismatch$"):
        application.validate_bundle(root, materialized=True, launcher_root=tmp_path / "elsewhere")


_VALIDATE_UNDER_DESCRIPTOR_LIMIT = """
import resource, sys
from pathlib import Path
from vigil_cli import application
resource.setrlimit(resource.RLIMIT_NOFILE, (int(sys.argv[3]), resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
try:
    metadata = application.validate_bundle(Path(sys.argv[1]), materialized=sys.argv[2] == "materialized")
except ValueError as exc:
    print(f"refused: {exc}")
else:
    print(metadata["content_sha256"])
"""


def test_validation_fits_a_release_with_more_directories_than_open_descriptors(tmp_path, monkeypatch):
    # A release has hundreds of directories; macOS starts processes with 256 descriptors.
    limit = 48
    files = {"agent/scripts/acme_000/probe.py": b"VALUE = 0\n"}
    files["orchestrator/" + "/".join(f"level{depth}" for depth in range(12)) + "/acme.md"] = b"deep\n"
    # Listed after the deep file: the walk returns to a directory it already left.
    files["agent/scripts/acme_000/second.py"] = b"VALUE = 'second'\n"
    files.update({f"agent/scripts/acme_{index:03}/probe.py": f"VALUE = {index}\n".encode() for index in range(1, 4 * limit)})
    bundle, metadata = _release(tmp_path, monkeypatch, files)
    root = application.resolve_application_root()

    def validate(path: Path, kind: str) -> str:
        result = subprocess.run(
            [sys.executable, "-c", _VALIDATE_UNDER_DESCRIPTOR_LIMIT, str(path), kind, str(limit)],
            env={**os.environ, "PYTHONPATH": str(_CLI_SOURCES)}, text=True, capture_output=True,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    assert validate(bundle, "source") == metadata["content_sha256"]
    assert validate(root, "materialized") == metadata["content_sha256"]
    (root / "agent/scripts/acme_000/second.py").chmod(0o600)
    assert validate(root, "materialized") == "refused: Application bundle mode mismatch: agent/scripts/acme_000/second.py"


# --------------------------------------------------------------------------- #
# Bytecode for a validated release. Helpers run with PYTHONDONTWRITEBYTECODE, so
# a materialized release would otherwise recompile every module on every call.
# After validation the release's helper sources are compiled once per
# interpreter as CHECKED-HASH bytecode beside them: an import uses a cached file
# only while it matches the source bytes on disk, never by mtime.
# --------------------------------------------------------------------------- #


def _python_release(tmp_path, monkeypatch, extra=None):
    return _release(tmp_path, monkeypatch, {
        "agent/AGENTS.md": b"synthetic release prompt\n",
        "agent/scripts/acme_probe.py": b"VALUE = 'release'\n",
        "orchestrator/backend/app/main.py": b"# synthetic backend\n",
        "cli/vigil_cli/__init__.py": b"# synthetic CLI\n",
        **(extra or {}),
    })


_TAG = sys.implementation.cache_tag


def _bytecode_state(root: Path) -> tuple[Path, Path]:
    cache = root / "__pycache__"
    return cache / f"vigil-checked-hash.{_TAG}", cache / f"vigil-checked-hash.{_TAG}.lock"


def _compiled(root: Path) -> Path:
    marker, _ = _bytecode_state(root)
    for _ in range(600):
        if marker.exists():
            return marker
        time.sleep(0.05)
    raise AssertionError(f"release bytecode never completed: {marker}")


def _settled(root: Path) -> None:
    """Wait for the release compile to finish, whether or not it succeeded."""
    marker, lock = _bytecode_state(root)
    for _ in range(600):
        if marker.exists() or not lock.exists() or lock.read_bytes():
            return
        time.sleep(0.05)
    raise AssertionError(f"release bytecode compile never finished: {lock}")


def _pyc(source: Path) -> Path:
    return source.parent / "__pycache__" / f"{source.stem}.{_TAG}.pyc"


def _pyc_flags(source: Path) -> int:
    # PEP 552 flags word: bit 0 hash-based, bit 1 check_source.
    return int.from_bytes(_pyc(source).read_bytes()[4:8], "little")


@contextlib.contextmanager
def _recorded_launches():
    """Record every process the resolver would start, starting none."""
    launched: list[object] = []

    def refuse(*args, **kwargs):
        launched.append(args)
        raise OSError("process launch recorded by the test")

    with mock.patch.object(application.subprocess, "Popen", refuse):
        yield launched


def _probe(root: Path) -> str:
    return subprocess.run(
        [sys.executable, "-c", "import acme_probe; print(acme_probe.VALUE)"],
        cwd=root.parent, env={**os.environ, "PYTHONPATH": str(root / "agent/scripts"), "PYTHONDONTWRITEBYTECODE": "1"},
        text=True, capture_output=True, check=True,
    ).stdout.strip()


def test_validated_release_compiles_checked_hash_bytecode_once(tmp_path, monkeypatch):
    _python_release(tmp_path, monkeypatch)
    root = application.resolve_application_root()
    _compiled(root)
    assert _pyc_flags(root / "agent/scripts/acme_probe.py") == 0b11
    assert _pyc_flags(root / "cli/vigil_cli/__init__.py") == 0b11
    assert _probe(root) == "release"

    with _recorded_launches() as launched:
        assert application.resolve_application_root() == root
    assert launched == []


def test_tampered_source_never_runs_its_stale_bytecode(tmp_path, monkeypatch):
    _python_release(tmp_path, monkeypatch)
    root = application.resolve_application_root()
    _compiled(root)
    source = root / "agent/scripts/acme_probe.py"
    before = source.stat()
    # Same size and the same mtime: exactly what timestamp bytecode cannot see.
    source.write_bytes(b"VALUE = 'changed'\n")
    os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert source.stat().st_size == before.st_size
    assert _probe(root) == "changed"
    with pytest.raises(ValueError, match="^Application bundle content mismatch: agent/scripts/acme_probe.py$"):
        application.validate_bundle(root, materialized=True)


def test_a_failed_release_compile_waits_out_the_retry_window(tmp_path, monkeypatch):
    _python_release(tmp_path, monkeypatch, {"agent/scripts/acme_broken.py": b"def broken(:\n"})
    root = application.resolve_application_root()
    _settled(root)
    marker, lock = _bytecode_state(root)
    assert not marker.exists()
    assert _pyc_flags(root / "agent/scripts/acme_probe.py") == 0b11
    with _recorded_launches() as launched:
        assert application.resolve_application_root() == root
        assert launched == []
        stale = time.time() - application._RELEASE_BYTECODE_LOCK_SECONDS - 1
        os.utime(lock, (stale, stale))
        assert application.resolve_application_root() == root
    assert len(launched) == 1


def test_a_release_compile_keeps_current_bytecode_and_replaces_the_rest(tmp_path, monkeypatch):
    _python_release(tmp_path, monkeypatch)
    root = application.resolve_application_root()
    marker = _compiled(root)
    current = _pyc(root / "agent/scripts/acme_probe.py")
    kept = current.stat()
    # A plain import writes timestamp bytecode, which matches a source by mtime and size alone.
    source = root / "cli/vigil_cli/__init__.py"
    py_compile.compile(str(source), str(_pyc(source)), doraise=True,
                       invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
    assert _pyc_flags(source) == 0
    marker.unlink()
    assert application.resolve_application_root() == root
    _compiled(root)
    assert (current.stat().st_ino, current.stat().st_mtime_ns) == (kept.st_ino, kept.st_mtime_ns)
    assert _pyc_flags(source) == 0b11


def test_a_release_compile_ignores_the_callers_python_environment(tmp_path, monkeypatch):
    _python_release(tmp_path, monkeypatch)
    # Helpers run wherever the operator works, and that may be a target checkout.
    work = tmp_path / "acme-checkout"
    work.mkdir()
    canary = tmp_path / "canary"
    for module in ("compileall", "py_compile", "importlib"):
        (work / f"{module}.py").write_text(f"open({str(canary)!r}, 'a').write({module!r})\n")
    monkeypatch.chdir(work)
    monkeypatch.setenv("PYTHONPYCACHEPREFIX", str(tmp_path / "pycache-prefix"))
    root = application.resolve_application_root()
    _compiled(root)
    assert _pyc_flags(root / "agent/scripts/acme_probe.py") == 0b11
    assert not canary.exists()
    assert not (tmp_path / "pycache-prefix").exists()


_RESOLVE_AND_REAP = """
import os, sys, time
from vigil_cli import application
application.__file__ = sys.argv[1]
root = application.resolve_application_root()
marker = root / "__pycache__" / f"vigil-checked-hash.{sys.implementation.cache_tag}"
deadline = time.monotonic() + 30
while not marker.exists() and time.monotonic() < deadline:
    time.sleep(0.02)
while True:
    try:
        pid, _ = os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        print("no children")
        break
    if pid:
        print("left a finished child to reap")
        break
    if time.monotonic() > deadline:
        print("left a running child")
        break
    time.sleep(0.02)
"""


def test_a_long_lived_helper_is_left_no_compile_child(tmp_path, monkeypatch):
    # `vigil assess` execs the helper in the process that started the compile, and
    # `heartbeat --keepalive` then runs for the whole lane.
    bundle, _ = _python_release(tmp_path, monkeypatch)
    result = subprocess.run(
        [sys.executable, "-c", _RESOLVE_AND_REAP, str(bundle.parent / "application.py")],
        env={**os.environ, "PYTHONPATH": str(_CLI_SOURCES)}, text=True, capture_output=True, timeout=60,
    )
    assert (result.returncode, result.stdout.strip()) == (0, "no children"), result.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes through permission bits")
@pytest.mark.parametrize("read_only", ["release", "bytecode-cache"])
def test_an_unwritable_release_keeps_compiling_from_source(tmp_path, monkeypatch, read_only):
    bundle, _ = _python_release(tmp_path, monkeypatch)
    root = application.materialize_bundle(bundle)
    if read_only == "bytecode-cache":
        (root / "__pycache__").mkdir()
    directory = root if read_only == "release" else root / "__pycache__"
    directory.chmod(0o555)
    try:
        with _recorded_launches() as launched:
            assert application.resolve_application_root() == root
    finally:
        directory.chmod(0o755)
    assert launched == []
    written = [path for path in root.rglob("*") if "__pycache__" in path.relative_to(root).parts]
    assert written == ([] if read_only == "release" else [root / "__pycache__"])
    assert _probe(root) == "release"
