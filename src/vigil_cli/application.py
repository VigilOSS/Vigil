"""Resolve release assets from the imported CLI, never from private workspaces."""
from __future__ import annotations

import os
import json
import tomllib
import hashlib
import re
import shlex
import stat
import tempfile
from pathlib import Path, PurePosixPath

from .install_fs import atomic_write_bytes, open_child_directory, open_pinned_directory


def _read_file(root_fd: int, relative: str) -> bytes:
    descriptor = os.dup(root_fd)
    try:
        parts = PurePosixPath(relative).parts
        for part in parts[:-1]:
            child = open_child_directory(descriptor, part, Path(relative))
            os.close(descriptor)
            descriptor = child
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        source = os.open(parts[-1], flags, dir_fd=descriptor)
        try:
            before = os.fstat(source)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"Invalid application bundle file: {relative}")
            with os.fdopen(os.dup(source), "rb") as stream:
                payload = stream.read()
            after = os.fstat(source)
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise ValueError(f"Application bundle changed while reading: {relative}")
            return payload
        finally:
            os.close(source)
    finally:
        os.close(descriptor)


def validate_bundle(root: Path, *, materialized: bool = False, launcher_root: Path | None = None) -> dict[str, object]:
    """Validate paths, exact inventory and content before using a packaged release."""
    pin = open_pinned_directory(root)
    assert pin is not None
    with pin:
        try:
            metadata = json.loads(_read_file(pin.fd, "bundle.json"))
            if not isinstance(metadata, dict) or type(metadata.get("schema_version")) is not int or metadata["schema_version"] != 1:
                raise ValueError("Invalid application bundle schema")
            version = metadata.get("version")
            if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]*", version):
                raise ValueError("Invalid application bundle version")
            files, executables = metadata.get("files"), metadata.get("executables")
            if not isinstance(files, dict) or not files or not isinstance(executables, list):
                raise ValueError("Invalid application bundle inventory")
            for name, digest in files.items():
                if not isinstance(name, str) or not name or "\\" in name or "\0" in name:
                    raise ValueError("Invalid application bundle path")
                path = PurePosixPath(name)
                if path.is_absolute() or any(part in {".", ".."} for part in path.parts) or path.as_posix() != name or name == "bundle.json":
                    raise ValueError(f"Invalid application bundle path: {name}")
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise ValueError(f"Invalid application bundle digest: {name}")
            if any(not isinstance(item, str) or item not in files for item in executables) or executables != sorted(set(executables)):
                raise ValueError("Invalid application bundle executables")
            inventory = {"files": files, "executables": executables}
            expected = hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if metadata.get("content_sha256") != expected:
                raise ValueError("Invalid application bundle content digest")
            actual: set[str] = set()
            for entry in root.rglob("*"):
                relative = entry.relative_to(root)
                if entry.is_symlink():
                    raise ValueError(f"Symbolic link in application bundle: {entry}")
                # pip compiles package data at install time, and importing helpers
                # from a materialized cache writes bytecode beside them. Python
                # regenerates it from the verified sources; it is never copied.
                if "__pycache__" in relative.parts and (entry.is_dir() or entry.suffix == ".pyc"):
                    continue
                if entry.is_file():
                    actual.add(entry.relative_to(root).as_posix())
                elif not entry.is_dir():
                    raise ValueError(f"Invalid application bundle entry: {entry}")
            allowed = set(files) | {"bundle.json"} | ({"bin/vigil"} if materialized else set())
            if actual != allowed:
                raise ValueError("Application bundle contains missing or unlisted files")
            for name, digest in files.items():
                if hashlib.sha256(_read_file(pin.fd, name)).hexdigest() != digest:
                    raise ValueError(f"Application bundle content mismatch: {name}")
                if materialized and stat.S_IMODE((root / name).stat().st_mode) != (0o755 if name in executables else 0o644):
                    raise ValueError(f"Application bundle mode mismatch: {name}")
            if materialized:
                if _read_file(pin.fd, "bin/vigil") != _launcher(launcher_root or root):
                    raise ValueError("Application helper launcher content mismatch")
                if stat.S_IMODE((root / "bin/vigil").stat().st_mode) != 0o755:
                    raise ValueError("Application helper launcher mode mismatch")
            pin.require_attached()
            return metadata
        except (KeyError, json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"Invalid application bundle metadata: {root}") from exc


def _launcher(root: Path, cli: Path | None = None) -> bytes:
    # uv retains a compatible interpreter and CLI dependencies independently of
    # the tool venv, which a reinstall may remove while a session still runs.
    return (
        "#!/bin/sh\n"
        f"export VIGIL_APPLICATION_DIR={shlex.quote(str(root))}\n"
        f"export PYTHONPATH={shlex.quote(str(cli or root / 'cli'))}\n"
        "export PYTHONDONTWRITEBYTECODE=1\n"
        'exec uv run --no-project --python ">=3.11" --with "questionary>=2.1.1,<3" --with "rich>=14,<15" '
        '--quiet python -c "from vigil_cli.main import main; main()" "$@"\n'
    ).encode()


def _application_cache() -> Path:
    configured = os.environ.get("VIGIL_APPLICATION_CACHE")
    if configured:
        return Path(configured).expanduser().resolve()
    # XDG requires an absolute path; ignore empty or relative values. Resolving
    # accepts a symlinked cache, which pinned directory traversal would refuse.
    xdg = os.environ.get("XDG_CACHE_HOME", "")
    base = Path(xdg) if os.path.isabs(xdg) else Path.home() / ".cache"
    return (base / "vigil" / "applications").resolve()


def session_cli_directory(root: Path) -> Path | None:
    """Helpers follow the session's CLI snapshot even if the installed wheel changes."""
    if (root / "bundle.json").is_file():
        return root / "bin"
    cli = root / "src"
    if not (cli / "vigil_cli" / "main.py").is_file():
        return None
    cache = _application_cache()
    identity = hashlib.sha256(str(root).encode()).hexdigest()
    directory = cache / ".cli-launchers" / identity / "bin"
    pin = open_pinned_directory(directory, create=True)
    assert pin is not None
    with pin:
        atomic_write_bytes(pin.fd, "vigil", _launcher(root, cli), mode=0o755, display=directory / "vigil")
    return directory


def materialize_bundle(bundle: Path) -> Path:
    bundle = Path(os.path.abspath(bundle))
    metadata = validate_bundle(bundle)
    cache = _application_cache()
    root = cache / f"{metadata['version']}-{metadata['content_sha256']}"
    pin = open_pinned_directory(cache, create=True)
    assert pin is not None
    with pin, pin.working_directory():
        relative_root = Path(root.name)
        pin.require_attached()
        if relative_root.exists() or relative_root.is_symlink():
            if validate_bundle(relative_root, materialized=True, launcher_root=root) != metadata:
                raise ValueError("Cached application does not match the requested release identity")
            pin.require_attached()
            return root
        with tempfile.TemporaryDirectory(prefix=".application-", dir=".") as temporary:
            staging = Path(temporary) / "release"
            staging.mkdir()
            source_pin = open_pinned_directory(bundle)
            assert source_pin is not None
            with source_pin:
                files = metadata["files"]
                assert isinstance(files, dict)
                executables = metadata["executables"]
                assert isinstance(executables, list)
                for name, digest in files.items():
                    payload = _read_file(source_pin.fd, name)
                    if hashlib.sha256(payload).hexdigest() != digest:
                        raise ValueError(f"Application bundle changed while staging: {name}")
                    path = staging / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(payload)
                    path.chmod(0o755 if name in executables else 0o644)
                source_pin.require_attached()
            (staging / "bundle.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
            (staging / "bundle.json").chmod(0o644)
            (staging / "bin").mkdir()
            bin_pin = open_pinned_directory(staging / "bin")
            assert bin_pin is not None
            with bin_pin:
                atomic_write_bytes(bin_pin.fd, "vigil", _launcher(root), mode=0o755, display=staging / "bin/vigil")
            validate_bundle(staging, materialized=True, launcher_root=root)
            pin.require_attached()
            try:
                os.rename(staging, root.name, src_dir_fd=pin.fd, dst_dir_fd=pin.fd)
            except OSError:
                if not relative_root.exists() and not relative_root.is_symlink():
                    raise
                if validate_bundle(relative_root, materialized=True, launcher_root=root) != metadata:
                    raise ValueError("Cached application does not match the requested release identity")
            pin.require_attached()
        pin.require_attached()
    return root


def resolve_application_root(
    value: str | Path | None = None, *, preserve_path: bool = False
) -> Path:
    explicit = value or os.environ.get("VIGIL_APPLICATION_DIR")
    if explicit:
        path = Path(os.path.abspath(Path(explicit).expanduser()))
        if not (path / "agent").is_dir() or not (path / "orchestrator").is_dir():
            raise SystemExit(f"Invalid Vigil application directory: {path}")
        if (path / "bundle.json").exists():
            validate_bundle(path, materialized=True)
        return path if preserve_path else path.resolve()
    module = Path(__file__).resolve()
    bundle = module.parent / "_bundle"
    if bundle.is_dir():
        return materialize_bundle(bundle)
    # Editable imports and retained release snapshots both have a known layout.
    root = module.parents[2]
    if (root / "agent").is_dir() and (root / "orchestrator").is_dir():
        if (root / "bundle.json").exists():
            validate_bundle(root, materialized=True)
        return root
    raise SystemExit("Cannot locate the matched Vigil application bundle. Reinstall the release wheel.")


def application_root_for_workspace(workspace: Path) -> Path:
    """A workspace selects data; the imported CLI or explicit session pin selects code."""
    return resolve_application_root()


def application_provenance(root: Path) -> dict[str, str]:
    """Content identity for the application independently of private workspace bytes."""
    from .install_manifest import install_source_content_sha256

    manifest_path = root / "bundle.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        version = manifest["version"]
        digest = manifest["content_sha256"]
    else:
        project_path = root / "pyproject.toml"
        version = "0.0.0+unknown"
        if project_path.is_file():
            project = tomllib.loads(project_path.read_text(encoding="utf-8"))
            version = project.get("project", {}).get("version", version)
        digest = install_source_content_sha256(root)
    return {"root": str(root), "version": str(version), "content_sha256": str(digest)}
