"""Private workspace metadata and data locations, independent of release assets."""
from __future__ import annotations

import json
import os
import errno
import stat
from pathlib import Path

from .install_fs import PinnedDirectory, atomic_write_bytes, entry_stat, open_pinned_directory, unsafe_path

WORKSPACE_FILENAME = "workspace.json"


def _metadata_identity(entry: os.stat_result | None) -> tuple[int, int, int, int] | None:
    if entry is None:
        return None
    return entry.st_dev, entry.st_ino, entry.st_size, entry.st_mtime_ns


def _require_metadata_unchanged(pin: PinnedDirectory, snapshot: os.stat_result | None) -> None:
    if _metadata_identity(entry_stat(pin.fd, WORKSPACE_FILENAME)) != _metadata_identity(snapshot):
        raise unsafe_path(pin.path / WORKSPACE_FILENAME, "changed workspace metadata")


def _read_workspace_pinned(pin: PinnedDirectory) -> tuple[dict[str, object] | None, os.stat_result | None]:
    path = pin.path / WORKSPACE_FILENAME
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(WORKSPACE_FILENAME, flags, dir_fd=pin.fd)
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise unsafe_path(path) from exc
        raise
    try:
        snapshot = os.fstat(descriptor)
        if not stat.S_ISREG(snapshot.st_mode):
            raise unsafe_path(path, "non-regular workspace file")
        with os.fdopen(os.dup(descriptor), "r", encoding="utf-8") as stream:
            payload = stream.read()
        if _metadata_identity(os.fstat(descriptor)) != _metadata_identity(snapshot):
            raise unsafe_path(path, "changed workspace metadata")
    finally:
        os.close(descriptor)
    try:
        parsed = json.loads(payload)
    except (ValueError, OSError) as exc:
        raise SystemExit(f"Cannot read Vigil workspace metadata: {path}: {exc}") from exc
    if not isinstance(parsed, dict) or parsed.get("schema_version") != 1 or not isinstance(parsed.get("paths"), dict):
        raise SystemExit(f"Invalid Vigil workspace metadata: {path}")
    _require_metadata_unchanged(pin, snapshot)
    return parsed, snapshot


def read_workspace(root: Path) -> dict[str, object] | None:
    pin = open_pinned_directory(root, missing_ok=True)
    if pin is None:
        return None
    with pin:
        metadata, _snapshot = _read_workspace_pinned(pin)
        pin.require_attached()
        return metadata


def _default_paths(root: Path) -> dict[str, Path]:
    legacy_engagements = root / "agent" / "engagements"
    legacy_data = root / "orchestrator" / "backend" / "data"
    legacy_runtime = root / ".runtime-data"
    legacy_tenants = root / "agent" / "references" / "tenants"
    runtime = legacy_runtime if legacy_runtime.exists() else root / "state" / "runtime"
    return {
        "engagements": legacy_engagements if legacy_engagements.exists() else root / "engagements",
        "data": legacy_data if legacy_data.exists() else root / "state",
        "runtime_state": runtime,
        "tenant_references": legacy_tenants if legacy_tenants.exists() else root / "tenant-references",
        "logs": legacy_runtime / "logs" if legacy_runtime.exists() else root / "logs",
        "cache": root / "cache",
    }


def workspace_path(root: Path, name: str) -> Path:
    metadata = read_workspace(root)
    if metadata is not None:
        locations = _workspace_locations(root, metadata)
        value = locations.get(name)
        if not isinstance(value, str) or not value:
            raise SystemExit(f"Missing workspace path {name!r} in {root / WORKSPACE_FILENAME}")
        path = Path(value).expanduser()
        return path if path.is_absolute() else root / path
    return _default_paths(root)[name]


def validate_workspace(root: Path) -> None:
    """Preflight only owned metadata/data roots; operator files are never rewritten."""
    pin = open_pinned_directory(root, missing_ok=True)
    if pin is None:
        return
    with pin:
        metadata, snapshot = _read_workspace_pinned(pin)
        locations = _workspace_locations(pin.path, metadata)
        _validate_workspace_pinned(pin, locations)
        _require_metadata_unchanged(pin, snapshot)
        pin.require_attached()


def _workspace_locations(root: Path, metadata: dict[str, object] | None) -> dict[str, str]:
    if metadata is None:
        return {name: str(path.relative_to(root)) for name, path in _default_paths(root).items()}
    locations = metadata["paths"]
    assert isinstance(locations, dict)
    for name in _default_paths(root):
        if name not in locations:
            raise SystemExit(f"Missing workspace path {name!r} in {root / WORKSPACE_FILENAME}")
    for name, value in locations.items():
        if not isinstance(name, str) or not isinstance(value, str) or not value:
            raise SystemExit(f"Invalid workspace path: {name}")
    result = dict(locations)
    # Old installers serialized every default absolutely. The cache anchor and
    # the complete recognized layout establish provenance; never prefix-rewrite
    # arbitrary operator storage or infer ownership from a path substring.
    cache = Path(result["cache"]).expanduser()
    if cache.is_absolute() and cache.name == "cache":
        previous = cache.parent
        if previous != root:
            layouts = {
                "engagements": {"engagements", "agent/engagements"},
                "data": {"state", "orchestrator/backend/data"},
                "runtime_state": {"state/runtime", ".runtime-data"},
                "tenant_references": {"tenant-references", "agent/references/tenants"},
                "logs": {"logs", ".runtime-data/logs"},
                "cache": {"cache"},
            }
            converted = {}
            for name, value in result.items():
                path = Path(value).expanduser()
                if name == "data" and path.is_absolute() and not path.is_relative_to(previous):
                    converted[name] = value  # Explicit external storage stays external.
                    continue
                if (not path.is_absolute() or not path.is_relative_to(previous)
                        or str(path.relative_to(previous)) not in layouts.get(name, set())):
                    raise SystemExit(f"Ambiguous workspace relocation in {root / WORKSPACE_FILENAME}; "
                                     "set each intended workspace path explicitly before adoption.")
                converted[name] = str(path.relative_to(previous))
            if previous.exists():
                raise SystemExit(f"Cannot adopt copied workspace: original workspace still exists at {previous}. "
                                 f"Set the intended paths in {root / WORKSPACE_FILENAME} explicitly, "
                                 "and stop/restart active services before using the copy.")
            return converted
    return result


def _validate_workspace_pinned(pin: PinnedDirectory, locations: dict[str, str]) -> None:
    for name in (WORKSPACE_FILENAME, ".env", ".vigil-install-meta.json"):
        entry = entry_stat(pin.fd, name)
        if entry is not None and not stat.S_ISREG(entry.st_mode):
            raise unsafe_path(pin.path / name, "non-regular workspace file")
    for value in locations.values():
        path = Path(value).expanduser()
        existing = open_pinned_directory(path if path.is_absolute() else pin.path / path, missing_ok=True)
        if existing is not None:
            existing.close()
    pin.require_attached()


def initialize_workspace(root: Path, application_root: Path | None = None) -> dict[str, object]:
    """Adopt locations in place and create private data, never copy application trees."""
    from .application import application_provenance, resolve_application_root

    root = Path(os.path.abspath(root.expanduser()))
    application = resolve_application_root(application_root)
    provenance = application_provenance(application)
    pinned = open_pinned_directory(root, create=True)
    assert pinned is not None
    with pinned:
        pinned.require_attached()
        metadata, snapshot = _read_workspace_pinned(pinned)
        locations = _workspace_locations(root, metadata)
        if metadata is None:
            override = os.environ.get("VIGIL_DATA_DIR") or os.environ.get("REDTEAM_ORCHESTRATOR_DATA_DIR")
            if override:
                locations["data"] = os.path.abspath(Path(override).expanduser())
        # Validate all roots from the same metadata snapshot before any writes.
        _validate_workspace_pinned(pinned, locations)
        _require_metadata_unchanged(pinned, snapshot)
        for value in locations.values():
            location = Path(str(value)).expanduser()
            directory = open_pinned_directory(location if location.is_absolute() else root / location, create=True)
            assert directory is not None
            directory.close()
        pinned.require_attached()
        env_metadata = entry_stat(pinned.fd, ".env")
        if env_metadata is None:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(".env", flags, 0o600, dir_fd=pinned.fd)
            except FileExistsError:
                # A concurrent initializer/operator won. Never replace its bytes.
                env_metadata = entry_stat(pinned.fd, ".env")
                if env_metadata is None or not stat.S_ISREG(env_metadata.st_mode):
                    raise unsafe_path(root / ".env", "non-regular workspace file")
            else:
                try:
                    os.fchmod(descriptor, 0o600)
                finally:
                    os.close(descriptor)
        elif not stat.S_ISREG(env_metadata.st_mode):
            raise unsafe_path(root / ".env", "non-regular workspace file")
        updated = dict(metadata or {})
        updated.update(schema_version=1, paths=locations, application=provenance)
        if updated != metadata:
            _require_metadata_unchanged(pinned, snapshot)
            atomic_write_bytes(
                pinned.fd, WORKSPACE_FILENAME,
                (json.dumps(updated, indent=2, sort_keys=True) + "\n").encode(),
                mode=0o600, display=root / WORKSPACE_FILENAME,
            )
        pinned.require_attached()
    return updated
