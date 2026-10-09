from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .image_freshness import is_excluded_input
from .install_fs import (
    entry_stat,
    open_child_directory,
    open_pinned_directory,
    unsafe_path,
)

ROOT_MANAGED_NAMES = frozenset(
    {
        "README.md",
        "CODE-MAP.md",
        "agent",
        "orchestrator",
        "docker",
        "pyproject.toml",
        "src",
    }
)
INSTALL_META_FILENAME = ".vigil-install-meta.json"
MANAGED_PRESERVE_REL_PATHS = frozenset(
    {
        Path("agent") / "engagements",
        Path("orchestrator") / "backend" / "data",
    }
)

_MANIFEST_VERSION = b"vigil-install-inputs-v2"
_LENGTH_BYTES = 8
_READ_CHUNK_BYTES = 1024 * 1024
_NORMALIZED_REQUIRED_DIRECTORIES = frozenset(
    {Path("agent"), Path("orchestrator"), Path("orchestrator/backend")}
)


def _update_digest(
    digest: hashlib._Hash,
    *,
    record_type: bytes,
    label: str,
    mode: int = 0,
    payload: bytes = b"",
) -> None:
    label_bytes = label.encode("utf-8")
    digest.update(record_type)
    digest.update(len(label_bytes).to_bytes(_LENGTH_BYTES, "big"))
    digest.update(label_bytes)
    digest.update(mode.to_bytes(4, "big"))
    digest.update(len(payload).to_bytes(_LENGTH_BYTES, "big"))
    digest.update(payload)


def _read_regular_file(
    directory_fd: int, name: str, display: Path, expected: os.stat_result
) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        opened = os.fstat(descriptor)
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            stat.S_IMODE(opened.st_mode),
        )
        expected_identity = (
            expected.st_dev,
            expected.st_ino,
            expected.st_size,
            expected.st_mtime_ns,
            stat.S_IMODE(expected.st_mode),
        )
        if not stat.S_ISREG(opened.st_mode):
            raise unsafe_path(display, "non-regular file")
        if identity != expected_identity:
            raise OSError(f"install-managed file changed while reading: {display}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, _READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
        final = os.fstat(descriptor)
        final_identity = (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
            stat.S_IMODE(final.st_mode),
        )
        payload = b"".join(chunks)
        if len(payload) != opened.st_size or final_identity != identity:
            raise OSError(f"install-managed file changed while reading: {display}")
        return payload
    finally:
        os.close(descriptor)


def _digest_install_path(
    digest: hashlib._Hash,
    parent_fd: int,
    name: str,
    relative_path: Path,
    display: Path,
) -> None:
    if relative_path in MANAGED_PRESERVE_REL_PATHS or is_excluded_input(name):
        return
    metadata = entry_stat(parent_fd, name)
    required_directory = relative_path in _NORMALIZED_REQUIRED_DIRECTORIES
    if metadata is None:
        if required_directory:
            return
        _update_digest(digest, record_type=b"A", label=relative_path.as_posix())
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise unsafe_path(display)
    if required_directory and not stat.S_ISDIR(metadata.st_mode):
        raise unsafe_path(display, "non-directory required path")
    if stat.S_ISDIR(metadata.st_mode):
        if not required_directory:
            _update_digest(digest, record_type=b"D", label=relative_path.as_posix())
        child_fd = open_child_directory(parent_fd, name, display)
        try:
            children = {relative_path / child for child in os.listdir(child_fd)}
            for child in sorted(children, key=lambda path: path.name):
                _digest_install_path(
                    digest, child_fd, child.name, child, display / child.name
                )
        finally:
            os.close(child_fd)
        return
    if stat.S_ISREG(metadata.st_mode):
        _update_digest(
            digest,
            record_type=b"F",
            label=relative_path.as_posix(),
            mode=stat.S_IMODE(metadata.st_mode),
            payload=_read_regular_file(parent_fd, name, display, metadata),
        )
        return
    raise unsafe_path(display, "non-regular file")


def install_content_sha256_from_fd(root_fd: int, *, display_root: Path) -> str:
    digest = hashlib.sha256(_MANIFEST_VERSION)
    for name in sorted(ROOT_MANAGED_NAMES):
        _digest_install_path(digest, root_fd, name, Path(name), display_root / name)
    return digest.hexdigest()


def install_source_content_sha256(source_root: Path) -> str:
    """Digest the normalized install-managed tree through pinned descriptors."""

    pinned = open_pinned_directory(source_root)
    assert pinned is not None
    with pinned:
        return install_content_sha256_from_fd(pinned.fd, display_root=pinned.path)


def _validate_fd_entry(directory_fd: int, name: str, display: Path) -> None:
    if is_excluded_input(name):
        return
    metadata = entry_stat(directory_fd, name)
    if metadata is None:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise unsafe_path(display)
    if stat.S_ISDIR(metadata.st_mode):
        child_fd = open_child_directory(directory_fd, name, display)
        try:
            for child in os.listdir(child_fd):
                _validate_fd_entry(child_fd, child, display / child)
        finally:
            os.close(child_fd)
    elif not stat.S_ISREG(metadata.st_mode):
        raise unsafe_path(display, "non-regular file")


def _validate_relative_directory(root_fd: int, relative: Path, root: Path) -> None:
    descriptor = os.dup(root_fd)
    try:
        display = root
        for part in relative.parts:
            display /= part
            metadata = entry_stat(descriptor, part)
            if metadata is None:
                return
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise unsafe_path(display)
            child = open_child_directory(descriptor, part, display)
            os.close(descriptor)
            descriptor = child
    finally:
        os.close(descriptor)


def validate_install_destination(install_root: Path) -> None:
    """Reject unsafe output paths through no-follow ancestry and child opens."""

    pinned = open_pinned_directory(install_root, missing_ok=True)
    if pinned is None:
        return
    with pinned:
        install_content_sha256_from_fd(pinned.fd, display_root=pinned.path)
        for relative in MANAGED_PRESERVE_REL_PATHS:
            _validate_relative_directory(pinned.fd, relative, pinned.path)
        for name in (
            "AGENTS.md",
            "CLAUDE.md",
            ".codex",
            ".claude",
            ".runtime-data",
            INSTALL_META_FILENAME,
        ):
            _validate_fd_entry(pinned.fd, name, pinned.path / name)
