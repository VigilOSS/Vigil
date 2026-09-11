from __future__ import annotations

import errno
import os
import stat
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY
if hasattr(os, "O_NOFOLLOW"):
    _DIRECTORY_FLAGS |= os.O_NOFOLLOW

_WORKING_DIRECTORY_LOCK = threading.RLock()


def unsafe_path(path: Path, kind: str = "symbolic link") -> OSError:
    return OSError(f"unsafe {kind} in install-managed tree: {path}")


@dataclass(slots=True)
class PinnedDirectory:
    path: Path
    fd: int

    def close(self) -> None:
        os.close(self.fd)

    def __enter__(self) -> PinnedDirectory:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def require_attached(self) -> None:
        """Require the requested path to still name this pinned directory."""

        try:
            current = self.path.lstat()
        except OSError as exc:
            raise unsafe_path(self.path, "replaced directory") from exc
        pinned = os.fstat(self.fd)
        if stat.S_ISLNK(current.st_mode) or (current.st_dev, current.st_ino) != (
            pinned.st_dev,
            pinned.st_ino,
        ):
            raise unsafe_path(self.path, "replaced directory")

    @contextmanager
    def working_directory(self) -> Iterator[Path]:
        """Yield ``.`` rooted at this descriptor, restoring cwd on every exit.

        macOS cannot traverse directory descriptors through ``/dev/fd`` the way
        Linux can through ``/proc/self/fd``. A locked, scoped ``fchdir`` is the
        common inode-bound path surface for helpers that still consume ``Path``.
        """

        with _WORKING_DIRECTORY_LOCK:
            previous = os.open(".", _DIRECTORY_FLAGS)
            try:
                os.fchdir(self.fd)
                yield Path(".")
            finally:
                try:
                    os.fchdir(previous)
                finally:
                    os.close(previous)


def open_pinned_directory(
    path: Path, *, create: bool = False, missing_ok: bool = False
) -> PinnedDirectory | None:
    """Open a directory through no-follow descriptors for every path component."""

    absolute = Path(os.path.abspath(path.expanduser()))
    descriptor = os.open(absolute.anchor, _DIRECTORY_FLAGS)
    walked = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            walked /= part
            try:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    if missing_ok:
                        os.close(descriptor)
                        return None
                    raise
                os.mkdir(part, dir_fd=descriptor)
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise unsafe_path(walked) from exc
                raise
            os.close(descriptor)
            descriptor = child
        return PinnedDirectory(absolute, descriptor)
    except BaseException:
        os.close(descriptor)
        raise


def entry_stat(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def open_child_directory(directory_fd: int, name: str, display: Path) -> int:
    try:
        return os.open(name, _DIRECTORY_FLAGS, dir_fd=directory_fd)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise unsafe_path(display) from exc
        raise


def remove_entry(directory_fd: int, name: str, display: Path) -> None:
    metadata = entry_stat(directory_fd, name)
    if metadata is None:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise unsafe_path(display)
    if stat.S_ISDIR(metadata.st_mode):
        child_fd = open_child_directory(directory_fd, name, display)
        try:
            for child in os.listdir(child_fd):
                remove_entry(child_fd, child, display / child)
        finally:
            os.close(child_fd)
        os.rmdir(name, dir_fd=directory_fd)
        return
    if not stat.S_ISREG(metadata.st_mode):
        raise unsafe_path(display, "non-regular file")
    os.unlink(name, dir_fd=directory_fd)


def ensure_directory(directory_fd: int, name: str, display: Path) -> int:
    metadata = entry_stat(directory_fd, name)
    if metadata is not None and stat.S_ISLNK(metadata.st_mode):
        raise unsafe_path(display)
    if metadata is not None and not stat.S_ISDIR(metadata.st_mode):
        remove_entry(directory_fd, name, display)
        metadata = None
    if metadata is None:
        os.mkdir(name, dir_fd=directory_fd)
    return open_child_directory(directory_fd, name, display)


def atomic_write_bytes(
    directory_fd: int,
    name: str,
    payload: bytes,
    *,
    mode: int,
    display: Path,
) -> None:
    metadata = entry_stat(directory_fd, name)
    if metadata is not None and stat.S_ISLNK(metadata.st_mode):
        raise unsafe_path(display)
    if metadata is not None and stat.S_ISDIR(metadata.st_mode):
        remove_entry(directory_fd, name, display)
    elif metadata is not None and not stat.S_ISREG(metadata.st_mode):
        raise unsafe_path(display, "non-regular file")

    temporary = f".vigil-install-{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    output = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
    open_output: int | None = output
    try:
        view = memoryview(payload)
        while view:
            written = os.write(output, view)
            view = view[written:]
        os.fchmod(output, mode)
        os.close(output)
        open_output = None
        os.replace(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
    except BaseException:
        if open_output is not None:
            try:
                os.close(open_output)
            except OSError:
                pass
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


def copy_regular_file(
    source_fd: int,
    source_name: str,
    destination_fd: int,
    destination_name: str,
    *,
    source_display: Path,
    destination_display: Path,
) -> None:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        input_fd = os.open(source_name, flags, dir_fd=source_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise unsafe_path(source_display) from exc
        raise
    try:
        metadata = os.fstat(input_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise unsafe_path(source_display, "non-regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(input_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        atomic_write_bytes(
            destination_fd,
            destination_name,
            b"".join(chunks),
            mode=stat.S_IMODE(metadata.st_mode),
            display=destination_display,
        )
    finally:
        os.close(input_fd)
