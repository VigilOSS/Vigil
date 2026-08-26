"""Immutable, content-addressed source snapshots for code assessment."""
from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable, Self

SOURCE_MANIFEST_SCHEMA = "code-source-manifest/v2"
_READ_CHUNK_SIZE = 1024 * 1024
_MAX_REPO_KEY_BYTES = 255
MAX_JSON_ARTIFACT_BYTES = 64 * 1024 * 1024
_HEADER_MAX_LINES = 50
_HEADER_MAX_CHARS = 8192
_HEADER_PREFIX_BYTES = (_HEADER_MAX_CHARS * 4) + 4


class SourceSnapshotRaceError(RuntimeError):
    """The selected source path changed while its bytes were being sealed."""


@dataclass
class CapturedSourceFile:
    sha256: str
    size: int
    loc: int
    header: str
    executable: bool
    materialized: bytes | None = field(default=None, repr=False)
    _spool: BinaryIO | None = field(default=None, repr=False)

    @property
    def spool(self) -> BinaryIO:
        """Return the disk spool retained for snapshot publication."""
        if self._spool is None:
            raise ValueError("captured source has no retained spool")
        return self._spool

    def copy_to_fd(self, destination_fd: int) -> None:
        """Copy captured bytes from the spool without reopening the origin."""
        spool = self.spool
        if spool.closed:
            raise ValueError("captured source spool is closed")
        spool.flush()
        spool.seek(0)
        while True:
            chunk = spool.read(_READ_CHUNK_SIZE)
            if not chunk:
                break
            _write_all(destination_fd, chunk)

    def read_bounded(self, max_bytes: int) -> bytes:
        """Materialize at most ``max_bytes`` from a retained or captured value."""
        if self.size > max_bytes:
            raise ValueError(f"captured source exceeds {max_bytes} bytes")
        if self.materialized is not None:
            return self.materialized
        spool = self.spool
        if spool.closed:
            raise ValueError("captured source spool is closed")
        spool.flush()
        spool.seek(0)
        data = spool.read(max_bytes + 1)
        if len(data) != self.size:
            raise ValueError("captured source spool size mismatch")
        return data

    def close(self) -> None:
        if self._spool is not None and not self._spool.closed:
            self._spool.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


@dataclass(frozen=True)
class SealedSnapshot:
    source_path: Path
    manifest_path: Path
    snapshot_digest: str
    reused: bool


@dataclass(frozen=True)
class RootedWalk:
    relative_dir: str
    directories: list[str]
    regular_files: list[str]
    other_entries: list[str]


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _header_from_bytes(data: bytes, *, max_lines: int = 50, max_chars: int = 8192) -> str:
    decoded = data.decode("utf-8", errors="replace")
    parts: list[str] = []
    count = 0
    for line_no, line in enumerate(decoded.splitlines(keepends=True)):
        if line_no >= max_lines or count >= max_chars:
            break
        remaining = max_chars - count
        parts.append(line[:remaining])
        count += min(len(line), remaining)
    return "".join(parts)


def _capture_open_file(
    fd: int,
    *,
    display_path: Path,
    stat_after,
    retain_spool: bool,
    materialize_limit: int | None,
    chunk_consumer: Callable[[bytes], None] | None,
) -> CapturedSourceFile:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise OSError(errno.EINVAL, "source is not a regular file", str(display_path))
    if materialize_limit is not None and materialize_limit < 0:
        raise ValueError("materialize_limit must be non-negative")
    if retain_spool and materialize_limit is not None:
        raise ValueError("capture cannot retain a spool and materialize bytes together")

    spool = tempfile.TemporaryFile(mode="w+b") if retain_spool else None
    digest = hashlib.sha256()
    materialized = bytearray() if materialize_limit is not None else None
    header_prefix = bytearray()
    size = 0
    line_breaks = 0
    previous_ended_cr = False
    last_was_break = False
    try:
        while True:
            chunk = os.read(fd, _READ_CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
            if spool is not None:
                spool.write(chunk)
            if chunk_consumer is not None:
                chunk_consumer(chunk)
            if materialized is not None:
                if len(materialized) + len(chunk) <= int(materialize_limit):
                    materialized.extend(chunk)
                else:
                    materialized = None
            if len(header_prefix) < _HEADER_PREFIX_BYTES:
                remaining = _HEADER_PREFIX_BYTES - len(header_prefix)
                header_prefix.extend(chunk[:remaining])

            line_breaks += chunk.count(b"\n") + chunk.count(b"\r")
            line_breaks -= chunk.count(b"\r\n")
            if previous_ended_cr and chunk.startswith(b"\n"):
                line_breaks -= 1
            previous_ended_cr = chunk.endswith(b"\r")
            last_was_break = chunk.endswith((b"\r", b"\n"))
        if spool is not None:
            spool.flush()
            spool.seek(0)
    except Exception:
        if spool is not None:
            spool.close()
        raise
    after = os.fstat(fd)
    try:
        path_after = stat_after()
    except OSError as exc:
        if spool is not None:
            spool.close()
        raise SourceSnapshotRaceError(f"{display_path} changed while being sealed") from exc
    if (
        not _same_identity(before, after)
        or not _same_identity(after, path_after)
        or not stat.S_ISREG(path_after.st_mode)
    ):
        if spool is not None:
            spool.close()
        raise SourceSnapshotRaceError(f"{display_path} changed while being sealed")

    return CapturedSourceFile(
        sha256=digest.hexdigest(),
        size=size,
        loc=line_breaks + (1 if size and not last_was_break else 0),
        header=_header_from_bytes(bytes(header_prefix)),
        executable=bool(before.st_mode & 0o111),
        materialized=bytes(materialized) if materialized is not None else None,
        _spool=spool,
    )


def _regular_file_read_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    if not nofollow:
        raise RuntimeError("this platform does not provide O_NOFOLLOW")
    if not nonblock:
        raise RuntimeError("this platform does not provide O_NONBLOCK")
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | nonblock


def capture_regular_file(
    path: str | os.PathLike[str],
    *,
    retain_spool: bool = True,
    materialize_limit: int | None = None,
    chunk_consumer: Callable[[bytes], None] | None = None,
) -> CapturedSourceFile:
    """Read one regular file once, without following a final-component symlink."""
    source = Path(path)
    fd = os.open(source, _regular_file_read_flags())
    try:
        return _capture_open_file(
            fd,
            display_path=source,
            stat_after=lambda: os.lstat(source),
            retain_spool=retain_spool,
            materialize_limit=materialize_limit,
            chunk_consumer=chunk_consumer,
        )
    finally:
        os.close(fd)


def read_bounded_regular_file(
    path: str | os.PathLike[str],
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    """Read a no-follow regular file with a hard pre-materialization size cap."""
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    source = Path(path)
    fd = os.open(source, _regular_file_read_flags())
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise OSError(errno.EINVAL, f"{label} is not a regular file", str(source))
        if before.st_size > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} bytes: {source}")
        captured = _capture_open_file(
            fd,
            display_path=source,
            stat_after=lambda: os.lstat(source),
            retain_spool=False,
            materialize_limit=max_bytes,
            chunk_consumer=None,
        )
    finally:
        os.close(fd)
    if captured.materialized is None:
        raise ValueError(f"{label} exceeds {max_bytes} bytes: {source}")
    return captured.materialized


def _safe_relative_path(raw: str) -> PurePosixPath:
    rel = PurePosixPath(raw.replace(os.sep, "/"))
    if rel.is_absolute() or not rel.parts or any(part in {"", ".", ".."} for part in rel.parts):
        raise ValueError(f"unsafe snapshot path: {raw!r}")
    if rel.parts[0] == ".git":
        raise ValueError("Git metadata cannot be sealed as source")
    return rel


def validate_repo_key(raw: str) -> str:
    """Return one filesystem-safe repository-key component."""
    try:
        encoded = os.fsencode(raw)
    except UnicodeEncodeError as exc:
        raise ValueError("repo_key must be one safe path component") from exc
    if (
        not raw
        or len(encoded) > _MAX_REPO_KEY_BYTES
        or raw in {".", ".."}
        or "/" in raw
        or "\\" in raw
        or any(ord(character) < 32 or ord(character) == 127 for character in raw)
    ):
        raise ValueError("repo_key must be one safe path component")
    return raw


class RootedSourceTree:
    """Traverse and read a source tree through one no-follow root descriptor."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        if not nofollow or not directory:
            raise RuntimeError("this platform lacks O_NOFOLLOW/O_DIRECTORY")
        self._directory_flags = (
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory
        )
        self._file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
        self._root_fd = os.open(self.root, self._directory_flags)
        self._root_stat = os.fstat(self._root_fd)
        if not stat.S_ISDIR(self._root_stat.st_mode):
            os.close(self._root_fd)
            raise ValueError(f"source root is not a directory: {self.root}")
        self._closed = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            os.close(self._root_fd)
            self._closed = True

    def _open_directory(self, raw: str = "") -> int:
        if self._closed:
            raise ValueError("source tree descriptor is closed")
        fd = os.dup(self._root_fd)
        if not raw:
            return fd
        try:
            rel = _safe_relative_path(raw)
            for part in rel.parts:
                next_fd = os.open(part, self._directory_flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            return fd
        except Exception:
            os.close(fd)
            raise

    def capture(
        self,
        raw: str,
        *,
        retain_spool: bool = True,
        materialize_limit: int | None = None,
        chunk_consumer: Callable[[bytes], None] | None = None,
    ) -> CapturedSourceFile:
        rel = _safe_relative_path(raw)
        parent_text = PurePosixPath(*rel.parts[:-1]).as_posix() if len(rel.parts) > 1 else ""
        parent_fd = self._open_directory(parent_text)
        try:
            fd = os.open(rel.name, self._file_flags, dir_fd=parent_fd)
            try:
                return _capture_open_file(
                    fd,
                    display_path=self.root.joinpath(*rel.parts),
                    stat_after=lambda: os.stat(
                        rel.name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    ),
                    retain_spool=retain_spool,
                    materialize_limit=materialize_limit,
                    chunk_consumer=chunk_consumer,
                )
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)

    def regular_file_size(self, raw: str) -> int:
        """Return a no-follow regular file size beneath the pinned root."""
        entry_stat = self.stat_entry(raw)
        if not stat.S_ISREG(entry_stat.st_mode):
            raise OSError(errno.EINVAL, "source is not a regular file", raw)
        return entry_stat.st_size

    def stat_entry(self, raw: str) -> os.stat_result:
        """Return no-follow metadata for one entry beneath the pinned root."""
        rel = _safe_relative_path(raw)
        parent_text = (
            PurePosixPath(*rel.parts[:-1]).as_posix() if len(rel.parts) > 1 else ""
        )
        parent_fd = self._open_directory(parent_text)
        try:
            entry_stat = os.stat(rel.name, dir_fd=parent_fd, follow_symlinks=False)
        finally:
            os.close(parent_fd)
        return entry_stat

    def entry_kind(self, raw: str) -> str:
        """Classify one non-regular entry without following any symlink."""

        rel = _safe_relative_path(raw)
        parent_text = (
            PurePosixPath(*rel.parts[:-1]).as_posix() if len(rel.parts) > 1 else ""
        )
        parent_fd = self._open_directory(parent_text)
        try:
            mode = os.stat(
                rel.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            ).st_mode
        finally:
            os.close(parent_fd)
        if stat.S_ISLNK(mode):
            return "symlink"
        if stat.S_ISFIFO(mode):
            return "fifo"
        if stat.S_ISSOCK(mode):
            return "socket"
        if stat.S_ISCHR(mode):
            return "character_device"
        if stat.S_ISBLK(mode):
            return "block_device"
        return "special"

    def walk(self, start: str = ""):
        start_rel = _safe_relative_path(start).as_posix() if start else ""
        pending = [start_rel]
        while pending:
            relative_dir = pending.pop()
            directory_fd = self._open_directory(relative_dir)
            try:
                directories: list[str] = []
                regular_files: list[str] = []
                other_entries: list[str] = []
                for name in sorted(os.listdir(directory_fd)):
                    entry_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISDIR(entry_stat.st_mode):
                        directories.append(name)
                    elif stat.S_ISREG(entry_stat.st_mode):
                        regular_files.append(name)
                    else:
                        other_entries.append(name)
            finally:
                os.close(directory_fd)
            item = RootedWalk(
                relative_dir=relative_dir,
                directories=directories,
                regular_files=regular_files,
                other_entries=other_entries,
            )
            yield item
            for dirname in reversed(item.directories):
                pending.append(f"{relative_dir}/{dirname}" if relative_dir else dirname)

    def verify_root_identity(self) -> None:
        try:
            current = os.stat(self.root, follow_symlinks=False)
        except OSError as exc:
            raise SourceSnapshotRaceError(f"source root changed while being sealed: {self.root}") from exc
        if (
            not stat.S_ISDIR(current.st_mode)
            or current.st_dev != self._root_stat.st_dev
            or current.st_ino != self._root_stat.st_ino
        ):
            raise SourceSnapshotRaceError(f"source root changed while being sealed: {self.root}")


def sealed_source_file_path(source_root: Path, raw: str) -> Path:
    """Resolve one manifest path beneath a sealed source without symlink parents."""
    try:
        rel = _safe_relative_path(raw)
    except ValueError as exc:
        raise ValueError(f"unsafe source file path: {raw!r}") from exc

    current = source_root
    try:
        root_stat = current.lstat()
    except OSError as exc:
        raise ValueError(f"invalid sealed source directory: {source_root}") from exc
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError(f"invalid sealed source directory: {source_root}")
    for part in rel.parts[:-1]:
        current /= part
        try:
            parent_stat = current.lstat()
        except OSError as exc:
            raise ValueError(f"invalid sealed source parent for {raw!r}: {current}") from exc
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise ValueError(f"invalid sealed source parent for {raw!r}: {current}")
    return current / rel.name


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while sealing source")
        view = view[written:]


def _make_tree_writable(path: Path) -> None:
    if not path.exists():
        return
    for root, dirs, files in os.walk(path, topdown=False):
        for filename in files:
            try:
                os.chmod(Path(root) / filename, 0o600, follow_symlinks=False)
            except OSError:
                pass
        for dirname in dirs:
            try:
                os.chmod(Path(root) / dirname, 0o700, follow_symlinks=False)
            except OSError:
                pass
    try:
        os.chmod(path, 0o700, follow_symlinks=False)
    except OSError:
        pass


def _remove_staging(path: Path) -> None:
    _make_tree_writable(path)
    shutil.rmtree(path, ignore_errors=True)


def _set_read_only(path: Path) -> None:
    for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
        for filename in files:
            file_path = Path(root) / filename
            current_mode = file_path.stat(follow_symlinks=False).st_mode
            os.chmod(
                file_path,
                0o555 if current_mode & 0o111 else 0o444,
                follow_symlinks=False,
            )
        for dirname in dirs:
            os.chmod(Path(root) / dirname, 0o555, follow_symlinks=False)
    os.chmod(path, 0o555, follow_symlinks=False)


class SnapshotBuilder:
    """Stage a source tree and atomically publish its immutable manifest."""

    def __init__(self, snapshots_root: Path, repo_key: str) -> None:
        self.repo_key = validate_repo_key(repo_key)
        self.repo_root = snapshots_root / self.repo_key
        self.repo_root.mkdir(parents=True, exist_ok=True)
        self.stage = Path(tempfile.mkdtemp(prefix=".snapshot-stage-", dir=self.repo_root))
        self.source = self.stage / "source"
        self.source.mkdir(mode=0o700)
        self.files: list[dict[str, Any]] = []
        self._finished = False

    def add(self, rel_path: str, captured: CapturedSourceFile, *, language: str) -> None:
        try:
            rel = _safe_relative_path(rel_path)
            destination = self.source.joinpath(*rel.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(
                destination,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                captured.copy_to_fd(fd)
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            captured.close()
        os.chmod(destination, 0o500 if captured.executable else 0o400, follow_symlinks=False)
        self.files.append(
            {
                "file_path": rel.as_posix(),
                "source_sha256": captured.sha256,
                "size": captured.size,
                "loc": captured.loc,
                "language": language,
                "executable": captured.executable,
            }
        )

    def finish(
        self,
        *,
        repo_key: str,
        repo_name: str,
        source_origin_path: str,
        git: dict[str, Any],
        excluded_entries: list[dict[str, Any]] | None = None,
    ) -> SealedSnapshot:
        if validate_repo_key(repo_key) != self.repo_key:
            raise ValueError("repo_key differs from the snapshot builder repository")
        ordered = sorted(self.files, key=lambda item: item["file_path"])
        exclusions = sorted(
            (
                json.loads(json.dumps(record, sort_keys=True))
                for record in (excluded_entries or [])
            ),
            key=lambda record: (
                str(record.get("path") or ""),
                str(record.get("kind") or ""),
                str(record.get("reason") or ""),
            ),
        )
        exclusion_paths: set[str] = set()
        for record in exclusions:
            if not isinstance(record, dict):
                raise ValueError("excluded snapshot entries must be objects")
            path = _safe_relative_path(str(record.get("path") or "")).as_posix()
            if path in exclusion_paths:
                raise ValueError(f"duplicate excluded snapshot path: {path}")
            if not str(record.get("kind") or "") or not str(record.get("reason") or ""):
                raise ValueError(f"excluded snapshot entry lacks kind/reason: {path}")
            record["path"] = path
            exclusion_paths.add(path)
        copied_paths = {str(record["file_path"]) for record in ordered}
        overlap = copied_paths & exclusion_paths
        if overlap:
            raise ValueError(
                f"snapshot paths cannot be copied and excluded: {sorted(overlap)}"
            )
        # V2 authenticates both copied bytes and the provenance/exclusion
        # boundary describing exactly what was reviewed and omitted.
        digest_payload = {
            "schema": SOURCE_MANIFEST_SCHEMA,
            "repo_key": repo_key,
            "repo_name": repo_name,
            "source_origin_path": source_origin_path,
            "git": git,
            "files": ordered,
            "excluded_entries": exclusions,
        }
        digest = hashlib.sha256(
            json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        final = self.repo_root / digest
        source_path = final / "source"
        manifest_path = final / "manifest.json"
        manifest = {
            **digest_payload,
            "source_path": str(source_path.resolve(strict=False)),
            "snapshot_digest": digest,
        }
        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        manifest_fd = os.open(
            self.stage / "manifest.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            _write_all(manifest_fd, manifest_bytes)
            os.fsync(manifest_fd)
        finally:
            os.close(manifest_fd)
        _set_read_only(self.stage)
        # Darwin requires owner write permission on the directory being
        # renamed. Its source subtree and manifest are already read-only; seal
        # the published root immediately after the atomic directory rename.
        os.chmod(self.stage, 0o700, follow_symlinks=False)

        reused = final.exists()
        if reused:
            reused = True
            _remove_staging(self.stage)
            validate_snapshot(final, expected_digest=digest)
        else:
            try:
                os.rename(self.stage, final)
                os.chmod(final, 0o555, follow_symlinks=False)
                # APFS rejects renaming a 0555 source directory, so the stage
                # root is briefly 0700 while every child remains read-only.
                # Revalidation happens only after the published root is sealed
                # and before its path can be returned to any backend consumer.
                validate_snapshot(final, expected_digest=digest)
            except OSError:
                if not final.exists():
                    raise
                reused = True
                _remove_staging(self.stage)
                validate_snapshot(final, expected_digest=digest)
        self._finished = True
        return SealedSnapshot(
            source_path=source_path,
            manifest_path=manifest_path,
            snapshot_digest=digest,
            reused=reused,
        )

    def abort(self) -> None:
        if not self._finished:
            _remove_staging(self.stage)
            self._finished = True


def validate_snapshot(snapshot_root: Path, *, expected_digest: str | None = None) -> dict[str, Any]:
    manifest_path = snapshot_root / "manifest.json"
    source = snapshot_root / "source"
    for directory in (snapshot_root, source):
        try:
            directory_stat = directory.lstat()
        except OSError as exc:
            raise ValueError(f"invalid sealed snapshot directory: {directory}") from exc
        if not stat.S_ISDIR(directory_stat.st_mode) or stat.S_IMODE(directory_stat.st_mode) != 0o555:
            raise ValueError(f"sealed snapshot directory permission/type drift: {directory}")
    try:
        manifest_stat = manifest_path.lstat()
    except OSError as exc:
        raise ValueError(f"invalid sealed snapshot manifest: {manifest_path}") from exc
    if (
        not stat.S_ISREG(manifest_stat.st_mode)
        or stat.S_IMODE(manifest_stat.st_mode) != 0o444
    ):
        raise ValueError(f"sealed snapshot manifest permission/type drift: {manifest_path}")
    try:
        manifest = json.loads(
            read_bounded_regular_file(
                manifest_path,
                max_bytes=MAX_JSON_ARTIFACT_BYTES,
                label="sealed snapshot manifest",
            ).decode("utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid sealed snapshot manifest: {manifest_path}") from exc
    if not isinstance(manifest, dict):
        raise ValueError(f"sealed snapshot manifest must contain a JSON object: {manifest_path}")
    digest = str(manifest.get("snapshot_digest") or "")
    schema = str(manifest.get("schema") or "")
    if schema != SOURCE_MANIFEST_SCHEMA or not digest:
        raise ValueError(f"unsupported sealed snapshot manifest: {manifest_path}")
    if Path(str(manifest.get("source_path") or "")).resolve() != source.resolve():
        raise ValueError(f"sealed snapshot source path binding mismatch: {snapshot_root}")
    if expected_digest and digest != expected_digest:
        raise ValueError(f"sealed snapshot digest mismatch: expected {expected_digest}, got {digest}")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValueError(  # noqa: TRY004 - malformed manifests are validation failures
            f"sealed snapshot has invalid file inventory: {manifest_path}"
        )

    expected_paths: set[str] = set()
    expected_by_path: dict[str, dict[str, Any]] = {}
    for item in files:
        if not isinstance(item, dict):
            raise ValueError(  # noqa: TRY004 - malformed manifests are validation failures
                f"sealed snapshot has an invalid file record: {snapshot_root}"
            )
        rel = _safe_relative_path(str(item.get("file_path", "")))
        rel_text = rel.as_posix()
        if rel_text in expected_paths:
            raise ValueError(f"sealed snapshot has duplicate path: {rel_text}")
        expected_paths.add(rel_text)
        expected_by_path[rel_text] = item

    ordered_files = sorted(files, key=lambda row: row["file_path"])
    exclusions = manifest.get("excluded_entries")
    git = manifest.get("git")
    if not isinstance(exclusions, list) or not isinstance(git, dict):
        raise ValueError(f"sealed snapshot has invalid v2 identity: {manifest_path}")
    exclusion_paths: set[str] = set()
    ordered_exclusions: list[dict[str, Any]] = []
    for record in exclusions:
        if not isinstance(record, dict):
            raise ValueError(f"sealed snapshot has invalid excluded entry: {manifest_path}")
        rel = _safe_relative_path(str(record.get("path") or "")).as_posix()
        if rel in exclusion_paths:
            raise ValueError(f"sealed snapshot has duplicate excluded path: {rel}")
        if not str(record.get("kind") or "") or not str(record.get("reason") or ""):
            raise ValueError(f"sealed snapshot has incomplete excluded entry: {rel}")
        normalized = dict(record)
        normalized["path"] = rel
        ordered_exclusions.append(normalized)
        exclusion_paths.add(rel)
    if exclusion_paths & expected_paths:
        raise ValueError("sealed snapshot copied/excluded path sets overlap")
    ordered_exclusions.sort(
        key=lambda record: (
            str(record["path"]),
            str(record["kind"]),
            str(record["reason"]),
        )
    )
    for key in ("repo_key", "repo_name", "source_origin_path"):
        if not isinstance(manifest.get(key), str) or not manifest[key]:
            raise ValueError(f"sealed snapshot has invalid {key}: {manifest_path}")
    try:
        manifest_repo_key = validate_repo_key(manifest["repo_key"])
    except ValueError as exc:
        raise ValueError(f"sealed snapshot has invalid repo_key: {manifest_path}") from exc
    if snapshot_root.parent.name != manifest_repo_key:
        raise ValueError(f"sealed snapshot repo_key path binding mismatch: {snapshot_root}")
    digest_payload = {
        "schema": schema,
        "repo_key": manifest["repo_key"],
        "repo_name": manifest["repo_name"],
        "source_origin_path": manifest["source_origin_path"],
        "git": git,
        "files": ordered_files,
        "excluded_entries": ordered_exclusions,
    }
    computed = hashlib.sha256(
        json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    if computed != digest or snapshot_root.name != digest:
        raise ValueError(f"sealed snapshot content address mismatch: {snapshot_root}")

    actual_paths: set[str] = set()
    with RootedSourceTree(source) as source_tree:
        for listing in source_tree.walk():
            for dirname in listing.directories:
                rel_text = (
                    f"{listing.relative_dir}/{dirname}"
                    if listing.relative_dir
                    else dirname
                )
                entry_stat = source_tree.stat_entry(rel_text)
                if (
                    not stat.S_ISDIR(entry_stat.st_mode)
                    or stat.S_IMODE(entry_stat.st_mode) != 0o555
                ):
                    raise ValueError(f"sealed snapshot directory drift: {source / rel_text}")
            for name in listing.other_entries:
                rel_text = (
                    f"{listing.relative_dir}/{name}" if listing.relative_dir else name
                )
                raise ValueError(f"sealed snapshot contains symlink/special path: {rel_text}")
            for name in listing.regular_files:
                rel_text = (
                    f"{listing.relative_dir}/{name}" if listing.relative_dir else name
                )
                entry_stat = source_tree.stat_entry(rel_text)
                if not stat.S_ISREG(entry_stat.st_mode):
                    raise ValueError(
                        f"sealed snapshot contains symlink/special path: {rel_text}"
                    )
                actual_paths.add(rel_text)
                item = expected_by_path.get(rel_text)
                if item is None:
                    raise ValueError(f"sealed snapshot contains unexpected path: {rel_text}")
                expected_mode = 0o555 if item.get("executable") else 0o444
                if stat.S_IMODE(entry_stat.st_mode) != expected_mode:
                    raise ValueError(f"sealed snapshot permission drift: {rel_text}")
                captured = source_tree.capture(rel_text, retain_spool=False)
                if (
                    captured.sha256 != item.get("source_sha256")
                    or captured.size != item.get("size")
                    or captured.loc != item.get("loc")
                    or captured.executable is not bool(item.get("executable"))
                ):
                    raise ValueError(f"sealed snapshot file mismatch: {rel_text}")
        source_tree.verify_root_identity()
    if actual_paths != expected_paths:
        raise ValueError(
            f"sealed snapshot path-set mismatch: missing={sorted(expected_paths - actual_paths)}"
        )
    return manifest
