from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

SOURCE_MANIFEST_VERSION = "v1"
SEALED_SOURCE_MANIFEST_SCHEMA = "code-source-manifest/v2"
SEALED_SOURCE_REVIEW_IDENTITY_SCHEMA = "code-source-review-identity/v1"
MAX_SEALED_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_SEALED_MANIFEST_NESTING = 64
_READ_CHUNK_SIZE = 1024 * 1024
_HEADER_MAX_LINES = 50
_HEADER_MAX_CHARS = 8192
_HEADER_PREFIX_BYTES = (_HEADER_MAX_CHARS * 4) + 4


class SnapshotAttestationError(ValueError):
    """A caller-requested verified snapshot cannot be independently proven."""


def _is_lower_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _safe_relative_path(raw: Any) -> PurePosixPath:
    if not isinstance(raw, str):
        raise SnapshotAttestationError("snapshot paths must be strings")
    relative = PurePosixPath(raw)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.parts[0] == ".git"
    ):
        raise SnapshotAttestationError(f"unsafe snapshot path: {raw!r}")
    return relative


def _lexical_absolute(raw: Any, *, label: str) -> Path:
    if not isinstance(raw, str) or not raw:
        raise SnapshotAttestationError(f"{label} is missing")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise SnapshotAttestationError(f"{label} must be an absolute path")
    return Path(os.path.normpath(os.fspath(path)))


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _header_from_bytes(data: bytes) -> str:
    decoded = data.decode("utf-8", errors="replace")
    parts: list[str] = []
    count = 0
    for line_number, line in enumerate(decoded.splitlines(keepends=True)):
        if line_number >= _HEADER_MAX_LINES or count >= _HEADER_MAX_CHARS:
            break
        remaining = _HEADER_MAX_CHARS - count
        parts.append(line[:remaining])
        count += min(len(line), remaining)
    return "".join(parts)


def _validate_json_nesting(data: bytes) -> None:
    """Reject pathological JSON depth before the recursive decoder runs."""
    depth = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            continue
        if byte == ord('"'):
            in_string = True
        elif byte in (ord("{"), ord("[")):
            depth += 1
            if depth > MAX_SEALED_MANIFEST_NESTING:
                raise SnapshotAttestationError(
                    "sealed snapshot manifest nesting exceeds "
                    f"{MAX_SEALED_MANIFEST_NESTING} levels"
                )
        elif byte in (ord("}"), ord("]")):
            depth -= 1


def _open_directory_at(parent_fd: int, name: str) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise SnapshotAttestationError(
            "verified snapshot attestation requires O_NOFOLLOW and O_DIRECTORY"
        )
    return os.open(
        name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory,
        dir_fd=parent_fd,
    )


def _open_root_directory(path: Path) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise SnapshotAttestationError(
            "verified snapshot attestation requires O_NOFOLLOW and O_DIRECTORY"
        )
    if not path.is_absolute():
        raise SnapshotAttestationError("snapshot root must be absolute")
    fd = os.open(
        os.path.sep,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory,
    )
    try:
        for component in path.parts[1:]:
            next_fd = _open_directory_at(fd, component)
            os.close(fd)
            fd = next_fd
        return fd
    except Exception:
        os.close(fd)
        raise


def _read_regular_at(
    parent_fd: int,
    name: str,
    *,
    display_path: Path,
    max_bytes: int | None,
) -> tuple[bytes | None, dict[str, Any], os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise SnapshotAttestationError(
            "verified snapshot attestation requires O_NOFOLLOW"
        )
    fd = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow,
        dir_fd=parent_fd,
    )
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise SnapshotAttestationError(
                f"sealed source entry is not a regular file: {display_path}"
            )
        if max_bytes is not None and before.st_size > max_bytes:
            raise SnapshotAttestationError(
                f"sealed snapshot manifest exceeds {max_bytes} bytes"
            )
        digest = hashlib.sha256()
        materialized = bytearray() if max_bytes is not None else None
        header_prefix = bytearray()
        size = 0
        line_breaks = 0
        previous_ended_cr = False
        last_was_break = False
        while True:
            chunk = os.read(fd, _READ_CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            if max_bytes is not None and size > max_bytes:
                raise SnapshotAttestationError(
                    f"sealed snapshot manifest exceeds {max_bytes} bytes"
                )
            digest.update(chunk)
            if materialized is not None:
                materialized.extend(chunk)
            if len(header_prefix) < _HEADER_PREFIX_BYTES:
                remaining = _HEADER_PREFIX_BYTES - len(header_prefix)
                header_prefix.extend(chunk[:remaining])
            line_breaks += chunk.count(b"\n") + chunk.count(b"\r")
            line_breaks -= chunk.count(b"\r\n")
            if previous_ended_cr and chunk.startswith(b"\n"):
                line_breaks -= 1
            previous_ended_cr = chunk.endswith(b"\r")
            last_was_break = chunk.endswith((b"\r", b"\n"))
        after = os.fstat(fd)
        path_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_identity(before, after) or not _same_identity(after, path_after):
            raise SnapshotAttestationError(
                f"sealed source changed during attestation: {display_path}"
            )
        return (
            bytes(materialized) if materialized is not None else None,
            {
                "source_sha256": digest.hexdigest(),
                "size": size,
                "loc": line_breaks + (1 if size and not last_was_break else 0),
                "header_snippet": _header_from_bytes(bytes(header_prefix)),
                "executable": bool(before.st_mode & 0o111),
            },
            after,
        )
    finally:
        os.close(fd)


def _canonical_snapshot_digest(manifest: Mapping[str, Any]) -> str:
    payload = {
        "schema": manifest.get("schema"),
        "repo_key": manifest.get("repo_key"),
        "repo_name": manifest.get("repo_name"),
        "source_origin_path": manifest.get("source_origin_path"),
        "git": manifest.get("git"),
        "files": sorted(
            manifest.get("files", []), key=lambda row: str(row.get("file_path", ""))
        ),
        "excluded_entries": sorted(
            manifest.get("excluded_entries", []),
            key=lambda row: (
                str(row.get("path", "")),
                str(row.get("kind", "")),
                str(row.get("reason", "")),
            ),
        ),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_review_identity_digest(manifest: Mapping[str, Any]) -> str:
    """Identify the reviewed bytes and exclusion boundary, not their checkout provenance."""
    payload = {
        "schema": SEALED_SOURCE_REVIEW_IDENTITY_SCHEMA,
        "repo_key": manifest.get("repo_key"),
        "files": sorted(
            manifest.get("files", []), key=lambda row: str(row.get("file_path", ""))
        ),
        "excluded_entries": sorted(
            manifest.get("excluded_entries", []),
            key=lambda row: (
                str(row.get("path", "")),
                str(row.get("kind", "")),
                str(row.get("reason", "")),
            ),
        ),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class VerifiedSnapshotAttestation:
    """Live backend proof of one engagement-owned, sealed source snapshot."""

    snapshot_digest: str
    review_identity_digest: str
    manifest_files: dict[str, dict[str, Any]]
    excluded_non_directories: int
    _engagement_path: Path = field(repr=False)
    _snapshot_path: Path = field(repr=False)
    _engagement_fd: int = field(repr=False)
    _snapshot_fd: int = field(repr=False)
    _source_fd: int = field(repr=False)
    _engagement_stat: os.stat_result = field(repr=False)
    _snapshot_stat: os.stat_result = field(repr=False)
    _source_stat: os.stat_result = field(repr=False)
    _manifest_stat: os.stat_result = field(repr=False)
    _directory_stats: dict[str, os.stat_result] = field(repr=False)
    _file_stats: dict[str, os.stat_result] = field(repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __enter__(self) -> VerifiedSnapshotAttestation:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        for fd in (self._source_fd, self._snapshot_fd, self._engagement_fd):
            try:
                os.close(fd)
            except OSError:
                pass
        self._closed = True

    def _open_source_directory(self, raw: str = "") -> int:
        if self._closed:
            raise SnapshotAttestationError("snapshot attestation is closed")
        fd = os.dup(self._source_fd)
        if not raw:
            return fd
        try:
            relative = _safe_relative_path(raw)
            for part in relative.parts:
                next_fd = _open_directory_at(fd, part)
                os.close(fd)
                fd = next_fd
            return fd
        except Exception:
            os.close(fd)
            raise

    def assert_staged_inventory(
        self,
        staged: Mapping[str, Mapping[str, Any]],
        metadata: Mapping[str, Any],
    ) -> None:
        expected_paths = set(self.manifest_files)
        actual_paths = set(staged)
        if actual_paths != expected_paths:
            missing = sorted(expected_paths - actual_paths)
            extra = sorted(actual_paths - expected_paths)
            raise SnapshotAttestationError(
                "staged inventory differs from sealed source manifest "
                f"(missing={missing}, extra={extra})"
            )
        for file_path, expected in self.manifest_files.items():
            actual = staged[file_path]
            if not isinstance(actual, Mapping):
                raise SnapshotAttestationError(
                    f"staged source metadata is invalid for {file_path}"
                )
            comparisons = {
                "file_hash": (actual.get("file_hash"), expected["source_sha256"]),
                "language": (actual.get("language", ""), expected["language"]),
                "loc": (actual.get("loc", 0), expected["loc"]),
                "header_snippet": (
                    actual.get("header_snippet", ""),
                    expected["header_snippet"],
                ),
            }
            drifted = [
                field_name
                for field_name, (observed, wanted) in comparisons.items()
                if observed != wanted
            ]
            if drifted:
                raise SnapshotAttestationError(
                    f"staged source metadata differs for {file_path}: "
                    + ", ".join(drifted)
                )
        expected_analyzable = len(expected_paths)
        expected_total = expected_analyzable + self.excluded_non_directories
        expected_loc = sum(int(item["loc"]) for item in self.manifest_files.values())
        declared = {
            "analyzable_files": (metadata.get("analyzable_files"), expected_analyzable),
            "total_files": (metadata.get("total_files"), expected_total),
            "total_loc": (metadata.get("total_loc"), expected_loc),
        }
        drifted_counts = [
            name for name, (observed, wanted) in declared.items() if observed != wanted
        ]
        if drifted_counts:
            raise SnapshotAttestationError(
                "declared repository counts differ from sealed source manifest: "
                + ", ".join(drifted_counts)
            )

    def _verify_path_bindings(self) -> None:
        engagement_fd = snapshot_fd = source_fd = -1
        try:
            engagement_fd = _open_root_directory(self._engagement_path)
            snapshot_fd = _open_root_directory(self._snapshot_path)
            source_fd = _open_directory_at(snapshot_fd, "source")
            engagement_path_stat = os.fstat(engagement_fd)
            snapshot_path_stat = os.fstat(snapshot_fd)
            source_path_stat = os.fstat(source_fd)
        except OSError as exc:
            raise SnapshotAttestationError(
                "snapshot path changed after attestation"
            ) from exc
        finally:
            for fd in (source_fd, snapshot_fd, engagement_fd):
                if fd >= 0:
                    os.close(fd)
        if not _same_identity(engagement_path_stat, self._engagement_stat):
            raise SnapshotAttestationError("engagement root path changed after attestation")
        if not _same_identity(snapshot_path_stat, self._snapshot_stat):
            raise SnapshotAttestationError("snapshot root path changed after attestation")
        if not _same_identity(source_path_stat, self._source_stat):
            raise SnapshotAttestationError("snapshot source path changed after attestation")

    def verify_unchanged(self) -> None:
        """Recheck identities while the DB promotion transaction is still open."""
        if self._closed:
            raise SnapshotAttestationError("snapshot attestation is closed")
        try:
            identity_checks = (
                (os.fstat(self._engagement_fd), self._engagement_stat, "engagement root"),
                (os.fstat(self._snapshot_fd), self._snapshot_stat, "snapshot root"),
                (os.fstat(self._source_fd), self._source_stat, "snapshot source"),
                (
                    os.stat(
                        "manifest.json",
                        dir_fd=self._snapshot_fd,
                        follow_symlinks=False,
                    ),
                    self._manifest_stat,
                    "snapshot manifest",
                ),
            )
        except OSError as exc:
            raise SnapshotAttestationError(
                "snapshot entries changed after attestation"
            ) from exc
        for observed, expected, label in identity_checks:
            if not _same_identity(observed, expected):
                raise SnapshotAttestationError(f"{label} changed after attestation")

        for relative_dir, expected in self._directory_stats.items():
            try:
                fd = self._open_source_directory(relative_dir)
                try:
                    observed = os.fstat(fd)
                finally:
                    os.close(fd)
            except OSError as exc:
                raise SnapshotAttestationError(
                    f"sealed source directory changed after attestation: {relative_dir}"
                ) from exc
            if not _same_identity(observed, expected):
                raise SnapshotAttestationError(
                    f"sealed source directory changed after attestation: {relative_dir}"
                )
        for file_path, expected in self._file_stats.items():
            relative = _safe_relative_path(file_path)
            parent = (
                PurePosixPath(*relative.parts[:-1]).as_posix()
                if len(relative.parts) > 1
                else ""
            )
            try:
                parent_fd = self._open_source_directory(parent)
                try:
                    observed = os.stat(
                        relative.name, dir_fd=parent_fd, follow_symlinks=False
                    )
                finally:
                    os.close(parent_fd)
            except OSError as exc:
                raise SnapshotAttestationError(
                    f"sealed source file changed after attestation: {file_path}"
                ) from exc
            if not _same_identity(observed, expected):
                raise SnapshotAttestationError(
                    f"sealed source file changed after attestation: {file_path}"
                )
        # This must remain the final check: the nested identity walk above uses
        # pinned descriptors and therefore cannot itself prove that the public
        # lexical path was not swapped while those descriptors were inspected.
        self._verify_path_bindings()


def attest_verified_snapshot(
    *,
    engagement_root: str | os.PathLike[str],
    metadata: Mapping[str, Any],
) -> VerifiedSnapshotAttestation:
    """Independently verify one caller-requested sealed snapshot.

    The returned object intentionally keeps the engagement/snapshot/source root
    descriptors open. The commit service rechecks every attested identity before
    allowing its SQLite transaction to commit, closing the validation-to-promotion
    race without hashing repository bytes under the global write lock.
    """

    lexical_engagement_path = _lexical_absolute(
        os.fspath(engagement_root), label="engagement root"
    )
    try:
        engagement_path = lexical_engagement_path.resolve(strict=True)
    except OSError as exc:
        raise SnapshotAttestationError(
            f"engagement root cannot be resolved: {exc}"
        ) from exc
    repo_key = str(metadata.get("repo_key") or "")
    snapshot_digest = str(metadata.get("snapshot_digest") or "")
    if not repo_key or repo_key in {".", ".."} or "/" in repo_key or "\\" in repo_key:
        raise SnapshotAttestationError("repo_key is not one safe path component")
    if not _is_lower_sha256(snapshot_digest):
        raise SnapshotAttestationError("snapshot_digest is not a lowercase SHA-256")
    snapshot_path = (
        engagement_path
        / "tools"
        / "analysis-state"
        / "code-snapshots"
        / repo_key
        / snapshot_digest
    )
    expected_manifest_path = snapshot_path / "manifest.json"
    expected_source_path = snapshot_path / "source"
    if _lexical_absolute(
        metadata.get("snapshot_manifest_path"), label="snapshot_manifest_path"
    ) != expected_manifest_path:
        raise SnapshotAttestationError(
            "snapshot_manifest_path is not the exact engagement-owned sealed manifest"
        )
    if _lexical_absolute(metadata.get("repo_path"), label="repo_path") != expected_source_path:
        raise SnapshotAttestationError(
            "repo_path is not the exact engagement-owned sealed source"
        )

    engagement_fd = snapshot_fd = source_fd = -1
    try:
        engagement_fd = _open_root_directory(engagement_path)
        engagement_stat = os.fstat(engagement_fd)
        cursor_fd = os.dup(engagement_fd)
        try:
            for component in (
                "tools",
                "analysis-state",
                "code-snapshots",
                repo_key,
                snapshot_digest,
            ):
                next_fd = _open_directory_at(cursor_fd, component)
                os.close(cursor_fd)
                cursor_fd = next_fd
            snapshot_fd = cursor_fd
            cursor_fd = -1
        finally:
            if cursor_fd >= 0:
                os.close(cursor_fd)
        snapshot_stat = os.fstat(snapshot_fd)
        if stat.S_IMODE(snapshot_stat.st_mode) != 0o555:
            raise SnapshotAttestationError("sealed snapshot root must have mode 0555")

        manifest_bytes, _, manifest_stat = _read_regular_at(
            snapshot_fd,
            "manifest.json",
            display_path=expected_manifest_path,
            max_bytes=MAX_SEALED_MANIFEST_BYTES,
        )
        if stat.S_IMODE(manifest_stat.st_mode) != 0o444:
            raise SnapshotAttestationError("sealed snapshot manifest must have mode 0444")
        assert manifest_bytes is not None
        _validate_json_nesting(manifest_bytes)
        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise SnapshotAttestationError(
                "sealed snapshot manifest is not valid UTF-8 JSON"
            ) from exc
        if not isinstance(manifest, dict):
            raise SnapshotAttestationError("sealed snapshot manifest must be an object")
        if manifest.get("schema") != SEALED_SOURCE_MANIFEST_SCHEMA:
            raise SnapshotAttestationError("sealed snapshot manifest schema is unsupported")
        if manifest.get("repo_key") != repo_key:
            raise SnapshotAttestationError("sealed snapshot manifest repo_key mismatch")
        if manifest.get("snapshot_digest") != snapshot_digest:
            raise SnapshotAttestationError("sealed snapshot manifest digest mismatch")
        if manifest.get("source_path") != os.fspath(expected_source_path):
            raise SnapshotAttestationError("sealed snapshot manifest source_path mismatch")
        if manifest.get("repo_name") != metadata.get("name"):
            raise SnapshotAttestationError("sealed snapshot manifest repo_name mismatch")
        if manifest.get("source_origin_path") != metadata.get("source_origin_path"):
            raise SnapshotAttestationError(
                "sealed snapshot manifest source_origin_path mismatch"
            )
        raw_files = manifest.get("files")
        exclusions = manifest.get("excluded_entries")
        if not isinstance(raw_files, list) or not isinstance(exclusions, list):
            raise SnapshotAttestationError("sealed snapshot inventories are invalid")
        if any(not isinstance(row, dict) for row in raw_files):
            raise SnapshotAttestationError("sealed snapshot file record is invalid")
        if any(not isinstance(row, dict) for row in exclusions):
            raise SnapshotAttestationError("sealed snapshot exclusion is invalid")
        try:
            canonical_digest = _canonical_snapshot_digest(manifest)
        except RecursionError as exc:
            raise SnapshotAttestationError(
                "sealed snapshot manifest nesting is invalid"
            ) from exc
        if canonical_digest != snapshot_digest:
            raise SnapshotAttestationError(
                "sealed snapshot manifest content address mismatch"
            )
        review_identity_digest = _canonical_review_identity_digest(manifest)

        git = manifest.get("git")
        if not isinstance(git, dict):
            raise SnapshotAttestationError("sealed snapshot git provenance is invalid")
        source_kind = metadata.get("source_kind")
        expected_source_kind = "git" if str(git.get("head") or "") else "directory"
        if source_kind != expected_source_kind:
            raise SnapshotAttestationError(
                "source_kind differs from sealed snapshot git provenance"
            )
        git_bindings = {
            "commit_hash": (metadata.get("commit_hash", ""), git.get("head", "")),
            "branch": (metadata.get("branch", ""), git.get("branch", "")),
            "worktree_dirty": (metadata.get("worktree_dirty"), git.get("dirty")),
        }
        drifted_git = [
            name for name, (observed, expected) in git_bindings.items() if observed != expected
        ]
        if drifted_git:
            raise SnapshotAttestationError(
                "request differs from sealed snapshot git provenance: "
                + ", ".join(drifted_git)
            )

        manifest_files: dict[str, dict[str, Any]] = {}
        for raw_file in raw_files:
            if not isinstance(raw_file, dict):
                raise SnapshotAttestationError("sealed snapshot file record is invalid")
            file_path = _safe_relative_path(raw_file.get("file_path")).as_posix()
            if file_path in manifest_files:
                raise SnapshotAttestationError(
                    f"sealed snapshot has duplicate file path: {file_path}"
                )
            if not _is_lower_sha256(raw_file.get("source_sha256")):
                raise SnapshotAttestationError(
                    f"sealed snapshot has invalid source hash: {file_path}"
                )
            if (
                type(raw_file.get("size")) is not int
                or raw_file["size"] < 0
                or type(raw_file.get("loc")) is not int
                or raw_file["loc"] < 0
                or not isinstance(raw_file.get("language"), str)
                or type(raw_file.get("executable")) is not bool
            ):
                raise SnapshotAttestationError(
                    f"sealed snapshot file metadata is invalid: {file_path}"
                )
            manifest_files[file_path] = dict(raw_file)

        exclusion_paths: set[str] = set()
        excluded_non_directories = 0
        for raw_exclusion in exclusions:
            if not isinstance(raw_exclusion, dict):
                raise SnapshotAttestationError("sealed snapshot exclusion is invalid")
            exclusion_path = _safe_relative_path(raw_exclusion.get("path")).as_posix()
            if exclusion_path in exclusion_paths or exclusion_path in manifest_files:
                raise SnapshotAttestationError(
                    f"sealed snapshot has duplicate/overlapping exclusion: {exclusion_path}"
                )
            if not isinstance(raw_exclusion.get("kind"), str) or not raw_exclusion.get("kind"):
                raise SnapshotAttestationError(
                    f"sealed snapshot exclusion kind is invalid: {exclusion_path}"
                )
            if not isinstance(raw_exclusion.get("reason"), str) or not raw_exclusion.get("reason"):
                raise SnapshotAttestationError(
                    f"sealed snapshot exclusion reason is invalid: {exclusion_path}"
                )
            exclusion_paths.add(exclusion_path)
            if raw_exclusion["kind"] != "directory":
                excluded_non_directories += 1

        source_fd = _open_directory_at(snapshot_fd, "source")
        source_stat = os.fstat(source_fd)
        if stat.S_IMODE(source_stat.st_mode) != 0o555:
            raise SnapshotAttestationError("sealed snapshot source must have mode 0555")

        actual_files: dict[str, dict[str, Any]] = {}
        file_stats: dict[str, os.stat_result] = {}
        directory_stats: dict[str, os.stat_result] = {"": source_stat}
        pending = [""]
        while pending:
            relative_dir = pending.pop()
            directory_fd = os.dup(source_fd)
            if relative_dir:
                try:
                    for component in _safe_relative_path(relative_dir).parts:
                        next_fd = _open_directory_at(directory_fd, component)
                        os.close(directory_fd)
                        directory_fd = next_fd
                except Exception:
                    os.close(directory_fd)
                    raise
            try:
                observed_directory = os.fstat(directory_fd)
                if stat.S_IMODE(observed_directory.st_mode) != 0o555:
                    raise SnapshotAttestationError(
                        f"sealed source directory must have mode 0555: {relative_dir or '.'}"
                    )
                directory_stats[relative_dir] = observed_directory
                for name in os.listdir(directory_fd):
                    entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    file_path = f"{relative_dir}/{name}" if relative_dir else name
                    if stat.S_ISDIR(entry.st_mode):
                        if stat.S_IMODE(entry.st_mode) != 0o555:
                            raise SnapshotAttestationError(
                                f"sealed source directory must have mode 0555: {file_path}"
                            )
                        pending.append(file_path)
                        continue
                    if not stat.S_ISREG(entry.st_mode):
                        raise SnapshotAttestationError(
                            f"sealed source contains a symlink or special entry: {file_path}"
                        )
                    if file_path in actual_files:
                        raise SnapshotAttestationError(
                            f"sealed source has duplicate file path: {file_path}"
                        )
                    _, observed, observed_stat = _read_regular_at(
                        directory_fd,
                        name,
                        display_path=expected_source_path / file_path,
                        max_bytes=None,
                    )
                    expected_mode = 0o555 if observed["executable"] else 0o444
                    if stat.S_IMODE(observed_stat.st_mode) != expected_mode:
                        raise SnapshotAttestationError(
                            f"sealed source file permission drift: {file_path}"
                        )
                    actual_files[file_path] = observed
                    file_stats[file_path] = observed_stat
            finally:
                os.close(directory_fd)

        if set(actual_files) != set(manifest_files):
            missing = sorted(set(manifest_files) - set(actual_files))
            extra = sorted(set(actual_files) - set(manifest_files))
            raise SnapshotAttestationError(
                f"sealed source path set mismatch (missing={missing}, extra={extra})"
            )
        for file_path, expected in manifest_files.items():
            observed = actual_files[file_path]
            for field_name in ("source_sha256", "size", "loc", "executable"):
                if observed[field_name] != expected[field_name]:
                    raise SnapshotAttestationError(
                        f"sealed source {field_name} mismatch: {file_path}"
                    )
            expected["header_snippet"] = observed["header_snippet"]

        attestation = VerifiedSnapshotAttestation(
            snapshot_digest=snapshot_digest,
            review_identity_digest=review_identity_digest,
            manifest_files=manifest_files,
            excluded_non_directories=excluded_non_directories,
            _engagement_path=engagement_path,
            _snapshot_path=snapshot_path,
            _engagement_fd=engagement_fd,
            _snapshot_fd=snapshot_fd,
            _source_fd=source_fd,
            _engagement_stat=engagement_stat,
            _snapshot_stat=snapshot_stat,
            _source_stat=source_stat,
            _manifest_stat=manifest_stat,
            _directory_stats=directory_stats,
            _file_stats=file_stats,
        )
        engagement_fd = snapshot_fd = source_fd = -1
        return attestation
    except SnapshotAttestationError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, OSError) and exc.errno == errno.ELOOP:
            detail = "snapshot path contains a symlink"
        else:
            detail = str(exc) or exc.__class__.__name__
        raise SnapshotAttestationError(detail) from exc
    finally:
        for fd in (source_fd, snapshot_fd, engagement_fd):
            if fd >= 0:
                os.close(fd)


def source_manifest_digest(
    records: Iterable[Mapping[str, Any]],
    *,
    version: str = SOURCE_MANIFEST_VERSION,
) -> str:
    """Return the stable identity of a repository's analyzed source tree."""
    files = sorted(
        (
            {
                "file_path": str(record.get("file_path", "") or ""),
                "language": str(record.get("language", "") or ""),
                "source_sha256": str(record.get("file_hash", "") or ""),
            }
            for record in records
        ),
        key=lambda record: record["file_path"],
    )
    canonical = json.dumps(
        {"files": files, "version": version},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
