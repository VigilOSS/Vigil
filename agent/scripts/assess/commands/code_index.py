"""vigil assess code-index — generation-bound structural indexing."""
from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from assess.commands.code_ingest import SKIP_DIRS, _is_regular_file, _should_skip_file
from assess.lib.client import AssessmentClient
from assess.lib.code_snapshot import (
    MAX_JSON_ARTIFACT_BYTES,
    RootedSourceTree,
    SOURCE_MANIFEST_SCHEMA,
    capture_regular_file,
    read_bounded_regular_file,
    sealed_source_file_path,
    validate_repo_key,
    validate_snapshot,
)
from assess.lib.code_structural_identity import (
    STRUCTURAL_AGGREGATE_SCHEMA,
    STRUCTURAL_INDEX_PATH_VERSION,
    STRUCTURAL_INDEX_SCHEMA,
    bind_structural_inputs,
    fetch_backend_file_inventory,
    structural_input_digest,
)
from assess.lib.config import load_config, resolve_engagement_dir
from assess.lib.parser_boundary import ParserBoundaryCancelled, index_file
from assess.lib.treesitter_index import (
    SUPPORTED_LANGUAGES,
    STREAMING_FALLBACK_BASELINE_UNAVAILABLE,
    StreamingSecurityScanner,
    language_for_file,
)

DEFAULT_MAX_TREE_SITTER_BYTES = 8 * 1024 * 1024
LEGACY_STRUCTURAL_AGGREGATE_SCHEMA = "structural-index-aggregate/v3"
LEGACY_STRUCTURAL_AGGREGATE_ARCHIVE = Path(
    "structural-index/history/aggregates/v3"
)
LEGACY_STRUCTURAL_AGGREGATE_FIELDS = frozenset({"schema", "updated_at", "repos"})
LEGACY_STRUCTURAL_REPO_FIELDS = frozenset(
    {
        "analysis_status_counts",
        "artifact_truncated_file_paths",
        "artifact_truncated_files",
        "degraded_file_paths",
        "degraded_files",
        "manifest_path",
        "repo_generation",
        "repo_id",
        "repo_key",
        "source_manifest_digest",
        "structural_input_digest",
    }
)
LEGACY_STRUCTURAL_STATUS_FIELDS = frozenset(
    {"complete", "degraded", "unsupported"}
)
LOWER_HEX_DIGITS = frozenset("0123456789abcdef")
MAX_SQLITE_INTEGER = (1 << 63) - 1
SIGNAL_DIMENSIONS = (
    "entry_points",
    "imports",
    "security_sinks",
    "security_sources",
)
STRUCTURAL_RECORD_FIELDS = (
    "functions",
    "entry_points",
    "security_sinks",
    "security_sources",
    "call_sites",
    "imports",
    "import_targets",
    "exports",
    "classes",
)
UNAVAILABLE_RECORD_FIELDS = {
    "functions": ("functions",),
    "entry_points": ("entry_points",),
    "security_sinks": ("security_sinks",),
    "security_sources": ("security_sources",),
    "call_sites": ("call_sites",),
    "imports": ("imports", "import_targets"),
    "exports": ("exports",),
    "classes": ("classes",),
}


class _DuplicateJSONKeyError(ValueError):
    pass


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJSONKeyError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def register(subparsers) -> None:
    from assess.commands import code_index_sync

    parser = subparsers.add_parser(
        "code-index",
        help="Tree-sitter structural index for a sealed repository snapshot: build | sync",
    )
    action_sub = parser.add_subparsers(dest="code_index_action")
    _register_build(action_sub)
    code_index_sync.register_sync(action_sub)

    def _print_help(_args) -> None:
        parser.print_help()
        sys.exit(1)

    parser.set_defaults(func=_print_help)


def _register_build(subparsers) -> None:
    parser = subparsers.add_parser(
        "build",
        help="Build a structural index for a sealed code-ingest snapshot",
    )
    parser.add_argument("repo_path", metavar="snapshot", help="Sealed .../<digest>/source path")
    parser.add_argument(
        "--repo-id",
        type=int,
        default=None,
        help="Backend repository ID. If omitted, the snapshot path must match exactly one repo.",
    )
    parser.add_argument("--repo-key", default=None, help="Optional assertion for the snapshot repo_key")
    parser.add_argument("--repo-name", default=None, help="Optional human-readable name override")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output base (default: <engagement>/tools/analysis-state)",
    )
    parser.add_argument(
        "--file-list",
        default=None,
        help="Optional JSON subset of snapshot files to index",
    )
    parser.add_argument(
        "--max-tree-sitter-bytes",
        type=int,
        default=DEFAULT_MAX_TREE_SITTER_BYTES,
        help=(
            "Maximum source bytes materialized for Tree-sitter per file "
            f"(default: {DEFAULT_MAX_TREE_SITTER_BYTES}); larger files receive an "
            "all-bytes streaming security fallback"
        ),
    )
    parser.set_defaults(func=run)


def _walk_repo(repo_path: str) -> list[dict[str, str]]:
    """Compatibility inventory helper; authored builds use the sealed manifest."""
    files: list[dict[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(repo_path, followlinks=False):
        dirnames[:] = [
            name
            for name in dirnames
            if name not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, name))
        ]
        for filename in filenames:
            absolute = os.path.join(dirpath, filename)
            if not _is_regular_file(absolute):
                continue
            relative = os.path.relpath(absolute, repo_path).replace(os.sep, "/")
            if _should_skip_file(relative, filename):
                continue
            language = language_for_file(filename)
            if language and language in SUPPORTED_LANGUAGES:
                files.append({"file_path": relative, "language": language})
    return files


def _file_id(repo_id: int, repo_generation: int, rel_path: str) -> str:
    value = f"{repo_id}:{repo_generation}:{rel_path}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def _load_json_bytes(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = read_bounded_regular_file(
            path,
            max_bytes=MAX_JSON_ARTIFACT_BYTES,
            label=label,
        )
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object)
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJSONKeyError,
    ) as exc:
        raise ValueError(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(  # noqa: TRY004 - malformed artifacts are validation failures
            f"{label} must contain a JSON object: {path}"
        )
    return value, raw


def _load_json(path: Path, *, label: str) -> dict[str, Any]:
    value, _raw = _load_json_bytes(path, label=label)
    return value


def _load_snapshot(source_path: Path) -> dict[str, Any]:
    if source_path.name != "source":
        # Naming the fix, not just the rule: every repair hint that sends an
        # operator here prints a `<snapshot-path>` placeholder, and the snapshot
        # directory is the obvious thing to reach for. The index binds to the
        # sealed source tree inside it.
        raise ValueError(
            "code-index input must be the sealed snapshot source directory — "
            f"pass {source_path}/source, not the snapshot directory itself"
        )
    digest = source_path.parent.name
    manifest = validate_snapshot(source_path.parent, expected_digest=digest)
    if Path(str(manifest.get("source_path", ""))).resolve() != source_path:
        raise ValueError("source snapshot manifest path does not match the selected source")
    if manifest.get("schema") != SOURCE_MANIFEST_SCHEMA or len(digest) != 64:
        raise ValueError("source snapshot digest/path binding is invalid")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValueError(  # noqa: TRY004 - malformed artifacts are validation failures
            "source snapshot manifest files must be an array"
        )
    paths = [str(item.get("file_path", "")) for item in files if isinstance(item, dict)]
    if len(paths) != len(files) or len(set(paths)) != len(paths) or not all(paths):
        raise ValueError("source snapshot manifest contains invalid or duplicate file paths")
    for rel_path in paths:
        sealed_source_file_path(source_path, rel_path)
    return manifest


def _resolve_backend_repo(client: AssessmentClient, repo_id: int | None, source_path: Path) -> dict:
    if repo_id is not None:
        repo = client.get(f"code/repos/{repo_id}")
        if not isinstance(repo, dict):
            raise ValueError(f"backend repo {repo_id} returned an invalid response")
        return repo
    repos = client.get("code/repos")
    if not isinstance(repos, list):
        raise ValueError(  # noqa: TRY004 - invalid backend data cannot bind an index
            "backend repo listing returned an invalid response"
        )
    exact = [
        repo
        for repo in repos
        if isinstance(repo, dict)
        and repo.get("repo_path")
        and Path(str(repo["repo_path"])).resolve() == source_path
    ]
    if len(exact) != 1:
        raise ValueError(
            "omitting --repo-id requires the sealed snapshot path to match exactly one backend repo"
        )
    return exact[0]


def _select_files(
    manifest: dict[str, Any],
    file_list_path: str | None,
    *,
    language_by_path: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    by_path = {str(item["file_path"]): dict(item) for item in manifest["files"]}
    if language_by_path is not None:
        if set(language_by_path) != set(by_path):
            raise ValueError("backend/source language inventories differ")
        for rel_path, entry in by_path.items():
            entry["language"] = language_by_path[rel_path]
    if not file_list_path:
        return list(by_path.values())
    try:
        selected = json.loads(
            read_bounded_regular_file(
                Path(file_list_path),
                max_bytes=MAX_JSON_ARTIFACT_BYTES,
                label="--file-list",
            ).decode("utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read --file-list: {exc}") from exc
    if not isinstance(selected, list):
        raise ValueError(  # noqa: TRY004 - CLI document validation uses ValueError
            "--file-list must contain a JSON array"
        )
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in selected:
        if not isinstance(item, dict) or not item.get("file_path"):
            raise ValueError("--file-list entries require file_path")
        rel_path = str(item["file_path"])
        if rel_path in seen or rel_path not in by_path:
            raise ValueError(f"--file-list path is duplicate or absent from snapshot: {rel_path}")
        seen.add(rel_path)
        entry = dict(by_path[rel_path])
        if item.get("language"):
            requested_language = str(item["language"])
            if requested_language != str(entry.get("language") or ""):
                raise ValueError("--file-list cannot override authoritative languages")
        output.append(entry)
    if seen != set(by_path):
        raise ValueError(
            "partial structural generations are not publishable; --file-list must name every file"
        )
    return output


def _set_read_only(path: Path) -> None:
    for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
        for filename in files:
            os.chmod(Path(root) / filename, 0o444, follow_symlinks=False)
        for dirname in dirs:
            os.chmod(Path(root) / dirname, 0o555, follow_symlinks=False)
    os.chmod(path, 0o555, follow_symlinks=False)


def _remove_tree(path: Path) -> None:
    for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
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
    shutil.rmtree(path, ignore_errors=True)


def _validate_existing_generation(
    final_dir: Path,
    expected: dict[str, Any],
    structural_root: Path,
) -> dict[str, Any]:
    manifest_path = final_dir / "manifest.json"
    files_dir = final_dir / "files"
    for directory in (final_dir, files_dir):
        try:
            entry_stat = directory.lstat()
        except OSError as exc:
            raise ValueError(f"invalid existing structural index directory: {directory}") from exc
        if not stat.S_ISDIR(entry_stat.st_mode) or stat.S_IMODE(entry_stat.st_mode) != 0o555:
            raise ValueError(f"existing structural index directory drift: {directory}")
    try:
        manifest_stat = manifest_path.lstat()
    except OSError as exc:
        raise ValueError(f"invalid existing structural index manifest: {manifest_path}") from exc
    if not stat.S_ISREG(manifest_stat.st_mode) or stat.S_IMODE(manifest_stat.st_mode) != 0o444:
        raise ValueError(f"existing structural index manifest permission drift: {manifest_path}")
    try:
        existing = json.loads(
            read_bounded_regular_file(
                manifest_path,
                max_bytes=MAX_JSON_ARTIFACT_BYTES,
                label="existing structural index manifest",
            ).decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJSONKeyError,
    ) as exc:
        raise ValueError(f"invalid existing structural index manifest: {manifest_path}") from exc
    if not isinstance(existing, dict):
        raise ValueError(  # noqa: TRY004 - malformed artifacts are validation failures
            f"existing structural index manifest is not an object: {manifest_path}"
        )
    if set(existing) != set(expected):
        raise ValueError("existing generation-scoped index manifest fields conflict")

    stable_fields = (
        "schema",
        "repo_id",
        "repo_key",
        "repo_name",
        "repo_generation",
        "source_manifest_digest",
        "structural_input_digest",
        "source_path",
        "source_snapshot_manifest_path",
        "snapshot_digest",
        "manifest_path",
        "total_files",
        "indexed_files",
        "skipped_unsupported",
        "languages",
        "total_functions",
        "total_entry_points",
        "total_security_sinks",
        "total_exports",
        "degraded_files",
        "degraded_file_paths",
        "artifact_truncated_files",
        "artifact_truncated_file_paths",
        "analysis_status_counts",
        "files",
        "path_to_index",
    )
    if any(existing.get(field) != expected.get(field) for field in stable_fields):
        raise ValueError("existing generation-scoped index conflicts with the requested build")

    expected_files = expected.get("files")
    if not isinstance(expected_files, dict):
        raise ValueError(  # noqa: TRY004 - malformed artifacts are validation failures
            "requested structural index has an invalid file inventory"
        )
    expected_artifacts: set[Path] = set()
    for rel_path, binding in expected_files.items():
        if not isinstance(binding, dict):
            raise ValueError(  # noqa: TRY004 - malformed artifacts are validation failures
                f"invalid existing structural index binding: {rel_path}"
            )
        index_rel = Path(str(binding.get("index_path") or ""))
        if index_rel.is_absolute() or ".." in index_rel.parts:
            raise ValueError(f"unsafe existing structural index path: {index_rel}")
        index_path = structural_root / index_rel
        if index_path.parent != files_dir:
            raise ValueError(f"misbound existing structural index path: {index_path}")
        try:
            artifact_stat = index_path.lstat()
        except OSError as exc:
            raise ValueError(f"invalid existing structural index artifact: {index_path}") from exc
        if not stat.S_ISREG(artifact_stat.st_mode) or stat.S_IMODE(artifact_stat.st_mode) != 0o444:
            raise ValueError(f"existing structural index artifact permission drift: {index_path}")
        try:
            captured = capture_regular_file(index_path, retain_spool=False)
        except OSError as exc:
            raise ValueError(f"invalid existing structural index artifact: {index_path}") from exc
        if captured.sha256 != binding.get("index_sha256"):
            raise ValueError(f"existing structural index artifact hash mismatch: {index_path}")
        expected_artifacts.add(index_path)
    actual_artifacts = set(files_dir.iterdir())
    if actual_artifacts != expected_artifacts:
        raise ValueError("existing structural index artifact path-set mismatch")
    return existing


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    """Persist directory-entry changes where the host filesystem supports it."""
    try:
        directory_fd = os.open(path, os.O_RDONLY)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EINVAL, errno.ENOTSUP}:
            return
        raise
    try:
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EINVAL, errno.ENOTSUP}:
                raise
    finally:
        os.close(directory_fd)


def _fsync_directory_strict(path: Path) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    if not nofollow or not directory or not nonblock:
        raise RuntimeError(
            "structural index durability requires O_NOFOLLOW, O_DIRECTORY, and O_NONBLOCK"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | nofollow
        | directory
        | nonblock
    )
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"invalid structural index durability directory: {path}") from exc
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ValueError(f"invalid structural index durability directory: {path}")
        os.fsync(fd)
        after = os.fstat(fd)
        current_after = path.lstat()
        if (
            not stat.S_ISDIR(current_after.st_mode)
            or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
            or (after.st_dev, after.st_ino)
            != (current_after.st_dev, current_after.st_ino)
        ):
            raise ValueError(f"structural index durability directory changed: {path}")
    finally:
        os.close(fd)


def _nearest_existing_directory(path: Path) -> Path:
    current = path
    while True:
        try:
            entry = current.lstat()
        except FileNotFoundError:
            parent = current.parent
            if parent == current:
                raise ValueError(f"structural index path has no existing ancestor: {path}")
            current = parent
            continue
        except OSError as exc:
            raise ValueError(f"invalid structural index directory: {current}") from exc
        if not stat.S_ISDIR(entry.st_mode):
            raise ValueError(f"invalid structural index directory: {current}")
        return current


def _ensure_safe_directory_chain(path: Path, anchor: Path) -> None:
    try:
        components = path.relative_to(anchor).parts
    except ValueError as exc:
        raise ValueError(f"structural index path escapes durable anchor: {path}") from exc
    current = anchor
    for component in components:
        child = current / component
        try:
            child.mkdir(mode=0o755)
        except FileExistsError:
            try:
                entry = child.lstat()
            except OSError as exc:
                raise ValueError(f"invalid structural index directory: {child}") from exc
            if not stat.S_ISDIR(entry.st_mode) or stat.S_IMODE(entry.st_mode) & 0o022:
                raise ValueError(f"invalid structural index directory: {child}")
        else:
            os.chmod(child, 0o755, follow_symlinks=False)
        current = child


def _fsync_directory_chain(path: Path, anchor: Path) -> None:
    try:
        path.relative_to(anchor)
    except ValueError as exc:
        raise ValueError(f"structural index path escapes durable anchor: {path}") from exc
    current = path
    while True:
        _fsync_directory_strict(current)
        if current == anchor:
            return
        current = current.parent


def _regular_file_identity(entry: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        entry.st_dev,
        entry.st_ino,
        entry.st_size,
        entry.st_mtime_ns,
        entry.st_ctime_ns,
    )


def _fsync_regular_file(path: Path) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    if not nofollow or not nonblock:
        raise RuntimeError("structural index durability requires O_NOFOLLOW and O_NONBLOCK")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | nonblock
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"invalid structural index durability file: {path}") from exc
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or _regular_file_identity(opened) != _regular_file_identity(current)
        ):
            raise ValueError(f"invalid structural index durability file: {path}")
        os.fsync(fd)
        after = os.fstat(fd)
        current_after = path.lstat()
        if (
            not stat.S_ISREG(current_after.st_mode)
            or _regular_file_identity(opened) != _regular_file_identity(after)
            or _regular_file_identity(after) != _regular_file_identity(current_after)
        ):
            raise ValueError(f"structural index durability file changed: {path}")
    finally:
        os.close(fd)


def _fsync_generation_tree(generation_dir: Path) -> None:
    files_dir = generation_dir / "files"
    manifest_path = generation_dir / "manifest.json"
    for directory in (generation_dir, files_dir):
        try:
            entry = directory.lstat()
        except OSError as exc:
            raise ValueError(f"invalid structural index durability directory: {directory}") from exc
        if not stat.S_ISDIR(entry.st_mode):
            raise ValueError(f"invalid structural index durability directory: {directory}")
    try:
        artifacts = sorted(files_dir.iterdir(), key=lambda candidate: candidate.name)
    except OSError as exc:
        raise ValueError(f"invalid structural index durability directory: {files_dir}") from exc
    for artifact in artifacts:
        _fsync_regular_file(artifact)
    _fsync_directory_strict(files_dir)
    _fsync_regular_file(manifest_path)
    _fsync_directory_strict(generation_dir)


def _open_structural_lock(path: Path) -> Any:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    if not nofollow or not nonblock:
        raise RuntimeError("structural index locking requires O_NOFOLLOW and O_NONBLOCK")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | nofollow | nonblock
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ValueError(f"invalid structural index lock file: {path}") from exc
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or opened.st_nlink != 1
            or opened.st_size != 0
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) & 0o022
        ):
            raise ValueError(f"invalid structural index lock file: {path}")
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        _fsync_directory(path.parent)
        return os.fdopen(fd, "r+b", buffering=0)
    except Exception:
        os.close(fd)
        raise


def _is_positive_int(value: object) -> bool:
    return type(value) is int and 0 < value <= MAX_SQLITE_INTEGER


def _is_nonnegative_int(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_SQLITE_INTEGER


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value) <= LOWER_HEX_DIGITS
    )


def _is_canonical_file_path(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and all(component not in {"", ".", ".."} for component in path.parts)
    )


def _is_sorted_unique_file_paths(value: object) -> bool:
    return (
        isinstance(value, list)
        and all(_is_canonical_file_path(item) for item in value)
        and value == sorted(set(value))
    )


def _invalid_legacy_aggregate(reason: str) -> ValueError:
    return ValueError(f"invalid legacy structural index aggregate: {reason}")


def _validate_legacy_aggregate(aggregate: dict[str, Any]) -> None:
    if set(aggregate) != LEGACY_STRUCTURAL_AGGREGATE_FIELDS:
        raise _invalid_legacy_aggregate("unexpected top-level fields")
    updated_at = aggregate.get("updated_at")
    if not isinstance(updated_at, str):
        raise _invalid_legacy_aggregate("updated_at is not a UTC timestamp")
    try:
        parsed_updated_at = datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise _invalid_legacy_aggregate("updated_at is not a UTC timestamp") from exc
    if parsed_updated_at.strftime("%Y-%m-%dT%H:%M:%SZ") != updated_at:
        raise _invalid_legacy_aggregate("updated_at is not a canonical UTC timestamp")

    repos = aggregate.get("repos")
    if not isinstance(repos, dict) or not repos:
        raise _invalid_legacy_aggregate("repos must be a non-empty object")
    for map_key, summary in repos.items():
        if not isinstance(summary, dict) or set(summary) != LEGACY_STRUCTURAL_REPO_FIELDS:
            raise _invalid_legacy_aggregate(f"repo {map_key} has unexpected summary fields")
        repo_id = summary.get("repo_id")
        generation = summary.get("repo_generation")
        source_digest = summary.get("source_manifest_digest")
        input_digest = summary.get("structural_input_digest")
        if not _is_positive_int(repo_id) or map_key != str(repo_id):
            raise _invalid_legacy_aggregate(f"repo {map_key} has an invalid identity")
        repo_key = summary.get("repo_key")
        try:
            if not isinstance(repo_key, str) or validate_repo_key(repo_key) != repo_key:
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise _invalid_legacy_aggregate(f"repo {map_key} has an invalid repo_key") from exc
        if not _is_positive_int(generation):
            raise _invalid_legacy_aggregate(f"repo {map_key} has an invalid generation")
        if not _is_sha256(source_digest) or not _is_sha256(input_digest):
            raise _invalid_legacy_aggregate(f"repo {map_key} has an invalid digest")
        expected_manifest_path = PurePosixPath(
            "structural-index",
            map_key,
            str(generation),
            "v4",
            str(source_digest),
            str(input_digest),
            "manifest.json",
        )
        if summary.get("manifest_path") != str(expected_manifest_path):
            raise _invalid_legacy_aggregate(f"repo {map_key} has a misbound manifest path")

        degraded_count = summary.get("degraded_files")
        degraded_paths = summary.get("degraded_file_paths")
        truncated_count = summary.get("artifact_truncated_files")
        truncated_paths = summary.get("artifact_truncated_file_paths")
        if (
            not _is_nonnegative_int(degraded_count)
            or not _is_sorted_unique_file_paths(degraded_paths)
            or degraded_count != len(degraded_paths)
        ):
            raise _invalid_legacy_aggregate(f"repo {map_key} has invalid degraded debt")
        if (
            not _is_nonnegative_int(truncated_count)
            or not _is_sorted_unique_file_paths(truncated_paths)
            or truncated_count != len(truncated_paths)
        ):
            raise _invalid_legacy_aggregate(f"repo {map_key} has invalid truncation debt")
        status_counts = summary.get("analysis_status_counts")
        if (
            not isinstance(status_counts, dict)
            or set(status_counts) != LEGACY_STRUCTURAL_STATUS_FIELDS
            or not all(_is_nonnegative_int(value) for value in status_counts.values())
            or status_counts["degraded"] != degraded_count
            or truncated_count > sum(status_counts.values())
        ):
            raise _invalid_legacy_aggregate(f"repo {map_key} has invalid status counts")


def _archive_directory(out_base: Path) -> Path:
    current = out_base
    for component in LEGACY_STRUCTURAL_AGGREGATE_ARCHIVE.parts:
        child = current / component
        try:
            child.mkdir(mode=0o755)
        except FileExistsError:
            try:
                existing = child.lstat()
            except OSError as exc:
                raise ValueError(f"invalid structural aggregate archive directory: {child}") from exc
            if (
                not stat.S_ISDIR(existing.st_mode)
                or child.is_symlink()
                or stat.S_IMODE(existing.st_mode) & 0o022
            ):
                raise ValueError(f"invalid structural aggregate archive directory: {child}")
        else:
            os.chmod(child, 0o755, follow_symlinks=False)
            _fsync_directory(child)
            _fsync_directory(current)
        current = child
    return current


def _validate_legacy_archive(path: Path, expected: bytes) -> None:
    try:
        archive_stat = path.lstat()
    except OSError as exc:
        raise ValueError(f"invalid archived structural index aggregate: {path}") from exc
    if not stat.S_ISREG(archive_stat.st_mode):
        raise ValueError(f"invalid archived structural index aggregate: {path}")
    if stat.S_IMODE(archive_stat.st_mode) != 0o444:
        raise ValueError(f"conflicting archived structural index aggregate: {path}")
    try:
        actual = read_bounded_regular_file(
            path,
            max_bytes=MAX_JSON_ARTIFACT_BYTES,
            label="archived structural index aggregate",
        )
    except OSError as exc:
        raise ValueError(f"invalid archived structural index aggregate: {path}") from exc
    if actual != expected:
        raise ValueError(f"conflicting archived structural index aggregate: {path}")


def _archive_legacy_aggregate(out_base: Path, raw: bytes) -> Path:
    archive_dir = _archive_directory(out_base)
    archive_path = archive_dir / f"{hashlib.sha256(raw).hexdigest()}.json"
    if archive_path.exists() or archive_path.is_symlink():
        _validate_legacy_archive(archive_path, raw)
        return archive_path

    fd, temporary_name = tempfile.mkstemp(prefix=f".{archive_path.name}.", dir=archive_dir)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fchmod(handle.fileno(), 0o444)
            os.fsync(handle.fileno())
        try:
            os.link(temporary, archive_path, follow_symlinks=False)
        except FileExistsError:
            _validate_legacy_archive(archive_path, raw)
        else:
            _fsync_directory(archive_dir)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    finally:
        temporary.unlink(missing_ok=True)
    return archive_path


def _publish_aggregate(out_base: Path, repo_id: int, manifest_path: Path, manifest: dict) -> Path:
    aggregate_path = out_base / "structural-index-manifest.json"
    lock_path = out_base / ".structural-index.lock"
    out_base.mkdir(parents=True, exist_ok=True)
    with _open_structural_lock(lock_path) as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if aggregate_path.exists() or aggregate_path.is_symlink():
            existing, aggregate_bytes = _load_json_bytes(
                aggregate_path,
                label="structural index aggregate",
            )
            schema = existing.get("schema")
            repos = existing.get("repos")
            if not isinstance(repos, dict):
                raise ValueError("structural index aggregate repos must contain an object")
            if schema == LEGACY_STRUCTURAL_AGGREGATE_SCHEMA:
                _validate_legacy_aggregate(existing)
                _archive_legacy_aggregate(out_base, aggregate_bytes)
                repos = {}
            elif schema != STRUCTURAL_AGGREGATE_SCHEMA:
                raise ValueError(
                    f"structural index aggregate must use {STRUCTURAL_AGGREGATE_SCHEMA}; "
                    f"build can archive only known {LEGACY_STRUCTURAL_AGGREGATE_SCHEMA} "
                    "aggregates; migrate this artifact explicitly"
                )
        else:
            repos = {}
        repos[str(repo_id)] = {
            "repo_id": repo_id,
            "repo_key": manifest["repo_key"],
            "repo_generation": manifest["repo_generation"],
            "source_manifest_digest": manifest["source_manifest_digest"],
            "structural_input_digest": manifest["structural_input_digest"],
            "manifest_path": str(manifest_path.relative_to(out_base)),
            "degraded_files": manifest["degraded_files"],
            "degraded_file_paths": manifest["degraded_file_paths"],
            "artifact_truncated_files": manifest["artifact_truncated_files"],
            "artifact_truncated_file_paths": manifest[
                "artifact_truncated_file_paths"
            ],
            "analysis_status_counts": manifest["analysis_status_counts"],
        }
        payload = {
            "schema": STRUCTURAL_AGGREGATE_SCHEMA,
            # This file sits at a stable, guessable, top-level path and shares a
            # stem with the per-repo manifest, so a consumer without a populated
            # structural_index_manifest_path finds it by name and reads it
            # against the per-repo schema — getting nulls for every field rather
            # than an error. It announces what it is instead of answering.
            "kind": "aggregate",
            "per_repo_manifest_hint": (
                "resolve repos[<repo_id>].manifest_path; path_to_index lives in "
                "the per-repo manifest, not here"
            ),
            "updated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "repos": repos,
        }
        _atomic_json(aggregate_path, payload)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    return aggregate_path


def _unsupported_index(rel_path: str, language: str, *, source_size: int) -> dict[str, Any]:
    return {
        "file_path": rel_path,
        "language": language,
        "structural_index_available": False,
        "analysis_status": "unsupported",
        "analysis_mode": "none",
        "degradation_reason": "unsupported_language",
        "source_size": source_size,
        "bytes_scanned": source_size,
        "unavailable_dimensions": [
            "call_sites",
            "classes",
            "dataflow",
            "entry_points",
            "exports",
            "functions",
            "imports",
            "security_sinks",
            "security_sources",
        ],
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
        "total_lines": 0,
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


def _validate_analysis_artifact(
    indexed: dict[str, Any],
    *,
    rel_path: str,
    source_size: int,
) -> None:
    status = indexed.get("analysis_status")
    mode = indexed.get("analysis_mode")
    available = indexed.get("structural_index_available")
    if status not in {"complete", "degraded", "unsupported"}:
        raise ValueError(f"structural analysis status is invalid for {rel_path}")
    if not isinstance(available, bool):
        raise ValueError(f"structural availability is missing for {rel_path}")
    if indexed.get("source_size") != source_size or indexed.get("bytes_scanned") != source_size:
        raise ValueError(f"structural scan byte accounting differs for {rel_path}")
    truncated = indexed.get("artifact_truncated")
    if not isinstance(truncated, bool):
        raise ValueError(f"structural truncation status is missing for {rel_path}")
    if truncated and status != "degraded":
        raise ValueError(f"truncated structural analysis must be degraded for {rel_path}")
    if status == "complete" and (
        not available
        or truncated
        or mode not in {"tree_sitter", "lightweight_regex"}
        or indexed.get("degradation_reason")
        or indexed.get("unavailable_dimensions")
    ):
        raise ValueError(f"complete structural analysis is inconsistent for {rel_path}")
    if status == "unsupported" and (
        available
        or mode != "none"
        or indexed.get("degradation_reason") != "unsupported_language"
        or not indexed.get("unavailable_dimensions")
    ):
        raise ValueError(f"unsupported structural analysis is inconsistent for {rel_path}")
    if status == "degraded":
        if mode == "streaming_security_fallback":
            if (
                available
                or not indexed.get("degradation_reason")
                or not STREAMING_FALLBACK_BASELINE_UNAVAILABLE.issubset(
                    indexed.get("unavailable_dimensions") or []
                )
            ):
                raise ValueError(f"streaming fallback debt is incomplete for {rel_path}")
        elif not (
            mode in {"tree_sitter", "lightweight_regex"}
            and
            available
            and truncated
            and indexed.get("degradation_reason") == "artifact_signal_limit"
        ):
            raise ValueError(f"degraded structural analysis is inconsistent for {rel_path}")
    counts = indexed.get("signal_counts")
    if not isinstance(counts, dict) or set(counts) != set(SIGNAL_DIMENSIONS) or any(
        not isinstance(counts.get(dimension), int) or int(counts[dimension]) < 0
        for dimension in SIGNAL_DIMENSIONS
    ):
        raise ValueError(f"structural signal counts are invalid for {rel_path}")
    for field in STRUCTURAL_RECORD_FIELDS:
        if not isinstance(indexed.get(field), list):
            raise ValueError(f"structural {field} records are invalid for {rel_path}")
    if not isinstance(indexed.get("total_functions"), int) or int(
        indexed["total_functions"]
    ) < 0:
        raise ValueError(f"structural function total is invalid for {rel_path}")
    if not isinstance(indexed.get("total_exports"), int) or int(indexed["total_exports"]) < 0:
        raise ValueError(f"structural export total is invalid for {rel_path}")
    if status == "unsupported" and (
        int(indexed["total_functions"]) != 0
        or int(indexed["total_exports"]) != 0
        or any(int(counts[dimension]) for dimension in SIGNAL_DIMENSIONS)
        or any(indexed[field] for field in STRUCTURAL_RECORD_FIELDS)
    ):
        raise ValueError(f"unsupported structural analysis contains signals for {rel_path}")
    retained_counts = {
        "entry_points": len(indexed["entry_points"]),
        "imports": max(len(indexed["imports"]), len(indexed["import_targets"])),
        "security_sinks": len(indexed["security_sinks"]),
        "security_sources": len(indexed["security_sources"]),
    }
    if any(int(counts[dimension]) < retained_counts[dimension] for dimension in SIGNAL_DIMENSIONS):
        raise ValueError(f"structural signal totals undercount retained records for {rel_path}")
    if int(indexed["total_exports"]) < len(indexed["exports"]):
        raise ValueError(f"structural export total undercounts retained records for {rel_path}")
    unavailable = set(indexed.get("unavailable_dimensions") or [])
    unavailable_signals = unavailable.intersection(SIGNAL_DIMENSIONS)
    if (
        any(int(counts[dimension]) for dimension in unavailable_signals)
        or ("functions" in unavailable and int(indexed["total_functions"]) != 0)
        or ("exports" in unavailable and int(indexed["total_exports"]) != 0)
        or any(
            any(indexed[field] for field in fields)
            for dimension, fields in UNAVAILABLE_RECORD_FIELDS.items()
            if dimension in unavailable
        )
    ):
        raise ValueError(f"unavailable structural dimension contains signals for {rel_path}")


def run(args) -> None:
    source_path = Path(args.repo_path).resolve()
    if not source_path.is_dir():
        print(f"Sealed snapshot source not found: {source_path}", file=sys.stderr)
        sys.exit(1)
    try:
        source_manifest = _load_snapshot(source_path)
    except ValueError as exc:
        print(f"Cannot index source: {exc}", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(getattr(args, "engagement_dir", None))
    try:
        with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
            backend_repo = _resolve_backend_repo(client, getattr(args, "repo_id", None), source_path)
            repo_id = int(backend_repo.get("id") or backend_repo.get("repo_id") or 0)
            if repo_id < 1:
                raise ValueError("backend repo has no valid ID")
            generation = int(backend_repo.get("active_generation") or 0)
            source_digest = str(backend_repo.get("source_manifest_digest") or "")
            repo_key = str(source_manifest.get("repo_key") or "")
            backend_repo_key = str(backend_repo.get("repo_key") or "")
            if generation < 1:
                raise ValueError("backend repo is not on a published generation")
            if Path(str(backend_repo.get("repo_path") or "")).resolve() != source_path:
                raise ValueError("backend repo path differs from snapshot")
            if len(source_digest) != 64:
                raise ValueError("backend has no valid source manifest digest")
            if not repo_key or backend_repo_key != repo_key:
                raise ValueError("backend repo_key differs from snapshot")
            requested_key = getattr(args, "repo_key", None)
            if requested_key and requested_key != repo_key:
                raise ValueError("--repo-key differs from snapshot")
            backend_files = fetch_backend_file_inventory(client, repo_id)
    except ValueError as exc:
        print(f"Cannot bind structural index: {exc}", file=sys.stderr)
        sys.exit(1)

    snapshot_digest = str(source_manifest["snapshot_digest"])

    try:
        bound_inputs = bind_structural_inputs(
            source_manifest["files"],
            backend_files,
            repo_id=repo_id,
        )
        input_digest = structural_input_digest(
            bound_inputs,
            repo_id=repo_id,
            repo_generation=generation,
            source_manifest_digest=source_digest,
        )
    except ValueError as exc:
        print(f"Cannot bind structural index: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.output_dir:
        out_base = Path(args.output_dir).resolve()
    else:
        try:
            engagement = resolve_engagement_dir(getattr(args, "engagement_dir", None))
        except SystemExit:
            print("Cannot resolve engagement directory for structural index output", file=sys.stderr)
            sys.exit(1)
        out_base = Path(engagement).resolve() / "tools" / "analysis-state"

    try:
        selected = _select_files(
            source_manifest,
            getattr(args, "file_list", None),
            language_by_path={
                rel_path: str(binding["language"])
                for rel_path, binding in bound_inputs.items()
            },
        )
    except ValueError as exc:
        print(f"Cannot select snapshot files: {exc}", file=sys.stderr)
        sys.exit(1)
    max_tree_sitter_bytes = int(
        getattr(args, "max_tree_sitter_bytes", DEFAULT_MAX_TREE_SITTER_BYTES)
    )
    if max_tree_sitter_bytes < 1:
        print("Cannot build structural index: --max-tree-sitter-bytes must be positive", file=sys.stderr)
        sys.exit(1)

    structural_root = out_base / "structural-index"
    generation_parent = structural_root / str(repo_id) / str(generation)
    identity_parent = generation_parent / STRUCTURAL_INDEX_PATH_VERSION / source_digest
    try:
        durable_anchor = _nearest_existing_directory(out_base)
        _ensure_safe_directory_chain(identity_parent, durable_anchor)
    except (OSError, ValueError) as exc:
        print(f"Cannot prepare structural index output: {exc}", file=sys.stderr)
        sys.exit(1)
    final_dir = identity_parent / input_digest
    stage = Path(tempfile.mkdtemp(prefix=f".{input_digest}.stage-", dir=identity_parent))
    files_dir = stage / "files"
    files_dir.mkdir()

    lang_counts: dict[str, int] = {}
    totals = {
        "total_functions": 0,
        "total_entry_points": 0,
        "total_security_sinks": 0,
        "total_exports": 0,
    }
    files_manifest: dict[str, dict[str, Any]] = {}
    skipped_unsupported = 0
    degraded_file_paths: list[str] = []
    truncated_file_paths: list[str] = []
    analysis_status_counts = {"complete": 0, "degraded": 0, "unsupported": 0}
    try:
        with RootedSourceTree(source_path) as source_tree:
            for entry in selected:
                rel_path = str(entry["file_path"])
                language = str(entry["language"])
                absolute = sealed_source_file_path(source_path, rel_path)
                supported = language in SUPPORTED_LANGUAGES
                scanner = (
                    StreamingSecurityScanner(rel_path, language)
                    if supported and int(entry.get("size") or 0) > max_tree_sitter_bytes
                    else None
                )
                captured = source_tree.capture(
                    rel_path,
                    retain_spool=False,
                    materialize_limit=max_tree_sitter_bytes if supported else None,
                    chunk_consumer=scanner.feed if scanner is not None else None,
                )
                if captured.sha256 != entry.get("source_sha256") or captured.size != entry.get("size"):
                    raise ValueError(f"snapshot file no longer matches manifest: {rel_path}")
                if supported and captured.materialized is not None:
                    indexed = index_file(
                        str(absolute),
                        language,
                        source=captured.materialized,
                        result_validator=lambda result: _validate_analysis_artifact(
                            result,
                            rel_path=rel_path,
                            source_size=captured.size,
                        ),
                    )
                elif supported and scanner is not None:
                    indexed = scanner.finish(degradation_reason="tree_sitter_resource_limit")
                else:
                    skipped_unsupported += 1
                    indexed = _unsupported_index(rel_path, language, source_size=captured.size)
                    indexed["total_lines"] = captured.loc
                if indexed.get("language") != language:
                    raise ValueError(f"structural parser language differs for {rel_path}")
                _validate_analysis_artifact(
                    indexed,
                    rel_path=rel_path,
                    source_size=captured.size,
                )
                signal_counts = indexed["signal_counts"]
                indexed["total_entry_points"] = int(signal_counts["entry_points"])
                indexed["total_security_sinks"] = int(signal_counts["security_sinks"])
                indexed.update(
                    {
                        "file_path": rel_path,
                        "repo_id": repo_id,
                        "repo_generation": generation,
                        "source_manifest_digest": source_digest,
                        "structural_input_digest": input_digest,
                        "source_sha256": captured.sha256,
                    }
                )
                filename = f"{_file_id(repo_id, generation, rel_path)}.json"
                path = files_dir / filename
                index_bytes = (json.dumps(indexed, indent=2, sort_keys=True) + "\n").encode("utf-8")
                path.write_bytes(index_bytes)
                files_manifest[rel_path] = {
                    "index_path": str((final_dir / "files" / filename).relative_to(structural_root)),
                    "source_sha256": captured.sha256,
                    "language": language,
                    "index_sha256": hashlib.sha256(index_bytes).hexdigest(),
                    "analysis_status": indexed["analysis_status"],
                    "analysis_mode": indexed["analysis_mode"],
                    "artifact_truncated": indexed["artifact_truncated"],
                }
                lang_counts[language] = lang_counts.get(language, 0) + 1
                status = str(indexed["analysis_status"])
                analysis_status_counts[status] += 1
                if status == "degraded":
                    degraded_file_paths.append(rel_path)
                if indexed["artifact_truncated"]:
                    truncated_file_paths.append(rel_path)
                totals["total_functions"] += int(indexed.get("total_functions", 0))
                totals["total_entry_points"] += int(signal_counts["entry_points"])
                totals["total_security_sinks"] += int(signal_counts["security_sinks"])
                totals["total_exports"] += int(indexed["total_exports"])
            source_tree.verify_root_identity()

        with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
            current_repo = _resolve_backend_repo(client, repo_id, source_path)
            current_files = fetch_backend_file_inventory(client, repo_id)
        current_repo_binding = (
            int(current_repo.get("id") or current_repo.get("repo_id") or 0),
            str(current_repo.get("repo_key") or ""),
            Path(str(current_repo.get("repo_path") or "")).resolve(),
            int(current_repo.get("active_generation") or 0),
            str(current_repo.get("source_manifest_digest") or ""),
        )
        initial_repo_binding = (
            repo_id,
            backend_repo_key,
            source_path,
            generation,
            source_digest,
        )
        current_inputs = bind_structural_inputs(
            source_manifest["files"],
            current_files,
            repo_id=repo_id,
        )
        current_input_digest = structural_input_digest(
            current_inputs,
            repo_id=repo_id,
            repo_generation=int(current_repo.get("active_generation") or 0),
            source_manifest_digest=str(current_repo.get("source_manifest_digest") or ""),
        )
        if current_repo_binding != initial_repo_binding or current_input_digest != input_digest:
            raise ValueError("backend repo/files changed during structural indexing")

        repo_name = getattr(args, "repo_name", None) or source_manifest.get("repo_name") or repo_key
        manifest_path = final_dir / "manifest.json"
        manifest = {
            "schema": STRUCTURAL_INDEX_SCHEMA,
            "repo_id": repo_id,
            "repo_key": repo_key,
            "repo_name": repo_name,
            "repo_generation": generation,
            "source_manifest_digest": source_digest,
            "structural_input_digest": input_digest,
            "source_path": str(source_path),
            "source_snapshot_manifest_path": str(source_path.parent / "manifest.json"),
            "snapshot_digest": snapshot_digest,
            "manifest_path": str(manifest_path),
            "indexed_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_files": len(selected),
            "indexed_files": len(files_manifest),
            "skipped_unsupported": skipped_unsupported,
            "degraded_files": len(degraded_file_paths),
            "degraded_file_paths": sorted(degraded_file_paths),
            "artifact_truncated_files": len(truncated_file_paths),
            "artifact_truncated_file_paths": sorted(truncated_file_paths),
            "analysis_status_counts": analysis_status_counts,
            "languages": lang_counts,
            **totals,
            "files": files_manifest,
            "path_to_index": {
                path: binding["index_path"] for path, binding in files_manifest.items()
            },
        }
        (stage / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _set_read_only(stage)
        os.chmod(stage, 0o700, follow_symlinks=False)
        if final_dir.exists():
            _remove_tree(stage)
            manifest = _validate_existing_generation(final_dir, manifest, structural_root)
            _fsync_generation_tree(final_dir)
        else:
            _fsync_generation_tree(stage)
            _fsync_directory_chain(identity_parent, durable_anchor)
            try:
                os.rename(stage, final_dir)
                os.chmod(final_dir, 0o555, follow_symlinks=False)
                manifest = _validate_existing_generation(final_dir, manifest, structural_root)
                _fsync_directory_strict(final_dir)
            except OSError:
                if not final_dir.exists():
                    raise
                _remove_tree(stage)
                manifest = _validate_existing_generation(final_dir, manifest, structural_root)
                _fsync_generation_tree(final_dir)
        _fsync_directory_chain(identity_parent, durable_anchor)
        aggregate = _publish_aggregate(out_base, repo_id, manifest_path, manifest)
    except (KeyboardInterrupt, ParserBoundaryCancelled):
        _remove_tree(stage)
        raise
    except Exception as exc:  # noqa: BLE001 - parser failures must abort atomic publication
        _remove_tree(stage)
        print(f"Structural index build failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print("\n=== Structural Index Summary ===", file=sys.stderr)
    print(
        f"Repository: {repo_name} (repo_id={repo_id}, generation={generation})",
        file=sys.stderr,
    )
    print(f"Source digest: {source_digest}", file=sys.stderr)
    print(f"Indexed files: {len(files_manifest)}", file=sys.stderr)
    print(f"Per-repo manifest: {manifest_path}", file=sys.stderr)
    print(f"Aggregate manifest: {aggregate}", file=sys.stderr)
    print("\nRun 'code-index sync' to push structural metadata to the backend.", file=sys.stderr)
