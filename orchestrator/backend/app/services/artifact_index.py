from __future__ import annotations

import datetime as dt
import errno
import hashlib
import mimetypes
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, status

from ..db import get_connection
from .events import _engagement_or_404
from .search import canonical_finding_alias, expanded_fts_query

PREVIEW_BYTES = 4096
# Verified command-output registration receives a bounded sample from the
# retention owner. Ordinary registered text is indexed in full below; this
# remaining sealed-output boundary is reported as ``index_status=partial``.
VERIFIED_OUTPUT_INDEX_BYTES = 16384
GET_CONTENT_BYTES = 65536


def _utcnow_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _escape_like(value: str) -> str:
    """Escape SQL LIKE metacharacters with a backslash.

    Callers must pair the resulting pattern with ``LIKE ? ESCAPE '\\'`` so
    SQLite treats ``\\%`` / ``\\_`` / ``\\\\`` as literal characters.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _engagement_root(engagement_id: int) -> tuple[Any, Path]:
    engagement = _engagement_or_404(engagement_id)
    return engagement, Path(engagement.engagement_root).resolve()


def _normalize_relative_path(root: Path, path_value: str) -> str:
    value = str(path_value or "").strip()
    if not value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="artifact path is required"
        )
    if "://" in value and urlparse(value).scheme != "file":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="artifact path must be engagement-local",
        )
    raw_path = Path(value)
    candidate = raw_path.expanduser() if raw_path.is_absolute() else root / raw_path
    # Canonicalise platform aliases such as macOS ``/var`` → ``/private/var``
    # for the containment comparison. The returned relative path is then
    # re-opened component-by-component with O_NOFOLLOW, so this resolution is
    # not trusted as the read authorization.
    normalized = candidate.resolve(strict=False)
    try:
        relative = normalized.relative_to(root)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="artifact path must be inside the engagement directory",
        ) from exc
    return relative.as_posix()


def _open_registered_artifact(root: Path, relative_path: str) -> int | None:
    """Open one registered path without following any component symlink."""
    parts = Path(relative_path).parts
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    leaf_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    opened: list[int] = []
    try:
        if not parts:
            return os.open(root, leaf_flags)
        current = os.open(root, directory_flags)
        opened.append(current)
        for component in parts[:-1]:
            current = os.open(component, directory_flags, dir_fd=current)
            opened.append(current)
        try:
            return os.open(parts[-1], leaf_flags, dir_fd=current)
        except FileNotFoundError:
            return None
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            detail = "artifact path must not traverse a symlink"
        else:
            detail = "artifact path could not be opened safely"
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
        ) from exc
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def _guess_kind(relative_path: str, explicit: str = "") -> str:
    if explicit.strip():
        return explicit.strip()
    path = relative_path.lower()
    if path.startswith("notes/"):
        return "note"
    if path.startswith("findings_payloads/"):
        return "finding-payload"
    if path.startswith("tools/exploit-state/"):
        return "exploit-state"
    if path.startswith("scans/reports/"):
        return "scan-report"
    if path.startswith("downloads/"):
        return "download"
    if path.startswith("ir/alerts/"):
        return "ir-alert"
    if path.startswith("ir/evidence/"):
        return "ir-evidence"
    if path.startswith("ir/reports/"):
        return "ir-report"
    if path.startswith("tmp/"):
        return "tmp-reference"
    if "command-runs" in path:
        return "command-run-output"
    return "artifact"


def _media_type(relative_path: str, explicit: str = "") -> str:
    if explicit.strip():
        return explicit.strip()
    guessed, _ = mimetypes.guess_type(relative_path)
    return guessed or "application/octet-stream"


def _is_textual(media_type: str, sample: bytes) -> bool:
    if media_type.startswith("text/"):
        return True
    if media_type in {"application/json", "application/xml", "application/x-yaml"}:
        return True
    return b"\x00" not in sample[:1024]


def _file_payload(
    root: Path,
    relative_path: str,
    media_type: str,
    *,
    reject_unsafe_path: bool = False,
) -> dict[str, Any]:
    """Index one registered path. ``present`` is EXISTENCE, not file-ness.

    ``vigil assess artifact register <dir>`` accepts a directory, and specialists
    legitimately point ``evidence_ref`` at a directory holding a whole capture
    set. An ``is_file()`` predicate here reported every one of those as
    ``present=False``, which report-readiness surfaces as "the file is missing on
    disk" against directories that were sitting there full of live evidence. A
    directory has no single body to hash or preview, so those fields stay empty —
    but it is unambiguously present.
    """
    try:
        descriptor = _open_registered_artifact(root, relative_path)
    except HTTPException:
        if reject_unsafe_path:
            raise
        descriptor = None
    if descriptor is None:
        return {
            "present": False,
            "size_bytes": 0,
            "sha256": "",
            "preview_text": "",
            "indexed_text": "",
        }
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return {
                "present": True,
                "size_bytes": 0,
                "sha256": "",
                "preview_text": "",
                "indexed_text": "",
            }
        digest = hashlib.sha256()
        size = 0
        preview = bytearray()
        indexed = bytearray()
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if len(preview) < PREVIEW_BYTES:
                preview.extend(chunk[: PREVIEW_BYTES - len(preview)])
            indexed.extend(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or size != after.st_size
        ):
            if reject_unsafe_path:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="artifact changed while it was being indexed",
                )
            return {
                "present": False,
                "size_bytes": 0,
                "sha256": "",
                "preview_text": "",
                "indexed_text": "",
            }
    finally:
        os.close(descriptor)
    sample = bytes(indexed or preview)
    if not _is_textual(media_type, sample):
        preview_text = ""
        indexed_text = ""
    else:
        preview_text = bytes(preview).decode("utf-8", errors="replace")
        indexed_text = bytes(indexed).decode("utf-8", errors="replace")
    return {
        "present": True,
        "size_bytes": size,
        "sha256": digest.hexdigest(),
        "preview_text": preview_text,
        "indexed_text": indexed_text,
    }


def _serialize_artifact(row, *, compact: bool = False) -> dict[str, Any]:
    data = dict(row)
    data.pop("sensitive", None)
    for key in ("present", "scratch"):
        data[key] = bool(data.get(key))
    indexed_text = str(data.get("indexed_text") or "")
    indexed_bytes = len(indexed_text.encode("utf-8"))
    size_bytes = int(data.get("size_bytes") or 0)
    if not data["present"]:
        index_status = "missing"
    elif indexed_text:
        index_status = "partial" if indexed_bytes < size_bytes else "complete"
    elif size_bytes == 0:
        index_status = "complete"
    else:
        index_status = "not_text"
    data["indexed_bytes"] = indexed_bytes
    data["index_status"] = index_status
    if compact:
        data.pop("indexed_text", None)
    return data


def _file_payload_if_changed(
    engagement_id: int,
    root: Path,
    relative_path: str,
    media_type: str,
) -> dict[str, Any]:
    """Build registration metadata from one no-follow file descriptor."""
    del engagement_id
    return _file_payload(
        root,
        relative_path,
        media_type,
        reject_unsafe_path=True,
    )


def _execute_artifact_upsert(
    connection,
    sql: str,
    parameters: tuple[Any, ...],
):
    try:
        return connection.execute(sql, parameters)
    except sqlite3.IntegrityError as exc:
        if "artifact path is reserved from indexing" in str(exc):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="artifact path is reserved from indexing",
            ) from exc
        raise


def _normalize_related_finding_slug(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    return canonical_finding_alias(raw) or raw


def _store_artifact(
    engagement_id: int,
    *,
    relative_path: str,
    kind: str,
    media_type: str,
    file_data: dict[str, Any],
    producer_agent_id: str | None,
    producer_agent_role: str | None,
    producer_command_run_id: int | None,
    related_finding_slug: str | None,
    related_chain_key: str | None,
    related_surface_id: int | None,
    related_request_variant_id: int | None,
    verified_device: int | None = None,
    verified_inode: int | None = None,
    integrity_status: str = "unverified",
) -> dict[str, Any]:
    kind_value = _guess_kind(relative_path, kind)
    media_type_value = _media_type(relative_path, media_type)
    now = _utcnow_iso()
    linked_finding = _normalize_related_finding_slug(related_finding_slug)
    with get_connection() as connection:
        _execute_artifact_upsert(
            connection,
            """
            INSERT INTO assessment_artifacts (
                engagement_id, relative_path, kind, media_type, size_bytes, sha256,
                preview_text, indexed_text, present, producer_agent_id,
                verified_device, verified_inode, integrity_status,
                producer_agent_role, producer_command_run_id, related_finding_slug,
                related_chain_key, related_surface_id, related_request_variant_id,
                created_at, updated_at, last_indexed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, relative_path) DO UPDATE SET
                -- Bind the RAW caller-supplied kind/media_type here, not
                -- excluded.* — excluded.kind carries the _guess_kind() result,
                -- which is never empty, so NULLIF(excluded.kind, '') would
                -- never preserve the stored kind and a bare re-register would
                -- clobber an explicit kind (e.g. verification-narrative).
                kind = CASE
                    WHEN assessment_artifacts.verified_device IS NOT NULL
                     AND excluded.verified_device IS NULL
                    THEN assessment_artifacts.kind
                    ELSE COALESCE(NULLIF(?, ''), assessment_artifacts.kind)
                END,
                media_type = CASE
                    WHEN assessment_artifacts.verified_device IS NOT NULL
                     AND excluded.verified_device IS NULL
                    THEN assessment_artifacts.media_type
                    ELSE COALESCE(NULLIF(?, ''), assessment_artifacts.media_type)
                END,
                size_bytes = CASE
                    WHEN (assessment_artifacts.verified_device IS NOT NULL
                      AND excluded.verified_device IS NULL)
                      OR excluded.present = 0
                    THEN assessment_artifacts.size_bytes ELSE excluded.size_bytes END,
                sha256 = CASE
                    WHEN (assessment_artifacts.verified_device IS NOT NULL
                      AND excluded.verified_device IS NULL)
                      OR excluded.present = 0
                    THEN assessment_artifacts.sha256 ELSE excluded.sha256 END,
                preview_text = CASE
                    WHEN (assessment_artifacts.verified_device IS NOT NULL
                      AND excluded.verified_device IS NULL)
                      OR excluded.present = 0
                    THEN assessment_artifacts.preview_text ELSE excluded.preview_text END,
                indexed_text = CASE
                    WHEN (assessment_artifacts.verified_device IS NOT NULL
                      AND excluded.verified_device IS NULL)
                      OR excluded.present = 0
                    THEN assessment_artifacts.indexed_text ELSE excluded.indexed_text END,
                present = CASE
                    WHEN assessment_artifacts.verified_device IS NOT NULL
                     AND excluded.verified_device IS NULL
                    THEN assessment_artifacts.present ELSE excluded.present END,
                verified_device = COALESCE(excluded.verified_device, assessment_artifacts.verified_device),
                verified_inode = COALESCE(excluded.verified_inode, assessment_artifacts.verified_inode),
                integrity_status = CASE
                    WHEN excluded.verified_device IS NOT NULL
                     AND excluded.verified_inode IS NOT NULL
                    THEN excluded.integrity_status
                    WHEN assessment_artifacts.verified_device IS NOT NULL
                     AND excluded.verified_device IS NULL
                    THEN assessment_artifacts.integrity_status
                    WHEN excluded.present = 0 THEN 'missing'
                    ELSE 'unverified'
                END,
                producer_agent_id = CASE
                    WHEN assessment_artifacts.verified_device IS NOT NULL
                     AND excluded.verified_device IS NULL
                    THEN assessment_artifacts.producer_agent_id
                    WHEN excluded.producer_agent_id IS NOT NULL
                     AND excluded.producer_agent_id IS NOT assessment_artifacts.producer_agent_id
                     AND EXISTS (
                        SELECT 1 FROM assessment_proof_receipts
                        WHERE artifact_id = assessment_artifacts.id
                      )
                    THEN assessment_artifacts.producer_agent_id
                    ELSE COALESCE(excluded.producer_agent_id, assessment_artifacts.producer_agent_id) END,
                producer_agent_role = CASE
                    WHEN assessment_artifacts.verified_device IS NOT NULL
                     AND excluded.verified_device IS NULL
                    THEN assessment_artifacts.producer_agent_role
                    ELSE COALESCE(excluded.producer_agent_role, assessment_artifacts.producer_agent_role) END,
                producer_command_run_id = CASE
                    WHEN assessment_artifacts.verified_device IS NOT NULL
                     AND excluded.verified_device IS NULL
                    THEN assessment_artifacts.producer_command_run_id
                    WHEN excluded.producer_command_run_id IS NOT NULL
                     AND excluded.producer_command_run_id IS NOT assessment_artifacts.producer_command_run_id
                     AND EXISTS (
                        SELECT 1 FROM assessment_proof_receipts
                        WHERE artifact_id = assessment_artifacts.id
                      )
                    THEN assessment_artifacts.producer_command_run_id
                    ELSE COALESCE(excluded.producer_command_run_id, assessment_artifacts.producer_command_run_id) END,
                related_finding_slug = CASE
                    WHEN assessment_artifacts.verified_device IS NOT NULL
                     AND excluded.verified_device IS NULL
                    THEN assessment_artifacts.related_finding_slug
                    ELSE COALESCE(excluded.related_finding_slug, assessment_artifacts.related_finding_slug) END,
                related_chain_key = CASE
                    WHEN assessment_artifacts.verified_device IS NOT NULL
                     AND excluded.verified_device IS NULL
                    THEN assessment_artifacts.related_chain_key
                    ELSE COALESCE(excluded.related_chain_key, assessment_artifacts.related_chain_key) END,
                related_surface_id = CASE
                    WHEN assessment_artifacts.verified_device IS NOT NULL
                     AND excluded.verified_device IS NULL
                    THEN assessment_artifacts.related_surface_id
                    ELSE COALESCE(excluded.related_surface_id, assessment_artifacts.related_surface_id) END,
                related_request_variant_id = CASE
                    WHEN assessment_artifacts.verified_device IS NOT NULL
                     AND excluded.verified_device IS NULL
                    THEN assessment_artifacts.related_request_variant_id
                    ELSE COALESCE(excluded.related_request_variant_id, assessment_artifacts.related_request_variant_id) END,
                updated_at = excluded.updated_at,
                last_indexed_at = excluded.last_indexed_at
            """,
            (
                engagement_id,
                relative_path,
                kind_value,
                media_type_value,
                int(file_data["size_bytes"]),
                str(file_data["sha256"]),
                str(file_data["preview_text"]),
                str(file_data["indexed_text"]),
                1 if file_data["present"] else 0,
                producer_agent_id,
                verified_device,
                verified_inode,
                integrity_status,
                producer_agent_role,
                producer_command_run_id,
                linked_finding,
                related_chain_key,
                related_surface_id,
                related_request_variant_id,
                now,
                now,
                now,
                # DO UPDATE placeholders (raw explicit kind/media_type, stripped).
                kind.strip(),
                media_type.strip(),
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_artifacts WHERE engagement_id = ? AND relative_path = ?",
            (engagement_id, relative_path),
        ).fetchone()
        assert row is not None
        requested_producer = {
            "producer_agent_id": producer_agent_id,
            "producer_command_run_id": producer_command_run_id,
        }
        producer_mismatch = any(
            value is not None and row[field] != value
            for field, value in requested_producer.items()
        )
        if producer_mismatch and connection.execute(
            "SELECT EXISTS(SELECT 1 FROM assessment_proof_receipts WHERE artifact_id = ?)",
            (int(row["id"]),),
        ).fetchone()[0]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "artifact producer agent/command attribution is immutable after proof "
                    "registration"
                ),
            )
    return _serialize_artifact(row)


def register_artifact(
    engagement_id: int,
    *,
    path: str,
    kind: str = "",
    media_type: str = "",
    producer_agent_id: str | None = None,
    producer_agent_role: str | None = None,
    producer_command_run_id: int | None = None,
    related_finding_slug: str | None = None,
    related_chain_key: str | None = None,
    related_surface_id: int | None = None,
    related_request_variant_id: int | None = None,
) -> dict[str, Any]:
    _engagement, root = _engagement_root(engagement_id)
    relative_path = _normalize_relative_path(root, path)
    with get_connection() as connection:
        reservation = connection.execute(
            """
            SELECT 1 FROM assessment_artifact_path_reservations
            WHERE engagement_id = ? AND relative_path = ?
            """,
            (engagement_id, relative_path),
        ).fetchone()
        if reservation is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="artifact path is reserved from indexing",
            )
        existing = connection.execute(
            """
            SELECT verified_device, verified_inode
            FROM assessment_artifacts
            WHERE engagement_id = ? AND relative_path = ?
            """,
            (engagement_id, relative_path),
        ).fetchone()
    if (
        existing is not None
        and existing["verified_device"] is not None
        and existing["verified_inode"] is not None
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="verified command output metadata is internal and immutable",
        )
    media_type_value = _media_type(relative_path, media_type)
    file_data = _file_payload_if_changed(
        engagement_id, root, relative_path, media_type_value
    )
    return _store_artifact(
        engagement_id,
        relative_path=relative_path,
        kind=kind,
        media_type=media_type,
        file_data=file_data,
        producer_agent_id=producer_agent_id,
        producer_agent_role=producer_agent_role,
        producer_command_run_id=producer_command_run_id,
        related_finding_slug=related_finding_slug,
        related_chain_key=related_chain_key,
        related_surface_id=related_surface_id,
        related_request_variant_id=related_request_variant_id,
    )


def register_artifacts_bulk(
    engagement_id: int, items: list[dict[str, Any]]
) -> dict[str, Any]:
    """Register many engagement-local paths in one transaction.

    Each item is written inside its own savepoint, so a path the index refuses —
    outside the engagement directory, reserved from indexing, verified command
    output, or an immutable producer attribution — is reported with the reason it
    was refused instead of discarding every other path's work. ``registered`` and
    ``failed`` sum to ``requested`` exactly; ``outcomes`` carries one row per
    submitted item in submission order, and ``artifacts`` the registered rows in
    that same order — the row ``register_artifact`` returns minus ``indexed_text``,
    in the same compact shape ``search_artifacts`` returns (see the loop).
    """
    outcomes: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    # Deliberately NOT one batch-wide transaction. Each register_artifact opens,
    # reads and digests its file with no size cap, so wrapping 500 of them in a
    # single BEGIN IMMEDIATE would hold the WAL write lock across every one of
    # those reads — up to ~100s, during which every other specialist's write
    # takes the 8s busy_timeout and 503s. Per-path partial success is this
    # endpoint's whole contract, so batch atomicity is an invariant no reader
    # relies on; get_connection()'s depth-0 rollback inside _store_artifact
    # already isolates a path refused after its own upsert.
    for index, item in enumerate(items):
        try:
            record = register_artifact(engagement_id, **item)
        except HTTPException as refused:
            outcomes.append(
                {
                    "index": index,
                    "path": str(item.get("path") or ""),
                    "relative_path": None,
                    "artifact_id": None,
                    "outcome": "failed",
                    "status_code": refused.status_code,
                    "detail": str(refused.detail),
                }
            )
            continue
        outcomes.append(
            {
                "index": index,
                "path": str(item.get("path") or ""),
                "relative_path": record["relative_path"],
                "artifact_id": record["id"],
                "outcome": "registered",
                "status_code": None,
                "detail": "",
            }
        )
        # The receipt does not echo back the files it registered. `indexed_text`
        # is each file's whole text — 32 KB average, 56 MB max on this tree — so
        # a 500-path batch is a ~100 MB response that `artifact register --json`
        # prints to an agent's stdout, text the caller read off its own disk a
        # call earlier. Not ADR 0019 masking: nothing is rewritten or shaped,
        # `indexed_bytes`/`index_status` still report the indexing, and
        # `artifact get` returns the text verbatim. Same row `search_artifacts`
        # already returns.
        record.pop("indexed_text", None)
        artifacts.append(record)
    return {
        "requested": len(items),
        "registered": len(artifacts),
        "failed": len(items) - len(artifacts),
        "outcomes": outcomes,
        "artifacts": artifacts,
    }


def _verified_command_output_relative_path(relative_path: str) -> str:
    path = Path(str(relative_path))
    if (
        path.is_absolute()
        or ".." in path.parts
        or len(path.parts) != 3
        or path.parts[0] != "scans"
        or path.parts[1] not in {"host-exec", "command-runs"}
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "verified command output must be beneath "
                "scans/host-exec or scans/command-runs"
            ),
        )
    return path.as_posix()


def _open_verified_snapshot(root: Path, relative_path: str) -> int:
    """Open a command-run snapshot without following any path component."""
    normalized = _verified_command_output_relative_path(relative_path)
    parts = Path(normalized).parts
    if parts[:2] != ("scans", "command-runs"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="verified artifact no longer points at the snapshot directory",
        )
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    opened: list[int] = []
    try:
        current = os.open(root, directory_flags)
        opened.append(current)
        for component in parts[:-1]:
            current = os.open(component, directory_flags, dir_fd=current)
            opened.append(current)
        descriptor = os.open(parts[-1], file_flags, dir_fd=current)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="verified artifact is no longer a regular file",
            )
        return descriptor
    except HTTPException:
        raise
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            detail = "verified artifact path must not traverse a symlink"
        elif exc.errno == errno.ENOENT:
            detail = "verified artifact is missing"
        else:
            detail = "verified artifact could not be opened safely"
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
        ) from exc
    finally:
        for directory_descriptor in reversed(opened):
            os.close(directory_descriptor)


def _verified_snapshot_payload(
    root: Path,
    relative_path: str,
    *,
    expected_device: int,
    expected_inode: int,
    expected_size: int,
    expected_sha256: str,
) -> dict[str, Any]:
    """Read and verify one immutable snapshot from a single descriptor."""
    descriptor = _open_verified_snapshot(root, relative_path)
    try:
        before = os.fstat(descriptor)
        if (int(before.st_dev), int(before.st_ino)) != (
            int(expected_device),
            int(expected_inode),
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="verified artifact identity changed",
            )
        digest = hashlib.sha256()
        size = 0
        content = bytearray()
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if len(content) <= GET_CONTENT_BYTES:
                content.extend(chunk[: GET_CONTENT_BYTES + 1 - len(content)])
        after = os.fstat(descriptor)
        observed_sha = digest.hexdigest() if size else ""
        if (
            (int(after.st_dev), int(after.st_ino))
            != (int(expected_device), int(expected_inode))
            or size != int(expected_size)
            or observed_sha != str(expected_sha256)
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="verified artifact content changed",
            )
        return {
            "content_bytes": bytes(content[:GET_CONTENT_BYTES]),
            "content_truncated": size > GET_CONTENT_BYTES,
        }
    finally:
        os.close(descriptor)


def verified_snapshot_evidence_health(
    root: Path,
    relative_path: str,
    *,
    expected_device: int,
    expected_inode: int,
    expected_size: int,
    expected_sha256: str,
) -> str:
    """Check immutable artifact identity and bytes without mutating its index row."""

    try:
        _verified_snapshot_payload(
            root,
            relative_path,
            expected_device=expected_device,
            expected_inode=expected_inode,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
        )
    except HTTPException as exc:
        if exc.detail == "verified artifact is missing":
            return "missing"
        return "stale"
    except OSError:
        return "stale"
    return "healthy"


def registered_snapshot_evidence_health(
    root: Path,
    relative_path: str,
    *,
    expected_size: int,
    expected_sha256: str,
    verified_device: int | None,
    verified_inode: int | None,
) -> str:
    """Read current bytes safely and compare them with one registered snapshot."""

    if verified_device is not None or verified_inode is not None:
        if verified_device is None or verified_inode is None:
            return "stale"
        return verified_snapshot_evidence_health(
            root,
            relative_path,
            expected_device=verified_device,
            expected_inode=verified_inode,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
        )
    try:
        descriptor = _open_registered_artifact(root, relative_path)
    except HTTPException:
        return "stale"
    if descriptor is None:
        return "missing"
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return "stale"
        digest = hashlib.sha256()
        size = 0
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or size != after.st_size
        ):
            return "stale"
        if size != expected_size or digest.hexdigest() != expected_sha256:
            return "stale"
        return "healthy"
    except OSError:
        return "stale"
    finally:
        os.close(descriptor)


def register_verified_command_output(
    engagement_id: int,
    *,
    relative_path: str,
    size_bytes: int,
    sha256: str,
    sample_bytes: bytes,
    verified_device: int,
    verified_inode: int,
    producer_command_run_id: int,
    producer_agent_role: str,
) -> dict[str, Any]:
    """Index command output already read from a no-follow file descriptor.

    The caller owns path opening and supplies metadata from that same descriptor,
    so artifact indexing never reopens an attacker-swappable pathname.
    """
    normalized = _verified_command_output_relative_path(relative_path)
    media_type_value = _media_type(normalized)
    sample = bytes(sample_bytes[:VERIFIED_OUTPUT_INDEX_BYTES])
    if _is_textual(media_type_value, sample):
        preview_text = sample[:PREVIEW_BYTES].decode("utf-8", errors="replace")
        indexed_text = sample.decode("utf-8", errors="replace")
    else:
        preview_text = ""
        indexed_text = ""
    return _store_artifact(
        engagement_id,
        relative_path=normalized,
        kind="command-run-output",
        media_type=media_type_value,
        file_data={
            "present": True,
            "size_bytes": int(size_bytes),
            "sha256": str(sha256),
            "preview_text": preview_text,
            "indexed_text": indexed_text,
        },
        producer_agent_id=None,
        producer_agent_role=producer_agent_role,
        producer_command_run_id=int(producer_command_run_id),
        related_finding_slug=None,
        related_chain_key=None,
        related_surface_id=None,
        related_request_variant_id=None,
        verified_device=int(verified_device),
        verified_inode=int(verified_inode),
        integrity_status="verified",
    )


def remove_verified_command_output(
    engagement_id: int,
    *,
    relative_path: str,
) -> None:
    """Remove every canonical row for a suppressed host-output pathname.

    Path suppression is authoritative regardless of which older producer or
    finding link registered the unique engagement/path row.
    """
    normalized = _verified_command_output_relative_path(relative_path)
    with get_connection() as connection:
        connection.execute(
            """
            DELETE FROM assessment_artifacts
            WHERE engagement_id = ?
              AND relative_path = ?
            """,
            (engagement_id, normalized),
        )


def reserve_suppressed_command_output(
    engagement_id: int,
    *,
    relative_path: str,
    reason: str,
    command_run_id: int,
) -> None:
    """Durably prevent logical-suppression paths from being re-indexed."""
    normalized = _verified_command_output_relative_path(relative_path)
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO assessment_artifact_path_reservations (
                engagement_id, relative_path, reason, command_run_id
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(engagement_id, relative_path) DO UPDATE SET
                reason = excluded.reason,
                command_run_id = excluded.command_run_id
            """,
            (
                engagement_id,
                normalized,
                str(reason or "suppressed")[:1024],
                int(command_run_id),
            ),
        )


def refresh_artifacts(
    engagement_id: int, *, artifact_id: int | None = None
) -> dict[str, Any]:
    """Refresh on-disk presence/hash metadata for existing artifact rows only.

    This intentionally does not walk directories or discover new files. It keeps
    explicit registration as the only way a path enters the index while letting
    report-readiness see deleted or restored files without per-path re-registers.
    """
    _engagement, root = _engagement_root(engagement_id)
    now = _utcnow_iso()
    with get_connection() as connection:
        if artifact_id is None:
            rows = connection.execute(
                "SELECT * FROM assessment_artifacts WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM assessment_artifacts WHERE engagement_id = ? AND id = ?",
                (engagement_id, artifact_id),
            ).fetchall()
            if not rows:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"artifact id={artifact_id} not found",
                )
        present = 0
        missing = 0
        for row in rows:
            relative_path = str(row["relative_path"])
            media_type_value = _media_type(relative_path, str(row["media_type"] or ""))
            is_verified = (
                row["verified_device"] is not None
                or row["verified_inode"] is not None
            )
            if is_verified:
                verified_ok = False
                if (
                    row["verified_device"] is not None
                    and row["verified_inode"] is not None
                ):
                    try:
                        _verified_snapshot_payload(
                            root,
                            relative_path,
                            expected_device=int(row["verified_device"]),
                            expected_inode=int(row["verified_inode"]),
                            expected_size=int(row["size_bytes"] or 0),
                            expected_sha256=str(row["sha256"] or ""),
                        )
                        verified_ok = True
                    except HTTPException:
                        verified_ok = False
                if verified_ok:
                    present += 1
                    integrity_status = "verified"
                else:
                    missing += 1
                    integrity_status = "mismatch"
                connection.execute(
                    """
                    UPDATE assessment_artifacts
                    SET present = ?, integrity_status = ?, updated_at = ?,
                        last_indexed_at = ?
                    WHERE id = ?
                    """,
                    (
                        1 if verified_ok else 0,
                        integrity_status,
                        now,
                        now,
                        int(row["id"]),
                    ),
                )
                continue
            file_data = _file_payload(root, relative_path, media_type_value)
            if bool(file_data["present"]):
                present += 1
            else:
                missing += 1
                # The artifact row is also the durable tombstone for evidence
                # that has disappeared from disk. Keep its last observed hash,
                # extent, preview, and indexed text so absence never rewrites
                # history into an empty artifact.
                connection.execute(
                    """
                    UPDATE assessment_artifacts
                    SET media_type = ?, present = 0, integrity_status = 'missing',
                        updated_at = ?, last_indexed_at = ?
                    WHERE id = ?
                    """,
                    (media_type_value, now, now, int(row["id"])),
                )
                continue
            connection.execute(
                """
                UPDATE assessment_artifacts
                SET media_type = ?, size_bytes = ?, sha256 = ?, preview_text = ?,
                    indexed_text = ?, present = 1, integrity_status = 'unverified',
                    updated_at = ?, last_indexed_at = ?
                WHERE id = ?
                """,
                (
                    media_type_value,
                    int(file_data["size_bytes"]),
                    str(file_data["sha256"]),
                    str(file_data["preview_text"]),
                    str(file_data["indexed_text"]),
                    now,
                    now,
                    int(row["id"]),
                ),
            )
        connection.commit()
    return {
        "refreshed": len(rows),
        "present": present,
        "missing": missing,
    }


def clear_finding_link(engagement_id: int, *, artifact_id: int) -> dict[str, Any]:
    """Clear only the artifact/finding association, preserving artifact bytes and proof."""
    _engagement_root(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_artifacts WHERE engagement_id = ? AND id = ?",
            (engagement_id, artifact_id),
        ).fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"artifact id={artifact_id} not found",
            )
        connection.execute(
            "UPDATE assessment_artifacts SET related_finding_slug = NULL, updated_at = ? "
            "WHERE engagement_id = ? AND id = ?",
            (_utcnow_iso(), engagement_id, artifact_id),
        )
        connection.execute(
            "UPDATE assessment_findings SET evidence_artifact_id = NULL "
            "WHERE engagement_id = ? AND evidence_artifact_id = ?",
            (engagement_id, artifact_id),
        )
        connection.commit()
        updated = connection.execute(
            "SELECT * FROM assessment_artifacts WHERE engagement_id = ? AND id = ?",
            (engagement_id, artifact_id),
        ).fetchone()
    assert updated is not None
    return _serialize_artifact(updated)


# Characters that can only appear in a COMPOSITE or prose reference, never in
# one engagement-local path: the semicolon/pipe list joiners and any control
# whitespace. A ref carrying these describes several things (or a sentence), so
# there is no single path an artifact row could ever point at.
_COMPOSITE_REF_CHARS = (";", "|", "\n", "\r", "\t", "\x00")


def _path_ref(value: Any) -> str | None:
    """Return *value* when it looks like ONE plausible engagement-local path.

    Used by ``register_reference_if_local`` so a finding/transition/chain
    write with ``evidence_ref`` set automatically lands an artifact row when
    the value is a file path.  Rejects sentence-text and multi-path composites
    so callers don't silently create ghost artifact rows: a composite ref
    ("scans/a.out; scans/b.out", "command-runs 56052/56054/56061") minted a
    PERMANENT artifact row for a path that can never exist and then linked it
    as the finding's ``evidence_artifact_id``.

    This is a shape check, not a gate. The finding/transition/chain write itself
    still succeeds — recording a real finding mid-hunt must never be blocked —
    it just does not acquire a bogus artifact link. The CLI
    (``record_finding._normalize_evidence_ref``) mirrors these rules to warn the
    author at record time; keep the two in sync.

    Heuristics (any match → reject):
    - contains ``://`` (URL)
    - empty or whitespace-only
    - no ``/`` or ``.`` (real paths have at least an extension or a directory)
    - two or more consecutive spaces (natural language, not a path)
    - a composite/prose separator (``;``, ``|``, newline, tab)
    - contains a space AND the first token is not itself path-shaped
      ("command-runs 56052/..." — a prose prefix), or a later token carries its
      own ``/`` (a second path root). A single path with a space inside one
      component ("notes/my triage.md") still passes.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped or "://" in stripped:
        return None
    if "/" not in stripped and "." not in stripped:
        return None
    if "  " in stripped:
        return None
    if any(char in stripped for char in _COMPOSITE_REF_CHARS):
        return None
    tokens = stripped.split(" ")
    if len(tokens) > 1:
        if "/" not in tokens[0] and "." not in tokens[0]:
            return None
        if any("/" in token for token in tokens[1:]):
            return None
    return stripped


def search_artifacts(
    engagement_id: int,
    *,
    query: str = "",
    finding: str = "",
    kind: str = "",
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    _engagement, _root = _engagement_root(engagement_id)
    where = ["a.engagement_id = ?"]
    params: list[Any] = [engagement_id]
    select_params: list[Any] = []
    join_sql = ""
    canonical_finding = canonical_finding_alias(finding) if finding else None
    fts_terms: list[str] = []
    if query:
        fts_terms.append(expanded_fts_query(query))
    if canonical_finding:
        fts_terms.append(expanded_fts_query(canonical_finding))
    fts_expr = " ".join(term for term in fts_terms if term)
    if fts_expr:
        join_sql = (
            "JOIN assessment_artifacts_fts ON assessment_artifacts_fts.rowid = a.id"
        )
        where.append("assessment_artifacts_fts MATCH ?")
        params.append(fts_expr)
    if canonical_finding:
        # Slugs are validated to canonical `<PREFIX>-NNN` and won't contain
        # LIKE wildcards today; escape defensively in case the validator
        # ever relaxes.
        escaped_slug = _escape_like(canonical_finding)
        where.append(
            "(a.related_finding_slug = ? OR a.indexed_text LIKE ? ESCAPE '\\' "
            "OR a.relative_path LIKE ? ESCAPE '\\')"
        )
        params.extend([canonical_finding, f"%{escaped_slug}%", f"%{escaped_slug}%"])
    # Optional ``kind`` filter (e.g. ``note``, ``ir-alert``, ``scan-report``).
    # No new index — v1 query volumes are small enough that a WHERE on ``kind``
    # is fine even with a full scan per engagement.
    if kind:
        where.append("a.kind = ?")
        params.append(kind)
    params.extend([int(limit), int(offset)])
    rank_select = ""
    if canonical_finding:
        rank_select += ", CASE WHEN a.related_finding_slug = ? THEN 0 ELSE 1 END AS finding_link_rank"
        select_params.append(canonical_finding)
    if fts_expr:
        rank_select += ", bm25(assessment_artifacts_fts) AS search_rank"
    order_terms: list[str] = []
    if canonical_finding:
        order_terms.append("finding_link_rank ASC")
    if fts_expr:
        order_terms.append("search_rank ASC")
    order_terms.extend(["a.updated_at DESC", "a.id DESC"])
    order_sql = "ORDER BY " + ", ".join(order_terms)
    sql = (
        f"SELECT a.*{rank_select} FROM assessment_artifacts a {join_sql} "
        f"WHERE {' AND '.join(where)} {order_sql} LIMIT ? OFFSET ?"
    )
    with get_connection() as connection:
        rows = connection.execute(sql, tuple(select_params + params)).fetchall()
    return [_serialize_artifact(row, compact=True) for row in rows]


def get_artifact(engagement_id: int, artifact_id: int) -> dict[str, Any]:
    _engagement, root = _engagement_root(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_artifacts WHERE engagement_id = ? AND id = ?",
            (engagement_id, int(artifact_id)),
        ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="artifact not found"
        )
    data = _serialize_artifact(row)
    data["content"] = ""
    data["content_truncated"] = False
    if row["verified_device"] is not None or row["verified_inode"] is not None:
        try:
            if row["verified_device"] is None or row["verified_inode"] is None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="verified artifact identity metadata is incomplete",
                )
            verified = _verified_snapshot_payload(
                root,
                str(row["relative_path"]),
                expected_device=int(row["verified_device"]),
                expected_inode=int(row["verified_inode"]),
                expected_size=int(row["size_bytes"] or 0),
                expected_sha256=str(row["sha256"] or ""),
            )
        except HTTPException:
            with get_connection() as connection:
                connection.execute(
                    """
                    UPDATE assessment_artifacts
                    SET present = 0, integrity_status = 'mismatch', updated_at = ?
                    WHERE id = ?
                    """,
                    (_utcnow_iso(), int(row["id"])),
                )
            raise
        data["content"] = bytes(verified["content_bytes"]).decode(
            "utf-8", errors="replace"
        )
        data["content_truncated"] = bool(verified["content_truncated"])
        data["present"] = True
        data["integrity_status"] = "verified"
        return data
    if bool(row["present"]):
        descriptor = _open_registered_artifact(root, str(row["relative_path"]))
        if descriptor is None:
            data["present"] = False
            return data
        try:
            metadata = os.fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode):
                if metadata.st_size <= GET_CONTENT_BYTES:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    chunks: list[bytes] = []
                    remaining = GET_CONTENT_BYTES
                    while remaining:
                        chunk = os.read(descriptor, min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    data["content"] = b"".join(chunks).decode(
                        "utf-8", errors="replace"
                    )
                else:
                    data["content_truncated"] = True
        finally:
            os.close(descriptor)
    return data


def set_scratch_under_prefix(
    engagement_id: int,
    *,
    prefix: str,
    scratch: bool = True,
) -> dict[str, Any]:
    """Bulk-mark every indexed artifact whose relative_path starts with ``prefix``.

    For the report-time landslide case: an engagement with 30 unlinked
    `notes/*.md` scratch files can be cleared with one call
    (``--under notes/scratch/``) instead of 30 single-target mark-scratch
    invocations. Returns the affected paths so the caller has an audit
    trail of what changed.
    """
    _engagement, root = _engagement_root(engagement_id)
    # Reuse the normalizer so callers can pass either a relative ("notes/")
    # or an absolute prefix inside the engagement directory. Empty / "."
    # prefixes are rejected because they would silently flag every indexed
    # artifact — `notes/` is the conservative default if the caller wanted
    # "all my markdown notes".
    if prefix in (".", "./", ""):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="prefix is required; pass e.g. 'notes/' to mark every indexed note",
        )
    normalized = _normalize_relative_path(root, prefix)
    # Anchor at a path-segment boundary so "notes/foo" never accidentally
    # matches "notes/foobar".
    if not normalized.endswith("/"):
        normalized = normalized + "/"
    # SQL LIKE treats `%` and `_` as wildcards. Engagement paths can legally
    # contain `_` ("notes/my_scratch/") and could theoretically contain `%`
    # (URL-encoded artifacts). Escape both with a backslash and tell SQLite
    # to use that as the escape character so the prefix matches as a literal
    # path segment.
    escaped_prefix = _escape_like(normalized)
    like_pattern = f"{escaped_prefix}%"
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT id, relative_path FROM assessment_artifacts "
            "WHERE engagement_id = ? AND relative_path LIKE ? ESCAPE '\\'",
            (engagement_id, like_pattern),
        ).fetchall()
        if not rows:
            return {"matched": 0, "updated": [], "prefix": normalized}
        ids = [int(r["id"]) for r in rows]
        placeholders = ",".join("?" for _ in ids)
        connection.execute(
            f"UPDATE assessment_artifacts SET scratch = ?, updated_at = ? "
            f"WHERE id IN ({placeholders})",
            (1 if scratch else 0, _utcnow_iso(), *ids),
        )
    return {
        "matched": len(rows),
        "updated": [str(r["relative_path"]) for r in rows],
        "prefix": normalized,
    }


def register_reference_if_local(
    engagement_id: int,
    *,
    path: str,
    **metadata: Any,
) -> dict[str, Any] | None:
    if not _path_ref(path):
        return None
    try:
        return register_artifact(engagement_id, path=path, **metadata)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_400_BAD_REQUEST:
            return None
        raise


def set_scratch_flag(
    engagement_id: int,
    *,
    path: str = "",
    artifact_id: int | None = None,
    scratch: bool = True,
) -> dict[str, Any]:
    """Mark an artifact row as scratch (excluded from report-readiness checks).

    A scratch artifact stays in the FTS index — search and resume-brief still
    surface it — but report-readiness ignores it. When called by path against
    an engagement-local file that has not yet been indexed (e.g., a freshly
    written `notes/triage.md` that hasn't been explicitly registered yet),
    this registers the row inline so the caller doesn't need a separate
    register step. Called by id requires the row to exist.
    """
    _engagement, root = _engagement_root(engagement_id)
    with get_connection() as connection:
        row = None
        if artifact_id is not None:
            row = connection.execute(
                "SELECT * FROM assessment_artifacts WHERE engagement_id = ? AND id = ?",
                (engagement_id, int(artifact_id)),
            ).fetchone()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="artifact not found"
                )
        elif path:
            relative_path = _normalize_relative_path(root, path)
            row = connection.execute(
                "SELECT * FROM assessment_artifacts WHERE engagement_id = ? AND relative_path = ?",
                (engagement_id, relative_path),
            ).fetchone()
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="path or artifact_id is required",
            )
    if row is None:
        # Path-based mark on a path that exists on disk but has not been
        # indexed yet — register inline so the operator does not have to
        # chase a sync before scratching a brand-new note. Refuse the
        # convenience path when nothing exists on disk: scratching
        # a ghost path would leave a row with present=False that future
        # consumers can't act on, and the operator probably mistyped.
        # EXISTENCE, not file-ness: a registered evidence DIRECTORY is a valid
        # artifact here exactly as it is in `_file_payload`.
        on_disk = (root / _normalize_relative_path(root, path)).exists()
        if not on_disk:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"artifact not found for path={path!r} and that path does not exist on disk. "
                    "Register it with `vigil assess artifact register <path>` first, or check the path."
                ),
            )
        row_dict = register_artifact(engagement_id, path=path)
        artifact_id_value = int(row_dict["id"])
    else:
        artifact_id_value = int(row["id"])
    with get_connection() as connection:
        connection.execute(
            "UPDATE assessment_artifacts SET scratch = ?, updated_at = ? WHERE id = ?",
            (1 if scratch else 0, _utcnow_iso(), artifact_id_value),
        )
        updated = connection.execute(
            "SELECT * FROM assessment_artifacts WHERE id = ?",
            (artifact_id_value,),
        ).fetchone()
    assert updated is not None
    return _serialize_artifact(updated)
