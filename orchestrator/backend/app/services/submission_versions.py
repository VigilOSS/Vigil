"""Immutable, staged submission packages shared by the CLI and web UI."""
from __future__ import annotations

import hashlib
import heapq
import io
import json
import os
import re
import secrets
import stat
import zipfile
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from fastapi import HTTPException, status

from ..db import get_connection
from . import activity as activity_service
from . import artifact_index, state_manager
from .events import _engagement_or_404
from .state_manager.proofs import proof_evidence_health_issues_for_finding
from .state_manager.report_readiness import report_readiness
from .state_manager.repro_currentness import reproduction_sha256


SUBMISSION_PLATFORMS = frozenset({"bugcrowd", "hackerone", "direct"})
ACTOR_SURFACES = frozenset({"vigil-assess", "web-ui"})
WORKSPACE_MARKDOWN_MAX_BYTES = 4 * 1024 * 1024
WORKSPACE_CONTEXT_MAX_BYTES = 2 * 1024 * 1024
ATTACHMENT_MAX_BYTES = 64 * 1024 * 1024
ATTACHMENTS_TOTAL_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_ATTACHMENT_PAGE_LIMIT = 100
MAX_ATTACHMENT_PAGE_LIMIT = 500
DEFAULT_SUBMISSION_PAGE_LIMIT = 100
MAX_SUBMISSION_PAGE_LIMIT = 500
PACKAGE_MAX_BYTES = (
    WORKSPACE_MARKDOWN_MAX_BYTES + ATTACHMENTS_TOTAL_MAX_BYTES + 2 * 1024 * 1024
)
_SHA256_LENGTH = 64
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_ATTACHMENT_BASENAME_MAX_LENGTH = 120
_REPORTABLE_STATUSES = frozenset(
    {"active", "blocked", "exploited", "contained", "eradicated", "recovered", "reported"}
)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_package_relative_path(path_value: str) -> str:
    """Validate an internal package path without resolving away its leaf."""
    value = str(path_value or "").strip()
    components = value.split("/")
    if (
        not value
        or value.startswith("/")
        or any(component in {"", ".", ".."} for component in components)
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission package reservation contains an unsafe path",
        )
    return "/".join(components)


def _json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    try:
        decoded = json.loads(str(value or "[]"))
    except json.JSONDecodeError:
        return []
    return decoded if isinstance(decoded, list) else []


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    try:
        decoded = json.loads(str(value or "{}"))
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _page_metadata(*, offset: int, limit: int, returned: int, total: int) -> dict[str, Any]:
    next_offset = offset + returned
    has_more = next_offset < total
    return {
        "offset": offset,
        "limit": limit,
        "returned": returned,
        "total": total,
        "has_more": has_more,
        "next_offset": next_offset if has_more else None,
    }


def _validate_offset_page(*, offset: int, limit: int, label: str) -> None:
    if offset < 0:
        raise HTTPException(status_code=400, detail=f"{label}_offset must be non-negative")
    if limit < 1 or limit > MAX_SUBMISSION_PAGE_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=(
                f"{label}_limit must be between 1 and "
                f"{MAX_SUBMISSION_PAGE_LIMIT}"
            ),
        )


def _iter_staging_relative_paths(root: Path) -> Iterable[str]:
    submissions = root / "submissions"
    if not submissions.exists() or submissions.is_symlink():
        return
    try:
        finding_directories = submissions.iterdir()
        for finding_directory in finding_directories:
            if finding_directory.is_symlink() or not finding_directory.is_dir():
                continue
            staging = finding_directory / "versions" / ".staging"
            if not staging.exists() or staging.is_symlink() or not staging.is_dir():
                continue
            for path in staging.iterdir():
                if path.is_symlink() or not path.is_file():
                    continue
                try:
                    yield path.relative_to(root).as_posix()
                except ValueError:
                    continue
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"submission staging tree could not be scanned safely: {exc}",
        ) from exc


def _orphaned_staging_page(
    root: Path,
    known_staging: set[str],
    *,
    after: str,
    limit: int,
) -> tuple[list[str], dict[str, Any]]:
    if limit < 1 or limit > MAX_SUBMISSION_PAGE_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=(
                "orphan_limit must be between 1 and "
                f"{MAX_SUBMISSION_PAGE_LIMIT}"
            ),
        )
    candidates = (
        relative
        for relative in _iter_staging_relative_paths(root)
        if relative not in known_staging and (not after or relative > after)
    )
    selected = heapq.nsmallest(limit + 1, candidates)
    has_more = len(selected) > limit
    paths = selected[:limit]
    return paths, {
        "limit": limit,
        "returned": len(paths),
        "has_more": has_more,
        "next_after": paths[-1] if has_more else None,
    }


def _read_stable_file(
    root: Path,
    relative_path: str,
    *,
    max_bytes: int,
    label: str,
    package_path: bool = False,
) -> tuple[str, bytes]:
    normalized = (
        _normalize_package_relative_path(relative_path)
        if package_path
        else artifact_index._normalize_relative_path(root, relative_path)
    )
    descriptor = artifact_index._open_registered_artifact(root, normalized)
    if descriptor is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{label} is missing: {normalized}",
        )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{label} must be a regular file: {normalized}",
            )
        if before.st_size > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"{label} exceeds the {max_bytes}-byte limit: {normalized}",
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(data) > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"{label} exceeds the {max_bytes}-byte limit: {normalized}",
            )
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or len(data) != after.st_size
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{label} changed while it was being read: {normalized}",
            )
        return normalized, data
    finally:
        os.close(descriptor)


def _load_context(data: bytes) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        decoded = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"submission context is invalid JSON: {exc}",
        ) from exc
    if not isinstance(decoded, dict):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission context must be a JSON object",
        )
    return decoded


def _target_readiness_blockers(engagement_id: int, slug: str) -> list[dict[str, Any]]:
    readiness = report_readiness(engagement_id)
    blockers = readiness.get("blockers", [])
    result: list[dict[str, Any]] = []
    for blocker in blockers if isinstance(blockers, list) else []:
        if not isinstance(blocker, dict):
            continue
        slugs = blocker.get("slugs", [])
        matches_many = isinstance(slugs, list) and slug in {str(item) for item in slugs}
        if str(blocker.get("slug") or blocker.get("finding_slug") or "") == slug or matches_many:
            result.append(blocker)
    return result


def _workspace_artifact(
    engagement_id: int,
    *,
    relative_path: str,
    finding_slug: str,
    sha256: str,
) -> dict[str, Any]:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT * FROM assessment_artifacts
            WHERE engagement_id = ? AND relative_path = ?
            """,
            (engagement_id, relative_path),
        ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission workspace is not registered as an artifact",
        )
    record = dict(row)
    if not bool(record.get("present")):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission workspace artifact is indexed as missing",
        )
    if str(record.get("kind") or "") != "submission":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission workspace artifact must use kind='submission'",
        )
    if str(record.get("related_finding_slug") or "") != finding_slug:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission workspace artifact is not linked to this finding",
        )
    if str(record.get("sha256") or "") != sha256:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission workspace changed since artifact registration",
        )
    return record


def _workspace_state(
    engagement_id: int,
    slug: str,
    *,
    submission_path: str,
    context_path: str,
    require_registered: bool,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    root = Path(engagement.engagement_root).expanduser().resolve()
    finding = state_manager.get_finding(engagement_id, slug)
    normalized_submission, markdown = _read_stable_file(
        root,
        submission_path,
        max_bytes=WORKSPACE_MARKDOWN_MAX_BYTES,
        label="submission workspace",
    )
    normalized_context, context_bytes = _read_stable_file(
        root,
        context_path,
        max_bytes=WORKSPACE_CONTEXT_MAX_BYTES,
        label="submission context",
    )
    try:
        markdown_text = markdown.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission workspace Markdown must be valid UTF-8",
        ) from exc
    expected_context = (
        PurePosixPath(normalized_submission).parent / "submission-context.json"
    ).as_posix()
    if normalized_context != expected_context:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission context must be adjacent to submission.md",
        )
    markdown_sha256 = _sha256(markdown)
    context = _load_context(context_bytes)
    blockers: list[str] = []
    body_path = (PurePosixPath(normalized_submission).parent / "submission-body.md").as_posix()
    try:
        _, external_body = _read_stable_file(
            root, body_path, max_bytes=WORKSPACE_MARKDOWN_MAX_BYTES,
            label="external submission body",
        )
    except HTTPException as exc:
        external_body = b""
        blockers.append(str(exc.detail))
    if str(context.get("slug") or "") != slug:
        blockers.append("submission context names a different finding")
    if str(context.get("submission_path") or "") != normalized_submission:
        blockers.append("submission context names a different Markdown path")
    if str(context.get("submission_sha256") or "") != markdown_sha256:
        blockers.append("submission context does not bind the current Markdown bytes")
    if str(context.get("external_body_sha256") or "") != _sha256(external_body):
        blockers.append("submission context does not bind the current external body bytes")
    if str(context.get("mode") or "") != "final":
        blockers.append("workspace is a draft render; create a final render before export")
    source = context.get("source_finding")
    if not isinstance(source, dict):
        blockers.append("submission context has no source finding snapshot")
        source = {}
    expected_source = {
        "id": finding.get("id"),
        "row_version": finding.get("row_version"),
        "updated_at": finding.get("updated_at"),
        "workflow_status": finding.get("workflow_status"),
        "verification_status": finding.get("verification_status"),
    }
    if any(source.get(key) != value for key, value in expected_source.items()):
        blockers.append("submission workspace is stale relative to the current finding")
    if finding.get("workflow_status") not in _REPORTABLE_STATUSES:
        blockers.append(
            f"finding workflow_status={finding.get('workflow_status')!r} is not reportable"
        )
    if finding.get("verification_status") not in {"confirmed", "downgraded"}:
        blockers.append("finding is not currently verified as confirmed or downgraded")
    if context.get("missing") != []:
        blockers.append("submission context still has proof-critical missing fields")
    proof = context.get("proof")
    if not isinstance(proof, dict) or proof.get("has_durable_proof") is not True:
        blockers.append("submission context has no durable proof")
    if context.get("hygiene_warnings") != []:
        blockers.append("submission context still has hygiene warnings")
    if context.get("readiness_blockers") != [] or str(
        context.get("readiness_error") or ""
    ):
        blockers.append("submission context still has readiness blockers")
    audit = finding.get("verification_audit")
    if not isinstance(audit, dict) or int(audit.get("proof_receipt_total") or 0) < 1:
        blockers.append("finding has no current verification proof receipt")
    if isinstance(audit, dict) and audit.get("claim_review_pending"):
        blockers.append("finding claim change awaits an independent equivalence review or new verification")
    with get_connection() as connection:
        proof_issues = proof_evidence_health_issues_for_finding(
            connection, engagement_id, int(finding["id"])
        )
    if proof_issues:
        blockers.append("finding has unhealthy required proof evidence")
    for row in _target_readiness_blockers(engagement_id, slug):
        detail = str(row.get("detail") or row.get("kind") or "readiness blocker")
        blockers.append(f"report readiness: {detail}")

    artifact = None
    if require_registered:
        artifact = _workspace_artifact(
            engagement_id,
            relative_path=normalized_submission,
            finding_slug=slug,
            sha256=markdown_sha256,
        )
    return {
        "finding": finding,
        "submission_path": normalized_submission,
        "context_path": normalized_context,
        "markdown": markdown,
        "markdown_text": markdown_text,
        "external_body": external_body,
        "external_body_sha256": _sha256(external_body),
        "submission_sha256": markdown_sha256,
        "context": context,
        "context_sha256": _sha256(context_bytes),
        "workspace_artifact": artifact,
        "blockers": list(dict.fromkeys(blockers)),
    }


def _read_attachment(
    engagement_id: int,
    root: Path,
    artifact_id: int,
) -> tuple[dict[str, Any], bytes]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_artifacts WHERE engagement_id = ? AND id = ?",
            (engagement_id, artifact_id),
        ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"attachment artifact {artifact_id} was not found in this engagement",
        )
    record = dict(row)
    if not bool(record.get("present")):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"attachment artifact {artifact_id} is indexed as missing",
        )
    relative_path, data = _read_stable_file(
        root,
        str(record.get("relative_path") or ""),
        max_bytes=ATTACHMENT_MAX_BYTES,
        label=f"attachment artifact {artifact_id}",
    )
    digest = _sha256(data)
    if (
        len(str(record.get("sha256") or "")) != _SHA256_LENGTH
        or str(record.get("sha256") or "") != digest
        or int(record.get("size_bytes") or 0) != len(data)
    ):
        with get_connection() as connection:
            connection.execute(
                """
                UPDATE assessment_artifacts
                SET integrity_status = 'mismatch', updated_at = ?
                WHERE engagement_id = ? AND id = ?
                """,
                (_utcnow_iso(), engagement_id, artifact_id),
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"attachment artifact {artifact_id} changed since registration",
        )
    archive_path = (
        f"attachments/{artifact_id}-{_portable_attachment_basename(relative_path)}"
    )
    return (
        {
            "artifact_id": artifact_id,
            "archive_path": archive_path,
            "original_relative_path": relative_path,
            "media_type": str(record.get("media_type") or "application/octet-stream"),
            "size_bytes": len(data),
            "sha256": digest,
        },
        data,
    )


def _portable_attachment_basename(relative_path: str) -> str:
    basename = PurePosixPath(relative_path).name
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "-", basename)
    sanitized = re.sub(r"\.{2,}", "-", sanitized)
    sanitized = re.sub(r"[-_]{2,}", "-", sanitized).strip("._-")
    sanitized = sanitized[:_ATTACHMENT_BASENAME_MAX_LENGTH].rstrip("._-")
    return sanitized or "artifact"


def _blind_triage_issue(
    engagement_id: int,
    slug: str,
    root: Path,
    workspace: dict[str, Any],
    platform: str,
    attachments: list[tuple[dict[str, Any], bytes]],
    connection: Any | None = None,
) -> str | None:
    """Compare the latest verdict with the exact external package being exported."""
    if str(workspace["finding"].get("severity") or "").lower() not in {
        "medium", "high", "critical",
    }:
        return None
    with nullcontext(connection) if connection is not None else get_connection() as current:
        decision = current.execute(
            """
            SELECT payload_json FROM assessment_dispatch_decisions
            WHERE engagement_id = ? AND kind = 'blind_triage_verdict'
              AND json_extract(payload_json, '$.finding_slug') = ?
            ORDER BY id DESC LIMIT 1
            """,
            (engagement_id, slug),
        ).fetchone()
    if decision is None:
        return "blind triage has no verdict for the current finding"
    payload = json.loads(decision["payload_json"])
    if not re.fullmatch(r"Accept@P[1-5]", str(payload.get("verdict") or "")):
        return "latest blind triage verdict does not accept this finding"
    packet_id = str(payload.get("packet_id") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", packet_id):
        return "latest blind triage verdict has no content-addressed packet"
    try:
        _, raw = _read_stable_file(
            root,
            f"submissions/{slug}/blind-triage/{packet_id}/manifest.json",
            max_bytes=WORKSPACE_CONTEXT_MAX_BYTES,
            label="blind triage packet manifest",
        )
        manifest = json.loads(raw)
    except (HTTPException, ValueError) as exc:
        return f"blind triage packet manifest is unavailable or invalid: {exc}"
    if not isinstance(manifest, dict) or manifest.get("packet_id") != packet_id:
        return "blind triage packet manifest does not match its verdict"
    identity = {key: value for key, value in manifest.items() if key not in {"packet_id", "outputs"}}
    if _sha256(_canonical_json(identity).encode("utf-8")) != packet_id:
        return "blind triage packet identity is invalid"
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        return "blind triage packet inputs are missing"
    if (
        manifest.get("finding_slug") != slug
        or manifest.get("platform") != platform
        or (inputs.get("submission") or {}).get("sha256") != workspace["external_body_sha256"]
    ):
        return "blind triage verdict covers a different submission body or platform"
    selected = sorted(
        (int(row["artifact_id"]), str(row["sha256"]), int(row["size_bytes"]))
        for row, _ in attachments
    )
    packet_attachments = inputs.get("attachments")
    if not isinstance(packet_attachments, list):
        return "blind triage packet does not declare selected attachments"
    reviewed = sorted(
        (int(row["artifact_id"]), str(row["sha256"]), int(row["bytes"]))
        for row in packet_attachments
        if isinstance(row, dict)
    )
    if selected != reviewed:
        return "blind triage verdict covers different external attachments"
    _, brief = _read_stable_file(
        root, "ENGAGEMENT.md", max_bytes=WORKSPACE_MARKDOWN_MAX_BYTES,
        label="blind triage program brief",
    )
    prompt_root = Path(__file__).resolve().parents[4]
    _, rubric = _read_stable_file(
        prompt_root, "agent/skills/blind-triage/SKILL.md",
        max_bytes=WORKSPACE_MARKDOWN_MAX_BYTES, label="blind triage verdict rubric",
    )
    # New decisions require attribution at creation. Stored pre-attribution
    # Accepts retain their original rubric when the exact external package and
    # program brief still match; an upgrade must not fabricate audit history.
    if (
        (inputs.get("program_brief") or {}).get("sha256") != _sha256(brief)
        or (
            payload.get("reviewer_dispatch_agent_id")
            and (inputs.get("verdict_rubric") or {}).get("sha256") != _sha256(rubric)
        )
    ):
        return "blind triage verdict covers an older program brief or rubric"
    return None


def _reproduction_issue(
    engagement_id: int, slug: str, finding: dict[str, Any],
    connection: Any | None = None,
) -> str | None:
    """A report can only publish the reproduction last checked by a tester."""
    with nullcontext(connection) if connection is not None else get_connection() as current:
        decision = current.execute(
            """
            SELECT payload_json FROM assessment_dispatch_decisions
            WHERE engagement_id = ? AND kind = 'repro_rehearsal'
              AND json_extract(payload_json, '$.finding_slug') = ?
            ORDER BY id DESC LIMIT 1
            """,
            (engagement_id, slug),
        ).fetchone()
    if decision is None:
        return "reproduction has no independent check"
    payload = json.loads(decision["payload_json"])
    if payload.get("verdict") not in {"followed", "equivalent"}:
        return "latest reproduction check did not confirm the authored steps"
    if payload.get("reproduction_sha256") != reproduction_sha256(finding):
        return "reproduction steps changed after the latest independent check"
    return None


def _zip_member(name: str, data: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name, date_time=_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    info.flag_bits = 0
    return info, data


def _build_package(
    slug: str,
    markdown: bytes,
    attachments: list[tuple[dict[str, Any], bytes]],
) -> tuple[bytes, str, str, dict[str, Any]]:
    if not attachments:
        return markdown, "markdown", "text/markdown", {}
    submission_sha256 = _sha256(markdown)
    manifest = {
        "schema": "vigil-submission-attachment-manifest/v1",
        "finding_slug": slug,
        "submission_sha256": submission_sha256,
        "attachments": [row for row, _data in attachments],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", allowZip64=True) as archive:
        for name, data in (
            ("submission.md", markdown),
            ("attachment-manifest.json", manifest_bytes),
            *((row["archive_path"], data) for row, data in attachments),
        ):
            info, content = _zip_member(str(name), data)
            archive.writestr(info, content)
    package = stream.getvalue()
    if len(package) > PACKAGE_MAX_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"submission package exceeds the {PACKAGE_MAX_BYTES}-byte limit",
        )
    return package, "zip", "application/zip", manifest


def _ensure_parent(root: Path, relative_path: str) -> Path:
    normalized = _normalize_package_relative_path(relative_path)
    candidate = root.joinpath(*PurePosixPath(normalized).parts)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptors: list[int] = []
    current_path = root
    try:
        current = os.open(root, directory_flags)
        descriptors.append(current)
        for part in PurePosixPath(normalized).parts[:-1]:
            created = False
            try:
                child = os.open(part, directory_flags, dir_fd=current)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                    created = True
                except FileExistsError:
                    pass
                child = os.open(part, directory_flags, dir_fd=current)
            except OSError as exc:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"submission package parent is unsafe: {normalized}",
                ) from exc
            descriptors.append(child)
            if created:
                _fsync_parent_directory(current, current_path)
            current = child
            current_path = current_path / part
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"submission package parent could not be opened safely: {normalized}",
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return candidate


def _stage_package(root: Path, relative_path: str, package: bytes, expected_sha256: str) -> None:
    path = _ensure_parent(root, relative_path)
    if path.exists() or path.is_symlink():
        _normalized, existing = _read_stable_file(
            root,
            relative_path,
            max_bytes=PACKAGE_MAX_BYTES,
            label="staged submission package",
            package_path=True,
        )
        if _sha256(existing) != expected_sha256:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="staged submission package does not match its durable reservation",
            )
        return
    transient = path.with_name(f"{path.name}.writing-{secrets.token_hex(8)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(transient, flags, 0o600)
    try:
        created_stat = os.fstat(descriptor)
    except OSError as exc:
        try:
            os.close(descriptor)
        finally:
            try:
                current = transient.lstat()
                if stat.S_ISREG(current.st_mode):
                    transient.unlink()
                    _fsync_directory(transient.parent)
            except FileNotFoundError:
                pass
            except OSError as cleanup_exc:
                raise OSError(
                    f"{exc}; transient cleanup failed: {cleanup_exc}"
                ) from exc
        raise
    try:
        try:
            view = memoryview(package)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("could not write staged submission package")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(transient.parent)
        transient_relative = transient.relative_to(root).as_posix()
        _normalized, staged = _read_stable_file(
            root,
            transient_relative,
            max_bytes=PACKAGE_MAX_BYTES,
            label="transient staged submission package",
            package_path=True,
        )
        if len(staged) != len(package) or _sha256(staged) != expected_sha256:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="transient staged submission package failed byte verification",
            )
        try:
            os.link(transient, path, follow_symlinks=False)
        except FileExistsError:
            cleanup_error = _cleanup_transient_stage(transient, created_stat)
            if cleanup_error:
                raise OSError(cleanup_error)
            _normalized, existing = _read_stable_file(
                root,
                relative_path,
                max_bytes=PACKAGE_MAX_BYTES,
                label="staged submission package",
                package_path=True,
            )
            if _sha256(existing) != expected_sha256:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "staged submission package conflicts with its durable "
                        "reservation"
                    ),
                )
            return
        _fsync_directory(path.parent)
        cleanup_error = _cleanup_transient_stage(transient, created_stat)
        if cleanup_error:
            raise OSError(cleanup_error)
    except (HTTPException, OSError) as exc:
        cleanup_error = _cleanup_transient_stage(transient, created_stat)
        if not cleanup_error:
            raise
        if isinstance(exc, HTTPException):
            raise HTTPException(
                status_code=exc.status_code,
                detail=f"{exc.detail}; transient cleanup failed: {cleanup_error}",
            ) from exc
        raise OSError(f"{exc}; transient cleanup failed: {cleanup_error}") from exc


def _cleanup_transient_stage(path: Path, created_stat: os.stat_result) -> str:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return ""
    except OSError as exc:
        return f"could not inspect transient stage {path}: {exc}"
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_dev != created_stat.st_dev
        or current.st_ino != created_stat.st_ino
    ):
        return f"transient stage changed identity and was left in place: {path}"
    try:
        path.unlink()
    except OSError as exc:
        return f"could not remove transient stage {path}: {exc}"
    try:
        _fsync_directory(path.parent)
    except OSError as exc:
        return f"removed transient stage but could not fsync {path.parent}: {exc}"
    return ""


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_parent_directory(descriptor: int, path: Path) -> None:
    """Persist one newly-created child entry through its already-pinned parent."""
    del path
    os.fsync(descriptor)


def _atomic_publish(
    root: Path,
    staging_relative_path: str,
    relative_path: str,
    expected_sha256: str,
) -> None:
    destination = _ensure_parent(root, relative_path)
    normalized_staging = _normalize_package_relative_path(staging_relative_path)
    staging = root.joinpath(*PurePosixPath(normalized_staging).parts)
    if destination.exists() or destination.is_symlink():
        _normalized, existing = _read_stable_file(
            root,
            relative_path,
            max_bytes=PACKAGE_MAX_BYTES,
            label="published submission package",
            package_path=True,
        )
        if _sha256(existing) != expected_sha256:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="published submission package conflicts with its durable reservation",
            )
        if staging.exists() or staging.is_symlink():
            _normalized, staged = _read_stable_file(
                root,
                normalized_staging,
                max_bytes=PACKAGE_MAX_BYTES,
                label="staged submission package",
                package_path=True,
            )
            if _sha256(staged) != expected_sha256:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "staged submission package conflicts with its durable "
                        "reservation"
                    ),
                )
            staging.unlink()
            _fsync_directory(staging.parent)
        return
    _normalized, staged = _read_stable_file(
        root,
        normalized_staging,
        max_bytes=PACKAGE_MAX_BYTES,
        label="staged submission package",
        package_path=True,
    )
    if _sha256(staged) != expected_sha256:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="staged submission package failed pre-publish verification",
        )
    os.replace(staging, destination)
    _normalized, published = _read_stable_file(
        root,
        relative_path,
        max_bytes=PACKAGE_MAX_BYTES,
        label="published submission package",
        package_path=True,
    )
    if _sha256(published) != expected_sha256:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="published submission package failed byte verification",
        )
    descriptor = os.open(
        destination,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(destination.parent)
    if staging.parent != destination.parent:
        _fsync_directory(staging.parent)


def _serialize_version(row: Mapping[str, Any], *, idempotent_replay: bool = False) -> dict[str, Any]:
    attachments = _json_list(row.get("attachment_ids_json"))
    return {
        "id": int(row["id"]),
        "finding_id": int(row["finding_id"]),
        "version_number": int(row["version_number"]),
        "status": str(row["status"]),
        "platform": str(row["platform"]),
        "package_format": str(row["package_format"]),
        "actor_surface": str(row["actor_surface"]),
        "relative_path": str(row["relative_path"]),
        "media_type": str(row["media_type"]),
        "size_bytes": int(row["size_bytes"]),
        "sha256": str(row["sha256"]),
        "submission_sha256": str(row["submission_sha256"]),
        "source_finding_row_version": int(row["source_finding_row_version"]),
        "source_finding_updated_at": str(row["source_finding_updated_at"]),
        "attachment_ids": [int(value) for value in attachments],
        "attachment_count": len(attachments),
        "manifest": _json_object(row.get("manifest_json")),
        "sources": _json_object(row.get("sources_json")),
        "artifact_id": row.get("artifact_id"),
        "failure_reason": str(row.get("failure_reason") or ""),
        "created_at": str(row["created_at"]),
        "completed_at": row.get("completed_at"),
        "stale": int(row["source_finding_row_version"])
        != int(row.get("current_finding_row_version") or row["source_finding_row_version"]),
        "idempotent_replay": idempotent_replay,
    }


def _serialize_pending_version(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "finding_slug": str(row["finding_slug"]),
        "version_number": int(row["version_number"]),
        "status": str(row["status"]),
        "failure_reason": str(row.get("failure_reason") or ""),
        "staging_relative_path": str(row["staging_relative_path"]),
        "relative_path": str(row["relative_path"]),
    }


def _version_row(version_id: int) -> dict[str, Any]:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT versions.*, findings.row_version AS current_finding_row_version
            FROM assessment_submission_versions AS versions
            JOIN assessment_findings AS findings ON findings.id = versions.finding_id
            WHERE versions.id = ?
            """,
            (version_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="submission version not found",
        )
    return dict(row)


def _verify_published_package(root: Path, row: Mapping[str, Any]) -> bytes:
    _normalized, package = _read_stable_file(
        root,
        str(row["relative_path"]),
        max_bytes=PACKAGE_MAX_BYTES,
        label="published submission package",
        package_path=True,
    )
    if len(package) != int(row["size_bytes"]) or _sha256(package) != str(row["sha256"]):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="published submission package no longer matches its immutable metadata",
        )
    return package


def _reserve_version(
    engagement_id: int,
    finding: Mapping[str, Any],
    *,
    platform: str,
    package_format: str,
    actor_surface: str,
    media_type: str,
    size_bytes: int,
    sha256: str,
    submission_sha256: str,
    attachment_ids: list[int],
    manifest: Mapping[str, Any],
    sources: Mapping[str, Any],
    request_sha256: str,
) -> tuple[dict[str, Any], bool]:
    finding_id = int(finding["id"])
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            """
            SELECT * FROM assessment_submission_versions
            WHERE engagement_id = ? AND finding_id = ? AND request_sha256 = ?
            """,
            (engagement_id, finding_id, request_sha256),
        ).fetchone()
        if existing is not None:
            existing_row = dict(existing)
            if existing_row["status"] == "failed":
                connection.execute(
                    """
                    UPDATE assessment_submission_versions
                    SET status = 'staging', failure_reason = ''
                    WHERE id = ?
                    """,
                    (int(existing_row["id"]),),
                )
                existing_row["status"] = "staging"
                existing_row["failure_reason"] = ""
            return existing_row, True
        next_number = int(
            connection.execute(
                """
                SELECT COALESCE(MAX(version_number), 0) + 1
                FROM assessment_submission_versions
                WHERE engagement_id = ? AND finding_id = ?
                """,
                (engagement_id, finding_id),
            ).fetchone()[0]
        )
        extension = "md" if package_format == "markdown" else "zip"
        relative_path = (
            f"submissions/{finding['slug']}/versions/{next_number:04d}/"
            f"submission.{extension}"
        )
        staging_relative_path = (
            f"submissions/{finding['slug']}/versions/.staging/"
            f"{next_number:04d}-{request_sha256}.tmp"
        )
        cursor = connection.execute(
            """
            INSERT INTO assessment_submission_versions (
                engagement_id, finding_id, version_number, status, platform,
                package_format, actor_surface, relative_path,
                staging_relative_path, media_type, size_bytes, sha256,
                submission_sha256, source_finding_row_version,
                source_finding_updated_at, attachment_ids_json, manifest_json,
                sources_json, request_sha256
            ) VALUES (?, ?, ?, 'staging', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                finding_id,
                next_number,
                platform,
                package_format,
                actor_surface,
                relative_path,
                staging_relative_path,
                media_type,
                size_bytes,
                sha256,
                submission_sha256,
                int(finding["row_version"]),
                str(finding["updated_at"]),
                _canonical_json(attachment_ids),
                _canonical_json(manifest),
                _canonical_json(sources),
                request_sha256,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_submission_versions WHERE id = ?",
            (int(cursor.lastrowid),),
        ).fetchone()
    assert row is not None
    return dict(row), False


def _complete_version(engagement_id: int, row: Mapping[str, Any]) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    root = Path(engagement.engagement_root).expanduser().resolve()
    _verify_published_package(root, row)
    sources = _json_object(row["sources_json"])
    finding_source = sources.get("finding")
    if not isinstance(finding_source, dict) or not finding_source.get("slug"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission version reservation has no source finding identity",
        )
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        finding = connection.execute(
            """
            SELECT *
            FROM assessment_findings
            WHERE engagement_id = ? AND id = ?
            """,
            (engagement_id, int(row["finding_id"])),
        ).fetchone()
        source_matches = bool(
            finding is not None
            and int(finding_source.get("id") or 0) == int(finding["id"])
            and str(finding_source.get("slug") or "") == str(finding["slug"])
            and int(finding_source.get("row_version") or 0)
            == int(finding["row_version"])
            and str(finding_source.get("updated_at") or "")
            == str(finding["updated_at"])
            and str(finding_source.get("workflow_status") or "")
            == str(finding["status"])
            and str(finding_source.get("verification_status") or "")
            == str(finding["verification_status"])
        )
        if not source_matches:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "finding changed while the submission version was being finalized; "
                    "render and review a fresh final workspace"
                ),
            )
        proof_issues = proof_evidence_health_issues_for_finding(
            connection, engagement_id, int(row["finding_id"])
        )
        if proof_issues:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "finding proof evidence changed while the submission version "
                    "was being finalized; capture healthy proof and render a fresh "
                    "final workspace"
                ),
            )
        readiness_blockers = _target_readiness_blockers(
            engagement_id, str(finding["slug"])
        )
        if readiness_blockers:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "finding readiness changed while the submission version was "
                    "being finalized; resolve the current blockers and render a "
                    "fresh final workspace"
                ),
            )
        workspace_source = sources.get("workspace")
        attachment_sources = sources.get("attachments")
        if not isinstance(workspace_source, dict) or not isinstance(attachment_sources, list) or any(
            not isinstance(item, dict) for item in attachment_sources
        ):
            raise HTTPException(status_code=409, detail="submission reservation has incomplete review sources")
        reviewed_workspace = {
            "finding": dict(finding),
            "external_body_sha256": workspace_source.get("external_body_sha256"),
        }
        triage_issue = _blind_triage_issue(
            engagement_id, str(finding["slug"]), root, reviewed_workspace,
            str(row["platform"]), [(item, b"") for item in attachment_sources],
            connection,
        )
        reproduction_issue = _reproduction_issue(
            engagement_id, str(finding["slug"]), dict(finding), connection,
        )
        if triage_issue or reproduction_issue:
            raise HTTPException(
                status_code=409,
                detail="submission review changed during finalization: " + "; ".join(
                    issue for issue in (triage_issue, reproduction_issue) if issue
                ),
            )
        artifact = artifact_index.register_artifact(
            engagement_id,
            path=str(row["relative_path"]),
            kind="submission-version",
            media_type=str(row["media_type"]),
            related_finding_slug=str(finding["slug"]),
        )
        if (
            not bool(artifact.get("present"))
            or int(artifact.get("size_bytes") or 0) != int(row["size_bytes"])
            or str(artifact.get("sha256") or "") != str(row["sha256"])
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "published submission package changed while version metadata "
                    "was finalized; recover from the verified staging package"
                ),
            )
        completed_at = _utcnow_iso()
        connection.execute(
            """
            UPDATE assessment_submission_versions
            SET status = 'complete', artifact_id = ?, completed_at = ?, failure_reason = ''
            WHERE id = ? AND status != 'complete'
            """,
            (int(artifact["id"]), completed_at, int(row["id"])),
        )
    return _version_row(int(row["id"]))


def export_version(
    engagement_id: int,
    slug: str,
    *,
    platform: str,
    submission_path: str,
    context_path: str,
    attachment_ids: Iterable[int],
    actor_surface: str,
) -> dict[str, Any]:
    if platform not in SUBMISSION_PLATFORMS:
        raise HTTPException(status_code=400, detail=f"unsupported submission platform: {platform}")
    if actor_surface not in ACTOR_SURFACES:
        raise HTTPException(status_code=400, detail=f"unsupported actor surface: {actor_surface}")
    ids = [int(value) for value in attachment_ids]
    if len(ids) != len(set(ids)):
        raise HTTPException(status_code=400, detail="attachment_ids must not contain duplicates")
    ids.sort()
    workspace = _workspace_state(
        engagement_id,
        slug,
        submission_path=submission_path,
        context_path=context_path,
        require_registered=True,
    )
    if str(workspace["context"].get("platform") or "") != platform:
        workspace["blockers"].append("submission platform differs from its rendered context")
    if workspace["blockers"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission export is not final-ready: " + "; ".join(workspace["blockers"]),
        )
    engagement = _engagement_or_404(engagement_id)
    root = Path(engagement.engagement_root).expanduser().resolve()
    attachments: list[tuple[dict[str, Any], bytes]] = []
    attachment_bytes = 0
    for artifact_id in ids:
        attachment = _read_attachment(engagement_id, root, artifact_id)
        attachment_bytes += len(attachment[1])
        if attachment_bytes > ATTACHMENTS_TOTAL_MAX_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=(
                    "selected attachments exceed the "
                    f"{ATTACHMENTS_TOTAL_MAX_BYTES}-byte total limit"
                ),
            )
        attachments.append(attachment)
    triage_issue = _blind_triage_issue(
        engagement_id, slug, root, workspace, platform, attachments,
    )
    if triage_issue:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission export is not final-ready: " + triage_issue,
        )
    reproduction_issue = _reproduction_issue(engagement_id, slug, workspace["finding"])
    if reproduction_issue:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission export is not final-ready: " + reproduction_issue,
        )
    package, package_format, media_type, manifest = _build_package(
        slug, workspace["external_body"], attachments
    )
    package_sha256 = _sha256(package)
    sources = {
        "finding": {
            "id": int(workspace["finding"]["id"]),
            "slug": slug,
            "row_version": int(workspace["finding"]["row_version"]),
            "updated_at": str(workspace["finding"]["updated_at"]),
            "workflow_status": str(workspace["finding"]["workflow_status"]),
            "verification_status": str(workspace["finding"]["verification_status"]),
        },
        "workspace": {
            "artifact_id": int(workspace["workspace_artifact"]["id"]),
            "submission_path": workspace["submission_path"],
            "submission_sha256": workspace["submission_sha256"],
            "external_body_sha256": workspace["external_body_sha256"],
            "context_path": workspace["context_path"],
            "context_sha256": workspace["context_sha256"],
        },
        "attachments": [row for row, _data in attachments],
    }
    request_sha256 = _sha256(
        _canonical_json(
            {
                "schema": "vigil-submission-export-request/v1",
                "platform": platform,
                "package_format": package_format,
                "package_sha256": package_sha256,
                "sources": sources,
            }
        ).encode("utf-8")
    )
    row, replay = _reserve_version(
        engagement_id,
        workspace["finding"],
        platform=platform,
        package_format=package_format,
        actor_surface=actor_surface,
        media_type=media_type,
        size_bytes=len(package),
        sha256=package_sha256,
        submission_sha256=workspace["external_body_sha256"],
        attachment_ids=ids,
        manifest=manifest,
        sources=sources,
        request_sha256=request_sha256,
    )
    if row["status"] == "complete":
        _verify_published_package(root, row)
        return _serialize_version(_version_row(int(row["id"])), idempotent_replay=True)
    try:
        _stage_package(root, str(row["staging_relative_path"]), package, package_sha256)
        _atomic_publish(
            root,
            str(row["staging_relative_path"]),
            str(row["relative_path"]),
            package_sha256,
        )
        completed = _complete_version(engagement_id, row)
    except HTTPException:
        raise
    except OSError as exc:
        with get_connection() as connection:
            connection.execute(
                "UPDATE assessment_submission_versions SET failure_reason = ? WHERE id = ?",
                (str(exc), int(row["id"])),
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"submission version {row['version_number']} remains staged for recovery: {exc}"
            ),
        ) from exc
    return _serialize_version(completed, idempotent_replay=replay)


def list_versions(
    engagement_id: int,
    slug: str,
    *,
    limit: int = DEFAULT_SUBMISSION_PAGE_LIMIT,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    _validate_offset_page(offset=offset, limit=limit, label="version")
    finding = state_manager.get_finding(engagement_id, slug)
    with get_connection() as connection:
        total = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM assessment_submission_versions
                WHERE engagement_id = ? AND finding_id = ? AND status = 'complete'
                """,
                (engagement_id, int(finding["id"])),
            ).fetchone()[0]
        )
        rows = connection.execute(
            """
            SELECT versions.*, findings.row_version AS current_finding_row_version
            FROM assessment_submission_versions AS versions
            JOIN assessment_findings AS findings ON findings.id = versions.finding_id
            WHERE versions.engagement_id = ? AND versions.finding_id = ?
              AND versions.status = 'complete'
            ORDER BY versions.version_number DESC
            LIMIT ? OFFSET ?
            """,
            (engagement_id, int(finding["id"]), limit, offset),
        ).fetchall()
    serialized = [_serialize_version(dict(row)) for row in rows]
    return serialized, _page_metadata(
        offset=offset,
        limit=limit,
        returned=len(serialized),
        total=total,
    )


def _workspace_paths(slug: str) -> tuple[str, str]:
    base = f"submissions/{slug}"
    return f"{base}/submission.md", f"{base}/submission-context.json"


def submission_detail(
    engagement_id: int,
    slug: str,
    *,
    attachment_ids: Iterable[int] = (),
    attachment_offset: int = 0,
    attachment_limit: int = DEFAULT_ATTACHMENT_PAGE_LIMIT,
    version_offset: int = 0,
    version_limit: int = DEFAULT_SUBMISSION_PAGE_LIMIT,
    pending_version_offset: int = 0,
    pending_version_limit: int = DEFAULT_SUBMISSION_PAGE_LIMIT,
) -> dict[str, Any]:
    selected_ids = [int(value) for value in attachment_ids]
    if len(selected_ids) != len(set(selected_ids)):
        raise HTTPException(status_code=400, detail="attachment_ids must not contain duplicates")
    selected_ids.sort()
    if attachment_offset < 0:
        raise HTTPException(status_code=400, detail="attachment_offset must be non-negative")
    if attachment_limit < 1 or attachment_limit > MAX_ATTACHMENT_PAGE_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=(
                "attachment_limit must be between 1 and "
                f"{MAX_ATTACHMENT_PAGE_LIMIT}"
            ),
        )
    _validate_offset_page(offset=version_offset, limit=version_limit, label="version")
    _validate_offset_page(
        offset=pending_version_offset,
        limit=pending_version_limit,
        label="pending_version",
    )
    finding = state_manager.get_finding(engagement_id, slug)
    submission_path, context_path = _workspace_paths(str(finding["slug"]))
    workspace_payload: dict[str, Any]
    try:
        workspace = _workspace_state(
            engagement_id,
            str(finding["slug"]),
            submission_path=submission_path,
            context_path=context_path,
            require_registered=False,
        )
        blockers = list(workspace["blockers"])
        try:
            _workspace_artifact(
                engagement_id,
                relative_path=workspace["submission_path"],
                finding_slug=str(finding["slug"]),
                sha256=workspace["submission_sha256"],
            )
        except HTTPException as exc:
            blockers.append(str(exc.detail))
        if not blockers:
            root = Path(_engagement_or_404(engagement_id).engagement_root).expanduser().resolve()
            try:
                attachments = [_read_attachment(engagement_id, root, artifact_id) for artifact_id in selected_ids]
                if sum(len(data) for _, data in attachments) > ATTACHMENTS_TOTAL_MAX_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="selected attachments exceed the total size limit",
                    )
                triage_issue = _blind_triage_issue(
                    engagement_id, str(finding["slug"]), root, workspace,
                    str(workspace["context"].get("platform") or ""), attachments,
                )
                if triage_issue:
                    blockers.append(triage_issue)
            except HTTPException as exc:
                blockers.append(str(exc.detail))
            reproduction_issue = _reproduction_issue(engagement_id, str(finding["slug"]), workspace["finding"])
            if reproduction_issue:
                blockers.append(reproduction_issue)
        workspace_payload = {
            "present": True,
            "submission_path": workspace["submission_path"],
            "context_path": workspace["context_path"],
            "markdown": workspace["markdown_text"],
            "submission_sha256": workspace["submission_sha256"],
            "external_body_sha256": workspace["external_body_sha256"],
            "context": workspace["context"],
            "final_ready": not blockers,
            "blockers": list(dict.fromkeys(blockers)),
        }
    except HTTPException as exc:
        workspace_payload = {
            "present": False,
            "submission_path": submission_path,
            "context_path": context_path,
            "markdown": "",
            "submission_sha256": "",
            "external_body_sha256": "",
            "context": {},
            "final_ready": False,
            "blockers": [str(exc.detail)],
        }
    with get_connection() as connection:
        eligible_attachment_total = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM assessment_artifacts
                WHERE engagement_id = ? AND present = 1 AND scratch = 0
                  AND length(sha256) = 64
                  AND kind NOT IN ('submission', 'submission-version')
                """,
                (engagement_id,),
            ).fetchone()[0]
        )
        artifact_rows = connection.execute(
            """
            SELECT * FROM assessment_artifacts
            WHERE engagement_id = ? AND present = 1 AND scratch = 0
              AND length(sha256) = 64
              AND kind NOT IN ('submission', 'submission-version')
            ORDER BY CASE WHEN related_finding_slug = ? THEN 0 ELSE 1 END,
                     updated_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (
                engagement_id,
                str(finding["slug"]),
                attachment_limit,
                attachment_offset,
            ),
        ).fetchall()
        pending_version_total = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM assessment_submission_versions
                WHERE engagement_id = ? AND finding_id = ? AND status != 'complete'
                """,
                (engagement_id, int(finding["id"])),
            ).fetchone()[0]
        )
        pending_rows = connection.execute(
            """
            SELECT versions.*, findings.slug AS finding_slug
            FROM assessment_submission_versions AS versions
            JOIN assessment_findings AS findings ON findings.id = versions.finding_id
            WHERE versions.engagement_id = ? AND versions.finding_id = ?
              AND versions.status != 'complete'
            ORDER BY versions.version_number DESC
            LIMIT ? OFFSET ?
            """,
            (
                engagement_id,
                int(finding["id"]),
                pending_version_limit,
                pending_version_offset,
            ),
        ).fetchall()
    eligible = [artifact_index._serialize_artifact(row, compact=True) for row in artifact_rows]
    next_offset = attachment_offset + len(eligible)
    has_more = next_offset < eligible_attachment_total
    versions, versions_page = list_versions(
        engagement_id,
        str(finding["slug"]),
        limit=version_limit,
        offset=version_offset,
    )
    pending_versions = [
        _serialize_pending_version(dict(row)) for row in pending_rows
    ]
    return {
        "finding": finding,
        "workspace": workspace_payload,
        "eligible_attachments": eligible,
        "eligible_attachments_page": {
            "offset": attachment_offset,
            "limit": attachment_limit,
            "returned": len(eligible),
            "total": eligible_attachment_total,
            "has_more": has_more,
            "next_offset": next_offset if has_more else None,
        },
        "versions": versions,
        "versions_page": versions_page,
        "pending_version_count": pending_version_total,
        "pending_versions": pending_versions,
        "pending_versions_page": _page_metadata(
            offset=pending_version_offset,
            limit=pending_version_limit,
            returned=len(pending_versions),
            total=pending_version_total,
        ),
    }


def list_submissions(
    engagement_id: int,
    *,
    limit: int = DEFAULT_SUBMISSION_PAGE_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    _validate_offset_page(offset=offset, limit=limit, label="finding")
    _engagement_or_404(engagement_id)
    with get_connection() as connection:
        finding_total = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM assessment_findings
                WHERE engagement_id = ? AND status NOT IN ('merged', 'false_positive')
                """,
                (engagement_id,),
            ).fetchone()[0]
        )
        rows = connection.execute(
            """
            SELECT findings.id, findings.slug, findings.title, findings.severity,
                   findings.status AS workflow_status,
                   findings.verification_status, findings.submission_status,
                   findings.submission_platform, findings.submission_ref,
                   findings.submission_url, findings.row_version,
                   COUNT(CASE WHEN versions.status = 'complete' THEN 1 END) AS version_count,
                   COUNT(CASE WHEN versions.status = 'staging' THEN 1 END)
                       AS staging_version_count,
                   COUNT(CASE WHEN versions.status = 'failed' THEN 1 END)
                       AS failed_version_count,
                   MAX(CASE WHEN versions.status = 'complete' THEN versions.version_number END)
                       AS latest_version_number
            FROM assessment_findings AS findings
            LEFT JOIN assessment_submission_versions AS versions
              ON versions.finding_id = findings.id
             AND versions.engagement_id = findings.engagement_id
            WHERE findings.engagement_id = ?
              AND findings.status NOT IN ('merged', 'false_positive')
            GROUP BY findings.id
            ORDER BY findings.updated_at DESC, findings.id DESC
            LIMIT ? OFFSET ?
            """,
            (engagement_id, limit, offset),
        ).fetchall()
        staging_count = connection.execute(
            """
            SELECT COUNT(*) FROM assessment_submission_versions
            WHERE engagement_id = ? AND status = 'staging'
            """,
            (engagement_id,),
        ).fetchone()[0]
        failed_count = connection.execute(
            """
            SELECT COUNT(*) FROM assessment_submission_versions
            WHERE engagement_id = ? AND status = 'failed'
            """,
            (engagement_id,),
        ).fetchone()[0]
    findings = [dict(row) for row in rows]
    return {
        "findings": findings,
        "findings_page": _page_metadata(
            offset=offset,
            limit=limit,
            returned=len(findings),
            total=finding_total,
        ),
        "staging_count": int(staging_count),
        "failed_count": int(failed_count),
    }


def read_version(
    engagement_id: int, slug: str, version_number: int
) -> tuple[bytes, str, str]:
    finding = state_manager.get_finding(engagement_id, slug)
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT * FROM assessment_submission_versions
            WHERE engagement_id = ? AND finding_id = ? AND version_number = ?
              AND status = 'complete'
            """,
            (engagement_id, int(finding["id"]), version_number),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="completed submission version not found")
    engagement = _engagement_or_404(engagement_id)
    root = Path(engagement.engagement_root).expanduser().resolve()
    _normalized, data = _read_stable_file(
        root,
        str(row["relative_path"]),
        max_bytes=PACKAGE_MAX_BYTES,
        label="submission version",
        package_path=True,
    )
    if len(data) != int(row["size_bytes"]) or _sha256(data) != str(row["sha256"]):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="submission version bytes no longer match immutable metadata",
        )
    filename = Path(str(row["relative_path"])).name
    return data, str(row["media_type"]), filename


def recover_exports(
    engagement_id: int,
    *,
    actor_surface: str,
    orphan_after: str = "",
    orphan_limit: int = DEFAULT_SUBMISSION_PAGE_LIMIT,
    failed_version_offset: int = 0,
    failed_version_limit: int = DEFAULT_SUBMISSION_PAGE_LIMIT,
) -> dict[str, Any]:
    if actor_surface not in ACTOR_SURFACES:
        raise HTTPException(status_code=400, detail=f"unsupported actor surface: {actor_surface}")
    _validate_offset_page(
        offset=failed_version_offset,
        limit=failed_version_limit,
        label="failed_version",
    )
    engagement = _engagement_or_404(engagement_id)
    activity_service.record_activity_entry(
        engagement_id,
        actor_kind="system",
        actor_name=actor_surface,
        title="Submission export recovery",
        action="recover_submission_exports",
        result="recovery requested",
        metadata={
            "actor_surface": actor_surface,
            "orphan_after": orphan_after,
            "orphan_limit": orphan_limit,
            "failed_version_offset": failed_version_offset,
            "failed_version_limit": failed_version_limit,
        },
    )
    root = Path(engagement.engagement_root).expanduser().resolve()
    with get_connection() as connection:
        known_staging = {
            str(row["staging_relative_path"])
            for row in connection.execute(
                """
                SELECT staging_relative_path FROM assessment_submission_versions
                WHERE engagement_id = ?
                """,
                (engagement_id,),
            ).fetchall()
        }
        rows = [
            dict(row)
            for row in connection.execute(
                """
                SELECT * FROM assessment_submission_versions
                WHERE engagement_id = ? AND status = 'staging'
                ORDER BY id
                """,
                (engagement_id,),
            ).fetchall()
        ]
    recovered: list[int] = []
    for row in rows:
        try:
            _atomic_publish(
                root,
                str(row["staging_relative_path"]),
                str(row["relative_path"]),
                str(row["sha256"]),
            )
            _complete_version(engagement_id, row)
        except (HTTPException, OSError) as exc:
            reason = str(exc.detail) if isinstance(exc, HTTPException) else str(exc)
            with get_connection() as connection:
                connection.execute(
                    """
                    UPDATE assessment_submission_versions
                    SET status = 'failed', failure_reason = ?
                    WHERE id = ? AND status = 'staging'
                    """,
                    (reason, int(row["id"])),
                )
        else:
            recovered.append(int(row["id"]))
    orphaned, orphaned_page = _orphaned_staging_page(
        root,
        known_staging,
        after=orphan_after,
        limit=orphan_limit,
    )
    with get_connection() as connection:
        failed_version_total = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM assessment_submission_versions
                WHERE engagement_id = ? AND status = 'failed'
                """,
                (engagement_id,),
            ).fetchone()[0]
        )
        failed_rows = connection.execute(
            """
            SELECT versions.*, findings.slug AS finding_slug
            FROM assessment_submission_versions AS versions
            JOIN assessment_findings AS findings ON findings.id = versions.finding_id
            WHERE versions.engagement_id = ? AND versions.status = 'failed'
            ORDER BY versions.id
            LIMIT ? OFFSET ?
            """,
            (engagement_id, failed_version_limit, failed_version_offset),
        ).fetchall()
    failed_versions = [
        _serialize_pending_version(dict(row)) for row in failed_rows
    ]
    return {
        "actor_surface": actor_surface,
        "recovered_version_ids": recovered,
        "failed_version_ids": [row["id"] for row in failed_versions],
        "failed_versions": failed_versions,
        "failed_versions_page": _page_metadata(
            offset=failed_version_offset,
            limit=failed_version_limit,
            returned=len(failed_versions),
            total=failed_version_total,
        ),
        "orphaned_staging_paths": orphaned,
        "orphaned_staging_page": orphaned_page,
    }
