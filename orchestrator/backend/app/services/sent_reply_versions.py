"""Atomic sent-reply transitions backed by immutable exact outbound bytes."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import HTTPException, status

from ..db import get_connection
from ..reply_render import (
    REPLY_RENDERER_IDENTITY,
    REPLY_RENDERER_VERSION,
    render_outbound_reply_bytes,
)
from .events import _engagement_or_404
from .state_manager import findings as finding_service
from .state_manager._common import canonical_finding_alias
from .state_manager.finding_details import validate_stored_reply_sequence_identity


MAX_SENT_REPLY_BYTES = 4 * 1024 * 1024


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    try:
        decoded = json.loads(str(value or "{}"))
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _finding_row(connection, engagement_id: int, slug: str):
    lookup = canonical_finding_alias(slug) or slug
    row = connection.execute(
        "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
        (engagement_id, lookup),
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"finding not found: {slug}",
        )
    return row


def _reply_entry(finding: Mapping[str, Any], reply_sequence: int) -> dict[str, Any]:
    details = _json_object(finding["details_json"])
    slug = str(finding["slug"])
    validate_stored_reply_sequence_identity(details, finding_slug=slug)
    replies = details.get("replies")
    rows = replies if isinstance(replies, list) else []
    entry = next(
        (
            row
            for row in rows
            if isinstance(row, dict) and row.get("seq") == reply_sequence
        ),
        None,
    )
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"reply sequence {reply_sequence} not found on finding {slug}",
        )
    return entry


def _record_metadata(row: Mapping[str, Any], *, idempotent_replay: bool = False) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "reply_sequence": int(row["reply_sequence"]),
        "availability": "captured",
        "size_bytes": int(row["size_bytes"]),
        "sha256": str(row["sha256"]),
        "renderer_identity": str(row["renderer_identity"]),
        "renderer_version": str(row["renderer_version"]),
        "created_at": str(row["created_at"]),
        "idempotent_replay": idempotent_replay,
    }


def _verified_record_bytes(
    finding: Mapping[str, Any], entry: Mapping[str, Any], row: Mapping[str, Any]
) -> bytes:
    if entry.get("sent_status") != "sent":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="sent-reply integrity failure: exact bytes exist for a draft reply",
        )
    data = bytes(row["body_bytes"])
    expected_size = int(row["size_bytes"])
    expected_sha256 = str(row["sha256"])
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"sent-reply integrity failure for {finding['slug']} reply "
                f"{row['reply_sequence']}: stored bytes do not match size/digest metadata"
            ),
        )
    return data


def _validate_rendered_bytes(body_bytes: bytes) -> None:
    if len(body_bytes) > MAX_SENT_REPLY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"sent reply body exceeds the {MAX_SENT_REPLY_BYTES}-byte limit",
        )


def send_reply(
    engagement_id: int,
    slug: str,
    reply_sequence: int,
    *,
    expected_row_version: int,
    actor: str,
    reason: str,
) -> dict[str, Any]:
    """Derive exact bytes from one transaction-selected draft and mark it sent."""

    engagement = _engagement_or_404(engagement_id)
    idempotent = False
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        finding = _finding_row(connection, engagement.id, slug)
        entry = _reply_entry(finding, reply_sequence)
        existing = connection.execute(
            """
            SELECT * FROM assessment_sent_reply_versions
            WHERE engagement_id = ? AND finding_id = ? AND reply_sequence = ?
            """,
            (engagement.id, int(finding["id"]), reply_sequence),
        ).fetchone()
        if entry.get("sent_status") == "sent":
            if existing is None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "legacy sent reply bytes are unavailable and must not be "
                        "reconstructed from mutable finding content"
                    ),
                )
            _verified_record_bytes(finding, entry, existing)
            record = existing
            idempotent = True
        else:
            if int(finding["row_version"]) != expected_row_version:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "finding changed before sent-reply byte capture; refetch, "
                        "rerender, and review the current draft"
                    ),
                )
            try:
                body_bytes = render_outbound_reply_bytes(entry)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            _validate_rendered_bytes(body_bytes)
            size_bytes = len(body_bytes)
            sha256 = hashlib.sha256(body_bytes).hexdigest()
            sent_at = _utcnow_iso()
            updated_entry = {**entry, "sent_status": "sent", "sent_at": sent_at}
            details = _json_object(finding["details_json"])
            replies = list(details.get("replies") or [])
            replies = [
                updated_entry
                if isinstance(row, dict) and row.get("seq") == reply_sequence
                else row
                for row in replies
            ]
            details["replies"] = replies
            cursor = connection.execute(
                """
                INSERT INTO assessment_sent_reply_versions (
                    engagement_id, finding_id, reply_sequence, body_bytes,
                    size_bytes, sha256, renderer_identity, renderer_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    int(finding["id"]),
                    reply_sequence,
                    body_bytes,
                    size_bytes,
                    sha256,
                    REPLY_RENDERER_IDENTITY,
                    REPLY_RENDERER_VERSION,
                ),
            )
            updated = connection.execute(
                """
                UPDATE assessment_findings
                SET details_json = ?, row_version = row_version + 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND engagement_id = ? AND row_version = ?
                """,
                (
                    _json_text(details),
                    int(finding["id"]),
                    engagement.id,
                    expected_row_version,
                ),
            )
            if updated.rowcount != 1:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="finding changed during sent-reply byte capture",
                )
            current = connection.execute(
                "SELECT * FROM assessment_findings WHERE id = ?", (int(finding["id"]),)
            ).fetchone()
            assert current is not None
            finding_service._record_finding_transition(
                connection,
                engagement_id=engagement.id,
                finding_id=int(finding["id"]),
                actor=actor,
                action="reply_sent",
                before=finding_service._finding_state_snapshot(finding),
                after=finding_service._finding_state_snapshot(current),
                reason_code="reply_sent",
                reason_text=reason,
                artifact_ref="",
                metadata={
                    "reply_sequence": reply_sequence,
                    "size_bytes": size_bytes,
                    "sha256": sha256,
                    "renderer_identity": REPLY_RENDERER_IDENTITY,
                    "renderer_version": REPLY_RENDERER_VERSION,
                },
                before_content=finding_service._finding_content_snapshot(finding),
                after_content=finding_service._finding_content_snapshot(current),
            )
            record = connection.execute(
                "SELECT * FROM assessment_sent_reply_versions WHERE id = ?",
                (int(cursor.lastrowid),),
            ).fetchone()
            assert record is not None

    return {
        "finding": finding_service.get_finding(engagement.id, str(finding["slug"])),
        "sent_reply": _record_metadata(record, idempotent_replay=idempotent),
    }


def read_sent_reply(
    engagement_id: int, slug: str, reply_sequence: int
) -> tuple[dict[str, Any], bytes | None]:
    """Read one sent reply, verifying captured bytes or reporting legacy absence."""

    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        finding = _finding_row(connection, engagement.id, slug)
        entry = _reply_entry(finding, reply_sequence)
        if entry.get("sent_status") != "sent":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"reply sequence {reply_sequence} is still a draft",
            )
        row = connection.execute(
            """
            SELECT * FROM assessment_sent_reply_versions
            WHERE engagement_id = ? AND finding_id = ? AND reply_sequence = ?
            """,
            (engagement.id, int(finding["id"]), reply_sequence),
        ).fetchone()
        if row is None:
            return {
                "reply_sequence": reply_sequence,
                "availability": "legacy_unavailable",
            }, None
        data = _verified_record_bytes(finding, entry, row)
        return _record_metadata(row), data
