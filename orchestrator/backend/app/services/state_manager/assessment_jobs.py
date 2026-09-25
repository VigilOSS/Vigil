"""Assessment job lifecycle records linked to command-run audits."""

from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException, status

from ..events import _engagement_or_404
from . import _common


_JOB_VALID_STATUSES = _common.JOB_STATUSES
_JOB_TERMINAL_STATUSES = _common.JOB_TERMINAL_STATUSES
_JOB_PRE_TERMINAL_STATUSES = _common.JOB_PRE_TERMINAL_STATUSES


def _serialize_job(row) -> dict[str, Any]:
    data = dict(row)
    raw_meta = data.pop("audit_metadata_json", None) or ""
    if raw_meta:
        try:
            data["audit_metadata"] = json.loads(raw_meta)
        except json.JSONDecodeError:
            data["audit_metadata"] = None
    else:
        data["audit_metadata"] = None
    return data


def record_job(
    engagement_id: int,
    *,
    parent_command_run_id: int | None = None,
    status_value: str = "queued",
    started_at: str | None = None,
    ended_at: str | None = None,
    exit_code: int | None = None,
    dtach_socket_path: str | None = None,
    stdout_path: str | None = None,
    stderr_path: str | None = None,
    audit_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if status_value not in _JOB_VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"job status must be one of {sorted(str(s) for s in _JOB_VALID_STATUSES)}",
        )
    metadata_json = (
        json.dumps(audit_metadata, ensure_ascii=False)
        if audit_metadata is not None
        else None
    )
    with _common.get_connection() as connection:
        if parent_command_run_id is not None:
            row = connection.execute(
                "SELECT id FROM assessment_command_runs WHERE engagement_id = ? AND id = ?",
                (engagement.id, int(parent_command_run_id)),
            ).fetchone()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="parent_command_run_id does not reference an existing command run for this engagement",
                )
        cursor = connection.execute(
            """
            INSERT INTO assessment_jobs (
                engagement_id, parent_command_run_id, status,
                started_at, ended_at, exit_code,
                dtach_socket_path, stdout_path, stderr_path,
                audit_metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                parent_command_run_id,
                status_value,
                started_at,
                ended_at,
                exit_code,
                dtach_socket_path,
                stdout_path,
                stderr_path,
                metadata_json,
            ),
        )
        out_row = connection.execute(
            "SELECT * FROM assessment_jobs WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        assert out_row is not None
        return _serialize_job(out_row)


def update_job(
    engagement_id: int,
    *,
    job_id: int,
    status_value: str | None = None,
    started_at: str | None = None,
    ended_at: str | None = None,
    exit_code: int | None = None,
    dtach_socket_path: str | None = None,
    stdout_path: str | None = None,
    stderr_path: str | None = None,
    audit_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    sets: list[str] = []
    values: list[Any] = []
    if status_value is not None:
        if status_value not in _JOB_VALID_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"job status must be one of {sorted(str(s) for s in _JOB_VALID_STATUSES)}",
            )
        sets.append("status = ?")
        values.append(status_value)
    for column, value in (
        ("started_at", started_at),
        ("ended_at", ended_at),
        ("dtach_socket_path", dtach_socket_path),
        ("stdout_path", stdout_path),
        ("stderr_path", stderr_path),
    ):
        if value is not None:
            sets.append(f"{column} = ?")
            values.append(value)
    if exit_code is not None:
        sets.append("exit_code = ?")
        values.append(int(exit_code))
    if audit_metadata is not None:
        sets.append("audit_metadata_json = ?")
        values.append(json.dumps(audit_metadata, ensure_ascii=False))
    if not sets:
        return get_job(engagement.id, job_id)
    sets.append("updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')")
    with _common.get_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM assessment_jobs WHERE engagement_id = ? AND id = ?",
            (engagement.id, int(job_id)),
        ).fetchone()
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="job not found"
            )
        existing_status = str(existing["status"] or "")
        if (
            status_value is not None
            and existing_status in _JOB_TERMINAL_STATUSES
            and status_value != existing_status
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": "job already terminal",
                    "existing": _serialize_job(existing),
                },
            )
        where = "WHERE engagement_id = ? AND id = ?"
        where_values: list[Any] = [engagement.id, int(job_id)]
        if status_value is not None and existing_status in _JOB_PRE_TERMINAL_STATUSES:
            statuses = tuple(sorted(str(s) for s in _JOB_PRE_TERMINAL_STATUSES))
            where += f" AND status IN ({', '.join('?' for _ in statuses)})"
            where_values.extend(statuses)
        cursor = connection.execute(
            f"UPDATE assessment_jobs SET {', '.join(sets)} {where}",
            tuple(values + where_values),
        )
        if cursor.rowcount == 0:
            current = connection.execute(
                "SELECT * FROM assessment_jobs WHERE engagement_id = ? AND id = ?",
                (engagement.id, int(job_id)),
            ).fetchone()
            if current is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="job not found"
                )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": "job already terminal",
                    "existing": _serialize_job(current),
                },
            )
        row = connection.execute(
            "SELECT * FROM assessment_jobs WHERE id = ?", (int(job_id),)
        ).fetchone()
        assert row is not None
        return _serialize_job(row)


def list_jobs(
    engagement_id: int,
    *,
    status_value: str = "",
    parent_command_run_id: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    where = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if status_value:
        where.append("status = ?")
        params.append(status_value)
    if parent_command_run_id is not None:
        where.append("parent_command_run_id = ?")
        params.append(int(parent_command_run_id))
    params.extend([int(limit), int(offset)])
    with _common.get_connection() as connection:
        rows = connection.execute(
            f"SELECT * FROM assessment_jobs WHERE {' AND '.join(where)} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            tuple(params),
        ).fetchall()
    return [_serialize_job(row) for row in rows]


def get_job(engagement_id: int, job_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_jobs WHERE engagement_id = ? AND id = ?",
            (engagement.id, int(job_id)),
        ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="job not found"
        )
    return _serialize_job(row)
