from __future__ import annotations

import datetime as dt
import hashlib
import json
import mimetypes
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, status

from ..db import get_connection
from .events import _engagement_or_404
from .search import canonical_finding_alias, expanded_fts_query

DEFAULT_ROOTS = (
    "notes",
    "findings_payloads",
    "tools/exploit-state",
    "scans/reports",
    "downloads",
)
PREVIEW_BYTES = 4096
INDEXED_TEXT_BYTES = 16384
GET_CONTENT_BYTES = 65536


def _utcnow_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engagement_root(engagement_id: int) -> tuple[Any, Path]:
    engagement = _engagement_or_404(engagement_id)
    return engagement, Path(engagement.engagement_root).resolve()


def _normalize_relative_path(root: Path, path_value: str) -> str:
    value = str(path_value or "").strip()
    if not value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="artifact path is required")
    if "://" in value and urlparse(value).scheme != "file":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="artifact path must be engagement-local")
    raw_path = Path(value)
    candidate = raw_path.expanduser() if raw_path.is_absolute() else root / raw_path
    resolved = candidate.resolve(strict=False)
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="artifact path must be inside the engagement directory",
        ) from exc
    return relative.as_posix()


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


def _file_payload(root: Path, relative_path: str, media_type: str) -> dict[str, Any]:
    path = root / relative_path
    if not path.is_file():
        return {
            "present": False,
            "size_bytes": 0,
            "sha256": "",
            "preview_text": "",
            "indexed_text": "",
        }
    digest = hashlib.sha256()
    size = 0
    preview = bytearray()
    indexed = bytearray()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if len(preview) < PREVIEW_BYTES:
                preview.extend(chunk[: PREVIEW_BYTES - len(preview)])
            if len(indexed) < INDEXED_TEXT_BYTES:
                indexed.extend(chunk[: INDEXED_TEXT_BYTES - len(indexed)])
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


def _serialize_artifact(row) -> dict[str, Any]:
    data = dict(row)
    for key in ("sensitive", "present"):
        data[key] = bool(data.get(key))
    return data


def register_artifact(
    engagement_id: int,
    *,
    path: str,
    kind: str = "",
    media_type: str = "",
    sensitive: bool = False,
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
    kind_value = _guess_kind(relative_path, kind)
    media_type_value = _media_type(relative_path, media_type)
    file_data = _file_payload(root, relative_path, media_type_value)
    now = _utcnow_iso()
    canonical_finding = canonical_finding_alias(related_finding_slug) if related_finding_slug else None
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO assessment_artifacts (
                engagement_id, relative_path, kind, media_type, size_bytes, sha256,
                preview_text, indexed_text, sensitive, present, producer_agent_id,
                producer_agent_role, producer_command_run_id, related_finding_slug,
                related_chain_key, related_surface_id, related_request_variant_id,
                created_at, updated_at, last_indexed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, relative_path) DO UPDATE SET
                kind = COALESCE(NULLIF(excluded.kind, ''), assessment_artifacts.kind),
                media_type = COALESCE(NULLIF(excluded.media_type, ''), assessment_artifacts.media_type),
                size_bytes = excluded.size_bytes,
                sha256 = excluded.sha256,
                preview_text = excluded.preview_text,
                indexed_text = excluded.indexed_text,
                sensitive = excluded.sensitive OR assessment_artifacts.sensitive,
                present = excluded.present,
                producer_agent_id = COALESCE(excluded.producer_agent_id, assessment_artifacts.producer_agent_id),
                producer_agent_role = COALESCE(excluded.producer_agent_role, assessment_artifacts.producer_agent_role),
                producer_command_run_id = COALESCE(excluded.producer_command_run_id, assessment_artifacts.producer_command_run_id),
                related_finding_slug = COALESCE(excluded.related_finding_slug, assessment_artifacts.related_finding_slug),
                related_chain_key = COALESCE(excluded.related_chain_key, assessment_artifacts.related_chain_key),
                related_surface_id = COALESCE(excluded.related_surface_id, assessment_artifacts.related_surface_id),
                related_request_variant_id = COALESCE(excluded.related_request_variant_id, assessment_artifacts.related_request_variant_id),
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
                1 if sensitive else 0,
                1 if file_data["present"] else 0,
                producer_agent_id,
                producer_agent_role,
                producer_command_run_id,
                canonical_finding,
                related_chain_key,
                related_surface_id,
                related_request_variant_id,
                now,
                now,
                now,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_artifacts WHERE engagement_id = ? AND relative_path = ?",
            (engagement_id, relative_path),
        ).fetchone()
    assert row is not None
    return _serialize_artifact(row)


def _iter_default_files(root: Path) -> set[str]:
    paths: set[str] = set()
    for root_name in DEFAULT_ROOTS:
        base = root / root_name
        if not base.exists():
            continue
        if base.is_file():
            paths.add(base.relative_to(root).as_posix())
            continue
        for path in base.rglob("*"):
            if path.is_file():
                paths.add(path.relative_to(root).as_posix())
    return paths


def _path_ref(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped or "://" in stripped:
        return None
    return stripped


def _referenced_artifacts(engagement_id: int, root: Path) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    with get_connection() as connection:
        for row in connection.execute(
            """
            SELECT slug, evidence_ref, details_json, provenance_json
            FROM assessment_findings
            WHERE engagement_id = ?
            """,
            (engagement_id,),
        ).fetchall():
            for value in (row["evidence_ref"],):
                if path_ref := _path_ref(value):
                    refs.append({"path": path_ref, "related_finding_slug": row["slug"], "kind": "evidence"})
        for row in connection.execute(
            """
            SELECT finding_id, artifact_ref
            FROM assessment_finding_transitions
            WHERE engagement_id = ? AND artifact_ref != ''
            """,
            (engagement_id,),
        ).fetchall():
            if path_ref := _path_ref(row["artifact_ref"]):
                finding = connection.execute(
                    "SELECT slug FROM assessment_findings WHERE id = ?",
                    (row["finding_id"],),
                ).fetchone()
                refs.append({
                    "path": path_ref,
                    "related_finding_slug": finding["slug"] if finding else None,
                    "kind": "evidence",
                })
        for row in connection.execute(
            """
            SELECT id, agent_name, stdout_artifact_ref, stderr_artifact_ref, stdout_path, stderr_path
            FROM assessment_command_runs
            WHERE engagement_id = ?
            """,
            (engagement_id,),
        ).fetchall():
            for value in (row["stdout_artifact_ref"], row["stderr_artifact_ref"], row["stdout_path"], row["stderr_path"]):
                if path_ref := _path_ref(value):
                    try:
                        _normalize_relative_path(root, path_ref)
                    except HTTPException:
                        continue
                    refs.append({
                        "path": path_ref,
                        "kind": "command-run-output",
                        "producer_agent_role": row["agent_name"],
                        "producer_command_run_id": int(row["id"]),
                    })
        for row in connection.execute(
            """
            SELECT agent_id, agent_role, finding_slugs_json, working_artifacts_json
            FROM assessment_dispatch_handoffs
            WHERE engagement_id = ?
            """,
            (engagement_id,),
        ).fetchall():
            finding_slug = None
            try:
                slugs = json.loads(row["finding_slugs_json"] or "[]")
                if isinstance(slugs, list) and slugs:
                    finding_slug = str(slugs[0])
            except json.JSONDecodeError:
                finding_slug = None
            try:
                artifacts = json.loads(row["working_artifacts_json"] or "[]")
            except json.JSONDecodeError:
                artifacts = []
            if isinstance(artifacts, list):
                for item in artifacts:
                    if isinstance(item, dict) and (path_ref := _path_ref(item.get("path"))):
                        refs.append({
                            "path": path_ref,
                            "kind": str(item.get("kind") or "handoff-artifact"),
                            "producer_agent_id": row["agent_id"],
                            "producer_agent_role": row["agent_role"],
                            "related_finding_slug": finding_slug,
                        })
        for row in connection.execute(
            """
            SELECT chain_key, evidence_ref
            FROM assessment_attack_chains
            WHERE engagement_id = ? AND evidence_ref != ''
            """,
            (engagement_id,),
        ).fetchall():
            if path_ref := _path_ref(row["evidence_ref"]):
                refs.append({"path": path_ref, "related_chain_key": row["chain_key"], "kind": "chain-evidence"})
    return refs


def sync_artifacts(engagement_id: int) -> dict[str, Any]:
    _engagement, root = _engagement_root(engagement_id)
    with get_connection() as connection:
        existing_paths = {
            str(row["relative_path"])
            for row in connection.execute(
                "SELECT relative_path FROM assessment_artifacts WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
        }
        connection.execute(
            "UPDATE assessment_artifacts SET present = 0, updated_at = ? WHERE engagement_id = ?",
            (_utcnow_iso(), engagement_id),
        )
    discovered = _iter_default_files(root) | existing_paths
    registered = 0
    for relative_path in sorted(discovered):
        register_artifact(engagement_id, path=relative_path)
        registered += 1
    for ref in _referenced_artifacts(engagement_id, root):
        register_artifact(engagement_id, **ref)
        registered += 1
    with get_connection() as connection:
        present = connection.execute(
            "SELECT COUNT(*) FROM assessment_artifacts WHERE engagement_id = ? AND present = 1",
            (engagement_id,),
        ).fetchone()[0]
        missing = connection.execute(
            "SELECT COUNT(*) FROM assessment_artifacts WHERE engagement_id = ? AND present = 0",
            (engagement_id,),
        ).fetchone()[0]
    return {"registered": registered, "present": int(present), "missing": int(missing)}


def search_artifacts(
    engagement_id: int,
    *,
    query: str = "",
    finding: str = "",
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
        join_sql = "JOIN assessment_artifacts_fts ON assessment_artifacts_fts.rowid = a.id"
        where.append("assessment_artifacts_fts MATCH ?")
        params.append(fts_expr)
    if canonical_finding:
        where.append("(a.related_finding_slug = ? OR a.indexed_text LIKE ? OR a.relative_path LIKE ?)")
        params.extend([canonical_finding, f"%{canonical_finding}%", f"%{canonical_finding}%"])
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
    return [_serialize_artifact(row) for row in rows]


def get_artifact(engagement_id: int, artifact_id: int) -> dict[str, Any]:
    _engagement, root = _engagement_root(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_artifacts WHERE engagement_id = ? AND id = ?",
            (engagement_id, int(artifact_id)),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="artifact not found")
    data = _serialize_artifact(row)
    data["content"] = ""
    data["content_truncated"] = False
    path = root / str(row["relative_path"])
    if bool(row["present"]) and path.is_file() and int(row["size_bytes"] or 0) <= GET_CONTENT_BYTES:
        data["content"] = path.read_text(encoding="utf-8", errors="replace")
    elif bool(row["present"]) and path.is_file():
        data["content_truncated"] = True
    return data


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
