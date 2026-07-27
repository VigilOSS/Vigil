from __future__ import annotations

import datetime as dt
import hashlib
import mimetypes
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, status

from ..db import get_connection
from .events import _engagement_or_404
from .search import canonical_finding_alias, expanded_fts_query

PREVIEW_BYTES = 4096
INDEXED_TEXT_BYTES = 16384
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


def _file_payload(root: Path, relative_path: str, media_type: str) -> dict[str, Any]:
    """Index one registered path. ``present`` is EXISTENCE, not file-ness.

    ``vigil assess artifact register <dir>`` accepts a directory, and specialists
    legitimately point ``evidence_ref`` at a directory holding a whole capture
    set. An ``is_file()`` predicate here reported every one of those as
    ``present=False``, which report-readiness surfaces as "the file is missing on
    disk" against directories that were sitting there full of live evidence. A
    directory has no single body to hash or preview, so those fields stay empty —
    but it is unambiguously present.
    """
    path = root / relative_path
    if not path.exists():
        return {
            "present": False,
            "size_bytes": 0,
            "sha256": "",
            "preview_text": "",
            "indexed_text": "",
        }
    if not path.is_file():
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


def _serialize_artifact(row, *, compact: bool = False) -> dict[str, Any]:
    data = dict(row)
    for key in ("sensitive", "present", "scratch"):
        data[key] = bool(data.get(key))
    if compact:
        data.pop("indexed_text", None)
    return data


def _file_payload_if_changed(
    engagement_id: int,
    root: Path,
    relative_path: str,
    media_type: str,
) -> dict[str, Any]:
    """Skip the hash + preview read when the on-disk file is unchanged.

    Compares the on-disk (size, mtime) against the stored row's
    (size_bytes, last_indexed_at). When both match and the row already has a
    sha256, return the cached payload — saves a full re-read on
    re-registration of files that haven't changed since the last index.
    """
    path = root / relative_path
    if not path.is_file():
        # Directories (a registered evidence directory) and absent paths both
        # fall through to the full builder — the (size, mtime) fast path below
        # only models a regular file's body. `_file_payload` is the single
        # existence predicate for both, so a directory is reported present.
        return _file_payload(root, relative_path, media_type)
    try:
        stat = path.stat()
    except OSError:
        return _file_payload(root, relative_path, media_type)
    with get_connection() as connection:
        existing = connection.execute(
            "SELECT size_bytes, sha256, preview_text, indexed_text, last_indexed_at "
            "FROM assessment_artifacts WHERE engagement_id = ? AND relative_path = ?",
            (engagement_id, relative_path),
        ).fetchone()
    if existing is None:
        return _file_payload(root, relative_path, media_type)
    stored_size = int(existing["size_bytes"] or 0)
    stored_sha = str(existing["sha256"] or "")
    stored_indexed_at = _parse_indexed_at(existing["last_indexed_at"])
    if stored_size != stat.st_size or not stored_sha or stored_indexed_at is None:
        return _file_payload(root, relative_path, media_type)
    if stat.st_mtime > stored_indexed_at:
        return _file_payload(root, relative_path, media_type)
    return {
        "present": True,
        "size_bytes": stored_size,
        "sha256": stored_sha,
        "preview_text": str(existing["preview_text"] or ""),
        "indexed_text": str(existing["indexed_text"] or ""),
    }


def _parse_indexed_at(value: Any) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _normalize_related_finding_slug(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    return canonical_finding_alias(raw) or raw


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
    file_data = _file_payload_if_changed(engagement_id, root, relative_path, media_type_value)
    now = _utcnow_iso()
    linked_finding = _normalize_related_finding_slug(related_finding_slug)
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
                -- Bind the RAW caller-supplied kind/media_type here, not
                -- excluded.* — excluded.kind carries the _guess_kind() result,
                -- which is never empty, so NULLIF(excluded.kind, '') would
                -- never preserve the stored kind and a bare re-register would
                -- clobber an explicit kind (e.g. verification-narrative).
                kind = COALESCE(NULLIF(?, ''), assessment_artifacts.kind),
                media_type = COALESCE(NULLIF(?, ''), assessment_artifacts.media_type),
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
    return _serialize_artifact(row)


def refresh_artifacts(engagement_id: int) -> dict[str, Any]:
    """Refresh on-disk presence/hash metadata for existing artifact rows only.

    This intentionally does not walk directories or discover new files. It keeps
    explicit registration as the only way a path enters the index while letting
    report-readiness see deleted or restored files without per-path re-registers.
    """
    _engagement, root = _engagement_root(engagement_id)
    now = _utcnow_iso()
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT id, relative_path, media_type FROM assessment_artifacts WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchall()
        present = 0
        missing = 0
        for row in rows:
            relative_path = str(row["relative_path"])
            media_type_value = _media_type(relative_path, str(row["media_type"] or ""))
            file_data = _file_payload(root, relative_path, media_type_value)
            if bool(file_data["present"]):
                present += 1
            else:
                missing += 1
            connection.execute(
                """
                UPDATE assessment_artifacts
                SET media_type = ?, size_bytes = ?, sha256 = ?, preview_text = ?,
                    indexed_text = ?, present = ?, updated_at = ?, last_indexed_at = ?
                WHERE id = ?
                """,
                (
                    media_type_value,
                    int(file_data["size_bytes"]),
                    str(file_data["sha256"]),
                    str(file_data["preview_text"]),
                    str(file_data["indexed_text"]),
                    1 if file_data["present"] else 0,
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
        join_sql = "JOIN assessment_artifacts_fts ON assessment_artifacts_fts.rowid = a.id"
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
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="artifact not found")
        elif path:
            relative_path = _normalize_relative_path(root, path)
            row = connection.execute(
                "SELECT * FROM assessment_artifacts WHERE engagement_id = ? AND relative_path = ?",
                (engagement_id, relative_path),
            ).fetchone()
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="path or artifact_id is required")
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
