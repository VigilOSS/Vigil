from __future__ import annotations

from typing import Any
from fastapi import HTTPException, status

from ..events import _engagement_or_404

from . import _common
from ._common import ROOT_CAUSE_EFFECTS, ROOT_CAUSE_LINK_KIND, SEVERITY_RANK, _is_suppressed_workflow_status, _json_object, _json_text, _merge_object_text, _resolve_existing_finding_slug, _row_workflow_status, _serialize_finding_record



def _root_cause_link_metadata(link: dict[str, Any]) -> dict[str, Any]:
    provenance = _json_object(link.get("provenance_json", "{}"))
    effect = str(provenance.get("root_cause_effect") or "eliminates_finding").strip()
    if effect not in ROOT_CAUSE_EFFECTS:
        effect = "eliminates_finding"
    order_value = provenance.get("sibling_order")
    try:
        sibling_order = int(order_value) if order_value not in (None, "") else None
    except (TypeError, ValueError):
        sibling_order = None
    return {
        "root_cause_slug": str(link.get("target_ref", "") or ""),
        "root_cause_note": str(link.get("notes", "") or ""),
        "root_cause_effect": effect,
        "sibling_order": sibling_order,
        "root_cause_link_id": link.get("id"),
    }

def _is_root_cause_link(link: dict[str, Any] | Any) -> bool:
    return str(link["link_kind"]) == ROOT_CAUSE_LINK_KIND and str(link["target_kind"]) == "finding"

def _upsert_finding_link(
    connection,
    engagement_id: int,
    *,
    finding_id: int,
    link_kind: str,
    target_kind: str,
    target_id: int | None,
    target_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    if str(target_kind) == "finding" and target_ref:
        target_ref = _resolve_existing_finding_slug(
            connection,
            engagement_id,
            target_ref,
            field="target_ref",
        )
    row = connection.execute(
        """
        SELECT *
        FROM assessment_finding_links
        WHERE engagement_id = ? AND finding_id = ? AND link_kind = ?
          AND target_kind = ? AND target_id IS ? AND target_ref = ?
          AND retired_at IS NULL
        """,
        (engagement_id, finding_id, link_kind, target_kind, target_id, target_ref),
    ).fetchone()
    if row is None:
        cursor = connection.execute(
            """
            INSERT INTO assessment_finding_links (
                engagement_id, finding_id, link_kind, target_kind, target_id, target_ref, notes, provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement_id, finding_id, link_kind, target_kind, target_id, target_ref, notes, _json_text(provenance)),
        )
        row = connection.execute("SELECT * FROM assessment_finding_links WHERE id = ?", (cursor.lastrowid,)).fetchone()
    else:
        connection.execute(
            """
            UPDATE assessment_finding_links
            SET notes = ?, provenance_json = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (_common._append_notes(row["notes"], notes), _merge_object_text(row["provenance_json"], provenance), row["id"]),
        )
        row = connection.execute("SELECT * FROM assessment_finding_links WHERE id = ?", (row["id"],)).fetchone()
    assert row is not None
    return dict(row)

def create_finding_link(
    engagement_id: int,
    *,
    finding_slug: str,
    link_kind: str,
    target_kind: str,
    target_id: int | None,
    target_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        finding_slug = _resolve_existing_finding_slug(connection, engagement.id, finding_slug)
        if str(target_kind) == "finding" and target_ref:
            target_ref = _resolve_existing_finding_slug(
                connection,
                engagement.id,
                target_ref,
                field="target_ref",
            )
        finding = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, finding_slug),
        ).fetchone()
        if str(target_kind) == "finding":
            if target_ref == finding_slug or (
                target_id is not None and int(target_id) == int(finding["id"])
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="finding cannot link to itself",
                )
        return _upsert_finding_link(
            connection,
            engagement.id,
            finding_id=int(finding["id"]),
            link_kind=link_kind,
            target_kind=target_kind,
            target_id=target_id,
            target_ref=target_ref,
            notes=notes,
            provenance=provenance,
        )

def set_root_cause_link(
    engagement_id: int,
    *,
    finding_slug: str,
    root_cause_slug: str,
    sibling_order: int | None,
    root_cause_effect: str,
    note: str,
    source_name: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    effect = (root_cause_effect or "eliminates_finding").strip()
    if effect not in ROOT_CAUSE_EFFECTS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid root_cause_effect: {root_cause_effect}")
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        finding_slug = _resolve_existing_finding_slug(connection, engagement.id, finding_slug)
        root_cause_slug = _resolve_existing_finding_slug(
            connection,
            engagement.id,
            root_cause_slug,
            field="root_cause_slug",
        )
        finding = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, finding_slug),
        ).fetchone()
        root = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, root_cause_slug),
        ).fetchone()
        if int(finding["id"]) == int(root["id"]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="finding cannot be its own root cause")
        if _is_suppressed_workflow_status(_row_workflow_status(finding)):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="merged or false-positive findings cannot be linked as siblings")
        if _is_suppressed_workflow_status(_row_workflow_status(root)):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="merged or false-positive findings cannot be root causes")
        root_parent = connection.execute(
            """
            SELECT 1
            FROM assessment_finding_links
            WHERE engagement_id = ?
              AND finding_id = ?
              AND link_kind = ?
              AND target_kind = 'finding'
              AND retired_at IS NULL
            LIMIT 1
            """,
            (engagement.id, int(root["id"]), ROOT_CAUSE_LINK_KIND),
        ).fetchone()
        if root_parent is not None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="nested root-cause groups are not supported")
        finding_is_root = connection.execute(
            """
            SELECT 1
            FROM assessment_finding_links
            WHERE engagement_id = ?
              AND target_ref = ?
              AND link_kind = ?
              AND target_kind = 'finding'
              AND finding_id != ?
              AND retired_at IS NULL
            LIMIT 1
            """,
            (engagement.id, finding_slug, ROOT_CAUSE_LINK_KIND, int(finding["id"])),
        ).fetchone()
        if finding_is_root is not None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="nested root-cause groups are not supported")

        existing_link = connection.execute(
            """
            SELECT *
            FROM assessment_finding_links
            WHERE engagement_id = ?
              AND finding_id = ?
              AND link_kind = ?
              AND target_kind = 'finding'
              AND retired_at IS NULL
            LIMIT 1
            """,
            (engagement.id, int(finding["id"]), ROOT_CAUSE_LINK_KIND),
        ).fetchone()

        if (
            sibling_order is None
            and existing_link is not None
            and str(existing_link["target_ref"]) == root_cause_slug
        ):
            existing_metadata = _json_object(existing_link["provenance_json"])
            existing_order = existing_metadata.get("sibling_order")
            try:
                sibling_order = int(existing_order)
            except (TypeError, ValueError):
                sibling_order = None
        if sibling_order is None:
            row = connection.execute(
                """
                SELECT MAX(
                    CAST(json_extract(provenance_json, '$.sibling_order') AS INTEGER)
                ) AS highest
                FROM assessment_finding_links
                WHERE engagement_id = ?
                  AND link_kind = ?
                  AND target_kind = 'finding'
                  AND target_ref = ?
                  AND finding_id != ?
                  AND retired_at IS NULL
                """,
                (engagement.id, ROOT_CAUSE_LINK_KIND, root_cause_slug, int(finding["id"])),
            ).fetchone()
            sibling_order = int(row["highest"] or 0) + 1 if row is not None else 1
        if sibling_order < 1:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="sibling_order must be >= 1")

        metadata = (
            _json_object(existing_link["provenance_json"])
            if existing_link is not None
            else {}
        )
        metadata.update(provenance or {})
        metadata["sibling_order"] = sibling_order
        metadata["root_cause_effect"] = effect
        if source_name:
            metadata.setdefault("source_name", source_name)

        if existing_link is None:
            link = _upsert_finding_link(
                connection,
                engagement.id,
                finding_id=int(finding["id"]),
                link_kind=ROOT_CAUSE_LINK_KIND,
                target_kind="finding",
                target_id=int(root["id"]),
                target_ref=root_cause_slug,
                notes=note,
                provenance=metadata,
            )
        else:
            connection.execute(
                """
                UPDATE assessment_finding_links
                SET target_id = ?,
                    target_ref = ?,
                    notes = ?,
                    provenance_json = ?,
                    retired_at = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    int(root["id"]),
                    root_cause_slug,
                    _common._append_notes(existing_link["notes"], note),
                    _json_text(metadata),
                    int(existing_link["id"]),
                ),
            )
            updated_link = connection.execute(
                "SELECT * FROM assessment_finding_links WHERE id = ?",
                (int(existing_link["id"]),),
            ).fetchone()
            assert updated_link is not None
            link = dict(updated_link)
    result = dict(link)
    result["finding_slug"] = finding_slug
    result.update(_root_cause_link_metadata(result))
    return result

def clear_root_cause_link(engagement_id: int, *, finding_slug: str) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        finding_slug = _resolve_existing_finding_slug(connection, engagement.id, finding_slug)
        finding = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, finding_slug),
        ).fetchone()
        cursor = connection.execute(
            """
            UPDATE assessment_finding_links
            SET retired_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ?
              AND finding_id = ?
              AND link_kind = ?
              AND target_kind = 'finding'
              AND retired_at IS NULL
            """,
            (engagement.id, int(finding["id"]), ROOT_CAUSE_LINK_KIND),
        )
    return {"finding_slug": finding_slug, "cleared": int(cursor.rowcount)}

def list_finding_links(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT links.*, findings.slug AS finding_slug
            FROM assessment_finding_links AS links
            JOIN assessment_findings AS findings ON findings.id = links.finding_id
            WHERE links.engagement_id = ?
            ORDER BY links.updated_at DESC, links.id DESC
            """,
            (engagement.id,),
        ).fetchall()
    return [dict(row) for row in rows]


def update_finding_link(
    engagement_id: int,
    *,
    finding_slug: str,
    link_id: int,
    target_kind: str | None,
    target_id: int | None,
    target_ref: str | None,
    notes: str | None,
    provenance: dict[str, Any] | None,
    retired: bool | None,
) -> dict[str, Any]:
    """Correct or retire a generic link in place, preserving its durable id."""
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        finding_slug = _resolve_existing_finding_slug(
            connection, engagement.id, finding_slug
        )
        finding = connection.execute(
            "SELECT * FROM assessment_findings "
            "WHERE engagement_id = ? AND slug = ?",
            (engagement.id, finding_slug),
        ).fetchone()
        link = connection.execute(
            "SELECT * FROM assessment_finding_links "
            "WHERE engagement_id = ? AND finding_id = ? AND id = ?",
            (engagement.id, int(finding["id"]), int(link_id)),
        ).fetchone()
        if link is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="finding link not found",
            )
        if _is_root_cause_link(link):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="use the root-cause lifecycle for root-cause links",
            )
        if target_kind is not None and target_id is None and target_ref is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="changing target_kind requires target_id or target_ref",
            )

        next_kind = str(target_kind) if target_kind is not None else str(link["target_kind"])
        if target_ref is not None:
            next_id = None
            next_ref = str(target_ref)
        elif target_id is not None:
            next_id = target_id
            next_ref = ""
        else:
            next_id = link["target_id"]
            next_ref = str(link["target_ref"])
        if next_kind == "finding":
            if next_ref:
                next_ref = _resolve_existing_finding_slug(
                    connection,
                    engagement.id,
                    next_ref,
                    field="target_ref",
                )
                target = connection.execute(
                    "SELECT id FROM assessment_findings "
                    "WHERE engagement_id = ? AND slug = ?",
                    (engagement.id, next_ref),
                ).fetchone()
            else:
                target = connection.execute(
                    "SELECT id, slug FROM assessment_findings "
                    "WHERE engagement_id = ? AND id = ?",
                    (engagement.id, next_id),
                ).fetchone()
                if target is None:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="target_id finding not found",
                    )
                next_ref = str(target["slug"])
            assert target is not None
            next_id = int(target["id"])
        if next_kind == "finding" and (
            next_ref == finding_slug
            or (next_id is not None and int(next_id) == int(finding["id"]))
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="finding cannot link to itself",
            )
        if next_id is None and not next_ref:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="finding link requires target_id or target_ref",
            )

        next_notes = str(link["notes"]) if notes is None else str(notes)
        next_provenance = _merge_object_text(
            link["provenance_json"], provenance
        )
        if retired is None:
            retired_sql = "retired_at"
        elif retired:
            retired_sql = "CURRENT_TIMESTAMP"
        else:
            retired_sql = "NULL"
        connection.execute(
            f"""
            UPDATE assessment_finding_links
            SET target_kind = ?, target_id = ?, target_ref = ?,
                notes = ?, provenance_json = ?,
                retired_at = {retired_sql},
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                next_kind,
                next_id,
                next_ref,
                next_notes,
                next_provenance,
                int(link_id),
            ),
        )
        updated = connection.execute(
            "SELECT * FROM assessment_finding_links WHERE id = ?",
            (int(link_id),),
        ).fetchone()
    assert updated is not None
    result = dict(updated)
    result["finding_slug"] = finding_slug
    return result

def list_finding_groups(engagement_id: int, *, root_slug: str | None = None) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        finding_rows = connection.execute(
            """
            SELECT findings.*, merged.slug AS merged_into_slug
            FROM assessment_findings AS findings
            LEFT JOIN assessment_findings AS merged ON merged.id = findings.merged_into_finding_id
            WHERE findings.engagement_id = ?
            """,
            (engagement.id,),
        ).fetchall()
        findings_by_slug = {
            str(row["slug"]): _serialize_finding_record(row)
            for row in finding_rows
        }
        if root_slug is not None and root_slug not in findings_by_slug:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="root finding not found")
        params: tuple[Any, ...]
        root_filter = ""
        if root_slug is not None:
            root_filter = "AND links.target_ref = ?"
            params = (engagement.id, ROOT_CAUSE_LINK_KIND, root_slug)
        else:
            params = (engagement.id, ROOT_CAUSE_LINK_KIND)
        link_rows = connection.execute(
            f"""
            SELECT links.*, findings.slug AS finding_slug
            FROM assessment_finding_links AS links
            JOIN assessment_findings AS findings ON findings.id = links.finding_id
            WHERE links.engagement_id = ?
              AND links.link_kind = ?
              AND links.target_kind = 'finding'
              AND links.retired_at IS NULL
              {root_filter}
            ORDER BY links.updated_at DESC, links.id DESC
            """,
            params,
        ).fetchall()

    groups: dict[str, dict[str, Any]] = {}
    if root_slug is not None:
        groups[root_slug] = {
            "root": findings_by_slug[root_slug],
            "siblings": [],
            "sibling_count": 0,
            "residual_path_count": 0,
            "highest_severity": findings_by_slug[root_slug].get("severity", "info"),
        }
    for row in link_rows:
        link = dict(row)
        sibling_slug = str(link.get("finding_slug", "") or "")
        root_ref = str(link.get("target_ref", "") or "")
        sibling = findings_by_slug.get(sibling_slug)
        root = findings_by_slug.get(root_ref)
        if sibling is None or root is None:
            continue
        sibling_record = dict(sibling)
        sibling_record.update(_root_cause_link_metadata(link))
        group = groups.setdefault(
            root_ref,
            {
                "root": root,
                "siblings": [],
                "sibling_count": 0,
                "residual_path_count": 0,
                "highest_severity": root.get("severity", "info"),
            },
        )
        group["siblings"].append(sibling_record)

    for group in groups.values():
        siblings = group["siblings"]
        siblings.sort(
            key=lambda item: (
                item.get("sibling_order") if item.get("sibling_order") is not None else 999999,
                -SEVERITY_RANK.get(str(item.get("severity", "info")), 0),
                str(item.get("slug", "")),
            )
        )
        group["sibling_count"] = len(siblings)
        group["residual_path_count"] = sum(
            1 for item in siblings if item.get("root_cause_effect") == "eliminates_attack_path"
        )
        severities = [str(group["root"].get("severity", "info"))] + [str(item.get("severity", "info")) for item in siblings]
        group["highest_severity"] = max(severities, key=lambda sev: SEVERITY_RANK.get(sev, 0))
    return sorted(
        groups.values(),
        key=lambda group: (
            -SEVERITY_RANK.get(str(group.get("highest_severity", "info")), 0),
            str(group["root"].get("slug", "")),
        ),
    )
