from __future__ import annotations

from typing import Any
from fastapi import HTTPException, status

from ..events import _engagement_or_404

from . import _common
from ._common import _fetch_all, _json_text, _merge_object_text, _normalize_severity, _resolve_existing_finding_slug, _slugify



def _upsert_chain_link(
    connection,
    engagement_id: int,
    *,
    chain_id: int,
    relation: str,
    entity_kind: str,
    entity_id: int | None,
    entity_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    if str(entity_kind) == "finding" and entity_ref:
        entity_ref = _resolve_existing_finding_slug(
            connection,
            engagement_id,
            entity_ref,
            field="entity_ref",
        )
    row = connection.execute(
        """
        SELECT *
        FROM assessment_attack_chain_links
        WHERE engagement_id = ? AND chain_id = ? AND relation = ? AND entity_kind = ? AND entity_id IS ? AND entity_ref = ?
        """,
        (engagement_id, chain_id, relation, entity_kind, entity_id, entity_ref),
    ).fetchone()
    if row is None:
        cursor = connection.execute(
            """
            INSERT INTO assessment_attack_chain_links (
                engagement_id, chain_id, relation, entity_kind, entity_id, entity_ref, notes, provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement_id, chain_id, relation, entity_kind, entity_id, entity_ref, notes, _json_text(provenance)),
        )
        row = connection.execute("SELECT * FROM assessment_attack_chain_links WHERE id = ?", (cursor.lastrowid,)).fetchone()
    else:
        connection.execute(
            """
            UPDATE assessment_attack_chain_links
            SET notes = ?, provenance_json = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (_common._append_notes(row["notes"], notes), _merge_object_text(row["provenance_json"], provenance), row["id"]),
        )
        row = connection.execute("SELECT * FROM assessment_attack_chain_links WHERE id = ?", (row["id"],)).fetchone()
    assert row is not None
    return dict(row)

def create_attack_chain(
    engagement_id: int,
    *,
    chain_key: str | None,
    title: str,
    status_value: str,
    severity: str,
    narrative: str,
    evidence_ref: str,
    provenance: dict[str, Any] | None,
    links: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    resolved_key = chain_key or _slugify(title)
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO assessment_attack_chains (
                engagement_id, chain_key, title, status, severity, narrative, evidence_ref, provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, chain_key) DO UPDATE SET
                title = excluded.title,
                status = excluded.status,
                severity = excluded.severity,
                narrative = CASE WHEN excluded.narrative = '' THEN assessment_attack_chains.narrative ELSE excluded.narrative END,
                evidence_ref = COALESCE(NULLIF(excluded.evidence_ref, ''), assessment_attack_chains.evidence_ref),
                provenance_json = excluded.provenance_json,
                updated_at = CURRENT_TIMESTAMP
            """,
            (engagement.id, resolved_key, title, status_value, _normalize_severity(severity), narrative, evidence_ref, _json_text(provenance)),
        )
        row = connection.execute(
            "SELECT * FROM assessment_attack_chains WHERE engagement_id = ? AND chain_key = ?",
            (engagement.id, resolved_key),
        ).fetchone()
        assert row is not None
        chain = dict(row)
        chain_links = [
            _upsert_chain_link(
                connection,
                engagement.id,
                chain_id=chain["id"],
                relation=str(item.get("relation", "step")),
                entity_kind=str(item.get("entity_kind", "unknown")),
                entity_id=item.get("entity_id"),
                entity_ref=str(item.get("entity_ref", "")),
                notes=str(item.get("notes", "")),
                provenance=item.get("provenance"),
            )
            for item in (links or [])
        ]
    if evidence_ref:
        artifact_id = _common._register_artifact_reference(
            engagement.id,
            evidence_ref,
            kind="chain-evidence",
            related_chain_key=str(chain["chain_key"]),
        )
        with _common.get_connection() as connection:
            connection.execute(
                "UPDATE assessment_attack_chains SET evidence_artifact_id = ? WHERE id = ?",
                (artifact_id, int(chain["id"])),
            )
            chain = dict(connection.execute(
                "SELECT * FROM assessment_attack_chains WHERE id = ?",
                (int(chain["id"]),),
            ).fetchone())
    return {"chain": chain, "links": chain_links}

def create_attack_chain_link(
    engagement_id: int,
    *,
    chain_key: str,
    relation: str,
    entity_kind: str,
    entity_id: int | None,
    entity_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        chain = connection.execute(
            "SELECT * FROM assessment_attack_chains WHERE engagement_id = ? AND chain_key = ?",
            (engagement.id, chain_key),
        ).fetchone()
        if chain is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="attack chain not found")
        return _upsert_chain_link(
            connection,
            engagement.id,
            chain_id=int(chain["id"]),
            relation=relation,
            entity_kind=entity_kind,
            entity_id=entity_id,
            entity_ref=entity_ref,
            notes=notes,
            provenance=provenance,
        )

def list_attack_chains(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_attack_chains WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))

def list_attack_chain_links(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT links.*, chains.chain_key
            FROM assessment_attack_chain_links AS links
            JOIN assessment_attack_chains AS chains ON chains.id = links.chain_id
            WHERE links.engagement_id = ?
            ORDER BY links.updated_at DESC, links.id DESC
            """,
            (engagement.id,),
        ).fetchall()
    return [dict(row) for row in rows]

def _upsert_simple_entity(
    connection,
    *,
    table: str,
    engagement_id: int,
    key_column: str,
    key_value: str,
    values: dict[str, Any],
) -> dict[str, Any]:
    columns = ", ".join(["engagement_id", key_column, *values.keys()])
    placeholders = ", ".join(["?"] * (2 + len(values)))
    assignments = ", ".join([f"{column} = excluded.{column}" for column in values.keys()])
    connection.execute(
        f"""
        INSERT INTO {table} ({columns})
        VALUES ({placeholders})
        ON CONFLICT(engagement_id, {key_column}) DO UPDATE SET
            {assignments},
            updated_at = CURRENT_TIMESTAMP
        """,
        (engagement_id, key_value, *values.values()),
    )
    row = connection.execute(
        f"SELECT * FROM {table} WHERE engagement_id = ? AND {key_column} = ?",
        (engagement_id, key_value),
    ).fetchone()
    assert row is not None
    return dict(row)

def record_credential(
    engagement_id: int,
    *,
    credential_key: str,
    kind: str,
    principal: str,
    secret: str,
    source_name: str,
    status_value: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _upsert_simple_entity(
            connection,
            table="assessment_credentials",
            engagement_id=engagement.id,
            key_column="credential_key",
            key_value=credential_key,
            values={
                "kind": kind,
                "principal": principal,
                "secret": secret,
                "source_name": source_name,
                "status": status_value,
                "notes": notes,
                "provenance_json": _json_text(provenance),
            },
        )

def list_credentials(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_credentials WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))

def record_credential_test(
    engagement_id: int,
    *,
    credential_id: int,
    service_id: int | None,
    target_ref: str,
    auth_context: str,
    outcome: str,
    evidence_ref: str,
    notes: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO assessment_credential_tests (
                engagement_id, credential_id, service_id, target_ref, auth_context, outcome, evidence_ref, notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement.id, credential_id, service_id, target_ref, auth_context, outcome, evidence_ref, notes),
        )
        row = connection.execute("SELECT * FROM assessment_credential_tests WHERE id = ?", (cursor.lastrowid,)).fetchone()
    assert row is not None
    return dict(row)

def list_credential_tests(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_credential_tests WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))

def record_access_record(
    engagement_id: int,
    *,
    access_key: str,
    credential_id: int | None,
    service_id: int | None,
    principal: str,
    access_level: str,
    target_ref: str,
    status_value: str,
    evidence_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _upsert_simple_entity(
            connection,
            table="assessment_access_records",
            engagement_id=engagement.id,
            key_column="access_key",
            key_value=access_key,
            values={
                "credential_id": credential_id,
                "service_id": service_id,
                "principal": principal,
                "access_level": access_level,
                "target_ref": target_ref,
                "status": status_value,
                "evidence_ref": evidence_ref,
                "notes": notes,
                "provenance_json": _json_text(provenance),
            },
        )

def list_access_records(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_access_records WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))

def record_pivot(
    engagement_id: int,
    *,
    pivot_key: str,
    access_record_id: int | None,
    source_ref: str,
    destination_ref: str,
    technique: str,
    status_value: str,
    evidence_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _upsert_simple_entity(
            connection,
            table="assessment_pivots",
            engagement_id=engagement.id,
            key_column="pivot_key",
            key_value=pivot_key,
            values={
                "access_record_id": access_record_id,
                "source_ref": source_ref,
                "destination_ref": destination_ref,
                "technique": technique,
                "status": status_value,
                "evidence_ref": evidence_ref,
                "notes": notes,
                "provenance_json": _json_text(provenance),
            },
        )

def list_pivots(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_pivots WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))

def record_tunnel(
    engagement_id: int,
    *,
    tunnel_key: str,
    pivot_id: int | None,
    tunnel_type: str,
    source_endpoint: str,
    destination_endpoint: str,
    status_value: str,
    evidence_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _upsert_simple_entity(
            connection,
            table="assessment_tunnels",
            engagement_id=engagement.id,
            key_column="tunnel_key",
            key_value=tunnel_key,
            values={
                "pivot_id": pivot_id,
                "tunnel_type": tunnel_type,
                "source_endpoint": source_endpoint,
                "destination_endpoint": destination_endpoint,
                "status": status_value,
                "evidence_ref": evidence_ref,
                "notes": notes,
                "provenance_json": _json_text(provenance),
            },
        )

def list_tunnels(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_tunnels WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))

def record_blocked_technique(
    engagement_id: int,
    *,
    technique_key: str,
    technique: str,
    target_kind: str,
    target_ref: str,
    reason: str,
    retry_state: str,
    evidence_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _upsert_simple_entity(
            connection,
            table="assessment_blocked_techniques",
            engagement_id=engagement.id,
            key_column="technique_key",
            key_value=technique_key,
            values={
                "technique": technique,
                "target_kind": target_kind,
                "target_ref": target_ref,
                "reason": reason,
                "retry_state": retry_state,
                "evidence_ref": evidence_ref,
                "notes": notes,
                "provenance_json": _json_text(provenance),
            },
        )

def list_blocked_techniques(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_blocked_techniques WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))
