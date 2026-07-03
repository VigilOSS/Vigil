from __future__ import annotations

import enum
import hashlib
import json
import re
from typing import Any
from urllib.parse import urlparse
from fastapi import HTTPException, status

from ..events import _engagement_or_404

from . import _common
from ._common import (
    SEVERITY_RANK,
    WORKFLOW_STATUS_RANK,
    _fetch_all,
    _hash_json,
    _json_text,
    _normalize_severity,
    _normalize_workflow_status,
    _normalize_verification_state,
    _parse_url,
    _scalar_row,
)
from .dispatches import _serialize_decision



class CoverageStatus(enum.StrEnum):
    """Per-item coverage status. ``StrEnum`` so members serialize/compare as their
    bare lowercase string identically to the prior raw-string constants."""

    PENDING = "pending"
    QUEUED = "queued"
    DEFERRED = "deferred"
    COVERED = "covered"
    NOT_APPLICABLE = "not_applicable"
    BLOCKED = "blocked"


# Raw operator-input synonyms → canonical members. Keys stay plain strings
# (e.g. "done", "n/a") because they are non-member inputs we accept on the wire.
#
_COVERAGE_STATUS_SYNONYMS = {
    "done": CoverageStatus.COVERED,
    "not-applicable": CoverageStatus.NOT_APPLICABLE,
    "n/a": CoverageStatus.NOT_APPLICABLE,
}

# Derived membership set (frozenset of members, NOT an alias of the class).
COVERAGE_STATUSES = frozenset(CoverageStatus)

PROBE_RESULT_STATUSES: tuple[str, ...] = (
    "tested",
    "signal",
    "attempted",
    "blocked",
    "error",
    "no-signal",
)

PROBE_RESULT_STATUSES_COVERING: frozenset[str] = frozenset({"tested", "signal"})

PROBE_RESULT_STATUS_DEFAULT = "tested"


def _normalize_probe_result_status(value: str) -> str:
    """Validate a probe ``result_status`` against the canonical vocabulary.

    Unknown statuses are rejected (400) rather than silently stored, so the
    free-text column can never drift into an un-interpretable value that a
    later gate has to guess about. Empty input falls back to the default.
    """
    status_value = (value or "").strip().lower()
    if not status_value:
        return PROBE_RESULT_STATUS_DEFAULT
    if status_value not in PROBE_RESULT_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"invalid probe result_status: {value!r}; "
                f"allowed: {', '.join(PROBE_RESULT_STATUSES)}"
            ),
        )
    return status_value

def _normalize_coverage_status(value: str) -> CoverageStatus:
    status_value = (value or "pending").strip().lower()
    status_value = _COVERAGE_STATUS_SYNONYMS.get(status_value, status_value)
    if status_value not in COVERAGE_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid coverage status: {value}")
    return CoverageStatus(status_value)

def _coalesce_coverage_status(existing: str, incoming: str, *, explicit_override: bool = False) -> CoverageStatus:
    existing_normalized = _normalize_coverage_status(existing)
    incoming_normalized = _normalize_coverage_status(incoming)
    if explicit_override:
        return incoming_normalized
    if incoming_normalized in {"pending", "queued"} and existing_normalized not in {"pending", "queued"}:
        return existing_normalized
    if existing_normalized == "queued" and incoming_normalized == "pending":
        return existing_normalized
    return incoming_normalized

def _find_target_id(connection, engagement_id: int, identity: str | None) -> int | None:
    if not identity:
        return None
    row = connection.execute(
        "SELECT id FROM assessment_targets WHERE engagement_id = ? AND identity = ?",
        (engagement_id, identity),
    ).fetchone()
    return int(row["id"]) if row else None

def _upsert_target(
    connection,
    engagement_id: int,
    *,
    identity: str,
    kind: str,
    host: str | None,
    ip_address: str | None,
    hostname: str | None,
    notes: str,
    discovered_by: str,
) -> dict[str, Any]:
    connection.execute(
        """
        INSERT INTO assessment_targets (engagement_id, identity, kind, host, ip_address, hostname, notes, discovered_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, identity) DO UPDATE SET
            kind = excluded.kind,
            host = COALESCE(excluded.host, assessment_targets.host),
            ip_address = COALESCE(excluded.ip_address, assessment_targets.ip_address),
            hostname = COALESCE(excluded.hostname, assessment_targets.hostname),
            notes = CASE
                WHEN excluded.notes = '' THEN assessment_targets.notes
                WHEN assessment_targets.notes = '' THEN excluded.notes
                ELSE assessment_targets.notes || char(10) || excluded.notes
            END,
            discovered_by = COALESCE(NULLIF(excluded.discovered_by, ''), assessment_targets.discovered_by),
            updated_at = CURRENT_TIMESTAMP
        """,
        (engagement_id, identity, kind, host, ip_address, hostname, notes, discovered_by),
    )
    row = connection.execute(
        """
        SELECT id, engagement_id, identity, kind, host, ip_address, hostname, notes, discovered_by, created_at, updated_at
        FROM assessment_targets
        WHERE engagement_id = ? AND identity = ?
        """,
        (engagement_id, identity),
    ).fetchone()
    assert row is not None
    return dict(row)

def _upsert_service(
    connection,
    engagement_id: int,
    *,
    endpoint: str,
    protocol: str,
    port: int | None,
    service: str,
    state: str,
    coverage_status: str,
    banner: str,
    notes: str,
    discovered_by: str,
    target_identity: str | None,
) -> dict[str, Any]:
    target_id = _find_target_id(connection, engagement_id, target_identity)
    connection.execute(
        """
        INSERT INTO assessment_services (
            engagement_id, target_id, endpoint, port, protocol, service, state, coverage_status, banner, notes, discovered_by
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, endpoint, protocol) DO UPDATE SET
            target_id = COALESCE(excluded.target_id, assessment_services.target_id),
            port = COALESCE(excluded.port, assessment_services.port),
            service = COALESCE(NULLIF(excluded.service, ''), assessment_services.service),
            state = excluded.state,
            coverage_status = CASE
                WHEN excluded.coverage_status = 'pending'
                    AND assessment_services.coverage_status IN ('covered', 'partial', 'blocked')
                THEN assessment_services.coverage_status
                ELSE excluded.coverage_status
            END,
            banner = COALESCE(NULLIF(excluded.banner, ''), assessment_services.banner),
            notes = CASE
                WHEN excluded.notes = '' THEN assessment_services.notes
                WHEN assessment_services.notes = '' THEN excluded.notes
                ELSE assessment_services.notes || char(10) || excluded.notes
            END,
            discovered_by = COALESCE(NULLIF(excluded.discovered_by, ''), assessment_services.discovered_by),
            updated_at = CURRENT_TIMESTAMP
        """,
        (engagement_id, target_id, endpoint, port, protocol, service, state, coverage_status, banner, notes, discovered_by),
    )
    row = connection.execute(
        """
        SELECT id, engagement_id, target_id, endpoint, port, protocol, service, state, coverage_status, banner, notes, discovered_by, created_at, updated_at
        FROM assessment_services
        WHERE engagement_id = ? AND endpoint = ? AND protocol = ?
        """,
        (engagement_id, endpoint, protocol),
    ).fetchone()
    assert row is not None
    return dict(row)

def _upsert_request_variant(
    connection,
    engagement_id: int,
    *,
    url: str,
    method: str,
    auth_context: str,
    content_type_family: str,
    query_schema: Any,
    body_schema: Any,
    path_schema: Any,
    cookie_schema: Any,
    header_schema: Any,
    path_template: str,
    discovery_source: str,
    notes: str,
) -> dict[str, Any]:
    scheme, host, port, normalized_path = _parse_url(url)
    params_schema_hash = _hash_json(
        {
            "query": query_schema or {},
            "path": path_schema or {},
            "cookie": cookie_schema or {},
            "headers": header_schema or {},
        }
    )
    body_schema_hash = _hash_json(body_schema or {})
    connection.execute(
        """
        INSERT INTO assessment_request_variants (
            engagement_id, auth_context, scheme, host, port, method, normalized_path, path_template,
            canonical_url, content_type_family, query_schema_json, body_schema_json, path_schema_json,
            cookie_schema_json, header_schema_json, params_schema_hash, body_schema_hash, discovery_source, notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(
            engagement_id, scheme, host, port, method, normalized_path, auth_context, params_schema_hash, body_schema_hash, content_type_family
        ) DO UPDATE SET
            path_template = COALESCE(NULLIF(excluded.path_template, ''), assessment_request_variants.path_template),
            canonical_url = COALESCE(NULLIF(excluded.canonical_url, ''), assessment_request_variants.canonical_url),
            query_schema_json = excluded.query_schema_json,
            body_schema_json = excluded.body_schema_json,
            path_schema_json = excluded.path_schema_json,
            cookie_schema_json = excluded.cookie_schema_json,
            header_schema_json = excluded.header_schema_json,
            discovery_source = COALESCE(NULLIF(excluded.discovery_source, ''), assessment_request_variants.discovery_source),
            notes = CASE
                WHEN excluded.notes = '' THEN assessment_request_variants.notes
                WHEN assessment_request_variants.notes = '' THEN excluded.notes
                ELSE assessment_request_variants.notes || char(10) || excluded.notes
            END,
            last_seen_at = CURRENT_TIMESTAMP
        """,
        (
            engagement_id,
            auth_context,
            scheme,
            host,
            port,
            method.upper(),
            normalized_path,
            path_template,
            url,
            content_type_family,
            _json_text(query_schema),
            _json_text(body_schema),
            _json_text(path_schema),
            _json_text(cookie_schema),
            _json_text(header_schema),
            params_schema_hash,
            body_schema_hash,
            discovery_source,
            notes,
        ),
    )
    row = connection.execute(
        """
        SELECT *
        FROM assessment_request_variants
        WHERE engagement_id = ? AND scheme = ? AND host = ? AND port = ? AND method = ? AND normalized_path = ?
          AND auth_context = ? AND params_schema_hash = ? AND body_schema_hash = ? AND content_type_family = ?
        """,
        (engagement_id, scheme, host, port, method.upper(), normalized_path, auth_context, params_schema_hash, body_schema_hash, content_type_family),
    ).fetchone()
    assert row is not None
    return dict(row)

def _insert_request_observation(
    connection,
    engagement_id: int,
    *,
    request_variant_id: int,
    url: str,
    discovery_source: str,
    response_status: int | None,
    evidence_ref: str,
    observation_payload: Any,
) -> dict[str, Any]:
    cursor = connection.execute(
        """
        INSERT INTO assessment_request_observations (
            engagement_id, request_variant_id, observed_url, source_name, response_status, evidence_ref, raw_payload
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (engagement_id, request_variant_id, url, discovery_source, response_status, evidence_ref, _json_text(observation_payload or {})),
    )
    row = connection.execute(
        "SELECT * FROM assessment_request_observations WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()
    assert row is not None
    return dict(row)

def _upsert_coverage_item(
    connection,
    engagement_id: int,
    *,
    request_variant_id: int | None,
    service_id: int | None,
    auth_context: str,
    input_slot: str,
    attack_family: str,
    status_value: str,
    notes: str,
    preserve_existing_status: bool = False,
    refresh_service_status: bool = True,
) -> dict[str, Any]:
    normalized_status = _normalize_coverage_status(status_value)
    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO assessment_coverage_items (
            engagement_id, request_variant_id, service_id, auth_context, input_slot, attack_family, status, notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (engagement_id, request_variant_id, service_id, auth_context, input_slot, attack_family, normalized_status, notes),
    )
    row = connection.execute(
        """
        SELECT *
        FROM assessment_coverage_items
        WHERE engagement_id = ? AND request_variant_id IS ? AND service_id IS ? AND auth_context = ? AND input_slot = ? AND attack_family = ?
        """,
        (engagement_id, request_variant_id, service_id, auth_context, input_slot, attack_family),
    ).fetchone()
    assert row is not None
    if cursor.rowcount == 0:
        resolved_status = (
            _coalesce_coverage_status(row["status"], normalized_status)
            if preserve_existing_status
            else normalized_status
        )
        connection.execute(
            """
            UPDATE assessment_coverage_items
            SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (resolved_status, _common._append_notes(row["notes"], notes), row["id"]),
        )
        row = connection.execute("SELECT * FROM assessment_coverage_items WHERE id = ?", (row["id"],)).fetchone()
    assert row is not None
    if refresh_service_status and row["service_id"] is not None:
        _refresh_service_coverage_status(connection, engagement_id, int(row["service_id"]))
    return dict(row)

def _refresh_service_coverage_status(connection, engagement_id: int, service_id: int) -> None:
    rows = connection.execute(
        "SELECT status FROM assessment_coverage_items WHERE engagement_id = ? AND service_id = ?",
        (engagement_id, service_id),
    ).fetchall()
    if not rows:
        return
    statuses = [_normalize_coverage_status(str(row["status"])) for row in rows]
    if all(status_value in {"covered", "not_applicable"} for status_value in statuses):
        coverage_status = "covered"
    elif any(status_value == "blocked" for status_value in statuses):
        coverage_status = "blocked"
    elif any(status_value in {"covered", "not_applicable", "deferred"} for status_value in statuses):
        coverage_status = "partial"
    else:
        coverage_status = "pending"
    connection.execute(
        """
        UPDATE assessment_services
        SET coverage_status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND engagement_id = ?
        """,
        (coverage_status, service_id, engagement_id),
    )

def _probe_key(
    *,
    request_variant_id: int | None,
    service_id: int | None,
    coverage_item_id: int | None,
    auth_context: str,
    input_slot: str,
    attack_family: str,
    payload_family: str,
    payload_value: str,
    tool_name: str,
    target_host: str = "",
    target_path: str = "",
    target_port: int | None = None,
    lens: str = "",
) -> tuple[str, str]:
    payload_hash = hashlib.sha256(payload_value.encode("utf-8")).hexdigest() if payload_value else ""
    key_fields: dict[str, Any] = {
        "request_variant_id": request_variant_id,
        "service_id": service_id,
        "coverage_item_id": coverage_item_id,
        "auth_context": auth_context,
        "input_slot": input_slot,
        "attack_family": attack_family,
        "payload_family": payload_family,
        "payload_hash": payload_hash,
        "tool_name": tool_name,
        "target_host": target_host,
        "target_path": target_path,
        "target_port": target_port,
    }
    # lens partitions the probe space: the SAME target/payload probed under a
    # DIFFERENT mindset is a distinct attempt, not a dedup hit. Add it to the key
    # ONLY when set — a bare lens="" is not a distinct partition, and omitting the
    # field keeps lens-less probes hashing to the SAME key they had before the
    # lens column existed, so dedup stays intact for rows written pre-migration.
    if lens:
        key_fields["lens"] = lens
    probe_key = hashlib.sha256(
        json.dumps(key_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return payload_hash, probe_key

def _upsert_probe_run(
    connection,
    engagement_id: int,
    *,
    request_variant_id: int | None,
    service_id: int | None,
    coverage_item_id: int | None,
    auth_context: str,
    input_slot: str,
    attack_family: str,
    payload_family: str,
    payload_value: str,
    tool_name: str,
    agent_name: str,
    result_status: str,
    observed_http_status: int | None,
    signal_type: str,
    evidence_ref: str,
    notes: str,
    target_host: str = "",
    target_path: str = "",
    target_port: int | None = None,
    lens: str = "",
    finding_id: int | None = None,
) -> dict[str, Any]:
    result_status = _normalize_probe_result_status(result_status)
    # lens is free-text: light strip/normalize only, never hard-enumerated.
    lens = (lens or "").strip()
    # Validate the optional finding linkage up front so a typo'd id is a clean
    # 404 rather than a raw FK IntegrityError (foreign_keys is ON).
    if finding_id is not None:
        finding_row = connection.execute(
            "SELECT id FROM assessment_findings WHERE engagement_id = ? AND id = ?",
            (engagement_id, finding_id),
        ).fetchone()
        if finding_row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"finding id={finding_id} not found",
            )
    payload_hash, probe_key = _probe_key(
        request_variant_id=request_variant_id,
        service_id=service_id,
        coverage_item_id=coverage_item_id,
        auth_context=auth_context,
        input_slot=input_slot,
        attack_family=attack_family,
        payload_family=payload_family,
        payload_value=payload_value,
        tool_name=tool_name,
        target_host=target_host,
        target_path=target_path,
        target_port=target_port,
        lens=lens,
    )
    connection.execute(
        """
        INSERT INTO assessment_probe_runs (
            engagement_id, request_variant_id, service_id, coverage_item_id, auth_context, input_slot, attack_family,
            payload_family, payload_value_hash, probe_key, tool_name, agent_name, result_status,
            observed_http_status, signal_type, evidence_ref, notes, target_host, target_path, target_port,
            lens, finding_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, probe_key) DO UPDATE SET
            agent_name = COALESCE(NULLIF(excluded.agent_name, ''), assessment_probe_runs.agent_name),
            result_status = excluded.result_status,
            observed_http_status = COALESCE(excluded.observed_http_status, assessment_probe_runs.observed_http_status),
            signal_type = COALESCE(NULLIF(excluded.signal_type, ''), assessment_probe_runs.signal_type),
            evidence_ref = COALESCE(NULLIF(excluded.evidence_ref, ''), assessment_probe_runs.evidence_ref),
            target_host = COALESCE(NULLIF(excluded.target_host, ''), assessment_probe_runs.target_host),
            target_path = COALESCE(NULLIF(excluded.target_path, ''), assessment_probe_runs.target_path),
            target_port = COALESCE(excluded.target_port, assessment_probe_runs.target_port),
            -- finding_id backfills on a re-run of the same probe_key (it is NOT
            -- part of probe_key); lens IS part of probe_key so it never differs
            -- on a conflict and needs no update clause.
            finding_id = COALESCE(excluded.finding_id, assessment_probe_runs.finding_id),
            notes = CASE
                WHEN excluded.notes = '' THEN assessment_probe_runs.notes
                WHEN assessment_probe_runs.notes = '' THEN excluded.notes
                ELSE assessment_probe_runs.notes || char(10) || excluded.notes
            END
        """,
        (
            engagement_id,
            request_variant_id,
            service_id,
            coverage_item_id,
            auth_context,
            input_slot,
            attack_family,
            payload_family,
            payload_hash,
            probe_key,
            tool_name,
            agent_name,
            result_status,
            observed_http_status,
            signal_type,
            evidence_ref,
            notes,
            target_host,
            target_path,
            target_port,
            lens,
            finding_id,
        ),
    )
    row = connection.execute(
        "SELECT * FROM assessment_probe_runs WHERE engagement_id = ? AND probe_key = ?",
        (engagement_id, probe_key),
    ).fetchone()
    assert row is not None
    return dict(row)

def _upsert_surface(
    connection,
    engagement_id: int,
    *,
    surface_type: str,
    target_descriptor: str,
    source_name: str,
    rationale: str,
    evidence_ref: str,
    status_value: str,
) -> dict[str, Any]:
    connection.execute(
        """
        INSERT INTO assessment_surfaces (engagement_id, surface_type, target_descriptor, source_name, rationale, evidence_ref, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, surface_type, target_descriptor) DO UPDATE SET
            source_name = COALESCE(NULLIF(excluded.source_name, ''), assessment_surfaces.source_name),
            rationale = CASE
                WHEN excluded.rationale = '' THEN assessment_surfaces.rationale
                WHEN assessment_surfaces.rationale = '' THEN excluded.rationale
                ELSE assessment_surfaces.rationale || char(10) || excluded.rationale
            END,
            evidence_ref = COALESCE(NULLIF(excluded.evidence_ref, ''), assessment_surfaces.evidence_ref),
            status = excluded.status,
            updated_at = CURRENT_TIMESTAMP
        """,
        (engagement_id, surface_type, target_descriptor, source_name, rationale, evidence_ref, status_value),
    )
    row = connection.execute(
        """
        SELECT *
        FROM assessment_surfaces
        WHERE engagement_id = ? AND surface_type = ? AND target_descriptor = ?
        """,
        (engagement_id, surface_type, target_descriptor),
    ).fetchone()
    assert row is not None
    return dict(row)

def _service_fields_from_url(url: str) -> tuple[str, str, int, str]:
    scheme, host, port, _ = _parse_url(url)
    endpoint = f"{host}:{port}"
    service_name = "https" if scheme == "https" else "http"
    return scheme, endpoint, port, service_name

def _auto_request_coverage_candidates(
    *,
    query_schema: dict[str, Any],
    body_schema: dict[str, Any],
    path_schema: dict[str, Any],
    cookie_schema: dict[str, Any],
    header_schema: dict[str, Any],
) -> list[dict[str, str]]:
    candidates = [{"input_slot": "endpoint", "attack_family": "endpoint-review", "status": "pending", "notes": "Auto-generated from request observation"}]
    if query_schema:
        candidates.append({"input_slot": "query", "attack_family": "parameter-review", "status": "pending", "notes": "Auto-generated from request observation"})
    if body_schema:
        candidates.append({"input_slot": "body", "attack_family": "parameter-review", "status": "pending", "notes": "Auto-generated from request observation"})
    if path_schema:
        candidates.append({"input_slot": "path", "attack_family": "parameter-review", "status": "pending", "notes": "Auto-generated from request observation"})
    if cookie_schema:
        candidates.append({"input_slot": "cookie", "attack_family": "session-review", "status": "pending", "notes": "Auto-generated from request observation"})
    if header_schema:
        candidates.append({"input_slot": "header", "attack_family": "header-review", "status": "pending", "notes": "Auto-generated from request observation"})
    return candidates

def record_target(
    engagement_id: int,
    *,
    identity: str,
    kind: str,
    host: str | None,
    ip_address: str | None,
    hostname: str | None,
    notes: str,
    discovered_by: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _upsert_target(
            connection,
            engagement.id,
            identity=identity,
            kind=kind,
            host=host,
            ip_address=ip_address,
            hostname=hostname,
            notes=notes,
            discovered_by=discovered_by,
        )

def list_targets(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_targets WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))

def record_service(
    engagement_id: int,
    *,
    endpoint: str,
    protocol: str,
    port: int | None,
    service: str,
    state: str,
    coverage_status: str,
    banner: str,
    notes: str,
    discovered_by: str,
    target_identity: str | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _upsert_service(
            connection,
            engagement.id,
            endpoint=endpoint,
            protocol=protocol,
            port=port,
            service=service,
            state=state,
            coverage_status=coverage_status,
            banner=banner,
            notes=notes,
            discovered_by=discovered_by,
            target_identity=target_identity,
        )

def list_services(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_services WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))

def record_request_variant(
    engagement_id: int,
    *,
    url: str,
    method: str,
    auth_context: str,
    content_type_family: str,
    query_schema: Any,
    body_schema: Any,
    path_schema: Any,
    cookie_schema: Any,
    header_schema: Any,
    path_template: str,
    discovery_source: str,
    notes: str,
    response_status: int | None,
    evidence_ref: str,
    observation_payload: Any,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        variant = _upsert_request_variant(
            connection,
            engagement.id,
            url=url,
            method=method,
            auth_context=auth_context,
            content_type_family=content_type_family,
            query_schema=query_schema,
            body_schema=body_schema,
            path_schema=path_schema,
            cookie_schema=cookie_schema,
            header_schema=header_schema,
            path_template=path_template,
            discovery_source=discovery_source,
            notes=notes,
        )
        _insert_request_observation(
            connection,
            engagement.id,
            request_variant_id=variant["id"],
            url=url,
            discovery_source=discovery_source,
            response_status=response_status,
            evidence_ref=evidence_ref,
            observation_payload=observation_payload,
        )
        return variant

DEFAULT_REQUEST_VARIANT_LIMIT = 250
DEFAULT_REQUEST_OBSERVATION_LIMIT = 250
DEFAULT_PROBE_RUN_LIMIT = 250
DEFAULT_COVERAGE_ITEM_LIMIT = 1000
DEFAULT_SURFACE_LIMIT = 1000
MAX_REQUEST_LIST_LIMIT = 5000
MAX_PROBE_RUN_LIST_LIMIT = 5000
MAX_ASSESSMENT_LIST_LIMIT = 5000


def _bounded_request_list_window(limit: int, offset: int) -> tuple[int, int]:
    return (
        max(1, min(int(limit), MAX_REQUEST_LIST_LIMIT)),
        max(0, int(offset)),
    )


def _bounded_probe_run_window(limit: int, offset: int) -> tuple[int, int]:
    return (
        max(1, min(int(limit), MAX_PROBE_RUN_LIST_LIMIT)),
        max(0, int(offset)),
    )


def _bounded_assessment_list_window(limit: int, offset: int) -> tuple[int, int]:
    return (
        max(1, min(int(limit), MAX_ASSESSMENT_LIST_LIMIT)),
        max(0, int(offset)),
    )


def list_request_variants(
    engagement_id: int,
    *,
    limit: int = DEFAULT_REQUEST_VARIANT_LIMIT,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    limit, offset = _bounded_request_list_window(limit, offset)
    with _common.get_connection() as connection:
        return _fetch_all(
            connection,
            """
            SELECT *
            FROM assessment_request_variants
            WHERE engagement_id = ?
            ORDER BY last_seen_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (engagement.id, limit, offset),
        )

def list_request_observations(
    engagement_id: int,
    *,
    limit: int = DEFAULT_REQUEST_OBSERVATION_LIMIT,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    limit, offset = _bounded_request_list_window(limit, offset)
    with _common.get_connection() as connection:
        return _fetch_all(
            connection,
            """
            SELECT *
            FROM assessment_request_observations
            WHERE engagement_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (engagement.id, limit, offset),
        )

def _ingest_request_observation(
    connection,
    engagement_id: int,
    *,
    url: str,
    method: str,
    auth_context: str,
    content_type_family: str,
    query_schema: dict[str, Any],
    body_schema: dict[str, Any],
    path_schema: dict[str, Any],
    cookie_schema: dict[str, Any],
    header_schema: dict[str, Any],
    path_template: str,
    discovery_source: str,
    notes: str,
    response_status: int | None,
    evidence_ref: str,
    observation_payload: dict[str, Any],
    target_identity: str | None,
    target_kind: str,
    target_notes: str,
    target_ip_address: str | None,
    target_hostname: str | None,
    banner: str,
    coverage_candidates: list[dict[str, Any]] | None,
    auto_generate_coverage: bool,
    deferred_service_refreshes: set[int] | None = None,
) -> dict[str, Any]:
    scheme, host, _, _ = _parse_url(url)
    _, endpoint, port, service_name = _service_fields_from_url(url)
    identity = target_identity or host
    discovered_by = discovery_source
    target = _upsert_target(
        connection,
        engagement_id,
        identity=identity,
        kind=target_kind,
        host=host,
        ip_address=target_ip_address,
        hostname=target_hostname or host,
        notes=target_notes or notes,
        discovered_by=discovered_by,
    )
    service = _upsert_service(
        connection,
        engagement_id,
        endpoint=endpoint,
        protocol=scheme,
        port=port,
        service=service_name,
        state="discovered",
        coverage_status="pending",
        banner=banner,
        notes=notes,
        discovered_by=discovered_by,
        target_identity=identity,
    )
    request_variant = _upsert_request_variant(
        connection,
        engagement_id,
        url=url,
        method=method,
        auth_context=auth_context,
        content_type_family=content_type_family,
        query_schema=query_schema,
        body_schema=body_schema,
        path_schema=path_schema,
        cookie_schema=cookie_schema,
        header_schema=header_schema,
        path_template=path_template,
        discovery_source=discovery_source,
        notes=notes,
    )
    observation = _insert_request_observation(
        connection,
        engagement_id,
        request_variant_id=request_variant["id"],
        url=url,
        discovery_source=discovery_source,
        response_status=response_status,
        evidence_ref=evidence_ref,
        observation_payload=observation_payload,
    )
    candidates = coverage_candidates or []
    if auto_generate_coverage:
        candidates = [
            *candidates,
            *_auto_request_coverage_candidates(
                query_schema=query_schema,
                body_schema=body_schema,
                path_schema=path_schema,
                cookie_schema=cookie_schema,
                header_schema=header_schema,
            ),
            {
                "input_slot": "service",
                "attack_family": "service-validation",
                "status": "pending",
                "notes": "Auto-generated from service observation",
            },
        ]
    coverage_items: list[dict[str, Any]] = []
    seen_keys: set[tuple[int | None, int | None, str, str, str]] = set()
    for candidate in candidates:
        key = (
            request_variant["id"] if candidate.get("input_slot") != "service" else None,
            service["id"] if candidate.get("input_slot") == "service" else None,
            auth_context,
            str(candidate.get("input_slot", "unknown")),
            str(candidate.get("attack_family", "review")),
        )
        if key in seen_keys:
            continue
        seen_keys.add(key)
        coverage_item = _upsert_coverage_item(
            connection,
            engagement_id,
            request_variant_id=key[0],
            service_id=key[1],
            auth_context=auth_context,
            input_slot=key[3],
            attack_family=key[4],
            status_value=str(candidate.get("status", "pending")),
            notes=str(candidate.get("notes", "")),
            preserve_existing_status=True,
            refresh_service_status=deferred_service_refreshes is None,
        )
        if deferred_service_refreshes is not None and coverage_item["service_id"] is not None:
            deferred_service_refreshes.add(int(coverage_item["service_id"]))
        coverage_items.append(coverage_item)
    return {
        "target": target,
        "service": service,
        "request_variant": request_variant,
        "request_observation": observation,
        "coverage_items": coverage_items,
    }


def ingest_request_observation(
    engagement_id: int,
    *,
    url: str,
    method: str,
    auth_context: str,
    content_type_family: str,
    query_schema: dict[str, Any],
    body_schema: dict[str, Any],
    path_schema: dict[str, Any],
    cookie_schema: dict[str, Any],
    header_schema: dict[str, Any],
    path_template: str,
    discovery_source: str,
    notes: str,
    response_status: int | None,
    evidence_ref: str,
    observation_payload: dict[str, Any],
    target_identity: str | None,
    target_kind: str,
    target_notes: str,
    target_ip_address: str | None,
    target_hostname: str | None,
    banner: str,
    coverage_candidates: list[dict[str, Any]] | None,
    auto_generate_coverage: bool,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _ingest_request_observation(
            connection,
            engagement.id,
            url=url,
            method=method,
            auth_context=auth_context,
            content_type_family=content_type_family,
            query_schema=query_schema,
            body_schema=body_schema,
            path_schema=path_schema,
            cookie_schema=cookie_schema,
            header_schema=header_schema,
            path_template=path_template,
            discovery_source=discovery_source,
            notes=notes,
            response_status=response_status,
            evidence_ref=evidence_ref,
            observation_payload=observation_payload,
            target_identity=target_identity,
            target_kind=target_kind,
            target_notes=target_notes,
            target_ip_address=target_ip_address,
            target_hostname=target_hostname,
            banner=banner,
            coverage_candidates=coverage_candidates,
            auto_generate_coverage=auto_generate_coverage,
        )


def ingest_request_observations_bulk(
    engagement_id: int,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    records: list[dict[str, Any]] = []
    deferred_service_refreshes: set[int] = set()
    with _common.get_connection() as connection:
        for item in items:
            records.append(
                _ingest_request_observation(
                    connection,
                    engagement.id,
                    deferred_service_refreshes=deferred_service_refreshes,
                    **item,
                )
            )
        for service_id in sorted(deferred_service_refreshes):
            _refresh_service_coverage_status(connection, engagement.id, service_id)
    return {"engagement_id": engagement.id, "count": len(records), "records": records}

def record_coverage_item(
    engagement_id: int,
    *,
    request_variant_id: int | None,
    service_id: int | None,
    auth_context: str,
    input_slot: str,
    attack_family: str,
    status_value: str,
    notes: str,
    preserve_existing_status: bool = True,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _upsert_coverage_item(
            connection,
            engagement.id,
            request_variant_id=request_variant_id,
            service_id=service_id,
            auth_context=auth_context,
            input_slot=input_slot,
            attack_family=attack_family,
            status_value=status_value,
            notes=notes,
            preserve_existing_status=preserve_existing_status,
        )

def record_coverage_items_bulk(
    engagement_id: int,
    items: list[dict[str, Any]],
    *,
    preserve_existing_status: bool = True,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    records: list[dict[str, Any]] = []
    deferred_service_refreshes: set[int] = set()
    with _common.get_connection() as connection:
        for item in items:
            record = _upsert_coverage_item(
                connection,
                engagement.id,
                request_variant_id=item.get("request_variant_id"),
                service_id=item.get("service_id"),
                auth_context=str(item.get("auth_context", "anonymous")),
                input_slot=str(item.get("input_slot", "endpoint")),
                attack_family=str(item["attack_family"]),
                status_value=str(item.get("status_value", "pending")),
                notes=str(item.get("notes", "")),
                preserve_existing_status=preserve_existing_status,
                refresh_service_status=False,
            )
            if record["service_id"] is not None:
                deferred_service_refreshes.add(int(record["service_id"]))
            records.append(record)
        for service_id in sorted(deferred_service_refreshes):
            _refresh_service_coverage_status(connection, engagement.id, service_id)
    return {"engagement_id": engagement.id, "count": len(records), "records": records}

def list_coverage_items(
    engagement_id: int,
    *,
    limit: int = DEFAULT_COVERAGE_ITEM_LIMIT,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    limit, offset = _bounded_assessment_list_window(limit, offset)
    with _common.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                coverage.*,
                request_variants.method,
                request_variants.canonical_url,
                request_variants.normalized_path,
                request_variants.host,
                services.endpoint AS service_endpoint,
                services.service AS service_name
            FROM assessment_coverage_items AS coverage
            LEFT JOIN assessment_request_variants AS request_variants ON request_variants.id = coverage.request_variant_id
            LEFT JOIN assessment_services AS services ON services.id = coverage.service_id
            WHERE coverage.engagement_id = ?
            ORDER BY coverage.updated_at DESC, coverage.id DESC
            LIMIT ? OFFSET ?
            """,
            (engagement.id, limit, offset),
        ).fetchall()
    return [dict(row) for row in rows]

def record_probe_run(
    engagement_id: int,
    *,
    request_variant_id: int | None,
    service_id: int | None,
    coverage_item_id: int | None,
    auth_context: str,
    input_slot: str,
    attack_family: str,
    payload_family: str,
    payload_value: str,
    tool_name: str,
    agent_name: str,
    result_status: str,
    observed_http_status: int | None,
    signal_type: str,
    evidence_ref: str,
    notes: str,
    target_host: str = "",
    target_path: str = "",
    target_port: int | None = None,
    lens: str = "",
    finding_id: int | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _upsert_probe_run(
            connection,
            engagement.id,
            request_variant_id=request_variant_id,
            service_id=service_id,
            coverage_item_id=coverage_item_id,
            auth_context=auth_context,
            input_slot=input_slot,
            attack_family=attack_family,
            payload_family=payload_family,
            payload_value=payload_value,
            tool_name=tool_name,
            agent_name=agent_name,
            result_status=result_status,
            observed_http_status=observed_http_status,
            signal_type=signal_type,
            evidence_ref=evidence_ref,
            notes=notes,
            target_host=target_host,
            target_path=target_path,
            target_port=target_port,
            lens=lens,
            finding_id=finding_id,
        )

def list_probe_runs(
    engagement_id: int,
    *,
    limit: int = DEFAULT_PROBE_RUN_LIMIT,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    limit, offset = _bounded_probe_run_window(limit, offset)
    with _common.get_connection() as connection:
        return _fetch_all(
            connection,
            """
            SELECT *
            FROM assessment_probe_runs
            WHERE engagement_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (engagement.id, limit, offset),
        )

def record_surface(
    engagement_id: int,
    *,
    surface_type: str,
    target_descriptor: str,
    source_name: str,
    rationale: str,
    evidence_ref: str,
    status_value: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _upsert_surface(
            connection,
            engagement.id,
            surface_type=surface_type,
            target_descriptor=target_descriptor,
            source_name=source_name,
            rationale=rationale,
            evidence_ref=evidence_ref,
            status_value=status_value,
        )

def list_surfaces(
    engagement_id: int,
    *,
    limit: int | None = DEFAULT_SURFACE_LIMIT,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        if limit is None:
            return _fetch_all(
                connection,
                """
                SELECT *
                FROM assessment_surfaces
                WHERE engagement_id = ?
                ORDER BY updated_at DESC, id DESC
                """,
                (engagement.id,),
            )
        limit, offset = _bounded_assessment_list_window(limit, offset)
        return _fetch_all(
            connection,
            """
            SELECT *
            FROM assessment_surfaces
            WHERE engagement_id = ?
            ORDER BY updated_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (engagement.id, limit, offset),
        )

def update_surface(
    engagement_id: int,
    surface_id: int,
    *,
    status_value: str | None = None,
    rationale: str | None = None,
    source_name: str | None = None,
    evidence_ref: str | None = None,
    followup_condition: str | None = None,
) -> dict[str, Any]:
    """Patch an assessment_surfaces row by id.

    Operators reach this through ``vigil assess resolve-surface`` to mark
    discovered surfaces ``covered``, ``not_applicable``, ``deferred``, or
    ``partially-covered``. Unspecified fields stay untouched, but at least
    one mutable field must be supplied so the call records something
    durable. ``rationale`` is appended (mirrors the upsert behavior of
    ``_upsert_surface``) so the audit trail accumulates context.
    """
    engagement = _engagement_or_404(engagement_id)
    valid_statuses = {"covered", "not_applicable", "deferred", "discovered", "partially-covered"}
    if status_value is not None and status_value not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid surface status '{status_value}'; allowed: {sorted(valid_statuses)}",
        )
    # Empty strings for source_name / evidence_ref are not a valid clear
    # signal: callers must pass null to leave the field untouched, or a
    # real value to set it. The frontend and CLI strip empties before they
    # reach this layer, so an empty here is a deliberate (but malformed)
    # call.
    if source_name is not None and source_name == "":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="source_name cannot be empty; use null to leave unchanged",
        )
    if evidence_ref is not None and evidence_ref == "":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="evidence_ref cannot be empty; use null to leave unchanged",
        )
    if all(
        value is None
        for value in (status_value, rationale, source_name, evidence_ref, followup_condition)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="update-surface requires at least one of status, rationale, source_name, evidence_ref, followup_condition",
        )

    with _common.get_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM assessment_surfaces WHERE engagement_id = ? AND id = ?",
            (engagement.id, surface_id),
        ).fetchone()
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"surface id={surface_id} not found",
            )

        current_status = str(existing["status"] or "")
        # Lifecycle guard: regressions to ``discovered`` from a decided
        # state (covered / not_applicable) erase audit context. Operators
        # should mark the surface ``deferred`` to re-queue it instead. The
        # same applies to ``partially-covered`` → ``discovered`` (audit
        # context loss).
        if (
            status_value is not None
            and status_value == "discovered"
            and current_status in {"covered", "not_applicable", "partially-covered"}
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"cannot regress surface from '{current_status}' to "
                    "'discovered'; use 'deferred' to re-queue"
                ),
            )

        # When the operator changes status, rationale is mandatory: the
        # audit trail must capture the WHY of every transition.
        if (
            status_value is not None
            and status_value != current_status
            and not (rationale and rationale.strip())
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="rationale required when changing surface status",
            )

        # ``partially-covered`` requires ``followup_condition`` so the
        # audit trail names what the next coverage pass must satisfy.
        if status_value == "partially-covered":
            if not (followup_condition and followup_condition.strip()):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "followup_condition required when status='partially-covered'"
                    ),
                )

        assignments: list[str] = []
        params: list[Any] = []
        if status_value is not None:
            assignments.append("status = ?")
            params.append(status_value)
            # Transitioning OUT of partially-covered into ``covered`` clears
            # the followup_condition because the follow-up has completed.
            if (
                current_status == "partially-covered"
                and status_value == "covered"
                and followup_condition is None
            ):
                assignments.append("followup_condition = ?")
                params.append("")
        if rationale is not None:
            existing_rationale = str(existing["rationale"] or "")
            new_rationale = rationale
            if (
                existing_rationale
                and rationale
                and rationale not in existing_rationale
            ):
                new_rationale = existing_rationale + "\n" + rationale
            elif rationale == "" or rationale in existing_rationale:
                new_rationale = existing_rationale
            assignments.append("rationale = ?")
            params.append(new_rationale)
        if source_name is not None:
            assignments.append("source_name = ?")
            params.append(source_name)
        if evidence_ref is not None:
            assignments.append("evidence_ref = ?")
            params.append(evidence_ref)
        if followup_condition is not None:
            assignments.append("followup_condition = ?")
            params.append(followup_condition)

        if not assignments:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="update-surface produced no effective changes",
            )

        assignments.append("updated_at = CURRENT_TIMESTAMP")
        params.extend([engagement.id, surface_id])
        connection.execute(
            f"UPDATE assessment_surfaces SET {', '.join(assignments)} "
            f"WHERE engagement_id = ? AND id = ?",
            tuple(params),
        )
        row = connection.execute(
            "SELECT * FROM assessment_surfaces WHERE engagement_id = ? AND id = ?",
            (engagement.id, surface_id),
        ).fetchone()
        assert row is not None
        return dict(row)

def _upsert_surface_request_variant_link(
    connection,
    engagement_id: int,
    *,
    surface_id: int,
    request_variant_id: int,
    relation: str,
    evidence_ref: str,
) -> dict[str, Any]:
    connection.execute(
        """
        INSERT INTO surface_request_variant_links (engagement_id, surface_id, request_variant_id, relation, evidence_ref)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(surface_id, request_variant_id, relation) DO UPDATE SET
            evidence_ref = COALESCE(NULLIF(excluded.evidence_ref, ''), surface_request_variant_links.evidence_ref),
            updated_at = CURRENT_TIMESTAMP
        """,
        (engagement_id, surface_id, request_variant_id, relation, evidence_ref),
    )
    row = connection.execute(
        """
        SELECT *
        FROM surface_request_variant_links
        WHERE surface_id = ? AND request_variant_id = ? AND relation = ?
        """,
        (surface_id, request_variant_id, relation),
    ).fetchone()
    assert row is not None
    return dict(row)

def create_surface_request_variant_link(
    engagement_id: int,
    *,
    surface_id: int,
    request_variant_id: int,
    relation: str = "",
    evidence_ref: str = "",
) -> dict[str, Any]:
    """Link a surface to a request variant by their durable backend ids.

    ``request_variant_id`` is the cross-system join key (handed back on a
    request-observation POST); a local cases.db work_item id would be
    meaningless here. Both ends are validated against the engagement so a
    typo'd id is a 404 rather than a dangling row.
    """
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        surface = connection.execute(
            "SELECT id FROM assessment_surfaces WHERE engagement_id = ? AND id = ?",
            (engagement.id, surface_id),
        ).fetchone()
        if surface is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"surface id={surface_id} not found",
            )
        variant = connection.execute(
            "SELECT id FROM assessment_request_variants WHERE engagement_id = ? AND id = ?",
            (engagement.id, request_variant_id),
        ).fetchone()
        if variant is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"request_variant id={request_variant_id} not found",
            )
        return _upsert_surface_request_variant_link(
            connection,
            engagement.id,
            surface_id=surface_id,
            request_variant_id=request_variant_id,
            relation=relation,
            evidence_ref=evidence_ref,
        )

def list_surface_request_variant_links_by_surface(
    engagement_id: int,
    surface_id: int,
    *,
    limit: int = DEFAULT_SURFACE_LIMIT,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    limit, offset = _bounded_assessment_list_window(limit, offset)
    with _common.get_connection() as connection:
        return _fetch_all(
            connection,
            """
            SELECT *
            FROM surface_request_variant_links
            WHERE engagement_id = ? AND surface_id = ?
            ORDER BY updated_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (engagement.id, surface_id, limit, offset),
        )

def list_surface_request_variant_links_by_variant(
    engagement_id: int,
    request_variant_id: int,
    *,
    limit: int = DEFAULT_SURFACE_LIMIT,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    limit, offset = _bounded_assessment_list_window(limit, offset)
    with _common.get_connection() as connection:
        return _fetch_all(
            connection,
            """
            SELECT *
            FROM surface_request_variant_links
            WHERE engagement_id = ? AND request_variant_id = ?
            ORDER BY updated_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (engagement.id, request_variant_id, limit, offset),
        )

HIGH_RISK_DEFERRED_SURFACE_TYPES: frozenset[str] = frozenset(
    {"account_recovery", "dynamic_render", "object_reference", "privileged_write"}
)


def _active_finding_hosts(engagement_id: int) -> set[str]:
    """Hosts that carry at least one ACTIVE (reportable, non-draft) finding.

    Surfaces have no FK to findings (depth-gate S16), so "this surface is
    linked to an active finding" is resolved by matching the surface's host to
    a reportable finding's ``canonical_location`` host. Draft / false-positive /
    merged findings are excluded — only a finding the engagement is actually
    standing behind makes its surface a real (non-advisory) blocker (L1-2).
    """
    reportable_statuses = (
        "active",
        "blocked",
        "exploited",
        "contained",
        "eradicated",
        "recovered",
        "reported",
    )
    engagement = _engagement_or_404(engagement_id)
    placeholders = ", ".join("?" for _ in reportable_statuses)
    with _common.get_connection() as connection:
        rows = connection.execute(
            f"SELECT canonical_location FROM assessment_findings "
            f"WHERE engagement_id = ? AND status IN ({placeholders})",
            (engagement.id, *reportable_statuses),
        ).fetchall()
    hosts: set[str] = set()
    for row in rows:
        host = _coverage_endpoint_host(str(row["canonical_location"] or ""))
        if host:
            hosts.add(host)
    return hosts


def _surface_is_finding_linked(surface: dict[str, Any], active_hosts: set[str]) -> bool:
    host = _coverage_endpoint_host(str(surface.get("target_descriptor") or ""))
    return bool(host) and host in active_hosts


def _deferral_exempt_surface_types(engagement_id: int) -> set[str]:
    """Surface types an operator has exempted from the high-risk deferral block
    via a recorded engagement-wide policy decision (L1-10).

    The policy is a durable ``surface_deferral_exemption`` decision row whose
    payload lists ``surface_types`` (or ``surface_type``). This is the bounded,
    visible escape valve the doctrine requires — an exemption is an audited
    decision, not a transient ``--force`` flag.
    """
    engagement = _engagement_or_404(engagement_id)
    exempt: set[str] = set()
    with _common.get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions "
            "WHERE engagement_id = ? AND kind = ? AND resolved = 0",
            (engagement.id, "surface_deferral_exemption"),
        ).fetchall()
    for row in rows:
        payload = _serialize_decision(row).get("payload") or {}
        if not isinstance(payload, dict):
            continue
        names = payload.get("surface_types")
        if isinstance(names, str):
            names = [names]
        if not isinstance(names, list):
            single = payload.get("surface_type")
            names = [single] if isinstance(single, str) else []
        for name in names:
            if isinstance(name, str) and name.strip():
                exempt.add(name.strip())
    return exempt


def _partial_followup_resolved(surface: dict[str, Any]) -> bool:
    """True when a ``partially-covered`` surface's follow-up is satisfied so it
    should stop blocking (L1-9 accept-partial path).

    Resolution is recorded durably on the surface itself: clearing the
    ``followup_condition`` (the follow-up was met — mirrors the existing
    "covered clears followup_condition" transition in ``update_surface``) marks
    the partial as accepted. An empty ``followup_condition`` on a
    partially-covered surface therefore means "the follow-up obligation is
    resolved" and the surface no longer blocks; a still-present condition keeps
    it as an advisory item.
    """
    return not str(surface.get("followup_condition") or "").strip()


def coverage_readiness(engagement_id: int) -> dict[str, Any]:
    """Surface-coverage readiness for the web/code/blue tracks.

    NOTE (cross-track invariant): this function is shared and NOT
    engagement_type-gated. The CODE track has no surfaces, so ``list_surfaces``
    returns ``[]`` and every bucket below is empty → ``ready=True`` trivially.
    The return SHAPE is load-bearing (``report_readiness`` relays ``ready`` /
    ``blocker_count`` and the surface buckets); keys are preserved. Wave-2
    softening (L1-2/L1-9/L1-10) only changes WHICH surfaces count toward
    ``blocker_count`` and adds advisory buckets — it never changes the shape.
    """
    surfaces = list_surfaces(engagement_id, limit=None)

    if not surfaces:
        return {
            "ready": True,
            "blocker_count": 0,
            "unresolved_surfaces": [],
            "partially_covered_surfaces": [],
            "high_risk_deferred_surfaces": [],
            "advisory_surfaces": [],
        }

    active_hosts = _active_finding_hosts(engagement_id)
    exempt_types = _deferral_exempt_surface_types(engagement_id)

    discovered = [row for row in surfaces if row.get("status") == "discovered"]
    partial = [row for row in surfaces if row.get("status") == "partially-covered"]
    deferred_high_risk = [
        row
        for row in surfaces
        if row.get("status") == "deferred"
        and row.get("surface_type") in HIGH_RISK_DEFERRED_SURFACE_TYPES
    ]

    unresolved_blocking = [
        row for row in discovered if _surface_is_finding_linked(row, active_hosts)
    ]
    unresolved_advisory = [
        row for row in discovered if not _surface_is_finding_linked(row, active_hosts)
    ]

    partial_blocking: list[dict[str, Any]] = []
    partial_advisory: list[dict[str, Any]] = []
    for row in partial:
        if _partial_followup_resolved(row):
            partial_advisory.append(row)
        elif _surface_is_finding_linked(row, active_hosts):
            partial_blocking.append(row)
        else:
            partial_advisory.append(row)

    deferred_blocking = [
        row
        for row in deferred_high_risk
        if row.get("surface_type") not in exempt_types
    ]
    deferred_advisory = [
        row
        for row in deferred_high_risk
        if row.get("surface_type") in exempt_types
    ]

    blocker_count = (
        len(unresolved_blocking) + len(partial_blocking) + len(deferred_blocking)
    )
    advisory_surfaces = (
        unresolved_advisory + partial_advisory + deferred_advisory
    )

    return {
        "ready": blocker_count == 0,
        "blocker_count": blocker_count,
        "unresolved_surfaces": unresolved_blocking,
        "partially_covered_surfaces": partial_blocking,
        "high_risk_deferred_surfaces": deferred_blocking,
        "advisory_surfaces": advisory_surfaces,
    }

# C40 — outcome-based per-host coverage projection
# The five sub-objectives the recon phase nominally produces per host. None of
# them check `assessment_command_runs` — every signal is a row in an outcome
# table the specialists are already writing to. That is the contract: rename
# wafw00f → wafw00f-ng tomorrow and the gate keeps working as long as the
# tech-component row still gets recorded.


PER_HOST_OBJECTIVES: tuple[str, ...] = (
    "waf_tier",
    "service_inventory",
    "directory_fuzz",
    "tech_fingerprint",
    "osint",
)

# WAF families operators classify hosts into. Matched case-insensitively as a
# substring of the `component` field on `intel_tech_components`. Extending this
# tuple (e.g., new CDN entrant) is the canonical drift-prone seam — keep it
# small and additive.
_WAF_FAMILY_TOKENS: tuple[str, ...] = (
    "cloudflare",
    "akamai",
    "f5",
    "aws waf",
    "awswaf",
    "imperva",
    "fastly",
    "incapsula",
    "sucuri",
    "cloudfront",
    "azure front door",
    "barracuda",
)

# Tokens that suggest a tech-component row came from a "nikto-equivalent"
# scanner (whatweb, httpx -tech-detect, wappalyzer, nuclei tech templates,
# nmap http-* scripts, nikto itself). We do NOT hardcode tool names in the
# CLI side of the gate — this list is the BACKEND'S read-only interpretation
# of "scanner that produced a tech fingerprint". Operators recording intel
# manually still satisfy the gate because they set `source_name` to their
# agent identity.
_TECH_SCAN_SOURCE_TOKENS: tuple[str, ...] = (
    "whatweb",
    "httpx",
    "wappalyzer",
    "nuclei",
    "nikto",
    "nmap",
    "recon-specialist",
    "wafw00f",
    "wafw0of",
    "source-analyzer",
    "operator",
)

_NON_LIVE_SERVICE_STATES_FOR_INVENTORY: frozenset[str] = frozenset(
    {"down", "filtered", "unreachable"}
)

def _coverage_endpoint_host(endpoint: str) -> str:
    """Lowercased host portion of a service endpoint or surface descriptor.

    Mirrors `_endpoint_host` in `lib/coverage_checks.py` but the CLI version
    cannot be imported here. Keep the two in sync — they extract the same
    host string from the same shapes (bare host, host:port, full URL).
    """
    raw = (endpoint or "").strip().lower()
    if not raw:
        return ""
    first = raw.split()[0]
    if "://" in first:
        parsed = urlparse(first)
        return (parsed.hostname or "").strip("[]")
    # Strip leading/trailing wrappers and trailing punctuation.
    stripped = first.strip("'\"<>()").rstrip(",;").rstrip(".")
    if stripped.startswith("[") and "]" in stripped:
        # Bracketed IPv6 with optional :port suffix.
        host = stripped[1 : stripped.find("]")]
        return host
    if stripped.count(":") >= 2:
        # IPv6 literal without brackets (e.g., 2001:db8::1 or 2001:db8::1:443).
        # Splitting on rpartition risks chopping the address; only strip a
        # trailing port if the suffix is purely numeric AND the prefix parses
        # as an IPv6 address.
        host, _, port = stripped.rpartition(":")
        if port.isdigit():
            try:
                import ipaddress

                ipaddress.ip_address(host)
                return host
            except ValueError:
                return stripped
        return stripped
    host, _, port = stripped.rpartition(":")
    if port.isdigit() and host:
        return host
    return stripped

def _string_contains_host(haystack: str, host: str) -> bool:
    """True when `host` appears as a token in `haystack` (case-insensitive).

    Avoids substring false positives like "evil.target.example" matching
    "target.example" — we require the match to be on a word boundary so
    `notes='banner=cf-cf'` does not falsely satisfy `host='cf'`.
    """
    if not haystack or not host:
        return False
    lower_hay = haystack.lower()
    lower_host = host.lower()
    if lower_host not in lower_hay:
        return False
    idx = 0
    while True:
        pos = lower_hay.find(lower_host, idx)
        if pos == -1:
            return False
        left_ok = pos == 0 or not (lower_hay[pos - 1].isalnum() or lower_hay[pos - 1] in ".-")
        end = pos + len(lower_host)
        right_ok = end == len(lower_hay) or not (
            lower_hay[end].isalnum() or lower_hay[end] in ".-"
        )
        if left_ok and right_ok:
            return True
        idx = pos + 1

def _intel_row_references_host(row: dict[str, Any], host: str) -> bool:
    """True when an intel row's evidence/notes/provenance mentions the host."""
    if not host:
        return False
    for key in ("evidence_ref", "notes", "source_name"):
        if _string_contains_host(str(row.get(key, "") or ""), host):
            return True
    raw_provenance = row.get("provenance_json", row.get("provenance"))
    provenance: Any = raw_provenance
    if isinstance(raw_provenance, str) and raw_provenance:
        try:
            provenance = json.loads(raw_provenance)
        except (ValueError, TypeError):
            return _string_contains_host(raw_provenance, host)
    if isinstance(provenance, dict):
        for k in ("host", "target", "url", "endpoint"):
            val = provenance.get(k)
            if isinstance(val, str) and _string_contains_host(val, host):
                return True
        return _string_contains_host(json.dumps(provenance, ensure_ascii=False), host)
    return False

def _row_is_waf_classification(row: dict[str, Any]) -> bool:
    component = str(row.get("component", "") or "").lower()
    if not component:
        return False
    for token in _WAF_FAMILY_TOKENS:
        if token in component:
            return True
    return False

def _row_is_tech_scan_evidence(row: dict[str, Any]) -> bool:
    """True when a tech-component row plausibly came from a 'nikto-equivalent'
    scanner — i.e., any active fingerprinting tool or operator recording."""
    source = str(row.get("source_name", "") or "").lower()
    if not source:
        # An empty source_name is still a tech-component row that records a
        # real classification — count it as satisfying the trigger.
        return True
    for token in _TECH_SCAN_SOURCE_TOKENS:
        if token in source:
            return True
    return False

def _coverage_deferral_payload_hosts(payload: dict[str, Any]) -> list[str]:
    """Return host strings referenced by a coverage_deferral decision payload.

    Normalizes each value through ``_coverage_endpoint_host`` so URL or
    host:port shapes (``https://api.example.com/v1``, ``api.example.com:8443``)
    collapse to the same bare-hostname key used by ``services_by_host`` /
    ``surfaces_by_host``. Without this, an operator-recorded deferral with a
    URL value silently fails to match and the gate stays unmet.
    """
    candidates: list[str] = []
    for key in ("host", "target", "hostname"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            normalized = _coverage_endpoint_host(val) or val.strip().lower()
            candidates.append(normalized)
    hosts_field = payload.get("hosts")
    if isinstance(hosts_field, list):
        for entry in hosts_field:
            if isinstance(entry, str) and entry.strip():
                normalized = _coverage_endpoint_host(entry) or entry.strip().lower()
                candidates.append(normalized)
    return candidates

def _coverage_deferral_objectives(payload: dict[str, Any]) -> list[str]:
    raw = payload.get("deferred_objectives")
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    return out

def _active_coverage_deferrals(engagement_id: int) -> list[dict[str, Any]]:
    """Return every active (``resolved=0``) coverage_deferral decision row
    for the engagement, ordered newest-first.

    Reads directly through ``get_connection`` to avoid the public
    ``list_decisions`` endpoint's ``limit`` cap — large wildcard engagements
    can legitimately accumulate thousands of operator-approved deferrals,
    and a silent truncation would let objectives reappear as unmet in the
    per-host gate.
    """
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        cursor = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions "
            "WHERE engagement_id = ? AND kind = ? AND resolved = 0 "
            "ORDER BY created_at DESC, id DESC",
            (engagement.id, "coverage_deferral"),
        )
        return [_serialize_decision(row) for row in cursor.fetchall()]

def _active_coverage_completeness_deferrals(engagement_id: int) -> list[dict[str, Any]]:
    """Active (``resolved=0``) ``coverage_completeness_deferral`` decision rows,
    newest-first.

    W3 override reader — mirrors :func:`_active_coverage_deferrals` (same direct
    ``get_connection`` read to dodge the ``list_decisions`` ``limit`` cap) but
    for the report-time completeness escape. The decision is recorded free-form
    via ``vigil assess agent decision --kind coverage_completeness_deferral``;
    its payload is ``{host, reason}`` (or aliases ``hosts``/``target``/
    ``hostname``) for a per-host carve-out, or ``{engagement_wide: true}`` to
    accept residual uncovered hosts program-wide at the report boundary.
    """
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        cursor = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions "
            "WHERE engagement_id = ? AND kind = ? AND resolved = 0 "
            "ORDER BY created_at DESC, id DESC",
            (engagement.id, "coverage_completeness_deferral"),
        )
        return [_serialize_decision(row) for row in cursor.fetchall()]

def _completeness_deferral_index(
    rows: list[dict[str, Any]],
) -> tuple[set[str], bool]:
    """Split completeness-deferral rows into ``(deferred_hosts, engagement_wide)``.

    A row tagged ``engagement_wide=true`` clears EVERY uncovered host; otherwise
    the payload's host fields (normalized through ``_coverage_deferral_payload_hosts``
    so URL / host:port shapes collapse to the bare-host key) name the hosts it
    clears.
    """
    deferred_hosts: set[str] = set()
    engagement_wide = False
    for row in rows:
        payload = row.get("payload") or {}
        if not isinstance(payload, dict):
            continue
        if payload.get("engagement_wide") is True:
            engagement_wide = True
            continue
        for host in _coverage_deferral_payload_hosts(payload):
            deferred_hosts.add(host)
    return deferred_hosts, engagement_wide

def _coverage_engagement_wide_deferrals(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return active deferral rows tagged ``engagement_wide=true``.

    These apply to EVERY host with signal — operators use them for objectives
    that are not host-scoped (e.g., "OSINT is out of scope for this whole
    engagement"). Validated at POST time to be mutually exclusive with host
    fields, so a row is either engagement-wide or per-host but not both.
    """
    out: list[dict[str, Any]] = []
    for row in rows:
        payload = row.get("payload") or {}
        if isinstance(payload, dict) and payload.get("engagement_wide") is True:
            out.append(row)
    return out

def _empty_finding_verdict() -> dict[str, Any]:
    """The "no verdict on this host" cell. Stable shape so the CLI ledger never
    has to special-case a missing key."""
    return {
        "has_finding": False,
        "finding_count": 0,
        "verified_count": 0,
        "strongest_status": None,
        "max_severity": None,
        "auth_contexts": [],
        "verification_states": [],
        "slugs": [],
    }


def _build_finding_verdicts_by_host(
    finding_rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Project finding rows into ``{host: verdict}``.

    A ``merged`` finding (or one with a ``merged_into_finding_id``) is excluded —
    it is no longer the canonical record. Every other finding counts as a
    RECORDED VERDICT for its host (a ``false_positive`` finding is the canonical
    evidence-backed negative: "we tested it, here is why it is not a bug").
    Host is taken from ``canonical_location`` via the same normalizer used for
    services/surfaces so the ledger join lands on one key. The ``slugs`` list is
    capped to keep the payload bounded on noisy hosts.
    """
    by_host: dict[str, dict[str, Any]] = {}
    for row in finding_rows:
        if row.get("merged_into_finding_id") is not None:
            continue
        try:
            status_value = _normalize_workflow_status(str(row.get("status") or "draft"))
        except HTTPException:
            status_value = "draft"  # tolerate a legacy/invalid status on read
        if status_value == "merged":
            continue
        host = _coverage_endpoint_host(str(row.get("canonical_location") or ""))
        if not host:
            continue
        verdict = by_host.setdefault(host, _empty_finding_verdict())
        verdict["has_finding"] = True
        verdict["finding_count"] += 1

        try:
            verification_state = str(
                _normalize_verification_state(str(row.get("verification_state") or "unreviewed"))
            )
        except HTTPException:
            verification_state = "unreviewed"
        if verification_state == "verified":
            verdict["verified_count"] += 1
        if verification_state not in verdict["verification_states"]:
            verdict["verification_states"].append(verification_state)

        severity = _normalize_severity(str(row.get("severity") or "info"))
        if verdict["max_severity"] is None or (
            SEVERITY_RANK[severity] > SEVERITY_RANK[verdict["max_severity"]]
        ):
            verdict["max_severity"] = severity

        current_strongest = verdict["strongest_status"]
        if current_strongest is None or (
            WORKFLOW_STATUS_RANK[status_value] > WORKFLOW_STATUS_RANK[current_strongest]
        ):
            verdict["strongest_status"] = str(status_value)

        auth_context = str(row.get("auth_context") or "").strip()
        if auth_context and auth_context not in verdict["auth_contexts"]:
            verdict["auth_contexts"].append(auth_context)

        slug = str(row.get("slug") or "").strip()
        if slug and len(verdict["slugs"]) < 25 and slug not in verdict["slugs"]:
            verdict["slugs"].append(slug)

    for verdict in by_host.values():
        verdict["auth_contexts"].sort()
        verdict["verification_states"].sort()
        verdict["slugs"].sort()
    return by_host


def per_host_finding_verdicts(engagement_id: int) -> dict[str, dict[str, Any]]:
    """Standalone per-host finding-VERDICT projection (sibling of
    :func:`per_host_coverage`).

    Exposed for callers that only need the verdict join (and for direct test
    coverage). ``per_host_coverage`` reuses the same builder so the inline
    ``finding_verdict`` and this map never drift.
    """
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        finding_rows = _fetch_all(
            connection,
            "SELECT slug, canonical_location, status, verification_state, "
            "verification_disposition, severity, auth_context, merged_into_finding_id "
            "FROM assessment_findings WHERE engagement_id = ?",
            (engagement.id,),
        )
    return _build_finding_verdicts_by_host(finding_rows)


def per_host_coverage(engagement_id: int) -> dict[str, Any]:
    """Outcome-based per-host coverage projection (C40).

    Five sub-objectives per host, each evaluated against an outcome table:

    1. ``waf_tier`` — an ``intel_tech_components`` row whose ``component`` matches
       a known WAF family. Engagement-level WAF intel (no host evidence in
       evidence_ref/notes/provenance) counts for every host: CDN-class WAFs
       typically sit in front of an entire property, and demanding per-host
       evidence would produce false negatives that don't reflect operator
       reality.
    2. ``service_inventory`` — at least one ``assessment_services`` row in a live
       state for the host, OR at least one ``assessment_surfaces`` row.
    3. ``directory_fuzz`` — at least one ``assessment_surfaces`` row for the host.
       Specialists running ffuf / feroxbuster / dirsearch record their
       findings as surfaces (via ``record-surface``) so the gate cares about
       the surface row, not the binary that produced it.
    4. ``tech_fingerprint`` — at least one ``intel_tech_components`` row whose
       ``source_name`` plausibly came from a fingerprinting scanner (whatweb,
       httpx, wappalyzer, nuclei, nmap, nikto, recon-specialist, etc.). The
       trigger is "did fingerprinting happen", which the operator can satisfy
       with any of those tools — or by recording the row manually.
    5. ``osint`` — engagement-level. ≥1 row in any of ``intel_tech_components``,
       ``intel_people``, or ``intel_breach_records`` proves OSINT happened.
       OSINT is not naturally host-keyed (people, breach corpora, org facts
       are organization-level), so this objective is the same answer for
       every host in the engagement.

    A host with an active ``coverage_deferral`` decision row whose payload
    lists an objective passes that objective regardless of the underlying
    signal. The deferral is the operator's explicit "we decided not to do
    this for this host" record; the gate trusts it.

    NOTE: this function deliberately does NOT consult
    ``assessment_command_runs``. The whole point of the C40 reframe is that
    the gate reads outcomes, not tool runs. Adding a `command-runs` join
    here is the regression we're trying to prevent — `test_check_scope_coverage`
    asserts the CLI does not query it.
    """
    engagement = _engagement_or_404(engagement_id)
    eng_id = engagement.id

    with _common.get_connection() as connection:
        services = _fetch_all(
            connection,
            "SELECT endpoint, state FROM assessment_services WHERE engagement_id = ?",
            (eng_id,),
        )
        surfaces = _fetch_all(
            connection,
            "SELECT surface_type, target_descriptor, status FROM assessment_surfaces "
            "WHERE engagement_id = ?",
            (eng_id,),
        )
        tech_components = _fetch_all(
            connection,
            "SELECT component, version, source_name, evidence_ref, notes, "
            "provenance_json, superseded_by_id "
            "FROM intel_tech_components WHERE engagement_id = ?",
            (eng_id,),
        )
        people_count = _scalar_row(
            connection,
            "SELECT COUNT(*) FROM intel_people WHERE engagement_id = ? "
            "AND superseded_by_id IS NULL",
            (eng_id,),
        )
        breach_count = _scalar_row(
            connection,
            "SELECT COUNT(*) FROM intel_breach_records WHERE engagement_id = ? "
            "AND superseded_by_id IS NULL",
            (eng_id,),
        )
        finding_rows = _fetch_all(
            connection,
            "SELECT slug, canonical_location, status, verification_state, "
            "verification_disposition, severity, auth_context, merged_into_finding_id "
            "FROM assessment_findings WHERE engagement_id = ?",
            (eng_id,),
        )

    # W2 — per-host finding VERDICT join. A host is only "covered" with a
    # RECORDED VERDICT; this map is what the coverage ledger reads to tell a
    # real_app gap (routes but no verdict) from a closed one. Keyed by the same
    # ``_coverage_endpoint_host`` normalization as services/surfaces so the join
    # lands on one host key. Includes finding-only hosts (a host with a finding
    # but no recon service/surface) so a crown-jewel verdict is never dropped.
    finding_verdicts_by_host = _build_finding_verdicts_by_host(finding_rows)

    # Filter out superseded tech-component rows from outcome consideration —
    # the current row is the canonical answer.
    live_tech_components = [
        row for row in tech_components if row.get("superseded_by_id") is None
    ]

    # Discover every host the engagement actually has signal for.
    hosts: set[str] = set()
    services_by_host: dict[str, list[dict[str, Any]]] = {}
    surfaces_by_host: dict[str, list[dict[str, Any]]] = {}
    for row in services:
        host = _coverage_endpoint_host(str(row.get("endpoint") or ""))
        if not host:
            continue
        hosts.add(host)
        services_by_host.setdefault(host, []).append(row)
    for row in surfaces:
        host = _coverage_endpoint_host(str(row.get("target_descriptor") or ""))
        if not host:
            continue
        hosts.add(host)
        surfaces_by_host.setdefault(host, []).append(row)

    all_deferral_rows = _active_coverage_deferrals(eng_id)
    deferrals_by_host: dict[str, list[dict[str, Any]]] = {}
    for row in all_deferral_rows:
        payload = row.get("payload") or {}
        if not isinstance(payload, dict):
            continue
        if payload.get("engagement_wide") is True:
            continue  # handled below — applies to every host with signal
        row_hosts = _coverage_deferral_payload_hosts(payload)
        if not row_hosts:
            continue
        for host in row_hosts:
            deferrals_by_host.setdefault(host, []).append(row)
    for host in deferrals_by_host.keys():
        hosts.add(host)

    engagement_wide_deferral_rows = _coverage_engagement_wide_deferrals(all_deferral_rows)
    engagement_wide_deferred_objectives: set[str] = set()
    for row in engagement_wide_deferral_rows:
        for obj in _coverage_deferral_objectives(row.get("payload") or {}):
            engagement_wide_deferred_objectives.add(obj)

    # Engagement-level signals (apply to every host).
    osint_met = (
        len(live_tech_components) > 0 or people_count > 0 or breach_count > 0
    )
    osint_evidence: list[str] = []
    if live_tech_components:
        osint_evidence.append(f"tech_components:{len(live_tech_components)}")
    if people_count:
        osint_evidence.append(f"people:{int(people_count)}")
    if breach_count:
        osint_evidence.append(f"breach_records:{int(breach_count)}")

    waf_rows = [row for row in live_tech_components if _row_is_waf_classification(row)]
    engagement_has_waf_intel = bool(waf_rows)

    tech_fingerprint_rows = [row for row in live_tech_components if _row_is_tech_scan_evidence(row)]
    engagement_has_tech_fingerprint = bool(tech_fingerprint_rows)

    host_outcomes: list[dict[str, Any]] = []
    for host in sorted(hosts):
        host_services = services_by_host.get(host, [])
        host_surfaces = surfaces_by_host.get(host, [])

        # waf_tier — engagement-level WAF intel is sufficient; per-host
        # specificity is a tighter signal when the evidence_ref/notes
        # mention the host.
        waf_host_specific = any(_intel_row_references_host(row, host) for row in waf_rows)
        waf_met = waf_host_specific or engagement_has_waf_intel
        waf_evidence: list[str] = []
        for row in waf_rows:
            label = str(row.get("component") or "").strip()
            if not label:
                continue
            host_specific = _intel_row_references_host(row, host)
            waf_evidence.append(f"{label}{'(host)' if host_specific else ''}")

        # service_inventory — live service or surface row for the host
        live_services = [
            row
            for row in host_services
            if str(row.get("state") or "").lower() not in _NON_LIVE_SERVICE_STATES_FOR_INVENTORY
        ]
        service_met = bool(live_services) or bool(host_surfaces)
        service_evidence: list[str] = []
        if live_services:
            service_evidence.append(f"services:{len(live_services)}")
        if host_surfaces:
            service_evidence.append(f"surfaces:{len(host_surfaces)}")

        # directory_fuzz — surface presence proves URL-level discovery.
        # Backend cannot see the local cases.db `work_items` count, so the
        # CLI layer (`--by-host`) may upgrade this outcome based on the
        # local work-buffer rollup. From the backend's perspective a
        # surface is the durable proof.
        dirfuzz_met = bool(host_surfaces)
        dirfuzz_evidence: list[str] = []
        if host_surfaces:
            dirfuzz_evidence.append(f"surfaces:{len(host_surfaces)}")

        # tech_fingerprint — any fingerprinting-equivalent intel row, host-specific
        # preferred but engagement-level acceptable.
        tech_fingerprint_host_specific = any(
            _intel_row_references_host(row, host) for row in tech_fingerprint_rows
        )
        tech_fingerprint_met = tech_fingerprint_host_specific or engagement_has_tech_fingerprint
        tech_fingerprint_evidence: list[str] = []
        for row in tech_fingerprint_rows:
            label = str(row.get("source_name") or "").strip() or "unknown"
            host_specific = _intel_row_references_host(row, host)
            tech_fingerprint_evidence.append(f"{label}{'(host)' if host_specific else ''}")
            if len(tech_fingerprint_evidence) >= 5:
                break

        deferral_rows = deferrals_by_host.get(host, [])
        deferred_objectives: set[str] = set(engagement_wide_deferred_objectives)
        for row in deferral_rows:
            for obj in _coverage_deferral_objectives(row.get("payload") or {}):
                deferred_objectives.add(obj)
        # Surface engagement-wide rows in the per-host audit list too so
        # operators can see WHY an objective is marked deferred for this host.
        deferral_rows = deferral_rows + engagement_wide_deferral_rows

        outcomes: dict[str, dict[str, Any]] = {
            "waf_tier": {
                "met": waf_met,
                "evidence": waf_evidence,
                "deferred": "waf_tier" in deferred_objectives,
            },
            "service_inventory": {
                "met": service_met,
                "evidence": service_evidence,
                "deferred": "service_inventory" in deferred_objectives,
            },
            "directory_fuzz": {
                "met": dirfuzz_met,
                "evidence": dirfuzz_evidence,
                "deferred": "directory_fuzz" in deferred_objectives,
            },
            "tech_fingerprint": {
                "met": tech_fingerprint_met,
                "evidence": tech_fingerprint_evidence,
                "deferred": "tech_fingerprint" in deferred_objectives,
            },
            "osint": {
                "met": osint_met,
                "evidence": osint_evidence,
                "deferred": "osint" in deferred_objectives,
            },
        }

        unmet = [
            name
            for name, info in outcomes.items()
            if not info["met"] and not info["deferred"]
        ]

        host_outcomes.append(
            {
                "host": host,
                "outcomes": outcomes,
                "unmet_objectives": unmet,
                "deferred_objectives": sorted(deferred_objectives),
                "deferrals": [
                    {
                        "id": int(row.get("id", 0)),
                        "kind": str(row.get("kind", "") or ""),
                        "payload": row.get("payload") or {},
                        "created_at": row.get("created_at"),
                    }
                    for row in deferral_rows
                ],
                "finding_verdict": finding_verdicts_by_host.get(
                    host, _empty_finding_verdict()
                ),
            }
        )

    return {
        "objectives": list(PER_HOST_OBJECTIVES),
        "hosts": host_outcomes,
        # Superset of the per-host inline verdict: also carries finding-only
        # hosts (no recon service/surface) so the ledger never loses a verdict.
        "finding_verdicts": finding_verdicts_by_host,
        "engagement_signals": {
            "waf_intel_count": len(waf_rows),
            "tech_scan_intel_count": len(tech_fingerprint_rows),
            "osint_intel_total": len(live_tech_components) + int(people_count) + int(breach_count),
        },
    }

# W3 — backend web coverage-completeness gate (report_readiness).
#
# A host is a "real app" worth a recorded verdict at the report boundary when it
# has >= this many distinct recorded request-variant routes, OR it exposes an
# API/auth/GraphQL surface even under that count. This mirrors the CLI ledger's
# ``compute_real_app`` OR-inclusion (agent/scripts/assess/lib/coverage_checks.py)
# — kept duplicated here because the CLI module cannot be imported into the
# backend. The route signal is the durable backend equivalent of the CLI's
# cases.db live-route count: a recorded ``assessment_request_variants`` row IS an
# observed route.
WEB_ROUTE_REAL_APP_THRESHOLD = 6

# Path fragments that flag a high-value API / auth / GraphQL surface so a small
# crown-jewel host UNDER the route threshold is still treated as a real app.
# Mirrors the CLI ledger's token lists; keep the two in sync.
_WEB_API_PATH_TOKENS: tuple[str, ...] = (
    "/api/", "/api.", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql", "/gql",
    "/swagger", "/openapi", "/oauth", "/jsonrpc", "/.well-known/",
)
_WEB_API_PATH_SUFFIXES: tuple[str, ...] = (".json", "/api", "/graphql", "/v1", "/v2", "/v3")
_WEB_AUTH_PATH_TOKENS: tuple[str, ...] = (
    "/login", "/signin", "/sign-in", "/auth", "/oauth", "/sso", "/saml",
    "/oidc", "/session", "/logout", "/register", "/signup", "/password",
    "/mfa", "/2fa", "/token", "/authorize",
)
_WEB_GRAPHQL_PATH_TOKENS: tuple[str, ...] = ("/graphql", "/gql", "/graphiql")


def _web_path_is_high_value(path: str) -> bool:
    """True when a request-variant ``normalized_path`` is an API/auth/GraphQL
    surface (mirrors the CLI ``_path_matches`` over the same token lists)."""
    low = (path or "").lower()
    if not low:
        return False
    if any(tok in low for tok in _WEB_API_PATH_TOKENS):
        return True
    if any(low.endswith(suf) for suf in _WEB_API_PATH_SUFFIXES):
        return True
    if any(tok in low for tok in _WEB_AUTH_PATH_TOKENS):
        return True
    if any(tok in low for tok in _WEB_GRAPHQL_PATH_TOKENS):
        return True
    return False


def _scope_pattern_apex(pattern: str) -> str:
    """Apex of a scope.json host pattern: strips a leading ``*.`` wildcard.

    Both a literal (``example.com``) and a wildcard (``*.example.com``) entry
    cover the apex AND every subdomain (the HackerOne/Bugcrowd convention the
    CLI ``scope.entry_matches_host`` encodes), so they reduce to the same apex.
    """
    p = (pattern or "").strip().lower()
    if p.startswith("*."):
        p = p[2:]
    return p


def _host_matches_scope_pattern(host: str, pattern: str) -> bool:
    """True when ``host`` is the apex of ``pattern`` or a subdomain of it."""
    apex = _scope_pattern_apex(pattern)
    if not apex or not host:
        return False
    return host == apex or host.endswith("." + apex)


def _host_admitted_by_scope(
    host: str, allow_patterns: list[str], deny_patterns: list[str]
) -> bool:
    """Scope admission primitive: in the allowlist AND not in the denylist.

    Mirrors the CLI ``scope.host_admitted`` contract (the denylist always wins)
    so the W3 gate filters route hosts through the same allow/deny semantics the
    rest of the engagement trusts.
    """
    if not host:
        return False
    if not any(_host_matches_scope_pattern(host, p) for p in allow_patterns):
        return False
    if any(_host_matches_scope_pattern(host, p) for p in deny_patterns):
        return False
    return True


def _engagement_scope_admission(engagement: Any) -> tuple[list[str], list[str]] | None:
    """Best-effort ``(allow, deny)`` scope-host pattern lists for ``engagement``.

    Reuses the backend's canonical scope reader — the same scope.json
    ``hosts``/``scope_hosts`` allowlist and ``out_of_scope`` denylist that
    :class:`~app.services.engagements.EngagementView` already exposes — so the
    gate scopes route hosts through the exact admission inputs the rest of the
    backend uses. Returns ``None`` (caller fails OPEN, keeping the gate firing)
    when scope cannot be determined or no allowlist is present, rather than
    silently dropping every host and disabling the gate.
    """
    from .. import engagements as _engagements  # local import avoids any cycle

    try:
        view = _engagements._view_for(engagement)
    except Exception:  # pragma: no cover — defensive; never break the gate
        return None
    allow = [p for p in (view.scope_hosts or []) if p]
    if not allow:
        return None
    deny = [p for p in (view.out_of_scope or []) if p]
    return allow, deny


def web_uncovered_high_route_hosts(
    engagement_id: int,
    *,
    threshold: int = WEB_ROUTE_REAL_APP_THRESHOLD,
) -> list[dict[str, Any]]:
    """In-scope REAL-APP hosts with recorded routes but NO recorded verdict and
    no active ``coverage_completeness_deferral`` override.

    W3 backend gate input (consumed by ``report_readiness`` for web/both
    engagements). For every host that has recorded request-variant routes:

      * ``route_count`` = distinct ``normalized_path`` for the host.
      * ``real_app`` = ``route_count >= threshold`` OR an API/auth/GraphQL path
        — mirrors the CLI ledger's ``compute_real_app`` (a host with a finding
        is real_app there too, but a finding IS a recorded verdict, so such a
        host is COVERED and never appears here).
      * a recorded VERDICT is any non-merged finding on the host (a
        ``false_positive`` finding is the canonical evidence-backed negative) —
        read off the shared :func:`_build_finding_verdicts_by_host` projection.

    A host is dropped (out-of-scope) when it is not admitted by the
    engagement's scope (not in the scope.json allowlist, or carved out by
    ``out_of_scope``) — an SSO/CDN/third-party host recorded via archive/proxy/
    manual ingestion must never be forced through the completeness gate. A host
    is dropped (covered) when it carries a verdict, and dropped (deferred) when
    a matching active completeness deferral names it — or an engagement-wide one
    is present. The remaining hosts are the uncovered gaps.
    """
    engagement = _engagement_or_404(engagement_id)
    scope_admission = _engagement_scope_admission(engagement)
    with _common.get_connection() as connection:
        variant_rows = _fetch_all(
            connection,
            "SELECT host, normalized_path FROM assessment_request_variants "
            "WHERE engagement_id = ?",
            (engagement.id,),
        )
        finding_rows = _fetch_all(
            connection,
            "SELECT slug, canonical_location, status, verification_state, "
            "verification_disposition, severity, auth_context, merged_into_finding_id "
            "FROM assessment_findings WHERE engagement_id = ?",
            (engagement.id,),
        )

    route_paths: dict[str, set[str]] = {}
    high_value_hosts: set[str] = set()
    for row in variant_rows:
        host = _coverage_endpoint_host(str(row.get("host") or ""))
        path = str(row.get("normalized_path") or "").strip()
        if not host or not path:
            continue
        route_paths.setdefault(host, set()).add(path)
        if _web_path_is_high_value(path):
            high_value_hosts.add(host)

    finding_verdicts = _build_finding_verdicts_by_host(finding_rows)
    deferred_hosts, engagement_wide = _completeness_deferral_index(
        _active_coverage_completeness_deferrals(engagement.id)
    )

    out: list[dict[str, Any]] = []
    for host in sorted(route_paths):
        if scope_admission is not None and not _host_admitted_by_scope(
            host, scope_admission[0], scope_admission[1]
        ):
            continue  # out-of-scope host — never a completeness blocker
        route_count = len(route_paths[host])
        has_high_value = host in high_value_hosts
        if route_count < threshold and not has_high_value:
            continue  # not a real_app — excluded from the gate
        verdict = finding_verdicts.get(host)
        if verdict and verdict.get("has_finding"):
            continue  # a recorded verdict closes the host
        if engagement_wide or host in deferred_hosts:
            continue  # operator override
        if route_count >= threshold:
            reason = f">={threshold} recorded routes ({route_count})"
        else:
            reason = "exposes API/auth/GraphQL surface (under route threshold)"
        out.append(
            {
                "host": host,
                "route_count": route_count,
                "api_auth_graphql": has_high_value,
                "real_app_reason": reason,
            }
        )
    return out

def update_coverage_item_status(
    engagement_id: int,
    *,
    coverage_item_id: int,
    status_value: str,
    notes: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    normalized_status = _normalize_coverage_status(status_value)
    if normalized_status in {CoverageStatus.COVERED, CoverageStatus.NOT_APPLICABLE} and not (
        notes and notes.strip()
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"a non-empty rationale (notes) is required to mark a coverage "
                f"item '{normalized_status}'; 'covered' must mean tested with a "
                "stated reason"
            ),
        )
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_coverage_items WHERE id = ? AND engagement_id = ?",
            (coverage_item_id, engagement.id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="coverage item not found")
        connection.execute(
            "UPDATE assessment_coverage_items SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND engagement_id = ?",
            (normalized_status, _common._append_notes(row["notes"], notes), coverage_item_id, engagement.id),
        )
        if row["service_id"] is not None:
            _refresh_service_coverage_status(connection, engagement.id, int(row["service_id"]))
        updated = connection.execute(
            "SELECT * FROM assessment_coverage_items WHERE id = ?", (coverage_item_id,)
        ).fetchone()
    assert updated is not None
    return dict(updated)

_VENDOR_SAAS_HOST_SUFFIXES: list[tuple[str, str]] = [
    # Mirror of agent/scripts/assess/lib/scope.py:_VENDOR_SAAS_SUFFIXES so the
    # backend projection can answer the "is this host vendor SaaS" question
    # without spawning a Python subprocess. Keep the two lists in sync; the
    # CLI is the source of truth for the operator-side checkpoint, this list
    # exists only so the engagement summary projection can flag pending
    # decisions for the frontend banner.
    ("salesforce", ".salesforce.com"),
    ("salesforce", ".lightning.force.com"),
    ("salesforce", ".my.salesforce.com"),
    ("salesforce", ".force.com"),
    ("servicenow", ".service-now.com"),
    ("servicenow", ".servicenowservices.com"),
    ("statuspage", ".statuspage.io"),
    ("statuspage", ".statuspage.amazon.com"),
    ("govdelivery", ".govdelivery.com"),
    ("awsconnect", ".awsconnect.com"),
    ("awsconnect", ".amazonconnect.com"),
    ("auth0", ".auth0.com"),
    ("okta", ".okta.com"),
    ("okta", ".oktapreview.com"),
    ("zendesk", ".zendesk.com"),
    ("freshdesk", ".freshdesk.com"),
    ("intercom", ".intercom.io"),
]

def _host_is_vendor_saas(host: str | None) -> str | None:
    if not host:
        return None
    normalized = host.strip().rstrip(".").lower()
    if not normalized:
        return None
    for label, suffix in _VENDOR_SAAS_HOST_SUFFIXES:
        bare = suffix.lstrip(".")
        if normalized == bare or normalized.endswith(suffix):
            return label
    return None

def _host_from_endpoint(endpoint: str | None) -> str:
    raw = (endpoint or "").strip().lower()
    if not raw:
        return ""
    first = raw.split()[0]
    if "://" in first:
        try:
            host = urlparse(first).hostname or ""
        except ValueError:
            return ""
        return host.rstrip(".").lower()
    if first.startswith("["):
        closing = first.find("]")
        if closing > 1:
            return first[1:closing]
        return ""
    return first.split(":", 1)[0].rstrip(".").lower()

def vendor_saas_hosts_pending_decision(engagement_id: int) -> list[dict[str, str]]:
    """Return vendor-SaaS-flagged hosts that have no scope_decision record.

    A vendor-SaaS host is one whose recorded service endpoint or surface
    target descriptor matches a vendor SaaS suffix (Salesforce, ServiceNow,
    StatusPage, GovDelivery, AwsConnect, Auth0, Okta, Zendesk, Freshdesk,
    Intercom). The Vendor-SaaS scope checkpoint records the operator's
    choice as an ``assessment_dispatch_decisions`` row with
    ``kind='scope_decision'`` and ``payload.host`` set to the vendor host.
    Hosts that lack that record block the Phase 1 advance gate and surface
    in the frontend overview banner.
    """
    engagement = _engagement_or_404(engagement_id)
    pending: dict[str, str] = {}
    decided: set[str] = set()
    with _common.get_connection() as connection:
        service_rows = connection.execute(
            "SELECT endpoint FROM assessment_services WHERE engagement_id = ?",
            (engagement.id,),
        ).fetchall()
        surface_rows = connection.execute(
            "SELECT target_descriptor FROM assessment_surfaces WHERE engagement_id = ?",
            (engagement.id,),
        ).fetchall()
        decision_rows = connection.execute(
            """
            SELECT payload_json
            FROM assessment_dispatch_decisions
            WHERE engagement_id = ?
              AND kind = 'scope_decision'
            """,
            (engagement.id,),
        ).fetchall()
    for row in decision_rows:
        raw = row["payload_json"] if "payload_json" in row.keys() else row[0]
        try:
            payload = json.loads(raw or "{}")
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        host = _host_from_endpoint(str(payload.get("host") or payload.get("target") or ""))
        if _host_is_vendor_saas(host):
            decided.add(host)
    for row in service_rows:
        host = _host_from_endpoint(str(row["endpoint"] if "endpoint" in row.keys() else row[0]))
        vendor = _host_is_vendor_saas(host)
        if vendor and host not in decided and host not in pending:
            pending[host] = vendor
    for row in surface_rows:
        host = _host_from_endpoint(str(row["target_descriptor"] if "target_descriptor" in row.keys() else row[0]))
        vendor = _host_is_vendor_saas(host)
        if vendor and host not in decided and host not in pending:
            pending[host] = vendor
    return [{"host": host, "vendor": vendor} for host, vendor in sorted(pending.items())]

_EGRESS_BLOCK_INTENT_PATTERNS = (
    "egress reputation",
    "egress-block",
    "egress block",
    "cdn-ip-block",
    "ip-reputation",
)

def egress_block_status(engagement_id: int) -> dict[str, Any]:
    """Return ``{blocked_pct, pattern, samples_total, samples_blocked}``.

    Reads the most recent egress reputation check from
    ``assessment_command_runs`` (matched by intent text) and parses the
    ``egress_block_pct=N`` line out of stdout. When no recent run is
    available the projection returns zeros so the frontend can show a
    "not yet sampled" state instead of a stale percentage.

    ``pattern`` is one of ``unknown`` / ``cdn-403`` / ``geoblock-reset`` /
    ``mixed``, derived from the 403/000 ratio in the run output. The
    pattern is informational; the operator confirms the cause via the
    Egress reputation checkpoint.
    """
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT intent, stdout_preview, created_at
            FROM assessment_command_runs
            WHERE engagement_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT 50
            """,
            (engagement.id,),
        ).fetchall()
    for row in rows:
        intent = (row["intent"] if "intent" in row.keys() else "") or ""
        if not isinstance(intent, str):
            continue
        intent_lower = intent.lower()
        if not any(needle in intent_lower for needle in _EGRESS_BLOCK_INTENT_PATTERNS):
            continue
        stdout = row["stdout_preview"] if "stdout_preview" in row.keys() else ""
        if not isinstance(stdout, str):
            stdout = ""
        match = re.search(r"egress_block_pct\s*=\s*(\d+)", stdout)
        if not match:
            continue
        pct = int(match.group(1))
        n_403 = len(re.findall(r"\b403\b", stdout))
        n_000 = len(re.findall(r"\b000\b", stdout))
        if n_403 and not n_000:
            pattern = "cdn-403"
        elif n_000 and not n_403:
            pattern = "geoblock-reset"
        elif n_403 and n_000:
            pattern = "mixed"
        else:
            pattern = "unknown"
        return {
            "blocked_pct": pct,
            "pattern": pattern,
            "samples_total": n_403 + n_000,
            "samples_blocked": n_403 + n_000,
            "checked_at": row["created_at"] if "created_at" in row.keys() else None,
        }
    return {
        "blocked_pct": 0,
        "pattern": "unknown",
        "samples_total": 0,
        "samples_blocked": 0,
        "checked_at": None,
    }

def coverage_rollup(engagement_id: int) -> dict[str, Any]:
    """Split the flat coverage-items count by host reachability.

    The raw ``pending: N`` coverage number is permanently scary and hides the
    truth (most items sit on blackholed/unprobed hosts). This joins each
    coverage item to its host's verdict in the liveness ledger — via the
    request-variant `host` or the service `endpoint` (port-stripped) — and
    buckets the counts so the operator sees how many items are actually on
    reachable hosts. Reports STORED verdicts (no freshness overlay) since it is
    a coarse rollup, not a per-host dispatch decision. Observability only — no gate.
    """
    # Local import: coverage is imported before command_runs in this package's
    # __init__, so import the canonical host normalizer lazily to avoid any
    # init-order coupling (command_runs does not import coverage, so no cycle).
    from .command_runs import _normalize_liveness_host

    _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        # Project each coverage item's host (rv.host preferred, else the service
        # endpoint) and the liveness verdict map in Python, then bucket. The host
        # key is derived with ``_normalize_liveness_host`` — the same canonical,
        # IPv6-aware port-strip used when liveness rows are written — so the join
        # matches stored rows. (The old SQL stripped at the FIRST ':' via instr(),
        # which turned IPv6 endpoints like ``::1:8080`` into an empty host and
        # misreported them as 'unprobed'.)
        item_rows = connection.execute(
            """
            SELECT rv.host AS rv_host, s.endpoint AS endpoint
            FROM assessment_coverage_items ci
            LEFT JOIN assessment_services s ON s.id = ci.service_id
            LEFT JOIN assessment_request_variants rv ON rv.id = ci.request_variant_id
            WHERE ci.engagement_id = ?
            """,
            (engagement_id,),
        ).fetchall()
        liveness_rows = connection.execute(
            "SELECT host, reachability_class FROM assessment_host_liveness "
            "WHERE engagement_id = ? ORDER BY probed_at, id",
            (engagement_id,),
        ).fetchall()
    # IPv6-consistent liveness map. Liveness rows can be stored bare (``::1``) or
    # bracketed (``[::1]``, from a bracketed httpx ingest); request-variant item hosts
    # are always bare while service endpoints normalize to ``[::1]``. Strip brackets on
    # BOTH sides (here and in the item loop below) so every IPv6 form folds to one bare
    # key. When a bare and a bracketed liveness row exist for one literal they collapse
    # to a single key; ``ORDER BY probed_at, id`` makes the newest verdict win
    # deterministically (it is the last write into the dict).
    liveness = {
        str(r["host"]).strip("[]"): str(r["reachability_class"] or "unprobed")
        for r in liveness_rows
    }
    counts: dict[str, int] = {}
    for item in item_rows:
        # Strip brackets here too so a service endpoint that normalizes to ``[::1]``
        # matches the bracket-stripped liveness key. Residual: a service endpoint stored
        # as the ambiguous bare ``::1:8080`` (no brackets) keeps its port and still can't
        # be matched — disambiguating that needs a write-side fix.
        host = _normalize_liveness_host(str(item["rv_host"] or item["endpoint"] or "")).strip("[]")
        klass = liveness.get(host, "unprobed") if host else "unprobed"
        counts[klass] = counts.get(klass, 0) + 1
    return {
        "total": sum(counts.values()),
        "reachable": counts.get("live", 0),
        "blackholed": counts.get("blackholed", 0),
        "dead": counts.get("dead", 0),
        "unknown": counts.get("unknown", 0),
        "unprobed": counts.get("unprobed", 0),
    }
