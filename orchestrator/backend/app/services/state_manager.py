from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sqlite3
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, status

from ..db import get_connection
from .events import _engagement_or_404
from .search import fts_escape as _fts_escape_shared

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
WORKFLOW_STATUSES = {"draft", "active", "blocked", "exploited", "false_positive", "merged", "reported"}
WORKFLOW_STATUS_RANK = {
    "draft": 0,
    "active": 1,
    "blocked": 2,
    "exploited": 3,
    "reported": 4,
    "false_positive": -2,
    "merged": -1,
}
VERIFICATION_STATES = {"unreviewed", "verified", "disputed"}
VERIFICATION_STATE_RANK = {
    "unreviewed": 0,
    "disputed": 1,
    "verified": 2,
}
VERIFICATION_DISPOSITIONS = {"none", "confirmed", "downgraded", "false_positive"}
VERIFICATION_DISPOSITION_RANK = {
    "none": 0,
    "downgraded": 1,
    "confirmed": 2,
    "false_positive": -1,
}
_COVERAGE_STATUS_SYNONYMS = {
    "done": "covered",
    "not-applicable": "not_applicable",
    "n/a": "not_applicable",
    "tested": "covered",
}
COVERAGE_STATUSES = {"pending", "queued", "deferred", "covered", "not_applicable", "blocked"}
SLUG_RE = re.compile(r"[^a-z0-9]+")


def _json_text(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True, separators=(",", ":"))


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _merge_object_text(existing: str, incoming: dict[str, Any] | None) -> str:
    current = _json_object(existing)
    if incoming:
        current.update({key: value for key, value in incoming.items() if value not in (None, "", [], {})})
    return _json_text(current)


def _append_notes(existing: str, incoming: str) -> str:
    if not incoming:
        return existing
    if not existing:
        return incoming
    if incoming in existing.splitlines():
        return existing
    return f"{existing}\n{incoming}"


def _normalize_severity(value: str) -> str:
    severity = (value or "info").strip().lower()
    return severity if severity in SEVERITY_RANK else "info"


def _stronger_severity(existing: str, incoming: str) -> str:
    existing_normalized = _normalize_severity(existing)
    incoming_normalized = _normalize_severity(incoming)
    if SEVERITY_RANK[incoming_normalized] > SEVERITY_RANK[existing_normalized]:
        return incoming_normalized
    return existing_normalized


def _normalize_workflow_status(value: str) -> str:
    status_value = (value or "draft").strip().lower()
    if status_value not in WORKFLOW_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid workflow status: {value}")
    return status_value


def _normalize_verification_state(value: str) -> str:
    state_value = (value or "unreviewed").strip().lower()
    if state_value not in VERIFICATION_STATES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid verification state: {value}")
    return state_value


def _normalize_verification_disposition(value: str) -> str:
    disposition_value = (value or "none").strip().lower()
    if disposition_value not in VERIFICATION_DISPOSITIONS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid verification disposition: {value}")
    return disposition_value


def _normalize_coverage_status(value: str) -> str:
    status_value = (value or "pending").strip().lower()
    status_value = _COVERAGE_STATUS_SYNONYMS.get(status_value, status_value)
    if status_value not in COVERAGE_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid coverage status: {value}")
    return status_value


def _coalesce_workflow_status(existing: str, incoming: str, *, explicit_workflow_override: bool = False) -> str:
    existing_normalized = _normalize_workflow_status(existing)
    incoming_normalized = _normalize_workflow_status(incoming)
    if existing_normalized == "merged":
        return existing_normalized
    if explicit_workflow_override:
        return incoming_normalized
    if incoming_normalized == "merged":
        return incoming_normalized
    if incoming_normalized == "false_positive":
        return incoming_normalized
    if existing_normalized == "false_positive" and not explicit_workflow_override:
        # Keep prior verifier suppression sticky for semantic rediscovery so the same
        # location/family does not silently resurrect as a new live finding.
        return existing_normalized
    return (
        incoming_normalized
        if WORKFLOW_STATUS_RANK[incoming_normalized] >= WORKFLOW_STATUS_RANK[existing_normalized]
        else existing_normalized
    )


def _coalesce_verification_state(existing: str, incoming: str, *, explicit_override: bool = False) -> str:
    existing_normalized = _normalize_verification_state(existing)
    incoming_normalized = _normalize_verification_state(incoming)
    if explicit_override:
        return incoming_normalized
    return (
        incoming_normalized
        if VERIFICATION_STATE_RANK[incoming_normalized] >= VERIFICATION_STATE_RANK[existing_normalized]
        else existing_normalized
    )


def _coalesce_verification_disposition(existing: str, incoming: str, *, explicit_override: bool = False) -> str:
    existing_normalized = _normalize_verification_disposition(existing)
    incoming_normalized = _normalize_verification_disposition(incoming)
    if incoming_normalized == "false_positive":
        return incoming_normalized
    if existing_normalized == "false_positive" and not explicit_override:
        return existing_normalized
    if explicit_override:
        return incoming_normalized
    return (
        incoming_normalized
        if VERIFICATION_DISPOSITION_RANK[incoming_normalized] >= VERIFICATION_DISPOSITION_RANK[existing_normalized]
        else existing_normalized
    )


def _legacy_verification_defaults(workflow_status: str) -> tuple[str, str]:
    normalized_workflow = _normalize_workflow_status(workflow_status)
    if normalized_workflow == "false_positive":
        return ("verified", "false_positive")
    if normalized_workflow in {"blocked", "exploited", "reported"}:
        return ("verified", "confirmed")
    if normalized_workflow == "active":
        return ("unreviewed", "none")
    return ("unreviewed", "none")


def _raise_stale_finding_conflict() -> None:
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="finding changed since it was loaded; refetch and retry",
    )


def _row_workflow_status(row: dict[str, Any] | Any) -> str:
    if isinstance(row, dict):
        return _normalize_workflow_status(str(row.get("status", "draft")))
    return _normalize_workflow_status(str(row["status"]))


def _row_verification_state(row: dict[str, Any] | Any) -> str:
    if isinstance(row, dict):
        value = str(row.get("verification_state", "") or "")
        if value:
            return _normalize_verification_state(value)
        return _legacy_verification_defaults(_row_workflow_status(row))[0]
    value = str(row["verification_state"]) if "verification_state" in row.keys() else ""
    if value:
        return _normalize_verification_state(value)
    return _legacy_verification_defaults(_row_workflow_status(row))[0]


def _row_verification_disposition(row: dict[str, Any] | Any) -> str:
    if isinstance(row, dict):
        value = str(row.get("verification_disposition", "") or "")
        if value:
            return _normalize_verification_disposition(value)
        return _legacy_verification_defaults(_row_workflow_status(row))[1]
    value = str(row["verification_disposition"]) if "verification_disposition" in row.keys() else ""
    if value:
        return _normalize_verification_disposition(value)
    return _legacy_verification_defaults(_row_workflow_status(row))[1]


def _finding_state_snapshot(row: dict[str, Any] | Any) -> dict[str, str]:
    if isinstance(row, dict):
        severity_value = row.get("severity", "info")
    else:
        severity_value = row["severity"]
    return {
        "workflow_status": _row_workflow_status(row),
        "verification_state": _row_verification_state(row),
        "verification_disposition": _row_verification_disposition(row),
        "severity": _normalize_severity(str(severity_value)),
    }


def _finding_state_changed(before: dict[str, str] | None, after: dict[str, str]) -> bool:
    if before is None:
        return True
    return any(before[key] != after[key] for key in after)


def _infer_transition_action(before: dict[str, str] | None, after: dict[str, str]) -> str:
    if before is None:
        return "created"
    if after["workflow_status"] == "merged" and before["workflow_status"] != "merged":
        return "workflow_merged"
    if after["workflow_status"] == "reported" and before["workflow_status"] != "reported":
        return "workflow_reported"
    if after["workflow_status"] == "blocked" and before["workflow_status"] != "blocked":
        return "workflow_blocked"
    if (
        after["verification_state"] == "verified"
        and after["verification_disposition"] == "false_positive"
        and (
            before["verification_disposition"] != "false_positive"
            or before["workflow_status"] != "false_positive"
        )
    ):
        return "verified_false_positive"
    if (
        before["workflow_status"] == "false_positive"
        or before["verification_disposition"] == "false_positive"
    ) and (
        after["workflow_status"] != "false_positive"
        and after["verification_disposition"] != "false_positive"
    ):
        return "operator_override"
    if after["verification_state"] == "disputed" and before["verification_state"] != "disputed":
        return "verification_disputed"
    if after["verification_disposition"] == "downgraded" and before["verification_disposition"] != "downgraded":
        return "verified_downgraded"
    if (
        after["verification_state"] == "verified"
        and after["verification_disposition"] == "confirmed"
        and (
            before["verification_state"] != "verified"
            or before["verification_disposition"] != "confirmed"
        )
    ):
        return "verified_confirmed"
    return "operator_override"


def _default_transition_reason(action: str, after: dict[str, str]) -> str:
    if action == "created":
        return "Finding created."
    if action == "verified_confirmed":
        return "Verification confirmed the finding."
    if action == "verified_downgraded":
        return "Verification downgraded the finding severity."
    if action == "verified_false_positive":
        return "Verification marked the finding as a false positive."
    if action == "verification_disputed":
        return "Verification disputed the current finding assessment."
    if action == "workflow_reported":
        return "Finding included in report output."
    if action == "workflow_merged":
        return "Finding merged into another canonical record."
    if action == "workflow_blocked":
        return "Finding workflow moved to blocked."
    return f"Finding state updated to {after['workflow_status']}."


def _record_finding_transition(
    connection,
    *,
    engagement_id: int,
    finding_id: int,
    actor: str,
    action: str,
    before: dict[str, str] | None,
    after: dict[str, str],
    reason_code: str,
    reason_text: str,
    artifact_ref: str,
    metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    cursor = connection.execute(
        """
        INSERT INTO assessment_finding_transitions (
            engagement_id, finding_id, actor, action,
            from_workflow_status, to_workflow_status,
            from_verification_state, to_verification_state,
            from_verification_disposition, to_verification_disposition,
            from_severity, to_severity,
            reason_code, reason_text, artifact_ref, metadata_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            finding_id,
            actor,
            action,
            None if before is None else before["workflow_status"],
            after["workflow_status"],
            None if before is None else before["verification_state"],
            after["verification_state"],
            None if before is None else before["verification_disposition"],
            after["verification_disposition"],
            None if before is None else before["severity"],
            after["severity"],
            reason_code,
            reason_text,
            artifact_ref,
            _json_text(metadata),
        ),
    )
    row = connection.execute("SELECT * FROM assessment_finding_transitions WHERE id = ?", (cursor.lastrowid,)).fetchone()
    assert row is not None
    return dict(row)


def _is_suppressed_workflow_status(workflow_status: str) -> bool:
    return _normalize_workflow_status(workflow_status) in {"merged", "false_positive"}


def _serialize_finding_record(row: dict[str, Any] | Any) -> dict[str, Any]:
    record = dict(row) if not isinstance(row, dict) else dict(row)
    # Read-path serialization must not crash on invalid DB values.
    # Validation belongs on write paths; here we pass through raw data
    # so the frontend can still display the finding.
    try:
        record["workflow_status"] = _row_workflow_status(record)
    except HTTPException:
        record["workflow_status"] = str(record.get("status", "draft")).strip().lower()
    try:
        record["verification_state"] = _row_verification_state(record)
    except HTTPException:
        record["verification_state"] = str(record.get("verification_state", "unreviewed") or "unreviewed").strip().lower()
    try:
        record["verification_disposition"] = _row_verification_disposition(record)
    except HTTPException:
        record["verification_disposition"] = str(record.get("verification_disposition", "none") or "none").strip().lower()
    record.pop("status", None)
    return record


def _finding_confidence_tuple(row: dict[str, Any] | Any) -> tuple[int, int, int, int, int]:
    if isinstance(row, dict):
        severity_value = row.get("severity", "info")
        evidence_ref = row.get("evidence_ref", "")
    else:
        severity_value = row["severity"]
        evidence_ref = row["evidence_ref"]
    return (
        WORKFLOW_STATUS_RANK[_row_workflow_status(row)],
        VERIFICATION_STATE_RANK[_row_verification_state(row)],
        VERIFICATION_DISPOSITION_RANK[_row_verification_disposition(row)],
        SEVERITY_RANK[_normalize_severity(str(severity_value))],
        1 if evidence_ref else 0,
    )


def _slugify(value: str) -> str:
    normalized = SLUG_RE.sub("-", value.strip().lower()).strip("-")
    return normalized or "finding"


def _parse_url(url: str) -> tuple[str, str, int, str]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="request url must be absolute")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    normalized_path = parsed.path or "/"
    return parsed.scheme, parsed.hostname, port, normalized_path


def _hash_json(value: Any) -> str:
    return hashlib.sha256(_json_text(value).encode("utf-8")).hexdigest()


def _scalar_row(connection, query: str, params: tuple[Any, ...]) -> int:
    row = connection.execute(query, params).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _fetch_all(connection, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(query, params).fetchall()]


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
            coverage_status = excluded.coverage_status,
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
) -> dict[str, Any]:
    normalized_status = _normalize_coverage_status(status_value)
    row = connection.execute(
        """
        SELECT *
        FROM assessment_coverage_items
        WHERE engagement_id = ? AND request_variant_id IS ? AND service_id IS ? AND auth_context = ? AND input_slot = ? AND attack_family = ?
        """,
        (engagement_id, request_variant_id, service_id, auth_context, input_slot, attack_family),
    ).fetchone()
    if row is None:
        cursor = connection.execute(
            """
            INSERT INTO assessment_coverage_items (
                engagement_id, request_variant_id, service_id, auth_context, input_slot, attack_family, status, notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement_id, request_variant_id, service_id, auth_context, input_slot, attack_family, normalized_status, notes),
        )
        row = connection.execute(
            "SELECT * FROM assessment_coverage_items WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    else:
        connection.execute(
            """
            UPDATE assessment_coverage_items
            SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (normalized_status, _append_notes(row["notes"], notes), row["id"]),
        )
        row = connection.execute("SELECT * FROM assessment_coverage_items WHERE id = ?", (row["id"],)).fetchone()
    assert row is not None
    if row["service_id"] is not None:
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
) -> tuple[str, str]:
    payload_hash = hashlib.sha256(payload_value.encode("utf-8")).hexdigest() if payload_value else ""
    probe_key = hashlib.sha256(
        json.dumps(
            {
                "request_variant_id": request_variant_id,
                "service_id": service_id,
                "coverage_item_id": coverage_item_id,
                "auth_context": auth_context,
                "input_slot": input_slot,
                "attack_family": attack_family,
                "payload_family": payload_family,
                "payload_hash": payload_hash,
                "tool_name": tool_name,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
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
) -> dict[str, Any]:
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
    )
    connection.execute(
        """
        INSERT INTO assessment_probe_runs (
            engagement_id, request_variant_id, service_id, coverage_item_id, auth_context, input_slot, attack_family,
            payload_family, payload_value_hash, probe_key, tool_name, agent_name, result_status,
            observed_http_status, signal_type, evidence_ref, notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, probe_key) DO UPDATE SET
            agent_name = COALESCE(NULLIF(excluded.agent_name, ''), assessment_probe_runs.agent_name),
            result_status = excluded.result_status,
            observed_http_status = COALESCE(excluded.observed_http_status, assessment_probe_runs.observed_http_status),
            signal_type = COALESCE(NULLIF(excluded.signal_type, ''), assessment_probe_runs.signal_type),
            evidence_ref = COALESCE(NULLIF(excluded.evidence_ref, ''), assessment_probe_runs.evidence_ref),
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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


def list_request_variants(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        return _fetch_all(
            connection,
            "SELECT * FROM assessment_request_variants WHERE engagement_id = ? ORDER BY last_seen_at DESC, id DESC",
            (engagement.id,),
        )


def list_request_observations(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        return _fetch_all(
            connection,
            "SELECT * FROM assessment_request_observations WHERE engagement_id = ? ORDER BY created_at DESC, id DESC",
            (engagement.id,),
        )


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
    scheme, host, _, _ = _parse_url(url)
    _, endpoint, port, service_name = _service_fields_from_url(url)
    identity = target_identity or host
    discovered_by = discovery_source
    with get_connection() as connection:
        target = _upsert_target(
            connection,
            engagement.id,
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
            engagement.id,
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
        observation = _insert_request_observation(
            connection,
            engagement.id,
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
            coverage_items.append(
                _upsert_coverage_item(
                    connection,
                    engagement.id,
                    request_variant_id=key[0],
                    service_id=key[1],
                    auth_context=auth_context,
                    input_slot=key[3],
                    attack_family=key[4],
                    status_value=str(candidate.get("status", "pending")),
                    notes=str(candidate.get("notes", "")),
                )
            )
        return {
            "target": target,
            "service": service,
            "request_variant": request_variant,
            "request_observation": observation,
            "coverage_items": coverage_items,
        }


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
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
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
        )


def list_coverage_items(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
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
            """,
            (engagement.id,),
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
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
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
        )


def list_probe_runs(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_probe_runs WHERE engagement_id = ? ORDER BY created_at DESC, id DESC", (engagement.id,))


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
    with get_connection() as connection:
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


def list_surfaces(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_surfaces WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))


def _finding_slug(connection, engagement_id: int, slug: str | None, title: str, canonical_location: str) -> str:
    if slug:
        return slug
    base = _slugify(f"{title}-{canonical_location}")
    candidate = base
    suffix = 2
    while connection.execute(
        "SELECT 1 FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
        (engagement_id, candidate),
    ).fetchone():
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def _semantic_finding_match(
    connection,
    engagement_id: int,
    *,
    slug: str | None,
    defect_family: str,
    root_cause_key: str,
    canonical_location: str,
    auth_context: str,
    title: str,
) -> dict[str, Any] | None:
    if slug:
        row = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement_id, slug),
        ).fetchone()
        if row is not None:
            return dict(row)
    if defect_family and root_cause_key:
        row = connection.execute(
            """
            SELECT *
            FROM assessment_findings
            WHERE engagement_id = ?
              AND status != 'merged'
              AND defect_family = ?
              AND root_cause_key = ?
              AND auth_context = ?
              AND canonical_location = ?
            ORDER BY id ASC
            LIMIT 1
            """,
            (engagement_id, defect_family, root_cause_key, auth_context, canonical_location),
        ).fetchone()
        if row is not None:
            return dict(row)
    row = connection.execute(
        """
        SELECT *
        FROM assessment_findings
        WHERE engagement_id = ?
          AND status NOT IN ('merged', 'false_positive')
          AND title = ?
          AND canonical_location = ?
          AND auth_context = ?
        ORDER BY id ASC
        LIMIT 1
        """,
        (engagement_id, title, canonical_location, auth_context),
    ).fetchone()
    return dict(row) if row is not None else None


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
    row = connection.execute(
        """
        SELECT *
        FROM assessment_finding_links
        WHERE engagement_id = ? AND finding_id = ? AND link_kind = ? AND target_kind = ? AND target_id IS ? AND target_ref = ?
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
            (_append_notes(row["notes"], notes), _merge_object_text(row["provenance_json"], provenance), row["id"]),
        )
        row = connection.execute("SELECT * FROM assessment_finding_links WHERE id = ?", (row["id"],)).fetchone()
    assert row is not None
    return dict(row)


def create_finding(
    engagement_id: int,
    *,
    slug: str | None,
    title: str,
    severity: str,
    workflow_status: str,
    verification_state: str,
    verification_disposition: str,
    defect_family: str,
    root_cause_key: str,
    auth_context: str,
    canonical_location: str,
    summary: str,
    evidence_ref: str,
    notes: str,
    source_name: str,
    details: dict[str, Any] | None,
    provenance: dict[str, Any] | None,
    request_variant_id: int | None,
    service_id: int | None,
    surface_id: int | None,
    links: list[dict[str, Any]] | None,
    explicit_workflow_override: bool = False,
    explicit_verification_state_override: bool = False,
    explicit_verification_disposition_override: bool = False,
    explicit_severity_override: bool = False,
    transition_action: str | None = None,
    transition_reason_code: str = "",
    transition_reason_text: str = "",
    transition_artifact_ref: str = "",
    transition_metadata: dict[str, Any] | None = None,
    expected_updated_at: str | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    incoming_workflow_status = _normalize_workflow_status(workflow_status)
    incoming_verification_state = _normalize_verification_state(verification_state)
    incoming_verification_disposition = _normalize_verification_disposition(verification_disposition)
    incoming_severity = _normalize_severity(severity)
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = _semantic_finding_match(
            connection,
            engagement.id,
            slug=slug,
            defect_family=defect_family,
            root_cause_key=root_cause_key,
            canonical_location=canonical_location,
            auth_context=auth_context,
            title=title,
        )
        before_state = _finding_state_snapshot(existing) if existing is not None else None
        if existing is None:
            resolved_slug = _finding_slug(connection, engagement.id, slug, title, canonical_location)
            cursor = connection.execute(
                """
                INSERT INTO assessment_findings (
                    engagement_id, slug, title, severity, status, verification_state, verification_disposition, defect_family, root_cause_key, auth_context,
                    canonical_location, source_name, summary, evidence_ref, notes, details_json, provenance_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    resolved_slug,
                    title,
                    incoming_severity,
                    incoming_workflow_status,
                    incoming_verification_state,
                    incoming_verification_disposition,
                    defect_family,
                    root_cause_key,
                    auth_context,
                    canonical_location,
                    source_name,
                    summary,
                    evidence_ref,
                    notes,
                    _json_text(details),
                    _json_text(provenance),
                ),
            )
            row = connection.execute("SELECT * FROM assessment_findings WHERE id = ?", (cursor.lastrowid,)).fetchone()
        else:
            if expected_updated_at is not None and str(existing["updated_at"]) != expected_updated_at:
                _raise_stale_finding_conflict()
            existing_workflow = _row_workflow_status(existing)
            existing_verification_state = _row_verification_state(existing)
            existing_verification_disposition = _row_verification_disposition(existing)
            connection.execute(
                """
                UPDATE assessment_findings
                SET title = ?,
                    severity = ?,
                    status = ?,
                    verification_state = ?,
                    verification_disposition = ?,
                    defect_family = COALESCE(NULLIF(?, ''), defect_family),
                    root_cause_key = COALESCE(NULLIF(?, ''), root_cause_key),
                    auth_context = COALESCE(NULLIF(?, ''), auth_context),
                    canonical_location = COALESCE(NULLIF(?, ''), canonical_location),
                    source_name = COALESCE(NULLIF(?, ''), source_name),
                    summary = CASE WHEN ? = '' THEN summary ELSE ? END,
                    evidence_ref = COALESCE(NULLIF(?, ''), evidence_ref),
                    notes = ?,
                    details_json = ?,
                    provenance_json = ?,
                    last_seen_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    title,
                    incoming_severity if explicit_severity_override else _stronger_severity(existing["severity"], incoming_severity),
                    _coalesce_workflow_status(
                        existing_workflow,
                        incoming_workflow_status,
                        explicit_workflow_override=explicit_workflow_override,
                    ),
                    _coalesce_verification_state(
                        existing_verification_state,
                        incoming_verification_state,
                        explicit_override=explicit_verification_state_override,
                    ),
                    _coalesce_verification_disposition(
                        existing_verification_disposition,
                        incoming_verification_disposition,
                        explicit_override=explicit_verification_disposition_override,
                    ),
                    defect_family,
                    root_cause_key,
                    auth_context,
                    canonical_location,
                    source_name,
                    summary,
                    summary,
                    evidence_ref,
                    _append_notes(existing["notes"], notes),
                    _merge_object_text(existing["details_json"], details),
                    _merge_object_text(existing["provenance_json"], provenance),
                    existing["id"],
                ),
            )
            row = connection.execute("SELECT * FROM assessment_findings WHERE id = ?", (existing["id"],)).fetchone()
        assert row is not None
        finding = dict(row)
        after_state = _finding_state_snapshot(finding)
        derived_links = list(links or [])
        if request_variant_id is not None:
            derived_links.append({"link_kind": "related", "target_kind": "request_variant", "target_id": request_variant_id, "target_ref": "", "notes": "", "provenance": provenance or {}})
        if service_id is not None:
            derived_links.append({"link_kind": "related", "target_kind": "service", "target_id": service_id, "target_ref": "", "notes": "", "provenance": provenance or {}})
        if surface_id is not None:
            derived_links.append({"link_kind": "related", "target_kind": "surface", "target_id": surface_id, "target_ref": "", "notes": "", "provenance": provenance or {}})
        if evidence_ref:
            derived_links.append({"link_kind": "evidence", "target_kind": "evidence_artifact", "target_id": None, "target_ref": evidence_ref, "notes": "", "provenance": provenance or {}})
        finding_links = [
            _upsert_finding_link(
                connection,
                engagement.id,
                finding_id=finding["id"],
                link_kind=str(item.get("link_kind", "related")),
                target_kind=str(item.get("target_kind", "unknown")),
                target_id=item.get("target_id"),
                target_ref=str(item.get("target_ref", "")),
                notes=str(item.get("notes", "")),
                provenance=item.get("provenance"),
            )
            for item in derived_links
        ]
        transition = None
        if _finding_state_changed(before_state, after_state):
            action = transition_action or _infer_transition_action(before_state, after_state)
            actor = source_name or str((provenance or {}).get("agent_name", "") or (provenance or {}).get("verified_by", "") or (provenance or {}).get("reviewed_by", ""))
            transition = _record_finding_transition(
                connection,
                engagement_id=engagement.id,
                finding_id=int(finding["id"]),
                actor=actor,
                action=action,
                before=before_state,
                after=after_state,
                reason_code=transition_reason_code,
                reason_text=transition_reason_text or notes or _default_transition_reason(action, after_state),
                artifact_ref=transition_artifact_ref or evidence_ref,
                metadata=transition_metadata,
            )
    return {
        "finding": _serialize_finding_record(finding),
        "links": finding_links,
        "transition": transition,
    }


def update_finding(
    engagement_id: int,
    *,
    slug: str,
    title: str,
    severity: str,
    workflow_status: str,
    verification_state: str,
    verification_disposition: str,
    defect_family: str,
    root_cause_key: str,
    auth_context: str,
    canonical_location: str,
    summary: str,
    evidence_ref: str,
    notes: str,
    source_name: str,
    details: dict[str, Any] | None,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    result = create_finding(
        engagement_id,
        slug=slug,
        title=title,
        severity=severity,
        workflow_status=workflow_status,
        verification_state=verification_state,
        verification_disposition=verification_disposition,
        defect_family=defect_family,
        root_cause_key=root_cause_key,
        auth_context=auth_context,
        canonical_location=canonical_location,
        summary=summary,
        evidence_ref=evidence_ref,
        notes=notes,
        source_name=source_name,
        details=details,
        provenance=provenance,
        request_variant_id=None,
        service_id=None,
        surface_id=None,
        links=None,
        explicit_workflow_override=workflow_status is not None,
        explicit_verification_state_override=verification_state is not None,
        explicit_verification_disposition_override=verification_disposition is not None,
        explicit_severity_override=severity is not None,
    )
    return result["finding"]


def patch_finding(
    engagement_id: int,
    *,
    slug: str,
    title: str | None = None,
    severity: str | None = None,
    workflow_status: str | None = None,
    verification_state: str | None = None,
    verification_disposition: str | None = None,
    defect_family: str | None = None,
    root_cause_key: str | None = None,
    auth_context: str | None = None,
    canonical_location: str | None = None,
    summary: str | None = None,
    evidence_ref: str | None = None,
    notes: str | None = None,
    source_name: str | None = None,
    details: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
    transition_action: str | None = None,
    transition_reason_code: str = "",
    transition_reason_text: str = "",
    transition_artifact_ref: str = "",
    transition_metadata: dict[str, Any] | None = None,
    allow_verification_mutation: bool = False,
    expected_updated_at: str | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")

    existing_workflow = _row_workflow_status(existing)
    current_updated_at = str(existing["updated_at"])

    if not allow_verification_mutation:
        if verification_state is not None or verification_disposition is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="verification lifecycle changes must use POST /findings/{slug}/verify",
            )
        if workflow_status in {"false_positive", "merged"}:
            detail = (
                "false_positive workflow changes must use POST /findings/{slug}/verify"
                if workflow_status == "false_positive"
                else "merged workflow changes must use POST /findings/merge"
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
        if existing_workflow == "merged" and workflow_status is not None and workflow_status != "merged":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="merged findings cannot be reopened via patch",
            )
        if existing_workflow == "false_positive" and workflow_status is not None and workflow_status != "false_positive":
            verification_state = "unreviewed"
            verification_disposition = "none"

    return create_finding(
        engagement.id,
        slug=slug,
        title=title if title is not None else str(existing["title"]),
        severity=severity if severity is not None else str(existing["severity"]),
        workflow_status=workflow_status if workflow_status is not None else _row_workflow_status(existing),
        verification_state=verification_state if verification_state is not None else _row_verification_state(existing),
        verification_disposition=verification_disposition if verification_disposition is not None else _row_verification_disposition(existing),
        defect_family=defect_family or "",
        root_cause_key=root_cause_key or "",
        auth_context=auth_context or "",
        canonical_location=canonical_location or "",
        summary="" if summary is None else summary,
        evidence_ref=evidence_ref or "",
        notes="" if notes is None else notes,
        source_name=source_name or "",
        details=details,
        provenance=provenance,
        request_variant_id=None,
        service_id=None,
        surface_id=None,
        links=None,
        explicit_workflow_override=workflow_status is not None,
        explicit_verification_state_override=verification_state is not None,
        explicit_verification_disposition_override=verification_disposition is not None,
        explicit_severity_override=severity is not None,
        transition_action=transition_action,
        transition_reason_code=transition_reason_code,
        transition_reason_text=transition_reason_text,
        transition_artifact_ref=transition_artifact_ref,
        transition_metadata=transition_metadata,
        expected_updated_at=expected_updated_at or current_updated_at,
    )


def verify_finding(
    engagement_id: int,
    *,
    slug: str,
    disposition: str,
    reason_code: str,
    reason_text: str,
    source_name: str,
    evidence_ref: str,
    notes: str,
    details: dict[str, Any] | None,
    provenance: dict[str, Any] | None,
    artifact_ref: str,
    new_severity: str | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if disposition == "disputed":
        normalized_disposition = "none"
    else:
        normalized_disposition = _normalize_verification_disposition(disposition)
    if normalized_disposition == "none" and disposition != "disputed":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="verification disposition cannot be none")

    with get_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")

    expected_updated_at = str(existing["updated_at"])
    existing_workflow = _row_workflow_status(existing)
    if existing_workflow == "merged":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="merged findings cannot be re-verified")
    target_workflow = existing_workflow if existing_workflow not in {"false_positive", "merged"} else "active"
    target_verification_state = "verified"
    target_severity = str(existing["severity"])
    transition_action = "verified_confirmed"
    transition_metadata: dict[str, Any] = {}
    details_payload = dict(details or {})

    if normalized_disposition == "downgraded":
        if not new_severity:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="downgraded verification requires new_severity")
        normalized_new_severity = _normalize_severity(new_severity)
        if SEVERITY_RANK[normalized_new_severity] >= SEVERITY_RANK[_normalize_severity(str(existing["severity"]))]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="new_severity must be lower than the current severity")
        target_severity = normalized_new_severity
        transition_action = "verified_downgraded"
        transition_metadata["previous_severity"] = _normalize_severity(str(existing["severity"]))
    elif normalized_disposition == "false_positive":
        if not details_payload.get("kill_reason") or details_payload.get("kill_check") is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="false_positive verification requires details.kill_reason and details.kill_check",
            )
        target_workflow = "false_positive"
        transition_action = "verified_false_positive"
    elif normalized_disposition == "confirmed":
        transition_action = "verified_confirmed"
    else:
        target_verification_state = "disputed"
        normalized_disposition = "none"
        transition_action = "verification_disputed"

    return patch_finding(
        engagement.id,
        slug=slug,
        severity=target_severity,
        workflow_status=target_workflow,
        verification_state=target_verification_state,
        verification_disposition=normalized_disposition,
        evidence_ref=evidence_ref or None,
        notes=notes,
        source_name=source_name or None,
        details=details_payload,
        provenance=provenance,
        transition_action=transition_action,
        transition_reason_code=reason_code,
        transition_reason_text=reason_text,
        transition_artifact_ref=artifact_ref or evidence_ref,
        transition_metadata=transition_metadata or None,
        allow_verification_mutation=True,
        expected_updated_at=expected_updated_at,
    )


def merge_findings(
    engagement_id: int,
    *,
    source_slug: str,
    target_slug: str,
    reason: str,
    source_name: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        source = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, source_slug),
        ).fetchone()
        target = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, target_slug),
        ).fetchone()
        if source is None or target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
        if source["id"] == target["id"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="cannot merge a finding into itself")
        if _row_workflow_status(target) == "false_positive" and _row_workflow_status(source) != "false_positive":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="cannot merge a live finding into a false_positive target",
            )
        source_confidence = _finding_confidence_tuple(source)
        target_confidence = _finding_confidence_tuple(target)
        source_updated_at = str(source["updated_at"])
        target_updated_at = str(target["updated_at"])
        source_stronger = source_confidence > target_confidence
        source_workflow = _row_workflow_status(source)
        target_workflow = _row_workflow_status(target)
        source_verification_state = _row_verification_state(source)
        target_verification_state = _row_verification_state(target)
        source_verification_disposition = _row_verification_disposition(source)
        target_verification_disposition = _row_verification_disposition(target)
        source_before = _finding_state_snapshot(source)
        target_before = _finding_state_snapshot(target)
        merged_notes = _append_notes(
            _append_notes(target["notes"], f"Merged {source_slug}: {reason}"),
            source["notes"],
        )
        merged_details = _merge_object_text(target["details_json"], _json_object(source["details_json"]))
        merged_provenance_payload = _json_object(target["provenance_json"])
        merged_provenance_payload.update(_json_object(source["provenance_json"]))
        merged_provenance_payload["merge"] = {
            "source_slug": source_slug,
            "target_slug": target_slug,
            "reason": reason,
            "source_name": source_name,
        }
        source_links = connection.execute(
            "SELECT * FROM assessment_finding_links WHERE engagement_id = ? AND finding_id = ?",
            (engagement.id, source["id"]),
        ).fetchall()
        source_cursor = connection.execute(
            """
            UPDATE assessment_findings
            SET status = 'merged',
                verification_state = 'unreviewed',
                verification_disposition = 'none',
                merged_into_finding_id = ?,
                notes = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND updated_at = ?
            """,
            (target["id"], _append_notes(source["notes"], reason), source["id"], source_updated_at),
        )
        if source_cursor.rowcount != 1:
            _raise_stale_finding_conflict()
        target_cursor = connection.execute(
            """
            UPDATE assessment_findings
            SET severity = ?,
                status = ?,
                verification_state = ?,
                verification_disposition = ?,
                source_name = CASE
                    WHEN ? = '' THEN source_name
                    WHEN ? = 1 THEN ?
                    ELSE source_name
                END,
                summary = CASE
                    WHEN summary = '' THEN ?
                    WHEN ? = 1 AND ? != '' THEN ?
                    ELSE summary
                END,
                evidence_ref = CASE
                    WHEN evidence_ref = '' THEN ?
                    WHEN ? = 1 AND ? != '' THEN ?
                    ELSE evidence_ref
                END,
                notes = ?,
                details_json = ?,
                provenance_json = ?,
                updated_at = CURRENT_TIMESTAMP,
                last_seen_at = CURRENT_TIMESTAMP
            WHERE id = ? AND updated_at = ?
            """,
            (
                _stronger_severity(target["severity"], source["severity"]),
                (
                    target_workflow
                    if source_workflow == "false_positive" and target_workflow != "false_positive"
                    else _coalesce_workflow_status(target_workflow, source_workflow)
                ),
                (
                    target_verification_state
                    if source_workflow == "false_positive" and target_workflow != "false_positive"
                    else _coalesce_verification_state(target_verification_state, source_verification_state)
                ),
                (
                    target_verification_disposition
                    if source_verification_disposition == "false_positive"
                    and target_verification_disposition != "false_positive"
                    else _coalesce_verification_disposition(
                        target_verification_disposition,
                        source_verification_disposition,
                    )
                ),
                source["source_name"],
                1 if source_stronger else 0,
                source["source_name"],
                source["summary"],
                1 if source_stronger else 0,
                source["summary"],
                source["summary"],
                source["evidence_ref"],
                1 if source_stronger else 0,
                source["evidence_ref"],
                source["evidence_ref"],
                merged_notes,
                merged_details,
                _json_text(merged_provenance_payload),
                target["id"],
                target_updated_at,
            ),
        )
        if target_cursor.rowcount != 1:
            _raise_stale_finding_conflict()
        for row in source_links:
            _upsert_finding_link(
                connection,
                engagement.id,
                finding_id=target["id"],
                link_kind=row["link_kind"],
                target_kind=row["target_kind"],
                target_id=row["target_id"],
                target_ref=row["target_ref"],
                notes=row["notes"],
                provenance=_json_object(row["provenance_json"]),
            )
        connection.execute(
            "DELETE FROM assessment_finding_links WHERE engagement_id = ? AND finding_id = ?",
            (engagement.id, source["id"]),
        )
        link = _upsert_finding_link(
            connection,
            engagement.id,
            finding_id=target["id"],
            link_kind="merged_from",
            target_kind="finding",
            target_id=source["id"],
            target_ref=source_slug,
            notes=reason,
            provenance={"source_name": source_name},
        )
        source_row = connection.execute("SELECT * FROM assessment_findings WHERE id = ?", (source["id"],)).fetchone()
        target_row = connection.execute("SELECT * FROM assessment_findings WHERE id = ?", (target["id"],)).fetchone()
        assert source_row is not None and target_row is not None
        source_after = _finding_state_snapshot(source_row)
        target_after = _finding_state_snapshot(target_row)
        if _finding_state_changed(source_before, source_after):
            _record_finding_transition(
                connection,
                engagement_id=engagement.id,
                finding_id=int(source["id"]),
                actor=source_name,
                action="workflow_merged",
                before=source_before,
                after=source_after,
                reason_code="merge",
                reason_text=reason,
                artifact_ref="",
                metadata={"target_slug": target_slug},
            )
        if _finding_state_changed(target_before, target_after):
            _record_finding_transition(
                connection,
                engagement_id=engagement.id,
                finding_id=int(target["id"]),
                actor=source_name,
                action="operator_override",
                before=target_before,
                after=target_after,
                reason_code="merge",
                reason_text=f"Merged {source_slug} into {target_slug}: {reason}",
                artifact_ref="",
                metadata={"source_slug": source_slug},
            )
    return {
        "source": _serialize_finding_record(source_row),
        "target": _serialize_finding_record(target_row),
        "link": link,
    }


def list_findings(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT findings.*, merged.slug AS merged_into_slug
            FROM assessment_findings AS findings
            LEFT JOIN assessment_findings AS merged ON merged.id = findings.merged_into_finding_id
            WHERE findings.engagement_id = ?
            ORDER BY
                CASE findings.status
                    WHEN 'exploited' THEN 0
                    WHEN 'active' THEN 1
                    WHEN 'blocked' THEN 2
                    WHEN 'reported' THEN 3
                    WHEN 'draft' THEN 4
                    WHEN 'false_positive' THEN 5
                    WHEN 'merged' THEN 6
                    ELSE 7
                END,
                CASE findings.verification_state
                    WHEN 'verified' THEN 0
                    WHEN 'disputed' THEN 1
                    ELSE 2
                END,
                findings.updated_at DESC,
                findings.id DESC
            """,
            (engagement.id,),
        ).fetchall()
    return [_serialize_finding_record(row) for row in rows]


def list_exploit_candidates(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM assessment_findings
            WHERE engagement_id = ?
            ORDER BY updated_at DESC, id DESC
            """,
            (engagement.id,),
        ).fetchall()

    candidates: list[dict[str, Any]] = []
    for row in rows:
        record = _serialize_finding_record(row)
        workflow_status = record.get("workflow_status", "draft")
        if workflow_status in {"merged", "false_positive", "reported", "exploited"}:
            continue
        if record.get("verification_state") != "verified":
            continue
        if record.get("verification_disposition") not in {"confirmed", "downgraded"}:
            continue
        details = _json_object(record.get("details_json", "{}"))
        severity = _normalize_severity(str(record.get("severity", "info")))
        chain_required = details.get("chain_required") is True
        if SEVERITY_RANK[severity] < SEVERITY_RANK["medium"] and not chain_required:
            continue
        if chain_required and SEVERITY_RANK[severity] < SEVERITY_RANK["medium"]:
            candidate_reason = "verified_chain_required"
        else:
            candidate_reason = f"verified_{severity}"
        record["candidate_reason"] = candidate_reason
        record["chain_required"] = chain_required
        candidates.append(record)

    return sorted(
        candidates,
        key=lambda row: (
            {
                "verified_critical": 0,
                "verified_high": 1,
                "verified_medium": 2,
                "verified_chain_required": 3,
            }.get(str(row.get("candidate_reason", "")), 99),
            str(row.get("slug", "")),
        ),
    )


def coverage_readiness(engagement_id: int) -> dict[str, Any]:
    surfaces = list_surfaces(engagement_id)
    unresolved = [row for row in surfaces if row.get("status") == "discovered"]
    high_risk_deferred = [
        row
        for row in surfaces
        if row.get("status") == "deferred"
        and row.get("surface_type") in {"account_recovery", "dynamic_render", "object_reference", "privileged_write"}
    ]
    blocker_count = len(unresolved) + len(high_risk_deferred)
    return {
        "ready": blocker_count == 0,
        "blocker_count": blocker_count,
        "unresolved_surfaces": unresolved,
        "high_risk_deferred_surfaces": high_risk_deferred,
    }


def _report_candidate_records(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM assessment_findings
            WHERE engagement_id = ?
              AND status NOT IN ('merged', 'false_positive')
            ORDER BY updated_at DESC, id DESC
            """,
            (engagement.id,),
        ).fetchall()
    return [_serialize_finding_record(row) for row in rows]


def report_readiness(engagement_id: int) -> dict[str, Any]:
    coverage = coverage_readiness(engagement_id)
    blockers: list[dict[str, Any]] = []
    if not coverage["ready"]:
        blockers.append(
            {
                "kind": "coverage",
                "detail": "Coverage blockers remain",
                "blocker_count": coverage["blocker_count"],
            }
        )

    reportable_statuses = {"active", "blocked", "exploited", "reported"}
    candidates = [
        row
        for row in _report_candidate_records(engagement_id)
        if row.get("workflow_status") in reportable_statuses
    ]

    for row in candidates:
        if row.get("verification_state") != "verified":
            blockers.append(
                {
                    "kind": "finding_verification_state",
                    "slug": row.get("slug", ""),
                    "title": row.get("title", ""),
                    "detail": f"verification_state={row.get('verification_state', 'unknown')}",
                }
            )
            continue
        if row.get("verification_disposition") not in {"confirmed", "downgraded"}:
            blockers.append(
                {
                    "kind": "finding_verification_disposition",
                    "slug": row.get("slug", ""),
                    "title": row.get("title", ""),
                    "detail": f"verification_disposition={row.get('verification_disposition', 'unknown')}",
                }
            )

    duplicate_groups: dict[tuple[str, str], list[str]] = {}
    root_cause_groups: dict[str, list[str]] = {}
    for row in candidates:
        slug = str(row.get("slug", ""))
        root_cause_key = str(row.get("root_cause_key", "") or "").strip()
        if root_cause_key:
            root_cause_groups.setdefault(root_cause_key, []).append(slug)
        location = str(row.get("canonical_location", "") or "").strip()
        defect_family = str(row.get("defect_family", "") or "").strip()
        if location and defect_family:
            duplicate_groups.setdefault((location, defect_family), []).append(slug)

    for root_cause_key, slugs in root_cause_groups.items():
        if len(slugs) > 1:
            blockers.append(
                {
                    "kind": "duplicate_root_cause",
                    "slugs": sorted(slugs),
                    "detail": f"root_cause_key={root_cause_key}",
                }
            )
    for (location, defect_family), slugs in duplicate_groups.items():
        if len(slugs) > 1:
            blockers.append(
                {
                    "kind": "duplicate_location_family",
                    "slugs": sorted(slugs),
                    "detail": f"{defect_family} @ {location}",
                }
            )

    return {
        "ready": len(blockers) == 0,
        "blocker_count": len(blockers),
        "blockers": blockers,
        "coverage": coverage,
    }


def list_report_findings(engagement_id: int, *, mode: str = "draft") -> list[dict[str, Any]]:
    """Return findings formatted for report generation.

    Excludes merged and false-positive findings, orders by severity (critical
    first), and extracts structured fields from the ``details_json`` blob so
    the report-writer has them at the top level without manual JSON parsing:
    CVSS, remediation, steps_to_reproduce, CWE, OWASP, impact, evidence,
    entry_point, sink, poc_code, poc_request, poc_response, and references.
    """
    rows = _report_candidate_records(engagement_id)
    if mode == "draft":
        rows = [row for row in rows if row.get("verification_state") != "disputed"]
    elif mode == "final":
        rows = [
            row
            for row in rows
            if row.get("workflow_status") in {"active", "blocked", "exploited", "reported"}
            and row.get("verification_state") == "verified"
            and row.get("verification_disposition") in {"confirmed", "downgraded"}
        ]
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"unsupported report mode: {mode}")

    rows.sort(
        key=lambda row: (
            {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
            }.get(str(row.get("severity", "")), 5),
            {
                "exploited": 0,
                "active": 1,
                "reported": 2,
                "blocked": 3,
                "draft": 4,
            }.get(str(row.get("workflow_status", "")), 5),
            -int(row.get("id", 0)),
        )
    )

    results: list[dict[str, Any]] = []
    for idx, row in enumerate(rows, start=1):
        record = dict(row)
        details = _json_object(record.get("details_json", "{}"))
        record["report_id"] = f"FINDING-{idx:03d}"
        record["cvss_vector"] = details.get("cvss_vector", "")
        record["cvss_score"] = details.get("cvss_score")
        record["remediation"] = details.get("remediation", "")
        record["steps_to_reproduce"] = details.get("steps_to_reproduce", [])
        record["cwe_id"] = details.get("cwe_id", "")
        record["owasp_category"] = details.get("owasp_category", "")
        record["impact"] = details.get("impact", record.get("summary", ""))
        record["evidence_detail"] = details.get("evidence", "")
        record["entry_point"] = details.get("entry_point", "")
        record["sink"] = details.get("sink", "")
        record["poc_code"] = details.get("poc_code", "")
        raw_req = details.get("poc_request")
        record["poc_request"] = raw_req if isinstance(raw_req, dict) else None
        raw_resp = details.get("poc_response")
        record["poc_response"] = raw_resp if isinstance(raw_resp, dict) else None
        raw_refs = details.get("references", [])
        record["references"] = raw_refs if isinstance(raw_refs, list) else []
        results.append(record)

    return results


def list_finding_transitions(engagement_id: int, *, slug: str) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        finding = connection.execute(
            "SELECT id FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()
        if finding is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
        rows = connection.execute(
            """
            SELECT *
            FROM assessment_finding_transitions
            WHERE engagement_id = ? AND finding_id = ?
            ORDER BY created_at DESC, id DESC
            """,
            (engagement.id, int(finding["id"])),
        ).fetchall()
    return [dict(row) for row in rows]


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
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        finding = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, finding_slug),
        ).fetchone()
        if finding is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
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


def list_finding_links(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
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
            (_append_notes(row["notes"], notes), _merge_object_text(row["provenance_json"], provenance), row["id"]),
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_attack_chains WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))


def list_attack_chain_links(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
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
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_blocked_techniques WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))


def update_coverage_item_status(
    engagement_id: int,
    *,
    coverage_item_id: int,
    status_value: str,
    notes: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    normalized_status = _normalize_coverage_status(status_value)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_coverage_items WHERE id = ? AND engagement_id = ?",
            (coverage_item_id, engagement.id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="coverage item not found")
        connection.execute(
            "UPDATE assessment_coverage_items SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND engagement_id = ?",
            (normalized_status, _append_notes(row["notes"], notes), coverage_item_id, engagement.id),
        )
        if row["service_id"] is not None:
            _refresh_service_coverage_status(connection, engagement.id, int(row["service_id"]))
        updated = connection.execute(
            "SELECT * FROM assessment_coverage_items WHERE id = ?", (coverage_item_id,)
        ).fetchone()
    assert updated is not None
    return dict(updated)


def assessment_summary(engagement_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    exploit_candidate_count = len(list_exploit_candidates(engagement.id))
    coverage_gate = coverage_readiness(engagement.id)
    report_gate = report_readiness(engagement.id)
    with get_connection() as connection:
        target_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_targets WHERE engagement_id = ?", (engagement.id,))
        service_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_services WHERE engagement_id = ?", (engagement.id,))
        request_variant_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_request_variants WHERE engagement_id = ?", (engagement.id,))
        request_observation_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_request_observations WHERE engagement_id = ?", (engagement.id,))
        coverage_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_coverage_items WHERE engagement_id = ?", (engagement.id,))
        probe_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_probe_runs WHERE engagement_id = ?", (engagement.id,))
        finding_count = _scalar_row(
            connection,
            "SELECT COUNT(*) FROM assessment_findings WHERE engagement_id = ? AND status NOT IN ('merged', 'false_positive')",
            (engagement.id,),
        )
        open_surface_count = _scalar_row(
            connection,
            "SELECT COUNT(*) FROM assessment_surfaces WHERE engagement_id = ? AND status IN ('discovered', 'deferred')",
            (engagement.id,),
        )
        credential_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_credentials WHERE engagement_id = ?", (engagement.id,))
        access_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_access_records WHERE engagement_id = ?", (engagement.id,))
        pivot_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_pivots WHERE engagement_id = ?", (engagement.id,))
        tunnel_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_tunnels WHERE engagement_id = ?", (engagement.id,))
        blocked_technique_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_blocked_techniques WHERE engagement_id = ?", (engagement.id,))
        chain_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_attack_chains WHERE engagement_id = ?", (engagement.id,))
        coverage_rows = connection.execute(
            "SELECT status, COUNT(*) AS total FROM assessment_coverage_items WHERE engagement_id = ? GROUP BY status ORDER BY status ASC",
            (engagement.id,),
        ).fetchall()
        finding_rows = connection.execute(
            "SELECT status, COUNT(*) AS total FROM assessment_findings WHERE engagement_id = ? GROUP BY status ORDER BY status ASC",
            (engagement.id,),
        ).fetchall()
        verification_state_rows = connection.execute(
            """
            SELECT verification_state, COUNT(*) AS total
            FROM assessment_findings
            WHERE engagement_id = ?
            GROUP BY verification_state
            ORDER BY verification_state ASC
            """,
            (engagement.id,),
        ).fetchall()
        verification_disposition_rows = connection.execute(
            """
            SELECT verification_disposition, COUNT(*) AS total
            FROM assessment_findings
            WHERE engagement_id = ?
            GROUP BY verification_disposition
            ORDER BY verification_disposition ASC
            """,
            (engagement.id,),
        ).fetchall()
        top_surfaces = connection.execute(
            """
            SELECT *
            FROM assessment_surfaces
            WHERE engagement_id = ?
            ORDER BY
                CASE status
                    WHEN 'discovered' THEN 0
                    WHEN 'deferred' THEN 1
                    WHEN 'covered' THEN 2
                    ELSE 3
                END,
                updated_at DESC
            LIMIT 8
            """,
            (engagement.id,),
        ).fetchall()
        top_findings = connection.execute(
            """
            SELECT slug, title, severity, status, verification_state, verification_disposition, canonical_location, summary, source_name, updated_at
            FROM assessment_findings
            WHERE engagement_id = ?
              AND status NOT IN ('merged', 'false_positive')
            ORDER BY
                CASE status
                    WHEN 'exploited' THEN 0
                    WHEN 'active' THEN 1
                    WHEN 'blocked' THEN 2
                    WHEN 'reported' THEN 3
                    WHEN 'draft' THEN 4
                    ELSE 5
                END,
                updated_at DESC
            LIMIT 10
            """,
            (engagement.id,),
        ).fetchall()
        recent_probes = connection.execute(
            """
            SELECT result_status, attack_family, signal_type, agent_name, evidence_ref, created_at
            FROM assessment_probe_runs
            WHERE engagement_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT 10
            """,
            (engagement.id,),
        ).fetchall()
        open_coverage_items = connection.execute(
            """
            SELECT
                coverage.status,
                coverage.input_slot,
                coverage.attack_family,
                coverage.auth_context,
                coverage.updated_at,
                request_variants.method,
                request_variants.canonical_url,
                services.endpoint AS service_endpoint
            FROM assessment_coverage_items AS coverage
            LEFT JOIN assessment_request_variants AS request_variants ON request_variants.id = coverage.request_variant_id
            LEFT JOIN assessment_services AS services ON services.id = coverage.service_id
            WHERE coverage.engagement_id = ? AND coverage.status IN ('pending', 'queued', 'deferred', 'blocked')
            ORDER BY coverage.updated_at DESC, coverage.id DESC
            LIMIT 12
            """,
            (engagement.id,),
        ).fetchall()
        attack_chains = connection.execute(
            """
            SELECT chain_key, title, status, severity, narrative, updated_at
            FROM assessment_attack_chains
            WHERE engagement_id = ?
            ORDER BY updated_at DESC, id DESC
            LIMIT 8
            """,
            (engagement.id,),
        ).fetchall()
        service_coverage_gaps = connection.execute(
            """
            SELECT services.endpoint, services.service, services.coverage_status, services.updated_at
            FROM assessment_services AS services
            WHERE services.engagement_id = ? AND services.coverage_status IN ('pending', 'partial', 'blocked')
            ORDER BY services.updated_at DESC, services.id DESC
            LIMIT 10
            """,
            (engagement.id,),
        ).fetchall()
    return {
        "target_count": target_count,
        "service_count": service_count,
        "request_variant_count": request_variant_count,
        "request_observation_count": request_observation_count,
        "coverage_count": coverage_count,
        "probe_count": probe_count,
        "finding_count": finding_count,
        "open_surface_count": open_surface_count,
        "credential_count": credential_count,
        "access_count": access_count,
        "pivot_count": pivot_count,
        "tunnel_count": tunnel_count,
        "blocked_technique_count": blocked_technique_count,
        "attack_chain_count": chain_count,
        "exploit_candidate_count": exploit_candidate_count,
        "coverage_blocker_count": int(coverage_gate["blocker_count"]),
        "report_blocker_count": int(report_gate["blocker_count"]),
        "coverage_statuses": {row["status"]: int(row["total"]) for row in coverage_rows},
        "finding_workflow_statuses": {row["status"]: int(row["total"]) for row in finding_rows},
        "finding_verification_states": {row["verification_state"]: int(row["total"]) for row in verification_state_rows},
        "finding_verification_dispositions": {
            row["verification_disposition"]: int(row["total"]) for row in verification_disposition_rows
        },
        "top_surfaces": [dict(row) for row in top_surfaces],
        "top_findings": [_serialize_finding_record(row) for row in top_findings],
        "recent_probes": [dict(row) for row in recent_probes],
        "open_coverage_items": [dict(row) for row in open_coverage_items],
        "attack_chains": [dict(row) for row in attack_chains],
        "service_coverage_gaps": [dict(row) for row in service_coverage_gaps],
    }


# ── Command-run audit ───────────────────────────────────────────────

_DEFAULT_PREVIEW_BYTES = 65_536
_DEFAULT_RETENTION_CONFIG = Path(__file__).resolve().parents[1] / "config" / "command_run_retention.json"
_RUN_UUID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_ARTIFACT_LABEL_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


@lru_cache(maxsize=1)
def _retention_config() -> dict[str, Any]:
    override = os.environ.get("COMMAND_RUN_RETENTION_CONFIG")
    path = Path(override) if override else _DEFAULT_RETENTION_CONFIG
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return {"preview_bytes": _DEFAULT_PREVIEW_BYTES, "suppress_patterns": []}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"preview_bytes": _DEFAULT_PREVIEW_BYTES, "suppress_patterns": []}
    try:
        preview = int(data.get("preview_bytes") or _DEFAULT_PREVIEW_BYTES)
    except (TypeError, ValueError):
        preview = _DEFAULT_PREVIEW_BYTES
    if preview <= 0:
        preview = _DEFAULT_PREVIEW_BYTES
    patterns: list[dict[str, Any]] = []
    for entry in data.get("suppress_patterns") or []:
        if not isinstance(entry, dict):
            continue
        regex_src = entry.get("command_regex", "")
        if not regex_src:
            continue
        try:
            compiled = re.compile(regex_src)
        except re.error:
            continue
        patterns.append(
            {
                "tool_name": entry.get("tool_name", "*"),
                "reason": entry.get("reason", "suppressed"),
                "regex": compiled,
            }
        )
    return {"preview_bytes": preview, "suppress_patterns": patterns}


def _match_suppress_rule(command: str, tool_name: str) -> dict[str, Any] | None:
    config = _retention_config()
    for rule in config["suppress_patterns"]:
        if rule["tool_name"] not in ("*", tool_name):
            continue
        if rule["regex"].search(command):
            return rule
    return None


def _apply_output_retention(
    stream_bytes: bytes,
    *,
    suppression_reason: str,
    preview_bytes: int,
    artifact_writer,
    artifact_label: str,
) -> dict[str, Any]:
    size = len(stream_bytes)
    sha = hashlib.sha256(stream_bytes).hexdigest() if size else ""
    result: dict[str, Any] = {
        "sha256": sha,
        "bytes": size,
        "preview": "",
        "suppression_reason": "",
        "artifact_ref": "",
        "status": "empty",
    }
    if size == 0:
        return result
    if suppression_reason:
        result["suppression_reason"] = suppression_reason
        result["status"] = "suppressed"
        return result
    if size <= preview_bytes:
        result["preview"] = stream_bytes.decode("utf-8", errors="replace")
        result["status"] = "retained"
        return result
    # large — store preview + full artifact
    result["preview"] = stream_bytes[:preview_bytes].decode("utf-8", errors="replace")
    artifact_ref = artifact_writer(artifact_label, stream_bytes)
    result["artifact_ref"] = artifact_ref
    result["status"] = "artifact"
    return result


def _write_command_run_artifact(
    engagement_artifact_dir: str | None,
    run_uuid: str,
) -> Any:
    """Return a closure(label, bytes) → artifact_ref. Empty string when
    disabled. ``engagement_artifact_dir`` is the exact directory files
    land in — callers and the resolver are responsible for any subdir
    conventions (e.g. ``<root>/scans/command-runs/``)."""

    if not engagement_artifact_dir:

        def _noop(_label: str, _data: bytes) -> str:
            return ""

        return _noop

    base = Path(engagement_artifact_dir).expanduser().resolve()

    def _write(label: str, data: bytes) -> str:
        if not _ARTIFACT_LABEL_RE.fullmatch(label):
            raise RuntimeError(f"invalid command-run artifact label: {label}")
        base.mkdir(parents=True, exist_ok=True)
        target = (base / f"{run_uuid}.{label}.log").resolve()
        if target.parent != base:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="command-run artifact path escaped its base directory",
            )
        try:
            with target.open("xb") as handle:
                handle.write(data)
        except FileExistsError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="command-run artifact already exists for run_uuid",
            ) from exc
        return str(target)

    return _write


def _ensure_command_run_uuid_available(run_uuid: str) -> None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id FROM assessment_command_runs WHERE run_uuid = ?",
            (run_uuid,),
        ).fetchone()
    if row:
        _raise_duplicate_command_run_uuid()


def _raise_duplicate_command_run_uuid() -> None:
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="command-run run_uuid already exists",
    )


def _remove_written_command_run_artifacts(*artifact_refs: str) -> None:
    for artifact_ref in artifact_refs:
        if not artifact_ref:
            continue
        try:
            Path(artifact_ref).unlink(missing_ok=True)
        except OSError:
            pass


def _normalize_run_uuid(value: str) -> str:
    run_uuid = str(value or "").strip()
    if not _RUN_UUID_RE.fullmatch(run_uuid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="run_uuid must contain only letters, numbers, underscores, or hyphens",
        )
    return run_uuid


_SHELL_TOOL_WRAPPERS = {"bash", "dash", "ksh", "sh", "zsh"}
_PREFIX_TOOL_WRAPPERS = {
    "command",
    "env",
    "gtimeout",
    "ionice",
    "nice",
    "nohup",
    "stdbuf",
    "sudo",
    "timeout",
}
_SINGLE_ARG_WRAPPER_OPTIONS = {
    "env": {"-C", "--chdir", "-S", "--split-string", "-u", "--unset"},
    "gtimeout": {"-k", "--kill-after", "-s", "--signal"},
    "ionice": {"-c", "--class", "-n", "--classdata"},
    "nice": {"-n", "--adjustment"},
    "stdbuf": {"-e", "-i", "-o"},
    "sudo": {"-C", "-g", "-h", "-p", "-r", "-T", "-t", "-u"},
    "timeout": {"-k", "--kill-after", "-s", "--signal"},
}
_TIMEOUT_DURATION_RE = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")


def _shell_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _is_env_assignment(token: str) -> bool:
    if "=" not in token:
        return False
    name, _value = token.split("=", 1)
    return bool(name) and name.replace("_", "").isalnum()


def _strip_wrapper_options(wrapper: str, tokens: list[str]) -> list[str]:
    remaining = list(tokens)
    options_with_arg = _SINGLE_ARG_WRAPPER_OPTIONS.get(wrapper, set())
    while remaining:
        token = remaining[0]
        if wrapper == "env" and _is_env_assignment(token):
            remaining.pop(0)
            continue
        if not token.startswith("-") or token == "-":
            break
        option = remaining.pop(0)
        option_name = option.split("=", 1)[0]
        if option_name in options_with_arg and "=" not in option and remaining:
            remaining.pop(0)
    if wrapper in {"timeout", "gtimeout"} and remaining and _TIMEOUT_DURATION_RE.fullmatch(remaining[0]):
        remaining.pop(0)
    return remaining


def _derive_tool_bin_from_tokens(tokens: list[str], *, depth: int = 0) -> str:
    if depth > 4:
        return ""
    remaining = list(tokens)
    while remaining:
        token = remaining.pop(0).strip()
        if not token:
            continue
        if _is_env_assignment(token):
            continue
        bare = Path(token).name
        if bare in _SHELL_TOOL_WRAPPERS:
            for idx, arg in enumerate(remaining):
                if arg == "-c" or (arg.startswith("-") and "c" in arg[1:]):
                    if idx + 1 < len(remaining):
                        return _derive_tool_bin_from_tokens(
                            _shell_tokens(remaining[idx + 1]),
                            depth=depth + 1,
                        )
                    break
            return bare
        if bare in _PREFIX_TOOL_WRAPPERS:
            remaining = _strip_wrapper_options(bare, remaining)
            continue
        return bare.split(";", 1)[0].split("|", 1)[0].strip() or bare
    return ""


def _derive_tool_bin(command: str, argv: list[str] | None) -> str:
    """Return the first executable token of the command. The route-derived
    ``tool_name`` collapses every /api/command call to ``command``; tool_bin
    is the discriminator (cat vs curl vs sqlmap) that operator filtering
    actually needs."""
    if argv:
        derived = _derive_tool_bin_from_tokens([str(token) for token in argv])
        if derived:
            return derived
    text = (command or "").strip()
    if not text:
        return ""
    derived = _derive_tool_bin_from_tokens(_shell_tokens(text))
    return derived or text.split()[0]


def _resolve_artifact_dir(engagement, override: str | None) -> str | None:
    root = getattr(engagement, "engagement_root", "") or ""
    if not root:
        return None
    engagement_root = Path(root).expanduser().resolve()
    if override:
        candidate = Path(override).expanduser().resolve()
        try:
            candidate.relative_to(engagement_root)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="engagement_artifact_dir must be inside the engagement root",
            ) from exc
        if candidate == engagement_root:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="engagement_artifact_dir must be an engagement-root subdirectory",
            )
        return str(candidate)
    return str(engagement_root / "scans" / "command-runs")


def record_command_run(
    engagement_id: int,
    *,
    command: str,
    argv: list[str] | None = None,
    tool_name: str,
    route: str = "",
    agent_name: str,
    phase: str,
    return_code: int | None = None,
    timed_out: bool = False,
    success: bool | None = None,
    started_at: str,
    completed_at: str,
    duration_ms: int = 0,
    stdout: str = "",
    stderr: str = "",
    command_hash: str = "",
    stdout_sha256: str = "",
    stderr_sha256: str = "",
    notes: str = "",
    engagement_artifact_dir: str | None = None,
    run_uuid: str | None = None,
    audit_source: str = "header",
    technique: str | None = None,
    intent: str | None = None,
    probe_kind: str | None = None,
    destructive: bool | int | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)

    run_uuid = _normalize_run_uuid(run_uuid or uuid.uuid4().hex)
    _ensure_command_run_uuid_available(run_uuid)
    command_hash = command_hash or hashlib.sha256(command.encode("utf-8", errors="replace")).hexdigest()
    tool_bin = _derive_tool_bin(command, argv)

    effective_success = bool(success) if success is not None else (return_code == 0 and not timed_out)

    config = _retention_config()
    preview_bytes = int(config["preview_bytes"])

    suppress_rule = _match_suppress_rule(command, tool_name)
    suppress_reason = suppress_rule["reason"] if suppress_rule else ""

    effective_artifact_dir = _resolve_artifact_dir(engagement, engagement_artifact_dir)
    artifact_writer = _write_command_run_artifact(effective_artifact_dir, run_uuid)

    stdout_raw = stdout.encode("utf-8", errors="replace") if isinstance(stdout, str) else bytes(stdout or b"")
    stderr_raw = stderr.encode("utf-8", errors="replace") if isinstance(stderr, str) else bytes(stderr or b"")

    stdout_retention = _apply_output_retention(
        stdout_raw,
        suppression_reason=suppress_reason,
        preview_bytes=preview_bytes,
        artifact_writer=artifact_writer,
        artifact_label="stdout",
    )
    stderr_retention = _apply_output_retention(
        stderr_raw,
        suppression_reason=suppress_reason,
        preview_bytes=preview_bytes,
        artifact_writer=artifact_writer,
        artifact_label="stderr",
    )

    stdout_sha256 = stdout_sha256 or stdout_retention["sha256"]
    stderr_sha256 = stderr_sha256 or stderr_retention["sha256"]

    # Row-level retention status rolls up stream statuses.
    statuses = {stdout_retention["status"], stderr_retention["status"]}
    if "artifact" in statuses:
        row_status = "artifact"
    elif "suppressed" in statuses and "retained" not in statuses:
        row_status = "suppressed"
    elif "retained" in statuses:
        row_status = "retained"
    else:
        row_status = "empty"

    # Normalise the four command-metadata fields. Validation is intentionally
    # soft — the API/runtime layer follows the `audit_source` precedent and
    # stores values verbatim so we can add new technique/probe_kind values
    # without a backend redeploy. We only trim/coerce shape here.
    technique_value: str | None
    if technique is None:
        technique_value = None
    else:
        technique_stripped = str(technique).strip()
        technique_value = technique_stripped or None

    intent_value: str | None
    if intent is None:
        intent_value = None
    else:
        intent_stripped = str(intent).strip()
        # Trim to 200 chars server-side — the contract in the plan. The API
        # layer does not enforce max_length because this is the single
        # authoritative trim point.
        intent_value = intent_stripped[:200] or None

    probe_kind_value: str | None
    if probe_kind is None:
        probe_kind_value = None
    else:
        probe_kind_stripped = str(probe_kind).strip()
        probe_kind_value = probe_kind_stripped or None

    destructive_value: int | None
    if destructive is None:
        destructive_value = None
    else:
        destructive_value = 1 if bool(destructive) else 0

    with get_connection() as connection:
        try:
            cursor = connection.execute(
                """
                INSERT INTO assessment_command_runs (
                    engagement_id, run_uuid, command, argv_json, tool_name, tool_bin, route,
                    agent_name, phase, audit_source,
                    return_code, timed_out, success,
                    started_at, completed_at, duration_ms,
                    command_hash, stdout_sha256, stderr_sha256,
                    stdout_preview, stderr_preview, output_retention_status,
                    stdout_suppression_reason, stderr_suppression_reason,
                    stdout_artifact_ref, stderr_artifact_ref,
                    stdout_bytes, stderr_bytes, notes,
                    technique, intent, probe_kind, destructive
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?,
                    ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?
                )
                """,
                (
                    engagement.id,
                    run_uuid,
                    command,
                    json.dumps(list(argv) if argv else [], ensure_ascii=False),
                    tool_name,
                    tool_bin,
                    route,
                    agent_name,
                    phase,
                    audit_source or "header",
                    return_code,
                    1 if timed_out else 0,
                    1 if effective_success else 0,
                    started_at,
                    completed_at,
                    int(duration_ms or 0),
                    command_hash,
                    stdout_sha256,
                    stderr_sha256,
                    stdout_retention["preview"],
                    stderr_retention["preview"],
                    row_status,
                    stdout_retention["suppression_reason"],
                    stderr_retention["suppression_reason"],
                    stdout_retention["artifact_ref"],
                    stderr_retention["artifact_ref"],
                    stdout_retention["bytes"],
                    stderr_retention["bytes"],
                    notes,
                    technique_value,
                    intent_value,
                    probe_kind_value,
                    destructive_value,
                ),
            )
        except sqlite3.IntegrityError as exc:
            if "run_uuid" in str(exc):
                _remove_written_command_run_artifacts(
                    str(stdout_retention["artifact_ref"] or ""),
                    str(stderr_retention["artifact_ref"] or ""),
                )
                _raise_duplicate_command_run_uuid()
            raise
        row = connection.execute(
            "SELECT * FROM assessment_command_runs WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        assert row is not None
        return _serialize_command_run(row, include_output=True)


def _serialize_command_run(row, *, include_output: bool) -> dict[str, Any]:
    data = dict(row)
    try:
        data["argv"] = json.loads(data.pop("argv_json", None) or "[]")
    except json.JSONDecodeError:
        data["argv"] = []
    data["timed_out"] = bool(data.get("timed_out"))
    data["success"] = bool(data.get("success"))
    # Command-metadata fields — surfaced explicitly so callers don't rely on
    # sqlite3.Row dict coercion to include them. Default to None so rows
    # written before this migration (where dict(row) simply won't have the
    # key if the schema matched pre-ALTER) still serialize with a null
    # present. `destructive` is stored as 0/1 INTEGER; coerce back to a
    # Python bool for API consumers, preserving NULL.
    data["technique"] = data.get("technique")
    data["intent"] = data.get("intent")
    data["probe_kind"] = data.get("probe_kind")
    destructive_raw = data.get("destructive")
    if destructive_raw is None:
        data["destructive"] = None
    else:
        data["destructive"] = bool(destructive_raw)
    if not include_output:
        # Listings default to lightweight rows so a sub-agent fetching 50
        # records does not load 50 × 64 KiB of preview text into context.
        # Hashes, suppression reasons, artifact refs, and byte counts stay
        # so the caller can decide whether a follow-up get-command-run is
        # warranted. The full preview is always available via that detail
        # endpoint or by passing include_output=true on the list call.
        stdout_len = len(data.get("stdout_preview") or "")
        stderr_len = len(data.get("stderr_preview") or "")
        data["stdout_preview"] = ""
        data["stderr_preview"] = ""
        data["stdout_preview_chars"] = stdout_len
        data["stderr_preview_chars"] = stderr_len
    return data


def _fts_escape(term: str) -> str:
    """Back-compat shim; real implementation lives in ``services.search``."""
    return _fts_escape_shared(term)


def list_command_runs(
    engagement_id: int,
    *,
    q: str = "",
    agent_name: str = "",
    phase: str = "",
    tool_name: str = "",
    tool_bin: str = "",
    audit_source: str = "",
    success: bool | None = None,
    timed_out: bool | None = None,
    technique: str = "",
    probe_kind: str = "",
    destructive: bool | None = None,
    intent_q: str = "",
    limit: int = 100,
    offset: int = 0,
    include_output: bool = False,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    params: list[Any] = [engagement.id]
    where = ["r.engagement_id = ?"]

    # ``q`` is a global FTS match across all content columns. ``intent_q`` is
    # a scoped FTS match against the intent column only — SQLite FTS5 uses
    # the ``column:term`` syntax for this. When both are provided the
    # queries are AND-combined via an additional MATCH (FTS5 supports two
    # MATCH clauses against the same virtual table via two JOINs; simpler
    # here is to merge them into a single MATCH term joined with AND).
    join_sql = ""
    match_terms: list[str] = []
    fts_term = _fts_escape(q) if q else ""
    if fts_term:
        match_terms.append(fts_term)
    intent_term = _fts_escape(intent_q) if intent_q else ""
    if intent_term:
        # Scope every escaped token to the intent column. ``_fts_escape``
        # returns space-separated quoted phrases (implicit AND); prefixing
        # each with ``intent:`` restricts the match to that column.
        scoped_tokens = [f"intent:{tok}" for tok in intent_term.split(" ") if tok]
        if scoped_tokens:
            match_terms.append(" ".join(scoped_tokens))
    if match_terms:
        join_sql = "JOIN assessment_command_runs_fts f ON f.rowid = r.id"
        where.append("f.assessment_command_runs_fts MATCH ?")
        params.append(" ".join(match_terms))

    if agent_name:
        where.append("r.agent_name = ?")
        params.append(agent_name)
    if phase:
        where.append("r.phase = ?")
        params.append(phase)
    if tool_name:
        where.append("r.tool_name = ?")
        params.append(tool_name)
    if tool_bin:
        where.append("r.tool_bin = ?")
        params.append(tool_bin)
    if audit_source:
        where.append("r.audit_source = ?")
        params.append(audit_source)
    if success is not None:
        where.append("r.success = ?")
        params.append(1 if success else 0)
    if timed_out is not None:
        where.append("r.timed_out = ?")
        params.append(1 if timed_out else 0)
    if technique:
        where.append("r.technique = ?")
        params.append(technique)
    if probe_kind:
        where.append("r.probe_kind = ?")
        params.append(probe_kind)
    if destructive is not None:
        where.append("r.destructive = ?")
        params.append(1 if destructive else 0)

    params.extend([int(limit), int(offset)])
    query = (
        f"SELECT r.* FROM assessment_command_runs r {join_sql} "
        f"WHERE {' AND '.join(where)} "
        "ORDER BY r.created_at DESC, r.id DESC LIMIT ? OFFSET ?"
    )

    with get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [_serialize_command_run(row, include_output=include_output) for row in rows]


def get_command_run(engagement_id: int, command_run_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_command_runs WHERE engagement_id = ? AND id = ?",
            (engagement.id, int(command_run_id)),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="command run not found")
    return _serialize_command_run(row, include_output=True)
