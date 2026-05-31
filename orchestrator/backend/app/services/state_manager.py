from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sqlite3
import uuid
from difflib import get_close_matches
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, status

from ..db import get_connection
from .artifact_index import _normalize_relative_path
from .events import _engagement_or_404
from .search import (
    canonical_finding_alias,
    expanded_fts_query,
    finding_aliases_in_text,
    fts_escape as _fts_escape_shared,
    is_canonical_finding_slug,
)

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
WORKFLOW_STATUSES = {
    "draft",
    "active",
    "blocked",
    "exploited",
    "contained",
    "eradicated",
    "recovered",
    "false_positive",
    "merged",
    "reported",
}
WORKFLOW_STATUS_RANK = {
    "draft": 0,
    "active": 1,
    "blocked": 2,
    "exploited": 3,
    # Blue IR response phases sit between exploited and reported. They are
    # monotonically increasing (contained < eradicated < recovered) so the
    # standard "incoming must not regress" guard at line 186 below blocks an
    # accidental rollback (e.g., eradicated → contained) without an operator
    # reset.
    "contained": 4,
    "eradicated": 5,
    "recovered": 6,
    "reported": 7,
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
ROOT_CAUSE_LINK_KIND = "root_cause"
ROOT_CAUSE_EFFECTS = {"eliminates_finding", "eliminates_attack_path"}
_COVERAGE_STATUS_SYNONYMS = {
    "done": "covered",
    "not-applicable": "not_applicable",
    "n/a": "not_applicable",
    "tested": "covered",
}
COVERAGE_STATUSES = {"pending", "queued", "deferred", "covered", "not_applicable", "blocked"}
SLUG_RE = re.compile(r"[^a-z0-9]+")
_FINDING_PREFIX_BY_SOURCE = {
    "exploit-developer": "EX",
    "vulnerability-analyst": "VA",
    "source-analyzer": "SA",
    "recon-specialist": "RE",
    "fuzzer": "FZ",
    "osint-analyst": "OS",
    "code-architect": "CA",
    "code-vuln-hunter": "CH",
    "code-variant-hunter": "CV",
    "code-vuln-verifier": "VF",
    "surface-collector": "SC",
    "code-fuzz-engineer": "CF",
    "operator": "OP",
    "operator-review": "OR",
}
_TERMINAL_DISPATCH_STATUSES = {"completed", "failed", "aborted", "blocked"}


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


def _coalesce_coverage_status(existing: str, incoming: str, *, explicit_override: bool = False) -> str:
    existing_normalized = _normalize_coverage_status(existing)
    incoming_normalized = _normalize_coverage_status(incoming)
    if explicit_override:
        return incoming_normalized
    if incoming_normalized in {"pending", "queued"} and existing_normalized not in {"pending", "queued"}:
        return existing_normalized
    if existing_normalized == "queued" and incoming_normalized == "pending":
        return existing_normalized
    return incoming_normalized


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
            (resolved_status, _append_notes(row["notes"], notes), row["id"]),
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
    source_slug = _require_canonical_finding_slug(source_slug, field="source_slug")
    target_slug = _require_canonical_finding_slug(target_slug, field="target_slug")
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
                    preserve_existing_status=True,
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

    Operators reach this through ``aith assess resolve-surface`` to mark
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

    with get_connection() as connection:
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


# ── OAST (out-of-band) auto-correlation ──────────────────────────────────
#
# ``aith oob mint`` records a probe (the unique ``nonce`` subdomain label is
# the correlation token). ``aith oob poll`` parses the shared
# interactsh-client log and records each observed callback against the
# probe whose nonce appears in the callback host. See db.py
# :func:`_create_oob_correlation_tables` and src/ai_threat_hunting_cli/oob.py.

_OOB_PROBE_STATUSES = {"pending", "fired", "confirmed", "expired", "ignored"}


def record_oob_probe(
    engagement_id: int,
    *,
    nonce: str,
    target_url: str = "",
    param: str = "",
    technique: str = "",
    probe_kind: str = "",
    request_hash: str = "",
    oob_domain: str = "",
    notes: str = "",
    status_value: str = "pending",
) -> dict[str, Any]:
    """Insert (or idempotently re-fetch) an OAST probe keyed on ``nonce``.

    The nonce is globally unique (UNIQUE constraint). A repeat mint of the
    same nonce returns the existing row rather than erroring, so a retried
    CLI call is safe. Metadata fields are only filled in on the insert; an
    existing row is left untouched (the callback correlation, not the mint,
    is the mutable surface).
    """
    engagement = _engagement_or_404(engagement_id)
    nonce = str(nonce or "").strip()
    if not nonce:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="oob probe requires a non-empty nonce",
        )
    if status_value not in _OOB_PROBE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid oob probe status '{status_value}'; allowed: {sorted(_OOB_PROBE_STATUSES)}",
        )
    with get_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM assessment_oob_probes WHERE engagement_id = ? AND nonce = ?",
            (engagement.id, nonce),
        ).fetchone()
        if existing is not None:
            return dict(existing)
        # Guard against a nonce already claimed by a different engagement —
        # the column is globally UNIQUE so the insert would otherwise raise
        # an opaque IntegrityError.
        collision = connection.execute(
            "SELECT engagement_id FROM assessment_oob_probes WHERE nonce = ?",
            (nonce,),
        ).fetchone()
        if collision is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"oob nonce '{nonce}' already recorded for another engagement",
            )
        connection.execute(
            """
            INSERT INTO assessment_oob_probes (
                engagement_id, nonce, target_url, param, technique,
                probe_kind, request_hash, oob_domain, notes, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                nonce,
                target_url,
                param,
                technique,
                probe_kind,
                request_hash,
                oob_domain,
                notes,
                status_value,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_oob_probes WHERE engagement_id = ? AND nonce = ?",
            (engagement.id, nonce),
        ).fetchone()
        assert row is not None
        return dict(row)


def list_oob_probes(engagement_id: int, *, status_value: str | None = None) -> list[dict[str, Any]]:
    """Return OAST probes for an engagement, newest first, with their
    interaction count and most recent observed callback time embedded."""
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        if status_value is not None:
            rows = connection.execute(
                """
                SELECT * FROM assessment_oob_probes
                WHERE engagement_id = ? AND status = ?
                ORDER BY created_at DESC, id DESC
                """,
                (engagement.id, status_value),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT * FROM assessment_oob_probes
                WHERE engagement_id = ?
                ORDER BY created_at DESC, id DESC
                """,
                (engagement.id,),
            ).fetchall()
        probes: list[dict[str, Any]] = []
        for row in rows:
            probe = dict(row)
            agg = connection.execute(
                """
                SELECT COUNT(*) AS n, MAX(observed_at) AS last_seen
                FROM assessment_oob_interactions
                WHERE probe_id = ?
                """,
                (probe["id"],),
            ).fetchone()
            probe["interaction_count"] = int(agg["n"] or 0)
            probe["last_interaction_at"] = agg["last_seen"] or ""
            probes.append(probe)
        return probes


def get_oob_probe_by_nonce(engagement_id: int, nonce: str) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_oob_probes WHERE engagement_id = ? AND nonce = ?",
            (engagement.id, str(nonce or "").strip()),
        ).fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"oob probe nonce='{nonce}' not found",
            )
        probe = dict(row)
        interactions = connection.execute(
            """
            SELECT * FROM assessment_oob_interactions
            WHERE probe_id = ?
            ORDER BY observed_at ASC, id ASC
            """,
            (probe["id"],),
        ).fetchall()
        probe["interactions"] = [dict(item) for item in interactions]
        return probe


def correlate_oob_interaction(
    engagement_id: int,
    *,
    nonce: str,
    protocol: str = "",
    remote_address: str = "",
    query_type: str = "",
    raw_request: str = "",
    observed_at: str = "",
) -> dict[str, Any]:
    """Record a single observed callback against the probe owning ``nonce``.

    Returns ``{"matched": bool, "probe": {...}|None, "interaction": {...}|None,
    "duplicate": bool}``. Unknown nonces return ``matched=False`` (the caller —
    ``aith oob poll`` — collects those into an "unmatched interactions"
    section) rather than 404, so a single poll over a mixed log never aborts
    on the first stray callback. Recording a probe's first interaction flips
    its status ``pending`` → ``fired``. Duplicate callbacks (same
    interaction hash) are deduped via the UNIQUE(probe_id, interaction_hash)
    constraint and reported with ``duplicate=True``.
    """
    engagement = _engagement_or_404(engagement_id)
    nonce = str(nonce or "").strip()
    with get_connection() as connection:
        probe_row = connection.execute(
            "SELECT * FROM assessment_oob_probes WHERE engagement_id = ? AND nonce = ?",
            (engagement.id, nonce),
        ).fetchone()
        if probe_row is None:
            return {"matched": False, "probe": None, "interaction": None, "duplicate": False}
        probe = dict(probe_row)
        interaction_hash = hashlib.sha256(
            "|".join(
                [
                    nonce,
                    str(protocol or ""),
                    str(remote_address or ""),
                    str(query_type or ""),
                    str(observed_at or ""),
                    str(raw_request or ""),
                ]
            ).encode("utf-8")
        ).hexdigest()
        existing = connection.execute(
            "SELECT * FROM assessment_oob_interactions WHERE probe_id = ? AND interaction_hash = ?",
            (probe["id"], interaction_hash),
        ).fetchone()
        if existing is not None:
            return {
                "matched": True,
                "duplicate": True,
                "probe": probe,
                "interaction": dict(existing),
            }
        connection.execute(
            """
            INSERT INTO assessment_oob_interactions (
                engagement_id, probe_id, protocol, remote_address,
                query_type, raw_request, interaction_hash, observed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                probe["id"],
                protocol,
                remote_address,
                query_type,
                raw_request,
                interaction_hash,
                observed_at,
            ),
        )
        # First confirmed callback flips a pending probe to 'fired'. Decided
        # states (confirmed / expired / ignored) are left untouched so an
        # operator verdict is not silently reverted by a late poll.
        if str(probe["status"] or "") == "pending":
            connection.execute(
                "UPDATE assessment_oob_probes SET status = 'fired', updated_at = CURRENT_TIMESTAMP "
                "WHERE id = ?",
                (probe["id"],),
            )
        interaction_row = connection.execute(
            "SELECT * FROM assessment_oob_interactions WHERE probe_id = ? AND interaction_hash = ?",
            (probe["id"], interaction_hash),
        ).fetchone()
        probe_after = connection.execute(
            "SELECT * FROM assessment_oob_probes WHERE id = ?",
            (probe["id"],),
        ).fetchone()
        return {
            "matched": True,
            "duplicate": False,
            "probe": dict(probe_after),
            "interaction": dict(interaction_row) if interaction_row else None,
        }


def _finding_slug(
    connection,
    engagement_id: int,
    slug: str | None,
    title: str,
    canonical_location: str,
    source_name: str,
) -> str:
    if slug:
        _require_canonical_finding_slug(slug, field="slug")
        return slug
    prefix = _FINDING_PREFIX_BY_SOURCE.get(str(source_name or "").strip())
    if not prefix:
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
    rows = connection.execute(
        "SELECT slug FROM assessment_findings WHERE engagement_id = ? AND slug LIKE ?",
        (engagement_id, f"{prefix}-%"),
    ).fetchall()
    max_id = 0
    for row in rows:
        row_slug = str(row["slug"] or "")
        if is_canonical_finding_slug(row_slug) and row_slug.startswith(f"{prefix}-"):
            max_id = max(max_id, int(row_slug.rsplit("-", 1)[1]))
    return f"{prefix}-{max_id + 1:03d}"


def _require_canonical_finding_slug(slug: str | None, *, field: str = "finding_slug") -> str:
    value = str(slug or "").strip()
    if not is_canonical_finding_slug(value):
        alias = canonical_finding_alias(value)
        suggestion = f"; did you mean {alias}?" if alias and alias != value else ""
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field} must be canonical <PREFIX>-<at least 3 digits> (example VA-047){suggestion}",
        )
    return value


def _require_canonical_finding_slugs(slugs: list[str] | None, *, field: str = "finding_slugs") -> list[str] | None:
    if slugs is None:
        return None
    return [_require_canonical_finding_slug(str(slug), field=field) for slug in slugs]


def _finding_not_found(connection, engagement_id: int, slug: str) -> HTTPException:
    rows = connection.execute(
        "SELECT slug FROM assessment_findings WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchall()
    candidates = [str(row["slug"]) for row in rows]
    close = get_close_matches(slug, candidates, n=3, cutoff=0.55)
    detail = f"finding not found: {slug}"
    if close:
        detail += "; close matches: " + ", ".join(close)
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


def _resolve_existing_finding_slug(
    connection,
    engagement_id: int,
    slug: str | None,
    *,
    field: str = "finding_slug",
) -> str:
    value = str(slug or "").strip()
    lookup = canonical_finding_alias(value) or value
    if lookup:
        row = connection.execute(
            "SELECT slug FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement_id, lookup),
        ).fetchone()
        if row is not None:
            return str(row["slug"])
    if canonical_finding_alias(value):
        raise _finding_not_found(connection, engagement_id, lookup)
    _require_canonical_finding_slug(value, field=field)
    raise _finding_not_found(connection, engagement_id, value)


def _normalize_report_evidence_ref(root: Path, evidence_ref: str) -> str:
    try:
        return _normalize_relative_path(root, evidence_ref)
    except HTTPException:
        return evidence_ref


def _require_terminal_dispatch_status(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    if normalized not in _TERMINAL_DISPATCH_STATUSES:
        allowed = ", ".join(sorted(_TERMINAL_DISPATCH_STATUSES))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"closed_dispatch_status must be terminal ({allowed})",
        )
    return normalized


def _ensure_finding_slugs_exist(connection, engagement_id: int, slugs: list[str] | None) -> None:
    if not slugs:
        return
    for slug in slugs:
        if not connection.execute(
            "SELECT 1 FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement_id, slug),
        ).fetchone():
            raise _finding_not_found(connection, engagement_id, slug)


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
        (
            """
            SELECT *
            FROM assessment_findings
            WHERE engagement_id = ?
              AND status != 'merged'
              AND title = ?
              AND canonical_location = ?
              AND auth_context = ?
            """
            + (" AND defect_family = ?" if defect_family else "")
            + """
            ORDER BY CASE WHEN status = 'false_positive' THEN 0 ELSE 1 END, id ASC
            LIMIT 1
            """
        ),
        (
            (engagement_id, title, canonical_location, auth_context, defect_family)
            if defect_family
            else (engagement_id, title, canonical_location, auth_context)
        ),
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
    evidence_type: str | None = None,
    request_variant_id: int | None,
    service_id: int | None,
    surface_id: int | None,
    links: list[dict[str, Any]] | None,
    explicit_workflow_override: bool = False,
    explicit_verification_state_override: bool = False,
    explicit_verification_disposition_override: bool = False,
    explicit_severity_override: bool = False,
    allow_existing_noncanonical_slug: bool = False,
    transition_action: str | None = None,
    transition_reason_code: str = "",
    transition_reason_text: str = "",
    transition_artifact_ref: str = "",
    transition_metadata: dict[str, Any] | None = None,
    expected_updated_at: str | None = None,
    notes_mode: str = "append",
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if slug:
        slug = str(slug).strip()
        if not allow_existing_noncanonical_slug:
            slug = _require_canonical_finding_slug(slug, field="slug")
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
            resolved_slug = _finding_slug(connection, engagement.id, slug, title, canonical_location, source_name)
            cursor = connection.execute(
                """
                INSERT INTO assessment_findings (
                    engagement_id, slug, title, severity, status, verification_state, verification_disposition, defect_family, root_cause_key, auth_context,
                    canonical_location, source_name, summary, evidence_ref, notes, details_json, provenance_json, evidence_type
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    evidence_type,
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
                    evidence_type = COALESCE(?, evidence_type),
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
                    # Default appends (record-finding/verify-finding checkpoints);
                    # notes_mode="replace" overwrites so stale text can be scrubbed.
                    notes if notes_mode == "replace" else _append_notes(existing["notes"], notes),
                    _merge_object_text(existing["details_json"], details),
                    _merge_object_text(existing["provenance_json"], provenance),
                    evidence_type,
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
    if evidence_ref:
        artifact_id = _register_artifact_reference(
            engagement.id,
            evidence_ref,
            kind="evidence",
            producer_agent_role=source_name or None,
            related_finding_slug=str(finding["slug"]),
        )
        with get_connection() as connection:
            connection.execute(
                "UPDATE assessment_findings SET evidence_artifact_id = ? WHERE id = ?",
                (artifact_id, int(finding["id"])),
            )
            finding = connection.execute(
                "SELECT * FROM assessment_findings WHERE id = ?",
                (int(finding["id"]),),
            ).fetchone()
    for link in finding_links:
        if str(link.get("target_kind") or "") in {"evidence_artifact", "artifact"} and link.get("target_ref"):
            _register_artifact_reference(
                engagement.id,
                str(link.get("target_ref") or ""),
                kind="evidence",
                producer_agent_role=source_name or None,
                related_finding_slug=str(finding["slug"]),
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
    evidence_type: str | None = None,
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
        evidence_type=evidence_type,
        request_variant_id=None,
        service_id=None,
        surface_id=None,
        links=None,
        explicit_workflow_override=workflow_status is not None,
        explicit_verification_state_override=verification_state is not None,
        explicit_verification_disposition_override=verification_disposition is not None,
        explicit_severity_override=severity is not None,
        allow_existing_noncanonical_slug=True,
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
    evidence_type: str | None = None,
    transition_action: str | None = None,
    transition_reason_code: str = "",
    transition_reason_text: str = "",
    transition_artifact_ref: str = "",
    transition_metadata: dict[str, Any] | None = None,
    allow_verification_mutation: bool = False,
    expected_updated_at: str | None = None,
    notes_mode: str = "append",
) -> dict[str, Any]:
    if notes_mode == "replace" and notes is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="notes_mode='replace' requires notes",
        )

    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        slug = _resolve_existing_finding_slug(connection, engagement.id, slug)
        existing = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()

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
        evidence_type=evidence_type,
        request_variant_id=None,
        service_id=None,
        surface_id=None,
        links=None,
        explicit_workflow_override=workflow_status is not None,
        explicit_verification_state_override=verification_state is not None,
        explicit_verification_disposition_override=verification_disposition is not None,
        explicit_severity_override=severity is not None,
        allow_existing_noncanonical_slug=True,
        transition_action=transition_action,
        transition_reason_code=transition_reason_code,
        transition_reason_text=transition_reason_text,
        transition_artifact_ref=transition_artifact_ref,
        transition_metadata=transition_metadata,
        expected_updated_at=expected_updated_at or current_updated_at,
        notes_mode=notes_mode,
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
        slug = _resolve_existing_finding_slug(connection, engagement.id, slug)
        existing = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()

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

    result = patch_finding(
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
    if artifact_ref:
        _register_artifact_reference(
            engagement.id,
            artifact_ref,
            kind="verification-artifact",
            producer_agent_role=source_name or None,
            related_finding_slug=slug,
        )
    return result


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
            missing = source_slug if source is None else target_slug
            raise _finding_not_found(connection, engagement.id, missing)
        if source["id"] == target["id"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="cannot merge a finding into itself")
        if _row_workflow_status(target) == "false_positive" and _row_workflow_status(source) != "false_positive":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="cannot merge a live finding into a false_positive target",
            )
        source_children = connection.execute(
            """
            SELECT findings.slug
            FROM assessment_finding_links AS links
            JOIN assessment_findings AS findings ON findings.id = links.finding_id
            WHERE links.engagement_id = ?
              AND links.link_kind = ?
              AND links.target_kind = 'finding'
              AND links.target_ref = ?
              AND findings.status != 'merged'
            """,
            (engagement.id, ROOT_CAUSE_LINK_KIND, source_slug),
        ).fetchall()
        if source_children:
            child_slugs = ", ".join(str(row["slug"]) for row in source_children)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cannot merge root cause {source_slug} while siblings remain linked: {child_slugs}",
            )
        source_root_link = connection.execute(
            """
            SELECT target_ref
            FROM assessment_finding_links
            WHERE engagement_id = ?
              AND finding_id = ?
              AND link_kind = ?
              AND target_kind = 'finding'
            LIMIT 1
            """,
            (engagement.id, int(source["id"]), ROOT_CAUSE_LINK_KIND),
        ).fetchone()
        if source_root_link is not None and str(source_root_link["target_ref"]) != target_slug:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"cannot merge sibling {source_slug} into {target_slug}; "
                    f"clear or relink its root cause first"
                ),
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
            if _is_root_cause_link(row):
                continue
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


def get_finding(engagement_id: int, slug: str) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    slug = canonical_finding_alias(slug) or slug
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT findings.*, merged.slug AS merged_into_slug
            FROM assessment_findings AS findings
            LEFT JOIN assessment_findings AS merged ON merged.id = findings.merged_into_finding_id
            WHERE findings.engagement_id = ? AND findings.slug = ?
            """,
            (engagement.id, slug),
        ).fetchone()
        if row is None:
            raise _finding_not_found(connection, engagement.id, slug)
    return _serialize_finding_record(row)


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
    partially_covered = [
        row for row in surfaces if row.get("status") == "partially-covered"
    ]
    high_risk_deferred = [
        row
        for row in surfaces
        if row.get("status") == "deferred"
        and row.get("surface_type") in {"account_recovery", "dynamic_render", "object_reference", "privileged_write"}
    ]
    blocker_count = len(unresolved) + len(partially_covered) + len(high_risk_deferred)
    return {
        "ready": blocker_count == 0,
        "blocker_count": blocker_count,
        "unresolved_surfaces": unresolved,
        "partially_covered_surfaces": partially_covered,
        "high_risk_deferred_surfaces": high_risk_deferred,
    }


# ---------------------------------------------------------------------------
# C40 — outcome-based per-host coverage projection
#
# The five sub-objectives the recon phase nominally produces per host. None of
# them check `assessment_command_runs` — every signal is a row in an outcome
# table the specialists are already writing to. That is the contract: rename
# wafw00f → wafw00f-ng tomorrow and the gate keeps working as long as the
# tech-component row still gets recorded.
# ---------------------------------------------------------------------------


PER_HOST_OBJECTIVES: tuple[str, ...] = (
    "waf_tier",
    "service_inventory",
    "directory_fuzz",
    "nikto_trigger",
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

    Mirrors `_endpoint_host` in `check_scope_coverage.py` but the CLI version
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
    with get_connection() as connection:
        cursor = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions "
            "WHERE engagement_id = ? AND kind = ? AND resolved = 0 "
            "ORDER BY created_at DESC, id DESC",
            (engagement.id, "coverage_deferral"),
        )
        return [_serialize_decision(row) for row in cursor.fetchall()]


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
    4. ``nikto_trigger`` — at least one ``intel_tech_components`` row whose
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

    with get_connection() as connection:
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

    nikto_trigger_rows = [row for row in live_tech_components if _row_is_tech_scan_evidence(row)]
    engagement_has_nikto_trigger = bool(nikto_trigger_rows)

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

        # nikto_trigger — any fingerprinting-equivalent intel row, host-specific
        # preferred but engagement-level acceptable.
        nikto_host_specific = any(
            _intel_row_references_host(row, host) for row in nikto_trigger_rows
        )
        nikto_met = nikto_host_specific or engagement_has_nikto_trigger
        nikto_evidence: list[str] = []
        for row in nikto_trigger_rows:
            label = str(row.get("source_name") or "").strip() or "unknown"
            host_specific = _intel_row_references_host(row, host)
            nikto_evidence.append(f"{label}{'(host)' if host_specific else ''}")
            if len(nikto_evidence) >= 5:
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
            "nikto_trigger": {
                "met": nikto_met,
                "evidence": nikto_evidence,
                "deferred": "nikto_trigger" in deferred_objectives,
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
            }
        )

    return {
        "objectives": list(PER_HOST_OBJECTIVES),
        "hosts": host_outcomes,
        "engagement_signals": {
            "waf_intel_count": len(waf_rows),
            "tech_scan_intel_count": len(nikto_trigger_rows),
            "osint_intel_total": len(live_tech_components) + int(people_count) + int(breach_count),
        },
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
    engagement = _engagement_or_404(engagement_id)
    is_blue = str(getattr(engagement, "engagement_type", "") or "").lower() == "blue"
    engagement_root = Path(engagement.engagement_root).expanduser().resolve()
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

    reportable_statuses = {"active", "blocked", "exploited", "contained", "eradicated", "recovered", "reported"}
    candidates = [
        row
        for row in _report_candidate_records(engagement_id)
        if row.get("workflow_status") in reportable_statuses
    ]
    candidate_slugs = {str(row.get("slug", "")) for row in candidates if row.get("slug")}
    with get_connection() as connection:
        root_link_rows = connection.execute(
            """
            SELECT links.*, findings.slug AS finding_slug
            FROM assessment_finding_links AS links
            JOIN assessment_findings AS findings ON findings.id = links.finding_id
            WHERE links.engagement_id = ?
              AND links.link_kind = ?
              AND links.target_kind = 'finding'
            """,
            (engagement_id, ROOT_CAUSE_LINK_KIND),
        ).fetchall()
    root_link_by_slug = {
        str(row["finding_slug"]): str(row["target_ref"])
        for row in root_link_rows
        if str(row["finding_slug"]) in candidate_slugs
    }

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

    for row in candidates:
        if row.get("verification_state") != "verified":
            continue
        if row.get("verification_disposition") not in {"confirmed", "downgraded"}:
            continue
        slug = row.get("slug", "")
        title = row.get("title", "")
        details = _json_object(row.get("details_json", "{}"))
        missing_fields: list[str] = []
        if is_blue:
            mitre = details.get("mitre_techniques")
            if not isinstance(mitre, list) or not mitre:
                missing_fields.append("mitre_techniques")
        else:
            if not details.get("cvss_score") and details.get("cvss_score") != 0:
                missing_fields.append("cvss_score")
            if not details.get("cvss_vector"):
                missing_fields.append("cvss_vector")
            if not details.get("steps_to_reproduce"):
                missing_fields.append("steps_to_reproduce")
            if not details.get("remediation"):
                missing_fields.append("remediation")
        if not details.get("impact"):
            missing_fields.append("impact")
        if not details.get("evidence"):
            missing_fields.append("evidence")
        if missing_fields:
            blockers.append(
                {
                    "kind": "finding_field_quality",
                    "slug": slug,
                    "title": title,
                    "detail": f"missing structured fields: {', '.join(missing_fields)}",
                }
            )
        cvss_score = details.get("cvss_score")
        severity = str(row.get("severity", "")).lower()
        if not is_blue and cvss_score is not None and severity:
            try:
                score = float(cvss_score)
            except (TypeError, ValueError):
                score = -1
            expected = (
                "critical" if score >= 9.0
                else "high" if score >= 7.0
                else "medium" if score >= 4.0
                else "low" if score >= 0.1
                else "info"
            )
            if score >= 0 and severity != expected:
                blockers.append(
                    {
                        "kind": "severity_cvss_mismatch",
                        "slug": slug,
                        "title": title,
                        "detail": f"severity={severity} but cvss_score={score} expects {expected}",
                    }
                )

    for slug, root_slug in sorted(root_link_by_slug.items()):
        if root_slug not in candidate_slugs:
            blockers.append(
                {
                    "kind": "root_cause_root_not_reportable",
                    "slug": slug,
                    "detail": f"root_cause_slug={root_slug} is not reportable",
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
            grouped_roots = {
                root_link_by_slug.get(slug, slug)
                for slug in slugs
            }
            if len(grouped_roots) == 1:
                continue
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

    with get_connection() as connection:
        artifact_rows = {
            str(row["relative_path"]): dict(row)
            for row in connection.execute(
                "SELECT * FROM assessment_artifacts WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
        }
        for artifact_path, artifact in artifact_rows.items():
            lower_path = artifact_path.lower()
            if not (lower_path.startswith("notes/") and lower_path.endswith((".md", ".markdown"))):
                continue
            if not bool(artifact.get("present")):
                continue
            if bool(artifact.get("scratch")):
                # Operator explicitly marked this as scratch — outside the
                # report-readiness contract by design.
                continue
            linked = any(
                artifact.get(field)
                for field in (
                    "related_finding_slug",
                    "related_chain_key",
                    "related_surface_id",
                    "related_request_variant_id",
                    "producer_agent_id",
                    "producer_command_run_id",
                )
            )
            if not linked:
                blockers.append(
                    {
                        "kind": "unlinked_markdown_note",
                        "artifact_id": artifact.get("id"),
                        "path": artifact_path,
                        "detail": (
                            f"markdown note '{artifact_path}' is indexed but not linked to a finding, chain, "
                            "surface, request_variant, command_run, or producing agent. Fix with one of: "
                            f"`aith assess artifact register {artifact_path} --finding <slug>` to link, or "
                            f"`aith assess artifact mark-scratch {artifact_path}` to dismiss as scratch."
                        ),
                    }
                )
        artifact_rows_by_id = {int(a["id"]): a for a in artifact_rows.values() if a.get("id")}
        for row in candidates:
            slug = str(row.get("slug", ""))
            evidence_ref = str(row.get("evidence_ref", "") or "").strip()
            evidence_artifact_id = row.get("evidence_artifact_id")
            linked_evidence_artifact = None

            if evidence_artifact_id is not None:
                linked_evidence_artifact = artifact_rows_by_id.get(int(evidence_artifact_id))
                if linked_evidence_artifact is not None and not bool(linked_evidence_artifact.get("present")):
                    blockers.append(
                        {
                            "kind": "finding_evidence_missing_artifact",
                            "slug": slug,
                            "title": row.get("title", ""),
                            "detail": (
                                f"finding {slug} evidence artifact id={evidence_artifact_id} is indexed "
                                f"but the file is missing on disk. Restore the file and re-register with "
                                f"`aith assess artifact register {linked_evidence_artifact.get('relative_path', '')} --finding {slug}`, "
                                f"or repoint the finding via "
                                f"`aith assess update-finding {slug} --evidence-ref <relative-path>`."
                            ),
                        }
                    )
                    continue

            if not evidence_ref:
                blockers.append(
                    {
                        "kind": "finding_missing_evidence_ref",
                        "slug": slug,
                        "title": row.get("title", ""),
                        "detail": (
                            f"active/reportable finding {slug} has no evidence_ref. "
                            f"Fix with `aith assess update-finding {slug} --evidence-ref <relative-path>` "
                            "after writing the evidence artifact to disk."
                        ),
                    }
                )
                continue
            indexed_evidence_ref = _normalize_report_evidence_ref(engagement_root, evidence_ref)
            artifact = artifact_rows.get(indexed_evidence_ref)
            if artifact is None:
                blockers.append(
                    {
                        "kind": "finding_evidence_unindexed",
                        "slug": slug,
                        "title": row.get("title", ""),
                        "detail": (
                            f"finding {slug} evidence_ref={evidence_ref!r} is not in the artifact index. "
                            f"Fix with `aith assess artifact register {indexed_evidence_ref} --finding {slug}`."
                        ),
                    }
                )
            elif not bool(artifact.get("present")):
                blockers.append(
                    {
                        "kind": "finding_evidence_missing_artifact",
                        "slug": slug,
                        "title": row.get("title", ""),
                        "detail": (
                            f"finding {slug} evidence_ref={evidence_ref!r} is indexed but the file is "
                            f"missing on disk. Restore the file and re-register with "
                            f"`aith assess artifact register {indexed_evidence_ref} --finding {slug}`, "
                            f"or repoint the finding via "
                            f"`aith assess update-finding {slug} --evidence-ref <relative-path>`."
                        ),
                    }
                )
            elif (
                linked_evidence_artifact is not None
                and int(linked_evidence_artifact.get("id") or 0) != int(artifact.get("id") or 0)
            ):
                blockers.append(
                    {
                        "kind": "finding_evidence_artifact_mismatch",
                        "slug": slug,
                        "title": row.get("title", ""),
                        "detail": (
                            f"finding {slug} evidence_ref={evidence_ref!r} resolves to artifact "
                            f"id={artifact.get('id')}, but evidence_artifact_id points to "
                            f"id={evidence_artifact_id} ({linked_evidence_artifact.get('relative_path', '')!r}). "
                            f"Refresh the finding link with "
                            f"`aith assess update-finding {slug} --evidence-ref {indexed_evidence_ref}`."
                        ),
                    }
                )

        chain_links = connection.execute(
            """
            SELECT chains.chain_key, links.entity_kind, links.entity_ref
            FROM assessment_attack_chain_links AS links
            JOIN assessment_attack_chains AS chains ON chains.id = links.chain_id
            WHERE links.engagement_id = ?
            """,
            (engagement_id,),
        ).fetchall()
        for link in chain_links:
            if str(link["entity_kind"]) != "finding":
                blockers.append(
                    {
                        "kind": "chain_step_not_finding_linked",
                        "chain_key": link["chain_key"],
                        "detail": f"chain step entity_kind={link['entity_kind']} must link to a finding slug",
                    }
                )
                continue
            entity_ref = str(link["entity_ref"] or "")
            if not entity_ref or entity_ref not in candidate_slugs:
                blockers.append(
                    {
                        "kind": "chain_step_missing_finding",
                        "chain_key": link["chain_key"],
                        "detail": f"finding step {entity_ref or '<empty>'} is not reportable",
                    }
                )

        handoff_rows = connection.execute(
            """
            SELECT agent_id, finding_slugs_json
            FROM assessment_dispatch_handoffs
            WHERE engagement_id = ? AND finding_slugs_json IS NOT NULL
            """,
            (engagement_id,),
        ).fetchall()
        known_slugs = {
            str(row["slug"])
            for row in connection.execute(
                "SELECT slug FROM assessment_findings WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
        }
        for handoff in handoff_rows:
            try:
                handoff_slugs = json.loads(handoff["finding_slugs_json"] or "[]")
            except json.JSONDecodeError:
                handoff_slugs = []
            if not isinstance(handoff_slugs, list):
                continue
            missing = [str(slug) for slug in handoff_slugs if str(slug) not in known_slugs]
            if missing:
                blockers.append(
                    {
                        "kind": "handoff_unknown_finding",
                        "agent_id": handoff["agent_id"],
                        "slugs": missing,
                        "detail": "handoff references finding slugs not present in backend",
                    }
                )

        stale_ready = connection.execute(
            """
            SELECT dispatches.agent_id, dispatches.agent_role, handoffs.handoff_status
            FROM assessment_dispatches AS dispatches
            JOIN assessment_dispatch_handoffs AS handoffs
              ON handoffs.engagement_id = dispatches.engagement_id
             AND handoffs.agent_id = dispatches.agent_id
            WHERE dispatches.engagement_id = ?
              AND dispatches.status = 'in-progress'
              AND handoffs.handoff_status IN ('ready', 'blocked')
            """,
            (engagement_id,),
        ).fetchall()
        for row in stale_ready:
            blockers.append(
                {
                    "kind": "stale_dispatch_ready_handoff",
                    "agent_id": row["agent_id"],
                    "detail": (
                        f"{row['agent_role']} dispatch {row['agent_id']} has a "
                        f"{row['handoff_status']!r} handoff but is still in-progress. "
                        f"Close with `aith assess agent close {row['agent_id']}` "
                        "or bulk-close ready/blocked stales with "
                        "`aith assess agent reconcile-stale`."
                    ),
                }
            )

    return {
        "ready": len(blockers) == 0,
        "blocker_count": len(blockers),
        "blockers": blockers,
        "coverage": coverage,
    }


def _report_record(record: dict[str, Any], report_id: str) -> dict[str, Any]:
    item = dict(record)
    details = _json_object(item.get("details_json", "{}"))
    item["report_id"] = report_id
    item["cvss_vector"] = details.get("cvss_vector", "")
    item["cvss_score"] = details.get("cvss_score")
    item["remediation"] = details.get("remediation", "")
    item["steps_to_reproduce"] = details.get("steps_to_reproduce", [])
    item["cwe_id"] = details.get("cwe_id", "")
    item["owasp_category"] = details.get("owasp_category", "")
    item["impact"] = details.get("impact", item.get("summary", ""))
    item["evidence_detail"] = details.get("evidence", "")
    item["entry_point"] = details.get("entry_point", "")
    item["sink"] = details.get("sink", "")
    item["poc_code"] = details.get("poc_code", "")
    raw_req = details.get("poc_request")
    item["poc_request"] = raw_req if isinstance(raw_req, dict) else None
    raw_resp = details.get("poc_response")
    item["poc_response"] = raw_resp if isinstance(raw_resp, dict) else None
    raw_refs = details.get("references", [])
    item["references"] = raw_refs if isinstance(raw_refs, list) else []
    return item


def _report_finding_records(engagement_id: int, *, mode: str = "draft") -> list[dict[str, Any]]:
    rows = _report_candidate_records(engagement_id)
    if mode == "draft":
        rows = [row for row in rows if row.get("verification_state") != "disputed"]
    elif mode == "final":
        rows = [
            row
            for row in rows
            if row.get("workflow_status") in {"active", "blocked", "exploited", "contained", "eradicated", "recovered", "reported"}
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
                "contained": 1,
                "eradicated": 2,
                "recovered": 3,
                "active": 4,
                "reported": 5,
                "blocked": 6,
                "draft": 7,
            }.get(str(row.get("workflow_status", "")), 5),
            -int(row.get("id", 0)),
        )
    )
    return [_report_record(row, f"{idx:03d}") for idx, row in enumerate(rows, start=1)]


def list_report_findings(engagement_id: int, *, mode: str = "draft") -> list[dict[str, Any]]:
    """Return findings formatted for report generation.

    Excludes merged and false-positive findings, orders by severity (critical
    first), and extracts structured fields from the ``details_json`` blob so
    the report-writer has them at the top level without manual JSON parsing:
    CVSS, remediation, steps_to_reproduce, CWE, OWASP, impact, evidence,
    entry_point, sink, poc_code, poc_request, poc_response, and references.
    """
    return _report_finding_records(engagement_id, mode=mode)


def list_report_finding_groups(engagement_id: int, *, mode: str = "draft") -> dict[str, Any]:
    records = _report_finding_records(engagement_id, mode=mode)
    by_slug = {str(record.get("slug", "")): record for record in records if record.get("slug")}
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT links.*, findings.slug AS finding_slug
            FROM assessment_finding_links AS links
            JOIN assessment_findings AS findings ON findings.id = links.finding_id
            WHERE links.engagement_id = ?
              AND links.link_kind = ?
              AND links.target_kind = 'finding'
            """,
            (engagement_id, ROOT_CAUSE_LINK_KIND),
        ).fetchall()
    groups: dict[str, dict[str, Any]] = {}
    linked_siblings: set[str] = set()
    for row in rows:
        link = dict(row)
        sibling_slug = str(link.get("finding_slug", "") or "")
        root_slug = str(link.get("target_ref", "") or "")
        sibling = by_slug.get(sibling_slug)
        root = by_slug.get(root_slug)
        if sibling is None or root is None:
            continue
        sibling_record = dict(sibling)
        sibling_record.update(_root_cause_link_metadata(link))
        group = groups.setdefault(
            root_slug,
            {
                "root": root,
                "siblings": [],
                "sibling_count": 0,
                "residual_path_count": 0,
                "highest_severity": root.get("severity", "info"),
            },
        )
        group["siblings"].append(sibling_record)
        linked_siblings.add(sibling_slug)

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

    groups_list = sorted(
        groups.values(),
        key=lambda group: (
            -SEVERITY_RANK.get(str(group.get("highest_severity", "info")), 0),
            str(group["root"].get("report_id", "")),
        ),
    )
    grouped_roots = {str(group["root"].get("slug", "")) for group in groups_list}
    standalone = [
        record for record in records
        if str(record.get("slug", "")) not in linked_siblings
        and str(record.get("slug", "")) not in grouped_roots
    ]
    return {
        "mode": mode,
        "groups": groups_list,
        "standalone": standalone,
        "group_count": len(groups_list),
        "standalone_count": len(standalone),
        "finding_count": len(records),
    }


def list_finding_transitions(engagement_id: int, *, slug: str) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    slug = canonical_finding_alias(slug) or slug
    with get_connection() as connection:
        finding = connection.execute(
            "SELECT id FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()
        if finding is None:
            raise _finding_not_found(connection, engagement.id, slug)
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
    with get_connection() as connection:
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
            LIMIT 1
            """,
            (engagement.id, finding_slug, ROOT_CAUSE_LINK_KIND, int(finding["id"])),
        ).fetchone()
        if finding_is_root is not None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="nested root-cause groups are not supported")

        if sibling_order is None:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM assessment_finding_links
                WHERE engagement_id = ?
                  AND link_kind = ?
                  AND target_kind = 'finding'
                  AND target_ref = ?
                  AND finding_id != ?
                """,
                (engagement.id, ROOT_CAUSE_LINK_KIND, root_cause_slug, int(finding["id"])),
            ).fetchone()
            sibling_order = int(row["total"]) + 1 if row is not None else 1
        if sibling_order < 1:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="sibling_order must be >= 1")

        metadata = dict(provenance or {})
        metadata["sibling_order"] = sibling_order
        metadata["root_cause_effect"] = effect
        if source_name:
            metadata.setdefault("source_name", source_name)

        connection.execute(
            """
            DELETE FROM assessment_finding_links
            WHERE engagement_id = ?
              AND finding_id = ?
              AND link_kind = ?
              AND target_kind = 'finding'
            """,
            (engagement.id, int(finding["id"]), ROOT_CAUSE_LINK_KIND),
        )
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
    result = dict(link)
    result["finding_slug"] = finding_slug
    result.update(_root_cause_link_metadata(result))
    return result


def clear_root_cause_link(engagement_id: int, *, finding_slug: str) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        finding_slug = _resolve_existing_finding_slug(connection, engagement.id, finding_slug)
        finding = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, finding_slug),
        ).fetchone()
        cursor = connection.execute(
            """
            DELETE FROM assessment_finding_links
            WHERE engagement_id = ?
              AND finding_id = ?
              AND link_kind = ?
              AND target_kind = 'finding'
            """,
            (engagement.id, int(finding["id"]), ROOT_CAUSE_LINK_KIND),
        )
    return {"finding_slug": finding_slug, "cleared": int(cursor.rowcount)}


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


def list_finding_groups(engagement_id: int, *, root_slug: str | None = None) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
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
    if evidence_ref:
        artifact_id = _register_artifact_reference(
            engagement.id,
            evidence_ref,
            kind="chain-evidence",
            related_chain_key=str(chain["chain_key"]),
        )
        with get_connection() as connection:
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
    with get_connection() as connection:
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
    ``mixed``, derived from the `403`/`000` ratio in the run output. The
    pattern is informational; the operator confirms the cause via the
    Egress reputation checkpoint.
    """
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
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
            "SELECT COUNT(*) FROM assessment_surfaces WHERE engagement_id = ? AND status IN ('discovered', 'deferred', 'partially-covered')",
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
        "coverage_by_reachability": coverage_rollup(engagement.id),
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
        "vendor_saas_hosts_pending_decision": vendor_saas_hosts_pending_decision(engagement.id),
        "egress_status": egress_block_status(engagement.id),
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


def _register_artifact_reference(engagement_id: int, path: str, **metadata: Any) -> int | None:
    """Register an artifact reference and return the artifact id (or None)."""
    if not path:
        return None
    from .artifact_index import register_reference_if_local

    result = register_reference_if_local(engagement_id, path=path, **metadata)
    if result and result.get("id"):
        return int(result["id"])
    return None


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
_SHELL_COMMAND_SEPARATORS = {"&&", "||", ";", "|", "|&", "&"}
_SHELL_PREAMBLE_BUILTINS = {
    ".",
    "alias",
    "cd",
    "export",
    "local",
    "popd",
    "pushd",
    "readonly",
    "set",
    "shopt",
    "source",
    "typeset",
    "ulimit",
    "umask",
    "unalias",
    "unset",
}


def _shell_tokens(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        return list(lexer)
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
                if _is_shell_command_string_flag(arg):
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
        if bare in _SHELL_PREAMBLE_BUILTINS:
            post_preamble = _skip_shell_preamble_tokens(remaining)
            if post_preamble is not None:
                remaining = post_preamble
                continue
        return bare.split(";", 1)[0].split("|", 1)[0].strip() or bare
    return ""


def _is_shell_command_string_flag(arg: str) -> bool:
    if not arg.startswith("-"):
        return False
    if arg == "-c":
        return True
    if not arg.startswith("-") or arg.startswith("--"):
        return False
    short_flags = arg[1:]
    return bool(short_flags) and short_flags.endswith("c") and set(short_flags) <= {"l", "i", "s", "r", "c"}


def _skip_shell_preamble_tokens(tokens: list[str]) -> list[str] | None:
    for idx, token in enumerate(tokens):
        if token in _SHELL_COMMAND_SEPARATORS:
            return tokens[idx + 1 :]
    return None


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


_DEFAULT_DEDUP_WINDOW_SECONDS = 30


def _dedup_window_seconds() -> int:
    raw = os.environ.get("KALI_AUDIT_DEDUP_WINDOW_SECONDS", "")
    if not raw:
        return _DEFAULT_DEDUP_WINDOW_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_DEDUP_WINDOW_SECONDS
    return max(value, 0)


def _find_dedup_predecessor(
    connection: sqlite3.Connection,
    *,
    engagement_id: int,
    command: str,
    argv_json: str,
    window_seconds: int,
) -> int | None:
    if window_seconds <= 0:
        return None
    cutoff = (
        f"datetime('now', '-{int(window_seconds)} seconds')"
    )
    row = connection.execute(
        f"""
        SELECT id FROM assessment_command_runs
        WHERE engagement_id = ?
          AND command = ?
          AND argv_json = ?
          AND status IN ('queued', 'running')
          AND datetime(created_at) >= {cutoff}
        ORDER BY id DESC
        LIMIT 1
        """,
        (engagement_id, command, argv_json),
    ).fetchone()
    if row is None:
        return None
    return int(row[0])


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
    status: str | None = None,
    stdout_path: str | None = None,
    stderr_path: str | None = None,
    peak_rss_bytes: int | None = None,
    cpu_user_seconds: float | None = None,
    cpu_system_seconds: float | None = None,
    working_dir: str | None = None,
    scope_version: str | None = None,
    auth_context: str | None = None,
    target_host: str = "",
    timeout_seconds_requested: int | None = None,
    force: bool = False,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)

    if not (phase or "").strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="phase is required and cannot be empty",
        )

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

    status_value = _infer_command_run_status(
        status,
        return_code=return_code,
        timed_out=timed_out,
        success=success,
    )
    argv_json_value = json.dumps(list(argv) if argv else [], ensure_ascii=False)

    with get_connection() as connection:
        # Dedup-at-write-time: if an in-flight row exists with the same
        # (command, argv_json) for this engagement inside the configurable
        # window, ALWAYS insert a new row but link it to the predecessor via
        # ``superseded_by_id`` so the supersession is a relationship between
        # two rows rather than a row-merge. ``force=True`` is the deliberate-
        # retry escape hatch that suppresses both the warning (CLI-side) and
        # the supersede link (here) — operator says "I know there's a peer,
        # run it anyway as an independent retry."
        #
        # Audit-truthfulness rationale: the previous behavior returned the
        # predecessor's row id on dedup hit. Under the CLI's warn-and-continue
        # default the second subprocess still ran, so two executions collapsed
        # to one audit row and ``list-command-runs`` lied about coverage. By
        # always inserting we get one row per execution attempt; readers that
        # want to filter to "primary" runs can join on
        # ``superseded_by_id IS NULL``. The predecessor lookup itself scans all
        # in-flight peers, including already-linked duplicate rows, so duplicate
        # chains continue when the original primary finishes before later peers.
        superseded_by_id: int | None = None
        if not force:
            superseded_by_id = _find_dedup_predecessor(
                connection,
                engagement_id=engagement.id,
                command=command,
                argv_json=argv_json_value,
                window_seconds=_dedup_window_seconds(),
            )
        try:
            cursor = connection.execute(
                """
                INSERT INTO assessment_command_runs (
                    engagement_id, run_uuid, command, argv_json, tool_name, tool_bin, route,
                    agent_name, phase, audit_source, status,
                    return_code, timed_out, success,
                    started_at, completed_at, duration_ms,
                    command_hash, stdout_sha256, stderr_sha256,
                    stdout_preview, stderr_preview, output_retention_status,
                    stdout_suppression_reason, stderr_suppression_reason,
                    stdout_artifact_ref, stderr_artifact_ref,
                    stdout_bytes, stderr_bytes, notes,
                    technique, intent, probe_kind, destructive,
                    stdout_path, stderr_path,
                    peak_rss_bytes, cpu_user_seconds, cpu_system_seconds,
                    working_dir, scope_version, auth_context, target_host,
                    superseded_by_id, timeout_seconds_requested
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?,
                    ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?
                )
                """,
                (
                    engagement.id,
                    run_uuid,
                    command,
                    argv_json_value,
                    tool_name,
                    tool_bin,
                    route,
                    agent_name,
                    phase,
                    audit_source or "header",
                    status_value,
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
                    stdout_path,
                    stderr_path,
                    peak_rss_bytes,
                    cpu_user_seconds,
                    cpu_system_seconds,
                    working_dir,
                    scope_version,
                    auth_context,
                    (target_host or "").strip(),
                    superseded_by_id,
                    timeout_seconds_requested,
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
        serialized = _serialize_command_run(row, include_output=True)
        # Surface the dedup relationship to the caller so the CLI can warn-
        # and-continue. ``superseded_by_id`` already lives on the row payload;
        # ``dedup_predecessor_id`` is a separate hint surface so consumers can
        # tell "this row was inserted as a dedup peer" without re-querying the
        # predecessor row to check its status.
        if superseded_by_id is not None:
            serialized["dedup_predecessor_id"] = superseded_by_id
    for artifact_ref in (
        serialized.get("stdout_artifact_ref"),
        serialized.get("stderr_artifact_ref"),
        serialized.get("stdout_path"),
        serialized.get("stderr_path"),
    ):
        _register_artifact_reference(
            engagement.id,
            str(artifact_ref or ""),
            kind="command-run-output",
            producer_command_run_id=int(serialized["id"]),
            producer_agent_role=agent_name,
        )
    return serialized


def _infer_command_run_status(
    status_value: str | None,
    *,
    return_code: int | None,
    timed_out: bool,
    success: bool | None,
) -> str:
    explicit = (status_value or "").strip()
    if explicit:
        return explicit
    if timed_out:
        return "timed_out"
    if return_code is not None:
        return "completed" if return_code == 0 else "failed"
    if success is True:
        return "completed"
    if success is False:
        return "failed"
    return "running"


_FINALIZE_TERMINAL_STATUSES = {"completed", "failed", "timed_out", "killed", "lost"}
_FINALIZE_ALLOWED_STATUSES = _FINALIZE_TERMINAL_STATUSES | {"running"}
_FINALIZE_MUTABLE_STATUSES = {"queued", "running"}


def finalize_command_run(
    engagement_id: int,
    *,
    command_run_id: int,
    status_value: str,
    return_code: int | None = None,
    ended_at: str,
    duration_ms: int | None = None,
    stdout_preview: str | None = None,
    stderr_preview: str | None = None,
    timed_out: bool = False,
    partial_results: bool = False,
    peak_rss_bytes: int | None = None,
    cpu_user_seconds: float | None = None,
    cpu_system_seconds: float | None = None,
) -> dict[str, Any]:
    """Apply a status update to a pre-exec command-run row.

    Idempotency contract (B4): a row already in a terminal state must not be
    overwritten — the second writer is signalled with HTTP 409 carrying the
    existing row. ``queued`` and ``running`` are mutable pre-terminal states.
    A ``running``-to-``running`` PATCH is a refresh no-op that surfaces
    ``noop=true`` so the caller can distinguish it from a fresh write."""
    engagement = _engagement_or_404(engagement_id)
    if status_value not in _FINALIZE_ALLOWED_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"finalize status must be one of {sorted(_FINALIZE_ALLOWED_STATUSES)}",
        )
    with get_connection() as connection:
        existing_row = connection.execute(
            "SELECT * FROM assessment_command_runs WHERE engagement_id = ? AND id = ?",
            (engagement.id, command_run_id),
        ).fetchone()
        if existing_row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="command run not found",
            )
        existing_status = (existing_row["status"] or "").strip()
        if existing_status in _FINALIZE_TERMINAL_STATUSES:
            serialized = _serialize_command_run(existing_row, include_output=True)
            serialized["noop"] = True
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": (
                        f"command run id={command_run_id} already finalized with "
                        f"status='{existing_status}'; refusing to overwrite"
                    ),
                    "existing": serialized,
                },
            )
        if status_value == "running" and existing_status == "running":
            serialized = _serialize_command_run(existing_row, include_output=True)
            serialized["noop"] = True
            return serialized
        if status_value == "running":
            serialized = _serialize_command_run(existing_row, include_output=True)
            serialized["noop"] = True
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": (
                        f"command run id={command_run_id} is status='{existing_status or 'unknown'}'; "
                        "running refresh only applies to rows already in status='running'"
                    ),
                    "existing": serialized,
                },
            )
        success_flag = 1 if (status_value == "completed" and (return_code in (0, None) and not timed_out)) else 0
        if return_code is not None and return_code != 0:
            success_flag = 0
        sets: list[str] = [
            "status = ?",
            "completed_at = ?",
            "timed_out = ?",
            "success = ?",
        ]
        values: list[Any] = [
            status_value,
            ended_at,
            1 if timed_out else 0,
            success_flag,
        ]
        if return_code is not None:
            sets.append("return_code = ?")
            values.append(int(return_code))
        if duration_ms is not None:
            sets.append("duration_ms = ?")
            values.append(int(duration_ms))
        if stdout_preview is not None:
            sets.append("stdout_preview = ?")
            values.append(stdout_preview)
        if stderr_preview is not None:
            sets.append("stderr_preview = ?")
            values.append(stderr_preview)
        if peak_rss_bytes is not None:
            sets.append("peak_rss_bytes = ?")
            values.append(int(peak_rss_bytes))
        if cpu_user_seconds is not None:
            sets.append("cpu_user_seconds = ?")
            values.append(float(cpu_user_seconds))
        if cpu_system_seconds is not None:
            sets.append("cpu_system_seconds = ?")
            values.append(float(cpu_system_seconds))
        sets.append("partial_results = ?")
        values.append(1 if partial_results else 0)
        mutable_statuses = tuple(sorted(_FINALIZE_MUTABLE_STATUSES))
        values.append(command_run_id)
        values.extend(mutable_statuses)
        # Guard against the read→update race when two finalize PATCHes arrive
        # simultaneously: both can pass the SELECT-based terminal check above,
        # but the UPDATE must only land when the row is still pre-terminal.
        # The loser hits rowcount=0 and is funnelled into the same 409 path
        # with the canonical row payload that the SELECT-based check uses.
        mutable_placeholders = ", ".join("?" for _ in mutable_statuses)
        cursor = connection.execute(
            f"UPDATE assessment_command_runs SET {', '.join(sets)} WHERE id = ? AND status IN ({mutable_placeholders})",
            tuple(values),
        )
        if cursor.rowcount == 0:
            current_row = connection.execute(
                "SELECT * FROM assessment_command_runs WHERE id = ?",
                (command_run_id,),
            ).fetchone()
            if current_row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="command run not found",
                )
            serialized = _serialize_command_run(current_row, include_output=True)
            serialized["noop"] = True
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": (
                        f"command run id={command_run_id} already finalized with "
                        f"status='{(current_row['status'] or '').strip()}'; refusing to overwrite"
                    ),
                    "existing": serialized,
                },
            )
        row = connection.execute(
            "SELECT * FROM assessment_command_runs WHERE id = ?",
            (command_run_id,),
        ).fetchone()
        assert row is not None
        return _serialize_command_run(row, include_output=True)


# ── Assessment job lifecycle ────────────────────────────────────────


_JOB_TERMINAL_STATUSES = {"completed", "failed", "killed", "lost", "stop_failed"}
_JOB_VALID_STATUSES = {"queued", "running", *_JOB_TERMINAL_STATUSES}
_JOB_PRE_TERMINAL_STATUSES = _JOB_VALID_STATUSES - _JOB_TERMINAL_STATUSES


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
            detail=f"job status must be one of {sorted(_JOB_VALID_STATUSES)}",
        )
    metadata_json = json.dumps(audit_metadata, ensure_ascii=False) if audit_metadata is not None else None
    with get_connection() as connection:
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
            "SELECT * FROM assessment_jobs WHERE id = ?",
            (cursor.lastrowid,),
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
                detail=f"job status must be one of {sorted(_JOB_VALID_STATUSES)}",
            )
        sets.append("status = ?")
        values.append(status_value)
    if started_at is not None:
        sets.append("started_at = ?")
        values.append(started_at)
    if ended_at is not None:
        sets.append("ended_at = ?")
        values.append(ended_at)
    if exit_code is not None:
        sets.append("exit_code = ?")
        values.append(int(exit_code))
    if dtach_socket_path is not None:
        sets.append("dtach_socket_path = ?")
        values.append(dtach_socket_path)
    if stdout_path is not None:
        sets.append("stdout_path = ?")
        values.append(stdout_path)
    if stderr_path is not None:
        sets.append("stderr_path = ?")
        values.append(stderr_path)
    if audit_metadata is not None:
        sets.append("audit_metadata_json = ?")
        values.append(json.dumps(audit_metadata, ensure_ascii=False))
    if not sets:
        return get_job(engagement.id, job_id)
    sets.append("updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')")
    with get_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM assessment_jobs WHERE engagement_id = ? AND id = ?",
            (engagement.id, int(job_id)),
        ).fetchone()
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="job not found",
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
        guard_terminal_update = (
            status_value in _JOB_TERMINAL_STATUSES
            and existing_status in _JOB_PRE_TERMINAL_STATUSES
        )
        if guard_terminal_update:
            pre_terminal_statuses = tuple(sorted(_JOB_PRE_TERMINAL_STATUSES))
            placeholders = ", ".join("?" for _ in pre_terminal_statuses)
            where += f" AND status IN ({placeholders})"
            where_values.extend(pre_terminal_statuses)
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
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="job not found",
                )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": "job already terminal",
                    "existing": _serialize_job(current),
                },
            )
        row = connection.execute(
            "SELECT * FROM assessment_jobs WHERE id = ?",
            (int(job_id),),
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
    query = (
        f"SELECT * FROM assessment_jobs "
        f"WHERE {' AND '.join(where)} "
        "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    )
    with get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [_serialize_job(row) for row in rows]


def get_job(engagement_id: int, job_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_jobs WHERE engagement_id = ? AND id = ?",
            (engagement.id, int(job_id)),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="job not found")
    return _serialize_job(row)


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
    data["partial_results"] = bool(data.get("partial_results"))
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
    target_host: str = "",
    audit_source: str = "",
    route: str = "",
    success: bool | None = None,
    timed_out: bool | None = None,
    technique: str = "",
    probe_kind: str = "",
    destructive: bool | None = None,
    intent_q: str = "",
    sort: str = "",
    exact: bool = False,
    require_all: bool = False,
    show_matches: bool = False,
    limit: int = 100,
    offset: int = 0,
    include_output: bool = False,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)

    # Track WHERE filters as (clause, params) tuples so the distant-search
    # helper can drop the MATCH filter cleanly. Positional zip() against a
    # flat base_params list breaks when a filter takes >1 param.
    filters: list[tuple[str, list[Any]]] = [("r.engagement_id = ?", [engagement.id])]

    # ``q`` is a global FTS match across all content columns. ``intent_q`` is
    # a scoped FTS match against the intent column only — SQLite FTS5 uses
    # the ``column:term`` syntax for this. When both are provided the
    # queries are AND-combined via an additional MATCH (FTS5 supports two
    # MATCH clauses against the same virtual table via two JOINs; simpler
    # here is to merge them into a single MATCH term joined with AND).
    join_sql = ""
    match_terms: list[str] = []
    fts_term = expanded_fts_query(q, exact=exact, require_all=require_all) if q else ""
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
    match_filter: tuple[str, list[Any]] | None = None
    if match_terms:
        join_sql = "JOIN assessment_command_runs_fts ON assessment_command_runs_fts.rowid = r.id"
        match_filter = ("assessment_command_runs_fts MATCH ?", [" ".join(match_terms)])
        filters.append(match_filter)

    if agent_name:
        filters.append(("r.agent_name = ?", [agent_name]))
    if phase:
        filters.append(("r.phase = ?", [phase]))
    if tool_name:
        filters.append(("r.tool_name = ?", [tool_name]))
    if tool_bin:
        filters.append(("r.tool_bin = ?", [tool_bin]))
    if target_host:
        # Case-insensitive exact match against the parsed target_host column.
        # NULL-tolerant (LOWER(NULL) = NULL, which will not match the literal).
        filters.append(("LOWER(r.target_host) = ?", [target_host.strip().lower()]))
    if audit_source:
        filters.append(("r.audit_source = ?", [audit_source]))
    if route:
        # Provenance-lane filter so host-side katana/httpx coverage is visible.
        # host-exec rows are stamped route='host_exec'; container/kali typed-verb
        # rows are stamped route='aith assess kali/<tool>'. 'kali' is therefore a
        # prefix match, 'host_exec' an exact match, and any other value an exact
        # match against the stored route string.
        if route == "kali":
            filters.append(("r.route LIKE 'aith assess kali/%'", []))
        else:
            filters.append(("r.route = ?", [route]))
    if success is not None:
        filters.append(("r.success = ?", [1 if success else 0]))
    if timed_out is not None:
        filters.append(("r.timed_out = ?", [1 if timed_out else 0]))
    if technique:
        filters.append(("r.technique = ?", [technique]))
    if probe_kind:
        filters.append(("r.probe_kind = ?", [probe_kind]))
    if destructive is not None:
        filters.append(("r.destructive = ?", [1 if destructive else 0]))

    base_where = [clause for clause, _ in filters]
    base_params: list[Any] = [param for _, params in filters for param in params]

    sort_value = (sort or "").strip().lower()
    if not sort_value:
        sort_value = "relevance" if match_terms else "recent"
    if sort_value not in {"relevance", "recent", "distant"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid command-run sort: {sort}")

    if sort_value == "distant":
        return _list_distant_command_runs(
            engagement.id,
            q=q,
            filters=filters,
            match_filter=match_filter,
            match_terms=match_terms,
            limit=limit,
            offset=offset,
            include_output=include_output,
            show_matches=show_matches,
            exact=exact,
        )

    params = list(base_params)
    params.extend([int(limit), int(offset)])
    rank_select = ", bm25(assessment_command_runs_fts) AS search_rank" if match_terms else ""
    if sort_value == "relevance" and match_terms:
        order_sql = "ORDER BY search_rank ASC, r.created_at DESC, r.id DESC"
    else:
        order_sql = "ORDER BY r.created_at DESC, r.id DESC"
    query = (
        f"SELECT r.*{rank_select} FROM assessment_command_runs r {join_sql} "
        f"WHERE {' AND '.join(base_where)} "
        f"{order_sql} LIMIT ? OFFSET ?"
    )

    with get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [
        _serialize_command_run_with_matches(row, include_output=include_output, q=q, show_matches=show_matches, exact=exact)
        for row in rows
    ]


def _list_distant_command_runs(
    engagement_id: int,
    *,
    q: str,
    filters: list[tuple[str, list[Any]]],
    match_filter: tuple[str, list[Any]] | None,
    match_terms: list[str],
    limit: int,
    offset: int,
    include_output: bool,
    show_matches: bool,
    exact: bool = False,
) -> list[dict[str, Any]]:
    """Return nonmatching rows in the same inferred command scope.

    This is a coverage-gap view: first find direct matches, infer scope from
    their structured fields, then list older/nonmatching command families in
    that scope.
    """

    distant_filters = [(clause, list(params)) for clause, params in filters if (clause, params) != match_filter]
    if not distant_filters:
        distant_filters = [("r.engagement_id = ?", [engagement_id])]
    distant_where = [clause for clause, _ in distant_filters]
    distant_params: list[Any] = [p for _, ps in distant_filters for p in ps]

    direct_rows: list[Any] = []
    direct_ids: list[int] = []
    if match_terms:
        base_where = [clause for clause, _ in filters]
        base_params = [p for _, ps in filters for p in ps]
        direct_query = (
            "SELECT r.* FROM assessment_command_runs r "
            "JOIN assessment_command_runs_fts ON assessment_command_runs_fts.rowid = r.id "
            f"WHERE {' AND '.join(base_where)} "
            "ORDER BY r.created_at DESC, r.id DESC LIMIT 200"
        )
        with get_connection() as connection:
            direct_rows = connection.execute(direct_query, tuple(base_params)).fetchall()
        direct_ids = [int(row["id"]) for row in direct_rows]

    if direct_ids:
        placeholders = ", ".join("?" for _ in direct_ids)
        distant_where.append(f"r.id NOT IN ({placeholders})")
        distant_params.extend(direct_ids)
        scope_clauses: list[str] = []
        for column in ("target_host", "tool_bin", "technique", "probe_kind", "phase"):
            values = sorted({str(row[column] or "") for row in direct_rows if str(row[column] or "").strip()})
            if values:
                scope_placeholders = ", ".join("?" for _ in values)
                scope_clauses.append(f"r.{column} IN ({scope_placeholders})")
                distant_params.extend(values)
        if scope_clauses:
            distant_where.append("(" + " OR ".join(scope_clauses) + ")")
    elif match_terms:
        # No direct match means there is no safe inferred scope. Return no
        # distant rows rather than flooding resume output with unrelated runs.
        return []

    distant_params.extend([int(limit), int(offset)])
    query = (
        "SELECT r.* FROM assessment_command_runs r "
        f"WHERE {' AND '.join(distant_where)} "
        "ORDER BY r.created_at ASC, r.id ASC LIMIT ? OFFSET ?"
    )
    with get_connection() as connection:
        rows = connection.execute(query, tuple(distant_params)).fetchall()
    return [
        _serialize_command_run_with_matches(row, include_output=include_output, q=q, show_matches=show_matches, exact=exact)
        for row in rows
    ]


def _serialize_command_run_with_matches(
    row,
    *,
    include_output: bool,
    q: str,
    show_matches: bool,
    exact: bool = False,
) -> dict[str, Any]:
    data = _serialize_command_run(row, include_output=include_output)
    if show_matches:
        data["matches"] = _command_run_match_reasons(data, q, exact=exact)
    return data


def _command_run_match_reasons(row: dict[str, Any], q: str, *, exact: bool = False) -> list[str]:
    reasons: list[str] = []
    # In exact mode the FTS query is the user's raw phrase only — alias
    # expansion never ran, so attributing the match to an alias would be
    # misleading. Plain-token reasons still apply because the input phrase
    # itself was searched.
    if not exact:
        aliases = finding_aliases_in_text(q)
        if aliases:
            for canonical, values in aliases.items():
                needle_values = {value.lower() for value in values}
                for field in (
                    "command",
                    "tool_name",
                    "tool_bin",
                    "agent_name",
                    "phase",
                    "notes",
                    "intent",
                    "technique",
                    "stdout_suppression_reason",
                    "stderr_suppression_reason",
                    "stdout_artifact_ref",
                    "stderr_artifact_ref",
                ):
                    value = str(row.get(field) or "").lower()
                    if value and any(needle in value for needle in needle_values):
                        reasons.append(f"finding_alias:{canonical}:{field}")
    plain_terms = [term.lower() for term in str(q or "").split() if len(term) >= 3]
    for field in ("command", "tool_name", "tool_bin", "agent_name", "phase", "notes", "intent", "technique"):
        value = str(row.get(field) or "").lower()
        for term in plain_terms:
            if term in value:
                reasons.append(f"token:{term}:{field}")
                break
    return sorted(set(reasons))


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


# ── Round 9: dispatch / handoff / decision tables ────────────────────────
#
# These three CRUD helper sets follow the existing intel-table pattern: validate the
# engagement up front, do JSON serialize/deserialize at the boundary, raise
# 404/409 with HTTPException so the API layer can surface them directly.


# ── Host liveness ledger ──────────────────────────────────────────────────
# Authoritative per-host reachability, upserted from httpx probes via
# `aith assess ingest-httpx`. A verdict older than the TTL is reported as
# 'stale' by the read projection (not stored as 'stale'), forcing a re-probe
# rather than trusting it across the shifting-egress boundary (§9).
_HOST_LIVENESS_TTL_SECONDS = 120 * 60  # 2h
_HOST_LIVENESS_DECAYS = frozenset({"live", "blackholed", "dead"})


def _normalize_liveness_host(value: str) -> str:
    """Canonical liveness key: lowercased, scheme- and port-stripped authority.

    Must stay byte-for-byte in sync with ``discovery.normalize_host`` (CLI side)
    so a GET ?host= lookup matches stored rows.
    """
    h = (value or "").strip().lower().rstrip(".")
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]
    if h.startswith("["):  # [ipv6](:port)?
        end = h.find("]")
        if end != -1:
            h = h[: end + 1]
    elif h.count(":") == 1:
        # exactly one colon → host:port (a bare IPv6 has >=2 colons; leave it intact)
        h = h.split(":", 1)[0]
    return h


def _parse_probed_at(probed_at):
    """Parse an ISO probed_at into an aware UTC datetime, or None."""
    import datetime as _dt

    if not probed_at:
        return None
    raw = str(probed_at).strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


def _canonical_probed_at(probed_at):
    """Normalize probed_at to a single lexicographically-sortable UTC form so the
    keep-newest TEXT comparison in the upsert is correct across mixed input
    formats (fractional precision, ``+HH:MM`` offsets, naive). Returns None when
    unparseable/empty (the upsert then treats it as "no probe time")."""
    parsed = _parse_probed_at(probed_at)
    if parsed is None:
        return None
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _liveness_age_seconds(probed_at) -> float | None:
    import datetime as _dt

    parsed = _parse_probed_at(probed_at)
    if parsed is None:
        return None
    return (_dt.datetime.now(_dt.timezone.utc) - parsed).total_seconds()


def upsert_host_liveness(engagement_id: int, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Bulk-upsert host-liveness rows keyed by (engagement, host).

    The caller (ingest-httpx) supplies the already-classified ``reachability_class``
    — the backend stores it verbatim and keeps the newest probe per host (an
    incoming row with an older ``probed_at`` does not overwrite a newer one).
    """
    _engagement_or_404(engagement_id)
    upserted = 0
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        for r in rows:
            host = _normalize_liveness_host(str(r.get("host", "")))
            if not host:
                continue
            connection.execute(
                """
                INSERT INTO assessment_host_liveness (
                    engagement_id, host, status_code, scheme, final_url, host_ip,
                    tech, title, webserver, tls, failed, reachability_class,
                    probed_at, source, source_run_id, source_run_uuid
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, host) DO UPDATE SET
                    status_code = excluded.status_code,
                    scheme = excluded.scheme,
                    final_url = excluded.final_url,
                    host_ip = excluded.host_ip,
                    tech = excluded.tech,
                    title = excluded.title,
                    webserver = excluded.webserver,
                    tls = excluded.tls,
                    failed = excluded.failed,
                    reachability_class = excluded.reachability_class,
                    probed_at = excluded.probed_at,
                    source = excluded.source,
                    source_run_id = excluded.source_run_id,
                    source_run_uuid = excluded.source_run_uuid,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                -- Keep the newest probe: overwrite only when the existing row has
                -- no probe time, or the incoming probe is at-or-after it. A NULL
                -- incoming probed_at must NOT clobber a real timestamped verdict.
                -- probed_at is canonicalized to one sortable UTC form on the way
                -- in, so this TEXT comparison is correct across input formats.
                WHERE assessment_host_liveness.probed_at IS NULL
                   OR (excluded.probed_at IS NOT NULL
                       AND excluded.probed_at >= assessment_host_liveness.probed_at)
                """,
                (
                    engagement_id,
                    host,
                    r.get("status_code"),
                    str(r.get("scheme") or ""),
                    str(r.get("final_url") or ""),
                    str(r.get("host_ip") or ""),
                    str(r.get("tech") or ""),
                    str(r.get("title") or ""),
                    str(r.get("webserver") or ""),
                    str(r.get("tls") or ""),
                    1 if r.get("failed") else 0,
                    str(r.get("reachability_class") or "unknown"),
                    _canonical_probed_at(r.get("probed_at")),
                    str(r.get("source") or "httpx"),
                    r.get("source_run_id"),
                    str(r.get("source_run_uuid") or ""),
                ),
            )
            upserted += 1
    return {"upserted": upserted}


def host_liveness(
    engagement_id: int,
    *,
    hosts: list[str] | None = None,
    fresh_only: bool = False,
) -> list[dict[str, Any]]:
    """Read host-liveness rows with the freshness overlay applied.

    A stored verdict older than the TTL is reported as ``reachability_class``
    'stale' (the stored value is preserved under ``stored_reachability_class``)
    and each row carries ``age_seconds``. With ``fresh_only`` the stale/unprobed
    rows are dropped.
    """
    _engagement_or_404(engagement_id)
    with get_connection() as connection:
        if hosts:
            norm = sorted({_normalize_liveness_host(h) for h in hosts if _normalize_liveness_host(h)})
            if not norm:
                return []
            placeholders = ",".join("?" for _ in norm)
            cursor = connection.execute(
                f"SELECT * FROM assessment_host_liveness "
                f"WHERE engagement_id = ? AND host IN ({placeholders}) ORDER BY host",
                (engagement_id, *norm),
            )
        else:
            cursor = connection.execute(
                "SELECT * FROM assessment_host_liveness WHERE engagement_id = ? ORDER BY host",
                (engagement_id,),
            )
        rows = cursor.fetchall()

    out: list[dict[str, Any]] = []
    for row in rows:
        data = dict(row)
        age = _liveness_age_seconds(data.get("probed_at"))
        data["age_seconds"] = age
        stored = data.get("reachability_class") or "unknown"
        is_fresh = age is not None and age <= _HOST_LIVENESS_TTL_SECONDS
        if not is_fresh and stored in _HOST_LIVENESS_DECAYS:
            data["stored_reachability_class"] = stored
            data["reachability_class"] = "stale"
        if fresh_only and not is_fresh:
            continue
        out.append(data)
    return out


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
    _engagement_or_404(engagement_id)
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT COALESCE(hl.reachability_class, 'unprobed') AS klass, COUNT(*) AS count
            FROM assessment_coverage_items ci
            LEFT JOIN assessment_services s ON s.id = ci.service_id
            LEFT JOIN assessment_request_variants rv ON rv.id = ci.request_variant_id
            LEFT JOIN assessment_host_liveness hl
                ON hl.engagement_id = ci.engagement_id
               AND hl.host = LOWER(
                     COALESCE(
                       rv.host,
                       CASE WHEN instr(s.endpoint, ':') > 0
                            THEN substr(s.endpoint, 1, instr(s.endpoint, ':') - 1)
                            ELSE s.endpoint END
                     )
                   )
            WHERE ci.engagement_id = ?
            GROUP BY klass
            """,
            (engagement_id,),
        ).fetchall()
    counts = {row["klass"]: int(row["count"]) for row in rows}
    return {
        "total": sum(counts.values()),
        "reachable": counts.get("live", 0),
        "blackholed": counts.get("blackholed", 0),
        "dead": counts.get("dead", 0),
        "unknown": counts.get("unknown", 0),
        "unprobed": counts.get("unprobed", 0),
    }


def _utcnow_iso_dispatch() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _serialize_dispatch(row) -> dict[str, Any]:
    data = dict(row)
    for col in ("finding_slugs_json",):
        raw = data.pop(col, None) or ""
        key = col[: -len("_json")]
        if raw:
            try:
                data[key] = json.loads(raw)
            except json.JSONDecodeError:
                data[key] = None
        else:
            data[key] = None
    return data


def record_dispatch(
    engagement_id: int,
    *,
    agent_id: str,
    agent_role: str,
    task: str | None = None,
    scope_host: str | None = None,
    dispatched_at: str | None = None,
    status_value: str = "in-progress",
    model: str | None = None,
    reasoning: str | None = None,
    requested_model: str | None = None,
    actual_model: str | None = None,
    requested_reasoning: str | None = None,
    actual_reasoning: str | None = None,
    dispatch_mode: str | None = None,
    finding_slugs: list[str] | None = None,
    skills: str | None = None,
    tier: str | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not (agent_id or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="agent_id is required")
    dispatched_value = dispatched_at or _utcnow_iso_dispatch()
    finding_slugs = _require_canonical_finding_slugs(finding_slugs)
    findings_json = json.dumps(list(finding_slugs)) if finding_slugs is not None else None
    skills_value = (skills or "").strip() or None
    tier_value = (tier or "").strip() or None
    requested_model_value = requested_model if requested_model is not None else model
    requested_reasoning_value = requested_reasoning if requested_reasoning is not None else reasoning
    with get_connection() as connection:
        _ensure_finding_slugs_exist(connection, engagement.id, finding_slugs)
        existing = connection.execute(
            "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"dispatch with agent_id={agent_id!r} already exists for this engagement",
            )
        cursor = connection.execute(
            """
            INSERT INTO assessment_dispatches (
                engagement_id, agent_id, agent_role, task, scope_host,
                dispatched_at, status, model, reasoning,
                requested_model, actual_model, requested_reasoning, actual_reasoning,
                dispatch_mode, finding_slugs_json, skills, tier
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                agent_id,
                agent_role,
                task,
                scope_host,
                dispatched_value,
                status_value,
                requested_model_value,
                requested_reasoning_value,
                requested_model_value,
                actual_model,
                requested_reasoning_value,
                actual_reasoning,
                dispatch_mode,
                findings_json,
                skills_value,
                tier_value,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_dispatches WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    assert row is not None
    return _serialize_dispatch(row)


def update_dispatch(
    engagement_id: int,
    *,
    agent_id: str,
    status_value: str | None = None,
    completed_at: str | None = None,
    finding_slugs: list[str] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    finding_slugs = _require_canonical_finding_slugs(finding_slugs)
    with get_connection() as connection:
        _ensure_finding_slugs_exist(connection, engagement.id, finding_slugs)
        existing = connection.execute(
            "SELECT * FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if existing is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="dispatch not found")
        sets: list[str] = []
        values: list[Any] = []
        if status_value is not None:
            sets.append("status = ?")
            values.append(status_value)
        if completed_at is not None:
            sets.append("completed_at = ?")
            values.append(completed_at)
        if finding_slugs is not None:
            sets.append("finding_slugs_json = ?")
            values.append(json.dumps(list(finding_slugs)))
        if not sets:
            return _serialize_dispatch(existing)
        values.extend([engagement.id, agent_id])
        connection.execute(
            f"UPDATE assessment_dispatches SET {', '.join(sets)} WHERE engagement_id = ? AND agent_id = ?",
            tuple(values),
        )
        row = connection.execute(
            "SELECT * FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
    assert row is not None
    return _serialize_dispatch(row)


def get_dispatch(engagement_id: int, agent_id: str) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="dispatch not found")
    return _serialize_dispatch(row)


def list_dispatches(
    engagement_id: int,
    *,
    role: str = "",
    status_value: str = "",
    since: str = "",
    task_q: str = "",
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    where = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if role:
        where.append("agent_role = ?")
        params.append(role)
    if status_value:
        where.append("status = ?")
        params.append(status_value)
    if since:
        where.append("dispatched_at >= ?")
        params.append(since)
    if task_q:
        where.append("task LIKE ?")
        params.append(f"%{task_q}%")
    params.append(int(limit))
    params.append(max(int(offset), 0))
    query = (
        f"SELECT * FROM assessment_dispatches WHERE {' AND '.join(where)} "
        "ORDER BY dispatched_at DESC, id DESC LIMIT ? OFFSET ?"
    )
    with get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [_serialize_dispatch(row) for row in rows]


def _serialize_handoff(row) -> dict[str, Any]:
    data = dict(row)
    for col in (
        "finding_slugs_json",
        "coverage_gaps_json",
        "next_steps_json",
        "runtime_issues_json",
        "working_artifacts_json",
        "open_questions_json",
        "extras_json",
    ):
        raw = data.pop(col, None) or ""
        key = col[: -len("_json")]
        if raw:
            try:
                data[key] = json.loads(raw)
            except json.JSONDecodeError:
                data[key] = None
        else:
            data[key] = None
    return data


_HANDOFF_SUMMARY_MAX = 2000


def _register_handoff_artifacts(engagement_id: int, handoff: dict[str, Any]) -> None:
    artifacts = handoff.get("working_artifacts") or []
    if not isinstance(artifacts, list):
        return
    raw_slugs = handoff.get("finding_slugs") or []
    finding_slugs: list[str] = (
        [str(slug) for slug in raw_slugs if str(slug)] if isinstance(raw_slugs, list) else []
    )
    # The artifact row carries one related_finding_slug. The primary slug
    # (first in the handoff list, by specialist convention) gets the column;
    # multi-finding handoffs still find their artifact via indexed_text /
    # path LIKE searches in search_artifacts, so the column is the
    # canonical-link anchor rather than the only path back.
    related_finding_slug = finding_slugs[0] if finding_slugs else None
    producer_agent_id = str(handoff.get("agent_id") or "") or None
    producer_agent_role = str(handoff.get("agent_role") or "") or None
    for item in artifacts:
        if not isinstance(item, dict) or not item.get("path"):
            continue
        _register_artifact_reference(
            engagement_id,
            str(item.get("path") or ""),
            kind=str(item.get("kind") or "handoff-artifact"),
            producer_agent_id=producer_agent_id,
            producer_agent_role=producer_agent_role,
            related_finding_slug=related_finding_slug,
        )


def record_handoff(
    engagement_id: int,
    *,
    agent_id: str,
    agent_role: str,
    summary: str,
    phase: str | None = None,
    confidence: str | None = None,
    finding_slugs: list[str] | None = None,
    coverage_gaps: list[dict[str, Any]] | None = None,
    next_steps: list[dict[str, Any]] | None = None,
    runtime_issues: list[dict[str, Any]] | None = None,
    working_artifacts: list[dict[str, Any]] | None = None,
    open_questions: list[str] | None = None,
    recommended_next_agent: str | None = None,
    handoff_status: str = "checkpointed",
    closed_dispatch_status: str | None = None,
    extras: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not (agent_id or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="agent_id is required")
    if not (summary or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="summary is required")
    if len(summary) > _HANDOFF_SUMMARY_MAX:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"summary exceeds {_HANDOFF_SUMMARY_MAX} characters",
        )
    closed_dispatch_status = _require_terminal_dispatch_status(closed_dispatch_status)
    finding_slugs = _require_canonical_finding_slugs(finding_slugs)
    created_at = _utcnow_iso_dispatch()
    with get_connection() as connection:
        _ensure_finding_slugs_exist(connection, engagement.id, finding_slugs)
        dispatch_row = connection.execute(
            "SELECT agent_role FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if dispatch_row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"dispatch not found for handoff agent_id={agent_id!r}",
            )
        if str(dispatch_row["agent_role"]) != str(agent_role):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"agent_role mismatch: handoff agent_role={agent_role!r} does not match registered "
                    f"dispatch role={dispatch_row['agent_role']!r}"
                ),
            )
        existing = connection.execute(
            "SELECT id FROM assessment_dispatch_handoffs WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"handoff with agent_id={agent_id!r} already exists; PATCH to update",
            )
        cursor = connection.execute(
            """
            INSERT INTO assessment_dispatch_handoffs (
                engagement_id, agent_id, agent_role, phase, summary, confidence,
                finding_slugs_json, coverage_gaps_json, next_steps_json,
                runtime_issues_json, working_artifacts_json, open_questions_json,
                recommended_next_agent, handoff_status, handoff_version, last_checkpoint_at,
                closed_dispatch_status, extras_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                agent_id,
                agent_role,
                phase,
                summary,
                confidence,
                json.dumps(list(finding_slugs)) if finding_slugs is not None else None,
                json.dumps(list(coverage_gaps)) if coverage_gaps is not None else None,
                json.dumps(list(next_steps)) if next_steps is not None else None,
                json.dumps(list(runtime_issues)) if runtime_issues is not None else None,
                json.dumps(list(working_artifacts)) if working_artifacts is not None else None,
                json.dumps(list(open_questions)) if open_questions is not None else None,
                recommended_next_agent,
                handoff_status,
                1,
                created_at,
                closed_dispatch_status,
                json.dumps(extras) if extras is not None else None,
                created_at,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_dispatch_handoffs WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    assert row is not None
    serialized = _serialize_handoff(row)
    _register_handoff_artifacts(engagement.id, serialized)
    return serialized


def update_handoff(
    engagement_id: int,
    *,
    agent_id: str,
    summary: str | None = None,
    phase: str | None = None,
    confidence: str | None = None,
    finding_slugs: list[str] | None = None,
    coverage_gaps: list[dict[str, Any]] | None = None,
    next_steps: list[dict[str, Any]] | None = None,
    runtime_issues: list[dict[str, Any]] | None = None,
    working_artifacts: list[dict[str, Any]] | None = None,
    open_questions: list[str] | None = None,
    recommended_next_agent: str | None = None,
    handoff_status: str | None = None,
    closed_dispatch_status: str | None = None,
    extras: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    closed_dispatch_status = _require_terminal_dispatch_status(closed_dispatch_status)
    finding_slugs = _require_canonical_finding_slugs(finding_slugs)
    with get_connection() as connection:
        _ensure_finding_slugs_exist(connection, engagement.id, finding_slugs)
        dispatch_row = connection.execute(
            "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if dispatch_row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"dispatch not found for handoff agent_id={agent_id!r}",
            )
        existing = connection.execute(
            "SELECT * FROM assessment_dispatch_handoffs WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if existing is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="handoff not found")
        sets: list[str] = []
        values: list[Any] = []
        if summary is not None:
            if not summary.strip():
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="summary cannot be empty")
            if len(summary) > _HANDOFF_SUMMARY_MAX:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"summary exceeds {_HANDOFF_SUMMARY_MAX} characters",
                )
            sets.append("summary = ?")
            values.append(summary)
        if phase is not None:
            sets.append("phase = ?")
            values.append(phase)
        if confidence is not None:
            sets.append("confidence = ?")
            values.append(confidence)
        if finding_slugs is not None:
            sets.append("finding_slugs_json = ?")
            values.append(json.dumps(list(finding_slugs)))
        if coverage_gaps is not None:
            sets.append("coverage_gaps_json = ?")
            values.append(json.dumps(list(coverage_gaps)))
        if next_steps is not None:
            sets.append("next_steps_json = ?")
            values.append(json.dumps(list(next_steps)))
        if runtime_issues is not None:
            sets.append("runtime_issues_json = ?")
            values.append(json.dumps(list(runtime_issues)))
        if working_artifacts is not None:
            sets.append("working_artifacts_json = ?")
            values.append(json.dumps(list(working_artifacts)))
        if open_questions is not None:
            sets.append("open_questions_json = ?")
            values.append(json.dumps(list(open_questions)))
        if recommended_next_agent is not None:
            sets.append("recommended_next_agent = ?")
            values.append(recommended_next_agent)
        if handoff_status is not None:
            sets.append("handoff_status = ?")
            values.append(handoff_status)
        if closed_dispatch_status is not None:
            sets.append("closed_dispatch_status = ?")
            values.append(closed_dispatch_status)
        if extras is not None:
            sets.append("extras_json = ?")
            values.append(json.dumps(extras))
        if not sets:
            return _serialize_handoff(existing)
        sets.append("handoff_version = COALESCE(handoff_version, 1) + 1")
        sets.append("last_checkpoint_at = ?")
        values.append(_utcnow_iso_dispatch())
        values.extend([engagement.id, agent_id])
        connection.execute(
            f"UPDATE assessment_dispatch_handoffs SET {', '.join(sets)} WHERE engagement_id = ? AND agent_id = ?",
            tuple(values),
        )
        row = connection.execute(
            "SELECT * FROM assessment_dispatch_handoffs WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
    assert row is not None
    serialized = _serialize_handoff(row)
    _register_handoff_artifacts(engagement.id, serialized)
    return serialized


def get_handoff(engagement_id: int, agent_id: str) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_dispatch_handoffs WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="handoff not found")
    return _serialize_handoff(row)


def list_handoffs(
    engagement_id: int,
    *,
    role: str = "",
    since: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    where = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if role:
        where.append("agent_role = ?")
        params.append(role)
    if since:
        where.append("created_at >= ?")
        params.append(since)
    params.append(int(limit))
    query = (
        f"SELECT * FROM assessment_dispatch_handoffs WHERE {' AND '.join(where)} "
        "ORDER BY created_at DESC, id DESC LIMIT ?"
    )
    with get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [_serialize_handoff(row) for row in rows]


def _serialize_decision(row) -> dict[str, Any]:
    data = dict(row)
    raw = data.pop("payload_json", None) or "{}"
    try:
        data["payload"] = json.loads(raw)
    except json.JSONDecodeError:
        data["payload"] = None
    raw_resolution = data.pop("resolution_json", None) or ""
    if raw_resolution:
        try:
            data["resolution"] = json.loads(raw_resolution)
        except json.JSONDecodeError:
            data["resolution"] = None
    else:
        data["resolution"] = None
    if "surfaced_to_user" in data:
        data["surfaced_to_user"] = bool(data["surfaced_to_user"])
    if "resolved" in data:
        data["resolved"] = bool(data["resolved"])
    return data


def record_decision(
    engagement_id: int,
    *,
    kind: str,
    payload: dict[str, Any],
    surfaced_to_user: bool = False,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not (kind or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="kind is required")
    created_at = _utcnow_iso_dispatch()
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO assessment_dispatch_decisions (
                engagement_id, kind, payload_json, surfaced_to_user, resolved,
                resolution_json, created_at
            ) VALUES (?, ?, ?, ?, 0, NULL, ?)
            """,
            (
                engagement.id,
                kind,
                json.dumps(payload or {}),
                1 if surfaced_to_user else 0,
                created_at,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    assert row is not None
    return _serialize_decision(row)


def list_decisions(
    engagement_id: int,
    *,
    kind: str = "",
    resolved: bool | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    where = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if kind:
        where.append("kind = ?")
        params.append(kind)
    if resolved is not None:
        where.append("resolved = ?")
        params.append(1 if resolved else 0)
    params.append(int(limit))
    params.append(int(offset))
    query = (
        f"SELECT * FROM assessment_dispatch_decisions WHERE {' AND '.join(where)} "
        "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    )
    with get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [_serialize_decision(row) for row in rows]


def update_decision(
    engagement_id: int,
    *,
    decision_id: int,
    resolved: bool | None = None,
    resolution: dict[str, Any] | None = None,
    surfaced_to_user: bool | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions WHERE engagement_id = ? AND id = ?",
            (engagement.id, decision_id),
        ).fetchone()
        if existing is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="decision not found")
        sets: list[str] = []
        values: list[Any] = []
        if resolved is not None:
            sets.append("resolved = ?")
            values.append(1 if resolved else 0)
        if resolution is not None:
            sets.append("resolution_json = ?")
            values.append(json.dumps(resolution))
        if surfaced_to_user is not None:
            sets.append("surfaced_to_user = ?")
            values.append(1 if surfaced_to_user else 0)
        if not sets:
            return _serialize_decision(existing)
        values.extend([engagement.id, decision_id])
        connection.execute(
            f"UPDATE assessment_dispatch_decisions SET {', '.join(sets)} WHERE engagement_id = ? AND id = ?",
            tuple(values),
        )
        row = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions WHERE engagement_id = ? AND id = ?",
            (engagement.id, decision_id),
        ).fetchone()
    assert row is not None
    return _serialize_decision(row)
