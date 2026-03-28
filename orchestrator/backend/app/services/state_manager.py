from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, status

from ..db import get_connection
from ..models.user import User
from .events import _run_or_404

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
FINDING_STATUSES = {"draft", "confirmed", "exploited", "blocked", "merged", "reported"}
FINDING_STATUS_RANK = {
    "draft": 0,
    "confirmed": 1,
    "blocked": 2,
    "exploited": 3,
    "reported": 4,
    "merged": -1,
}
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


def _normalize_finding_status(value: str) -> str:
    status_value = (value or "draft").strip().lower()
    if status_value not in FINDING_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid finding status: {value}")
    return status_value


def _coalesce_finding_status(existing: str, incoming: str) -> str:
    existing_normalized = _normalize_finding_status(existing)
    incoming_normalized = _normalize_finding_status(incoming)
    if existing_normalized == "merged":
        return incoming_normalized
    if incoming_normalized == "merged":
        return incoming_normalized
    return incoming_normalized if FINDING_STATUS_RANK[incoming_normalized] >= FINDING_STATUS_RANK[existing_normalized] else existing_normalized


def _finding_confidence_tuple(row: dict[str, Any] | Any) -> tuple[int, int, int]:
    if isinstance(row, dict):
        status_value = row.get("status", "draft")
        severity_value = row.get("severity", "info")
        evidence_ref = row.get("evidence_ref", "")
    else:
        status_value = row["status"]
        severity_value = row["severity"]
        evidence_ref = row["evidence_ref"]
    return (
        FINDING_STATUS_RANK[_normalize_finding_status(str(status_value))],
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


def _find_target_id(connection, run_id: int, identity: str | None) -> int | None:
    if not identity:
        return None
    row = connection.execute(
        "SELECT id FROM assessment_targets WHERE run_id = ? AND identity = ?",
        (run_id, identity),
    ).fetchone()
    return int(row["id"]) if row else None


def _upsert_target(
    connection,
    run_id: int,
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
        INSERT INTO assessment_targets (run_id, identity, kind, host, ip_address, hostname, notes, discovered_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id, identity) DO UPDATE SET
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
        (run_id, identity, kind, host, ip_address, hostname, notes, discovered_by),
    )
    row = connection.execute(
        """
        SELECT id, run_id, identity, kind, host, ip_address, hostname, notes, discovered_by, created_at, updated_at
        FROM assessment_targets
        WHERE run_id = ? AND identity = ?
        """,
        (run_id, identity),
    ).fetchone()
    assert row is not None
    return dict(row)


def _upsert_service(
    connection,
    run_id: int,
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
    target_id = _find_target_id(connection, run_id, target_identity)
    connection.execute(
        """
        INSERT INTO assessment_services (
            run_id, target_id, endpoint, port, protocol, service, state, coverage_status, banner, notes, discovered_by
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id, endpoint, protocol) DO UPDATE SET
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
        (run_id, target_id, endpoint, port, protocol, service, state, coverage_status, banner, notes, discovered_by),
    )
    row = connection.execute(
        """
        SELECT id, run_id, target_id, endpoint, port, protocol, service, state, coverage_status, banner, notes, discovered_by, created_at, updated_at
        FROM assessment_services
        WHERE run_id = ? AND endpoint = ? AND protocol = ?
        """,
        (run_id, endpoint, protocol),
    ).fetchone()
    assert row is not None
    return dict(row)


def _upsert_request_variant(
    connection,
    run_id: int,
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
            run_id, auth_context, scheme, host, port, method, normalized_path, path_template,
            canonical_url, content_type_family, query_schema_json, body_schema_json, path_schema_json,
            cookie_schema_json, header_schema_json, params_schema_hash, body_schema_hash, discovery_source, notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(
            run_id, scheme, host, port, method, normalized_path, auth_context, params_schema_hash, body_schema_hash, content_type_family
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
            run_id,
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
        WHERE run_id = ? AND scheme = ? AND host = ? AND port = ? AND method = ? AND normalized_path = ?
          AND auth_context = ? AND params_schema_hash = ? AND body_schema_hash = ? AND content_type_family = ?
        """,
        (run_id, scheme, host, port, method.upper(), normalized_path, auth_context, params_schema_hash, body_schema_hash, content_type_family),
    ).fetchone()
    assert row is not None
    return dict(row)


def _insert_request_observation(
    connection,
    run_id: int,
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
            run_id, request_variant_id, observed_url, source_name, response_status, evidence_ref, raw_payload
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, request_variant_id, url, discovery_source, response_status, evidence_ref, _json_text(observation_payload or {})),
    )
    row = connection.execute(
        "SELECT * FROM assessment_request_observations WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()
    assert row is not None
    return dict(row)


def _upsert_coverage_item(
    connection,
    run_id: int,
    *,
    request_variant_id: int | None,
    service_id: int | None,
    auth_context: str,
    input_slot: str,
    attack_family: str,
    status_value: str,
    notes: str,
) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT *
        FROM assessment_coverage_items
        WHERE run_id = ? AND request_variant_id IS ? AND service_id IS ? AND auth_context = ? AND input_slot = ? AND attack_family = ?
        """,
        (run_id, request_variant_id, service_id, auth_context, input_slot, attack_family),
    ).fetchone()
    if row is None:
        cursor = connection.execute(
            """
            INSERT INTO assessment_coverage_items (
                run_id, request_variant_id, service_id, auth_context, input_slot, attack_family, status, notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (run_id, request_variant_id, service_id, auth_context, input_slot, attack_family, status_value, notes),
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
            (status_value, _append_notes(row["notes"], notes), row["id"]),
        )
        row = connection.execute("SELECT * FROM assessment_coverage_items WHERE id = ?", (row["id"],)).fetchone()
    assert row is not None
    return dict(row)


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
    run_id: int,
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
            run_id, request_variant_id, service_id, coverage_item_id, auth_context, input_slot, attack_family,
            payload_family, payload_value_hash, probe_key, tool_name, agent_name, result_status,
            observed_http_status, signal_type, evidence_ref, notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id, probe_key) DO UPDATE SET
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
            run_id,
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
        "SELECT * FROM assessment_probe_runs WHERE run_id = ? AND probe_key = ?",
        (run_id, probe_key),
    ).fetchone()
    assert row is not None
    return dict(row)


def _upsert_surface(
    connection,
    run_id: int,
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
        INSERT INTO assessment_surfaces (run_id, surface_type, target_descriptor, source_name, rationale, evidence_ref, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id, surface_type, target_descriptor) DO UPDATE SET
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
        (run_id, surface_type, target_descriptor, source_name, rationale, evidence_ref, status_value),
    )
    row = connection.execute(
        """
        SELECT *
        FROM assessment_surfaces
        WHERE run_id = ? AND surface_type = ? AND target_descriptor = ?
        """,
        (run_id, surface_type, target_descriptor),
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
    project_id: int,
    run_id: int,
    user: User,
    *,
    identity: str,
    kind: str,
    host: str | None,
    ip_address: str | None,
    hostname: str | None,
    notes: str,
    discovered_by: str,
) -> dict[str, Any]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _upsert_target(
            connection,
            run.id,
            identity=identity,
            kind=kind,
            host=host,
            ip_address=ip_address,
            hostname=hostname,
            notes=notes,
            discovered_by=discovered_by,
        )


def list_targets(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_targets WHERE run_id = ? ORDER BY updated_at DESC, id DESC", (run.id,))


def record_service(
    project_id: int,
    run_id: int,
    user: User,
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
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _upsert_service(
            connection,
            run.id,
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


def list_services(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_services WHERE run_id = ? ORDER BY updated_at DESC, id DESC", (run.id,))


def record_request_variant(
    project_id: int,
    run_id: int,
    user: User,
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
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        variant = _upsert_request_variant(
            connection,
            run.id,
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
            run.id,
            request_variant_id=variant["id"],
            url=url,
            discovery_source=discovery_source,
            response_status=response_status,
            evidence_ref=evidence_ref,
            observation_payload=observation_payload,
        )
        return variant


def list_request_variants(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _fetch_all(
            connection,
            "SELECT * FROM assessment_request_variants WHERE run_id = ? ORDER BY last_seen_at DESC, id DESC",
            (run.id,),
        )


def list_request_observations(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _fetch_all(
            connection,
            "SELECT * FROM assessment_request_observations WHERE run_id = ? ORDER BY created_at DESC, id DESC",
            (run.id,),
        )


def ingest_request_observation(
    project_id: int,
    run_id: int,
    user: User,
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
    run = _run_or_404(project_id, run_id, user)
    scheme, host, _, _ = _parse_url(url)
    _, endpoint, port, service_name = _service_fields_from_url(url)
    identity = target_identity or host
    discovered_by = discovery_source
    with get_connection() as connection:
        target = _upsert_target(
            connection,
            run.id,
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
            run.id,
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
            run.id,
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
            run.id,
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
                    run.id,
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
    project_id: int,
    run_id: int,
    user: User,
    *,
    request_variant_id: int | None,
    service_id: int | None,
    auth_context: str,
    input_slot: str,
    attack_family: str,
    status_value: str,
    notes: str,
) -> dict[str, Any]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _upsert_coverage_item(
            connection,
            run.id,
            request_variant_id=request_variant_id,
            service_id=service_id,
            auth_context=auth_context,
            input_slot=input_slot,
            attack_family=attack_family,
            status_value=status_value,
            notes=notes,
        )


def list_coverage_items(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
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
            WHERE coverage.run_id = ?
            ORDER BY coverage.updated_at DESC, coverage.id DESC
            """,
            (run.id,),
        ).fetchall()
    return [dict(row) for row in rows]


def record_probe_run(
    project_id: int,
    run_id: int,
    user: User,
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
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _upsert_probe_run(
            connection,
            run.id,
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


def list_probe_runs(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_probe_runs WHERE run_id = ? ORDER BY created_at DESC, id DESC", (run.id,))


def record_surface(
    project_id: int,
    run_id: int,
    user: User,
    *,
    surface_type: str,
    target_descriptor: str,
    source_name: str,
    rationale: str,
    evidence_ref: str,
    status_value: str,
) -> dict[str, Any]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _upsert_surface(
            connection,
            run.id,
            surface_type=surface_type,
            target_descriptor=target_descriptor,
            source_name=source_name,
            rationale=rationale,
            evidence_ref=evidence_ref,
            status_value=status_value,
        )


def list_surfaces(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_surfaces WHERE run_id = ? ORDER BY updated_at DESC, id DESC", (run.id,))


def _finding_slug(connection, run_id: int, slug: str | None, title: str, canonical_location: str) -> str:
    if slug:
        return slug
    base = _slugify(f"{title}-{canonical_location}")
    candidate = base
    suffix = 2
    while connection.execute(
        "SELECT 1 FROM assessment_findings WHERE run_id = ? AND slug = ?",
        (run_id, candidate),
    ).fetchone():
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def _semantic_finding_match(
    connection,
    run_id: int,
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
            "SELECT * FROM assessment_findings WHERE run_id = ? AND slug = ?",
            (run_id, slug),
        ).fetchone()
        if row is not None:
            return dict(row)
    if defect_family and root_cause_key:
        row = connection.execute(
            """
            SELECT *
            FROM assessment_findings
            WHERE run_id = ?
              AND status != 'merged'
              AND defect_family = ?
              AND root_cause_key = ?
              AND auth_context = ?
              AND canonical_location = ?
            ORDER BY id ASC
            LIMIT 1
            """,
            (run_id, defect_family, root_cause_key, auth_context, canonical_location),
        ).fetchone()
        if row is not None:
            return dict(row)
    row = connection.execute(
        """
        SELECT *
        FROM assessment_findings
        WHERE run_id = ?
          AND status != 'merged'
          AND title = ?
          AND canonical_location = ?
          AND auth_context = ?
        ORDER BY id ASC
        LIMIT 1
        """,
        (run_id, title, canonical_location, auth_context),
    ).fetchone()
    return dict(row) if row is not None else None


def _upsert_finding_link(
    connection,
    run_id: int,
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
        WHERE run_id = ? AND finding_id = ? AND link_kind = ? AND target_kind = ? AND target_id IS ? AND target_ref = ?
        """,
        (run_id, finding_id, link_kind, target_kind, target_id, target_ref),
    ).fetchone()
    if row is None:
        cursor = connection.execute(
            """
            INSERT INTO assessment_finding_links (
                run_id, finding_id, link_kind, target_kind, target_id, target_ref, notes, provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (run_id, finding_id, link_kind, target_kind, target_id, target_ref, notes, _json_text(provenance)),
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
    project_id: int,
    run_id: int,
    user: User,
    *,
    slug: str | None,
    title: str,
    severity: str,
    status_value: str,
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
) -> dict[str, Any]:
    run = _run_or_404(project_id, run_id, user)
    incoming_status = _normalize_finding_status(status_value)
    incoming_severity = _normalize_severity(severity)
    with get_connection() as connection:
        existing = _semantic_finding_match(
            connection,
            run.id,
            slug=slug,
            defect_family=defect_family,
            root_cause_key=root_cause_key,
            canonical_location=canonical_location,
            auth_context=auth_context,
            title=title,
        )
        if existing is None:
            resolved_slug = _finding_slug(connection, run.id, slug, title, canonical_location)
            cursor = connection.execute(
                """
                INSERT INTO assessment_findings (
                    run_id, slug, title, severity, status, defect_family, root_cause_key, auth_context,
                    canonical_location, source_name, summary, evidence_ref, notes, details_json, provenance_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.id,
                    resolved_slug,
                    title,
                    incoming_severity,
                    incoming_status,
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
            connection.execute(
                """
                UPDATE assessment_findings
                SET title = ?,
                    severity = ?,
                    status = ?,
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
                    _stronger_severity(existing["severity"], incoming_severity),
                    _coalesce_finding_status(existing["status"], incoming_status),
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
                run.id,
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
    return {"finding": finding, "links": finding_links}


def update_finding(
    project_id: int,
    run_id: int,
    user: User,
    *,
    slug: str,
    title: str,
    severity: str,
    status_value: str,
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
        project_id,
        run_id,
        user,
        slug=slug,
        title=title,
        severity=severity,
        status_value=status_value,
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
    )
    return result["finding"]


def merge_findings(
    project_id: int,
    run_id: int,
    user: User,
    *,
    source_slug: str,
    target_slug: str,
    reason: str,
    source_name: str,
) -> dict[str, Any]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        source = connection.execute(
            "SELECT * FROM assessment_findings WHERE run_id = ? AND slug = ?",
            (run.id, source_slug),
        ).fetchone()
        target = connection.execute(
            "SELECT * FROM assessment_findings WHERE run_id = ? AND slug = ?",
            (run.id, target_slug),
        ).fetchone()
        if source is None or target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
        if source["id"] == target["id"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="cannot merge a finding into itself")
        source_confidence = _finding_confidence_tuple(source)
        target_confidence = _finding_confidence_tuple(target)
        source_stronger = source_confidence > target_confidence
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
            "SELECT * FROM assessment_finding_links WHERE run_id = ? AND finding_id = ?",
            (run.id, source["id"]),
        ).fetchall()
        connection.execute(
            """
            UPDATE assessment_findings
            SET status = 'merged',
                merged_into_finding_id = ?,
                notes = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (target["id"], _append_notes(source["notes"], reason), source["id"]),
        )
        connection.execute(
            """
            UPDATE assessment_findings
            SET severity = ?,
                status = ?,
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
            WHERE id = ?
            """,
            (
                _stronger_severity(target["severity"], source["severity"]),
                _coalesce_finding_status(target["status"], source["status"]),
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
            ),
        )
        for row in source_links:
            _upsert_finding_link(
                connection,
                run.id,
                finding_id=target["id"],
                link_kind=row["link_kind"],
                target_kind=row["target_kind"],
                target_id=row["target_id"],
                target_ref=row["target_ref"],
                notes=row["notes"],
                provenance=_json_object(row["provenance_json"]),
            )
        connection.execute(
            "DELETE FROM assessment_finding_links WHERE run_id = ? AND finding_id = ?",
            (run.id, source["id"]),
        )
        link = _upsert_finding_link(
            connection,
            run.id,
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
    return {"source": dict(source_row), "target": dict(target_row), "link": link}


def list_findings(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT findings.*, merged.slug AS merged_into_slug
            FROM assessment_findings AS findings
            LEFT JOIN assessment_findings AS merged ON merged.id = findings.merged_into_finding_id
            WHERE findings.run_id = ?
            ORDER BY
                CASE findings.status
                    WHEN 'exploited' THEN 0
                    WHEN 'confirmed' THEN 1
                    WHEN 'blocked' THEN 2
                    WHEN 'reported' THEN 3
                    WHEN 'draft' THEN 4
                    WHEN 'merged' THEN 5
                    ELSE 6
                END,
                findings.updated_at DESC,
                findings.id DESC
            """,
            (run.id,),
        ).fetchall()
    return [dict(row) for row in rows]


def create_finding_link(
    project_id: int,
    run_id: int,
    user: User,
    *,
    finding_slug: str,
    link_kind: str,
    target_kind: str,
    target_id: int | None,
    target_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        finding = connection.execute(
            "SELECT * FROM assessment_findings WHERE run_id = ? AND slug = ?",
            (run.id, finding_slug),
        ).fetchone()
        if finding is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
        return _upsert_finding_link(
            connection,
            run.id,
            finding_id=int(finding["id"]),
            link_kind=link_kind,
            target_kind=target_kind,
            target_id=target_id,
            target_ref=target_ref,
            notes=notes,
            provenance=provenance,
        )


def list_finding_links(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT links.*, findings.slug AS finding_slug
            FROM assessment_finding_links AS links
            JOIN assessment_findings AS findings ON findings.id = links.finding_id
            WHERE links.run_id = ?
            ORDER BY links.updated_at DESC, links.id DESC
            """,
            (run.id,),
        ).fetchall()
    return [dict(row) for row in rows]


def _upsert_chain_link(
    connection,
    run_id: int,
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
        WHERE run_id = ? AND chain_id = ? AND relation = ? AND entity_kind = ? AND entity_id IS ? AND entity_ref = ?
        """,
        (run_id, chain_id, relation, entity_kind, entity_id, entity_ref),
    ).fetchone()
    if row is None:
        cursor = connection.execute(
            """
            INSERT INTO assessment_attack_chain_links (
                run_id, chain_id, relation, entity_kind, entity_id, entity_ref, notes, provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (run_id, chain_id, relation, entity_kind, entity_id, entity_ref, notes, _json_text(provenance)),
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
    project_id: int,
    run_id: int,
    user: User,
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
    run = _run_or_404(project_id, run_id, user)
    resolved_key = chain_key or _slugify(title)
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO assessment_attack_chains (
                run_id, chain_key, title, status, severity, narrative, evidence_ref, provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id, chain_key) DO UPDATE SET
                title = excluded.title,
                status = excluded.status,
                severity = excluded.severity,
                narrative = CASE WHEN excluded.narrative = '' THEN assessment_attack_chains.narrative ELSE excluded.narrative END,
                evidence_ref = COALESCE(NULLIF(excluded.evidence_ref, ''), assessment_attack_chains.evidence_ref),
                provenance_json = excluded.provenance_json,
                updated_at = CURRENT_TIMESTAMP
            """,
            (run.id, resolved_key, title, status_value, _normalize_severity(severity), narrative, evidence_ref, _json_text(provenance)),
        )
        row = connection.execute(
            "SELECT * FROM assessment_attack_chains WHERE run_id = ? AND chain_key = ?",
            (run.id, resolved_key),
        ).fetchone()
        assert row is not None
        chain = dict(row)
        chain_links = [
            _upsert_chain_link(
                connection,
                run.id,
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
    project_id: int,
    run_id: int,
    user: User,
    *,
    chain_key: str,
    relation: str,
    entity_kind: str,
    entity_id: int | None,
    entity_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        chain = connection.execute(
            "SELECT * FROM assessment_attack_chains WHERE run_id = ? AND chain_key = ?",
            (run.id, chain_key),
        ).fetchone()
        if chain is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="attack chain not found")
        return _upsert_chain_link(
            connection,
            run.id,
            chain_id=int(chain["id"]),
            relation=relation,
            entity_kind=entity_kind,
            entity_id=entity_id,
            entity_ref=entity_ref,
            notes=notes,
            provenance=provenance,
        )


def list_attack_chains(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_attack_chains WHERE run_id = ? ORDER BY updated_at DESC, id DESC", (run.id,))


def list_attack_chain_links(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT links.*, chains.chain_key
            FROM assessment_attack_chain_links AS links
            JOIN assessment_attack_chains AS chains ON chains.id = links.chain_id
            WHERE links.run_id = ?
            ORDER BY links.updated_at DESC, links.id DESC
            """,
            (run.id,),
        ).fetchall()
    return [dict(row) for row in rows]


def _upsert_simple_entity(
    connection,
    *,
    table: str,
    run_id: int,
    key_column: str,
    key_value: str,
    values: dict[str, Any],
) -> dict[str, Any]:
    columns = ", ".join(["run_id", key_column, *values.keys()])
    placeholders = ", ".join(["?"] * (2 + len(values)))
    assignments = ", ".join([f"{column} = excluded.{column}" for column in values.keys()])
    connection.execute(
        f"""
        INSERT INTO {table} ({columns})
        VALUES ({placeholders})
        ON CONFLICT(run_id, {key_column}) DO UPDATE SET
            {assignments},
            updated_at = CURRENT_TIMESTAMP
        """,
        (run_id, key_value, *values.values()),
    )
    row = connection.execute(
        f"SELECT * FROM {table} WHERE run_id = ? AND {key_column} = ?",
        (run_id, key_value),
    ).fetchone()
    assert row is not None
    return dict(row)


def record_credential(
    project_id: int,
    run_id: int,
    user: User,
    *,
    credential_key: str,
    kind: str,
    principal: str,
    secret_locator: str,
    source_name: str,
    status_value: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _upsert_simple_entity(
            connection,
            table="assessment_credentials",
            run_id=run.id,
            key_column="credential_key",
            key_value=credential_key,
            values={
                "kind": kind,
                "principal": principal,
                "secret_locator": secret_locator,
                "source_name": source_name,
                "status": status_value,
                "notes": notes,
                "provenance_json": _json_text(provenance),
            },
        )


def list_credentials(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_credentials WHERE run_id = ? ORDER BY updated_at DESC, id DESC", (run.id,))


def record_credential_test(
    project_id: int,
    run_id: int,
    user: User,
    *,
    credential_id: int,
    service_id: int | None,
    target_ref: str,
    auth_context: str,
    outcome: str,
    evidence_ref: str,
    notes: str,
) -> dict[str, Any]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO assessment_credential_tests (
                run_id, credential_id, service_id, target_ref, auth_context, outcome, evidence_ref, notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (run.id, credential_id, service_id, target_ref, auth_context, outcome, evidence_ref, notes),
        )
        row = connection.execute("SELECT * FROM assessment_credential_tests WHERE id = ?", (cursor.lastrowid,)).fetchone()
    assert row is not None
    return dict(row)


def list_credential_tests(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_credential_tests WHERE run_id = ? ORDER BY updated_at DESC, id DESC", (run.id,))


def record_access_record(
    project_id: int,
    run_id: int,
    user: User,
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
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _upsert_simple_entity(
            connection,
            table="assessment_access_records",
            run_id=run.id,
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


def list_access_records(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_access_records WHERE run_id = ? ORDER BY updated_at DESC, id DESC", (run.id,))


def record_pivot(
    project_id: int,
    run_id: int,
    user: User,
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
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _upsert_simple_entity(
            connection,
            table="assessment_pivots",
            run_id=run.id,
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


def list_pivots(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_pivots WHERE run_id = ? ORDER BY updated_at DESC, id DESC", (run.id,))


def record_tunnel(
    project_id: int,
    run_id: int,
    user: User,
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
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _upsert_simple_entity(
            connection,
            table="assessment_tunnels",
            run_id=run.id,
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


def list_tunnels(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_tunnels WHERE run_id = ? ORDER BY updated_at DESC, id DESC", (run.id,))


def record_blocked_technique(
    project_id: int,
    run_id: int,
    user: User,
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
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _upsert_simple_entity(
            connection,
            table="assessment_blocked_techniques",
            run_id=run.id,
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


def list_blocked_techniques(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_blocked_techniques WHERE run_id = ? ORDER BY updated_at DESC, id DESC", (run.id,))


def assessment_summary(project_id: int, run_id: int, user: User) -> dict[str, Any]:
    run = _run_or_404(project_id, run_id, user)
    with get_connection() as connection:
        target_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_targets WHERE run_id = ?", (run.id,))
        service_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_services WHERE run_id = ?", (run.id,))
        request_variant_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_request_variants WHERE run_id = ?", (run.id,))
        request_observation_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_request_observations WHERE run_id = ?", (run.id,))
        coverage_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_coverage_items WHERE run_id = ?", (run.id,))
        probe_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_probe_runs WHERE run_id = ?", (run.id,))
        finding_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_findings WHERE run_id = ?", (run.id,))
        open_surface_count = _scalar_row(
            connection,
            "SELECT COUNT(*) FROM assessment_surfaces WHERE run_id = ? AND status IN ('discovered', 'deferred')",
            (run.id,),
        )
        credential_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_credentials WHERE run_id = ?", (run.id,))
        access_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_access_records WHERE run_id = ?", (run.id,))
        pivot_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_pivots WHERE run_id = ?", (run.id,))
        tunnel_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_tunnels WHERE run_id = ?", (run.id,))
        blocked_technique_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_blocked_techniques WHERE run_id = ?", (run.id,))
        chain_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_attack_chains WHERE run_id = ?", (run.id,))
        coverage_rows = connection.execute(
            "SELECT status, COUNT(*) AS total FROM assessment_coverage_items WHERE run_id = ? GROUP BY status ORDER BY status ASC",
            (run.id,),
        ).fetchall()
        finding_rows = connection.execute(
            "SELECT status, COUNT(*) AS total FROM assessment_findings WHERE run_id = ? GROUP BY status ORDER BY status ASC",
            (run.id,),
        ).fetchall()
        top_surfaces = connection.execute(
            """
            SELECT *
            FROM assessment_surfaces
            WHERE run_id = ?
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
            (run.id,),
        ).fetchall()
        top_findings = connection.execute(
            """
            SELECT slug, title, severity, status, canonical_location, summary, source_name, updated_at
            FROM assessment_findings
            WHERE run_id = ?
            ORDER BY
                CASE status
                    WHEN 'exploited' THEN 0
                    WHEN 'confirmed' THEN 1
                    WHEN 'blocked' THEN 2
                    WHEN 'reported' THEN 3
                    WHEN 'draft' THEN 4
                    ELSE 5
                END,
                updated_at DESC
            LIMIT 10
            """,
            (run.id,),
        ).fetchall()
        recent_probes = connection.execute(
            """
            SELECT result_status, attack_family, signal_type, agent_name, evidence_ref, created_at
            FROM assessment_probe_runs
            WHERE run_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT 10
            """,
            (run.id,),
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
            WHERE coverage.run_id = ? AND coverage.status IN ('pending', 'queued', 'deferred')
            ORDER BY coverage.updated_at DESC, coverage.id DESC
            LIMIT 12
            """,
            (run.id,),
        ).fetchall()
        attack_chains = connection.execute(
            """
            SELECT chain_key, title, status, severity, narrative, updated_at
            FROM assessment_attack_chains
            WHERE run_id = ?
            ORDER BY updated_at DESC, id DESC
            LIMIT 8
            """,
            (run.id,),
        ).fetchall()
        service_coverage_gaps = connection.execute(
            """
            SELECT services.endpoint, services.service, services.coverage_status, services.updated_at
            FROM assessment_services AS services
            WHERE services.run_id = ? AND services.coverage_status IN ('pending', 'partial', 'blocked')
            ORDER BY services.updated_at DESC, services.id DESC
            LIMIT 10
            """,
            (run.id,),
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
        "coverage_statuses": {row["status"]: int(row["total"]) for row in coverage_rows},
        "finding_statuses": {row["status"]: int(row["total"]) for row in finding_rows},
        "top_surfaces": [dict(row) for row in top_surfaces],
        "top_findings": [dict(row) for row in top_findings],
        "recent_probes": [dict(row) for row in recent_probes],
        "open_coverage_items": [dict(row) for row in open_coverage_items],
        "attack_chains": [dict(row) for row in attack_chains],
        "service_coverage_gaps": [dict(row) for row in service_coverage_gaps],
    }
