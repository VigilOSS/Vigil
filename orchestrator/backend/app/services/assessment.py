from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, status

from ..db import get_connection
from ..models.user import User
from .events import _run_or_404, list_events_for_run
from . import state_manager as canonical_state

PHASE_WORKER_MATRIX = [
    {
        "phase": "recon",
        "title": "Recon / Enumeration",
        "workers": [
            {"agent": "recon-specialist", "responsibility": "network and service enumeration"},
            {"agent": "source-analyzer", "responsibility": "source and asset analysis"},
            {"agent": "osint-analyst", "responsibility": "external context and intelligence"},
        ],
    },
    {
        "phase": "collect",
        "title": "Collect / Coverage",
        "workers": [
            {"agent": "recon-specialist", "responsibility": "seed targets and ports"},
            {"agent": "source-analyzer", "responsibility": "expand routes and attack inputs"},
            {"agent": "fuzzer", "responsibility": "augment coverage candidates"},
        ],
    },
    {
        "phase": "test",
        "title": "Validation / Testing",
        "workers": [
            {"agent": "vulnerability-analyst", "responsibility": "validate web and service findings"},
            {"agent": "source-analyzer", "responsibility": "explain code paths and attackability"},
            {"agent": "fuzzer", "responsibility": "exercise payload families and edge cases"},
        ],
    },
    {
        "phase": "exploit",
        "title": "Exploit / Post-Access",
        "workers": [
            {"agent": "exploit-developer", "responsibility": "exploit development and chaining"},
            {"agent": "osint-analyst", "responsibility": "intel-driven pivots and enrichment"},
            {"agent": "vulnerability-analyst", "responsibility": "impact confirmation and retest"},
        ],
    },
    {
        "phase": "athena",
        "title": "Athena / Log Investigation",
        "workers": [
            {"agent": "osint-analyst", "responsibility": "telemetry pivots and historical activity review"},
            {"agent": "operator", "responsibility": "map findings and payloads into log queries"},
            {"agent": "report-writer", "responsibility": "capture exploitation-history conclusions"},
        ],
    },
    {
        "phase": "report",
        "title": "Report / Review",
        "workers": [
            {"agent": "report-writer", "responsibility": "finding synthesis and report generation"},
            {"agent": "operator", "responsibility": "coverage review and phase closure"},
        ],
    },
]


def _json_text(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True, separators=(",", ":"))


def _hash_json(value: Any) -> str:
    return hashlib.sha256(_json_text(value).encode("utf-8")).hexdigest()


def _scalar_row(connection, query: str, params: tuple[Any, ...]) -> int:
    row = connection.execute(query, params).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _find_target_id(connection, run_id: int, identity: str | None) -> int | None:
    if not identity:
        return None
    row = connection.execute(
        "SELECT id FROM assessment_targets WHERE run_id = ? AND identity = ?",
        (run_id, identity),
    ).fetchone()
    return int(row["id"]) if row else None


def _parse_url(url: str) -> tuple[str, str, int, str]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="request url must be absolute")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    normalized_path = parsed.path or "/"
    return parsed.scheme, parsed.hostname, port, normalized_path


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
            (run.id, identity, kind, host, ip_address, hostname, notes, discovered_by),
        )
        row = connection.execute(
            """
            SELECT id, run_id, identity, kind, host, ip_address, hostname, notes, discovered_by, created_at, updated_at
            FROM assessment_targets
            WHERE run_id = ? AND identity = ?
            """,
            (run.id, identity),
        ).fetchone()
    return dict(row)


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
        target_id = _find_target_id(connection, run.id, target_identity)
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
            (run.id, target_id, endpoint, port, protocol, service, state, coverage_status, banner, notes, discovered_by),
        )
        row = connection.execute(
            """
            SELECT id, run_id, target_id, endpoint, port, protocol, service, state, coverage_status, banner, notes, discovered_by, created_at, updated_at
            FROM assessment_services
            WHERE run_id = ? AND endpoint = ? AND protocol = ?
            """,
            (run.id, endpoint, protocol),
        ).fetchone()
    return dict(row)


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
    with get_connection() as connection:
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
                run.id,
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
            (run.id, scheme, host, port, method.upper(), normalized_path, auth_context, params_schema_hash, body_schema_hash, content_type_family),
        ).fetchone()
        assert row is not None
        connection.execute(
            """
            INSERT INTO assessment_request_observations (
                run_id, request_variant_id, observed_url, source_name, response_status, evidence_ref, raw_payload
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (run.id, row["id"], url, discovery_source, response_status, evidence_ref, _json_text(observation_payload or {})),
        )
    return dict(row)


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
        connection.execute(
            """
            INSERT INTO assessment_coverage_items (
                run_id, request_variant_id, service_id, auth_context, input_slot, attack_family, status, notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id, request_variant_id, service_id, auth_context, input_slot, attack_family) DO UPDATE SET
                status = excluded.status,
                notes = CASE
                    WHEN excluded.notes = '' THEN assessment_coverage_items.notes
                    WHEN assessment_coverage_items.notes = '' THEN excluded.notes
                    ELSE assessment_coverage_items.notes || char(10) || excluded.notes
                END,
                updated_at = CURRENT_TIMESTAMP
            """,
            (run.id, request_variant_id, service_id, auth_context, input_slot, attack_family, status_value, notes),
        )
        row = connection.execute(
            """
            SELECT *
            FROM assessment_coverage_items
            WHERE run_id = ? AND request_variant_id IS ? AND service_id IS ? AND auth_context = ? AND input_slot = ? AND attack_family = ?
            """,
            (run.id, request_variant_id, service_id, auth_context, input_slot, attack_family),
        ).fetchone()
    assert row is not None
    return dict(row)


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
    with get_connection() as connection:
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
                run.id,
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
            (run.id, probe_key),
        ).fetchone()
    assert row is not None
    return dict(row)


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
            (run.id, surface_type, target_descriptor, source_name, rationale, evidence_ref, status_value),
        )
        row = connection.execute(
            """
            SELECT *
            FROM assessment_surfaces
            WHERE run_id = ? AND surface_type = ? AND target_descriptor = ?
            """,
            (run.id, surface_type, target_descriptor),
        ).fetchone()
    assert row is not None
    return dict(row)


def list_surfaces(project_id: int, run_id: int, user: User) -> list[dict[str, Any]]:
    return canonical_state.list_surfaces(project_id, run_id, user)


def assessment_summary(project_id: int, run_id: int, user: User) -> dict[str, Any]:
    payload = canonical_state.assessment_summary(project_id, run_id, user)
    _run_or_404(project_id, run_id, user)
    events = list_events_for_run(project_id, run_id, user)
    active_by_phase: dict[str, set[str]] = defaultdict(set)
    for event in events[-100:]:
        if event.event_type.startswith("task.") or event.event_type == "artifact.updated":
            phase = event.phase if event.phase != "unknown" else "recon"
            active_by_phase[phase].add(event.agent_name)
    phase_workers = []
    for item in PHASE_WORKER_MATRIX:
        phase_workers.append(
            {
                **item,
                "active_agents": sorted(active_by_phase.get(item["phase"], set())),
            }
        )
    payload["phase_workers"] = phase_workers
    return payload
