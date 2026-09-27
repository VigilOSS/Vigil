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
    _fetch_all,
    _hash_json,
    _json_text,
    _parse_url,
)
from .work_buffer import _derive_work_item, mark_work_items_done
from .app_units import _surface_host_path, _path_under_prefix



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
    # Backend enforcement keeps the durable schema name-only even when a caller
    # accidentally submits captured values. Values (tokens, tenant ids, CSRF
    # secrets) never participate in deduplication or persistence.
    normalized_header_schema = (
        {str(name).strip(): "" for name in header_schema if str(name).strip()}
        if isinstance(header_schema, dict)
        else {}
    )
    params_schema_hash = _hash_json(
        {
            "query": query_schema or {},
            "path": path_schema or {},
            "cookie": cookie_schema or {},
            "headers": normalized_header_schema,
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
            _json_text(normalized_header_schema),
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
    if (
        normalized_status == CoverageStatus.COVERED
        and input_slot.startswith("header:")
        and attack_family == "identity-header-review"
    ):
        _require_identity_header_write_coverage(
            connection,
            engagement_id,
            {
                "request_variant_id": request_variant_id,
                "input_slot": input_slot,
                "attack_family": attack_family,
            },
        )
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
    outcome_assertion: str = "",
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
            observed_http_status, signal_type, outcome_assertion, evidence_ref, notes,
            target_host, target_path, target_port,
            lens, finding_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, probe_key) DO UPDATE SET
            agent_name = COALESCE(NULLIF(excluded.agent_name, ''), assessment_probe_runs.agent_name),
            result_status = excluded.result_status,
            observed_http_status = COALESCE(excluded.observed_http_status, assessment_probe_runs.observed_http_status),
            signal_type = COALESCE(NULLIF(excluded.signal_type, ''), assessment_probe_runs.signal_type),
            -- result_status and its application-level assertion are one
            -- adjudication. A later inconclusive/attempted re-run must clear a
            -- stale positive assertion instead of inheriting it.
            outcome_assertion = excluded.outcome_assertion,
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
            outcome_assertion,
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
    framework_registration: str,
) -> dict[str, Any]:
    connection.execute(
        """
        INSERT INTO assessment_surfaces (engagement_id, surface_type, target_descriptor, source_name, rationale, evidence_ref, status, framework_registration)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, surface_type, target_descriptor) DO UPDATE SET
            source_name = COALESCE(NULLIF(excluded.source_name, ''), assessment_surfaces.source_name),
            rationale = CASE
                WHEN excluded.rationale = '' THEN assessment_surfaces.rationale
                WHEN assessment_surfaces.rationale = '' THEN excluded.rationale
                ELSE assessment_surfaces.rationale || char(10) || excluded.rationale
            END,
            evidence_ref = COALESCE(NULLIF(excluded.evidence_ref, ''), assessment_surfaces.evidence_ref),
            framework_registration = COALESCE(
                NULLIF(excluded.framework_registration, ''),
                assessment_surfaces.framework_registration
            ),
            -- Re-observation enriches the row; status changes require PATCH.
            updated_at = CURRENT_TIMESTAMP
        """,
        (engagement_id, surface_type, target_descriptor, source_name, rationale, evidence_ref, status_value, framework_registration),
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
    for header_name in _security_relevant_header_names(header_schema):
        candidates.append(
            {
                "input_slot": f"header:{header_name}",
                "attack_family": "identity-header-review",
                "status": "pending",
                "notes": "Auto-generated name-only trust-header obligation from request observation",
            }
        )
    return candidates


_IDENTITY_HEADER_TOKENS = (
    "api-key", "apikey", "auth", "token", "csrf", "xsrf", "tenant",
    "user", "account", "principal", "role", "group", "org", "permission",
    "privilege", "forwarded", "original", "rewrite", "method-override",
    "admin", "internal", "client-id", "impersonat", "acting",
)
_HEADER_NOISE_TOKENS = ("trace", "request-id", "correlation", "b3", "sentry")
_COMMODITY_TRUST_HEADERS = frozenset(
    {
        "host",
        "x-forwarded-for",
        "x-forwarded-proto",
    }
)


def _security_relevant_header_names(header_schema: Any) -> list[str]:
    """Return canonical names for app-specific identity/trust header inputs.

    The request-schema owner has already removed transport/browser noise. This
    second, intentionally conservative filter materializes only identity,
    authorization, routing-trust, or method-override names as obligations; it
    avoids turning observability ids into fake security work.
    """
    if not isinstance(header_schema, dict):
        return []
    names: set[str] = set()
    for raw_name in header_schema:
        name = str(raw_name).strip().lower()
        if (
            not name
            or name in _COMMODITY_TRUST_HEADERS
            or any(token in name for token in _HEADER_NOISE_TOKENS)
        ):
            continue
        if any(token in name for token in _IDENTITY_HEADER_TOKENS):
            names.add(name)
    return sorted(names)


def _slot_class(input_slot: str | None) -> str:
    """Base slot class of an ``input_slot``, tolerating the ``slot:name`` probe
    convention (``header:X-Forwarded-Host`` -> ``header``).

    Coverage-item candidates are always coarse today (``endpoint|query|body|path|
    cookie|header|service``), so this is a forward guard, not a live-bug fix: if a
    prefixed slot ever reaches candidate linkage, the service-vs-request-variant
    decision still keys on the base class instead of mis-linking on the full
    string. For a coarse value with no ``:`` it returns the value unchanged, so
    existing behavior is preserved exactly.
    """
    return str(input_slot or "unknown").split(":", 1)[0]

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
    work_item: dict[str, Any] | None = None,
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
        is_service = _slot_class(candidate.get("input_slot")) == "service"
        key = (
            request_variant["id"] if not is_service else None,
            service["id"] if is_service else None,
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
    derived_work_item = _derive_work_item(
        connection,
        engagement_id,
        request_variant=request_variant,
        service=service,
        coverage_items=coverage_items,
        auth_context=auth_context,
        discovery_source=discovery_source,
        work_item=work_item,
    )
    return {
        "target": target,
        "service": service,
        "request_variant": request_variant,
        "request_observation": observation,
        "coverage_items": coverage_items,
        "work_item": derived_work_item,
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
    work_item: dict[str, Any] | None = None,
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
            work_item=work_item,
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
    status: str = "",
    attack_family: str = "",
    input_slot: str = "",
    auth_context: str = "",
    target_host: str = "",
    request_variant_id: int | None = None,
    service_id: int | None = None,
    limit: int = DEFAULT_COVERAGE_ITEM_LIMIT,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    limit, offset = _bounded_assessment_list_window(limit, offset)
    # Optional exact-match filters, mirroring ``list_probe_runs``. Column names
    # are a fixed allowlist, never caller text, so the f-string interpolation is
    # safe; every value is bound. An unknown VALUE narrows to zero rows — the
    # ledger fails closed rather than returning the whole table, which is the
    # "measured nothing looks like measured everything" shape.
    clauses = ["coverage.engagement_id = ?"]
    params: list[Any] = [engagement.id]
    for column, value in (
        ("coverage.status", status),
        ("coverage.attack_family", attack_family),
        ("coverage.input_slot", input_slot),
        ("coverage.auth_context", auth_context),
        ("request_variants.host", target_host),
    ):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    for column, numeric in (
        ("coverage.request_variant_id", request_variant_id),
        ("coverage.service_id", service_id),
    ):
        if numeric is not None:
            clauses.append(f"{column} = ?")
            params.append(int(numeric))
    params.extend([limit, offset])
    with _common.get_connection() as connection:
        rows = connection.execute(
            f"""
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
            WHERE {" AND ".join(clauses)}
            ORDER BY coverage.updated_at DESC, coverage.id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        ).fetchall()
    return [dict(row) for row in rows]

def _pending_work_item_ids_for_coverage_item(
    connection, engagement_id: int, coverage_item_id: int
) -> list[int]:
    """Ids of still-actionable work-items FK-linked to a coverage-item (1b drain).

    The default FK-derived drain target. An ingested observation links its work
    item to the deterministic endpoint-slot coverage item
    (``work_buffer._pick_coverage_item_id``), so a covering probe carrying that
    ``coverage_item_id`` drains exactly the buffered work it satisfies. Only
    ``pending``/``processing`` rows are returned — a ``done``/``skipped``/``error``
    row is already terminal and re-draining it would inflate ``affected`` with no
    state change.
    """
    rows = connection.execute(
        "SELECT id FROM assessment_work_items "
        "WHERE engagement_id = ? AND coverage_item_id = ? "
        "AND status IN ('pending', 'processing')",
        (engagement_id, coverage_item_id),
    ).fetchall()
    return [int(r["id"]) for r in rows]


def _advance_surfaces_for_request_variant(
    connection,
    engagement_id: int,
    request_variant_id: int,
    *,
    attack_family: str,
    result_status: str,
    notes: str,
) -> list[dict[str, Any]]:
    """Advance every DISCOVERED surface FK-linked to a request variant to
    ``partially-covered`` (1b default surface advance).

    Surfaces are linked to request variants through
    ``surface_request_variant_links`` (``work-buffer link-surface`` / ingest
    auto-linking). A covering probe carrying the variant id advances each surface
    still in the seed ``discovered`` state — a single probe partially covers, so
    ``partially-covered`` + a synthesized followup. A surface already resolved by
    a HUMAN verdict (``covered`` / ``not_applicable`` / ``deferred``) or already
    ``partially-covered`` is LEFT UNTOUCHED, so the default cascade can never
    regress a deliberate verdict (surface→``covered`` stays a rationale-bearing
    human decision, ADR 0001 d3).
    """
    link_rows = connection.execute(
        "SELECT DISTINCT link.surface_id AS surface_id, surfaces.status AS status "
        "FROM surface_request_variant_links AS link "
        "JOIN assessment_surfaces AS surfaces ON surfaces.id = link.surface_id "
        "WHERE link.engagement_id = ? AND link.request_variant_id = ?",
        (engagement_id, request_variant_id),
    ).fetchall()
    rationale = notes.strip() or f"probe recorded: {attack_family} {result_status}"
    followup = (
        f"partially covered by a {attack_family} probe ({result_status}); "
        "remaining vuln families for this surface still need coverage"
    )
    advanced: list[dict[str, Any]] = []
    for row in link_rows:
        if str(row["status"] or "") != "discovered":
            continue
        advanced.append(
            update_surface(
                engagement_id,
                int(row["surface_id"]),
                status_value="partially-covered",
                rationale=rationale,
                followup_condition=followup,
            )
        )
    return advanced


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
    outcome_assertion: str = "",
    evidence_ref: str,
    notes: str,
    target_host: str = "",
    target_path: str = "",
    target_port: int | None = None,
    lens: str = "",
    finding_id: int | None = None,
    work_item_ids: list[int] | None = None,
    resolve_surface_id: int | None = None,
    no_drain: bool = False,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    outcome_assertion = (outcome_assertion or "").strip()
    if result_status == "signal" and not outcome_assertion:
        result_status = "attempted"
        demotion_note = (
            "Signal demoted to attempted: no application-level outcome assertion "
            "was supplied; HTTP status or response size alone is inconclusive."
        )
        notes = f"{notes.rstrip()}\n{demotion_note}".lstrip()
    with _common.get_connection() as connection:
        record = _upsert_probe_run(
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
            outcome_assertion=outcome_assertion,
            evidence_ref=evidence_ref,
            notes=notes,
            target_host=target_host,
            target_path=target_path,
            target_port=target_port,
            lens=lens,
            finding_id=finding_id,
        )
        # 1b — DEFAULT-ON FK-derived cascade (the coverage-state write-unification
        # fix). A covering probe (normalized ``result_status`` in
        # PROBE_RESULT_STATUSES_COVERING) that carries a coverage-item / request-
        # variant link BY DEFAULT (a) drains the work-items linked to that
        # coverage-item and (b) advances the mapped surface(s) to
        # ``partially-covered`` — the SAME writes the former opt-in path did, made
        # the default so the write-side ledgers (work_items.status, surfaces.status)
        # stop disagreeing with the probe-derived truth the depth ledger already
        # computes. ``get_connection`` is re-entrant and commits at the outermost
        # depth, so the nested drains/advances commit atomically with the probe.
        #
        # Gate + valves (hard invariants):
        #   * COVERING-GATED: a non-covering attempt (attempted/blocked/no-signal/
        #     error) never auto-cascades — only whitelisted tested/signal counts;
        #     ``status="completed"`` alone never counts.
        #   * ``no_drain`` suppresses the whole default cascade.
        #   * EXPLICIT ``work_item_ids`` / ``resolve_surface_id`` OVERRIDE the
        #     derivation (narrow to those exact ids) and fire regardless of the
        #     covering gate — an operator can always drain/advance explicitly.
        #   * coverage_items.status is NEVER auto-promoted, and the surface advance
        #     only touches ``discovered`` surfaces (no regression of a human
        #     covered/not_applicable/deferred verdict).
        #
        # Unknown work-item ids are silently skipped (mirrors POST /work-items/done)
        # so a stale id never rolls the probe write back; the ``affected`` count
        # surfaces a short drain.
        covering = str(record.get("result_status") or "") in PROBE_RESULT_STATUSES_COVERING

        drain_ids: list[int] = []
        if work_item_ids:
            drain_ids = [int(x) for x in work_item_ids]
        elif covering and not no_drain and coverage_item_id is not None:
            drain_ids = _pending_work_item_ids_for_coverage_item(
                connection, engagement.id, int(coverage_item_id)
            )
        if drain_ids:
            record["work_items_done"] = mark_work_items_done(engagement.id, drain_ids)

        # A bad explicit surface id 404s and rolls the whole txn back; the probe
        # upsert is idempotent on its probe_key, so a corrected re-run is safe.
        if resolve_surface_id is not None:
            record["surface_resolved"] = update_surface(
                engagement.id,
                resolve_surface_id,
                status_value="partially-covered",
                rationale=(notes.strip() or f"probe recorded: {attack_family} {result_status}"),
                followup_condition=(
                    f"partially covered by a {attack_family} probe ({result_status}); "
                    "remaining vuln families for this surface still need coverage"
                ),
            )
        elif covering and not no_drain and request_variant_id is not None:
            advanced = _advance_surfaces_for_request_variant(
                connection,
                engagement.id,
                int(request_variant_id),
                attack_family=attack_family,
                result_status=str(record.get("result_status") or ""),
                notes=notes,
            )
            if advanced:
                record["surfaces_advanced"] = advanced
        return record

def list_probe_runs(
    engagement_id: int,
    *,
    attack_family: str = "",
    target_host: str = "",
    target_path: str = "",
    auth_context: str = "",
    result_status: str = "",
    limit: int = DEFAULT_PROBE_RUN_LIMIT,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    limit, offset = _bounded_probe_run_window(limit, offset)
    # Optional exact-match filters (empty string = no filter). Column names are a
    # fixed allowlist, never caller text, so the f-string interpolation is safe;
    # every value is bound. Lets `fetch probe-runs?attack_family=sqli` return only
    # that family instead of the full unfiltered set (the silent no-op it was).
    clauses = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    for column, value in (
        ("attack_family", attack_family),
        ("target_host", target_host),
        ("target_path", target_path),
        ("auth_context", auth_context),
        ("result_status", result_status),
    ):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    params.extend([limit, offset])
    with _common.get_connection() as connection:
        return _fetch_all(
            connection,
            f"""
            SELECT *
            FROM assessment_probe_runs
            WHERE {" AND ".join(clauses)}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )


_ATTEMPT_FIELDS: tuple[str, ...] = (
    "id", "target_host", "target_path", "target_port", "auth_context",
    "attack_family", "lens", "result_status", "observed_http_status",
    "signal_type", "outcome_assertion", "tool_name", "agent_name",
    "finding_id", "finding_slug",
    "finding_title", "finding_severity", "created_at",
)


def _serialize_attempt(row: dict[str, Any]) -> dict[str, Any]:
    """Project a probe-run⋈finding row onto the pinned ``/attempts`` shape.

    ``finding_*`` fields are ``None`` for probes with no linked finding (the
    LEFT JOIN yields nulls). ``request_variant_id`` is read for the surface
    containment test but never emitted — the wire shape carries only the
    finding-joined attempt fields the CLI groups by lens × result_status.
    """
    return {field: row.get(field) for field in _ATTEMPT_FIELDS}


def _attempt_matches_surface(
    row: dict[str, Any],
    *,
    linked_variant_ids: set[int],
    surface_host: str,
    surface_path: str,
) -> bool:
    """A probe belongs to ``surface`` when EITHER its ``request_variant_id`` is
    FK-linked to the surface (``surface_request_variant_links``) OR its
    ``target_host``/``target_path`` is contained by the surface descriptor.

    The containment arm is load-bearing: most CLI-recorded probes carry a null
    ``request_variant_id`` (raw/list-mode), so a link-table-only match would
    silently under-count them. Reuses the same host-equality + prefix-containment
    helpers the depth ledger uses for probe→unit mapping.
    """
    vid = row.get("request_variant_id")
    if vid is not None and int(vid) in linked_variant_ids:
        return True
    if not surface_host:
        return False
    t_host = str(row.get("target_host") or "").strip().lower()
    if not t_host or t_host != surface_host:
        return False
    t_path = str(row.get("target_path") or "/") or "/"
    return _path_under_prefix(t_path, surface_path)


def list_attempts(
    engagement_id: int,
    *,
    finding: str = "",
    surface_id: int | None = None,
    target_host: str = "",
    attack_family: str = "",
    result_status: str = "",
    lens: str = "",
    limit: int = DEFAULT_PROBE_RUN_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    """Finding-joined, surface-aware read of recorded probe attempts (A4a).

    A "what has actually been tried against this finding / surface / host, and did
    it land" view so a specialist does not re-run an already-walled probe. Additive
    to ``list_probe_runs`` (that raw read is unchanged): this LEFT JOINs
    ``assessment_findings`` so each attempt carries the linked finding's
    slug/title/severity (null when unlinked), and supports a ``finding`` SLUG filter
    (resolved slug→id server-side) and a ``surface`` filter that matches BOTH
    FK-linked and target-descriptor-contained probes.

    Returns ``{"attempts": [...], "count": <len>}`` — a flat, ordered
    (created_at DESC) list; grouping by lens × result_status is done CLI-side.
    """
    engagement = _engagement_or_404(engagement_id)
    limit, offset = _bounded_probe_run_window(limit, offset)

    with _common.get_connection() as connection:
        finding_id_filter: int | None = None
        if finding:
            frow = connection.execute(
                "SELECT id FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
                (engagement.id, finding),
            ).fetchone()
            if frow is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"finding slug '{finding}' not found",
                )
            finding_id_filter = int(frow["id"])

        # Resolve the surface row ONCE: its linked variant ids + parsed host/path.
        surface_active = surface_id is not None
        linked_variant_ids: set[int] = set()
        surface_host = ""
        surface_path = "/"
        if surface_active:
            srow = connection.execute(
                "SELECT target_descriptor FROM assessment_surfaces WHERE engagement_id = ? AND id = ?",
                (engagement.id, surface_id),
            ).fetchone()
            if srow is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"surface id={surface_id} not found",
                )
            surface_host, surface_path = _surface_host_path(str(srow["target_descriptor"] or ""))
            link_rows = connection.execute(
                "SELECT request_variant_id FROM surface_request_variant_links "
                "WHERE engagement_id = ? AND surface_id = ?",
                (engagement.id, surface_id),
            ).fetchall()
            linked_variant_ids = {int(r["request_variant_id"]) for r in link_rows}

        # SQL applies the exact-match column filters (fixed allowlist, every value
        # bound). The surface filter cannot be a WHERE clause (path containment is
        # segment-wise), so when it is active the window is sliced in Python after
        # filtering (so ``count`` and the window stay consistent). When it is NOT
        # active there is no post-fetch filter, so bound the window in SQL (like
        # ``list_probe_runs``) instead of loading every matching probe row.
        clauses = ["probe.engagement_id = ?"]
        params: list[Any] = [engagement.id]
        if finding_id_filter is not None:
            clauses.append("probe.finding_id = ?")
            params.append(finding_id_filter)
        for column, value in (
            ("probe.target_host", target_host),
            ("probe.attack_family", attack_family),
            ("probe.result_status", result_status),
            ("probe.lens", lens),
        ):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)

        sql = f"""
            SELECT
                probe.id, probe.target_host, probe.target_path, probe.target_port,
                probe.auth_context, probe.attack_family, probe.lens, probe.result_status,
                probe.observed_http_status, probe.signal_type, probe.tool_name,
                probe.agent_name, probe.request_variant_id, probe.finding_id, probe.created_at,
                finding.slug AS finding_slug,
                finding.title AS finding_title,
                finding.severity AS finding_severity
            FROM assessment_probe_runs AS probe
            LEFT JOIN assessment_findings AS finding
                ON probe.finding_id = finding.id
            WHERE {" AND ".join(clauses)}
            ORDER BY probe.created_at DESC, probe.id DESC
            """
        fetch_params = list(params)
        if not surface_active:
            sql += "            LIMIT ? OFFSET ?\n            "
            fetch_params.extend([limit, offset])
        rows = _fetch_all(connection, sql, tuple(fetch_params))

    if surface_active:
        rows = [
            row for row in rows
            if _attempt_matches_surface(
                row,
                linked_variant_ids=linked_variant_ids,
                surface_host=surface_host,
                surface_path=surface_path,
            )
        ]
        window = rows[offset:offset + limit]
    else:
        window = rows  # already bounded by SQL LIMIT/OFFSET above
    attempts = [_serialize_attempt(row) for row in window]
    return {"attempts": attempts, "count": len(attempts)}


def record_surface(
    engagement_id: int,
    *,
    surface_type: str,
    target_descriptor: str,
    source_name: str,
    rationale: str,
    evidence_ref: str,
    status_value: str,
    framework_registration: str = "",
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
            framework_registration=framework_registration,
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
    if status_value is not None and status_value not in SURFACE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid surface status '{status_value}'; allowed: {sorted(s.value for s in SURFACE_STATUSES)}",
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

# W3 — backend web coverage-completeness gate (report_readiness).
WEB_ROUTE_REAL_APP_THRESHOLD = 6
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

    ``*.example.com`` and ``example.com`` both reduce to ``example.com``; what
    the apex then COVERS differs by side (see ``_host_matches_scope_pattern``
    vs ``_host_matches_deny_pattern``).
    """
    p = (pattern or "").strip().lower()
    if p.startswith("*."):
        p = p[2:]
    return p


def _scope_pattern_is_wildcard(pattern: str) -> bool:
    """True for a ``*.example.com``-shaped entry (the only subdomain-expanding
    entry kind the CLI ``scope.classify_scope_entry`` recognises)."""
    p = (pattern or "").strip().lower()
    return p.startswith("*.") and len(p) > 2


def _host_matches_scope_pattern(host: str, pattern: str) -> bool:
    """ALLOWLIST match: ``host`` is the apex of ``pattern`` or a subdomain of it.

    A literal allow entry expands to its subtree here (the HackerOne/Bugcrowd
    reading of a bare program-scope host). That is deliberately permissive: an
    over-broad ALLOW only ever ADDS coverage obligations, so it fails in the
    safe direction for a completeness gate. The denylist does NOT mirror it —
    see :func:`_host_matches_deny_pattern`.
    """
    apex = _scope_pattern_apex(pattern)
    if not apex or not host:
        return False
    return host == apex or host.endswith("." + apex)


def _host_matches_deny_pattern(host: str, pattern: str) -> bool:
    """DENYLIST match — asymmetric with the allowlist ON PURPOSE.

    A wildcard carve-out (``*.staging.example.com``) covers its apex and every
    subdomain, exactly as on the allow side. A LITERAL carve-out
    (``example.com``) covers ONLY that one host: the CLI's canonical
    :func:`scope.entry_matches_host` matches a ``bare_host`` entry by equality,
    and a scope.json that carves out an apex while listing two dozen of its
    subdomains as in-scope means the apex host and nothing else.

    The asymmetry is the point. The denylist WINS, so an over-broad deny
    silently ERASES coverage obligations while an over-broad allow only adds
    them. Apex-expanding a literal carve-out is what dropped 155 of 176
    deep-required app units in a prior run: a single literal apex carve-out
    swallowed every explicitly in-scope wildcard product host, leaving only
    the non-product hosts behind.
    """
    apex = _scope_pattern_apex(pattern)
    if not apex or not host:
        return False
    if _scope_pattern_is_wildcard(pattern):
        return host == apex or host.endswith("." + apex)
    return host == apex


def _host_admitted_by_scope(
    host: str, allow_patterns: list[str], deny_patterns: list[str]
) -> bool:
    """Scope admission primitive: in the allowlist AND not in the denylist.

    Mirrors the CLI ``scope.host_admitted`` contract (the denylist always wins)
    so the W3 gate filters route hosts through the same allow/deny semantics the
    rest of the engagement trusts. Allow and deny matching are NOT the same
    predicate: only ``*.`` carve-outs extend a denial to a subtree.
    """
    if not host:
        return False
    if not any(_host_matches_scope_pattern(host, p) for p in allow_patterns):
        return False
    if any(_host_matches_deny_pattern(host, p) for p in deny_patterns):
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
            "SELECT slug, canonical_location, status, verification_status, "
            "severity, auth_context, merged_into_finding_id "
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
        if (
            normalized_status == CoverageStatus.COVERED
            and str(row["input_slot"]).startswith("header:")
            and str(row["attack_family"]) == "identity-header-review"
        ):
            _require_identity_header_write_coverage(
                connection, engagement.id, dict(row)
            )
        connection.execute(
            "UPDATE assessment_coverage_items SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND engagement_id = ?",
            (normalized_status, _common._append_notes(row["notes"], notes), coverage_item_id, engagement.id),
        )
        # I-09: resolving a coverage item to covered/not_applicable drains the
        # FK-linked pending/processing work items — the SAME drain the covering
        # probe path runs (``_pending_work_item_ids_for_coverage_item`` +
        # ``mark_work_items_done`` in ``record_probe_run``). Without it, work buffered for an
        # endpoint slot the operator has explicitly closed stays dispatchable
        # forever. ``get_connection`` is re-entrant and commits at the outermost
        # depth, so the drain commits atomically with this status write.
        drained: dict[str, Any] | None = None
        if normalized_status in {CoverageStatus.COVERED, CoverageStatus.NOT_APPLICABLE}:
            drain_ids = _pending_work_item_ids_for_coverage_item(
                connection, engagement.id, coverage_item_id
            )
            if drain_ids:
                drained = mark_work_items_done(engagement.id, drain_ids)
        if row["service_id"] is not None:
            _refresh_service_coverage_status(connection, engagement.id, int(row["service_id"]))
        updated = connection.execute(
            "SELECT * FROM assessment_coverage_items WHERE id = ?", (coverage_item_id,)
        ).fetchone()
    assert updated is not None
    result = dict(updated)
    if drained is not None:
        result["work_items_done"] = drained
    return result


_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _require_identity_header_write_coverage(
    connection, engagement_id: int, coverage_item: dict[str, Any]
) -> None:
    """Refuse a false 'covered' verdict without cross-principal WRITE evidence."""
    variant_id = coverage_item.get("request_variant_id")
    variant = connection.execute(
        "SELECT scheme, host, port, normalized_path, method FROM assessment_request_variants "
        "WHERE id = ? AND engagement_id = ?",
        (variant_id, engagement_id),
    ).fetchone()
    if variant is None or str(variant["method"]).upper() not in _STATE_CHANGING_METHODS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "identity-header coverage requires a WRITE request variant "
                "(POST/PUT/PATCH/DELETE) before it can be marked covered"
            ),
        )
    placeholders = ",".join("?" for _ in PROBE_RESULT_STATUSES_COVERING)
    # Count only DURABLE principals: distinct non-empty ``principal_id`` values.
    # Cookie-only / legacy / manual identities carry an empty principal_id; falling
    # back to identity_name would let two sessions (or re-logins) for the SAME
    # account count as two principals and falsely satisfy the cross-principal WRITE
    # gate. An unanchored identity contributes nothing until a durable principal is
    # established (JWT capture or an operator-set principal_id).
    principal_count = int(
        connection.execute(
            f"""
            SELECT COUNT(DISTINCT NULLIF(trim(credentials.principal_id), ''))
              FROM assessment_probe_runs pr
              JOIN assessment_request_variants rv
                ON rv.id = pr.request_variant_id
               AND rv.engagement_id = pr.engagement_id
              JOIN assessment_coverage_items ci
                ON ci.engagement_id = pr.engagement_id
               AND ci.request_variant_id = pr.request_variant_id
               AND ci.input_slot = pr.input_slot
               AND ci.attack_family = pr.attack_family
              LEFT JOIN engagement_credentials credentials
                ON credentials.engagement_id = pr.engagement_id
               AND credentials.identity_name = pr.auth_context
             WHERE pr.engagement_id = ?
               AND rv.scheme = ? AND rv.host = ? AND rv.port = ?
               AND rv.normalized_path = ? AND rv.method = ?
               AND pr.input_slot = ?
               AND pr.attack_family = 'identity-header-review'
               AND pr.result_status IN ({placeholders})
               AND pr.auth_context NOT IN ('', 'anonymous')
               AND pr.evidence_ref != ''
            """,
            (
                engagement_id,
                variant["scheme"],
                variant["host"],
                variant["port"],
                variant["normalized_path"],
                variant["method"],
                coverage_item["input_slot"],
                *sorted(PROBE_RESULT_STATUSES_COVERING),
            ),
        ).fetchone()[0]
    )
    if principal_count < 2:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "identity-header coverage requires evidence-backed WRITE probes "
                "from two distinct principals"
            ),
        )

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


# The decision projections are a separate domain from the coverage ledger, but
# coverage.py remains their compatibility import surface for direct callers.
from .coverage_readiness import (  # noqa: E402
    HIGH_RISK_DEFERRED_SURFACE_TYPES as HIGH_RISK_DEFERRED_SURFACE_TYPES,
    PER_HOST_OBJECTIVES as PER_HOST_OBJECTIVES,
    SURFACE_RESOLUTION_STATUSES as SURFACE_RESOLUTION_STATUSES,
    SURFACE_STATUSES as SURFACE_STATUSES,
    SurfaceStatus as SurfaceStatus,
    _active_coverage_completeness_deferrals,
    _build_finding_verdicts_by_host,
    _completeness_deferral_index,
    _coverage_endpoint_host,
    coverage_readiness as coverage_readiness,
    per_host_coverage as per_host_coverage,
)
