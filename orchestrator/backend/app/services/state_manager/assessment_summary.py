from __future__ import annotations

import copy
import time
from threading import Condition, Lock
from typing import Any

from ... import db
from ..events import _engagement_or_404

from . import _common
from ._common import _scalar_row, _serialize_finding_record
from .findings import list_exploit_candidates
from .coverage import coverage_readiness, coverage_rollup, egress_block_status, vendor_saas_hosts_pending_decision
from .coverage_readiness import OPEN_SURFACE_STATUSES
from .report_readiness import report_readiness

_OPEN_SURFACE_STATUS_VALUES = tuple(sorted(OPEN_SURFACE_STATUSES))

SummaryCacheKey = tuple[tuple[str, int, int, int], int]

_SUMMARY_CACHE_TTL_SECONDS = 1.0
_summary_cache_lock = Lock()
_summary_cache_condition = Condition(_summary_cache_lock)
_summary_cache: dict[SummaryCacheKey, tuple[float, dict[str, Any]]] = {}
_summary_cache_inflight: set[SummaryCacheKey] = set()
_summary_cache_generation: dict[SummaryCacheKey, int] = {}
_summary_cache_global_generation = 0


def _summary_cache_key(engagement_id: int) -> SummaryCacheKey:
    return (db.database_cache_token(), engagement_id)


def _summary_generation(cache_key: SummaryCacheKey) -> tuple[int, int]:
    return (
        _summary_cache_global_generation,
        _summary_cache_generation.get(cache_key, 0),
    )


def clear_assessment_summary_cache(engagement_id: int | None = None) -> None:
    global _summary_cache_global_generation
    with _summary_cache_condition:
        if engagement_id is None:
            _summary_cache.clear()
            _summary_cache_global_generation += 1
            _summary_cache_condition.notify_all()
            return
        affected_keys = {
            key
            for key in (
                set(_summary_cache)
                | _summary_cache_inflight
                | set(_summary_cache_generation)
            )
            if key[1] == engagement_id
        }
        affected_keys.add(_summary_cache_key(engagement_id))
        for key in [key for key in _summary_cache if key[1] == engagement_id]:
            _summary_cache.pop(key, None)
        for key in affected_keys:
            _summary_cache_generation[key] = _summary_cache_generation.get(key, 0) + 1
        _summary_cache_condition.notify_all()



def assessment_summary(engagement_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    cache_key = _summary_cache_key(engagement.id)
    with _summary_cache_condition:
        while True:
            now = time.monotonic()
            cached = _summary_cache.get(cache_key)
            if cached is not None and cached[0] > now:
                return copy.deepcopy(cached[1])
            if cache_key not in _summary_cache_inflight:
                _summary_cache_inflight.add(cache_key)
                generation = _summary_generation(cache_key)
                break
            _summary_cache_condition.wait()

    try:
        payload = _build_assessment_summary(engagement.id)
    except BaseException:
        with _summary_cache_condition:
            _summary_cache_inflight.discard(cache_key)
            _summary_cache_condition.notify_all()
        raise
    with _summary_cache_condition:
        if _summary_generation(cache_key) == generation:
            _summary_cache[cache_key] = (
                time.monotonic() + _SUMMARY_CACHE_TTL_SECONDS,
                copy.deepcopy(payload),
            )
        _summary_cache_inflight.discard(cache_key)
        _summary_cache_condition.notify_all()
    return payload


def _build_assessment_summary(engagement_id: int) -> dict[str, Any]:
    exploit_candidate_count = len(list_exploit_candidates(engagement_id))
    coverage_gate = coverage_readiness(engagement_id)
    report_gate = report_readiness(engagement_id)
    with _common.get_connection() as connection:
        target_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_targets WHERE engagement_id = ?", (engagement_id,))
        service_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_services WHERE engagement_id = ?", (engagement_id,))
        request_variant_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_request_variants WHERE engagement_id = ?", (engagement_id,))
        request_observation_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_request_observations WHERE engagement_id = ?", (engagement_id,))
        coverage_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_coverage_items WHERE engagement_id = ?", (engagement_id,))
        probe_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_probe_runs WHERE engagement_id = ?", (engagement_id,))
        finding_count = _scalar_row(
            connection,
            "SELECT COUNT(*) FROM assessment_findings WHERE engagement_id = ? AND status NOT IN ('merged', 'false_positive')",
            (engagement_id,),
        )
        open_surface_count = _scalar_row(
            connection,
            "SELECT COUNT(*) FROM assessment_surfaces WHERE engagement_id = ? "
            f"AND status IN ({', '.join('?' for _ in _OPEN_SURFACE_STATUS_VALUES)})",
            (engagement_id, *_OPEN_SURFACE_STATUS_VALUES),
        )
        credential_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_credentials WHERE engagement_id = ?", (engagement_id,))
        access_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_access_records WHERE engagement_id = ?", (engagement_id,))
        pivot_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_pivots WHERE engagement_id = ?", (engagement_id,))
        tunnel_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_tunnels WHERE engagement_id = ?", (engagement_id,))
        blocked_technique_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_blocked_techniques WHERE engagement_id = ?", (engagement_id,))
        chain_count = _scalar_row(connection, "SELECT COUNT(*) FROM assessment_attack_chains WHERE engagement_id = ?", (engagement_id,))
        coverage_rows = connection.execute(
            "SELECT status, COUNT(*) AS total FROM assessment_coverage_items WHERE engagement_id = ? GROUP BY status ORDER BY status ASC",
            (engagement_id,),
        ).fetchall()
        finding_rows = connection.execute(
            "SELECT status, COUNT(*) AS total FROM assessment_findings WHERE engagement_id = ? GROUP BY status ORDER BY status ASC",
            (engagement_id,),
        ).fetchall()
        # Severity rollup for the Overview donut. Mirror the ``finding_count``
        # WHERE clause exactly (merged/false_positive excluded) so the donut
        # total always equals ``finding_count``.
        finding_severity_rows = connection.execute(
            """
            SELECT severity, COUNT(*) AS total
            FROM assessment_findings
            WHERE engagement_id = ? AND status NOT IN ('merged', 'false_positive')
            GROUP BY severity
            ORDER BY severity ASC
            """,
            (engagement_id,),
        ).fetchall()
        verification_status_rows = connection.execute(
            """
            SELECT verification_status, COUNT(*) AS total
            FROM assessment_findings
            WHERE engagement_id = ?
            GROUP BY verification_status
            ORDER BY verification_status ASC
            """,
            (engagement_id,),
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
            (engagement_id,),
        ).fetchall()
        top_findings = connection.execute(
            """
            SELECT slug, title, severity, status, verification_status, canonical_location, summary, source_name, updated_at
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
            (engagement_id,),
        ).fetchall()
        recent_probes = connection.execute(
            """
            SELECT result_status, attack_family, signal_type, agent_name, evidence_ref, created_at
            FROM assessment_probe_runs
            WHERE engagement_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT 10
            """,
            (engagement_id,),
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
            (engagement_id,),
        ).fetchall()
        attack_chains = connection.execute(
            """
            SELECT chain_key, title, status, severity, narrative, updated_at
            FROM assessment_attack_chains
            WHERE engagement_id = ?
            ORDER BY updated_at DESC, id DESC
            LIMIT 8
            """,
            (engagement_id,),
        ).fetchall()
        service_coverage_gaps = connection.execute(
            """
            SELECT services.endpoint, services.service, services.coverage_status, services.updated_at
            FROM assessment_services AS services
            WHERE services.engagement_id = ? AND services.coverage_status IN ('pending', 'partial', 'blocked')
            ORDER BY services.updated_at DESC, services.id DESC
            LIMIT 10
            """,
            (engagement_id,),
        ).fetchall()
    return {
        "target_count": target_count,
        "service_count": service_count,
        "request_variant_count": request_variant_count,
        "request_observation_count": request_observation_count,
        "coverage_count": coverage_count,
        "probe_count": probe_count,
        "finding_count": finding_count,
        "finding_severities": {row["severity"]: int(row["total"]) for row in finding_severity_rows},
        "open_surface_count": open_surface_count,
        "open_surface_statuses": list(_OPEN_SURFACE_STATUS_VALUES),
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
        "coverage_by_reachability": coverage_rollup(engagement_id),
        "finding_workflow_statuses": {row["status"]: int(row["total"]) for row in finding_rows},
        "finding_verification_statuses": {
            row["verification_status"]: int(row["total"])
            for row in verification_status_rows
        },
        "top_surfaces": [dict(row) for row in top_surfaces],
        "top_findings": [_serialize_finding_record(row) for row in top_findings],
        "recent_probes": [dict(row) for row in recent_probes],
        "open_coverage_items": [dict(row) for row in open_coverage_items],
        "attack_chains": [dict(row) for row in attack_chains],
        "service_coverage_gaps": [dict(row) for row in service_coverage_gaps],
        "vendor_saas_hosts_pending_decision": vendor_saas_hosts_pending_decision(engagement_id),
        "egress_status": egress_block_status(engagement_id),
    }
