from __future__ import annotations

from typing import Any

from ..events import _engagement_or_404

from . import _common
from ._common import _scalar_row, _serialize_finding_record
from .findings import list_exploit_candidates
from .coverage import coverage_readiness, coverage_rollup, egress_block_status, vendor_saas_hosts_pending_decision
from .report_readiness import report_readiness



def assessment_summary(engagement_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    exploit_candidate_count = len(list_exploit_candidates(engagement.id))
    coverage_gate = coverage_readiness(engagement.id)
    report_gate = report_readiness(engagement.id)
    with _common.get_connection() as connection:
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
        "finding_severities": {row["severity"]: int(row["total"]) for row in finding_severity_rows},
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
