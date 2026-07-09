"""A1 — engagement-wide (application-unit × vuln-family) coverage grid.

Covers ``by_family_coverage`` (state_manager.depth_ledger) via the
``GET /engagements/{key}/assessment/coverage-readiness/by-family`` route.

The grid walks EVERY application unit (deep_required or not) and, for each,
emits one cell per vuln family in ``union(expected, probed)`` so an operator can
tell a never-probed gap (missing_* + covering_probe_count 0) from a
probed-and-walled family (probe_count > 0, covering 0) from a finding-linked one
(has_finding). These tests seed units + variants + probes + a linked finding on
real fixtures and assert the pinned response shape + totals.
"""
from __future__ import annotations

from app.services import state_manager
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-07-09-100000-byfamily"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"

DEEP_HOST = "app.example.com"
THIN_HOST = "thin.example.com"


def _seed(client, isolate_settings) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def _insert_unit(eng_id: int, *, host: str, path_prefix: str, deep_required: int) -> None:
    with state_manager.get_connection() as connection:
        connection.execute(
            "INSERT INTO assessment_application_units "
            "(engagement_id, host, port_class, path_prefix, deep_required) "
            "VALUES (?, ?, 'web', ?, ?)",
            (eng_id, host, path_prefix, deep_required),
        )


def _variant(eng_id: int, *, url: str, query: dict | None = None) -> None:
    state_manager.record_request_variant(
        eng_id, url=url, method="GET", auth_context="anonymous",
        content_type_family="json", query_schema=query or {}, body_schema={},
        path_schema={}, cookie_schema={}, header_schema={}, path_template="",
        discovery_source="proxy", notes="", response_status=200,
        evidence_ref="", observation_payload={},
    )


def _probe(eng_id: int, *, attack_family: str, result_status: str,
           target_path: str, tool_name: str = "curl",
           target_host: str = DEEP_HOST, finding_id: int | None = None) -> None:
    state_manager.record_probe_run(
        eng_id, request_variant_id=None, service_id=None, coverage_item_id=None,
        auth_context="anonymous", input_slot="query", attack_family=attack_family,
        payload_family="", payload_value=f"{attack_family}:{target_path}",
        tool_name=tool_name, agent_name="va-1", result_status=result_status,
        observed_http_status=None, signal_type="", evidence_ref="", notes="",
        target_host=target_host, target_path=target_path, target_port=443,
        finding_id=finding_id,
    )


def _create_finding(client, slug: str) -> int:
    response = client.post(
        f"{BASE}/findings",
        json={
            "slug": slug,
            "title": "SQLi in /api/items search parameter",
            "severity": "high",
            "workflow_status": "active",
            "defect_family": "injection",
            "root_cause_key": "unparameterized-query",
            "auth_context": "anonymous",
            "canonical_location": f"https://{DEEP_HOST}/api/items",
            "summary": "SQL injection",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "Replayable request.", "impact": "DB read."},
        },
    )
    assert response.status_code == 201, response.text
    return int(response.json()["finding"]["id"])


def _families(unit_row: dict) -> dict[str, dict]:
    return {cell["family"]: cell for cell in unit_row["families"]}


def _by_unit(body: dict) -> dict[str, dict]:
    return {row["host"]: row for row in body["units"]}


def _seed_grid(client, isolate_settings) -> int:
    eng_id = _seed(client, isolate_settings)
    # A deep_required unit with a param-bearing variant (expects injection +
    # client-side + disclosure) and a NON-deep unit that must still appear.
    _insert_unit(eng_id, host=DEEP_HOST, path_prefix="/api", deep_required=1)
    _insert_unit(eng_id, host=THIN_HOST, path_prefix="/", deep_required=0)
    _variant(eng_id, url=f"https://{DEEP_HOST}/api/items", query={"search": "string"})

    finding_id = _create_finding(client, "VA-001")
    # Covering injection probe carrying the finding linkage.
    _probe(eng_id, attack_family="sqli", result_status="tested",
           target_path="/api/items", tool_name="sqlmap", finding_id=finding_id)
    # Probed-and-walled client-side family (non-covering result).
    _probe(eng_id, attack_family="xss", result_status="blocked",
           target_path="/api/items", tool_name="xsstrike")
    return finding_id


def test_by_family_grid_shape_and_statuses(client, isolate_settings):
    finding_id = _seed_grid(client, isolate_settings)

    response = client.get(f"{BASE}/coverage-readiness/by-family")
    assert response.status_code == 200, response.text
    body = response.json()

    units = _by_unit(body)
    assert set(units) == {DEEP_HOST, THIN_HOST}

    deep = units[DEEP_HOST]
    assert deep["deep_required"] is True
    fams = _families(deep)
    assert set(fams) == {"injection", "client-side", "disclosure"}

    # A covered family: covering probe present, finding linked.
    injection = fams["injection"]
    assert injection["status"] == "covered"
    assert injection["covering_probe_count"] > 0
    assert injection["probe_count"] == 1
    assert injection["has_finding"] is True
    assert injection["finding_id"] == finding_id
    assert injection["expected_reason"] is not None

    # An expected-but-unprobed family: missing, no probes, no finding.
    disclosure = fams["disclosure"]
    assert disclosure["status"].startswith("missing")
    assert disclosure["covering_probe_count"] == 0
    assert disclosure["probe_count"] == 0
    assert disclosure["has_finding"] is False
    assert disclosure["finding_id"] is None

    # A probed-and-walled family: probed but no covering result → still missing.
    client_side = fams["client-side"]
    assert client_side["status"] == "missing_warn"
    assert client_side["probe_count"] == 1
    assert client_side["covering_probe_count"] == 0
    assert client_side["has_finding"] is False


def test_by_family_non_deep_unit_appears_in_grid(client, isolate_settings):
    _seed_grid(client, isolate_settings)
    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    units = _by_unit(body)
    # The deep_required=0 unit is NOT dropped (unlike the depth ledger, which
    # only scores deep_required units).
    assert THIN_HOST in units
    thin = units[THIN_HOST]
    assert thin["deep_required"] is False
    # disclosure is expected for every unit; it is uncovered/never-probed here.
    thin_fams = _families(thin)
    assert "disclosure" in thin_fams
    assert thin_fams["disclosure"]["status"].startswith("missing")


def test_by_family_totals_are_accurate(client, isolate_settings):
    _seed_grid(client, isolate_settings)
    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    totals = body["totals"]

    assert totals["units"] == 2
    # deep: injection + client-side + disclosure (3); thin: disclosure (1).
    assert totals["cells"] == 4
    assert totals["covered"] == 1              # injection
    assert totals["missing_block"] == 0
    assert totals["missing_warn"] == 3         # client-side + 2x disclosure
    assert totals["deferred"] == 0
    assert totals["with_finding"] == 1         # injection cell

    # covered + missing_block + missing_warn + deferred partitions every cell.
    partition = (
        totals["covered"] + totals["missing_block"]
        + totals["missing_warn"] + totals["deferred"]
    )
    assert partition == totals["cells"]


def test_by_family_active_deferral_marks_cell_deferred(client, isolate_settings):
    """An active depth_deferral covering an expected-but-uncovered family flips
    that cell from missing_* to ``deferred`` (same classification the depth
    ledger uses); covered families are unaffected (covered wins over deferred)."""
    _seed_grid(client, isolate_settings)
    # client-side (xss) is expected + probed-but-walled on the deep unit; defer it.
    resp = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/dispatch-decisions",
        json={
            "kind": "depth_deferral",
            "payload": {
                "host": DEEP_HOST,
                "path_prefix": "/api",
                "vuln_classes": ["xss"],
                "reason": "client-side deferred to next sprint; documented risk",
                "approved_by": "operator",
            },
            "surfaced_to_user": True,
        },
    )
    assert resp.status_code == 201, resp.text

    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    fams = _families(_by_unit(body)[DEEP_HOST])
    assert fams["client-side"]["status"] == "deferred"
    # injection stays covered (covered precedence), disclosure stays missing.
    assert fams["injection"]["status"] == "covered"
    assert fams["disclosure"]["status"].startswith("missing")
    assert body["totals"]["deferred"] == 1
    assert body["totals"]["missing_warn"] == 2  # was 3; client-side moved to deferred


def test_by_family_empty_engagement_returns_zero_grid(client, isolate_settings):
    _seed(client, isolate_settings)
    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    assert body["units"] == []
    assert body["totals"] == {
        "units": 0, "cells": 0, "covered": 0, "missing_block": 0,
        "missing_warn": 0, "deferred": 0, "with_finding": 0,
    }
