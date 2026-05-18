"""Tests for C40 — outcome-based per-host coverage projection.

Covers ``state_manager.per_host_coverage`` plus the
``GET /engagements/{key}/assessment/coverage-readiness/by-host`` endpoint.

The projection's central contract is that signals come from outcome tables
(``intel_tech_components``, ``intel_people``, ``intel_breach_records``,
``assessment_services``, ``assessment_surfaces``, ``assessment_dispatch_decisions``)
and NEVER from ``assessment_command_runs``. These tests assert behavior on
real fixtures and assert the abstraction holds against a hostile regression
(``test_per_host_coverage_does_not_read_command_runs_via_monkeypatch``).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from app import db as db_module
from app.services import state_manager
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-05-17-100000-perhost"
ASSESSMENT_BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> int:
    """Create the engagement on disk + in the backend; return engagement id."""
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def _create_service(client, *, endpoint: str, state: str = "up") -> None:
    """Insert a service directly through state_manager.record_service.

    No public POST endpoint exists for services (they are written by recon
    ingestion flows), so call the service-layer helper to set up fixtures.
    """
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    engagement_id = int(response.json()["id"])
    state_manager.record_service(
        engagement_id,
        endpoint=endpoint,
        protocol="tcp",
        port=None,
        service="",
        state=state,
        coverage_status="pending",
        banner="",
        notes="",
        discovered_by="test",
        target_identity=None,
    )


def _create_surface(client, *, target_descriptor: str, surface_type: str = "auth_entry") -> None:
    response = client.post(
        f"{ASSESSMENT_BASE}/surfaces",
        json={
            "surface_type": surface_type,
            "target_descriptor": target_descriptor,
            "source_name": "recon-specialist",
            "rationale": "live endpoint",
        },
    )
    assert response.status_code == 201, response.text


def _record_tech_component(client, *, component: str, evidence_ref: str = "", source_name: str = "") -> None:
    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/intel/tech-components",
        json={
            "component": component,
            "evidence_ref": evidence_ref,
            "source_name": source_name,
            "confidence": "high",
        },
    )
    assert response.status_code in (200, 201), response.text


def _record_decision(client, *, kind: str, payload: dict, surfaced: bool = True) -> None:
    response = client.post(
        f"{ASSESSMENT_BASE}/dispatch-decisions",
        json={
            "kind": kind,
            "payload": payload,
            "surfaced_to_user": surfaced,
        },
    )
    assert response.status_code in (200, 201), response.text


# ---------------------------------------------------------------------------
# Core outcome computation
# ---------------------------------------------------------------------------


def test_per_host_coverage_returns_objectives_and_empty_hosts(client, isolate_settings):
    """An engagement with no signal still returns the objective vocabulary."""
    _seed(client, isolate_settings)

    response = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["objectives"] == [
        "waf_tier",
        "service_inventory",
        "directory_fuzz",
        "nikto_trigger",
        "osint",
    ]
    assert body["hosts"] == []
    assert body["engagement_signals"]["waf_intel_count"] == 0


def test_per_host_coverage_marks_service_inventory_met_for_live_service(client, isolate_settings):
    _seed(client, isolate_settings)
    _create_service(client, endpoint="api.target.example", state="up")

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    rows = {row["host"]: row for row in body["hosts"]}
    assert "api.target.example" in rows
    row = rows["api.target.example"]
    assert row["outcomes"]["service_inventory"]["met"] is True
    # No tech intel recorded yet — three outcomes still unmet.
    assert row["outcomes"]["waf_tier"]["met"] is False
    assert row["outcomes"]["osint"]["met"] is False
    assert "service_inventory" not in row["unmet_objectives"]
    assert "waf_tier" in row["unmet_objectives"]


def test_per_host_coverage_waf_intel_satisfies_waf_tier_engagement_wide(client, isolate_settings):
    """A Cloudflare tech-component row satisfies waf_tier for every host."""
    _seed(client, isolate_settings)
    _create_service(client, endpoint="api.target.example")
    _create_service(client, endpoint="admin.target.example")
    _record_tech_component(client, component="Cloudflare", source_name="wafw00f")

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    rows = {row["host"]: row for row in body["hosts"]}
    # CDN-class WAFs cover the whole property: waf_tier=met on every host.
    for host in ("api.target.example", "admin.target.example"):
        assert rows[host]["outcomes"]["waf_tier"]["met"] is True, rows[host]


def test_per_host_coverage_osint_satisfied_by_intel_people_alone(client, isolate_settings):
    """OSINT is engagement-level: a single intel_people row satisfies every host."""
    _seed(client, isolate_settings)
    _create_service(client, endpoint="target.example")

    # Insert intel_people row directly (POST helper is not strictly needed for
    # the projection test).
    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/intel/people",
        json={"name": "Jane Doe", "role": "Engineer", "source_name": "linkedin"},
    )
    assert response.status_code in (200, 201), response.text

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    rows = {row["host"]: row for row in body["hosts"]}
    assert rows["target.example"]["outcomes"]["osint"]["met"] is True


def test_per_host_coverage_deferral_marks_objective_deferred(client, isolate_settings):
    """A coverage_deferral decision flags the named objective and removes it from unmet."""
    _seed(client, isolate_settings)
    _create_service(client, endpoint="api.target.example")
    _record_decision(
        client,
        kind="coverage_deferral",
        payload={
            "host": "api.target.example",
            "deferred_objectives": ["directory_fuzz", "nikto_trigger"],
            "reason": "Scope brief forbids brute-force",
            "approved_by": "operator",
        },
    )

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    rows = {row["host"]: row for row in body["hosts"]}
    row = rows["api.target.example"]
    assert row["outcomes"]["directory_fuzz"]["deferred"] is True
    assert row["outcomes"]["nikto_trigger"]["deferred"] is True
    assert "directory_fuzz" not in row["unmet_objectives"]
    assert "nikto_trigger" not in row["unmet_objectives"]
    assert sorted(row["deferred_objectives"]) == ["directory_fuzz", "nikto_trigger"]
    # Deferral row carried for audit visibility.
    assert any(d["kind"] == "coverage_deferral" for d in row["deferrals"])


def test_per_host_coverage_resolved_deferral_no_longer_satisfies(client, isolate_settings):
    """A resolved coverage_deferral (the operator un-deferred) returns the host to unmet status."""
    eng_id = _seed(client, isolate_settings)
    _create_service(client, endpoint="api.target.example")

    response = client.post(
        f"{ASSESSMENT_BASE}/dispatch-decisions",
        json={
            "kind": "coverage_deferral",
            "payload": {
                "host": "api.target.example",
                "deferred_objectives": ["waf_tier"],
                "reason": "temporary",
            },
            "surfaced_to_user": True,
        },
    )
    assert response.status_code in (200, 201), response.text
    decision_id = int(response.json()["id"])

    # Resolve the deferral.
    response = client.patch(
        f"{ASSESSMENT_BASE}/dispatch-decisions/{decision_id}",
        json={"resolved": True, "resolution": {"choice": "dispatched-waf-check"}},
    )
    assert response.status_code == 200, response.text

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    rows = {row["host"]: row for row in body["hosts"]}
    row = rows["api.target.example"]
    assert row["outcomes"]["waf_tier"]["deferred"] is False
    # waf_tier is now back to unmet — the resolved deferral no longer satisfies the gate.
    assert "waf_tier" in row["unmet_objectives"]


def test_per_host_coverage_does_not_read_command_runs_via_monkeypatch(
    client, isolate_settings, monkeypatch
):
    """Hostile-regression assertion: per_host_coverage must NEVER touch assessment_command_runs.

    Wraps the state_manager's ``get_connection`` context manager so every SQL
    statement issued inside ``per_host_coverage`` is captured. The C40 contract
    is that the function reads outcome tables only — adding a join against
    ``assessment_command_runs`` is exactly the regression this catches.
    """
    _seed(client, isolate_settings)
    _create_service(client, endpoint="api.target.example")
    _create_surface(client, target_descriptor="https://api.target.example/v1")
    _record_tech_component(client, component="Cloudflare")

    eng_response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    engagement_id = int(eng_response.json()["id"])

    seen_sql: list[str] = []
    original_get_connection = state_manager.get_connection

    class _RecordingConnection:
        """Proxy that records SQL on the underlying sqlite3 connection."""

        def __init__(self, inner: sqlite3.Connection) -> None:
            self._inner = inner

        def __getattr__(self, name: str):
            return getattr(self._inner, name)

        def execute(self, sql, *args, **kwargs):  # type: ignore[override]
            seen_sql.append(str(sql))
            return self._inner.execute(sql, *args, **kwargs)

        def executemany(self, sql, *args, **kwargs):  # type: ignore[override]
            seen_sql.append(str(sql))
            return self._inner.executemany(sql, *args, **kwargs)

    class _Wrapper:
        def __init__(self):
            self._cm = original_get_connection()

        def __enter__(self):
            inner = self._cm.__enter__()
            return _RecordingConnection(inner)

        def __exit__(self, *args):
            return self._cm.__exit__(*args)

    monkeypatch.setattr(state_manager, "get_connection", lambda: _Wrapper())
    try:
        result = state_manager.per_host_coverage(engagement_id)
    finally:
        monkeypatch.setattr(state_manager, "get_connection", original_get_connection)

    assert result["hosts"], "expected at least one host with signal"
    joined = "\n".join(seen_sql).lower()
    assert "assessment_command_runs" not in joined, (
        "per_host_coverage must never query assessment_command_runs; "
        "C40 outcome-based contract violated by:\n"
        + "\n".join(s for s in seen_sql if "assessment_command_runs" in s.lower())
    )
    # Sanity: at least one of the outcome tables was queried.
    assert any("intel_tech_components" in sql.lower() for sql in seen_sql), seen_sql


def test_report_readiness_includes_per_host_coverage(client, isolate_settings):
    """C58 — /report-readiness embeds the C40 per-host projection for the UI."""
    _seed(client, isolate_settings)
    _create_service(client, endpoint="api.target.example")

    response = client.get(f"{ASSESSMENT_BASE}/report-readiness")
    assert response.status_code == 200, response.text
    body = response.json()
    assert "per_host_coverage" in body
    assert body["per_host_coverage"]["objectives"]
    rows = {row["host"]: row for row in body["per_host_coverage"]["hosts"]}
    assert "api.target.example" in rows


# ---------------------------------------------------------------------------
# FU2: coverage_deferral payload validation
# ---------------------------------------------------------------------------


def _post_decision_raw(client, *, kind: str, payload: dict, surfaced: bool = True):
    return client.post(
        f"{ASSESSMENT_BASE}/dispatch-decisions",
        json={"kind": kind, "payload": payload, "surfaced_to_user": surfaced},
    )


def test_coverage_deferral_validator_accepts_canonical_payload(client, isolate_settings):
    _seed(client, isolate_settings)
    response = _post_decision_raw(
        client,
        kind="coverage_deferral",
        payload={
            "host": "api.target.example",
            "deferred_objectives": ["directory_fuzz"],
            "reason": "Scope brief forbids brute-force",
            "approved_by": "operator",
        },
    )
    assert response.status_code == 201, response.text


def test_coverage_deferral_validator_rejects_missing_host_aliases(client, isolate_settings):
    _seed(client, isolate_settings)
    response = _post_decision_raw(
        client,
        kind="coverage_deferral",
        payload={
            "deferred_objectives": ["osint"],
            "reason": "Engagement-level skip",
        },
    )
    assert response.status_code == 422
    assert "host" in response.text.lower() or "hostname" in response.text.lower()


def test_coverage_deferral_validator_rejects_unknown_objective(client, isolate_settings):
    _seed(client, isolate_settings)
    response = _post_decision_raw(
        client,
        kind="coverage_deferral",
        payload={
            "host": "api.target.example",
            "deferred_objectives": ["super_extensive_fuzz"],
            "reason": "...",
        },
    )
    assert response.status_code == 422


def test_coverage_deferral_validator_rejects_empty_objectives(client, isolate_settings):
    _seed(client, isolate_settings)
    response = _post_decision_raw(
        client,
        kind="coverage_deferral",
        payload={
            "host": "api.target.example",
            "deferred_objectives": [],
            "reason": "...",
        },
    )
    assert response.status_code == 422


def test_coverage_deferral_validator_rejects_missing_reason(client, isolate_settings):
    _seed(client, isolate_settings)
    response = _post_decision_raw(
        client,
        kind="coverage_deferral",
        payload={
            "host": "api.target.example",
            "deferred_objectives": ["directory_fuzz"],
        },
    )
    assert response.status_code == 422
    assert "reason" in response.text.lower()


def test_coverage_deferral_validator_accepts_hosts_list_alias(client, isolate_settings):
    _seed(client, isolate_settings)
    response = _post_decision_raw(
        client,
        kind="coverage_deferral",
        payload={
            "hosts": ["api.target.example", "edge.target.example"],
            "deferred_objectives": ["nikto_trigger"],
            "reason": "Vendor confirms WAF tier out-of-band",
        },
    )
    assert response.status_code == 201, response.text


def test_coverage_deferral_validator_does_not_constrain_other_kinds(client, isolate_settings):
    """Unknown kinds keep the free-form payload contract — only `coverage_deferral` is gated."""
    _seed(client, isolate_settings)
    response = _post_decision_raw(
        client,
        kind="scope_decision",
        payload={"host": "foo", "anything_goes": True, "deferred_objectives": "not even a list"},
    )
    assert response.status_code == 201, response.text


# ---------------------------------------------------------------------------
# P1#3: per-host coverage embeds scope_hosts for FE filter toggle
# ---------------------------------------------------------------------------


def test_per_host_coverage_embeds_scope_hosts_when_scope_json_present(
    client, isolate_settings, tmp_path
):
    """The /coverage-readiness/by-host endpoint surfaces the raw scope.json
    hosts list so the frontend can render the scope-literals-only toggle."""
    eng_id = _seed(client, isolate_settings)
    # _seed writes a scope.json — verify the response carries it back.
    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    assert "scope_hosts" in body
    # The seed scope.json contains at least one host entry.
    assert isinstance(body["scope_hosts"], list)


def test_report_readiness_per_host_coverage_embeds_scope_hosts(client, isolate_settings):
    """The /report-readiness endpoint (which the FE Readiness panel fetches)
    also embeds scope_hosts under per_host_coverage so the toggle works
    without a second request."""
    _seed(client, isolate_settings)
    body = client.get(f"{ASSESSMENT_BASE}/report-readiness").json()
    assert "per_host_coverage" in body
    assert "scope_hosts" in body["per_host_coverage"]
    assert isinstance(body["per_host_coverage"]["scope_hosts"], list)
