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
        "tech_fingerprint",
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
            "deferred_objectives": ["directory_fuzz", "tech_fingerprint"],
            "reason": "Scope brief forbids brute-force",
            "approved_by": "operator",
        },
    )

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    rows = {row["host"]: row for row in body["hosts"]}
    row = rows["api.target.example"]
    assert row["outcomes"]["directory_fuzz"]["deferred"] is True
    assert row["outcomes"]["tech_fingerprint"]["deferred"] is True
    assert "directory_fuzz" not in row["unmet_objectives"]
    assert "tech_fingerprint" not in row["unmet_objectives"]
    assert sorted(row["deferred_objectives"]) == ["directory_fuzz", "tech_fingerprint"]
    # Deferral row carried for audit visibility.
    assert any(d["kind"] == "coverage_deferral" for d in row["deferrals"])


def test_per_host_coverage_deferral_normalizes_url_shaped_target(client, isolate_settings):
    """A deferral whose `target` is a URL or host:port must match the bare-hostname key."""
    _seed(client, isolate_settings)
    _create_service(client, endpoint="api.target.example")
    _record_decision(
        client,
        kind="coverage_deferral",
        payload={
            "target": "https://api.target.example/v1/users",
            "deferred_objectives": ["directory_fuzz"],
            "reason": "OAS-only contract, no fuzz",
            "approved_by": "operator",
        },
    )
    _record_decision(
        client,
        kind="coverage_deferral",
        payload={
            "hosts": ["api.target.example:8443"],
            "deferred_objectives": ["tech_fingerprint"],
            "reason": "TLS-only endpoint",
            "approved_by": "operator",
        },
    )

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    rows = {row["host"]: row for row in body["hosts"]}
    row = rows["api.target.example"]
    assert row["outcomes"]["directory_fuzz"]["deferred"] is True
    assert row["outcomes"]["tech_fingerprint"]["deferred"] is True
    assert "directory_fuzz" not in row["unmet_objectives"]
    assert "tech_fingerprint" not in row["unmet_objectives"]


def test_per_host_coverage_deferral_lookup_not_capped_at_500(client, isolate_settings):
    """Large engagements can legitimately accumulate >500 active
    coverage_deferral rows; the per-host projection must read all of them so
    deferred objectives do not silently reappear as unmet beyond the cap.

    Regression: the helper previously called
    ``list_decisions(..., limit=500)`` which truncated silently.
    """
    _seed(client, isolate_settings)
    _create_service(client, endpoint="api.target.example")
    # 510 distinct host deferrals covering directory_fuzz for tail-host.test
    # plus 509 unrelated hosts. Use --inline-style POSTs.
    for i in range(509):
        _record_decision(
            client,
            kind="coverage_deferral",
            payload={
                "host": f"h{i:04d}.target.example",
                "deferred_objectives": ["directory_fuzz"],
                "reason": f"bulk skip {i}",
                "approved_by": "operator",
            },
        )
    # The 510th deferral — would be silently dropped at limit=500 because
    # the ordering is created_at DESC, so the OLDEST inserts fall off.
    _record_decision(
        client,
        kind="coverage_deferral",
        payload={
            "host": "tail-host.test",
            "deferred_objectives": ["directory_fuzz"],
            "reason": "must survive the cap",
            "approved_by": "operator",
        },
    )
    # tail-host.test was inserted LAST so it's the newest — under DESC
    # ordering it's at position 0 and would be kept by any limit.
    # Insert one MORE so the OLDEST row (h0000) is past the 500-cap boundary
    # and must be returned for its host outcome to be `deferred`.
    _record_decision(
        client,
        kind="coverage_deferral",
        payload={
            "host": "h0000.target.example",
            "deferred_objectives": ["tech_fingerprint"],
            "reason": "second deferral for h0000",
            "approved_by": "operator",
        },
    )

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    rows = {row["host"]: row for row in body["hosts"]}

    # h0000 was the oldest insert — at limit=500 with DESC order it would be
    # dropped. Confirm it's present and its directory_fuzz objective is deferred.
    assert "h0000.target.example" in rows
    assert rows["h0000.target.example"]["outcomes"]["directory_fuzz"]["deferred"] is True


def test_per_host_coverage_resolved_deferral_no_longer_satisfies(client, isolate_settings):
    """A resolved coverage_deferral (the operator un-deferred) returns the host to unmet status."""
    _seed(client, isolate_settings)
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

    monkeypatch.setattr(state_manager._common, "get_connection", lambda: _Wrapper())
    try:
        result = state_manager.per_host_coverage(engagement_id)
    finally:
        monkeypatch.setattr(state_manager._common, "get_connection", original_get_connection)

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


def test_report_readiness_omits_per_host_projection_when_projection_fails(
    client, isolate_settings, monkeypatch, caplog
):
    _seed(client, isolate_settings)

    def fail_projection(_engagement_id):
        raise RuntimeError("projection failed")

    monkeypatch.setattr(state_manager, "per_host_coverage", fail_projection)

    response = client.get(f"{ASSESSMENT_BASE}/report-readiness")

    assert response.status_code == 200, response.text
    assert "per_host_coverage" not in response.json()
    assert "projection failed" in caplog.text


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
            "deferred_objectives": ["tech_fingerprint"],
            "reason": "Vendor confirms WAF tier out-of-band",
        },
    )
    assert response.status_code == 201, response.text


def test_coverage_deferral_validator_accepts_engagement_wide_without_host(client, isolate_settings):
    """`engagement_wide=true` is the supported shape for engagement-level
    skips (e.g., OSINT out-of-scope for the whole engagement). Without this,
    operators would have to duplicate the same deferral per host on wildcard
    engagements — the CLI guidance recommends the engagement-wide form, so
    the validator must accept it."""
    _seed(client, isolate_settings)
    response = _post_decision_raw(
        client,
        kind="coverage_deferral",
        payload={
            "engagement_wide": True,
            "deferred_objectives": ["osint"],
            "reason": "Engagement brief explicitly excludes OSINT",
            "approved_by": "operator",
        },
    )
    assert response.status_code == 201, response.text


def test_coverage_deferral_validator_rejects_engagement_wide_mixed_with_host(client, isolate_settings):
    """Mixing engagement_wide=true with a host field is ambiguous (which
    wins?) and almost always an operator mistake. Reject outright."""
    _seed(client, isolate_settings)
    response = _post_decision_raw(
        client,
        kind="coverage_deferral",
        payload={
            "engagement_wide": True,
            "host": "api.target.example",
            "deferred_objectives": ["osint"],
            "reason": "...",
        },
    )
    assert response.status_code == 422
    assert "engagement_wide" in response.text.lower()


def test_per_host_coverage_engagement_wide_deferral_satisfies_every_host(client, isolate_settings):
    """An engagement-wide deferral marks the named objectives as deferred
    on EVERY host with signal — that's the whole point of the engagement-
    wide shape. Without this fold, operators on wildcard/large engagements
    have to record duplicate per-host deferrals for objectives that are
    fundamentally engagement-level (OSINT scope decisions, etc.).
    """
    _seed(client, isolate_settings)
    _create_service(client, endpoint="api.target.example")
    _create_service(client, endpoint="edge.target.example")
    _record_decision(
        client,
        kind="coverage_deferral",
        payload={
            "engagement_wide": True,
            "deferred_objectives": ["osint"],
            "reason": "Engagement brief excludes OSINT",
            "approved_by": "operator",
        },
    )

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    rows = {row["host"]: row for row in body["hosts"]}

    # Both hosts inherit the deferral, even though neither was named.
    for host in ("api.target.example", "edge.target.example"):
        assert host in rows
        assert rows[host]["outcomes"]["osint"]["deferred"] is True
        assert "osint" not in rows[host]["unmet_objectives"]
        assert "osint" in rows[host]["deferred_objectives"]
        # The engagement-wide row surfaces in the per-host audit list too so
        # operators can see WHY it was marked deferred.
        deferral_payloads = [d["payload"] for d in rows[host]["deferrals"]]
        assert any(p.get("engagement_wide") is True for p in deferral_payloads)


def test_coverage_deferral_engagement_wide_rejects_per_host_objectives(client, isolate_settings):
    """engagement_wide=true is restricted to objectives that legitimately apply
    program-wide (osint, waf_tier, directory_fuzz). Per-host signals like
    service_inventory and tech_fingerprint require an explicit host / hosts[] list
    so the audit row carries the per-host rationale."""
    _seed(client, isolate_settings)
    for forbidden in ("service_inventory", "tech_fingerprint"):
        response = _post_decision_raw(
            client,
            kind="coverage_deferral",
            payload={
                "engagement_wide": True,
                "deferred_objectives": [forbidden],
                "reason": "program-wide skip",
                "approved_by": "operator",
            },
        )
        assert response.status_code == 422, response.text
        body = response.text.lower()
        assert "engagement_wide" in body
        assert forbidden in body


def test_coverage_deferral_engagement_wide_rejects_mixed_objective_list(client, isolate_settings):
    """If any objective in a mixed list is per-host, the whole engagement_wide
    deferral is rejected — partial acceptance would silently drop the per-host
    objective from the audit ledger."""
    _seed(client, isolate_settings)
    response = _post_decision_raw(
        client,
        kind="coverage_deferral",
        payload={
            "engagement_wide": True,
            "deferred_objectives": ["osint", "service_inventory"],
            "reason": "...",
            "approved_by": "operator",
        },
    )
    assert response.status_code == 422
    assert "service_inventory" in response.text.lower()


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
    _seed(client, isolate_settings)
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
