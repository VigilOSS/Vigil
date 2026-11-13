"""A decision row can supersede an earlier row of the same kind.

The superseded row stays readable by id (and through ``include_superseded``),
carries ``superseded_by_id``, and no gate reads it; the new row names it in
``supersedes_id``. A supersession is refused for a row of another kind, a row
this engagement does not hold, an already superseded row, and a kind whose gate
state lives outside the decision row.
"""
from __future__ import annotations

import importlib

import pytest
from app.services import state_manager
from tests.test_engagements_api import write_engagement

# The package re-exports a function under the module's name.
coverage_readiness = importlib.import_module("app.services.state_manager.coverage_readiness")


ENGAGEMENT_KEY = "2026-11-14-110000-supersede"
OTHER_KEY = "2026-11-14-110001-supersede-other"
ASSESSMENT_BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings, key: str) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=key)
    response = client.get(f"/engagements/{key}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


@pytest.fixture
def engagement_id(client, isolate_settings) -> int:
    return _seed(client, isolate_settings, ENGAGEMENT_KEY)


def _decide(client, kind: str, payload: dict, *, supersedes: int | None = None, base=ASSESSMENT_BASE):
    body = {"kind": kind, "payload": payload, "surfaced_to_user": True}
    if supersedes is not None:
        body["supersedes"] = supersedes
    return client.post(f"{base}/dispatch-decisions", json=body)


def _deferral(objectives: list[str]) -> dict:
    return {
        "hosts": ["api.example.com"],
        "deferred_objectives": objectives,
        "reason": "authenticated recon needs a test account",
    }


def test_superseding_row_replaces_the_old_row_for_the_gate(client, engagement_id):
    state_manager.record_service(
        engagement_id, endpoint="api.example.com", protocol="tcp", port=None,
        service="", state="up", coverage_status="pending", banner="", notes="",
        discovered_by="test", target_identity=None,
    )
    placeholder = _decide(client, "coverage_deferral", _deferral(["osint"]))
    assert placeholder.status_code == 201, placeholder.text
    old_id = placeholder.json()["id"]

    corrected = _decide(
        client, "coverage_deferral", _deferral(["directory_fuzz"]), supersedes=old_id
    )
    assert corrected.status_code == 201, corrected.text
    new = corrected.json()
    assert new["supersedes_id"] == old_id
    assert new["superseded_by_id"] is None

    host = {
        row["host"]: row
        for row in client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()["hosts"]
    }["api.example.com"]
    assert host["deferred_objectives"] == ["directory_fuzz"]
    assert [row["id"] for row in host["deferrals"]] == [new["id"]]

    # History stays readable.
    old = client.get(f"{ASSESSMENT_BASE}/dispatch-decisions/{old_id}").json()
    assert old["superseded_by_id"] == new["id"]
    assert old["superseded_at"]
    assert old["payload"]["deferred_objectives"] == ["osint"]
    listed = client.get(f"{ASSESSMENT_BASE}/dispatch-decisions?kind=coverage_deferral").json()
    assert [row["id"] for row in listed] == [new["id"]]
    history = client.get(
        f"{ASSESSMENT_BASE}/dispatch-decisions?kind=coverage_deferral&include_superseded=true"
    ).json()
    assert {row["id"] for row in history} == {old_id, new["id"]}


def test_completeness_and_exemption_readers_skip_superseded_rows(client, engagement_id):
    old = _decide(
        client, "coverage_completeness_deferral", {"host": "old.example.com", "reason": "x"}
    ).json()
    _decide(
        client,
        "coverage_completeness_deferral",
        {"host": "new.example.com", "reason": "corrected host"},
        supersedes=old["id"],
    )
    rows = coverage_readiness._active_coverage_completeness_deferrals(engagement_id)
    assert [row["payload"]["host"] for row in rows] == ["new.example.com"]

    exempt = _decide(
        client, "surface_deferral_exemption", {"surface_types": ["dynamic_render"]}
    ).json()
    _decide(
        client,
        "surface_deferral_exemption",
        {"surface_types": ["account_recovery"]},
        supersedes=exempt["id"],
    )
    assert coverage_readiness._deferral_exempt_surface_types(engagement_id) == {
        "account_recovery"
    }


def test_superseding_a_row_of_another_kind_is_refused(client, engagement_id):
    old = _decide(client, "phase_step_deferral", {"step": "nuclei", "reason": "x"}).json()
    response = _decide(
        client, "coverage_deferral", _deferral(["osint"]), supersedes=old["id"]
    )
    assert response.status_code == 422, response.text
    assert "phase_step_deferral" in response.json()["detail"]
    # Nothing was written: the old row is still current.
    assert client.get(
        f"{ASSESSMENT_BASE}/dispatch-decisions/{old['id']}"
    ).json()["superseded_by_id"] is None


def test_superseding_a_missing_or_foreign_row_is_refused(client, isolate_settings, engagement_id):
    _seed(client, isolate_settings, OTHER_KEY)
    foreign = _decide(
        client,
        "phase_step_deferral",
        {"step": "nuclei", "reason": "x"},
        base=f"/engagements/{OTHER_KEY}/assessment",
    ).json()
    for missing in (foreign["id"], 987654):
        response = _decide(
            client, "phase_step_deferral", {"step": "nuclei", "reason": "y"}, supersedes=missing
        )
        assert response.status_code == 404, response.text
        assert str(missing) in response.json()["detail"]


def test_a_row_is_superseded_once(client, engagement_id):
    first = _decide(client, "phase_step_deferral", {"step": "a", "reason": "x"}).json()
    second = _decide(
        client, "phase_step_deferral", {"step": "b", "reason": "x"}, supersedes=first["id"]
    ).json()
    again = _decide(
        client, "phase_step_deferral", {"step": "c", "reason": "x"}, supersedes=first["id"]
    )
    assert again.status_code == 409, again.text
    assert str(second["id"]) in again.json()["detail"]


def test_a_superseded_row_cannot_be_resolved(client, engagement_id):
    first = _decide(client, "dispatch_blocked", {"agent_id": "VA-1", "reason": "x"}).json()
    second = _decide(
        client, "dispatch_blocked", {"agent_id": "VA-1", "reason": "y"}, supersedes=first["id"]
    ).json()
    response = client.patch(
        f"{ASSESSMENT_BASE}/dispatch-decisions/{first['id']}", json={"resolved": True}
    )
    assert response.status_code == 409, response.text
    assert str(second["id"]) in response.json()["detail"]


def test_severity_variance_is_not_superseded_by_a_decision_row(client, engagement_id):
    old = _decide(client, "phase_step_deferral", {"step": "a", "reason": "x"}).json()
    response = _decide(
        client,
        "severity_variance",
        {"finding_slug": "VA-001", "reason": "corrected"},
        supersedes=old["id"],
    )
    assert response.status_code == 422, response.text
    assert "finding verify" in response.json()["detail"]
