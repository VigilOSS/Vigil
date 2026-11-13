"""One helper says whether a finding's severity departs from its CVSS band and
whether the current verification explains it.

Report readiness and the finding point read both use
``report_readiness.finding_severity_band``, so the advisory readiness raises and
the band the finding record shows cannot disagree.
"""
from __future__ import annotations

import importlib
import json

import pytest

from app.services import state_manager
from tests.test_report_readiness_harness import (
    BASE,
    ENGAGEMENT_KEY,
    _readiness,
    _reportable_finding,
    _write_engagement,
)
from tests.test_severity_variance_derivation import _MEDIUM_DETAILS, _confirm, _receipt

report_readiness = importlib.import_module("app.services.state_manager.report_readiness")


@pytest.fixture
def unverified(client, isolate_settings):
    """A high-severity finding whose CVSS score sits in the medium band."""
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(
        client, eng, slug="SV-001", verification_status="unreviewed",
        details=dict(_MEDIUM_DETAILS),
    )
    return "SV-001"


def _band(client, slug: str) -> dict:
    record = client.get(f"{BASE}/findings/{slug}").json()
    engagement_id = int(record["engagement_id"])
    with state_manager.get_connection() as connection:
        return report_readiness.finding_severity_band(connection, engagement_id, record)


def test_an_unexplained_departure_matches_the_readiness_advisory(client, unverified):
    assert _confirm(client, unverified, _receipt(client, unverified)).status_code == 200

    band = _band(client, unverified)
    assert band == {
        "cvss_band": "medium",
        "departs": True,
        "current_variance_id": None,
        "explained": False,
    }
    assert any(
        row["kind"] == "severity_cvss_mismatch" and row["slug"] == unverified
        for row in _readiness(client)["advisories"]
    )


def test_a_variance_on_the_current_verification_explains_the_departure(client, unverified):
    response = _confirm(client, unverified, _receipt(client, unverified), severity_variance={
        "reason": "Contractual exposure for Acme justifies high.",
    })
    assert response.status_code == 200, response.text

    band = _band(client, unverified)
    audit = client.get(f"{BASE}/findings/{unverified}").json()["verification_audit"]
    assert band["departs"] is True
    assert band["explained"] is True
    assert band["current_variance_id"] == audit["severity_variances"][0]["id"]
    assert any(
        row["kind"] == "severity_cvss_band_divergence" and row["slug"] == unverified
        for row in _readiness(client)["advisories"]
    )


def test_the_finding_point_read_serves_the_band(client, unverified):
    assert _confirm(client, unverified, _receipt(client, unverified)).status_code == 200
    audit = client.get(f"{BASE}/findings/{unverified}").json()["verification_audit"]
    assert audit["severity_band"] == _band(client, unverified)


def test_a_blue_engagement_finding_is_not_judged_on_its_cvss_band(client, isolate_settings):
    """Blue severity follows MITRE impact (agent/rules/triage.md), and readiness
    raises no band advisory there; the point read agrees."""
    eng = _write_engagement(isolate_settings["engagements_dir"])
    scope = json.loads((eng / "scope.json").read_text(encoding="utf-8"))
    scope["tracks"] = {"blue": {"phase": "verify"}}
    (eng / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(
        client, eng, slug="SV-002", verification_status="unreviewed",
        details=dict(_MEDIUM_DETAILS, mitre_techniques=["T1078"]),
    )
    assert _confirm(client, "SV-002", _receipt(client, "SV-002")).status_code == 200

    band = _band(client, "SV-002")
    assert band["departs"] is False
    assert band["explained"] is False
    audit = client.get(f"{BASE}/findings/SV-002").json()["verification_audit"]
    assert audit["severity_band"] == band
    assert not any(
        row["kind"].startswith("severity_cvss") and row["slug"] == "SV-002"
        for row in _readiness(client)["advisories"]
    )
