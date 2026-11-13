"""An unknown severity is refused on every write, never stored as `info`.

Severity is an invalidating field, so a typo that silently landed as `info`
both under-rated the finding and reset its verdict. Every write input resolves
through `_common._require_severity`; stored rows keep reading through the
lenient `_normalize_severity`.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.services.state_manager._common import SEVERITY_RANK, _require_severity


ENGAGEMENT_KEY = "2026-11-13-120000-severity-input"
AUTHOR_AGENT_ID = "SEVERITY-FIXTURE-AUTHOR"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


@pytest.mark.parametrize(
    ("value", "expected"),
    [("high", "high"), ("HIGH", "high"), (" Critical ", "critical"), ("info", "info")],
)
def test_require_severity_accepts_each_canonical_band_in_any_case(value, expected) -> None:
    assert _require_severity(value) == expected


@pytest.mark.parametrize("value", ["moderate", "severe", "p1", "medium-high", "informational"])
def test_require_severity_refuses_an_unknown_band_naming_the_vocabulary(value) -> None:
    with pytest.raises(HTTPException) as exc:
        _require_severity(value, field="new_severity")

    assert exc.value.status_code == 400
    assert repr(value) in exc.value.detail
    assert "new_severity" in exc.value.detail
    assert ", ".join(SEVERITY_RANK) in exc.value.detail


def _seed(client, isolate_settings) -> None:
    engagement_dir = Path(isolate_settings["engagements_dir"]) / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Severity Input", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    dispatch = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": AUTHOR_AGENT_ID,
            "agent_role": "vulnerability-analyst",
            "task": "Record severity fixture findings",
        },
    )
    assert dispatch.status_code == 201, dispatch.text


def _finding(slug: str, severity: str) -> dict:
    return {
        "slug": slug,
        "title": f"Acme order export IDOR {slug}",
        "severity": severity,
        "workflow_status": "active",
        "verification_status": "unreviewed",
        "defect_family": "idor",
        "root_cause_key": slug.lower(),
        "canonical_location": f"https://app.example/orders/{slug.lower()}",
        "summary": "Order export returns another tenant's orders.",
        "evidence_ref": "findings.md",
        "source_name": "test",
        "provenance": {"agent_id": AUTHOR_AGENT_ID},
        "details": {
            "steps_to_reproduce": ["Replay the recorded request."],
            "impact": "Attackers read other tenants' orders.",
        },
    }


def test_finding_record_refuses_an_unknown_severity(client, isolate_settings) -> None:
    _seed(client, isolate_settings)

    refused = client.post(f"{BASE}/findings", json=_finding("SV-001", "moderate"))

    assert refused.status_code == 400, refused.text
    assert "'moderate'" in refused.json()["detail"]
    assert client.get(f"{BASE}/findings/SV-001").status_code == 404

    accepted = client.post(f"{BASE}/findings", json=_finding("SV-002", "High"))
    assert accepted.status_code in {200, 201}, accepted.text
    assert client.get(f"{BASE}/findings/SV-002").json()["severity"] == "high"


def test_finding_patch_refuses_an_unknown_severity_and_keeps_the_row(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    created = client.post(f"{BASE}/findings", json=_finding("SV-010", "high"))
    assert created.status_code in {200, 201}, created.text
    before = client.get(f"{BASE}/findings/SV-010").json()

    refused = client.patch(
        f"{BASE}/findings/SV-010",
        json={
            "severity": "moderate",
            "reason_text": "Program rated it moderate.",
            "expected_row_version": before["row_version"],
        },
    )

    assert refused.status_code == 400, refused.text
    assert "'moderate'" in refused.json()["detail"]
    after = client.get(f"{BASE}/findings/SV-010").json()
    assert (after["severity"], after["verification_status"], after["row_version"]) == (
        "high", before["verification_status"], before["row_version"],
    )


def test_attack_chain_refuses_an_unknown_severity(client, isolate_settings) -> None:
    _seed(client, isolate_settings)

    refused = client.post(
        f"{BASE}/attack-chains",
        json={"title": "IDOR to takeover", "severity": "severe"},
    )

    assert refused.status_code == 400, refused.text
    assert "'severe'" in refused.json()["detail"]
    assert client.get(f"{BASE}/attack-chains").json() == []


@pytest.mark.parametrize("verification_status", ["downgraded", "confirmed"])
def test_verify_refuses_an_unknown_new_severity(
    verification_status, client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    created = client.post(f"{BASE}/findings", json=_finding("SV-020", "high"))
    assert created.status_code in {200, 201}, created.text

    refused = client.post(
        f"{BASE}/findings/SV-020/verify",
        json={
            "verification_status": verification_status,
            "reason_text": "Program rated it moderate.",
            "new_severity": "moderate",
        },
    )

    assert refused.status_code == 400, refused.text
    assert "'moderate'" in refused.json()["detail"]
    after = client.get(f"{BASE}/findings/SV-020").json()
    assert (after["severity"], after["verification_status"]) == ("high", "unreviewed")
