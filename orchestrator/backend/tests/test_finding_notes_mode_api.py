"""PATCH /findings/{slug} notes_mode: append (default) vs replace.

Regression for the append-only `notes` column that made stale/contradicted
internal text impossible to scrub via the CLI (`update-finding`).
"""
import json

import pytest
from fastapi import HTTPException

from app import db as db_module
from app.services import state_manager

ENGAGEMENT_KEY = "2026-05-29-120000-notes-mode"


def _seed(client, isolate_settings) -> None:
    engagement_dir = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Notes Mode Test", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200


def _finding_payload() -> dict:
    return {
        "slug": "VA-001",
        "title": "IDOR in /api/users/{id} allows anon read of any user PII",
        "severity": "high",
        "workflow_status": "exploited",
        "verification_state": "verified",
        "verification_disposition": "confirmed",
        "defect_family": "access-control",
        "root_cause_key": "missing-object-authz",
        "canonical_location": "https://app.example/api/users",
        "summary": "IDOR",
        "evidence_ref": "findings.md",
        "source_name": "test",
        "notes": "PROVEN by run 13691",
        "details": {
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "steps_to_reproduce": ["Replay the recorded request."],
            "remediation": "Enforce object-level authorization.",
            "impact": "Anonymous attackers read any user's PII.",
            "evidence": "Replayable request.",
        },
    }


def _base(key=ENGAGEMENT_KEY):
    return f"/engagements/{key}/assessment"


def test_patch_notes_appends_by_default(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    resp = client.patch(f"{_base()}/findings/VA-001", json={"notes": "verify phase disproved run 13691"})
    assert resp.status_code == 200, resp.text
    notes = resp.json()["finding"]["notes"]
    # Default keeps the original line AND the new line (append/checkpoint behavior).
    assert "PROVEN by run 13691" in notes
    assert "verify phase disproved run 13691" in notes


def test_patch_notes_replace_overwrites(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    resp = client.patch(
        f"{_base()}/findings/VA-001",
        json={
            "notes": "Disproven; see VA-001 verify handoff.",
            "notes_mode": "replace",
            "expected_row_version": 1,
        },
    )
    assert resp.status_code == 200, resp.text
    notes = resp.json()["finding"]["notes"]
    # The stale line is gone — only the replacement remains.
    assert "PROVEN by run 13691" not in notes
    assert notes.strip() == "Disproven; see VA-001 verify handoff."


@pytest.mark.parametrize(
    "payload",
    [
        {"notes": "replacement", "notes_mode": "replace"},
        {"details": {}, "details_mode": "replace"},
    ],
    ids=["notes", "details"],
)
def test_patch_replace_requires_caller_cas_at_api_boundary(
    client, isolate_settings, payload
):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text

    resp = client.patch(f"{_base()}/findings/VA-001", json=payload)

    assert resp.status_code == 422, resp.text
    assert "expected_row_version" in resp.text
    unchanged = client.get(f"{_base()}/findings/VA-001")
    assert unchanged.status_code == 200
    assert unchanged.json()["row_version"] == 1
    assert unchanged.json()["notes"] == "PROVEN by run 13691"


@pytest.mark.parametrize(
    "patch_kwargs",
    [
        {"notes": "replacement", "notes_mode": "replace"},
        {"details": {}, "details_mode": "replace"},
    ],
    ids=["notes", "details"],
)
def test_patch_service_rejects_replace_without_caller_cas(
    client, isolate_settings, patch_kwargs
):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text
    with db_module.get_connection() as connection:
        engagement_id = int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
            ).fetchone()["id"]
        )

    with pytest.raises(HTTPException) as exc_info:
        state_manager.patch_finding(
            engagement_id,
            slug="VA-001",
            **patch_kwargs,
        )

    assert exc_info.value.status_code == 400
    assert "expected_row_version" in str(exc_info.value.detail)


def test_patch_notes_replace_requires_notes(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)

    resp = client.patch(
        f"{_base()}/findings/VA-001",
        json={"notes_mode": "replace"},
    )
    assert resp.status_code == 422

    detail = client.get(f"{_base()}/findings/VA-001")
    assert detail.status_code == 200
    assert detail.json()["notes"] == "PROVEN by run 13691"


def test_patch_notes_mode_rejects_unknown_value(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_finding_payload()).status_code in (200, 201)
    resp = client.patch(
        f"{_base()}/findings/VA-001",
        json={"notes": "x", "notes_mode": "prepend"},
    )
    assert resp.status_code == 422  # Literal["append","replace"] rejects others


@pytest.mark.parametrize(
    "payload",
    [
        {"expected_row_version": 1},
        {
            "expected_row_version": 1,
            "notes_mode": "append",
            "details_mode": "merge",
        },
    ],
)
def test_patch_rejects_only_concurrency_and_mode_controls(
    client, isolate_settings, payload
):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text

    resp = client.patch(f"{_base()}/findings/VA-001", json=payload)

    assert resp.status_code == 422, resp.text
    assert "do not update a finding" in resp.text
    unchanged = client.get(f"{_base()}/findings/VA-001")
    assert unchanged.status_code == 200
    assert unchanged.json()["row_version"] == 1


@pytest.mark.parametrize(
    "payload",
    [
        {
            "reason_code": "checkpoint",
            "reason_text": "No finding field changed.",
            "artifact_ref": "evidence/no-op.txt",
            "expected_row_version": 1,
        },
        {
            "summary": None,
            "notes": None,
            "details": None,
            "provenance": None,
            "expected_row_version": 1,
        },
        {
            "defect_family": "",
            "root_cause_key": "",
            "canonical_location": "",
            "summary": "",
            "evidence_ref": "",
            "notes": "",
            "notes_mode": "append",
            "source_name": "",
            "details": {},
            "details_mode": "merge",
            "provenance": {},
            "expected_row_version": 1,
        },
    ],
)
def test_patch_rejects_transition_metadata_and_empty_merge_noops(
    client, isolate_settings, payload
):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text

    resp = client.patch(f"{_base()}/findings/VA-001", json=payload)

    assert resp.status_code == 422, resp.text
    unchanged = client.get(f"{_base()}/findings/VA-001")
    assert unchanged.status_code == 200
    assert unchanged.json()["row_version"] == 1


def test_patch_allows_empty_notes_replacement_with_cas(client, isolate_settings):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text

    resp = client.patch(
        f"{_base()}/findings/VA-001",
        json={"notes": "", "notes_mode": "replace", "expected_row_version": 1},
    )

    assert resp.status_code == 200, resp.text
    finding = resp.json()["finding"]
    assert finding["notes"] == ""
    assert finding["row_version"] == 2


def test_patch_allows_empty_details_replacement_with_cas(client, isolate_settings):
    _seed(client, isolate_settings)
    created = client.post(f"{_base()}/findings", json=_finding_payload())
    assert created.status_code in (200, 201), created.text

    resp = client.patch(
        f"{_base()}/findings/VA-001",
        json={"details": {}, "details_mode": "replace", "expected_row_version": 1},
    )

    assert resp.status_code == 200, resp.text
    finding = resp.json()["finding"]
    assert json.loads(finding["details_json"]) == {}
    assert finding["row_version"] == 2
