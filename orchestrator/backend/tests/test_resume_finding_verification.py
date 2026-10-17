"""Resume summaries distinguish proven findings from unresolved proof obligations."""
from __future__ import annotations

import pytest

from app import db
from app.services.state_manager._common import VerificationStatus
from tests.test_engagements_api import _author_provenance, write_engagement


@pytest.mark.parametrize("verification_status", list(VerificationStatus))
def test_verified_resume_bucket_requires_positive_verification(client, isolate_settings, verification_status):
    path = write_engagement(isolate_settings["engagements_dir"])
    base = f"/engagements/{path.name}/assessment"
    response = client.post(f"{base}/findings", json={
        "slug": "VA-050", "title": "Acme authorization hypothesis", "severity": "high",
        "canonical_location": "https://example.com/login",
        "summary": "Challenge the authorization hypothesis",
        "provenance": _author_provenance(client, "VA-050"),
    })
    assert response.status_code == 201, response.text
    # Exercise the read classification for each already-persisted lifecycle state;
    # evidence admission and verification transitions have separate regressions.
    with db.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_findings SET verification_status=?,status=? "
            "WHERE slug=? AND engagement_id=(SELECT id FROM engagements WHERE key=?)",
            (verification_status, "false_positive" if verification_status == VerificationStatus.FALSE_POSITIVE else "active",
             "VA-050", path.name),
        )

    brief = client.get(f"{base}/resume-brief")
    assert brief.status_code == 200, brief.text
    body = brief.json()
    verified = body["findings"]["verified"]
    if verification_status in {VerificationStatus.CONFIRMED, VerificationStatus.DOWNGRADED}:
        assert [finding["slug"] for finding in verified] == ["VA-050"]
        assert verified[0]["verification_status"] == verification_status
    else:
        assert verified == []
    assert body["finding_counts"]["verification_status"][verification_status] == 1
