"""A record that duplicates an UNSUBMITTED sibling is warned toward corroboration.

Two lanes deriving one defect independently (same location, same family) is the
common duplicate, and the sibling is usually not yet submitted to a program. The
second lane credits its independent re-derivation on the existing finding
(`finding corroborate`) and the operator folds the second row in
(`finding merge`). A submitted sibling keeps the duplicate-link advice and is
listed first. Advisory only — the record still lands.
"""
from __future__ import annotations

from tests.test_finding_response_shape import _base, _payload, _seed


def _record(client, slug: str, **over) -> dict:
    response = client.post(f"{_base()}/findings", json=_payload(slug, **over))
    assert response.status_code == 201, response.text
    return response.json()


def test_an_unsubmitted_sibling_on_the_same_location_is_advised(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    _record(client, "VA-101", canonical_location="https://app.example/api/users/1")

    twin = _record(
        client,
        "VA-102",
        canonical_location="https://app.example/api/users/1",
        root_cause_key="independently-named-root-cause",
    )

    [advisory] = twin["duplicate_advisories"]
    assert advisory["slug"] == "VA-101"
    assert advisory["submission_status"] == "none"
    assert advisory["matched_on"] == ["canonical_location"]
    assert "vigil assess finding corroborate VA-101 --dispatch <your agent_id>" in advisory["detail"]
    assert "vigil assess finding merge VA-102 VA-101" in advisory["detail"]


def test_submitted_siblings_keep_the_duplicate_link_advice_and_lead(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    _record(client, "VA-111", canonical_location="https://app.example/api/users/7")
    _record(
        client, "VA-112", canonical_location="https://app.example/api/users/7",
        root_cause_key="second-name",
    )
    assert client.patch(
        f"{_base()}/findings/VA-111",
        json={"submission_status": "submitted", "submission_ref": "BC-9"},
    ).status_code == 200

    third = _record(
        client, "VA-113", canonical_location="https://app.example/api/users/7",
        root_cause_key="third-name",
    )

    advisories = third["duplicate_advisories"]
    assert [item["slug"] for item in advisories] == ["VA-111", "VA-112"]
    assert "--link-kind" in advisories[0]["detail"]
    assert "finding corroborate VA-112" in advisories[1]["detail"]


def test_merged_and_killed_unsubmitted_siblings_are_not_advised(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    _record(client, "VA-121", canonical_location="https://app.example/api/users/9")
    _record(
        client, "VA-122", canonical_location="https://app.example/api/users/9",
        root_cause_key="kept-name",
    )
    merged = client.post(
        f"{_base()}/findings/merge",
        json={
            "source_slug": "VA-122",
            "target_slug": "VA-121",
            "reason": "same defect",
            "source_name": "operator",
        },
    )
    assert merged.status_code in {200, 201}, merged.text

    unrelated = _record(
        client, "VA-123", canonical_location="https://app.example/api/users/10",
        root_cause_key="elsewhere",
    )
    again = _record(
        client, "VA-124", canonical_location="https://app.example/api/users/9",
        root_cause_key="fourth-name",
    )

    assert unrelated["duplicate_advisories"] == []
    assert [item["slug"] for item in again["duplicate_advisories"]] == ["VA-121"]


def test_a_different_family_is_not_a_duplicate(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    _record(client, "VA-131", canonical_location="https://app.example/api/users/3")

    other = _record(
        client, "VA-132", canonical_location="https://app.example/api/users/3",
        defect_family="server-side-request-forgery", root_cause_key="egress",
    )

    assert other["duplicate_advisories"] == []
