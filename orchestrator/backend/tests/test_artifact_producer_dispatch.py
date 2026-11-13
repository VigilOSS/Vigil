"""An artifact's producer_agent_id must name a recorded dispatch.

The producer is an identity review gates compare against — report QC refuses a
reviewer that ever registered the bytes it reviews — so an id that names no
dispatch is a producer nobody can be. The backend refuses it on the single and
the bulk route alike, before any write, so a raw POST is held to the same rule
`artifact register --agent-id` checks client-side. An omitted producer is an
operator registration.
"""
from __future__ import annotations

from app import db as db_module
from tests.test_artifact_resume_api import (
    BASE,
    ENGAGEMENT_KEY,
    _dispatch,
    _write_engagement,
)


def _prepared(client, isolate_settings):
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    (eng / "notes").mkdir(parents=True, exist_ok=True)
    for name in ("a.md", "b.md", "c.md"):
        (eng / "notes" / name).write_text(f"note {name}", encoding="utf-8")
    recorded = _dispatch(
        client, agent_id="VA-LANE-1", agent_role="vulnerability-analyst", task="notes"
    )
    assert recorded.status_code == 201, recorded.text
    return eng


def test_single_registration_refuses_an_unrecorded_producer(client, isolate_settings) -> None:
    _prepared(client, isolate_settings)

    refused = client.post(
        f"{BASE}/artifacts", json={"path": "notes/a.md", "producer_agent_id": "NOT-A-DISPATCH"}
    )

    assert refused.status_code == 404, refused.text
    assert "NOT-A-DISPATCH" in refused.json()["detail"]
    assert "recorded dispatch" in refused.json()["detail"]
    with db_module.get_connection() as connection:
        stored = connection.execute(
            "SELECT COUNT(*) AS n FROM assessment_artifacts WHERE relative_path = 'notes/a.md'"
        ).fetchone()
    assert stored["n"] == 0


def test_single_registration_accepts_a_recorded_producer_and_an_operator(
    client, isolate_settings
) -> None:
    _prepared(client, isolate_settings)

    attributed = client.post(
        f"{BASE}/artifacts", json={"path": "notes/a.md", "producer_agent_id": "VA-LANE-1"}
    )
    operator = client.post(f"{BASE}/artifacts", json={"path": "notes/b.md"})

    assert attributed.status_code == 201, attributed.text
    assert attributed.json()["producer_agent_id"] == "VA-LANE-1"
    assert operator.status_code == 201, operator.text
    assert operator.json()["producer_agent_id"] is None


def test_bulk_registration_refuses_only_the_unrecorded_producer(client, isolate_settings) -> None:
    _prepared(client, isolate_settings)

    response = client.post(
        f"{BASE}/artifacts/bulk",
        json={"items": [
            {"path": "notes/a.md", "producer_agent_id": "VA-LANE-1"},
            {"path": "notes/b.md", "producer_agent_id": "GHOST-7"},
            {"path": "notes/c.md"},
        ]},
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["requested"], body["registered"], body["failed"]) == (3, 2, 1)
    failed = body["outcomes"][1]
    assert failed["outcome"] == "failed"
    assert failed["status_code"] == 404
    assert "GHOST-7" in failed["detail"]
    assert [row["relative_path"] for row in body["artifacts"]] == ["notes/a.md", "notes/c.md"]


def test_a_padded_producer_is_stored_stripped_and_a_blank_one_is_the_operator(
    client, isolate_settings
) -> None:
    """The producer is compared by review gates, so it is one spelling: stripped."""
    _prepared(client, isolate_settings)

    padded = client.post(
        f"{BASE}/artifacts", json={"path": "notes/a.md", "producer_agent_id": "  VA-LANE-1 "}
    )
    blank = client.post(
        f"{BASE}/artifacts", json={"path": "notes/b.md", "producer_agent_id": "   "}
    )
    bulk = client.post(
        f"{BASE}/artifacts/bulk",
        json={"items": [
            {"path": "notes/c.md", "producer_agent_id": " VA-LANE-1"},
            {"path": "notes/a.md", "producer_agent_id": ""},
        ]},
    )

    assert padded.status_code == 201, padded.text
    assert padded.json()["producer_agent_id"] == "VA-LANE-1"
    assert padded.json()["producer_history"] == ["VA-LANE-1"]
    assert blank.status_code == 201, blank.text
    assert blank.json()["producer_agent_id"] is None
    assert bulk.status_code == 201, bulk.text
    assert bulk.json()["failed"] == 0, bulk.json()["outcomes"]
    assert [row["producer_agent_id"] for row in bulk.json()["artifacts"]] == [
        "VA-LANE-1", "VA-LANE-1",
    ]
