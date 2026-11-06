"""`details.replay_commands` names executed command runs, so the ids resolve.

The key exists so a reader can re-execute exactly what was run. An id that
resolves to nothing in this engagement is a citation to a transcript nobody can
fetch — the same reason `details.repro_runs` has been resolved at write time
since it was introduced, and the same error shape.
"""
from __future__ import annotations

import json

from tests.test_engagements_api import write_engagement

ENGAGEMENT_KEY = "2026-11-04-replay-commands"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    dispatch = client.post(
        f"{BASE}/dispatches",
        json={"agent_id": "HUNT-1", "agent_role": "vulnerability-analyst", "task": "hunt"},
    )
    assert dispatch.status_code == 201, dispatch.text
    finding = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-001",
            "title": "Replay citation finding",
            "severity": "medium",
            "workflow_status": "active",
            "defect_family": "access-control",
            "root_cause_key": "missing-object-authz",
            "canonical_location": "https://acme.example/api/orders",
            "summary": "Missing object authorization.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "Replayable request.", "impact": "PII disclosure."},
            "provenance": {"agent_id": "HUNT-1"},
        },
    )
    assert finding.status_code == 201, finding.text


def _command_run(client, tag: str) -> int:
    response = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": f"replay-{tag}",
            "command": "curl https://acme.example/api/orders/2",
            "tool_name": "curl",
            "agent_name": "HUNT-1",
            "phase": "verify",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-11-04T12:00:00Z",
            "completed_at": "2026-11-04T12:00:01Z",
            "stdout": "order 2",
        },
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def test_an_unresolvable_replay_command_id_is_refused(client, isolate_settings) -> None:
    _seed(client, isolate_settings)

    missing = client.patch(
        f"{BASE}/findings/VA-001", json={"details": {"replay_commands": [999999]}}
    )

    assert missing.status_code == 400, missing.text
    detail = missing.json()["detail"]
    assert "replay_commands" in detail
    assert "999999" in detail
    stored = client.get(f"{BASE}/findings/VA-001").json()["details"]
    assert "replay_commands" not in stored


def test_a_resolvable_replay_command_id_is_stored(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    run_id = _command_run(client, "ok")

    accepted = client.patch(
        f"{BASE}/findings/VA-001", json={"details": {"replay_commands": [run_id]}}
    )

    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["finding"]["details"]["replay_commands"] == [run_id]


def test_a_replay_citation_from_another_engagement_is_refused(
    client, isolate_settings
) -> None:
    """Command-run ids are per-engagement, so a neighbour's id resolves to nothing."""
    _seed(client, isolate_settings)
    other_key = f"{ENGAGEMENT_KEY}-neighbour"
    write_engagement(isolate_settings["engagements_dir"], key=other_key)
    assert client.get(f"/engagements/{other_key}").status_code == 200
    other_base = f"/engagements/{other_key}/assessment"
    assert client.post(
        f"{other_base}/dispatches",
        json={"agent_id": "HUNT-9", "agent_role": "vulnerability-analyst", "task": "hunt"},
    ).status_code == 201
    neighbour = client.post(
        f"{other_base}/command-runs",
        json={
            "run_uuid": "replay-neighbour",
            "command": "curl https://acme.example/api/orders/9",
            "tool_name": "curl",
            "agent_name": "HUNT-9",
            "phase": "verify",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-11-04T12:00:00Z",
            "completed_at": "2026-11-04T12:00:01Z",
            "stdout": "order 9",
        },
    )
    assert neighbour.status_code == 201, neighbour.text

    refused = client.patch(
        f"{BASE}/findings/VA-001",
        json={"details": {"replay_commands": [neighbour.json()["id"]]}},
    )

    assert refused.status_code == 400, refused.text
    assert "replay_commands" in refused.json()["detail"]


def test_a_replay_command_id_must_be_an_id_not_a_command(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)

    refused = client.patch(
        f"{BASE}/findings/VA-001",
        json={"details": {"replay_commands": ["curl https://acme.example/api/orders/2"]}},
    )

    assert refused.status_code == 400, refused.text
    assert "replay_commands" in refused.json()["detail"]
    assert json.loads(json.dumps(refused.json()["detail"]))
