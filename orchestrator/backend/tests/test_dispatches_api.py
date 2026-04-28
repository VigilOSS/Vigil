"""Round 9: contract tests for the new ``assessment_dispatches`` API.

POST + GET + LIST + PATCH coverage. The dispatch row replaces the legacy
``$DIR/agent-registry.json`` audit trail; the sibling tables
(``assessment_dispatch_handoffs`` and ``assessment_dispatch_decisions``) have
their own files. UNIQUE(engagement_id, agent_id) enforcement → 409 on dup.
404 on missing agent_id. List filters: role, status, since, task_q, limit.
"""
from __future__ import annotations

import json
from pathlib import Path


ENGAGEMENT_KEY = "2026-04-28-120000-dispatches"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _write_engagement(engagements_dir: Path, key: str = ENGAGEMENT_KEY) -> Path:
    eng = engagements_dir / key
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "engagement.json").write_text(
        json.dumps({"key": key, "target": "https://example.com", "hostname": "example.com",
                    "created_at": "2026-04-28T12:00:00Z"}),
        encoding="utf-8",
    )
    (eng / "scope.json").write_text(
        json.dumps({
            "hostname": "example.com",
            "hosts": ["example.com"],
            "status": "in_progress",
            "current_phase": "recon",
        }),
        encoding="utf-8",
    )
    return eng


def _seed(client, isolate_settings) -> None:
    _write_engagement(isolate_settings["engagements_dir"])
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text


def test_dispatch_post_get_list_patch(client, isolate_settings) -> None:
    _seed(client, isolate_settings)

    payload = {
        "agent_id": "AG-001",
        "agent_role": "vulnerability-analyst",
        "task": "Validate IDOR on /api/users/{id}",
        "skill_loaded": "agent/skills/idor-testing/SKILL.md",
        "scope_host": "example.com",
        "model": "gpt-5.4",
        "reasoning": "high",
        "permission": "target-facing",
        "command_budget": 30,
        "dispatch_mode": "item-iterating",
        "files_allowed": ["agent/agents/vulnerability-analyst.md"],
        "finding_slugs": [],
    }
    resp = client.post(f"{BASE}/dispatches", json=payload)
    assert resp.status_code == 201, resp.text
    row = resp.json()
    assert row["agent_id"] == "AG-001"
    assert row["agent_role"] == "vulnerability-analyst"
    assert row["status"] == "in-progress"
    assert row["files_allowed"] == ["agent/agents/vulnerability-analyst.md"]
    assert row["finding_slugs"] == []
    assert row["dispatched_at"]  # server-stamped when not supplied

    # GET one
    resp = client.get(f"{BASE}/dispatches/AG-001")
    assert resp.status_code == 200, resp.text
    assert resp.json()["task"].startswith("Validate IDOR")

    # GET list
    resp = client.get(f"{BASE}/dispatches")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["agent_id"] == "AG-001"

    # Filter by role
    resp = client.get(f"{BASE}/dispatches", params={"role": "vulnerability-analyst"})
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    resp = client.get(f"{BASE}/dispatches", params={"role": "recon-specialist"})
    assert resp.status_code == 200
    assert resp.json() == []

    # PATCH status -> completed
    resp = client.patch(
        f"{BASE}/dispatches/AG-001",
        json={
            "status": "completed",
            "completed_at": "2026-04-28T13:00:00Z",
            "finding_slugs": ["VA-001", "VA-002"],
        },
    )
    assert resp.status_code == 200, resp.text
    updated = resp.json()
    assert updated["status"] == "completed"
    assert updated["completed_at"] == "2026-04-28T13:00:00Z"
    assert updated["finding_slugs"] == ["VA-001", "VA-002"]


def test_dispatch_duplicate_agent_id_returns_409(client, isolate_settings) -> None:
    _seed(client, isolate_settings)

    payload = {"agent_id": "AG-DUP", "agent_role": "recon-specialist"}
    resp = client.post(f"{BASE}/dispatches", json=payload)
    assert resp.status_code == 201
    resp2 = client.post(f"{BASE}/dispatches", json=payload)
    assert resp2.status_code == 409, resp2.text


def test_dispatch_404_on_missing(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    resp = client.get(f"{BASE}/dispatches/never-existed")
    assert resp.status_code == 404
    resp = client.patch(f"{BASE}/dispatches/never-existed", json={"status": "completed"})
    assert resp.status_code == 404


def test_dispatch_list_filters(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    rows = [
        {"agent_id": "F1", "agent_role": "recon-specialist", "task": "phase 1 enum",
         "status": "completed", "dispatched_at": "2026-04-27T09:00:00Z"},
        {"agent_id": "F2", "agent_role": "vulnerability-analyst", "task": "IDOR sweep",
         "status": "in-progress", "dispatched_at": "2026-04-28T10:00:00Z"},
        {"agent_id": "F3", "agent_role": "vulnerability-analyst", "task": "SQLi probe",
         "status": "failed", "dispatched_at": "2026-04-28T11:00:00Z"},
    ]
    for r in rows:
        assert client.post(f"{BASE}/dispatches", json=r).status_code == 201

    # status filter
    resp = client.get(f"{BASE}/dispatches", params={"status": "completed"})
    assert {r["agent_id"] for r in resp.json()} == {"F1"}

    # since filter
    resp = client.get(f"{BASE}/dispatches", params={"since": "2026-04-28T00:00:00Z"})
    assert {r["agent_id"] for r in resp.json()} == {"F2", "F3"}

    # task_q filter (substring)
    resp = client.get(f"{BASE}/dispatches", params={"task_q": "IDOR"})
    assert {r["agent_id"] for r in resp.json()} == {"F2"}

    # limit
    resp = client.get(f"{BASE}/dispatches", params={"limit": 2})
    assert len(resp.json()) == 2


def test_dispatch_validation_rejects_bad_status_and_unknown_fields(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    # Bad status enum
    bad = client.post(f"{BASE}/dispatches", json={
        "agent_id": "BAD-1",
        "agent_role": "recon-specialist",
        "status": "in_progress",  # underscore instead of hyphen
    })
    assert bad.status_code == 422

    # Unknown field (extra="forbid")
    bad = client.post(f"{BASE}/dispatches", json={
        "agent_id": "BAD-2",
        "agent_role": "recon-specialist",
        "garbage_key": "nope",
    })
    assert bad.status_code == 422
