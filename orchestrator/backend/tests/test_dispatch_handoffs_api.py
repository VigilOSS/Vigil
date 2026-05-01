"""Round 9: contract tests for the new ``assessment_dispatch_handoffs`` API.

POST + GET + LIST + PATCH coverage. Validates that ``summary`` is required
and ≤2000 chars, JSON-array fields round-trip, and 409 fires on duplicate
(engagement, agent_id).
"""
from __future__ import annotations

import json
from pathlib import Path


ENGAGEMENT_KEY = "2026-04-28-130000-handoffs"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _write_engagement(engagements_dir: Path, key: str = ENGAGEMENT_KEY) -> Path:
    eng = engagements_dir / key
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "engagement.json").write_text(
        json.dumps({"key": key, "target": "https://example.com", "hostname": "example.com",
                    "created_at": "2026-04-28T13:00:00Z"}),
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


def _register_dispatch(client, *, agent_id: str, agent_role: str) -> None:
    response = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": agent_id,
            "agent_role": agent_role,
            "task": f"handoff test for {agent_id}",
        },
    )
    assert response.status_code == 201, response.text


def _full_payload(agent_id: str = "HF-001", **overrides):
    payload = {
        "agent_id": agent_id,
        "agent_role": "vulnerability-analyst",
        "phase": "consume-test",
        "summary": "Validated IDOR write primitive on /api/users/{id}.",
        "confidence": "high",
        "finding_slugs": ["VA-001"],
        "coverage_gaps": [{"area": "auth boundary", "reason": "anonymous not tested"}],
        "next_steps": [{"action": "promote to exploit-developer", "recommended_agent": "exploit-developer"}],
        "runtime_issues": [{"kind": "rate-limit", "detail": "429 after 25rps", "severity": "low"}],
        "working_artifacts": [{"path": "tools/exploit-state/EX-001-payload.sql", "kind": "payload"}],
        "open_questions": ["Does write-primitive bypass MFA?"],
        "recommended_next_agent": "exploit-developer",
        "extras": {"dispatched_by": "operator"},
    }
    payload.update(overrides)
    return payload


def test_handoff_post_get_round_trip(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    _register_dispatch(client, agent_id="HF-001", agent_role="vulnerability-analyst")

    resp = client.post(f"{BASE}/dispatch-handoffs", json=_full_payload())
    assert resp.status_code == 201, resp.text
    row = resp.json()
    assert row["agent_id"] == "HF-001"
    assert row["finding_slugs"] == ["VA-001"]
    assert row["coverage_gaps"][0]["area"] == "auth boundary"
    assert row["next_steps"][0]["action"] == "promote to exploit-developer"
    assert row["extras"] == {"dispatched_by": "operator"}

    resp = client.get(f"{BASE}/dispatch-handoffs/HF-001")
    assert resp.status_code == 200
    fetched = resp.json()
    assert fetched["working_artifacts"][0]["path"].endswith("EX-001-payload.sql")
    assert fetched["recommended_next_agent"] == "exploit-developer"

    activity = client.get(f"/engagements/{ENGAGEMENT_KEY}/activity-entries", params={"q": "record-handoff"})
    assert activity.status_code == 200, activity.text
    titles = {row["title"] for row in activity.json()["items"]}
    assert "dispatch record-handoff" in titles


def test_handoff_summary_required_and_bounded(client, isolate_settings) -> None:
    _seed(client, isolate_settings)

    # Empty summary → 422
    bad = client.post(f"{BASE}/dispatch-handoffs", json={
        "agent_id": "EMPTY", "agent_role": "recon-specialist", "summary": "",
    })
    assert bad.status_code == 422

    # >2000 chars → 422
    huge = client.post(f"{BASE}/dispatch-handoffs", json={
        "agent_id": "HUGE", "agent_role": "recon-specialist", "summary": "x" * 2001,
    })
    assert huge.status_code == 422

    # 2000 chars exactly is fine
    _register_dispatch(client, agent_id="MAX", agent_role="recon-specialist")
    ok = client.post(f"{BASE}/dispatch-handoffs", json={
        "agent_id": "MAX", "agent_role": "recon-specialist", "summary": "x" * 2000,
    })
    assert ok.status_code == 201, ok.text


def test_handoff_duplicate_returns_409_and_patch_updates(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    payload = _full_payload(agent_id="HF-DUP")
    _register_dispatch(client, agent_id="HF-DUP", agent_role="vulnerability-analyst")
    assert client.post(f"{BASE}/dispatch-handoffs", json=payload).status_code == 201
    dup = client.post(f"{BASE}/dispatch-handoffs", json=payload)
    assert dup.status_code == 409, dup.text

    # PATCH should merge new fields
    patch = client.patch(
        f"{BASE}/dispatch-handoffs/HF-DUP",
        json={"summary": "Updated summary text", "confidence": "medium",
              "finding_slugs": ["VA-001", "VA-002"]},
    )
    assert patch.status_code == 200, patch.text
    updated = patch.json()
    assert updated["summary"] == "Updated summary text"
    assert updated["confidence"] == "medium"
    assert updated["finding_slugs"] == ["VA-001", "VA-002"]


def test_handoff_list_filters(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    rows = [
        _full_payload(agent_id="L1", agent_role="recon-specialist"),
        _full_payload(agent_id="L2", agent_role="vulnerability-analyst"),
    ]
    for r in rows:
        _register_dispatch(client, agent_id=r["agent_id"], agent_role=r["agent_role"])
        assert client.post(f"{BASE}/dispatch-handoffs", json=r).status_code == 201

    resp = client.get(f"{BASE}/dispatch-handoffs", params={"role": "recon-specialist"})
    assert {r["agent_id"] for r in resp.json()} == {"L1"}


def test_handoff_404_on_missing(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    resp = client.get(f"{BASE}/dispatch-handoffs/missing")
    assert resp.status_code == 404
    resp = client.patch(f"{BASE}/dispatch-handoffs/missing", json={"summary": "x"})
    assert resp.status_code == 404


def test_handoff_requires_registered_dispatch(client, isolate_settings) -> None:
    _seed(client, isolate_settings)

    resp = client.post(
        f"{BASE}/dispatch-handoffs",
        json=_full_payload(agent_id="UNREGISTERED", agent_role="vulnerability-analyst"),
    )

    assert resp.status_code == 404, resp.text
    assert "dispatch not found" in resp.text


def test_handoff_rejects_role_mismatch(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    _register_dispatch(client, agent_id="ROLE-MISMATCH", agent_role="recon-specialist")

    resp = client.post(
        f"{BASE}/dispatch-handoffs",
        json=_full_payload(agent_id="ROLE-MISMATCH", agent_role="vulnerability-analyst"),
    )

    assert resp.status_code == 409, resp.text
    assert "agent_role mismatch" in resp.text
