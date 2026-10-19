"""Round 9: contract tests for the new ``assessment_dispatch_handoffs`` API.

POST + GET + LIST + PATCH coverage. Validates that ``summary`` is required
and ≤2000 chars, JSON-array fields round-trip, and 409 fires on duplicate
(engagement, agent_id).
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi import HTTPException

from app import db as db_module
from app.services import state_manager


ENGAGEMENT_KEY = "2026-04-28-130000-handoffs"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"
SEED_AUTHOR_AGENT_ID = "HANDOFF-FINDING-AUTHOR"


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
    eng = _write_engagement(isolate_settings["engagements_dir"])
    (eng / "findings.md").write_text("# Findings\n", encoding="utf-8")
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    _register_dispatch(
        client,
        agent_id=SEED_AUTHOR_AGENT_ID,
        agent_role="vulnerability-analyst",
    )
    for slug in ("VA-001", "VA-002"):
        finding = client.post(
            f"{BASE}/findings",
            json={
                "slug": slug,
                "title": f"Seed finding {slug}",
                "severity": "medium",
                "workflow_status": "active",
                "verification_status": "unreviewed",
                "canonical_location": f"https://example.com/seed/{slug}",
                "summary": "Seed finding for handoff references",
                "evidence_ref": "findings.md",
                "source_name": "vulnerability-analyst",
                "provenance": {"agent_id": SEED_AUTHOR_AGENT_ID},
            },
        )
        assert finding.status_code == 201, finding.text


def _register_dispatch(client, *, agent_id: str, agent_role: str) -> None:
    response = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": agent_id,
            "agent_role": agent_role,
            "task": f"handoff test for {agent_id}",
            # Specialist roles require a non-empty `skills` value so the
            # dispatch row is auditable. Use a real on-disk skill name so
            # the validator's warn-only on-disk check stays quiet.
            "skills": "auth-bypass",
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

    activity = client.get(f"/engagements/{ENGAGEMENT_KEY}/activity-entries", params={"q": "handoff"})
    assert activity.status_code == 200, activity.text
    titles = {row["title"] for row in activity.json()["items"]}
    assert "agent handoff" in titles


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

    activity = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/activity-entries",
        params={"q": "handoff"},
    )
    assert activity.status_code == 200, activity.text
    assert sum(1 for row in activity.json()["items"] if row["title"] == "agent handoff") >= 2


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


def test_handoff_list_supports_stable_offset_pagination(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    for agent_id in ("PAGE-1", "PAGE-2", "PAGE-3"):
        _register_dispatch(
            client,
            agent_id=agent_id,
            agent_role="recon-specialist",
        )
        response = client.post(
            f"{BASE}/dispatch-handoffs",
            json=_full_payload(
                agent_id=agent_id,
                agent_role="recon-specialist",
            ),
        )
        assert response.status_code == 201, response.text

    first = client.get(
        f"{BASE}/dispatch-handoffs",
        params={"limit": 2, "offset": 0},
    )
    second = client.get(
        f"{BASE}/dispatch-handoffs",
        params={"limit": 2, "offset": 2},
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert len(first.json()) == 2
    assert len(second.json()) == 1
    assert {row["agent_id"] for row in first.json()}.isdisjoint(
        {row["agent_id"] for row in second.json()}
    )


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


def test_handoff_rejects_non_terminal_closed_dispatch_status(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    _register_dispatch(client, agent_id="HF-CLOSE", agent_role="vulnerability-analyst")

    rejected_create = client.post(
        f"{BASE}/dispatch-handoffs",
        json=_full_payload(
            agent_id="HF-CLOSE",
            handoff_status="ready",
            closed_dispatch_status="in-progress",
        ),
    )
    assert rejected_create.status_code == 422, rejected_create.text

    created = client.post(
        f"{BASE}/dispatch-handoffs",
        json=_full_payload(
            agent_id="HF-CLOSE",
            handoff_status="ready",
            closed_dispatch_status="completed",
        ),
    )
    assert created.status_code == 201, created.text

    rejected_patch = client.patch(
        f"{BASE}/dispatch-handoffs/HF-CLOSE",
        json={"closed_dispatch_status": "in-progress"},
    )
    assert rejected_patch.status_code == 422, rejected_patch.text


def test_handoff_status_accepted_on_post_and_patch(client, isolate_settings) -> None:
    """Regression: handoff_status used to 422 'Extra inputs are not permitted' on
    both POST and PATCH. All four enum values must round-trip on both verbs."""
    _seed(client, isolate_settings)
    for status_value in ("checkpointed", "ready", "blocked", "superseded"):
        aid = f"HS-{status_value}"
        _register_dispatch(client, agent_id=aid, agent_role="vulnerability-analyst")

        posted = client.post(
            f"{BASE}/dispatch-handoffs",
            json=_full_payload(agent_id=aid, handoff_status=status_value),
        )
        assert posted.status_code == 201, posted.text
        assert posted.json()["handoff_status"] == status_value

        patched = client.patch(
            f"{BASE}/dispatch-handoffs/{aid}",
            json={"handoff_status": status_value},
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["handoff_status"] == status_value


def test_handoff_model_still_forbids_unknown_fields_and_bad_status(client, isolate_settings) -> None:
    """The fix was 'declare handoff_status', NOT 'loosen the model' — an unknown
    field and an out-of-enum status both still 422."""
    _seed(client, isolate_settings)
    _register_dispatch(client, agent_id="HS-BAD", agent_role="vulnerability-analyst")

    unknown_field = client.post(
        f"{BASE}/dispatch-handoffs",
        json=_full_payload(agent_id="HS-BAD", totally_bogus_field="x"),
    )
    assert unknown_field.status_code == 422

    bad_status = client.post(
        f"{BASE}/dispatch-handoffs",
        json=_full_payload(agent_id="HS-BAD", handoff_status="completed"),
    )
    assert bad_status.status_code == 422


def _seed_three_handoffs_with_stamped_times(client, isolate_settings) -> int:
    """Three handoffs whose creation order is the REVERSE of their checkpoint order.

    SORT-A is the oldest created and the most recently checkpointed — the shape
    the creation ordering cannot surface. SORT-C never checkpointed after its
    insert (a null `last_checkpoint_at`, which the schema allows), so it pins the
    creation-time fallback. Returns the engagement id the service layer takes.
    """
    _seed(client, isolate_settings)
    for agent_id in ("SORT-A", "SORT-B", "SORT-C"):
        _register_dispatch(client, agent_id=agent_id, agent_role="recon-specialist")
        posted = client.post(
            f"{BASE}/dispatch-handoffs",
            json=_full_payload(agent_id=agent_id, agent_role="recon-specialist"),
        )
        assert posted.status_code == 201, posted.text

    with sqlite3.connect(str(db_module.database_path())) as connection:
        for agent_id, created_at, last_checkpoint_at in (
            ("SORT-A", "2026-09-01T00:00:00Z", "2026-09-30T00:00:00Z"),
            ("SORT-B", "2026-09-02T00:00:00Z", "2026-09-02T00:00:00Z"),
            ("SORT-C", "2026-09-03T00:00:00Z", None),
        ):
            connection.execute(
                "UPDATE assessment_dispatch_handoffs "
                "SET created_at = ?, last_checkpoint_at = ? WHERE agent_id = ?",
                (created_at, last_checkpoint_at, agent_id),
            )
        return int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
            ).fetchone()[0]
        )


def test_handoff_list_sorts_by_checkpoint_only_when_asked(client, isolate_settings) -> None:
    """The opt-in `checkpoint` ordering ranks by the timestamp PATCH actually moves.

    `created_at` is immutable and `update_handoff` writes only
    `last_checkpoint_at`, so "which handoffs moved most recently" is unanswerable
    from the arrival order. The default stays the arrival order because every
    existing reader of this list — the API endpoint, the assess client,
    reconcile-stale — is written against it.
    """
    engagement_id = _seed_three_handoffs_with_stamped_times(client, isolate_settings)

    assert [row["agent_id"] for row in state_manager.list_handoffs(engagement_id)] == [
        "SORT-C",
        "SORT-B",
        "SORT-A",
    ]
    # SORT-C's null `last_checkpoint_at` falls back to its creation time rather
    # than sorting below every populated row.
    assert [
        row["agent_id"]
        for row in state_manager.list_handoffs(engagement_id, sort="checkpoint")
    ] == ["SORT-A", "SORT-C", "SORT-B"]


def test_handoff_list_applies_the_checkpoint_sort_before_the_limit(
    client, isolate_settings
) -> None:
    """Ordering inside the query, not over the returned page.

    A caller that limited first and re-sorted afterwards could never see SORT-A:
    it is the oldest row created, so the creation ordering cuts it before the
    caller gets to look at `last_checkpoint_at` at all.
    """
    engagement_id = _seed_three_handoffs_with_stamped_times(client, isolate_settings)

    assert [
        row["agent_id"]
        for row in state_manager.list_handoffs(engagement_id, sort="checkpoint", limit=1)
    ] == ["SORT-A"]
    assert [
        row["agent_id"] for row in state_manager.list_handoffs(engagement_id, limit=1)
    ] == ["SORT-C"]


def test_handoff_list_rejects_an_unknown_sort(client, isolate_settings) -> None:
    """An unrecognised ordering is refused, not silently served as the default —
    a quiet fallback would hand the caller creation order under a name promising
    checkpoint order, which is the exact defect this argument exists to fix."""
    engagement_id = _seed_three_handoffs_with_stamped_times(client, isolate_settings)

    with pytest.raises(HTTPException) as exc_info:
        state_manager.list_handoffs(engagement_id, sort="last_checkpoint_at")
    assert exc_info.value.status_code == 400
    assert "invalid handoff sort" in str(exc_info.value.detail)


def test_handoff_conditional_update_preserves_a_newer_final_return(client, isolate_settings):
    _seed(client, isolate_settings)
    _register_dispatch(client, agent_id='HF-001', agent_role='vulnerability-analyst')
    created = client.post(f'{BASE}/dispatch-handoffs', json=_full_payload(handoff_status='checkpointed')).json()
    finished = client.patch(f'{BASE}/dispatch-handoffs/HF-001', json={
        'summary': 'Acme final evidence', 'handoff_status': 'ready',
        'expected_handoff_version': created['handoff_version'],
    })
    assert finished.status_code == 200, finished.text
    recovery = client.patch(f'{BASE}/dispatch-handoffs/HF-001', json={
        'handoff_status': 'blocked', 'closed_dispatch_status': 'failed',
        'expected_handoff_version': created['handoff_version'],
    })
    assert recovery.status_code == 409, recovery.text
    stored = client.get(f'{BASE}/dispatch-handoffs/HF-001').json()
    assert stored['handoff_status'] == 'ready'
    assert stored['summary'] == 'Acme final evidence'
    assert stored['handoff_version'] == finished.json()['handoff_version']
