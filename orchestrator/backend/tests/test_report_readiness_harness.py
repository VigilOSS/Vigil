"""Harness-doctrine tests for report_readiness softening (Wave 2).

These exercise the harness pivot recorded in ``docs/adr/0001`` / ``docs/plans/
harness-master-plan.md`` §0: administrative-hygiene checks at the report
boundary are softened from HARD blockers to ADVISORIES (``ready`` does not flip
to False on them alone), while a real finding parked in ``draft`` is surfaced
loudly as an advisory requiring disposition (S21 — never silent-drop). A
genuine quality blocker (unverified high finding) MUST still block, proving we
did not over-soften.

Covered:
  - L1-1: an unlinked markdown note → advisory, ``ready`` stays True.
  - L1-8: a stale ready handoff on an in-progress dispatch → advisory, not blocking.
  - S21 : a draft finding → ``draft_finding_needs_disposition`` advisory listing
          its slug; it is not silently hidden.
  - over-soften guard: an unverified high finding STILL hard-blocks.
"""
from __future__ import annotations

import json
from pathlib import Path


ENGAGEMENT_KEY = "2026-05-20-090000-harness"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _write_engagement(engagements_dir: Path) -> Path:
    eng = engagements_dir / ENGAGEMENT_KEY
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "engagement.json").write_text(
        json.dumps(
            {
                "key": ENGAGEMENT_KEY,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-05-20T09:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (eng / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "hosts": ["example.com"],
                "status": "in_progress",
                "current_phase": "consume-test",
            }
        ),
        encoding="utf-8",
    )
    return eng


def _reportable_finding(client, eng: Path, slug: str = "HR-001", **overrides) -> None:
    """Seed a fully-reportable finding (verified/confirmed, evidence linked)."""
    (eng / "notes").mkdir(parents=True, exist_ok=True)
    (eng / "notes" / f"{slug}-note.md").write_text(f"{slug} evidence", encoding="utf-8")
    payload = {
        "slug": slug,
        "title": "Reportable finding",
        "severity": "high",
        "workflow_status": "active",
        "verification_state": "verified",
        "verification_disposition": "confirmed",
        "canonical_location": f"https://example.com/{slug}",
        "summary": "A fully reportable finding.",
        "evidence_ref": f"notes/{slug}-note.md",
        "source_name": "vulnerability-analyst",
        "details": {
            "cvss_score": 8.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "steps_to_reproduce": ["step one", "step two"],
            "remediation": "Fix it",
            "impact": "High impact",
            "evidence": "Captured request in linked artifact",
        },
    }
    payload.update(overrides)
    response = client.post(f"{BASE}/findings", json=payload)
    assert response.status_code == 201, response.text


def _readiness(client) -> dict:
    response = client.get(f"{BASE}/report-readiness")
    assert response.status_code == 200, response.text
    return response.json()


def test_return_shape_backward_compatible(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(client, eng)

    body = _readiness(client)
    assert set(["ready", "blocker_count", "blockers", "coverage"]).issubset(body.keys())
    assert isinstance(body["advisories"], list)
    assert body["advisory_count"] == len(body["advisories"])
    assert body["ready"] is True, body


def test_l1_1_unlinked_markdown_note_is_advisory_not_blocking(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(client, eng)

    (eng / "notes" / "loose.md").write_text("durable, not linked anywhere", encoding="utf-8")
    register = client.post(f"{BASE}/artifacts", json={"path": "notes/loose.md", "kind": "note"})
    assert register.status_code == 201, register.text

    body = _readiness(client)
    assert not any(b["kind"] == "unlinked_markdown_note" for b in body["blockers"]), body
    advisory = next(
        a for a in body["advisories"]
        if a["kind"] == "unlinked_markdown_note" and a["path"] == "notes/loose.md"
    )
    assert "mark-scratch" in advisory["detail"]
    assert body["ready"] is True, body


def test_l1_8_stale_ready_handoff_is_advisory_not_blocking(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(client, eng)

    dispatch = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "HF-009",
            "agent_role": "vulnerability-analyst",
            "task": "stale handoff test",
            "skills": "auth-bypass",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    handoff = client.post(
        f"{BASE}/dispatch-handoffs",
        json={
            "agent_id": "HF-009",
            "agent_role": "vulnerability-analyst",
            "phase": "consume-test",
            "summary": "Ready for promotion but dispatch left in-progress.",
            "handoff_status": "ready",
        },
    )
    assert handoff.status_code == 201, handoff.text

    body = _readiness(client)
    assert not any(b["kind"] == "stale_dispatch_ready_handoff" for b in body["blockers"]), body
    advisory = next(
        a for a in body["advisories"]
        if a["kind"] == "stale_dispatch_ready_handoff" and a["agent_id"] == "HF-009"
    )
    assert "reconcile-stale" in advisory["detail"]
    assert body["ready"] is True, body


def test_s21_draft_finding_surfaced_as_advisory_with_slug(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(client, eng, slug="HR-002", workflow_status="draft")

    body = _readiness(client)
    advisory = next(
        a for a in body["advisories"]
        if a["kind"] == "draft_finding_needs_disposition" and a["slug"] == "HR-002"
    )
    assert "update-finding HR-002 --workflow-status active" in advisory["detail"]
    assert "kill-finding HR-002" in advisory["detail"]
    assert any(a["slug"] == "HR-002" for a in body["advisories"]), body


def test_over_soften_guard_unverified_high_finding_still_blocks(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(
        client,
        eng,
        slug="HR-003",
        verification_state="unreviewed",
        verification_disposition="none",
    )

    body = _readiness(client)
    assert body["ready"] is False, body
    assert any(
        b["kind"] == "finding_verification_state" and b["slug"] == "HR-003"
        for b in body["blockers"]
    ), body
