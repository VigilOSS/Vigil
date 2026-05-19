from __future__ import annotations

import json
from pathlib import Path

from app.services.assessment_memory import _recommended_actions


ENGAGEMENT_KEY = "2026-05-19-120000-memory"
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
                "created_at": "2026-05-19T12:00:00Z",
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


def _seed_finding(client, eng: Path, slug: str = "VA-047") -> None:
    (eng / "notes").mkdir(parents=True, exist_ok=True)
    (eng / "notes" / "VA-047-note.md").write_text(
        "VA-047 exploit chronology and OIDC static state notes",
        encoding="utf-8",
    )
    response = client.post(
        f"{BASE}/findings",
        json={
            "slug": slug,
            "title": "OIDC static state replay",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "canonical_location": "https://example.com/login",
            "summary": "Static state can be replayed",
            "evidence_ref": "notes/VA-047-note.md",
            "source_name": "vulnerability-analyst",
            "details": {
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "steps_to_reproduce": ["capture state", "replay state"],
                "remediation": "Bind state to a nonce",
                "impact": "Account takeover path",
                "evidence": "Captured request in linked artifact",
            },
        },
    )
    assert response.status_code == 201, response.text


def test_artifact_sync_search_get_and_missing_state(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)

    sync = client.post(f"{BASE}/artifacts/sync")
    assert sync.status_code == 200, sync.text
    assert sync.json()["present"] >= 1

    search = client.get(f"{BASE}/artifacts/search", params={"q": "VA047"})
    assert search.status_code == 200, search.text
    rows = search.json()
    assert any(row["relative_path"] == "notes/VA-047-note.md" for row in rows)

    artifact_id = next(row["id"] for row in rows if row["relative_path"] == "notes/VA-047-note.md")
    detail = client.get(f"{BASE}/artifacts/{artifact_id}")
    assert detail.status_code == 200, detail.text
    assert "OIDC static state" in detail.json()["content"]

    (eng / "notes" / "incidental-VA-047.md").write_text(
        "Incidental VA-047 mention that should not outrank the linked evidence artifact.",
        encoding="utf-8",
    )
    sync = client.post(f"{BASE}/artifacts/sync")
    assert sync.status_code == 200, sync.text
    by_finding = client.get(f"{BASE}/artifacts/search", params={"finding": "VA047"})
    assert by_finding.status_code == 200, by_finding.text
    assert by_finding.json()[0]["relative_path"] == "notes/VA-047-note.md"

    (eng / "notes" / "VA-047-note.md").unlink()
    sync = client.post(f"{BASE}/artifacts/sync")
    assert sync.status_code == 200, sync.text
    missing = client.get(f"{BASE}/artifacts/{artifact_id}")
    assert missing.status_code == 200, missing.text
    assert missing.json()["present"] is False


def test_resume_brief_returns_bounded_operating_picture(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)

    command = client.post(
        f"{BASE}/command-runs",
        json={
            "command": "curl https://example.com/login # VA-047",
            "argv": ["curl", "https://example.com/login"],
            "tool_name": "execute_command",
            "agent_name": "vulnerability-analyst",
            "phase": "consume-test",
            "return_code": 0,
            "timed_out": False,
            "success": True,
            "started_at": "2026-05-19T12:01:00Z",
            "completed_at": "2026-05-19T12:01:01Z",
            "duration_ms": 1000,
            "stdout": "large preview should not be included in resume brief",
            "stderr": "",
            "intent": "validate VA-047 OIDC state",
            "target_host": "example.com",
        },
    )
    assert command.status_code == 201, command.text
    dispatch = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "va-memory",
            "agent_role": "vulnerability-analyst",
            "task": "continue VA-047",
            "skills": "auth-bypass",
            "finding_slugs": ["VA-047"],
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    handoff = client.post(
        f"{BASE}/dispatch-handoffs",
        json={
            "agent_id": "va-memory",
            "agent_role": "vulnerability-analyst",
            "summary": "VA-047 ready for report",
            "finding_slugs": ["VA-047"],
            "handoff_status": "ready",
        },
    )
    assert handoff.status_code == 201, handoff.text

    brief = client.get(f"{BASE}/resume-brief", params={"finding": "VA047"})
    assert brief.status_code == 200, brief.text
    body = brief.json()
    assert body["target_finding"]["slug"] == "VA-047"
    assert body["command_runs"][0]["stdout_preview"] == ""
    assert any(row["relative_path"] == "notes/VA-047-note.md" for row in body["artifacts"])
    assert any("list-command-runs" in row["command"] for row in body["recommended_next_actions"])
    assert any(
        row["entity_kind"] == "command_run" and row["command"] == f"aith assess get-command-run {command.json()['id']}"
        for row in body["recommended_next_actions"]
    )
    artifact_id = next(row["id"] for row in body["artifacts"] if row["relative_path"] == "notes/VA-047-note.md")
    assert any(
        row["entity_kind"] == "artifact" and row["command"] == f"aith assess artifact get {artifact_id}"
        for row in body["recommended_next_actions"]
    )


def test_report_readiness_blocks_unlinked_markdown_notes(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    (eng / "notes" / "scratch.md").write_text("Durable state that is not linked anywhere", encoding="utf-8")

    sync = client.post(f"{BASE}/artifacts/sync")
    assert sync.status_code == 200, sync.text

    readiness = client.get(f"{BASE}/report-readiness")
    assert readiness.status_code == 200, readiness.text
    blockers = readiness.json()["blockers"]
    assert any(
        blocker["kind"] == "unlinked_markdown_note" and blocker["path"] == "notes/scratch.md"
        for blocker in blockers
    )


def test_mark_scratch_clears_unlinked_markdown_blocker(client, isolate_settings) -> None:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _seed_finding(client, eng)
    (eng / "notes" / "scratch.md").write_text("operator scratch", encoding="utf-8")
    sync = client.post(f"{BASE}/artifacts/sync")
    assert sync.status_code == 200, sync.text

    readiness_before = client.get(f"{BASE}/report-readiness")
    blockers_before = readiness_before.json()["blockers"]
    note_blocker = next(
        b for b in blockers_before
        if b["kind"] == "unlinked_markdown_note" and b["path"] == "notes/scratch.md"
    )
    # Blocker message must name the operator escape commands so a human or
    # LLM can fix without searching docs.
    assert "artifact register" in note_blocker["detail"]
    assert "mark-scratch" in note_blocker["detail"]

    flagged = client.post(
        f"{BASE}/artifacts/scratch-by-path",
        json={"path": "notes/scratch.md", "scratch": True},
    )
    assert flagged.status_code == 200, flagged.text
    assert flagged.json()["scratch"] is True

    readiness_after = client.get(f"{BASE}/report-readiness")
    assert readiness_after.status_code == 200, readiness_after.text
    blockers_after = readiness_after.json()["blockers"]
    assert not any(
        b["kind"] == "unlinked_markdown_note" and b["path"] == "notes/scratch.md"
        for b in blockers_after
    )


def test_recommended_actions_keep_lifecycle_items_before_inspect_cap() -> None:
    actions = _recommended_actions(
        finding="VA-047",
        agent_id="va-memory",
        artifacts=[{"id": 11}, {"id": 12}, {"id": 13}],
        command_matches=[{"id": 1}, {"id": 2}, {"id": 3}],
        stale_dispatches=[{"agent_id": "stale-va"}],
    )

    commands = [row["command"] for row in actions]
    assert len(actions) == 8
    assert "aith assess agent render-handoff va-memory" in commands
    assert "aith assess agent reconcile-stale --dry-run" in commands
