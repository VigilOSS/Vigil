"""Tests for the assessment_jobs lifecycle API.

Backed by the new `assessment_jobs` table introduced in the Wave-1 cutover.
The endpoints under test live in `app/api/assessment.py` and the service
helpers in `app/services/state_manager.py`.
"""
from __future__ import annotations

import json
from pathlib import Path

ENGAGEMENT_KEY = "2026-04-17-130000-jobs"


def _write_engagement(engagements_dir: Path, key: str = ENGAGEMENT_KEY) -> Path:
    engagement_dir = engagements_dir / key
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": key,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-04-17T13:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "scope_mode": "host_only",
                "scope_hosts": ["example.com"],
                "scope": ["example.com"],
                "status": "in_progress",
                "current_phase": "recon",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "log.md").write_text("# Engagement Log\n", encoding="utf-8")
    return engagement_dir


def _base_command_run_payload(**overrides):
    payload = {
        "command": "nuclei -l targets.txt",
        "argv": ["nuclei", "-l", "targets.txt"],
        "tool_name": "nuclei",
        "route": "/api/tools/nuclei",
        "agent_name": "recon-specialist",
        "phase": "recon",
        "started_at": "2026-04-17T13:00:00Z",
        "completed_at": "2026-04-17T13:00:01Z",
        "duration_ms": 1000,
        "status": "running",
    }
    payload.update(overrides)
    return payload


def _post_command_run(client, **kwargs):
    payload = _base_command_run_payload(**kwargs)
    return client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/command-runs",
        json=payload,
    )


def test_create_job_minimal_payload(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs",
        json={"status": "queued"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "queued"
    assert body["id"] >= 1
    assert body["parent_command_run_id"] is None
    assert body["audit_metadata"] is None


def test_create_job_links_to_command_run(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    parent = _post_command_run(client).json()
    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs",
        json={
            "parent_command_run_id": parent["id"],
            "status": "running",
            "dtach_socket_path": "/tmp/jobs/abc.sock",
            "stdout_path": "/engagements/example/scans/kali/job-abc.out",
            "stderr_path": "/engagements/example/scans/kali/job-abc.err",
            "audit_metadata": {
                "technique": "RECON",
                "intent": "long-running nuclei sweep",
                "probe_kind": "fingerprint",
                "destructive": False,
                "phase": "recon",
                "agent_name": "recon-specialist",
            },
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["parent_command_run_id"] == parent["id"]
    assert body["status"] == "running"
    assert body["dtach_socket_path"] == "/tmp/jobs/abc.sock"
    assert body["audit_metadata"]["technique"] == "RECON"


def test_create_job_rejects_unknown_parent(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs",
        json={"parent_command_run_id": 9999, "status": "queued"},
    )
    assert response.status_code == 400


def test_get_job_by_id(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs",
        json={"status": "queued"},
    ).json()
    response = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs/{created['id']}"
    )
    assert response.status_code == 200
    assert response.json()["id"] == created["id"]


def test_get_job_404_for_unknown(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    response = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs/9999"
    )
    assert response.status_code == 404


def test_list_jobs_filters_by_status(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs", json={"status": "queued"}
    )
    client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs", json={"status": "running"}
    )
    client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs", json={"status": "completed"}
    )
    all_rows = client.get(f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs").json()
    assert len(all_rows) == 3
    queued = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs?status=queued"
    ).json()
    assert len(queued) == 1
    assert queued[0]["status"] == "queued"
    running = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs?status=running"
    ).json()
    assert len(running) == 1
    assert running[0]["status"] == "running"


def test_list_jobs_filters_by_parent_command_run(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    parent = _post_command_run(client).json()
    client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs",
        json={"parent_command_run_id": parent["id"], "status": "queued"},
    )
    client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs",
        json={"status": "queued"},
    )
    rows = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs?parent_command_run_id={parent['id']}"
    ).json()
    assert len(rows) == 1
    assert rows[0]["parent_command_run_id"] == parent["id"]


def test_patch_job_updates_terminal_status(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs",
        json={"status": "running"},
    ).json()
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs/{created['id']}",
        json={
            "status": "completed",
            "ended_at": "2026-04-17T13:30:00Z",
            "exit_code": 0,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["exit_code"] == 0


def test_patch_job_404_for_unknown(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    response = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs/9999",
        json={"status": "completed", "exit_code": 0},
    )
    assert response.status_code == 404


def test_patch_job_broadcasts_via_websocket(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"])
    created = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs",
        json={"status": "running"},
    ).json()
    with client.websocket_connect(f"/ws/engagements/{ENGAGEMENT_KEY}") as websocket:
        response = client.patch(
            f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs/{created['id']}",
            json={"status": "completed", "exit_code": 0},
        )
        assert response.status_code == 200
        message = websocket.receive_json()
        assert message["type"] == "assessment.updated"
        assert message["record_type"] == "job"
        assert message["payload"]["id"] == created["id"]
        assert message["payload"]["status"] == "completed"


def test_parent_command_run_cascade_set_null(client, isolate_settings):
    """Deleting the parent command-run should NULL out the FK on the job row,
    not cascade-delete the job. The schema uses ON DELETE SET NULL."""
    _write_engagement(isolate_settings["engagements_dir"])
    parent = _post_command_run(client).json()
    job = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs",
        json={"parent_command_run_id": parent["id"], "status": "running"},
    ).json()
    # Delete the parent row directly. Use the underlying connection.
    from app.db import get_connection

    with get_connection() as connection:
        # Foreign key cascade rules require PRAGMA foreign_keys = ON.
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "DELETE FROM assessment_command_runs WHERE id = ?", (parent["id"],)
        )
        connection.commit()

    response = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/jobs/{job['id']}"
    )
    assert response.status_code == 200
    assert response.json()["parent_command_run_id"] is None
