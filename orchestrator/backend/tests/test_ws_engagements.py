from __future__ import annotations

import json
from pathlib import Path


def test_websocket_receives_new_event_payload(client, isolate_settings):
    engagements_dir: Path = isolate_settings["engagements_dir"]
    key = "2026-03-30-121500-example"
    engagement_dir = engagements_dir / key
    engagement_dir.mkdir(parents=True, exist_ok=True)
    (engagements_dir / ".active").write_text(f"{key}\n", encoding="utf-8")
    (engagement_dir / "engagement.json").write_text(
        json.dumps({"key": key, "target": "https://example.com", "hostname": "example.com"}),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hostname": "example.com", "scope": ["example.com"], "current_phase": "recon"}),
        encoding="utf-8",
    )

    with client.websocket_connect(f"/ws/engagements/{key}") as websocket:
        response = client.post(
            f"/engagements/{key}/events",
            json={
                "event_type": "task.started",
                "phase": "recon",
                "task_name": "recon-specialist",
                "agent_name": "recon-specialist",
                "summary": "Recon task started",
            },
        )
        assert response.status_code == 201

        payload = websocket.receive_json()
        assert payload["type"] == "event.created"
        assert payload["engagement_key"] == key
        assert payload["event"]["summary"] == "Recon task started"
