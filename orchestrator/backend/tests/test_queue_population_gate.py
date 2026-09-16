"""A5: hunt readiness must require a current queue row for every admitted file.

Classification alone once satisfied the hunt gate, so an operator could enter
Phase 2 with a complete classification table and an empty durable queue — the
one state in which no hunter dispatch can ever be claimed and no file is ever
accounted for.
"""
from __future__ import annotations

from test_code_analysis_api import (
    _classify_file,
    _create_files,
    _create_repo,
    _publish_structural_callables,
    write_engagement,
)


def _threat_model(client, engagement_key: str, repo_id: int) -> None:
    base = f"/engagements/{engagement_key}/assessment/code"
    binding = client.get(f"{base}/repos/{repo_id}").json()
    response = client.post(
        f"{base}/threat-model",
        json={
            "repo_id": repo_id,
            "repo_generation": binding["active_generation"],
            "source_manifest_digest": binding["source_manifest_digest"],
            "threat_model": {"trust_boundaries": ["network"]},
        },
    )
    assert response.status_code == 200, response.text


def test_hunt_readiness_blocks_admitted_files_without_a_current_queue_row(
    client, isolate_settings
):
    engagement_key = "2026-09-15-code-hunt-queue-gate"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="hunt-queue-gate-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    _publish_structural_callables(client, engagement_key, int(repo["id"]), files, {})
    _threat_model(client, engagement_key, int(repo["id"]))
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(helper["id"]), "skip", 0)
    base = f"/engagements/{engagement_key}/assessment/code"

    classified = client.get(f"{base}/readiness?target_phase=hunt").json()
    unqueued = [
        blocker
        for blocker in classified["blockers"]
        if blocker["code"] == "admitted_files_unqueued"
    ]
    assert classified["transition_ready"] is False
    assert len(unqueued) == 1
    assert unqueued[0]["repo_id"] == repo["id"]
    assert "2 admitted file(s)" in unqueued[0]["message"]

    partial = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": parser["id"], "priority": 100}]},
    )
    assert partial.status_code == 201, partial.text

    half_queued = client.get(f"{base}/readiness?target_phase=hunt").json()
    still_blocked = [
        blocker
        for blocker in half_queued["blockers"]
        if blocker["code"] == "admitted_files_unqueued"
    ]
    assert half_queued["transition_ready"] is False
    assert len(still_blocked) == 1
    assert "1 admitted file(s)" in still_blocked[0]["message"]

    # A skip-tier file still owns a queue row: classification orders claims, it
    # never removes a file from the ledger.
    remaining = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": helper["id"], "priority": 0}]},
    )
    assert remaining.status_code == 201, remaining.text

    queued = client.get(f"{base}/readiness?target_phase=hunt").json()
    assert queued["transition_ready"] is True
    assert queued["blockers"] == []


def test_classify_map_readiness_ignores_queue_population(client, isolate_settings):
    engagement_key = "2026-09-15-code-classify-queue-gate"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key="classify-queue-gate-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    _publish_structural_callables(client, engagement_key, int(repo["id"]), files, {})
    base = f"/engagements/{engagement_key}/assessment/code"

    classify_map = client.get(f"{base}/readiness?target_phase=classify-map").json()

    assert classify_map["transition_ready"] is True
    assert classify_map["blockers"] == []
