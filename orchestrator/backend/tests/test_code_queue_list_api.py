"""A6/A15b: a bounded, filterable read surface over the current analysis queue.

Initial queue outcomes cap at 200 rows, so after the insertion output scrolls
the explicit IDs `code-dispatch fetch --ids-file` needs were unrecoverable —
there was no queue listing route at all. `queue_mode` joins the same filter set
because requeued trigger rows already carry it and were otherwise unreachable.
"""
from __future__ import annotations

from test_code_analysis_api import (
    _classify_file,
    _create_files,
    _create_repo,
    _publish_structural_callables,
    write_engagement,
)


def _seed(client, engagement_key: str, repo_key: str):
    repo = _create_repo(client, engagement_key, repo_key=repo_key)
    files = _create_files(client, engagement_key, int(repo["id"]))
    _publish_structural_callables(client, engagement_key, int(repo["id"]), files, {})
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(helper["id"]), "low", 10)
    return repo, parser, helper


def test_queue_list_pages_stable_ids_and_filters_every_lane(client, isolate_settings):
    engagement_key = "2026-09-15-code-queue-list"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, parser, helper = _seed(client, engagement_key, "queue-list-repo")
    base = f"/engagements/{engagement_key}/assessment/code"
    created = client.post(
        f"{base}/analysis-queue",
        json={
            "items": [
                {
                    "file_id": parser["id"],
                    "priority": 100,
                    "batch_theme": "parser-core",
                    "slot_types": ["NETWORK-INPUT"],
                    "guidance_hypotheses": ["Trace request bytes into the decoder."],
                },
                {"file_id": helper["id"], "priority": 10, "batch_theme": "helpers"},
            ]
        },
    )
    assert created.status_code == 201, created.text
    queued_ids = sorted(
        int(outcome["queue_item_id"]) for outcome in created.json()["outcomes"]
    )

    listing = client.get(f"{base}/analysis-queue")
    assert listing.status_code == 200, listing.text
    payload = listing.json()
    assert payload["total"] == 2
    assert payload["offset"] == 0
    assert payload["count"] == 2
    assert payload["has_more"] is False
    assert sorted(payload["item_ids"]) == queued_ids
    # Highest priority first, exactly like the claim order fetch applies.
    first = payload["items"][0]
    assert first["file_path"] == "src/parser.py"
    assert first["priority"] == 100
    assert first["status"] == "pending"
    assert first["queue_mode"] == "initial"
    assert first["batch_theme"] == "parser-core"
    assert first["classification"] == "critical"
    assert first["repo_id"] == repo["id"]
    assert first["guidance_hypotheses"] == ["Trace request bytes into the decoder."]
    assert first["agent_name"] == ""
    assert first["lease_token"] == ""
    assert first["last_heartbeat_at"] is None

    page = client.get(f"{base}/analysis-queue?limit=1").json()
    assert page["count"] == 1
    assert page["has_more"] is True
    assert page["item_ids"] == [payload["items"][0]["id"]]
    tail = client.get(f"{base}/analysis-queue?limit=1&offset=1").json()
    assert tail["has_more"] is False
    assert tail["item_ids"] == [payload["items"][1]["id"]]

    assert client.get(
        f"{base}/analysis-queue?classification=critical"
    ).json()["item_ids"] == [payload["items"][0]["id"]]
    assert client.get(
        f"{base}/analysis-queue?batch_theme=helpers"
    ).json()["item_ids"] == [payload["items"][1]["id"]]
    assert client.get(f"{base}/analysis-queue?status=processing").json() == {
        "total": 0,
        "offset": 0,
        "count": 0,
        "has_more": False,
        "item_ids": [],
        "items": [],
    }
    assert client.get(
        f"{base}/analysis-queue?repo_id={repo['id']}"
    ).json()["total"] == 2
    assert client.get(
        f"{base}/analysis-queue?queue_mode=initial"
    ).json()["total"] == 2
    assert client.get(f"{base}/analysis-queue?queue_mode=trigger").json()["total"] == 0

    claimed = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 1, "agent_name": "hunter-a", "classification": "critical"},
    )
    assert claimed.status_code == 200, claimed.text
    leased = claimed.json()[0]
    processing = client.get(f"{base}/analysis-queue?status=processing").json()
    assert processing["item_ids"] == [leased["id"]]
    assert processing["items"][0]["agent_name"] == "hunter-a"
    assert processing["items"][0]["lease_token"] == leased["lease_token"]
    assert processing["items"][0]["last_heartbeat_at"]


def test_queue_list_and_fetch_filter_requeued_trigger_rows_by_queue_mode(
    client, isolate_settings
):
    engagement_key = "2026-09-15-code-queue-list-trigger"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, parser, helper = _seed(client, engagement_key, "queue-list-trigger-repo")
    base = f"/engagements/{engagement_key}/assessment/code"
    requeued = client.post(
        f"{base}/analysis-queue/requeue",
        json={"items": [{"file_id": helper["id"], "reason": "shared helper"}]},
    )
    assert requeued.status_code == 201, requeued.text

    trigger_rows = client.get(f"{base}/analysis-queue?queue_mode=trigger").json()
    assert trigger_rows["total"] == 1
    assert trigger_rows["items"][0]["file_path"] == "src/helpers.py"
    assert trigger_rows["items"][0]["queue_mode"] == "trigger"

    claimed = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 5, "agent_name": "trigger-hunter", "queue_mode": "trigger"},
    )
    assert claimed.status_code == 200, claimed.text
    assert [row["file"]["file_path"] for row in claimed.json()] == ["src/helpers.py"]
    assert [row["id"] for row in claimed.json()] == trigger_rows["item_ids"]


def test_queue_list_rejects_unknown_filter_values(client, isolate_settings):
    engagement_key = "2026-09-15-code-queue-list-invalid"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    _seed(client, engagement_key, "queue-list-invalid-repo")
    base = f"/engagements/{engagement_key}/assessment/code"

    assert client.get(f"{base}/analysis-queue?status=nonsense").status_code == 422
    assert client.get(f"{base}/analysis-queue?queue_mode=nonsense").status_code == 422
    assert client.get(f"{base}/analysis-queue?classification=nope").status_code == 422
    assert client.get(f"{base}/analysis-queue?limit=0").status_code == 422


def test_the_api_queue_vocabularies_match_the_service_sets() -> None:
    """One vocabulary, two declarations — this is what keeps them one.

    `CODE-MAP.md`'s "Single sources of truth" rule is that every mirror of a
    constant carries a test that fails when the copies drift. The API `Literal`s
    are what actually reject a bad filter (Pydantic answers 422 before the
    service's own 400 is reachable), so a value added to one side and not the
    other is either an unreachable branch or a silently rejected filter.
    """
    from typing import get_args

    from app.api.code_analysis import CodeClassification, CodeQueueMode, CodeQueueStatus
    from app.services.code_analysis import (
        _QUEUE_MODES,
        _QUEUE_STATUSES,
        _VALID_CLASSIFICATIONS,
    )

    assert set(get_args(CodeQueueStatus)) == set(_QUEUE_STATUSES)
    assert set(get_args(CodeQueueMode)) == set(_QUEUE_MODES)
    assert set(get_args(CodeClassification)) == set(_VALID_CLASSIFICATIONS)
