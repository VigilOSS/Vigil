"""A15a/A15b/A15d: strict trigger selectors, kept themes, exact accounting.

Requeue used to resolve one selector shape, silently skip the rest, default
every target to a `cross-file-trigger` lane that no natural fetch filter names,
and roll the whole batch back when a single target was blocked — while
reporting `total` in trigger inputs and every other bucket in targets.
"""
from __future__ import annotations

import pytest

from test_code_analysis_api import (
    _claim_file_for_analysis,
    _classify_file,
    _create_files,
    _create_repo,
    _network_input_coverage,
    _publish_structural_callables,
    _record_fixture_source_receipt,
    write_engagement,
)


def _seed(client, engagement_key: str, repo_key: str):
    repo = _create_repo(client, engagement_key, repo_key=repo_key)
    files = _create_files(client, engagement_key, int(repo["id"]))
    _publish_structural_callables(client, engagement_key, int(repo["id"]), files, {})
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    helper = next(row for row in files if row["file_path"] == "src/helpers.py")
    return repo, parser, helper


def _close_clean(client, engagement_key: str, queue_item: dict[str, object]) -> None:
    _record_fixture_source_receipt(client, engagement_key, queue_item)
    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json={
            "item_ids": [queue_item["id"]],
            "agent_name": queue_item["agent_name"],
            "lease_token": queue_item["lease_token"],
            "disposition": "clean",
            "notes": "Reviewed the fixture file end to end.",
            "cwe_coverage": _network_input_coverage(default_effort=80),
        },
    )
    assert done.status_code == 200, done.text


def test_requeue_preserves_the_original_batch_theme_and_trigger_provenance(
    client, isolate_settings
):
    engagement_key = "2026-09-15-code-requeue-theme"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, parser, helper = _seed(client, engagement_key, "requeue-theme-repo")
    _classify_file(client, engagement_key, int(helper["id"]), "high", 60)
    base = f"/engagements/{engagement_key}/assessment/code"
    queued = client.post(
        f"{base}/analysis-queue",
        json={
            "items": [
                {
                    "file_id": helper["id"],
                    "priority": 60,
                    "batch_theme": "shared-helpers",
                }
            ]
        },
    )
    assert queued.status_code == 201, queued.text

    requeued = client.post(
        f"{base}/analysis-queue/requeue",
        json={"items": [{"file_id": helper["id"], "reason": "helper carries taint"}]},
    )
    assert requeued.status_code == 201, requeued.text
    assert requeued.json()["already_queued"] == 1

    row = client.get(f"{base}/analysis-queue?queue_mode=trigger").json()["items"][0]
    assert row["batch_theme"] == "shared-helpers"
    assert row["queue_mode"] == "trigger"
    assert client.get(
        f"{base}/analysis-queue?batch_theme=shared-helpers"
    ).json()["total"] == 1

    explicit = client.post(
        f"{base}/analysis-queue/requeue",
        json={
            "items": [
                {
                    "file_id": helper["id"],
                    "batch_theme": "cross-file-trigger",
                    "reason": "operator chose a different lane",
                }
            ]
        },
    )
    assert explicit.status_code == 201, explicit.text
    retargeted = client.get(f"{base}/analysis-queue?queue_mode=trigger").json()["items"][0]
    assert retargeted["batch_theme"] == "cross-file-trigger"


def test_requeue_accepts_list_trigger_rows_and_rejects_selectorless_input(
    client, isolate_settings
):
    engagement_key = "2026-09-15-code-requeue-selectors"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, parser, helper = _seed(client, engagement_key, "requeue-selectors-repo")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(helper["id"]), "high", 60)
    base = f"/engagements/{engagement_key}/assessment/code"
    queue_item = _claim_file_for_analysis(
        client, engagement_key, int(parser["id"]), priority=100
    )
    result = client.post(
        f"{base}/analysis-results",
        json={
            "queue_item_id": queue_item["id"],
            "file_id": parser["id"],
            "agent_name": queue_item["agent_name"],
            "lease_token": queue_item["lease_token"],
            "reviewed_spans": [
                {"file_id": parser["id"], "start_line": 1, "end_line": 1}
            ],
            "hypothesis": "The helper may carry unvalidated bytes.",
            "evidence": "parse() delegates to the helper before validating.",
            "disposition": "clean",
            "confidence": "medium",
            "cross_file_triggers": [
                {
                    "file_path": "src/helpers.py",
                    "reason": "shared parser helper",
                    "vuln_class": "web-app-injection",
                }
            ],
        },
    )
    assert result.status_code == 201, result.text
    trigger = client.get(f"{base}/triggers").json()[0]

    # The trigger row is the selector: id + target_file_path, exactly as
    # `list-triggers` emits it.
    requeued = client.post(
        f"{base}/analysis-queue/requeue",
        json={"items": [{"trigger_id": trigger["id"]}]},
    )
    assert requeued.status_code == 201, requeued.text
    payload = requeued.json()
    assert payload["input_trigger_count"] == 1
    assert payload["target_count"] == 1
    assert payload["inserted"] == 1
    assert payload["inputs"] == [
        {
            "index": 0,
            "selector": {"trigger_id": trigger["id"]},
            "file_id": helper["id"],
            "outcome": "inserted",
        }
    ]
    queued_trigger = next(
        row for row in client.get(f"{base}/triggers").json() if row["id"] == trigger["id"]
    )
    assert queued_trigger["status"] == "queued"

    selectorless = client.post(
        f"{base}/analysis-queue/requeue", json={"items": [{"reason": "no selector"}]}
    )
    assert selectorless.status_code == 400
    assert "selector" in selectorless.json()["detail"].lower()

    scalar = client.post(f"{base}/analysis-queue/requeue", json={"items": [7]})
    assert scalar.status_code == 422


def test_one_blocked_target_does_not_reject_the_rest_of_the_batch(
    client, isolate_settings
):
    engagement_key = "2026-09-15-code-requeue-partial"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, parser, helper = _seed(client, engagement_key, "requeue-partial-repo")
    # `parser` stays unclassified: a state conflict the operator must fix, not a
    # reason to discard the helper's trigger context.
    _classify_file(client, engagement_key, int(helper["id"]), "high", 60)
    base = f"/engagements/{engagement_key}/assessment/code"

    response = client.post(
        f"{base}/analysis-queue/requeue",
        json={
            "items": [
                {"file_id": helper["id"], "reason": "first helper trigger"},
                {"file_id": helper["id"], "reason": "second helper trigger"},
                {"file_id": parser["id"], "reason": "unclassified target"},
                {"file_path": "src/nowhere.py", "reason": "missing target"},
            ]
        },
    )

    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["input_trigger_count"] == 4
    assert payload["target_count"] == 2
    assert payload["inserted"] == 1
    assert payload["already_queued"] == 0
    assert payload["already_completed"] == 0
    assert payload["blocked"] == 1
    assert (
        payload["inserted"]
        + payload["already_queued"]
        + payload["already_completed"]
        + payload["blocked"]
        == payload["target_count"]
    )
    assert payload["not_found"] == ["src/nowhere.py"]
    assert [entry["outcome"] for entry in payload["inputs"]] == [
        "inserted",
        "inserted",
        "blocked",
        "not_found",
    ]
    blocked = next(
        row for row in payload["outcomes"] if row["outcome"] == "blocked"
    )
    assert blocked["file_id"] == parser["id"]
    assert "classified" in blocked["detail"]
    assert payload["reopened_terminal_files"] == 0

    # The unblocked target committed, and both of its trigger inputs landed in
    # the one row.
    rows = client.get(f"{base}/analysis-queue?queue_mode=trigger").json()["items"]
    assert [row["file_id"] for row in rows] == [helper["id"]]
    assert len(rows[0]["cross_file_triggers"]) == 2


def test_blocked_reanalysis_target_is_reported_without_losing_committed_targets(
    client, isolate_settings
):
    engagement_key = "2026-09-15-code-requeue-reanalysis-block"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, parser, helper = _seed(client, engagement_key, "requeue-reanalysis-repo")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    _classify_file(client, engagement_key, int(helper["id"]), "high", 60)
    base = f"/engagements/{engagement_key}/assessment/code"
    queue_item = _claim_file_for_analysis(
        client, engagement_key, int(parser["id"]), priority=100
    )
    _close_clean(client, engagement_key, queue_item)
    reanalysis = client.post(
        f"{base}/analysis-queue",
        json={
            "mode": "reanalysis",
            "reason": "Second pass on the decoder.",
            "items": [
                {
                    "file_id": parser["id"],
                    "priority": 100,
                    "supersedes": queue_item["id"],
                }
            ],
        },
    )
    assert reanalysis.status_code == 201, reanalysis.text
    assert reanalysis.json()["reanalysis"] == 1

    response = client.post(
        f"{base}/analysis-queue/requeue",
        json={
            "items": [
                {"file_id": parser["id"], "reason": "trigger into the decoder"},
                {"file_id": helper["id"], "reason": "trigger into the helper"},
            ]
        },
    )

    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["target_count"] == 2
    assert payload["inserted"] == 1
    assert payload["blocked"] == 1
    blocked = next(row for row in payload["outcomes"] if row["outcome"] == "blocked")
    assert blocked["file_id"] == parser["id"]
    assert "reanalysis" in blocked["detail"]
    assert client.get(
        f"{base}/analysis-queue?queue_mode=trigger"
    ).json()["item_ids"]


def test_requeue_reports_reopened_terminal_files(client, isolate_settings):
    engagement_key = "2026-09-15-code-requeue-reopen"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, parser, helper = _seed(client, engagement_key, "requeue-reopen-repo")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    base = f"/engagements/{engagement_key}/assessment/code"
    queue_item = _claim_file_for_analysis(
        client, engagement_key, int(parser["id"]), priority=100
    )
    _close_clean(client, engagement_key, queue_item)

    response = client.post(
        f"{base}/analysis-queue/requeue",
        json={
            "items": [
                {
                    "file_id": parser["id"],
                    "reason": "new hypothesis after the clean close",
                    "guidance_hypotheses": ["Re-check the length guard."],
                }
            ]
        },
    )

    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["inserted"] == 1
    assert payload["reopened_terminal_files"] == 1


@pytest.mark.parametrize("selector", [{"file_id": 1, "trigger_id": 1}])
def test_requeue_rejects_conflicting_selectors(client, isolate_settings, selector):
    engagement_key = "2026-09-15-code-requeue-conflicting"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    _seed(client, engagement_key, "requeue-conflicting-repo")
    base = f"/engagements/{engagement_key}/assessment/code"

    response = client.post(f"{base}/analysis-queue/requeue", json={"items": [selector]})

    assert response.status_code == 400
    assert "one selector" in response.json()["detail"].lower()
