"""A cross-file trigger names a file in the source repository's current snapshot.

A target the snapshot cannot hold (a binary, a dependency outside the checkout)
is declared with ``outside_snapshot: true`` and kept as a pending obligation; a
path that is simply wrong is refused while the hunter still holds the lease.
"""
from __future__ import annotations

import pytest

from test_code_analysis_api import (
    _claim_file_for_analysis,
    _classify_file,
    _create_files,
    _create_repo,
    _publish_structural_callables,
    write_engagement,
)


def _seed(client, engagement_key: str):
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    # Staging the files promotes the generation the triggers are checked against.
    repo = client.get(f"/engagements/{engagement_key}/assessment/code/repos/{repo['id']}").json()
    _publish_structural_callables(client, engagement_key, int(repo["id"]), files, {})
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 100)
    queue_item = _claim_file_for_analysis(client, engagement_key, int(parser["id"]), priority=100)
    return repo, parser, queue_item


def _result(queue_item, parser, triggers):
    return {
        "queue_item_id": queue_item["id"],
        "file_id": parser["id"],
        "agent_name": queue_item["agent_name"],
        "lease_token": queue_item["lease_token"],
        "reviewed_spans": [{"file_id": parser["id"], "start_line": 1, "end_line": int(parser["loc"])}],
        "hypothesis": "The helper may carry unvalidated bytes.",
        "evidence": "parse() delegates to the helper before validating.",
        "disposition": "clean",
        "cross_file_triggers": triggers,
    }


def test_a_trigger_to_a_path_absent_from_the_snapshot_is_refused_with_the_closest_path(
    client, isolate_settings
):
    engagement_key = "2026-11-04-trigger-missing-path"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo, parser, queue_item = _seed(client, engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"

    refused = client.post(
        f"{base}/analysis-results",
        json=_result(
            queue_item,
            parser,
            [{"file_path": "src/helper.py", "reason": "shared helper", "vuln_class": "web-app-injection"}],
        ),
    )

    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert "cross_file_triggers target" in detail
    assert f"'src/helper.py' is not a file in generation {repo['active_generation']}" in detail
    assert "closest admitted path: 'src/helpers.py'" in detail
    assert "outside_snapshot" in detail
    assert client.get(f"{base}/triggers").json() == []

    # The lease survives the refusal, so the corrected result lands on the same claim.
    corrected = client.post(
        f"{base}/analysis-results",
        json=_result(
            queue_item,
            parser,
            [{"file_path": "src/helpers.py", "reason": "shared helper", "vuln_class": "web-app-injection"}],
        ),
    )
    assert corrected.status_code == 201, corrected.text
    [trigger] = client.get(f"{base}/triggers").json()
    assert trigger["target_file_path"] == "src/helpers.py"
    assert trigger["target_file_id"] is not None


def test_a_trigger_declared_outside_the_snapshot_is_recorded_pending(client, isolate_settings):
    engagement_key = "2026-11-04-trigger-outside-snapshot"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    _repo, parser, queue_item = _seed(client, engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"

    accepted = client.post(
        f"{base}/analysis-results",
        json=_result(
            queue_item,
            parser,
            [
                {
                    "file_path": "bin/StorageService.dll",
                    "reason": "implementation not present in source snapshot",
                    "vuln_class": "web-app-injection",
                    "outside_snapshot": True,
                }
            ],
        ),
    )

    assert accepted.status_code == 201, accepted.text
    [trigger] = client.get(f"{base}/triggers?status=pending").json()
    assert trigger["target_file_path"] == "bin/StorageService.dll"
    assert trigger["target_file_id"] is None


def test_an_outside_snapshot_declaration_for_an_admitted_file_is_refused(
    client, isolate_settings
):
    engagement_key = "2026-11-04-trigger-outside-but-admitted"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    _repo, parser, queue_item = _seed(client, engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"

    refused = client.post(
        f"{base}/analysis-results",
        json=_result(
            queue_item,
            parser,
            [
                {
                    "file_path": "src/helpers.py",
                    "reason": "shared helper",
                    "vuln_class": "web-app-injection",
                    "outside_snapshot": True,
                }
            ],
        ),
    )

    assert refused.status_code == 400, refused.text
    assert "'src/helpers.py' is a file in generation" in refused.json()["detail"]


@pytest.mark.parametrize("spelling", ["./src/helpers.py", "/src/helpers.py", "././src/helpers.py"])
def test_a_rooted_or_dotted_spelling_names_the_same_snapshot_file(client, isolate_settings, spelling):
    """A target is matched by its repository path whatever prefix the hunter
    typed, so `outside_snapshot` cannot park an admitted file as external."""
    engagement_key = "2026-11-05-trigger-dotted-spelling"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    _repo, parser, queue_item = _seed(client, engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    trigger = {"file_path": spelling, "reason": "shared helper", "vuln_class": "web-app-injection"}

    refused = client.post(
        f"{base}/analysis-results",
        json=_result(queue_item, parser, [{**trigger, "outside_snapshot": True}]),
    )
    assert refused.status_code == 400, refused.text
    assert "'src/helpers.py' is a file in generation" in refused.json()["detail"]

    recorded = client.post(f"{base}/analysis-results", json=_result(queue_item, parser, [trigger]))
    assert recorded.status_code == 201, recorded.text
    triggers = client.get(f"{base}/triggers").json()
    assert [(row["target_file_path"], row["target_file_id"] is not None) for row in triggers] == [
        ("src/helpers.py", True)
    ]

    resolved = client.post(
        f"{base}/triggers/resolve",
        json={
            "items": [{"file_path": spelling, "vuln_class": "web-app-injection"}],
            "resolution_status": "not_applicable",
            "resolution_note": "The helper escapes its input before use.",
        },
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["resolved"] == 1


def test_outside_snapshot_must_be_a_boolean(client, isolate_settings):
    engagement_key = "2026-11-04-trigger-outside-type"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    _repo, parser, queue_item = _seed(client, engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"

    refused = client.post(
        f"{base}/analysis-results",
        json=_result(
            queue_item,
            parser,
            [
                {
                    "file_path": "bin/StorageService.dll",
                    "reason": "binary dependency",
                    "vuln_class": "web-app-injection",
                    "outside_snapshot": "yes",
                }
            ],
        ),
    )

    assert refused.status_code == 400, refused.text
    assert "outside_snapshot must be a boolean" in refused.json()["detail"]
