"""Pinned reads that the coverage views share with one another.

`code_coverage_summary` and `code_coverage_cwe_detail` both measure per-file
review effort from the same row set: the file's current, unreplaced analysis
receipts. The CWE matrix exposes those counts directly (and is asserted
exactly elsewhere); the summary only ever exposes them as the boolean behind
`gate.coverage_integrity`, which is why that arm is recorded here. A reader
that counted zero receipts for a reviewed file would report an integrity
warning on it, so an empty list is a real assertion about the count.

The queue listing and the open-lease view likewise project the same lease
activity for one claimed item; both projections are recorded together so the
two cannot drift apart.
"""
from __future__ import annotations

from app import db as db_module

from tests.test_code_analysis_api import (
    _claim_file_for_analysis,
    _classify_file,
    _create_files,
    _create_repo,
    _network_input_coverage,
    _owned,
    _publish_structural_callables,
    _record_fixture_source_receipt,
    _structural_callable,
    write_engagement,
)

_EFFORT_ABOVE_EVERY_THRESHOLD = 80


def _seed_reviewed_critical_file(client, isolate_settings, engagement_key):
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    repo = _create_repo(client, engagement_key, repo_key=f"{engagement_key}-repo")
    files = _create_files(client, engagement_key, int(repo["id"]))
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    _publish_structural_callables(
        client,
        engagement_key,
        int(repo["id"]),
        files,
        {int(parser["id"]): [_structural_callable("parse", start_line=1, end_line=2)]},
    )
    _classify_file(client, engagement_key, int(parser["id"]), "critical", 90)
    return repo, parser


def test_coverage_summary_sees_the_current_receipt_behind_a_reviewed_file(
    client, isolate_settings
) -> None:
    engagement_key = "2026-11-09-s15-receipt-effort"
    repo, parser = _seed_reviewed_critical_file(client, isolate_settings, engagement_key)
    claim = _claim_file_for_analysis(
        client, engagement_key, int(parser["id"]), priority=90
    )
    _record_fixture_source_receipt(client, engagement_key, claim)
    done = client.post(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="Reviewed.",
            cwe_coverage=_network_input_coverage(
                default_effort=_EFFORT_ABOVE_EVERY_THRESHOLD
            ),
        ),
    )
    assert done.status_code == 200, done.text

    summary = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage?repo_id={repo['id']}"
    )
    assert summary.status_code == 200, summary.text
    gate = summary.json()["gate"]
    # One current receipt is on the file, so the integrity harness has nothing
    # to report. This fires the moment the per-file receipt count reads zero.
    assert gate["coverage_integrity"] == []
    assert summary.json()["by_classification"]["critical"] == {
        "count": 1,
        "analyzed": 1,
    }

    detail = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage"
        f"?detail=cwe&repo_id={repo['id']}"
    )
    assert detail.status_code == 200, detail.text
    parser_detail = next(
        row for row in detail.json()["files"] if row["file_id"] == parser["id"]
    )
    assert parser_detail["analysis_effort"] == {
        "current_receipt_rows": 1,
        "evidenced_receipt_rows": 1,
        "distinct_structural_callables_reviewed": 1,
        "total_functions": 1,
        "callable_coverage_pct": 100.0,
    }
    merged = {
        str(entry["family"]): entry for entry in parser_detail["cwe_coverage"]
    }
    assert merged["web-app-injection"]["effort"] == _EFFORT_ABOVE_EVERY_THRESHOLD


def test_queue_listing_and_open_leases_project_the_same_lease_activity(
    client, isolate_settings
) -> None:
    engagement_key = "2026-11-09-s15-lease-projection"
    _repo, parser = _seed_reviewed_critical_file(client, isolate_settings, engagement_key)
    claim = _claim_file_for_analysis(
        client,
        engagement_key,
        int(parser["id"]),
        priority=90,
        agent_name="code-vuln-hunter",
    )

    listing = client.get(
        f"/engagements/{engagement_key}/assessment/code/analysis-queue"
        f"?item_id={claim['id']}"
    )
    assert listing.status_code == 200, listing.text
    listed = next(row for row in listing.json()["items"] if row["id"] == claim["id"])

    coverage = client.get(
        f"/engagements/{engagement_key}/assessment/code/coverage"
    )
    assert coverage.status_code == 200, coverage.text
    open_leases = coverage.json()["open_leases"]
    leased = next(
        row for row in open_leases if row["queue_item_id"] == claim["id"]
    )

    shared_keys = (
        "queue_mode",
        "batch_theme",
        "agent_name",
        "lease_token",
        "consumed_at",
        "last_heartbeat_at",
        "lease_activity_at",
        "heartbeat_age_seconds",
        "current_result_count",
        "adopted_leases",
    )
    assert {key: listed[key] for key in shared_keys} == {
        key: leased[key] for key in shared_keys
    }
    assert listed["agent_name"] == "code-vuln-hunter"
    assert listed["lease_token"] == claim["lease_token"]
    assert listed["current_result_count"] == 0
    assert listed["adopted_leases"] == []
    assert listed["heartbeat_age_seconds"] is not None


def test_releasing_a_lease_returns_the_row_to_the_current_file_priority(
    client, isolate_settings
) -> None:
    """`release` hands the row back to the unleased pending rotation.

    Ownership, the adoption chain and the claim timestamps are cleared, and the
    row re-reads the file's current `analysis_priority` rather than keeping the
    one it was claimed under. Recorded here because the same SET clause is what
    `reset-stale`, `retry-error` and `retry-needs-context` apply.
    """
    engagement_key = "2026-11-09-s15-release-priority"
    _repo, parser = _seed_reviewed_critical_file(client, isolate_settings, engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    claim = _claim_file_for_analysis(
        client, engagement_key, int(parser["id"]), priority=90
    )
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE code_files SET analysis_priority = ? WHERE id = ?",
            (95, int(parser["id"])),
        )

    released = client.post(
        f"{base}/analysis-queue/release",
        json={
            "item_id": claim["id"],
            "agent_name": claim["agent_name"],
            "lease_token": claim["lease_token"],
            "reason": "handing the file back",
        },
    )
    assert released.status_code == 200, released.text

    with db_module.get_connection() as connection:
        row = connection.execute(
            """
            SELECT status, assigned_agent, lease_token, adopted_leases_json,
                   consumed_at, last_heartbeat_at, priority
            FROM code_analysis_queue WHERE id = ?
            """,
            (claim["id"],),
        ).fetchone()
    assert tuple(row) == ("pending", "", "", "[]", None, None, 95)


def _file_ids(client, engagement_key: str, query: str) -> list[int]:
    response = client.get(
        f"/engagements/{engagement_key}/assessment/code/files?{query}"
    )
    assert response.status_code == 200, response.text
    return [int(row["id"]) for row in response.json()["items"]]


def test_code_file_listing_filters_select_by_each_optional_predicate(
    client, isolate_settings
) -> None:
    """Each optional `GET /files` filter narrows the page on its own column.

    These queries bind positionally, so a predicate that lands out of step with
    its parameter silently answers a different question. One assertion per
    filter, plus the pair, records which rows each one admits.
    """
    engagement_key = "2026-11-09-s15-file-filters"
    repo, parser = _seed_reviewed_critical_file(client, isolate_settings, engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    helper = next(
        row
        for row in client.get(f"{base}/files?limit=1000").json()["items"]
        if row["file_path"] == "src/helpers.py"
    )
    _classify_file(client, engagement_key, int(helper["id"]), "low", 10)
    modules = client.post(
        f"{base}/modules",
        json={
            "repo_id": repo["id"],
            "modules": [{"module_key": "src", "name": "src"}],
        },
    )
    assert modules.status_code == 201, modules.text
    module_id = int(modules.json()[0]["id"])
    patched = client.patch(
        f"{base}/files/{parser['id']}", json={"module_id": module_id}
    )
    assert patched.status_code == 200, patched.text

    assert _file_ids(client, engagement_key, f"repo_id={repo['id']}&limit=1000") == sorted(
        [int(parser["id"]), int(helper["id"])],
        key=lambda fid: -(90 if fid == int(parser["id"]) else 10),
    )
    assert _file_ids(client, engagement_key, f"module_id={module_id}") == [
        int(parser["id"])
    ]
    assert _file_ids(client, engagement_key, "classification=low") == [
        int(helper["id"])
    ]
    assert _file_ids(client, engagement_key, "classification=critical") == [
        int(parser["id"])
    ]
    statuses = {
        int(row["id"]): str(row["analysis_status"])
        for row in client.get(f"{base}/files?limit=1000").json()["items"]
    }
    assert set(statuses.values()) == {"classified"}
    for analysis_status in sorted(set(statuses.values())):
        assert set(
            _file_ids(
                client, engagement_key, f"analysis_status={analysis_status}&limit=1000"
            )
        ) == {
            file_id
            for file_id, value in statuses.items()
            if value == analysis_status
        }
    assert (
        _file_ids(client, engagement_key, f"module_id={module_id}&classification=low")
        == []
    )


def test_analysis_result_listing_filters_select_by_each_optional_predicate(
    client, isolate_settings
) -> None:
    """Each optional `GET /analysis-results` filter narrows on its own column."""
    engagement_key = "2026-11-09-s15-result-filters"
    _repo, parser = _seed_reviewed_critical_file(client, isolate_settings, engagement_key)
    base = f"/engagements/{engagement_key}/assessment/code"
    claim = _claim_file_for_analysis(
        client, engagement_key, int(parser["id"]), priority=90
    )
    receipt = _record_fixture_source_receipt(client, engagement_key, claim)

    def result_ids(query: str) -> list[int]:
        response = client.get(f"{base}/analysis-results?{query}")
        assert response.status_code == 200, response.text
        return [int(row["id"]) for row in response.json()]

    assert result_ids(f"file_id={parser['id']}") == [int(receipt["id"])]
    assert result_ids(f"queue_item_id={claim['id']}") == [int(receipt["id"])]
    assert result_ids(f"lease_token={claim['lease_token']}") == [int(receipt["id"])]
    assert result_ids(f"disposition={receipt['disposition']}") == [int(receipt["id"])]
    assert result_ids("disposition=finding") == []
    assert result_ids(f"file_id={parser['id']}&queue_item_id={claim['id']}") == [
        int(receipt["id"])
    ]
    assert result_ids("file_id=999999") == []
    assert result_ids("function_name=no-such-function") == []
