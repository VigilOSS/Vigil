"""Every coverage view reads `<top-level>` file scope the same way.

The structural index publishes PHP file scope as `<top-level>` callables, and
the coverage views read them through separate projections: the summary gate
(`structural_review_gaps`), the function-coverage numerators
(`function_callable_link_sql`), the per-directory breakdown and readiness
(`_current_analysis_status_sql`, `_structural_debt_sql`), path-scoped queue
listing and claims (`_file_path_scope_sql`) and the families a path suggests
(`_path_suggested_families_for_file`). One repository with a mixed PHP file, a
script that is all file scope, a declarations-only file and an `.inc` fragment
runs through all of them, so the views are pinned to each other rather than
each to its own fixture.
"""
from __future__ import annotations

import sqlite3

from app import db as db_module

from tests.test_code_analysis_api import (
    _append_repo_files,
    _claim_file_for_analysis,
    _create_files,
    _create_repo,
    _network_input_coverage,
    _owned,
    _post_structural_callables,
    _source_hash,
    write_engagement,
)
from tests.test_code_coverage_uncovered_gate import _complete, _uncovered_paths

from assess.lib.code_structural_metadata import validated_callable_records
from assess.lib.treesitter_index import index_file

from app.services.code_analysis_support import TOP_LEVEL_CALLABLE_NAME

MIXED_PATH = "public/report.php"
SCRIPT_PATH = "public/export.php"
DECLARATIONS_PATH = "lib/contracts.php"
FRAGMENT_PATH = "payments/checkout.inc"
SOURCES = {
    MIXED_PATH: b"""<?php
require_once __DIR__ . '/bootstrap.php';
$id = $_GET['id'];

function acme_render($id)
{
    return htmlspecialchars($id);
}

echo acme_render($id);
""",
    SCRIPT_PATH: b"""<?php
$id = $_GET['id'];
$db = new mysqli('db.example.com', 'acme', 'secret', 'acme');
$rows = $db->query("SELECT * FROM exports WHERE id = " . $id);
echo json_encode($rows);
""",
    DECLARATIONS_PATH: b"""<?php
namespace Acme\\Lib;

use Acme\\Db\\Connection;

const EXPORT_LIMIT = 100;
""",
    FRAGMENT_PATH: b"""<?php
function acme_charge($amount)
{
    return $amount;
}

$total = acme_charge($_POST['amount']);
""",
}
TIERS = {
    MIXED_PATH: ("critical", 95),
    SCRIPT_PATH: ("high", 75),
    DECLARATIONS_PATH: ("high", 65),
    FRAGMENT_PATH: ("critical", 90),
}


def _seed(client, isolate_settings, key: str):
    write_engagement(isolate_settings["engagements_dir"], key)
    base = f"/engagements/{key}/assessment/code"
    repo_id = int(_create_repo(client, key, repo_key=f"{key}-app")["id"])
    _create_files(client, key, repo_id)
    files = _append_repo_files(
        client,
        key,
        repo_id,
        [
            {
                "file_path": path,
                "language": "php",
                "loc": len(source.splitlines()),
                "file_hash": _source_hash(path),
                "header_snippet": "<?php\n",
                "git_churn_score": 1,
                "has_past_cve_fix": False,
            }
            for path, source in SOURCES.items()
        ],
    )
    ids = {str(row["file_path"]): int(row["id"]) for row in files}
    registry = {
        ids[path]: validated_callable_records(index_file(path, "php", source), rel_path=path)
        for path, source in SOURCES.items()
    }
    published = _post_structural_callables(client, key, repo_id, files, registry)
    assert published.status_code == 200, published.text
    classified = client.post(
        f"{base}/files/bulk-classify",
        json={
            "classifications": [
                {
                    "file_id": ids[path],
                    "classification": tier,
                    "role": "request_handler",
                    "slot_types": ["NETWORK-INPUT"],
                    "analysis_priority": priority,
                }
                for path, (tier, priority) in TIERS.items()
            ]
        },
    )
    assert classified.status_code == 200, classified.text
    return base, repo_id, ids, registry


def _close(client, key, file_id: int, **proof) -> None:
    claim = _claim_file_for_analysis(client, key, file_id)
    receipt = client.post(
        f"/engagements/{key}/assessment/code/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            evidence="reviewed the sealed source of the claimed file",
            receipt_kind="file",
            cwe_coverage=_network_input_coverage(default_effort=80),
            **proof,
        ),
    )
    assert receipt.status_code == 201, receipt.text
    done = _complete(client, key, claim, _network_input_coverage(default_effort=80))
    assert done.status_code == 200, done.text


def _refs(file_id: int, records, *, top_level: bool | None = None):
    return [
        {"file_id": file_id, **record}
        for record in records
        if top_level is None or (record["name"] == TOP_LEVEL_CALLABLE_NAME) == top_level
    ]


def _reviewed_repo(client, isolate_settings, key: str):
    base, repo_id, ids, registry = _seed(client, isolate_settings, key)
    # A function citation leaves the mixed file's two file-scope segments owed.
    _close(
        client,
        key,
        ids[MIXED_PATH],
        callable_refs=_refs(ids[MIXED_PATH], registry[ids[MIXED_PATH]], top_level=False),
    )
    # The script's only callable is its one segment; citing it is the proof.
    _close(client, key, ids[SCRIPT_PATH], callable_refs=_refs(ids[SCRIPT_PATH], registry[ids[SCRIPT_PATH]]))
    # Imports and declarations open no segment, so only a whole-file span proves it.
    _close(
        client,
        key,
        ids[DECLARATIONS_PATH],
        reviewed_spans=[
            {
                "file_id": ids[DECLARATIONS_PATH],
                "start_line": 1,
                "end_line": len(SOURCES[DECLARATIONS_PATH].splitlines()),
            }
        ],
    )
    queued = client.post(
        f"{base}/analysis-queue",
        json={"items": [{"file_id": ids[FRAGMENT_PATH], "priority": 90}]},
    )
    assert queued.status_code == 201, queued.text
    with sqlite3.connect(str(db_module.database_path())) as connection:
        connection.execute(
            "UPDATE code_files SET structural_analysis_status = 'degraded' WHERE id = ?",
            (ids[FRAGMENT_PATH],),
        )
        connection.commit()
    return base, repo_id, ids, registry


def test_the_index_publishes_the_file_scope_each_fixture_relies_on():
    records = {
        path: [
            (item["name"], item["start_line"], item["end_line"])
            for item in validated_callable_records(index_file(path, "php", source), rel_path=path)
        ]
        for path, source in SOURCES.items()
    }

    assert records == {
        MIXED_PATH: [("acme_render", 5, 8), ("<top-level>", 2, 3), ("<top-level>", 10, 10)],
        SCRIPT_PATH: [("<top-level>", 2, 5)],
        DECLARATIONS_PATH: [],
        FRAGMENT_PATH: [("acme_charge", 2, 5), ("<top-level>", 7, 7)],
    }


def test_the_gate_owes_only_the_file_scope_no_receipt_covered(client, isolate_settings):
    key = "2026-11-05-file-scope-views-gate"
    base, repo_id, _ids, _registry = _reviewed_repo(client, isolate_settings, key)

    summary = client.get(f"{base}/coverage?repo_id={repo_id}").json()

    assert _uncovered_paths(summary["gate"]) == {MIXED_PATH}
    assert summary["by_classification"]["critical"] == {"count": 2, "analyzed": 1}
    assert summary["by_classification"]["high"] == {"count": 2, "analyzed": 2}


def test_function_coverage_counts_never_include_top_level_segments(client, isolate_settings):
    key = "2026-11-05-file-scope-views-functions"
    base, repo_id, ids, _registry = _reviewed_repo(client, isolate_settings, key)

    detail = client.get(f"{base}/coverage?repo_id={repo_id}&detail=cwe").json()
    effort = {row["file_path"]: row["analysis_effort"] for row in detail["files"]}

    assert effort[MIXED_PATH]["total_functions"] == 1
    assert effort[MIXED_PATH]["distinct_structural_callables_reviewed"] == 1
    assert effort[MIXED_PATH]["callable_coverage_pct"] == 100.0
    # Citing the script's `<top-level>` segment proves its review but is not a
    # reviewed function: the script has none.
    assert effort[SCRIPT_PATH]["total_functions"] == 0
    assert effort[SCRIPT_PATH]["distinct_structural_callables_reviewed"] == 0
    assert effort[SCRIPT_PATH]["callable_coverage_pct"] == 0.0
    file_detail = client.get(f"{base}/files/{ids[SCRIPT_PATH]}").json()
    assert file_detail["total_functions"] == 0


def test_directory_rows_agree_with_the_summary_and_readiness(client, isolate_settings):
    key = "2026-11-05-file-scope-views-by-path"
    base, repo_id, _ids, _registry = _reviewed_repo(client, isolate_settings, key)

    summary = client.get(f"{base}/coverage?repo_id={repo_id}").json()
    page = client.get(f"{base}/coverage/by-path?repo_id={repo_id}&depth=1").json()
    readiness = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    rows = {row["path"]: row for row in page["directories"]}

    assert set(rows) == {"public", "lib", "payments", "src"}
    assert sum(row["files"] for row in rows.values()) == summary["total_files"]
    by_status: dict[str, int] = {}
    for row in rows.values():
        for bucket, count in row["by_status"].items():
            by_status[bucket] = by_status.get(bucket, 0) + count
    assert {bucket: count for bucket, count in by_status.items() if count} == summary["by_status"]
    by_classification: dict[str, dict[str, int]] = {}
    for row in rows.values():
        for tier, counts in row["by_classification"].items():
            merged = by_classification.setdefault(tier, {"count": 0, "analyzed": 0})
            merged["count"] += counts["count"]
            merged["analyzed"] += counts["analyzed"]
    assert by_classification == summary["by_classification"]
    assert rows["public"]["by_status"]["analyzed"] == 2
    assert rows["payments"]["by_status"]["queued"] == 1
    assert rows["payments"]["uncovered_critical_high"] == 1
    assert readiness["structural_debt_count"] == 1
    assert sum(row["structural_debt"]["count"] for row in rows.values()) == 1
    assert rows["payments"]["structural_debt"] == {
        "count": 1, "degraded": 1, "unsupported": 0, "truncated": 0,
    }
    assert page["directories"][0]["path"] == "payments"


def test_path_scope_selects_php_fragments_and_their_workflow_hints(client, isolate_settings):
    key = "2026-11-05-file-scope-views-path-scope"
    base, _repo_id, ids, _registry = _reviewed_repo(client, isolate_settings, key)

    listed = client.get(
        f"{base}/analysis-queue", params={"path_glob": "payments/*.inc", "status": "pending"}
    ).json()
    assert [item["file_id"] for item in listed["items"]] == [ids[FRAGMENT_PATH]]
    claimed = client.post(
        f"{base}/analysis-queue/fetch",
        json={"limit": 5, "agent_name": "hunter", "path_prefix": ["payments"]},
    )
    assert claimed.status_code == 200, claimed.text
    claims = claimed.json()
    assert [claim["file_id"] for claim in claims] == [ids[FRAGMENT_PATH]]
    assert claims[0]["path_suggested_vuln_classes"] == ["business-logic", "race-condition"]
