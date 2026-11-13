"""A critical/high closeout that names fewer families than the file owes still closes.

The backend records each applicable family the closeout left out as an
`effort: 0` entry and returns the list, so the gap is a measured coverage
shortfall (an effort gap at 0) instead of a refused write the agent must pad
by hand. A medium closeout owes no entry per family and gets none added.
"""
from __future__ import annotations

import json

import pytest

from app import db as db_module
from app.services.code_analysis import _effort_gap_summary
from test_code_analysis_api import (
    _claim_file_for_analysis,
    _classify_file,
    _close_queue_item,
    _network_input_coverage,
    _owned,
    _publish_structural_callables,
    _record_fixture_source_receipt,
    _seed_repo_files,
)


def _seed(client, isolate_settings, key, tier):
    repo, files = _seed_repo_files(client, isolate_settings, key, repo_key=f"{key}-repo")
    parser = next(f for f in files if f["file_path"] == "src/parser.py")
    helper = next(f for f in files if f["file_path"] == "src/helpers.py")
    _classify_file(client, key, int(parser["id"]), tier, {"critical": 90, "high": 60, "medium": 30}[tier])
    _classify_file(client, key, int(helper["id"]), "low", 10)
    _publish_structural_callables(client, key, int(repo["id"]), files, {})
    return f"/engagements/{key}/assessment/code", repo, parser


@pytest.mark.parametrize("tier", ["high", "critical"])
def test_partial_critical_or_high_closeout_records_the_rest_at_effort_zero(
    client, isolate_settings, tier
):
    key = f"2026-11-14-acme-closeout-fill-{tier}"
    base, repo, parser = _seed(client, isolate_settings, key, tier)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _record_fixture_source_receipt(client, key, claim)
    required = list(claim["applicable_vuln_classes"])
    reviewed = _network_input_coverage(default_effort=80)[:2]
    reviewed_families = {entry["family"] for entry in reviewed}
    left_out = [family for family in required if family not in reviewed_families]
    assert left_out

    closed = _close_queue_item(client, key, claim, disposition="clean",
                               notes="Acme reviewed two families", cwe_coverage=reviewed)

    assert closed.status_code == 200, closed.text
    recorded = closed.json()["unreviewed_families_recorded"]
    assert recorded["families"] == left_out
    assert recorded["effort"] == 0
    assert "code-coverage --cwe-matrix" in recorded["detail"]

    # The gap stays measured: each left-out family is an effort gap at 0 on this
    # file, in the full matrix rows and in the grouped summary.
    matrix = client.get(f"{base}/coverage?repo_id={repo['id']}&detail=cwe").json()
    rows = matrix["gate"]["effort_gaps"]["rows"]
    gaps = {row["family"]: row["effort"] for row in rows if row["file_id"] == parser["id"]}
    assert {family: gaps.get(family) for family in left_out} == {family: 0 for family in left_out}
    [file_row] = [row for row in matrix["files"] if row["file_id"] == parser["id"]]
    filled = [entry for entry in file_row["cwe_coverage"] if entry["family"] in left_out]
    assert filled and all(entry["recorded_by"] == "closeout" for entry in filled)

    # A replay of the same closeout is the same write, not a conflict.
    replay = _close_queue_item(client, key, claim, disposition="clean",
                               notes="Acme reviewed two families", cwe_coverage=reviewed)
    assert replay.status_code == 200, replay.text
    assert replay.json()["already_applied"] is True
    # The replay reports what the stored attempt recorded, so a retried closeout
    # learns about the effort-0 entries the same way the first one did.
    assert replay.json()["unreviewed_families_recorded"] == recorded


def test_a_complete_critical_closeout_records_nothing_extra(client, isolate_settings):
    key = "2026-11-14-acme-closeout-fill-none"
    _base, _repo, parser = _seed(client, isolate_settings, key, "critical")
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _record_fixture_source_receipt(client, key, claim)
    coverage = [{"family": family, "effort": 80} for family in claim["applicable_vuln_classes"]]

    closed = _close_queue_item(client, key, claim, disposition="clean",
                               notes="Acme reviewed every family", cwe_coverage=coverage)

    assert closed.status_code == 200, closed.text
    assert "unreviewed_families_recorded" not in closed.json()


def test_a_medium_closeout_owes_no_entry_per_family(client, isolate_settings):
    key = "2026-11-14-acme-closeout-fill-medium"
    _base, _repo, parser = _seed(client, isolate_settings, key, "medium")
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _record_fixture_source_receipt(client, key, claim)

    closed = _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme reviewed two families",
        cwe_coverage=_network_input_coverage(default_effort=80)[:2],
    )

    assert closed.status_code == 200, closed.text
    assert "unreviewed_families_recorded" not in closed.json()


def _queue_coverage(item_id: int) -> list[dict]:
    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT cwe_coverage_json FROM code_analysis_queue WHERE id = ?", (item_id,)
        ).fetchone()
    return json.loads(row["cwe_coverage_json"])


def test_a_completed_row_correction_records_the_families_it_leaves_out(
    client, isolate_settings
):
    """`code-record analysis --supersede` on a done row rewrites its coverage, so
    the families the correction names no entry for are recorded at effort 0 and
    returned, exactly as `done` does."""
    key = "2026-11-14-acme-closeout-fill-correction"
    base, _repo, parser = _seed(client, isolate_settings, key, "high")
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    original = _record_fixture_source_receipt(client, key, claim)
    full = [{"family": family, "effort": 80} for family in claim["applicable_vuln_classes"]]
    closed = _close_queue_item(client, key, claim, disposition="clean",
                               notes="Acme reviewed every family", cwe_coverage=full)
    assert closed.status_code == 200, closed.text

    partial = full[:2]
    left_out = [entry["family"] for entry in full[2:]]
    corrected = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            supersedes=original["id"],
            disposition="clean",
            evidence="Acme corrective pass over the same source",
            cwe_coverage=partial,
        ),
    )

    assert corrected.status_code == 201, corrected.text
    recorded = corrected.json()["unreviewed_families_recorded"]
    assert recorded["families"] == left_out
    stored = {entry["family"]: entry for entry in _queue_coverage(int(claim["id"]))}
    assert all(
        stored[family]["effort"] == 0 and stored[family]["recorded_by"] == "closeout"
        for family in left_out
    )


@pytest.mark.parametrize("na_on", ["receipt", "closeout"])
def test_a_reviewed_not_applicable_entry_outranks_a_closeout_effort_zero_entry(
    client, isolate_settings, na_on
):
    """A family a reviewer marked not_applicable is not an effort gap because a
    closeout somewhere else on the file left it unnamed."""
    key = f"2026-11-14-acme-closeout-fill-na-{na_on.replace('_', '-')}"
    base, repo, parser = _seed(client, isolate_settings, key, "high")
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    families = list(claim["applicable_vuln_classes"])
    reviewed = [{"family": family, "effort": 80} for family in families[:-1]]
    na_family = families[-1]
    na_entry = {"family": na_family, "disposition": "not_applicable",
                "notes": "Acme parser performs no such operation"}
    receipt = client.post(
        f"{base}/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            evidence="Acme reviewed the exact current source.",
            cwe_coverage=[na_entry] if na_on == "receipt" else [],
        ),
    )
    assert receipt.status_code == 201, receipt.text
    closed = _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme reviewed the file",
        cwe_coverage=reviewed if na_on == "receipt" else [*reviewed, na_entry],
    )
    assert closed.status_code == 200, closed.text

    matrix = client.get(f"{base}/coverage?repo_id={repo['id']}&detail=cwe").json()
    gaps = {
        row["family"]
        for row in matrix["gate"]["effort_gaps"]["rows"]
        if row["file_id"] == parser["id"]
    }
    assert na_family not in gaps


def test_effort_gap_groups_count_files_not_paths():
    """Two repositories can each hold `src/app.py`; they are two files."""
    gaps = [
        {"file_id": 1, "file_path": "src/app.py", "classification": "high",
         "family": "ssrf", "threshold": 60, "effort": 0},
        {"file_id": 2, "file_path": "src/app.py", "classification": "high",
         "family": "ssrf", "threshold": 60, "effort": 0},
    ]
    summary = _effort_gap_summary(gaps, include_rows=False)
    [group] = summary["groups"]
    assert group["file_count"] == 2
    assert summary["file_count"] == 2
