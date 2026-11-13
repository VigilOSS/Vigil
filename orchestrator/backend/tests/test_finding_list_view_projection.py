"""``GET /findings?view=list``: the projected ledger the CLI list and gate reads use.

The full list materialises every finding's ``details``, ``notes``, proof
receipts and next test, which ``finding list``, ``chain list``, the phase gates
and the record clobber guard never read. The list view selects only the list
fields (plus a blocked finding's ``block_reason``) in SQL, returns the same rows
in the same order under the same filters and window, and every value it carries
equals the full row's value for that field.
"""
from __future__ import annotations

import json

import pytest

from app import db as db_module
from app.services.state_manager import findings as findings_module
from tests.test_finding_list_recency import _base, _record, _seed


def _engagement_id() -> int:
    with db_module.get_connection() as connection:
        return int(connection.execute(
            "SELECT id FROM engagements WHERE key = ?",
            (_base().split("/")[2],),
        ).fetchone()["id"])


def _update(slug: str, **columns: object) -> None:
    assignments = ", ".join(f"{name} = ?" for name in columns)
    with db_module.get_connection() as connection:
        connection.execute(
            f"UPDATE assessment_findings SET {assignments} WHERE slug = ?",
            (*columns.values(), slug),
        )


def _seed_ledger(client, isolate_settings, *, bulky_details: int = 0) -> list[str]:
    _seed(client, isolate_settings)
    slugs = [f"VA-{index:03d}" for index in range(1, 9)]
    for index, slug in enumerate(slugs):
        _record(client, slug, severity=("critical", "high", "medium", "low")[index % 4])
    filler = "Acme order export trace line. " * max(bulky_details // 30, 0)
    for slug in slugs:
        _update(
            slug,
            details_json=json.dumps({"impact": "Cross-tenant read.", "trace": filler}),
            notes="Acme operator note. " * 50,
        )
    # A blocked finding carries its reason in details; a pending hold may carry
    # one too, which the list view leaves out (only a blocked row reads it).
    _update(
        "VA-002",
        verification_status="blocked",
        details_json=json.dumps({"block_reason": "needs a second Acme tenant account", "trace": filler}),
    )
    _update(
        "VA-003",
        verification_status="pending_runtime_proof",
        details_json=json.dumps({"block_reason": "awaiting staging window"}),
    )
    # Code-snapshot classification: an unbound file finding and a stale binding.
    _update("VA-004", canonical_location="file:src/acme/orders.py:41")
    _update(
        "VA-005",
        canonical_location="file:src/acme/export.py:12",
        provenance_json=json.dumps({
            "agent_id": "RECENCY-FIXTURE-AUTHOR",
            "code_snapshot": {"repo_id": 999, "repo_generation": 1, "source_manifest_digest": "0" * 64},
        }),
    )
    _update("VA-006", status="reported", submission_status="submitted",
            submission_platform="acme-bounty", submission_ref="ACME-1")
    return slugs


def _list(client, **params: object) -> list[dict]:
    response = client.get(f"{_base()}/findings", params={"view": "list", **params})
    assert response.status_code == 200, response.text
    return response.json()


def test_list_view_rows_equal_the_full_rows_on_every_field_they_carry(client, isolate_settings):
    _seed_ledger(client, isolate_settings)

    full = client.get(f"{_base()}/findings").json()
    projected = _list(client)

    assert [row["slug"] for row in projected] == [row["slug"] for row in full]
    for full_row, row in zip(full, projected, strict=True):
        assert set(row) == set(findings_module.FINDING_LIST_VIEW_FIELDS)
        carried = {key: row[key] for key in row if key != "block_reason"}
        assert carried == {key: full_row[key] for key in carried}
        expected_reason = (
            full_row["details"].get("block_reason")
            if full_row["verification_status"] == "blocked" else None
        )
        assert row["block_reason"] == expected_reason
    by_slug = {row["slug"]: row for row in projected}
    assert by_slug["VA-002"]["block_reason"] == "needs a second Acme tenant account"
    assert by_slug["VA-003"]["block_reason"] is None
    assert by_slug["VA-004"]["code_snapshot_status"] == "unbound"
    assert by_slug["VA-005"]["code_snapshot_status"] == "stale"
    assert by_slug["VA-001"]["code_snapshot_status"] == "not_applicable"


@pytest.mark.parametrize(
    "params",
    [
        {"severity": "high"},
        {"verification_status": "blocked"},
        {"workflow_status": "reported"},
        {"holding": "true"},
        {"search": "va-00"},
        {"limit": 3, "offset": 2},
        {"severity": "critical", "limit": 1, "offset": 1},
    ],
)
def test_list_view_honours_the_filters_and_window_of_the_full_list(params, client, isolate_settings):
    _seed_ledger(client, isolate_settings)

    full = client.get(f"{_base()}/findings", params=params).json()

    assert [row["slug"] for row in _list(client, **params)] == [row["slug"] for row in full]


def test_list_view_refuses_an_unknown_filter_value_like_the_full_list(client, isolate_settings):
    _seed_ledger(client, isolate_settings)

    response = client.get(f"{_base()}/findings", params={"view": "list", "verification_status": "verified"})

    assert response.status_code == 400
    assert "verified" in response.json()["detail"]


def test_list_view_payload_is_a_small_fraction_of_the_full_list(client, isolate_settings):
    _seed_ledger(client, isolate_settings, bulky_details=20_000)

    full_bytes = len(client.get(f"{_base()}/findings").content)
    list_bytes = len(client.get(f"{_base()}/findings", params={"view": "list"}).content)

    assert full_bytes > 150_000
    assert list_bytes * 20 < full_bytes, (list_bytes, full_bytes)


def test_list_view_reads_the_ledger_in_a_bounded_number_of_queries(client, isolate_settings):
    _seed_ledger(client, isolate_settings, bulky_details=2_000)
    engagement_id = _engagement_id()
    queries: list[str] = []

    with db_module.get_connection() as connection:
        connection.set_trace_callback(queries.append)
        try:
            rows = findings_module.list_finding_list_rows(engagement_id)
        finally:
            connection.set_trace_callback(None)

    assert len(rows) == 8
    # One ledger SELECT plus the shared repository-identity read; the per-row
    # evidence, receipt and next-test reads of the full projection never run.
    assert len(queries) <= 3, queries


@pytest.mark.parametrize(
    ("status", "details_json"),
    [
        # Python's json reads NaN/Infinity (and json.dumps writes them); SQLite's
        # json_valid does not.
        ("blocked", '{"block_reason":"needs an Acme MFA seed","ratio":NaN}'),
        # A repeated key: Python keeps the last value, SQLite's json_extract the first.
        ("blocked", '{"block_reason":"stale reason","block_reason":"awaiting Acme VPN"}'),
        # A stored status the full serializer folds to ``blocked``.
        (" Blocked ", '{"block_reason":"waiting on the Acme tenant"}'),
    ],
)
def test_list_view_block_reason_equals_the_full_row_for_lenient_json(
    status, details_json, client, isolate_settings
):
    _seed_ledger(client, isolate_settings)
    _update("VA-007", verification_status=status, details_json=details_json)
    engagement_id = _engagement_id()

    full = {row["slug"]: row for row in findings_module.list_findings(engagement_id)}
    projected = {
        row["slug"]: row for row in findings_module.list_finding_list_rows(engagement_id)
    }

    assert full["VA-007"]["verification_status"] == "blocked"
    expected = full["VA-007"]["details"]["block_reason"]
    assert expected
    assert projected["VA-007"]["block_reason"] == expected
