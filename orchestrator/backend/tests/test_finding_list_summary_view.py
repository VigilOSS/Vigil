"""``GET /findings?view=summary``: the lean ledger the Overview and rail read.

The full list carries every finding's ``details`` and ``notes`` — most of the
payload on a busy engagement — which the Overview queue and the rail badges
never show. The summary view drops exactly those two fields, keeps the same
rows in the same order with every other field (including the derived
``status_reason``/``next_test``), and honours the same filters.
"""
from __future__ import annotations

from tests.test_finding_list_recency import _base, _record, _seed


def test_summary_view_drops_only_details_and_notes(client, isolate_settings):
    _seed(client, isolate_settings)
    _record(client, "VA-001")
    _record(client, "VA-002", severity="low")

    full = client.get(f"{_base()}/findings").json()
    summary = client.get(f"{_base()}/findings", params={"view": "summary"}).json()
    assert [row["slug"] for row in summary] == [row["slug"] for row in full]
    for full_row, summary_row in zip(full, summary, strict=True):
        assert "details" in full_row and "notes" in full_row
        assert set(full_row) - set(summary_row) == {"details", "notes"}
        assert {key: full_row[key] for key in summary_row} == summary_row

    filtered = client.get(f"{_base()}/findings", params={"view": "summary", "severity": "low"}).json()
    assert [row["slug"] for row in filtered] == ["VA-002"]
    assert client.get(f"{_base()}/findings", params={"view": "compact"}).status_code == 422
