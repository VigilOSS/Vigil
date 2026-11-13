"""Report readiness serves the report-QC standing of a registered report.md.

``report_qc`` says whether the newest ``report_qc_verdict`` passes and still
covers the registered report.md bytes, with the statuses submission QC uses
(missing, blocked, stale, current). The `complete` gate reads this field; it
does not recompute the rule.
"""
from __future__ import annotations

import pytest

from tests.test_submission_qc_verdict import (
    BASE,
    _record,
    _register_report,
    _report_payload,
    _root,
)
from tests.test_submission_versions_api import _seed_reportable_finding


def _report_qc(client) -> dict:
    response = client.get(f"{BASE}/report-readiness")
    assert response.status_code == 200, response.text
    return response.json()["report_qc"]


@pytest.fixture
def seeded(client, isolate_settings):
    _seed_reportable_finding(client, isolate_settings)


def test_an_unregistered_report_owes_no_review(client, isolate_settings, seeded):
    state = _report_qc(client)
    assert state["required"] is False
    assert state["status"] == "missing"


def test_a_registered_report_without_a_verdict_is_missing(client, isolate_settings, seeded):
    artifact = _register_report(client, isolate_settings)
    state = _report_qc(client)
    assert state["required"] is True
    assert state["status"] == "missing"
    assert state["artifact_id"] == artifact["id"]
    assert state["sha256"] == artifact["sha256"]
    assert "no passing independent report-writer QC verdict" in state["issue"]


def test_a_passing_review_of_the_registered_bytes_is_current(client, isolate_settings, seeded):
    artifact = _register_report(client, isolate_settings)
    recorded = _record(client, "report_qc_verdict", _report_payload(client, artifact))
    assert recorded.status_code == 201, recorded.text

    state = _report_qc(client)
    assert state["status"] == "current", state
    assert state["verdict"] == "pass"
    assert state["decision_id"] == recorded.json()["id"]
    assert state["reviewed_sha256"] == artifact["sha256"]
    assert state["reviewer_dispatch_agent_id"] == "QC-REPORT"
    assert state["decided_at"]
    assert state["issue"] == ""


def test_a_blocked_latest_verdict_is_blocked(client, isolate_settings, seeded):
    artifact = _register_report(client, isolate_settings)
    _record(client, "report_qc_verdict", _report_payload(client, artifact))
    blocked = _record(client, "report_qc_verdict", _report_payload(
        client, artifact, verdict="blocked",
        failed_rows=[{"row": "Executive summary", "quote": "TBD"}],
    ))
    assert blocked.status_code == 201, blocked.text

    state = _report_qc(client)
    assert state["status"] == "blocked"
    assert state["verdict"] == "blocked"


def test_bytes_registered_after_the_review_are_stale(client, isolate_settings, seeded):
    artifact = _register_report(client, isolate_settings)
    _record(client, "report_qc_verdict", _report_payload(client, artifact))
    _register_report(client, isolate_settings, b"# Acme internal report, revised\n")

    state = _report_qc(client)
    assert state["status"] == "stale"
    assert "registered with different bytes after its QC review" in state["issue"]


def test_an_edit_on_disk_after_the_review_is_stale(client, isolate_settings, seeded):
    artifact = _register_report(client, isolate_settings)
    _record(client, "report_qc_verdict", _report_payload(client, artifact))
    (_root(isolate_settings) / "report.md").write_bytes(b"# Edited after review\n")

    state = _report_qc(client)
    assert state["status"] == "stale"
    assert "changed on disk after its QC review" in state["issue"]


def test_a_deleted_report_is_stale_and_says_it_is_missing(client, isolate_settings, seeded):
    artifact = _register_report(client, isolate_settings)
    _record(client, "report_qc_verdict", _report_payload(client, artifact))
    (_root(isolate_settings) / "report.md").unlink()

    state = _report_qc(client)
    assert state["status"] == "stale"
    assert "missing from the engagement directory" in state["issue"]
