"""The `complete` edge reads report QC standing from report readiness.

The backend owns whether a registered report.md has a current independent QC
review (``report-readiness``'s ``report_qc``); the transition turns a standing
that is not ``current`` into one ``missing_report_qc`` blocker naming the issue,
and reads report readiness once per edge.
"""
from __future__ import annotations

from assess.commands import transition_phase


class _Client:
    def __init__(self, readiness: object, registered: list[dict] | None = None) -> None:
        self.readiness = readiness
        self.registered = registered
        self.requested: list[str] = []

    def get(self, path):
        self.requested.append(path)
        if path == "report-readiness":
            if isinstance(self.readiness, Exception):
                raise self.readiness
            return self.readiness
        if path.startswith("artifacts/search?path=report.md&") and self.registered is not None:
            return self.registered if path.endswith("offset=0") else []
        raise AssertionError(f"report QC must not read {path}")


def _state(**overrides) -> dict:
    return {
        "required": True, "status": "current", "verdict": "pass", "artifact_id": 77,
        "sha256": "a" * 64, "issue": "", **overrides,
    }


def _blockers(readiness, registered: list[dict] | None = None) -> list[dict]:
    return transition_phase._report_qc_blockers(_Client(readiness, registered))


def test_a_current_review_or_an_unregistered_report_passes():
    assert _blockers({"report_qc": _state()}) == []
    assert _blockers({"report_qc": _state(required=False, status="missing")}) == []


def test_a_standing_that_is_not_current_blocks_with_its_issue():
    for status, issue in (
        ("missing", "has no passing independent report-writer QC verdict"),
        ("blocked", "has no passing independent report-writer QC verdict"),
        ("stale", "changed on disk after its QC review"),
        ("stale", "is missing from the engagement directory"),
    ):
        (blocker,) = _blockers({"report_qc": _state(status=status, issue=issue)})
        assert blocker["kind"] == "missing_report_qc"
        assert f"registered report.md {issue}" in blocker["detail"]
        assert "report_qc_verdict" in blocker["detail"]


def test_an_unreadable_standing_fails_closed():
    for readiness in ({"ready": True}, {"report_qc": "current"}):
        (blocker,) = _blockers(readiness)
        assert blocker["kind"] == "precondition_check_failed", blocker
        assert blocker.get("severity", "block") == "block"


def test_an_unreadable_report_readiness_blocks_only_a_registered_report():
    down = RuntimeError("backend down")
    report = [{"id": 77, "kind": "report", "relative_path": "report.md"}]
    for registered in (report, None):  # registered, or its registration unreadable
        (blocker,) = _blockers(down, registered)
        assert blocker["kind"] == "precondition_check_failed", blocker
        assert blocker.get("severity", "block") == "block"
        assert blocker["detail"].startswith("report readiness check failed: backend down")
    (item,) = _blockers(down, [])
    assert item["severity"] == "advisory"
    assert item["detail"].startswith("report readiness check failed: backend down")


def test_the_complete_edge_reads_report_readiness_once():
    backend = _Client({"ready": True, "blockers": [], "report_qc": _state()})
    shared = transition_phase._SharedFindingList(backend)
    transition_phase._report_readiness_items(shared, "complete readiness")
    assert transition_phase._report_qc_blockers(shared) == []
    assert backend.requested == ["report-readiness"]
