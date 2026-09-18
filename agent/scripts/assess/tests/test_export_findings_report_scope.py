"""`export findings` renders the report-durable set, not every stored row.

``findings.md`` is a report document, and it is the one export that read
``GET findings`` straight through: an ``unreviewed`` guess, a ``disputed``
claim and a ``pending_runtime_proof`` holding-area park all landed in it under
the same heading shape as a confirmed finding. Every other report projection
(``report-findings`` draft and final, and therefore ``export submission`` and
the markdown-tree ``report.md``) admits only ``confirmed``/``downgraded``
findings in a reportable workflow state, so this pins the same predicate here.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from assess.commands import export_findings


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    def __init__(self, findings: list[dict]) -> None:
        self._findings = findings

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def get(self, endpoint: str):
        if endpoint == "findings":
            return self._findings
        if endpoint == "finding-groups":
            return []
        raise AssertionError(f"unexpected endpoint: {endpoint}")


def _finding(slug: str, verification: str, workflow: str = "active") -> dict:
    return {
        "slug": slug,
        "title": f"Finding {slug}",
        "severity": "high",
        "workflow_status": workflow,
        "verification_status": verification,
        "canonical_location": f"https://app.example/{slug.lower()}",
        "details": {"evidence": "proof", "impact": "impact"},
    }


def _run(tmp_path: Path, monkeypatch, findings: list[dict]) -> str:
    monkeypatch.setattr(export_findings, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(export_findings, "load_scope", lambda *a, **k: {"engagement_name": "Scope test"})
    monkeypatch.setattr(export_findings, "AssessmentClient", lambda *a, **k: _FakeClient(findings))
    export_findings.run(argparse.Namespace(engagement_dir=str(tmp_path)))
    return (tmp_path / "findings.md").read_text(encoding="utf-8")


def test_only_report_durable_findings_reach_findings_md(tmp_path, monkeypatch) -> None:
    content = _run(
        tmp_path,
        monkeypatch,
        [
            _finding("VA-001", "confirmed"),
            _finding("VA-002", "downgraded", workflow="exploited"),
            _finding("VA-003", "unreviewed"),
            _finding("VA-004", "disputed"),
            _finding("VA-005", "pending_runtime_proof"),
            _finding("VA-006", "blocked"),
            _finding("VA-007", "false_positive", workflow="false_positive"),
            _finding("VA-008", "confirmed", workflow="draft"),
            _finding("VA-009", "confirmed", workflow="merged"),
        ],
    )

    assert "[VA-001]" in content
    assert "[VA-002]" in content
    for excluded in ("VA-003", "VA-004", "VA-005", "VA-006", "VA-007", "VA-008", "VA-009"):
        assert f"[{excluded}]" not in content, excluded


def test_the_finding_count_header_counts_what_was_rendered(tmp_path, monkeypatch) -> None:
    content = _run(
        tmp_path,
        monkeypatch,
        [
            _finding("VA-001", "confirmed"),
            _finding("VA-002", "unreviewed"),
            _finding("VA-003", "pending_runtime_proof"),
        ],
    )

    assert "- **Finding Count**: 1" in content
