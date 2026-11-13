"""The `complete` edge requires independent report-writer QC of each deliverable.

Every submittable finding with a registered submission workspace needs a latest
``submission_qc_verdict`` of ``pass``; a registered internal ``report.md`` needs
a latest ``report_qc_verdict`` of ``pass`` bound to its current bytes, which
report readiness serves as ``report_qc`` (the rule itself is pinned by
``orchestrator/backend/tests/test_report_qc_state.py``). Entering ``report``
requires neither, because phase 8 is where those reviews happen.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from assess.commands import transition_phase

_PACKET = "c" * 64
_REPORT_SHA = "a" * 64


def _finding(slug: str, **overrides) -> dict:
    return {
        "slug": slug, "severity": "low", "verification_status": "confirmed",
        "workflow_status": "reported", **overrides,
    }


def _workspace(slug: str) -> dict:
    return {
        "id": 40, "kind": "submission", "relative_path": f"submissions/{slug}/submission.md",
        "related_finding_slug": slug, "present": True,
    }


def _report_artifact(sha256: str = _REPORT_SHA) -> dict:
    return {"id": 77, "kind": "artifact", "relative_path": "report.md", "sha256": sha256, "present": True}


def _qc(slug: str, verdict: str = "pass", row_id: int = 1) -> dict:
    return {"id": row_id, "kind": "submission_qc_verdict", "payload": {
        "finding_slug": slug, "packet_id": _PACKET, "verdict": verdict,
        "reviewer_dispatch_agent_id": "QC-1", "writer_dispatch_agent_id": "WRITE-1",
        "failed_rows": [] if verdict == "pass" else [{"row": "Impact", "quote": "may"}],
    }}


def _standing(status: str = "current", issue: str = "", required: bool = True) -> dict:
    """The ``report_qc`` standing report readiness serves for report.md."""
    return {"required": required, "status": status, "verdict": None, "artifact_id": 77,
            "sha256": _REPORT_SHA, "issue": issue}


_NO_REPORT = _standing("missing", required=False)


def _wire(monkeypatch, tmp_path, *, current_phase="report", findings=(), artifacts=(),
          decisions=None, failing_prefix="", engagement_type="web", report_qc=None):
    (tmp_path / "scope.json").write_text(
        json.dumps({"engagement_type": engagement_type, "current_phase": current_phase}),
        encoding="utf-8")
    decisions = decisions or {}
    requested: list[str] = []
    recorded: list[dict] = []

    class _Client:
        def __init__(self, *_a, **_k):
            pass

        def get(self, path):
            requested.append(path)
            if failing_prefix and path.startswith(failing_prefix):
                raise RuntimeError("backend unavailable")
            if path == "findings?view=list":
                return list(findings)
            if path == "report-readiness":
                return {"ready": True, "blockers": [], "report_qc": report_qc or _NO_REPORT}
            if path == "application-units/terminal-block":
                return {"skipped": False, "blocking": [], "warned_under_observed": [],
                        "deferred": [], "deferral_count": 0}
            if path.startswith("dispatch-decisions?kind="):
                kind = path.split("kind=", 1)[1].split("&", 1)[0]
                return list(decisions.get(kind, [])) if path.endswith("offset=0") else []
            if path.startswith("artifacts/search?"):
                if not path.endswith("offset=0"):
                    return []
                if "kind=" in path:
                    kind = path.split("kind=", 1)[1].split("&", 1)[0]
                    return [row for row in artifacts if row["kind"] == kind]
                if "path=" in path:
                    exact = path.split("path=", 1)[1].split("&", 1)[0]
                    return [row for row in artifacts if row["relative_path"] == exact]
                return list(artifacts)
            if path.startswith("code/readiness?target_phase="):
                return {"target_phase": path.split("=", 1)[1], "blockers": [],
                        "transition_ready": True}
            return []

        def record_decision(self, payload):
            recorded.append(payload)
            return {"id": len(recorded)}

        def __enter__(self):
            return self

        def __exit__(self, *_e):
            return False

    monkeypatch.setattr(transition_phase, "AssessmentClient", _Client)
    monkeypatch.setattr(transition_phase, "load_config", lambda *_a, **_k: SimpleNamespace(
        base_url="http://example.test", engagement_dir=str(tmp_path),
        engagement_key="eng", agent_root=str(tmp_path)))
    monkeypatch.setattr(transition_phase, "_chain_construction_blockers", lambda _c: [])
    monkeypatch.setattr(transition_phase, "_blind_triage_blockers", lambda _c: [])
    return requested, recorded


def _run(tmp_path, target, **overrides):
    args = dict(engagement_dir=str(tmp_path), target_phase=target, force=False,
                reason="", track="auto")
    args.update(overrides)
    transition_phase.run(SimpleNamespace(**args))


def _phase(tmp_path) -> str:
    return json.loads((tmp_path / "scope.json").read_text())["current_phase"]


def test_complete_requires_qc_for_every_registered_submission_at_any_severity(
    monkeypatch, tmp_path, capsys
):
    _wire(monkeypatch, tmp_path, findings=[_finding("VA-3")], artifacts=[_workspace("VA-3")])
    with pytest.raises(SystemExit):
        _run(tmp_path, "complete")
    err = capsys.readouterr().err
    assert "missing_submission_qc" in err and "VA-3" in err
    assert _phase(tmp_path) == "report"


def test_complete_passes_with_latest_passing_qc(monkeypatch, tmp_path, capsys):
    _wire(monkeypatch, tmp_path, findings=[_finding("VA-3")], artifacts=[_workspace("VA-3")],
          decisions={"submission_qc_verdict": [_qc("VA-3")]})
    _run(tmp_path, "complete")
    assert "missing_submission_qc" not in capsys.readouterr().err
    assert _phase(tmp_path) == "complete"


def test_latest_blocked_qc_revokes_an_earlier_pass(monkeypatch, tmp_path, capsys):
    _wire(monkeypatch, tmp_path, findings=[_finding("VA-3")], artifacts=[_workspace("VA-3")],
          decisions={"submission_qc_verdict": [_qc("VA-3", "blocked", 2), _qc("VA-3", "pass", 1)]})
    with pytest.raises(SystemExit):
        _run(tmp_path, "complete")
    assert "missing_submission_qc" in capsys.readouterr().err


@pytest.mark.parametrize(
    "finding",
    [_finding("VA-3", workflow_status="draft"), _finding("VA-3", verification_status="pending")],
)
def test_qc_is_scoped_to_submittable_verified_findings(monkeypatch, tmp_path, capsys, finding):
    _wire(monkeypatch, tmp_path, findings=[finding], artifacts=[_workspace("VA-3")])
    _run(tmp_path, "complete")
    assert "missing_submission_qc" not in capsys.readouterr().err


def test_finding_without_a_registered_submission_owes_no_qc(monkeypatch, tmp_path, capsys):
    _wire(monkeypatch, tmp_path, findings=[_finding("VA-3")], artifacts=[_workspace("VA-9")])
    _run(tmp_path, "complete")
    assert "missing_submission_qc" not in capsys.readouterr().err


def test_qc_gate_fails_closed_when_registrations_cannot_be_read(monkeypatch, tmp_path, capsys):
    _wire(monkeypatch, tmp_path, findings=[_finding("VA-3")], failing_prefix="artifacts/search")
    with pytest.raises(SystemExit):
        _run(tmp_path, "complete")
    assert "precondition_check_failed" in capsys.readouterr().err


def test_force_overrides_missing_qc_with_an_audited_decision(monkeypatch, tmp_path):
    _requested, recorded = _wire(
        monkeypatch, tmp_path, findings=[_finding("VA-3")], artifacts=[_workspace("VA-3")],
    )
    _run(tmp_path, "complete", force=True, reason="operator accepted the Acme closeout")
    assert _phase(tmp_path) == "complete"
    override = [row for row in recorded if row["kind"] == "forced_transition_override"]
    assert any(b["kind"] == "missing_submission_qc" for b in override[0]["payload"]["overridden_blockers"])


def test_entering_report_requires_neither_qc_nor_blind_triage(monkeypatch, tmp_path, capsys):
    _wire(monkeypatch, tmp_path, current_phase="exploit",
          findings=[_finding("VA-3", severity="high", workflow_status="active")],
          artifacts=[_workspace("VA-3"), _report_artifact()],
          report_qc=_standing("missing", "has no passing independent report-writer QC verdict"))
    monkeypatch.setattr(transition_phase, "_blind_triage_blockers", _fail_if_called)
    _run(tmp_path, "report")
    err = capsys.readouterr().err
    assert "missing_submission_qc" not in err and "missing_report_qc" not in err
    assert _phase(tmp_path) == "report"


def _fail_if_called(_client):
    raise AssertionError("blind triage verdicts are produced inside the report phase")


def test_complete_still_runs_the_blind_triage_backstop(monkeypatch, tmp_path):
    _wire(monkeypatch, tmp_path)
    called: list[bool] = []
    monkeypatch.setattr(
        transition_phase, "_blind_triage_blockers", lambda _c: called.append(True) or [],
    )
    _run(tmp_path, "complete")
    assert called == [True]


# -- internal report.md --------------------------------------------------------


def test_registered_report_requires_a_passing_report_qc(monkeypatch, tmp_path, capsys):
    _wire(monkeypatch, tmp_path, report_qc=_standing(
        "missing", "has no passing independent report-writer QC verdict"))
    with pytest.raises(SystemExit):
        _run(tmp_path, "complete")
    assert "missing_report_qc" in capsys.readouterr().err


def test_a_current_report_qc_clears_the_gate(monkeypatch, tmp_path, capsys):
    _wire(monkeypatch, tmp_path, report_qc=_standing("current"))
    _run(tmp_path, "complete")
    assert "missing_report_qc" not in capsys.readouterr().err
    assert _phase(tmp_path) == "complete"


@pytest.mark.parametrize(("status", "issue"), [
    ("blocked", "has no passing independent report-writer QC verdict"),
    ("stale", "was registered with different bytes after its QC review"),
    ("stale", "changed on disk after its QC review"),
])
def test_a_report_qc_that_is_not_current_blocks_with_its_issue(
    monkeypatch, tmp_path, capsys, status, issue
):
    _wire(monkeypatch, tmp_path, report_qc=_standing(status, issue))
    with pytest.raises(SystemExit):
        _run(tmp_path, "complete")
    err = capsys.readouterr().err
    assert "missing_report_qc" in err and issue in err


def test_unregistered_report_owes_no_report_qc(monkeypatch, tmp_path, capsys):
    _wire(monkeypatch, tmp_path, report_qc=_NO_REPORT)
    _run(tmp_path, "complete")
    assert "missing_report_qc" not in capsys.readouterr().err


def test_report_qc_reads_the_served_standing_once(monkeypatch, tmp_path, capsys):
    """The gate reads report readiness, shared with the readiness items, and
    never re-derives currency from the artifact index or the decision ledger."""
    requested, _ = _wire(monkeypatch, tmp_path, report_qc=_standing("current"))
    _run(tmp_path, "complete")
    assert requested.count("report-readiness") == 1
    assert not any(path.startswith("artifacts/search?path=report.md") for path in requested)
    assert not any("kind=report_qc_verdict" in path for path in requested)


def test_a_registered_report_that_is_missing_blocks_complete(monkeypatch, tmp_path, capsys):
    _wire(monkeypatch, tmp_path, report_qc=_standing(
        "stale", "is missing from the engagement directory"))
    with pytest.raises(SystemExit):
        _run(tmp_path, "complete")
    err = capsys.readouterr().err
    assert "missing_report_qc" in err and "missing" in err.split("missing_report_qc", 1)[1]
    assert _phase(tmp_path) == "report"


def test_report_qc_fails_closed_without_a_served_standing(monkeypatch, tmp_path, capsys):
    _wire(monkeypatch, tmp_path, failing_prefix="report-readiness", artifacts=[_report_artifact()])
    with pytest.raises(SystemExit):
        _run(tmp_path, "complete")
    err = capsys.readouterr().err
    assert "[precondition_check_failed] report readiness check failed" in err
    assert "report.md is registered" in err
    assert _phase(tmp_path) == "report"


# -- code track ----------------------------------------------------------------


def test_code_complete_requires_qc_for_every_registered_submission(monkeypatch, tmp_path, capsys):
    _wire(monkeypatch, tmp_path, engagement_type="code", current_phase="fuzz",
          findings=[_finding("CVH-3")], artifacts=[_workspace("CVH-3")])
    with pytest.raises(SystemExit):
        _run(tmp_path, "complete")
    err = capsys.readouterr().err
    assert "missing_submission_qc" in err and "CVH-3" in err
    assert _phase(tmp_path) == "fuzz"


def test_code_complete_requires_qc_of_a_registered_report(monkeypatch, tmp_path, capsys):
    _wire(monkeypatch, tmp_path, engagement_type="code", current_phase="fuzz",
          report_qc=_standing("missing", "has no passing independent report-writer QC verdict"))
    with pytest.raises(SystemExit):
        _run(tmp_path, "complete")
    assert "missing_report_qc" in capsys.readouterr().err
    assert _phase(tmp_path) == "fuzz"


def test_code_complete_passes_with_current_qc(monkeypatch, tmp_path):
    _wire(monkeypatch, tmp_path, engagement_type="code", current_phase="fuzz",
          findings=[_finding("CVH-3")], artifacts=[_workspace("CVH-3"), _report_artifact()],
          decisions={"submission_qc_verdict": [_qc("CVH-3")]}, report_qc=_standing("current"))
    _run(tmp_path, "complete")
    assert _phase(tmp_path) == "complete"


def test_a_code_complete_qc_blocker_is_overridable_with_an_audited_decision(monkeypatch, tmp_path):
    """Only the code readiness debt is unforceable at code `complete`; review
    blockers keep the audited override every other edge offers."""
    _requested, recorded = _wire(
        monkeypatch, tmp_path, engagement_type="code", current_phase="fuzz",
        findings=[_finding("CVH-3")], artifacts=[_workspace("CVH-3")],
    )
    _run(tmp_path, "complete", force=True, reason="operator accepted the Acme closeout")
    assert _phase(tmp_path) == "complete"
    override = [row for row in recorded if row["kind"] == "forced_transition_override"]
    assert any(b["kind"] == "missing_submission_qc" for b in override[0]["payload"]["overridden_blockers"])


def test_code_complete_refusal_lists_the_forceable_qc_blockers_beside_the_debt(
    monkeypatch, tmp_path, capsys
):
    """One refusal names every blocker on the edge, and says which ones
    `--force --reason` can override once the coverage debt is cleared."""
    _wire(monkeypatch, tmp_path, engagement_type="code", current_phase="fuzz",
          findings=[_finding("CVH-3")], artifacts=[_workspace("CVH-3")])
    debt = {"kind": "uncovered_high_risk_file", "detail": "src/acme/parser.py was never reviewed"}
    original = transition_phase._check_preconditions
    monkeypatch.setattr(
        transition_phase, "_check_preconditions",
        lambda *a, **k: [debt, *original(*a, **k)],
    )
    with pytest.raises(SystemExit):
        _run(tmp_path, "complete", force=True, reason="Acme deadline")
    err = capsys.readouterr().err
    debt_at = err.index("uncovered_high_risk_file")
    qc_at = err.index("missing_submission_qc")
    assert debt_at < qc_at, err
    assert "--force --reason" in err[debt_at:], err
    assert _phase(tmp_path) == "fuzz"


def test_code_complete_names_an_unreadable_report_readiness_for_what_it_is(
    monkeypatch, tmp_path, capsys
):
    """With no report.md registered no report QC is owed, so a report readiness
    read failure is reported as that read failing, not as a report QC blocker."""
    _wire(monkeypatch, tmp_path, engagement_type="code", current_phase="fuzz",
          failing_prefix="report-readiness")
    _run(tmp_path, "complete")
    err = capsys.readouterr().err
    assert "report QC check failed" not in err
    assert "report readiness check failed" in err
    assert _phase(tmp_path) == "complete"


def test_code_complete_with_a_registered_report_fails_closed_on_unreadable_readiness(
    monkeypatch, tmp_path, capsys
):
    _wire(monkeypatch, tmp_path, engagement_type="code", current_phase="fuzz",
          failing_prefix="report-readiness", artifacts=[_report_artifact()])
    with pytest.raises(SystemExit):
        _run(tmp_path, "complete")
    err = capsys.readouterr().err
    assert "[precondition_check_failed] report readiness check failed" in err
    assert _phase(tmp_path) == "fuzz"
