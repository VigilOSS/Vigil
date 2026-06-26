"""W3b — CODE-track coverage gate wiring in transition-phase.

Mirrors the in-process gate harness shape of
``orchestrator/backend/tests/test_blind_triage_gate.py``: it drives
``transition_phase.run`` with a fake ``AssessmentClient`` that returns a canned
``code/coverage`` payload, so the tests stay hermetic and never spin up FastAPI.

Three sub-gates are wired at hunt -> verify-variant and at report/complete, all
severity=block (overridable by --force --reason, satisfiable by recording the
analysis or an accepted-gap resolution):

  (a) ``code_coverage_incomplete``     — critical/high files not fully analyzed,
  (b) ``pending_cross_file_triggers``  — trigger_summary.pending > 0,
  (c) ``uncovered_high_risk_file``     — backend gate.uncovered_high_risk_files.

The per-family effort thresholds (70/50/30) stay a WARN: they live in
gate.effort_warnings and are intentionally NOT read by the phase gate, so a
shallow-but-nonzero effort score never blocks the transition.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[4]


def _load_transition_module(name: str):
    scripts_root = _REPO_ROOT / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = scripts_root / "assess" / "commands" / "transition_phase.py"
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_ACTIVE_CODE_FINDING = {
    "slug": "code-1",
    "severity": "high",
    "verification_state": "verified",
    "workflow_status": "active",
    "canonical_location": "file:src/other.py:3",
}


def _coverage(
    *,
    critical=(1, 1),
    high=(0, 0),
    pending=0,
    uncovered=None,
    effort_warnings=None,
):
    by_class: dict[str, dict[str, int]] = {}
    if critical is not None:
        by_class["critical"] = {"count": critical[0], "analyzed": critical[1]}
    if high is not None:
        by_class["high"] = {"count": high[0], "analyzed": high[1]}
    return {
        "total_files": 12,
        "by_classification": by_class,
        "trigger_summary": {"pending": pending, "queued": 0, "resolved": 0},
        "gate": {
            "passed": not (uncovered or effort_warnings),
            "reasons": list(effort_warnings or []),
            "effort_warnings": list(effort_warnings or []),
            "coverage_integrity": [],
            "uncovered_high_risk_files": list(uncovered or []),
        },
    }


def _setup_env(monkeypatch, module, tmp_path, *, scope, coverage, findings=None):
    engagement = tmp_path / "agent" / "engagements" / "eng-code"
    engagement.mkdir(parents=True, exist_ok=True)
    (engagement / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    recorded: list[dict] = []

    class _Client:
        def __init__(self, *_a, **_k) -> None:
            pass

        def get(self, path: str):
            if path == "findings":
                return findings if findings is not None else [_ACTIVE_CODE_FINDING]
            if path == "code/coverage":
                return coverage
            return []

        def record_decision(self, payload):
            recorded.append(payload)
            return {"id": len(recorded)}

        def close(self) -> None:
            return None

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(engagement),
            engagement_key=engagement.name,
            agent_root=str(tmp_path / "agent"),
        ),
    )
    return engagement, recorded


def _args(engagement, target_phase, **overrides):
    base = dict(
        engagement_dir=str(engagement),
        target_phase=target_phase,
        force=False,
        reason="",
        track="auto",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


_UNCOVERED = [{"file_id": 7, "file_path": "src/parser.py", "classification": "critical", "total_functions": 5}]


# ---------------------------------------------------------------------------
# (c) uncovered_high_risk_file blocks hunt -> verify-variant
# ---------------------------------------------------------------------------


def test_hunt_to_verify_blocks_on_uncovered_high_risk_file(monkeypatch, tmp_path, capsys):
    module = _load_transition_module("tp_cov_uncov_block")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "code", "current_phase": "hunt"},
        coverage=_coverage(uncovered=_UNCOVERED),
    )
    with pytest.raises(SystemExit):
        module.run(_args(eng, "verify-variant"))
    err = capsys.readouterr().err
    assert "uncovered_high_risk_file" in err
    assert "src/parser.py" in err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "hunt"


def test_uncovered_cleared_allows_transition(monkeypatch, tmp_path, capsys):
    module = _load_transition_module("tp_cov_uncov_clear")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "code", "current_phase": "hunt"},
        coverage=_coverage(uncovered=[]),
    )
    module.run(_args(eng, "verify-variant"))
    assert "uncovered_high_risk_file" not in capsys.readouterr().err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "verify-variant"


# ---------------------------------------------------------------------------
# (a) critical/high coverage incomplete blocks
# ---------------------------------------------------------------------------


def test_hunt_to_verify_blocks_on_incomplete_high_coverage(monkeypatch, tmp_path, capsys):
    module = _load_transition_module("tp_cov_incomplete")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "code", "current_phase": "hunt"},
        coverage=_coverage(critical=(2, 2), high=(3, 1)),
    )
    with pytest.raises(SystemExit):
        module.run(_args(eng, "verify-variant"))
    err = capsys.readouterr().err
    assert "code_coverage_incomplete" in err
    assert "1/3" in err


# ---------------------------------------------------------------------------
# (b) pending cross-file triggers block
# ---------------------------------------------------------------------------


def test_hunt_to_verify_blocks_on_pending_triggers(monkeypatch, tmp_path, capsys):
    module = _load_transition_module("tp_cov_triggers")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "code", "current_phase": "hunt"},
        coverage=_coverage(pending=2),
    )
    with pytest.raises(SystemExit):
        module.run(_args(eng, "verify-variant"))
    err = capsys.readouterr().err
    assert "pending_cross_file_triggers" in err


# ---------------------------------------------------------------------------
# KEEP-WARN: a below-70/50/30 effort score does NOT block
# ---------------------------------------------------------------------------


def test_low_effort_warning_does_not_block(monkeypatch, tmp_path, capsys):
    module = _load_transition_module("tp_cov_effort_warn")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "code", "current_phase": "hunt"},
        # Effort warnings present (would fail backend gate.passed), but the
        # hard sub-gates are all clear: must NOT block.
        coverage=_coverage(
            uncovered=[],
            effort_warnings=["Critical file src/parser.py: family 'ssrf' effort 40 < 70"],
        ),
    )
    module.run(_args(eng, "verify-variant"))
    err = capsys.readouterr().err
    assert "uncovered_high_risk_file" not in err
    assert "code_coverage_incomplete" not in err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "verify-variant"


# ---------------------------------------------------------------------------
# --force overrides and records the blocker (same path as missing_variant_pass)
# ---------------------------------------------------------------------------


def test_force_overrides_uncovered_and_records_decision(monkeypatch, tmp_path):
    module = _load_transition_module("tp_cov_force")
    eng, recorded = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "code", "current_phase": "hunt"},
        coverage=_coverage(uncovered=_UNCOVERED),
    )
    module.run(_args(eng, "verify-variant", force=True, reason="accepted residual risk"))
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "verify-variant"
    override = [d for d in recorded if d["kind"] == "forced_transition_override"]
    assert len(override) == 1
    assert any(
        b["kind"] == "uncovered_high_risk_file"
        for b in override[0]["payload"]["overridden_blockers"]
    )


# ---------------------------------------------------------------------------
# The same gate guards report/complete (CODE complete edge)
# ---------------------------------------------------------------------------


def test_complete_blocks_on_uncovered_high_risk_file(monkeypatch, tmp_path, capsys):
    module = _load_transition_module("tp_cov_complete_block")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "code", "current_phase": "fuzz"},
        coverage=_coverage(uncovered=_UNCOVERED),
        findings=[],
    )
    with pytest.raises(SystemExit):
        module.run(_args(eng, "complete"))
    assert "uncovered_high_risk_file" in capsys.readouterr().err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "fuzz"
