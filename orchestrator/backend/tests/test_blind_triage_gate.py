"""FIX E3 — blind-triage pre-submission gate: durable record + code enforcement.

Two layers are covered here:

1. **The transition-phase gate** (``_blind_triage_blockers`` in
   ``agent/scripts/assess/commands/transition_phase.py``). It mirrors the
   ``missing_variant_pass`` Verify->Exploit gate: it enumerates Medium-or-above
   ACTIVE findings and demands a recorded ``kind='blind_triage_verdict'``
   decision row whose ``verdict`` starts ``Accept`` for each. A finding without
   one appends a hard ``missing_blind_triage`` blocker at the DEFAULT
   ``severity="block"`` — the same enforcement level as ``missing_variant_pass``
   — so ``--force``/``--reason`` already overrides it. These tests drive
   ``module.run`` in-process with a fake ``AssessmentClient`` (the same harness
   shape as ``test_vigil_cli.py``'s transition-phase tests), so they stay
   hermetic and never spin up FastAPI.

2. **The agent-decision round-trip** (``vigil assess agent decision --kind
   blind_triage_verdict --payload-json ...`` -> ``assessment_dispatch_decisions``).
   This one DOES hit the backend through the FastAPI test client to prove the
   verdict persists and is readable filtered by ``kind`` — the read path the
   gate relies on.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_engagements_api import write_engagement


# ---------------------------------------------------------------------------
# In-process gate harness (mirrors test_vigil_cli.py transition-phase tests)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_transition_module(name: str):
    scripts_root = _REPO_ROOT / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = _REPO_ROOT / "agent" / "scripts" / "assess" / "commands" / "transition_phase.py"
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _setup_env(
    monkeypatch, module, tmp_path, *, scope, findings=None, decisions_by_kind=None,
):
    """Write scope.json + wire a fake client.

    ``decisions_by_kind`` maps a kind string to the list returned for a
    ``dispatch-decisions?kind=<kind>&...`` GET. ``record_decision`` appends to
    a captured list so the --force override decision is observable.
    """
    engagement = tmp_path / "agent" / "engagements" / "eng-blind"
    engagement.mkdir(parents=True, exist_ok=True)
    (engagement / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    recorded: list[dict] = []
    decisions_by_kind = decisions_by_kind or {}

    class _Client:
        def __init__(self, *_a, **_k) -> None:
            pass

        def get(self, path: str):
            if path == "findings":
                return findings or []
            if path == "report-readiness":
                return {"ready": True, "blockers": []}
            if path == "application-units/terminal-block":
                return {
                    "skipped": False, "blocking": [], "warned_under_observed": [],
                    "deferred": [], "deferral_count": 0,
                }
            if path.startswith("dispatch-decisions"):
                # path looks like dispatch-decisions?kind=blind_triage_verdict&limit=1000
                for kind, rows in decisions_by_kind.items():
                    if f"kind={kind}" in path:
                        return rows
                return []
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


_MEDIUM_ACTIVE = {
    "slug": "idor-7",
    "severity": "medium",
    "verification_status": "confirmed",
    "workflow_status": "active",
}


def _accept_verdict_row(slug: str, verdict: str = "Accept@P3") -> dict:
    return {
        "id": 1,
        "kind": "blind_triage_verdict",
        "payload": {
            "finding_slug": slug,
            "verdict": verdict,
            "claimed_severity": "medium",
            "weak_points": "none material",
        },
        "surfaced_to_user": False,
        "resolved": False,
    }


# ---------------------------------------------------------------------------
# Gate: blocker present when a Medium-or-above active finding has no verdict
# ---------------------------------------------------------------------------


def test_report_blocks_when_medium_finding_has_no_blind_verdict(monkeypatch, tmp_path, capsys):
    module = _load_transition_module("tp_blind_report_block")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        findings=[_MEDIUM_ACTIVE],
        decisions_by_kind={"blind_triage_verdict": []},
    )
    with pytest.raises(SystemExit):
        module.run(_args(eng, "report"))
    err = capsys.readouterr().err
    assert "missing_blind_triage" in err
    assert "idor-7" in err
    # Phase must NOT have advanced.
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "exploit"


def test_complete_blocks_when_medium_finding_has_no_blind_verdict(monkeypatch, tmp_path, capsys):
    module = _load_transition_module("tp_blind_complete_block")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "report"},
        findings=[_MEDIUM_ACTIVE],
        decisions_by_kind={"blind_triage_verdict": []},
    )
    with pytest.raises(SystemExit):
        module.run(_args(eng, "complete"))
    assert "missing_blind_triage" in capsys.readouterr().err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"


# ---------------------------------------------------------------------------
# Gate: a recorded Accept verdict clears the block
# ---------------------------------------------------------------------------


def test_report_passes_when_accept_verdict_recorded(monkeypatch, tmp_path, capsys):
    module = _load_transition_module("tp_blind_report_ok")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        findings=[_MEDIUM_ACTIVE],
        decisions_by_kind={"blind_triage_verdict": [_accept_verdict_row("idor-7", "Accept@P3")]},
    )
    module.run(_args(eng, "report"))
    assert "missing_blind_triage" not in capsys.readouterr().err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"


def test_non_accept_verdict_does_not_clear_block(monkeypatch, tmp_path, capsys):
    module = _load_transition_module("tp_blind_non_accept")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        findings=[_MEDIUM_ACTIVE],
        # A recorded but non-Accept verdict (e.g. Need-More-Info) is NOT clearance.
        decisions_by_kind={
            "blind_triage_verdict": [_accept_verdict_row("idor-7", "Need-More-Info")]
        },
    )
    with pytest.raises(SystemExit):
        module.run(_args(eng, "report"))
    assert "missing_blind_triage" in capsys.readouterr().err


def test_report_blocks_when_an_exploited_finding_has_no_blind_verdict(
    monkeypatch, tmp_path, capsys
):
    """A Medium+ finding driven to `exploited` is still a submission.

    The gate used to key on ``workflow_status == 'active'`` alone, so the
    findings with the strongest claims — the ones an exploit-developer pass
    proved out and moved to ``exploited`` — were the ones that walked past the
    blind pass. ``export submission`` accepts every reportable workflow status,
    so the gate has to enumerate the same set.
    """
    module = _load_transition_module("tp_blind_exploited")
    exploited = dict(_MEDIUM_ACTIVE, slug="rce-1", severity="critical", workflow_status="exploited")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        findings=[exploited],
        decisions_by_kind={"blind_triage_verdict": []},
    )
    with pytest.raises(SystemExit):
        module.run(_args(eng, "report"))
    err = capsys.readouterr().err
    assert "missing_blind_triage" in err
    assert "rce-1" in err


def test_complete_blocks_when_a_published_finding_has_no_blind_verdict(
    monkeypatch, tmp_path, capsys
):
    """The `complete` backstop has to see `reported` findings.

    Publication moves a finding to ``reported`` BEFORE ``transition-phase
    complete`` runs (phase-8 step e), so an ``active``-only gate could never
    catch an un-triaged submission at the edge that exists to catch it.
    """
    module = _load_transition_module("tp_blind_reported")
    reported = dict(_MEDIUM_ACTIVE, slug="ssrf-3", workflow_status="reported")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "report"},
        findings=[reported],
        decisions_by_kind={"blind_triage_verdict": []},
    )
    with pytest.raises(SystemExit):
        module.run(_args(eng, "complete"))
    assert "missing_blind_triage" in capsys.readouterr().err


def test_draft_and_false_positive_findings_never_block(monkeypatch, tmp_path, capsys):
    """Only submittable workflow states are at risk; a parked or killed row is not."""
    module = _load_transition_module("tp_blind_unsubmittable")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        findings=[
            dict(_MEDIUM_ACTIVE, slug="draft-1", workflow_status="draft"),
            dict(_MEDIUM_ACTIVE, slug="fp-1", workflow_status="false_positive"),
            dict(_MEDIUM_ACTIVE, slug="merged-1", workflow_status="merged"),
        ],
        decisions_by_kind={"blind_triage_verdict": []},
    )
    module.run(_args(eng, "report"))
    assert "missing_blind_triage" not in capsys.readouterr().err


def test_low_severity_finding_does_not_block(monkeypatch, tmp_path, capsys):
    module = _load_transition_module("tp_blind_low_sev")
    low = dict(_MEDIUM_ACTIVE, slug="info-1", severity="low")
    eng, _ = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        findings=[low],
        decisions_by_kind={"blind_triage_verdict": []},
    )
    module.run(_args(eng, "report"))
    assert "missing_blind_triage" not in capsys.readouterr().err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"


# ---------------------------------------------------------------------------
# Gate: --force overrides (same path as missing_variant_pass) and records it
# ---------------------------------------------------------------------------


def test_force_overrides_missing_blind_triage_and_records_decision(monkeypatch, tmp_path, capsys):
    module = _load_transition_module("tp_blind_force")
    eng, recorded = _setup_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        findings=[_MEDIUM_ACTIVE],
        decisions_by_kind={"blind_triage_verdict": []},
    )
    module.run(_args(eng, "report", force=True, reason="accepted-risk per program scope"))
    # Phase advanced under --force.
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"
    # The override was recorded with the missing_blind_triage blocker attached,
    # exactly like missing_variant_pass / depth_unsatisfied_units overrides.
    override = [d for d in recorded if d["kind"] == "forced_transition_override"]
    assert len(override) == 1
    assert any(
        b["kind"] == "missing_blind_triage"
        for b in override[0]["payload"]["overridden_blockers"]
    )


# ---------------------------------------------------------------------------
# Round-trip: the agent-decision persists to assessment_dispatch_decisions and
# is readable filtered by kind (the read path the gate depends on).
# ---------------------------------------------------------------------------

_RT_KEY = "2026-05-01-100000-blind-triage"
_RT_BASE = f"/engagements/{_RT_KEY}/assessment"


def _seed_engagement(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=_RT_KEY)
    response = client.get(f"/engagements/{_RT_KEY}")
    assert response.status_code == 200, response.text


def test_blind_triage_verdict_round_trips_to_dispatch_decisions(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    payload = {
        "finding_slug": "idor-7",
        "verdict": "Accept@P3",
        "claimed_severity": "medium",
        "weak_points": "single-object read, no cross-tenant proof requested",
    }
    create = client.post(
        f"{_RT_BASE}/dispatch-decisions",
        json={"kind": "blind_triage_verdict", "payload": payload, "surfaced_to_user": False},
    )
    assert create.status_code == 201, create.text
    created = create.json()
    assert created["kind"] == "blind_triage_verdict"
    assert created["payload"]["finding_slug"] == "idor-7"
    assert created["payload"]["verdict"] == "Accept@P3"

    # Readable filtered by kind — the exact read the gate issues.
    listed = client.get(f"{_RT_BASE}/dispatch-decisions?kind=blind_triage_verdict")
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 1
    assert rows[0]["payload"]["verdict"] == "Accept@P3"

    # A different kind filter must not return the blind-triage row.
    other = client.get(f"{_RT_BASE}/dispatch-decisions?kind=scope_decision")
    assert other.status_code == 200, other.text
    assert other.json() == []


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"finding_slug": "idor-7"},
        {"verdict": "Accept@P3"},
        {"finding_slug": "idor-7", "verdict": "Looks-Good"},
    ],
)
def test_blind_triage_verdict_rejects_missing_keys_and_unknown_verdicts(
    client, isolate_settings, payload
):
    _seed_engagement(client, isolate_settings)

    response = client.post(
        f"{_RT_BASE}/dispatch-decisions",
        json={"kind": "blind_triage_verdict", "payload": payload},
    )

    assert response.status_code == 422, response.text
    listed = client.get(f"{_RT_BASE}/dispatch-decisions?kind=blind_triage_verdict")
    assert listed.status_code == 200
    assert listed.json() == []
