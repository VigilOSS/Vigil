"""Canonical offensive tracks drive assessment commands independently."""

import json
from types import SimpleNamespace

from assess.commands import check_phase_readiness, code_coverage, transition_phase
from assess.lib.kali_output import _engagement_type
from assess.lib.tracks import track_phases


def test_transition_phase_selects_enabled_track_from_canonical_scope():
    scope = {"engagement_type": "offensive", "tracks": {
        "web": {"phase": "recon"}, "code": {"phase": "hunt"},
    }}

    assert transition_phase._phase_track(scope, "classify-map", "auto") == "code"


def test_transition_phase_updates_only_selected_canonical_track(monkeypatch, tmp_path):
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({
        "engagement_type": "offensive", "status": "in_progress",
        "tracks": {"web": {"phase": "recon"}, "code": {"phase": "hunt"}},
    }), encoding="utf-8")
    monkeypatch.setattr(transition_phase, "load_config", lambda *_: SimpleNamespace(
        engagement_dir=str(tmp_path), engagement_key="eng", base_url="http://unused"
    ))
    monkeypatch.setattr(transition_phase, "_check_preconditions", lambda *_: [])

    transition_phase.run(SimpleNamespace(
        engagement_dir=tmp_path, target_phase="verify-variant", track="code",
        force=False, reason="",
    ))

    updated = json.loads(scope_path.read_text(encoding="utf-8"))
    assert updated["tracks"] == {
        "web": {"phase": "recon"}, "code": {"phase": "verify-variant"},
    }
    assert updated["status"] == "in_progress"


def test_offensive_scope_without_tracks_does_not_infer_web():
    assert track_phases({"engagement_type": "offensive"}) == {}


def test_code_coverage_uses_canonical_code_phase(tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps({
        "engagement_type": "offensive",
        "tracks": {"web": {"phase": "recon"}, "code": {"phase": "hunt"}},
    }), encoding="utf-8")

    assert code_coverage._next_code_gate(str(tmp_path)) == "verify-variant"


def test_code_only_canonical_scope_skips_web_probe_emission(tmp_path):
    (tmp_path / "scope.json").write_text(json.dumps({
        "engagement_type": "offensive", "tracks": {"code": {"phase": "hunt"}},
    }), encoding="utf-8")

    assert _engagement_type(tmp_path) == "code"


def test_check_phase_readiness_routes_code_only_scope_to_code_gate(
    monkeypatch, tmp_path, capsys
):
    (tmp_path / "scope.json").write_text(json.dumps({
        "engagement_type": "offensive", "tracks": {"code": {"phase": "hunt"}},
    }), encoding="utf-8")
    monkeypatch.setattr(check_phase_readiness, "load_config", lambda *_: SimpleNamespace(
        engagement_dir=str(tmp_path), engagement_key="code-eng", base_url="http://unused"
    ))

    try:
        check_phase_readiness.run(SimpleNamespace(engagement_dir=tmp_path, phase="verify"))
    except SystemExit as exc:
        assert exc.code == 1
    else:
        raise AssertionError("code-only scope must not fetch web readiness")
    assert "code-coverage --require-transition-ready verify-variant" in capsys.readouterr().err
