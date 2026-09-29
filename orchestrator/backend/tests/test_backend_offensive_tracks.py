"""Track gates use durable enabled tracks rather than a combined type label."""

import json
from types import SimpleNamespace

from app.services.engagement_tracks import track_phases
from app.services.state_manager.app_units import _is_web_engagement


def test_canonical_track_phases_override_legacy_phase_fields():
    assert track_phases({
        "engagement_type": "offensive", "current_phase": "complete",
        "tracks": {"web": {"phase": "recon"}, "code": {"phase": "hunt"}},
    }) == {"web": "recon", "code": "hunt"}


def test_offensive_scope_without_valid_tracks_does_not_infer_web():
    assert track_phases({"engagement_type": "offensive"}) == {}


def test_web_gate_requires_enabled_web_track(tmp_path):
    root = tmp_path / "engagement"
    root.mkdir()
    (root / "scope.json").write_text(json.dumps({
        "engagement_type": "offensive", "tracks": {"code": {"phase": "hunt"}},
    }), encoding="utf-8")
    engagement = SimpleNamespace(engagement_type="offensive", engagement_root=str(root))

    assert _is_web_engagement(engagement) is False
