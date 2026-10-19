"""Phase recency is durable work metadata, not a file modification time."""
from datetime import datetime, timezone
import json
from types import SimpleNamespace

import pytest

from assess.commands import transition_phase


@pytest.mark.parametrize(("current", "target", "force", "reason"), [
    ("recon", "collect", False, ""),
    ("collect", "recon", False, "Revisit Acme inventory"),
    ("recon", "collect", True, "Approved ordinary gate override"),
])
def test_real_phase_change_records_utc_activity_and_preserves_other_track(
    tmp_path, monkeypatch, current, target, force, reason,
):
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({"engagement_type": "offensive", "status": "in_progress",
        "tracks": {"web": {"phase": current}, "code": {"phase": "hunt"}}}))
    monkeypatch.setattr(transition_phase, "load_config", lambda *_: SimpleNamespace(engagement_dir=str(tmp_path)))
    monkeypatch.setattr(transition_phase, "_check_preconditions", lambda *a, **kw: [])
    monkeypatch.setattr(transition_phase, "_record_transition_decision", lambda *a, **kw: None)
    before = datetime.now(timezone.utc)
    transition_phase.run(SimpleNamespace(engagement_dir=str(tmp_path), target_phase=target,
        track="web", force=force, reason=reason))
    after = datetime.now(timezone.utc)
    scope = json.loads(scope_path.read_text())
    changed = datetime.fromisoformat(scope["phase_changed_at"].replace("Z", "+00:00"))
    assert before <= changed <= after
    assert scope["tracks"] == {"web": {"phase": target}, "code": {"phase": "hunt"}}


def test_same_phase_keeps_existing_activity_clock(tmp_path, monkeypatch):
    scope_path = tmp_path / "scope.json"
    clock = "2026-01-01T01:02:03Z"
    scope_path.write_text(json.dumps({"engagement_type": "offensive", "status": "in_progress",
        "phase_changed_at": clock, "tracks": {"web": {"phase": "recon"}}}))
    monkeypatch.setattr(transition_phase, "load_config", lambda *_: SimpleNamespace(engagement_dir=str(tmp_path)))
    monkeypatch.setattr(transition_phase, "_check_preconditions", lambda *a, **kw: [])
    transition_phase.run(SimpleNamespace(engagement_dir=str(tmp_path), target_phase="recon",
        track="web", force=False, reason=""))
    assert json.loads(scope_path.read_text())["phase_changed_at"] == clock
