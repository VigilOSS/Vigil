"""Approval recency follows actual scope changes, never ordinary reads/repeats."""
import json
from types import SimpleNamespace

import pytest

from assess.commands import approve_exploit


@pytest.mark.parametrize("decision,previous,changed", [
    ("all", {"exploit_review_state": "pending", "approved_targets": []}, True),
    ("defer", {"exploit_review_state": "approved", "approved_targets": ["*"]}, True),
    ("all", {"exploit_review_state": "approved", "approved_targets": ["*"]}, False),
])
def test_approval_clock_changes_only_with_actual_approval_state(tmp_path, monkeypatch, decision, previous, changed):
    old = "2026-01-01T00:00:00+00:00"
    scope = {**previous, "exploit_review_changed_at": old}
    (tmp_path / "scope.json").write_text(json.dumps(scope))
    monkeypatch.setattr(approve_exploit, "load_config", lambda _: SimpleNamespace(engagement_dir=tmp_path))
    approve_exploit.run(SimpleNamespace(engagement_dir=tmp_path, decision=decision, slugs=[]))
    updated = json.loads((tmp_path / "scope.json").read_text())
    assert (updated["exploit_review_changed_at"] != old) is changed
    assert updated["approved_targets"] == (["*"] if decision == "all" else [])
