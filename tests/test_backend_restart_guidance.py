"""Startup recovery explains backend reloads and targets the intended workspace."""
import json

import pytest

from vigil_cli import engagements, paths, preflight, restart_manifest


@pytest.mark.parametrize("implicit", [True, False])
def test_stale_backend_advice_scopes_restart_and_explains_up(tmp_path, monkeypatch, implicit):
    workspace = tmp_path / "acme workspace"
    monkeypatch.setattr(paths, "resolve_install_root", lambda: workspace if implicit else tmp_path / "other")
    monkeypatch.setattr(engagements, "_backend_request", lambda *_: (200, json.dumps({}).encode(), "", None))
    monkeypatch.setattr(restart_manifest, "backend_state_from_readiness", lambda *_:
                        restart_manifest.ConsumerState("backend", "backend", "stale", "", "release changed"))
    with pytest.raises(SystemExit) as error:
        preflight._ensure_backend_freshness(workspace, "http://127.0.0.1:18000")
    advice = str(error.value)
    expected = "vigil orchestrator restart" if implicit else f"vigil --root '{workspace}' orchestrator restart"
    assert f"`{expected}`" in advice
    assert "vigil up" in advice and "reuse" in advice
    if not implicit:
        assert "workspace" in advice
