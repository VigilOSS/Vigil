from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from vigil_cli import remediation, restart_manifest


@pytest.mark.parametrize("state", ["stale", "current", "unknown", "not-running"])
def test_remediation_reports_backend_drift_without_polluting_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], state: str,
) -> None:
    monkeypatch.setattr(remediation, "_project", lambda *_: (tmp_path, {}))
    monkeypatch.setattr(remediation, "_api", lambda *_: {"cases": []})
    monkeypatch.setattr(restart_manifest, "backend_state", lambda *a, **kw: restart_manifest.ConsumerState(
        key="backend", label="orchestrator backend", state=state,
        remedy="vigil orchestrator restart" if state == "stale" else "",
        detail="changed inputs: app/services/remediation.py" if state == "stale" else "",
    ))
    args = argparse.Namespace(engagement_key="acme", remediation_command="list", json=True)
    remediation.run_remediation(args, tmp_path)
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"cases": []}
    if state == "stale":
        assert "backend restart required" in captured.err
        assert "app/services/remediation.py" in captured.err
        assert "orchestrator restart" in captured.err
    else:
        assert captured.err == ""


@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:18000", "https://backend.example.com"])
def test_restart_warning_targets_backend_owner(tmp_path, monkeypatch, capsys, endpoint):
    monkeypatch.setattr(remediation, "_project", lambda *_: (tmp_path, {}))
    monkeypatch.setattr(remediation, "_api", lambda *_: {"cases": []})
    monkeypatch.setattr(remediation, "resolve_orchestrator_base_url", lambda *_: endpoint)
    monkeypatch.setattr(restart_manifest, "backend_state", lambda *a, **kw: restart_manifest.ConsumerState(
        key="backend", label="orchestrator backend", state="stale",
        remedy="vigil orchestrator restart", detail="retained earlier application release",
    ))
    remediation.run_remediation(argparse.Namespace(engagement_key="acme", remediation_command="list", json=True), tmp_path)
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"cases": []}
    if endpoint.startswith("https"):
        assert endpoint in captured.err and "owning host" in captured.err
    else:
        assert "--root" in captured.err and str(tmp_path) in captured.err


@pytest.mark.parametrize("remote_drift", [True, False])
def test_backend_probe_uses_engagement_endpoint_and_remote_runtime(tmp_path, monkeypatch, remote_drift):
    from vigil_cli import paths, status

    engagement = tmp_path / "engagement"
    engagement.mkdir()
    (engagement / ".orchestrator.env").write_text("ORCHESTRATOR_BASE_URL=https://backend.example.com\n")
    assert paths.resolve_orchestrator_base_url(tmp_path, engagement) == "https://backend.example.com"
    probes = []
    def snapshot(root, *, engagement_dir=None):
        probes.append((root, engagement_dir))
        return True, {"reachable": True, "backend_runtime": {"install_root": "/remote/acme",
                     "application_root": "/remote/release", "restart_required": remote_drift}}
    monkeypatch.setattr(status, "_orchestrator_readyz_snapshot", snapshot)
    state = restart_manifest.backend_state(tmp_path, engagement_dir=engagement)
    assert probes == [(tmp_path, engagement)]
    assert state.state == ("stale" if remote_drift else "unknown")
