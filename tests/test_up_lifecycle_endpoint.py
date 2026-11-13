"""`vigil up` starts the backend on the workspace's own lifecycle endpoint,
the same one `vigil orchestrator start` binds."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_cli import orchestrator, up


@pytest.fixture
def started(monkeypatch: pytest.MonkeyPatch) -> list:
    calls: list = []
    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.setattr(up.docker, "container_running", lambda *a, **k: True)
    monkeypatch.setattr(up, "_start_or_restart_runtime", lambda *a, **k: "running")
    monkeypatch.setattr(up, "_start_mitmproxy_if_needed", lambda *a, **k: "running")
    monkeypatch.setattr(up, "_start_oob_if_needed", lambda *a, **k: "disabled")
    monkeypatch.setattr(up, "start_orchestrator", lambda options: calls.append(options))
    return calls


def _start_stack(workspace: Path) -> None:
    up._start_stack(
        workspace, workspace, up.UpOptions(install_root=workspace, no_build=True),
        runner=lambda *a, **k: None, build_runner=lambda *a, **k: None, state={},
    )


def test_up_binds_the_workspace_configured_loopback_port(tmp_path: Path, started: list) -> None:
    (tmp_path / ".orchestrator.env").write_text("ORCHESTRATOR_BASE_URL=http://127.0.0.1:18033\n")
    _start_stack(tmp_path)
    assert [(o.host, o.port, o.allow_existing) for o in started] == [("127.0.0.1", 18033, True)]


def test_up_reuses_the_owned_backend_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, started: list
) -> None:
    pids = tmp_path / "state/runtime/pids"
    pids.mkdir(parents=True)
    (pids / "orchestrator.pid").write_text("4242\n")
    (pids / "orchestrator.json").write_text(json.dumps({
        "pid": 4242, "process_identity": "acme-birth", "workspace": str(tmp_path.resolve()),
        "host": "127.0.0.1", "port": 18035, "process_group": 4242,
    }))
    monkeypatch.setattr(orchestrator, "_process_identity", lambda pid: "acme-birth")
    _start_stack(tmp_path)
    assert [(o.host, o.port) for o in started] == [("127.0.0.1", 18035)]


def test_up_on_a_remote_client_url_keeps_the_local_default(tmp_path: Path, started: list) -> None:
    (tmp_path / ".orchestrator.env").write_text("ORCHESTRATOR_BASE_URL=https://orchestrator.example.com\n")
    _start_stack(tmp_path)
    assert [(o.host, o.port) for o in started] == [
        (orchestrator.DEFAULT_HOST, orchestrator.DEFAULT_PORT)
    ]
