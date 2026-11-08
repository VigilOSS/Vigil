from __future__ import annotations

import io
import json
from urllib.error import HTTPError

import pytest

from vigil_cli import orchestrator, restart_manifest


@pytest.fixture
def owned_backend(tmp_path, monkeypatch):
    directory = tmp_path / "state/runtime/pids"
    directory.mkdir(parents=True)
    (directory / "orchestrator.pid").write_text("4242\n")
    (directory / "orchestrator.json").write_text(json.dumps({
        "pid": 4242, "process_identity": "acme-birth", "workspace": str(tmp_path),
        "host": "127.0.0.1", "port": 18000, "process_group": 4242,
    }))
    monkeypatch.setattr(orchestrator, "_process_identity", lambda _pid: "acme-birth")
    monkeypatch.setattr(orchestrator, "_port_in_use", lambda *_args: True)
    return tmp_path


@pytest.mark.parametrize("failure", [TimeoutError("timed out"), ConnectionRefusedError("refused")])
def test_owned_backend_is_not_reported_running_when_readiness_is_unreachable(
    owned_backend, monkeypatch, failure,
):
    calls = []

    def unavailable(url, *, timeout):
        calls.append((url, timeout))
        raise failure

    monkeypatch.setattr(orchestrator.urllib.request, "urlopen", unavailable)
    result = orchestrator.orchestrator_status_payload(owned_backend)

    assert result["state"] == "unresponsive"
    assert result["ownership"] == "owned"
    assert result["pid"] == 4242
    assert result["responsive"] is False
    assert "/readyz" in result["detail"]
    assert "restart" in result["detail"]
    assert calls == [("http://127.0.0.1:18000/readyz", 1.0)]


def test_responding_backend_with_unready_database_is_distinct_from_timeout(
    owned_backend, monkeypatch,
):
    def unready(url, *, timeout):
        raise HTTPError(url, 503, "not ready", {}, io.BytesIO(b'{"status":"not_ready"}'))

    monkeypatch.setattr(orchestrator.urllib.request, "urlopen", unready)
    result = orchestrator.orchestrator_status_payload(owned_backend)

    assert result["state"] == "not_ready"
    assert result["responsive"] is True
    assert result["ready"] is False
    assert result["ownership"] == "owned"


def test_readiness_response_is_required_to_report_owned_backend_running(owned_backend, monkeypatch):
    class Ready(io.BytesIO):
        status = 200

    monkeypatch.setattr(orchestrator.urllib.request, "urlopen", lambda *_a, **_k: Ready(b'{"status":"ready"}'))
    result = orchestrator.orchestrator_status_payload(owned_backend)

    assert result["state"] == "running"
    assert result["responsive"] is True
    assert result["ready"] is True


def test_unresponsive_owned_process_can_still_be_stopped(owned_backend, monkeypatch):
    monkeypatch.setattr(orchestrator, "orchestrator_status_payload", lambda *_a, **_k: {
        "state": "unresponsive", "ownership": "owned", "pid": 4242,
        "process_identity": "acme-birth", "process_group": 4242,
        "pid_file": str(owned_backend / "state/runtime/pids/orchestrator.pid"),
        "host": "127.0.0.1", "port": 18000,
    })
    signals = []
    monkeypatch.setattr(orchestrator, "_signal_process_group", lambda *args: signals.append(args))
    monkeypatch.setattr(orchestrator, "_wait_for_pid_exit", lambda *_a, **_k: True)
    monkeypatch.setattr(orchestrator, "_wait_for_port_release", lambda *_a, **_k: True)

    orchestrator.stop_orchestrator(owned_backend)

    assert signals == [(4242, orchestrator.signal.SIGTERM)]


def test_unresponsive_process_is_retained_in_restart_diagnostics(owned_backend, monkeypatch):
    monkeypatch.setattr(orchestrator, "orchestrator_status_payload", lambda *_a, **_k: {
        "state": "unresponsive", "ownership": "owned", "pid": 4242, "port_in_use": True,
    })
    result = restart_manifest.backend_state_from_readiness(
        owned_backend, {"reachable": False, "unreachable_reason": "timeout"},
    )
    assert "PID 4242" in result.detail
    assert "running" in result.detail
