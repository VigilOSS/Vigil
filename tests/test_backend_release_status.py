from __future__ import annotations

import pytest

from vigil_cli import status
from vigil_cli.docker import DockerResult


@pytest.fixture
def backend_status(tmp_path, monkeypatch):
    application = tmp_path / "application"
    (application / "agent").mkdir(parents=True)
    (application / "orchestrator").mkdir()
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    monkeypatch.setattr(status, "orchestrator_status", lambda _: "running")
    monkeypatch.setattr(status, "_binary_check", lambda name: status.Check(name, "MISSING"))
    return root, application


@pytest.mark.parametrize("release", ["legacy", "retained"])
def test_status_reports_backend_release_restart_even_when_old_backend_reports_current(
    backend_status, monkeypatch, capsys, release,
):
    root, application = backend_status
    runtime = {"install_root": str(root), "restart_required": False}
    if release == "retained":
        runtime["application_root"] = str(root.parent / "old-application")
    readiness = {"reachable": True, "status": "ready", "http_status": 200, "backend_runtime": runtime}
    probes = []

    def snapshot(workspace):
        probes.append(workspace)
        return True, readiness

    monkeypatch.setattr(status, "_orchestrator_readyz_snapshot", snapshot)
    result = status.collect_status(root, runner=lambda *_args, **_kwargs: DockerResult(1, "", ""))
    status.print_status(result)
    assert "backend restart required" in capsys.readouterr().out
    assert result["orchestrator"]["backend_runtime_state"]["state"] == "stale"
    assert result["orchestrator"]["readiness"]["backend_runtime"]["restart_required"] is False
    assert probes == [root]


@pytest.mark.parametrize("release", ["legacy", "retained"])
def test_doctor_reports_backend_release_restart_without_an_extra_readiness_probe(
    backend_status, monkeypatch, release,
):
    root, application = backend_status
    runtime = {"install_root": str(root), "restart_required": False}
    if release == "retained":
        runtime["application_root"] = str(root.parent / "old-application")
    readiness = {"reachable": True, "status": "ready", "http_status": 200, "backend_runtime": runtime}
    probes = []

    def snapshot(workspace):
        probes.append(workspace)
        return True, readiness

    monkeypatch.setattr(status, "_orchestrator_readyz_snapshot", snapshot)
    rows = {row.name: row for row in status.collect_doctor_checks(root)}
    assert rows["orchestrator-health"].status == "OK"
    assert rows["backend-runtime"].status == "STALE"
    assert "vigil orchestrator restart" in rows["backend-runtime"].detail
    assert probes == [root]


def test_status_and_doctor_name_why_the_application_is_unavailable(backend_status, monkeypatch, capsys):
    root, application = backend_status
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(root / "missing-application"))
    monkeypatch.setattr(status, "_orchestrator_readyz_snapshot", lambda _workspace: (False, {}))
    status.print_status(status.collect_status(root, runner=lambda *_args, **_kwargs: DockerResult(1, "", "")))
    assert "Invalid Vigil application directory" in capsys.readouterr().out
    rows = {row.name: row for row in status.collect_doctor_checks(root)}
    assert rows["application"].status == "MISSING"
    assert "Invalid Vigil application directory" in rows["application"].detail
