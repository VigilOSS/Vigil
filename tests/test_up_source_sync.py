from pathlib import Path
import os

import pytest

from vigil_cli import up


def test_up_stops_when_workspace_initialization_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(up, "resolve_application_root", lambda *_args, **_kwargs: tmp_path)
    monkeypatch.setattr(up, "initialize_workspace", lambda *_args, **_kwargs: (_ for _ in ()).throw(SystemExit("initialization failed")))
    startup_calls: list[str] = []
    def unexpected_startup(*_args, **_kwargs) -> bool:
        startup_calls.append("runtime")
        raise AssertionError("startup continued after workspace initialization failure")

    monkeypatch.setattr(up.docker, "container_running", unexpected_startup)

    with pytest.raises(SystemExit, match="initialization failed"):
        up.run_up(up.UpOptions(install_root=tmp_path, source_root=tmp_path))

    assert startup_calls == []


def test_up_pins_one_application_for_stack_and_restores_caller_environment(monkeypatch, tmp_path):
    application = tmp_path / "application"
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", "original-application")
    monkeypatch.setattr(up, "resolve_application_root", lambda *_args, **_kwargs: application)
    initialization = []
    monkeypatch.setattr(up, "initialize_workspace", lambda root, **kwargs: initialization.append((root, kwargs)))

    def start(root, release, options, **kwargs):
        assert root == workspace
        assert release == application
        assert os.environ["VIGIL_APPLICATION_DIR"] == str(application)
        raise SystemExit("startup failed")

    monkeypatch.setattr(up, "_start_stack", start)
    with pytest.raises(SystemExit, match="startup failed"):
        up.run_up(up.UpOptions(install_root=workspace, source_root=application))
    assert initialization == [(workspace, {"application_root": application})]
    assert os.environ["VIGIL_APPLICATION_DIR"] == "original-application"
