from __future__ import annotations

from pathlib import Path

import pytest

from vigil_cli import orchestrator, runtime
from vigil_cli.docker import DockerResult


def test_runtime_build_reads_application_inputs_not_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    application = tmp_path / "application"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (application / "orchestrator").mkdir(parents=True)
    (workspace / ".env").write_text("PRIVATE_TEST_VALUE=do-not-stage\n")
    for source in runtime.runtime_image_inputs(application):
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(source.name)
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    contexts: list[set[str]] = []

    def build(argv: list[str], **_: object) -> DockerResult:
        context = Path(argv[-1])
        contexts.append({path.relative_to(context).as_posix() for path in context.rglob("*") if path.is_file()})
        assert not (context / ".env").exists()
        return DockerResult(0, "", "")

    runtime.build_runtime(workspace, runner=build, daemon_runner=lambda *_args, **_kwargs: DockerResult(0, "", ""))

    assert contexts == [{source.relative_to(application).as_posix() for source in runtime.runtime_image_inputs(application)}]
    assert {path.name for path in workspace.iterdir()} == {".env"}


def test_orchestrator_launch_reads_application_and_pins_private_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    application = tmp_path / "application"
    workspace = tmp_path / "workspace"
    (application / "agent").mkdir(parents=True)
    (application / "orchestrator" / "backend").mkdir(parents=True)
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    monkeypatch.setattr(orchestrator, "_frontend_build_needed", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(orchestrator, "_report_build_needed", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(orchestrator, "_check_port_available", lambda *_args: None)
    observed: dict[str, object] = {}
    monkeypatch.setattr(orchestrator, "_sync_backend_environment", lambda root, **kwargs: observed.update(sync_root=root, sync_env=kwargs["env"]))

    class ExecIntercepted(Exception):
        pass

    def launch(_command: str, argv: list[str], env: dict[str, str]) -> None:
        observed.update(argv=argv, env=env, cwd=Path.cwd())
        raise ExecIntercepted

    monkeypatch.setattr(orchestrator.os, "execvpe", launch)
    monkeypatch.setattr(orchestrator.os, "chdir", lambda path: observed.update(chdir=path))
    with pytest.raises(ExecIntercepted):
        orchestrator.start_orchestrator(orchestrator.OrchestratorOptions(install_root=workspace, foreground=True))

    env = observed["env"]
    assert isinstance(env, dict)
    assert env["VIGIL_INSTALL_DIR"] == str(workspace)
    assert env["VIGIL_APPLICATION_DIR"] == str(application)
    assert env["VIGIL_ENGAGEMENTS_DIR"] == str(workspace / "engagements")
    assert env["VIGIL_DATA_DIR"] == str(workspace / "state")
    assert Path(env["UV_PROJECT_ENVIRONMENT"]).is_relative_to(workspace / "cache")
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert observed["chdir"] == application / "orchestrator/backend"
    assert observed["sync_root"] == application
    assert observed["sync_env"] == env
    argv = observed["argv"]
    assert argv[:4] == [str(Path(env["UV_PROJECT_ENVIRONMENT"]) / "bin/python"), "-m", "uvicorn", "app.main:app"]


def test_proxy_context_pins_scope_parser_from_explicit_application(tmp_path: Path) -> None:
    from vigil_cli import mitmproxy

    application = tmp_path / "application"
    for relative in ("agent/docker/mitmproxy/Dockerfile", "agent/scripts/assess/cli.py", "agent/scripts/proxy_addon.py", "cli/vigil_cli/scope_entries.py"):
        source = application / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(f"release input: {relative}")
    with mitmproxy._proxy_build_context(application) as context:
        assert (context / "vigil_cli/scope_entries.py").read_bytes() == (application / "cli/vigil_cli/scope_entries.py").read_bytes()
    assert application / "cli/vigil_cli/scope_entries.py" in mitmproxy.mitmproxy_image_inputs(application)


@pytest.mark.parametrize("builder", [orchestrator._build_frontend, orchestrator._build_report])
def test_packaged_release_build_does_not_require_node_or_mutate_assets(tmp_path, monkeypatch, builder):
    (tmp_path / "bundle.json").write_text('{"schema_version":1}')
    node_calls = []
    monkeypatch.setattr(orchestrator, "_npm_ci", lambda root: node_calls.append(root))
    monkeypatch.setattr(orchestrator.subprocess, "run", lambda *args, **kwargs: None)
    with pytest.raises(SystemExit, match="prebuilt"):
        builder(tmp_path)
    assert node_calls == []
