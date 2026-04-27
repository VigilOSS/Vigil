from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo_root / "src"))


def _copy_agent_fixture(agent_root: Path, install_root: Path) -> Path:
    target_agent = install_root / "agent"
    target_agent.mkdir(parents=True)
    for name in ("scripts", ".codex", ".claude"):
        shutil.copytree(agent_root / name, target_agent / name)
    for name in ("AGENTS.md", "CLAUDE.md", "SKILL.md"):
        shutil.copy2(agent_root / name, target_agent / name)
    (target_agent / "engagements").mkdir()
    return target_agent


def _write_marker_database(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE marker (value TEXT PRIMARY KEY)")
        connection.execute("INSERT INTO marker (value) VALUES (?)", (value,))


def test_engagement_create_web_writes_scope_launchers_and_list_entry(tmp_path: Path) -> None:
    from ai_threat_hunting_cli.engagements import CreateEngagementOptions, create_engagement, list_engagements

    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
            hosts=["app.example.com", "admin.example.com"],
            auth_mode="manual",
            exploit_policy="selected",
            skip_permissions=True,
        )
    )

    scope = json.loads((created.path / "scope.json").read_text(encoding="utf-8"))
    auth = json.loads((created.path / "auth.json").read_text(encoding="utf-8"))
    manifest = json.loads((created.path / "engagement.json").read_text(encoding="utf-8"))

    assert created.path.parent == install_root / "agent" / "engagements"
    assert scope["engagement_type"] == "web"
    assert scope["hostname"] == "app.example.com"
    assert scope["hosts"] == ["app.example.com", "admin.example.com"]
    assert scope["exploit_policy"] == "selected"
    assert auth["mode"] == "manual"
    assert auth["state"] == "missing"
    assert manifest["key"] == created.key
    assert (created.path / "cases.db").exists()
    assert (created.path / "start_codex.sh").exists()
    assert (created.path / "start_claude.sh").exists()
    assert "codex --full-auto" in (created.path / "start_codex.sh").read_text(encoding="utf-8")

    rows = list_engagements(install_root)
    assert [row.key for row in rows] == [created.key]
    assert rows[0].target == "https://app.example.com"


def test_engagement_create_snapshots_backend_data_dir_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli.engagements import CreateEngagementOptions, create_engagement

    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    custom_data = tmp_path / "backend-data"
    default_data = install_root / "orchestrator" / "backend" / "data"
    _write_marker_database(custom_data / "orchestrator.sqlite3", "custom")
    _write_marker_database(default_data / "orchestrator.sqlite3", "default")
    monkeypatch.delenv("AI_THREAT_HUNTING_DATA_DIR", raising=False)
    monkeypatch.setenv("REDTEAM_ORCHESTRATOR_DATA_DIR", str(custom_data))

    create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
        )
    )

    custom_snapshots = sorted(custom_data.glob("orchestrator.sqlite3.bak.*"))
    assert len(custom_snapshots) == 1
    assert not list(default_data.glob("orchestrator.sqlite3.bak.*"))
    with sqlite3.connect(custom_snapshots[0]) as connection:
        assert connection.execute("SELECT value FROM marker").fetchone() == ("custom",)


def test_resolve_source_root_prefers_cached_source_before_install_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import paths as paths_module

    install_root = tmp_path / "install"
    cached_source = tmp_path / "cached-source"
    for root in (install_root, cached_source):
        (root / "agent").mkdir(parents=True)
        (root / "orchestrator").mkdir()
    monkeypatch.delenv("AI_THREAT_HUNTING_SOURCE_DIR", raising=False)
    monkeypatch.setattr(paths_module, "get_config_value", lambda *args: None)
    monkeypatch.setattr(paths_module, "find_repo_root", lambda start=None: None)
    monkeypatch.setattr(paths_module, "_ensure_cached_source", lambda: cached_source)

    assert paths_module.resolve_source_root(install_root=install_root) == cached_source.resolve()


def test_install_preserves_local_state_and_replaces_managed_files(tmp_path: Path) -> None:
    from ai_threat_hunting_cli.install import InstallOptions, install_from_source

    source_root = tmp_path / "source"
    install_root = tmp_path / "install"
    for root in (source_root, install_root):
        (root / "agent" / "engagements" / "existing").mkdir(parents=True)
        (root / "orchestrator" / "backend" / "data").mkdir(parents=True)
        (root / "docker").mkdir()
    (source_root / "README.md").write_text("new readme\n", encoding="utf-8")
    (source_root / "agent" / "AGENTS.md").write_text("managed agent\n", encoding="utf-8")
    (source_root / "orchestrator" / "backend" / "app.py").write_text("managed backend\n", encoding="utf-8")
    (source_root / "docker" / "callback_listener.py").write_text("managed docker\n", encoding="utf-8")

    marker = install_root / "agent" / "engagements" / "existing" / "scope.json"
    marker.write_text('{"target":"https://old.example"}\n', encoding="utf-8")
    database = install_root / "orchestrator" / "backend" / "data" / "orchestrator.sqlite3"
    database.write_text("db", encoding="utf-8")
    (install_root / "README.md").write_text("old readme\n", encoding="utf-8")
    (install_root / "agent" / "old-managed.txt").write_text("remove me\n", encoding="utf-8")
    legacy_installer = install_root / ("install" + ".sh")
    legacy_installer.write_text("old installer\n", encoding="utf-8")

    install_from_source(
        InstallOptions(
            source_root=source_root,
            install_root=install_root,
            dry_run=False,
            force_image=False,
            verify_docker_image=False,
        )
    )

    assert (install_root / "README.md").read_text(encoding="utf-8") == "new readme\n"
    assert (install_root / "AGENTS.md").read_text(encoding="utf-8") == "managed agent\n"
    assert (install_root / "agent" / "AGENTS.md").read_text(encoding="utf-8") == "managed agent\n"
    assert marker.exists()
    assert database.read_text(encoding="utf-8") == "db"
    assert not (install_root / "agent" / "old-managed.txt").exists()
    assert not legacy_installer.exists()


def test_runtime_start_uses_expected_docker_mounts(tmp_path: Path) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)
    commands: list[list[str]] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "", "")
        if argv[:3] == ["docker", "ps", "-a"]:
            return DockerResult(0, "", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, f"{install_root / '.runtime-data'} -> /data\n{install_root / 'agent' / 'engagements'} -> /engagements\n", "")
        if argv[:2] == ["docker", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        return DockerResult(0, "", "")

    start_runtime(RuntimeOptions(install_root=install_root, recreate=False), runner=runner, validate_tools=False)

    run_command = next(command for command in commands if command[:3] == ["docker", "run", "-d"])
    assert "-v" in run_command
    assert f"{install_root / '.runtime-data'}:/data" in run_command
    assert f"{install_root / 'agent' / 'engagements'}:/engagements" in run_command
    assert "--add-host=host.docker.internal:host-gateway" in run_command
    assert "ORCHESTRATOR_BASE_URL=http://host.docker.internal:18000" in run_command


def test_runtime_start_grants_sys_ptrace_capability(tmp_path: Path) -> None:
    """B2: --strace inside the container needs CAP_SYS_PTRACE; the docker-run argv
    must request it explicitly so ptrace operations don't fail with EPERM."""
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)
    commands: list[list[str]] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "", "")
        if argv[:3] == ["docker", "ps", "-a"]:
            return DockerResult(0, "", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, f"{install_root / '.runtime-data'} -> /data\n{install_root / 'agent' / 'engagements'} -> /engagements\n", "")
        if argv[:2] == ["docker", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        return DockerResult(0, "", "")

    start_runtime(RuntimeOptions(install_root=install_root, recreate=False), runner=runner, validate_tools=False)

    run_command = next(command for command in commands if command[:3] == ["docker", "run", "-d"])
    assert "--cap-add=SYS_PTRACE" in run_command
    assert "--cap-add=NET_RAW" in run_command
    assert "--cap-add=NET_ADMIN" in run_command


def test_runtime_start_retries_without_host_gateway_when_docker_rejects_flag(tmp_path: Path) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)
    commands: list[list[str]] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "", "")
        if argv[:3] == ["docker", "ps", "-a"]:
            return DockerResult(0, "", "")
        if argv[:3] == ["docker", "run", "-d"] and "--add-host=host.docker.internal:host-gateway" in argv:
            return DockerResult(125, "", "invalid host-gateway")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, f"{install_root / '.runtime-data'} -> /data\n{install_root / 'agent' / 'engagements'} -> /engagements\n", "")
        if argv[:2] == ["docker", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        return DockerResult(0, "", "")

    start_runtime(RuntimeOptions(install_root=install_root), runner=runner, validate_tools=False)

    run_commands = [command for command in commands if command[:3] == ["docker", "run", "-d"]]
    assert len(run_commands) == 2
    assert "--add-host=host.docker.internal:host-gateway" in run_commands[0]
    assert "--add-host=host.docker.internal:host-gateway" not in run_commands[1]


def test_mitmproxy_docker_start_builds_and_mounts_engagement(tmp_path: Path) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.mitmproxy import MitmproxyOptions, start_proxy

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    (engagement / ".orchestrator.env").write_text(
        "ORCHESTRATOR_BASE_URL=http://127.0.0.1:18000\n",
        encoding="utf-8",
    )
    commands: list[list[str]] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(1, "", "")
        if argv[:4] == ["docker", "inspect", "--type", "image"]:
            return DockerResult(1, "", "")
        if argv[:3] == ["docker", "images", "-q"]:
            return DockerResult(0, "", "")
        if argv[:3] == ["docker", "ps", "-q"]:
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    start_proxy(
        MitmproxyOptions(install_root=install_root, engagement_dir=engagement, mode="docker", port=9090),
        runner=runner,
        verify_port=False,
    )

    build_command = next(command for command in commands if command[:3] == ["docker", "build", "-t"])
    run_command = next(command for command in commands if command[:3] == ["docker", "run", "-d"])
    assert str(install_root / "agent" / "docker" / "mitmproxy" / "Dockerfile") in build_command
    assert str(install_root / "agent") == build_command[-1]
    assert "--add-host=host.docker.internal:host-gateway" in run_command
    assert f"127.0.0.1:9090:8080" in run_command
    assert f"{engagement}:/engagement" in run_command
    assert "ORCHESTRATOR_BASE_URL=http://host.docker.internal:18000" in run_command


def test_mitmproxy_start_polls_port_until_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import mitmproxy as mitmproxy_module
    from ai_threat_hunting_cli.docker import DockerResult

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    (engagement / ".orchestrator.env").write_text(
        "ORCHESTRATOR_BASE_URL=http://127.0.0.1:18000\n",
        encoding="utf-8",
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "-q"]:
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    ready_sequence = iter([False, False, True])
    attempts: list[tuple[str, int]] = []

    def fake_port_open(host: str, port: int) -> bool:
        attempts.append((host, port))
        return next(ready_sequence)

    monkeypatch.setattr(mitmproxy_module, "_PORT_WAIT_ATTEMPTS", 3, raising=False)
    monkeypatch.setattr(mitmproxy_module, "_PORT_WAIT_DELAY_SECONDS", 0, raising=False)
    monkeypatch.setattr(mitmproxy_module, "_port_open", fake_port_open)

    mitmproxy_module.start_proxy(
        mitmproxy_module.MitmproxyOptions(install_root=install_root, engagement_dir=engagement, port=9090),
        runner=runner,
    )

    assert attempts == [("127.0.0.1", 9090)] * 3


def test_mitmproxy_start_without_arg_uses_current_engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_start_proxy(options: object) -> None:
        captured["engagement_dir"] = options.engagement_dir  # type: ignore[attr-defined]

    monkeypatch.chdir(engagement)
    monkeypatch.setattr(main_module, "start_proxy", fake_start_proxy)

    main_module.main(["--root", str(install_root), "mitmproxy", "start"])

    assert captured["engagement_dir"] == engagement


def test_orchestrator_foreground_execs_from_install_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import orchestrator as orchestrator_module

    install_root = tmp_path / "install"
    frontend_dist = install_root / "orchestrator" / "frontend" / "dist"
    frontend_dist.mkdir(parents=True)
    (frontend_dist / "index.html").write_text("ok", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.chdir(outside)
    captured: dict[str, object] = {}

    def fake_execvpe(file: str, argv: list[str], env: dict[str, str]) -> None:
        captured["file"] = file
        captured["argv"] = argv
        captured["cwd"] = Path.cwd()
        captured["env"] = env
        raise RuntimeError("exec blocked")

    monkeypatch.setattr(orchestrator_module.os, "execvpe", fake_execvpe)

    with pytest.raises(RuntimeError, match="exec blocked"):
        orchestrator_module.start_orchestrator(
            orchestrator_module.OrchestratorOptions(install_root=install_root, foreground=True)
        )

    assert captured["file"] == "uv"
    assert captured["cwd"] == install_root.resolve()
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[:4] == ["uv", "run", "--directory", "orchestrator/backend"]
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["AI_THREAT_HUNTING_INSTALL_DIR"] == str(install_root.resolve())


def test_orchestrator_start_builds_frontend_even_when_backend_already_running(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import orchestrator as orchestrator_module

    install_root = tmp_path / "install"
    frontend_dir = install_root / "orchestrator" / "frontend"
    (frontend_dir / "src").mkdir(parents=True)
    (frontend_dir / "package.json").write_text("{}", encoding="utf-8")
    (frontend_dir / "src" / "main.tsx").write_text("console.log('ok')\n", encoding="utf-8")
    pid_file = install_root / ".runtime-data" / "pids" / "orchestrator.pid"
    pid_file.parent.mkdir(parents=True)
    pid_file.write_text("123\n", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(orchestrator_module.subprocess, "run", fake_run)
    monkeypatch.setattr(orchestrator_module, "_pid_running", lambda path: True)

    orchestrator_module.start_orchestrator(orchestrator_module.OrchestratorOptions(install_root=install_root))

    assert calls == [["npm", "install"], ["npm", "run", "build"]]


def test_orchestrator_health_wait_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import orchestrator as orchestrator_module

    attempts: list[str] = []

    def fail_urlopen(url: str, timeout: int):
        attempts.append(url)
        raise OSError("down")

    monkeypatch.setattr(orchestrator_module.urllib.request, "urlopen", fail_urlopen)
    monkeypatch.setattr(orchestrator_module.time, "sleep", lambda _: None)

    assert orchestrator_module._wait_for_health("127.0.0.1", 18000) is False
    assert attempts == ["http://127.0.0.1:18000/healthz"] * 30


def test_orchestrator_start_terminates_child_when_health_times_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import orchestrator as orchestrator_module

    install_root = tmp_path / "install"
    frontend_dist = install_root / "orchestrator" / "frontend" / "dist"
    frontend_dist.mkdir(parents=True)
    (frontend_dist / "index.html").write_text("ok", encoding="utf-8")
    pid_file = install_root / ".runtime-data" / "pids" / "orchestrator.pid"

    class FakeProcess:
        pid = 4321

        def __init__(self) -> None:
            self.terminated = False
            self.killed = False

        def poll(self) -> int | None:
            return None

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def kill(self) -> None:
            self.killed = True

    fake_process = FakeProcess()

    def fake_popen(*_: object, **__: object) -> FakeProcess:
        return fake_process

    monkeypatch.setattr(orchestrator_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(orchestrator_module, "_wait_for_health", lambda *_, **__: False)

    with pytest.raises(SystemExit, match="did not become healthy"):
        orchestrator_module.start_orchestrator(orchestrator_module.OrchestratorOptions(install_root=install_root))

    assert fake_process.terminated is True
    assert fake_process.killed is False
    assert not pid_file.exists()


def test_assess_kali_help_lists_every_typed_verb(capsys: pytest.CaptureFixture[str]) -> None:
    """`aith assess kali --help` must enumerate the 13 typed verbs plus exec and job."""
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    # Reload assess modules so our injected sys.path takes effect.
    for module_name in list(sys.modules):
        if module_name == "assess" or module_name.startswith("assess."):
            sys.modules.pop(module_name, None)
    from assess.cli import main as assess_main

    with pytest.raises(SystemExit) as exc:
        assess_main(["kali", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for verb in (
        "nmap-scan",
        "nuclei",
        "httpx",
        "wafw00f",
        "ffuf",
        "sqlmap",
        "subfinder",
        "puredns",
        "dnsx",
        "nikto",
        "katana",
        "gau",
        "whatweb",
        "exec",
        "job",
    ):
        assert verb in out, f"verb {verb} missing from kali --help"


def test_main_assess_passthrough_only_applies_to_top_level_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import main as main_module

    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    def fail_execv(path: str, argv: list[str]) -> None:
        raise AssertionError(f"unexpected assess passthrough to {path}: {argv}")

    monkeypatch.setattr(main_module.os, "execv", fail_execv)

    main_module.main(["--root", str(install_root), "engagement", "create", "--type", "code", "assess", "--no-prompt"])

    created = list((install_root / "agent" / "engagements").iterdir())
    assert len(created) == 1
    assert created[0].name.endswith("-assess")


def test_main_assess_passthrough_execs_assess_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import main as main_module

    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    captured: dict[str, object] = {}

    def fake_execv(path: str, argv: list[str]) -> None:
        captured["path"] = path
        captured["argv"] = argv
        raise SystemExit(0)

    monkeypatch.setattr(main_module.os, "execv", fake_execv)

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(["--root", str(install_root), "assess", "--help"])

    assert excinfo.value.code == 0
    assert captured["path"] == str(install_root / "agent" / "scripts" / "assess.py")
    assert captured["argv"] == [str(install_root / "agent" / "scripts" / "assess.py"), "--help"]


def test_aith_mcp_subcommand_prints_deprecation_and_exits_two(capsys: pytest.CaptureFixture[str]) -> None:
    from ai_threat_hunting_cli import main as main_module

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(["mcp", "install", "both"])

    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert "removed in the typed-CLI cutover" in err
    assert "aith assess kali" in err


def test_runtime_start_applies_resource_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)
    monkeypatch.setenv("AITH_RUNTIME_MEMORY_GB", "16")
    monkeypatch.setenv("AITH_RUNTIME_CPUS", "8")
    monkeypatch.setenv("AITH_RUNTIME_PIDS_LIMIT", "1024")
    monkeypatch.setenv("AITH_RUNTIME_SHM_SIZE", "2g")
    commands: list[list[str]] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "", "")
        if argv[:3] == ["docker", "ps", "-a"]:
            return DockerResult(0, "", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, f"{install_root / '.runtime-data'} -> /data\n{install_root / 'agent' / 'engagements'} -> /engagements\n", "")
        if argv[:2] == ["docker", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        return DockerResult(0, "", "")

    start_runtime(RuntimeOptions(install_root=install_root, recreate=False), runner=runner, validate_tools=False)

    run_command = next(command for command in commands if command[:3] == ["docker", "run", "-d"])
    assert "--memory=16g" in run_command
    assert "--memory-swap=16g" in run_command
    assert "--memory-swappiness=0" in run_command
    assert "--cpus=8" in run_command
    assert "--pids-limit=1024" in run_command
    assert "--shm-size=2g" in run_command
    assert "--oom-score-adj=-500" in run_command
    nofile_idx = run_command.index("nofile=131072:131072")
    assert run_command[nofile_idx - 1] == "--ulimit"
    nproc_idx = run_command.index("nproc=16384")
    assert run_command[nproc_idx - 1] == "--ulimit"


def test_aith_runtime_resources_renders_configured_and_live_state(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.runtime import aith_runtime_resources

    monkeypatch.setenv("AITH_RUNTIME_MEMORY_GB", "8")
    monkeypatch.setenv("AITH_RUNTIME_CPUS", "4")
    monkeypatch.setenv("AITH_RUNTIME_PIDS_LIMIT", "512")
    monkeypatch.setenv("AITH_RUNTIME_SHM_SIZE", "1g")

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "security-research\n", "")
        if argv[:3] == ["docker", "exec", "security-research"]:
            return DockerResult(
                0,
                "/sys/fs/cgroup/memory.max=8589934592\n"
                "/sys/fs/cgroup/cpu.max=400000 100000\n"
                "/sys/fs/cgroup/pids.max=512\n",
                "",
            )
        return DockerResult(0, "", "")

    aith_runtime_resources(runner=runner)
    output = capsys.readouterr().out
    assert "configured\tmemory=8g" in output
    assert "cpus=4" in output
    assert "memory.max=8589934592" in output
    assert "cpu.max=400000 100000" in output
    assert "pids.max=512" in output


def test_aith_runtime_resources_handles_stopped_container(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.runtime import aith_runtime_resources

    monkeypatch.delenv("AITH_RUNTIME_MEMORY_GB", raising=False)
    monkeypatch.delenv("AITH_RUNTIME_CPUS", raising=False)
    monkeypatch.delenv("AITH_RUNTIME_PIDS_LIMIT", raising=False)
    monkeypatch.delenv("AITH_RUNTIME_SHM_SIZE", raising=False)

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    aith_runtime_resources(runner=runner)
    output = capsys.readouterr().out
    assert "running=False" in output
    assert "live\tcontainer not running" in output


def test_runtime_shell_exec_passes_symbol_heavy_command_as_single_shell_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import main as main_module

    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    command = (
        "printf '%s\\n' \"a b\" | tee /data/symbols.log >/dev/null; "
        "tmux new-session -d -s shell-4444 'pwncat -l -p 4444 2>&1 | tee /data/shell-4444.log'"
    )
    monkeypatch.setattr(main_module.subprocess, "run", fake_run)

    main_module.main(["runtime", "shell-exec", command])

    assert calls == [["docker", "exec", "security-research", "sh", "-lc", command]]


def test_runtime_shell_exec_propagates_container_command_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import main as main_module

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 37, "", "boom")

    monkeypatch.setattr(main_module.subprocess, "run", fake_run)

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(["runtime", "shell-exec", "false"])

    assert excinfo.value.code == 37


def test_runtime_shell_exec_strips_separator_and_quotes_multiple_parts(monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import main as main_module

    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(main_module.subprocess, "run", fake_run)

    main_module.main(["runtime", "shell-exec", "--", "printf", "%s", "a b"])

    assert calls == [["docker", "exec", "security-research", "sh", "-lc", "printf %s 'a b'"]]


def test_engagement_create_infers_localhost_url_as_web(tmp_path: Path) -> None:
    from ai_threat_hunting_cli import main as main_module

    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    main_module.main(["--root", str(install_root), "engagement", "create", "http://localhost:8080", "--no-prompt"])

    created = next((install_root / "agent" / "engagements").iterdir())
    scope = json.loads((created / "scope.json").read_text(encoding="utf-8"))
    manifest = json.loads((created / "engagement.json").read_text(encoding="utf-8"))
    assert scope["engagement_type"] == "web"
    assert scope["hostname"] == "localhost"
    assert manifest["target"] == "http://localhost:8080"


def test_engagement_select_uses_fzf_when_requested(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import engagements

    root = tmp_path / "install" / "agent" / "engagements"
    older = root / "2026-04-24-120000-z-last"
    newer = root / "2026-04-24-120000-a-first"
    for path, created_at in (
        (older, "2026-04-24T12:00:00Z"),
        (newer, "2026-04-24T12:00:01Z"),
    ):
        path.mkdir(parents=True)
        (path / "scope.json").write_text('{"status":"in_progress","current_phase":"recon"}', encoding="utf-8")
        (path / "engagement.json").write_text(json.dumps({"key": path.name, "target": path.name, "created_at": created_at}), encoding="utf-8")

    def fake_which(command: str) -> str | None:
        return "/usr/bin/fzf" if command == "fzf" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        assert argv == ["fzf", "--with-nth", "1,2,3,4"]
        return subprocess.CompletedProcess(argv, 0, f"{newer.name}\tin_progress\trecon\t{newer.name}\t{newer.resolve()}\n", "")

    monkeypatch.setattr(engagements.shutil, "which", fake_which)
    monkeypatch.setattr(engagements.subprocess, "run", fake_run)

    assert engagements.resolve_engagement_path(tmp_path / "install", select=True) == newer.resolve()


def test_runtime_start_rejects_running_container_with_wrong_mount(tmp_path: Path) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "security-research\n", "")
        if argv[:4] == ["docker", "inspect", "-f", "{{.Image}}"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:4] == ["docker", "image", "inspect", "-f"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, "/wrong/data -> /data\n/wrong/engagements -> /engagements\n", "")
        if argv[:3] == ["docker", "exec", "security-research"]:
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit, match="mount drift"):
        start_runtime(RuntimeOptions(install_root=install_root), runner=runner)


def test_doctor_reports_missing_binary_without_crashing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from ai_threat_hunting_cli import main as main_module
    from ai_threat_hunting_cli import status as status_module
    from ai_threat_hunting_cli.docker import DockerResult

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    def fake_which(command: str) -> str | None:
        return None if command == "uv" else f"/usr/bin/{command}"

    def fake_docker(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "", "")
        return DockerResult(0, "ok", "")

    monkeypatch.setattr(status_module.shutil, "which", fake_which)
    monkeypatch.setattr(status_module.subprocess, "run", fake_run)
    monkeypatch.setattr(main_module, "docker_run_command", fake_docker)

    main_module.main(["--root", str(tmp_path), "doctor"])

    assert "MISSING\tuv" in capsys.readouterr().out


def test_doctor_skips_docker_checks_when_docker_cli_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ai_threat_hunting_cli import main as main_module
    from ai_threat_hunting_cli import status as status_module
    from ai_threat_hunting_cli.docker import DockerResult

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    def fake_which(command: str) -> str | None:
        return None if command == "docker" else f"/usr/bin/{command}"

    def fail_docker(argv: list[str], **_: object) -> DockerResult:
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(status_module.shutil, "which", fake_which)
    monkeypatch.setattr(status_module.subprocess, "run", fake_run)
    monkeypatch.setattr(main_module, "docker_run_command", fail_docker)

    main_module.main(["--root", str(tmp_path), "doctor"])

    output = capsys.readouterr().out
    assert "MISSING\tdocker" in output
    assert "SKIPPED\tdocker-daemon" in output


def test_status_json_reports_runtime_mount_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from ai_threat_hunting_cli import main as main_module
    from ai_threat_hunting_cli import status as status_module
    from ai_threat_hunting_cli.docker import DockerResult

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "security-research\n", "")
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, "/wrong/data -> /data\n/wrong/engagements -> /engagements\n", "")
        return DockerResult(0, "", "")

    monkeypatch.setattr(main_module, "docker_run_command", runner)

    main_module.main(["--root", str(install_root), "status", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["runtime"]["state"] == "running"
    assert payload["runtime"]["mounts_ok"] is False


def test_config_set_get_and_unset_uses_config_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from ai_threat_hunting_cli import main as main_module

    config_path = tmp_path / "config.json"
    monkeypatch.setenv("AI_THREAT_HUNTING_CONFIG", str(config_path))

    main_module.main(["config", "set", "oob.domain", "oob.example.test"])
    main_module.main(["config", "get", "oob.domain"])
    assert "oob.example.test" in capsys.readouterr().out

    main_module.main(["config", "unset", "oob.domain"])
    main_module.main(["config", "list"])
    assert "oob.domain" not in capsys.readouterr().out


def test_logs_routes_to_centralized_targets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import main as main_module

    install_root = tmp_path / "install"
    log_file = install_root / ".runtime-data" / "logs" / "orchestrator.log"
    log_file.parent.mkdir(parents=True)
    log_file.write_text("hello\n", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(main_module.subprocess, "run", fake_run)

    main_module.main(["--root", str(install_root), "logs", "runtime", "--lines", "5"])
    main_module.main(["--root", str(install_root), "logs", "orchestrator", "--lines", "5"])

    assert ["docker", "logs", "--tail", "5", "security-research"] in calls
    assert ["tail", "-n", "5", str(log_file)] in calls


def test_auth_status_and_clear_operate_on_engagement_auth(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from ai_threat_hunting_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    (engagement / "auth.json").write_text(
        json.dumps({"mode": "manual", "state": "present", "expires_at": expires_at, "cookies": {"sid": "x"}, "headers": {}}),
        encoding="utf-8",
    )

    main_module.main(["--root", str(install_root), "auth", "status", "eng-1"])
    assert "present" in capsys.readouterr().out

    main_module.main(["--root", str(install_root), "auth", "clear", "eng-1"])
    auth = json.loads((engagement / "auth.json").read_text(encoding="utf-8"))
    assert auth["state"] == "missing"
    assert auth["cookies"] == {}


def test_auth_select_selector_overrides_current_engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import main as main_module
    from ai_threat_hunting_cli import engagements

    install_root = tmp_path / "install"
    root = install_root / "agent" / "engagements"
    older = root / "2026-04-24-120000-older"
    newer = root / "2026-04-24-120001-newer"
    for path, created_at in (
        (older, "2026-04-24T12:00:00Z"),
        (newer, "2026-04-24T12:00:01Z"),
    ):
        path.mkdir(parents=True)
        (path / "scope.json").write_text('{"status":"in_progress","current_phase":"recon"}', encoding="utf-8")
        (path / "engagement.json").write_text(json.dumps({"key": path.name, "target": path.name, "created_at": created_at}), encoding="utf-8")
        (path / "auth.json").write_text(
            json.dumps({"mode": "manual", "state": "present", "cookies": {"sid": path.name}, "headers": {}}),
            encoding="utf-8",
        )

    def fake_which(command: str) -> str | None:
        return "/usr/bin/fzf" if command == "fzf" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, f"{newer.name}\tin_progress\trecon\t{newer.name}\t{newer.resolve()}\n", "")

    monkeypatch.setattr(engagements.shutil, "which", fake_which)
    monkeypatch.setattr(engagements.subprocess, "run", fake_run)
    monkeypatch.chdir(older)

    main_module.main(["--root", str(install_root), "auth", "clear", "--select"])

    older_auth = json.loads((older / "auth.json").read_text(encoding="utf-8"))
    newer_auth = json.loads((newer / "auth.json").read_text(encoding="utf-8"))
    assert older_auth["state"] == "present"
    assert older_auth["cookies"] == {"sid": older.name}
    assert newer_auth["state"] == "missing"
    assert newer_auth["cookies"] == {}


def test_auth_without_engagement_context_requires_key_or_select(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    (engagement / "engagement.json").write_text(json.dumps({"key": "eng-1", "created_at": "2026-04-24T12:00:00Z"}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit, match="Specify an engagement key or --select"):
        main_module.main(["--root", str(install_root), "auth", "status"])


def test_mitmproxy_without_engagement_context_requires_key_path_or_select(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    (engagement / "engagement.json").write_text(json.dumps({"key": "eng-1", "created_at": "2026-04-24T12:00:00Z"}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit, match="Specify an engagement key/path or --select"):
        main_module.main(["--root", str(install_root), "mitmproxy", "start"])


def test_backup_create_and_list_uses_sqlite_backup(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from ai_threat_hunting_cli import main as main_module

    install_root = tmp_path / "install"
    data_dir = install_root / "orchestrator" / "backend" / "data"
    data_dir.mkdir(parents=True)
    import sqlite3

    with sqlite3.connect(data_dir / "orchestrator.sqlite3") as connection:
        connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO t DEFAULT VALUES")

    main_module.main(["--root", str(install_root), "backup", "create"])
    created_output = capsys.readouterr().out
    assert "orchestrator." in created_output

    main_module.main(["--root", str(install_root), "backup", "list"])
    assert "orchestrator." in capsys.readouterr().out


@pytest.mark.parametrize(
    "env_name",
    ["AI_THREAT_HUNTING_DATA_DIR", "REDTEAM_ORCHESTRATOR_DATA_DIR"],
)
def test_backup_helpers_use_backend_data_dir_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env_name: str) -> None:
    from ai_threat_hunting_cli.backup import create_backup, list_backups, live_database, restore_backup

    install_root = tmp_path / "install"
    default_data = install_root / "orchestrator" / "backend" / "data"
    custom_data = tmp_path / "backend-data"
    legacy_data = tmp_path / "legacy-data"
    if env_name == "AI_THREAT_HUNTING_DATA_DIR":
        monkeypatch.setenv("REDTEAM_ORCHESTRATOR_DATA_DIR", str(legacy_data))
    else:
        monkeypatch.delenv("AI_THREAT_HUNTING_DATA_DIR", raising=False)
    monkeypatch.setenv(env_name, str(custom_data))
    _write_marker_database(default_data / "orchestrator.sqlite3", "default")
    _write_marker_database(custom_data / "orchestrator.sqlite3", "custom")
    _write_marker_database(legacy_data / "orchestrator.sqlite3", "legacy")

    backup = create_backup(install_root, timestamp="20260425T010000Z")

    assert live_database(install_root) == custom_data / "orchestrator.sqlite3"
    assert backup.parent == custom_data / "backups"
    assert [item.path for item in list_backups(install_root)] == [backup.resolve()]
    with sqlite3.connect(custom_data / "orchestrator.sqlite3") as connection:
        connection.execute("DELETE FROM marker")
        connection.execute("INSERT INTO marker (value) VALUES ('changed')")

    restored = restore_backup(install_root, backup)

    assert restored == custom_data / "orchestrator.sqlite3"
    with sqlite3.connect(restored) as connection:
        assert connection.execute("SELECT value FROM marker").fetchone() == ("custom",)
    with sqlite3.connect(default_data / "orchestrator.sqlite3") as connection:
        assert connection.execute("SELECT value FROM marker").fetchone() == ("default",)
    with sqlite3.connect(legacy_data / "orchestrator.sqlite3") as connection:
        assert connection.execute("SELECT value FROM marker").fetchone() == ("legacy",)


def test_backup_create_uses_suffix_when_timestamp_collides(tmp_path: Path) -> None:
    from ai_threat_hunting_cli.backup import create_backup, list_backups

    install_root = tmp_path / "install"
    data_dir = install_root / "orchestrator" / "backend" / "data"
    data_dir.mkdir(parents=True)

    import sqlite3

    live = data_dir / "orchestrator.sqlite3"
    with sqlite3.connect(live) as connection:
        connection.execute("CREATE TABLE t (value TEXT PRIMARY KEY)")
        connection.execute("INSERT INTO t (value) VALUES ('first')")

    first = create_backup(install_root, timestamp="20260424T120000Z")

    with sqlite3.connect(live) as connection:
        connection.execute("INSERT INTO t (value) VALUES ('second')")

    second = create_backup(install_root, timestamp="20260424T120000Z")

    assert first.name == "orchestrator.20260424T120000Z.sqlite3"
    assert second.name == "orchestrator.20260424T120000Z_0001.sqlite3"
    assert [item.path.name for item in list_backups(install_root)] == [first.name, second.name]

    with sqlite3.connect(first) as connection:
        assert connection.execute("SELECT value FROM t ORDER BY value").fetchall() == [("first",)]
    with sqlite3.connect(second) as connection:
        assert connection.execute("SELECT value FROM t ORDER BY value").fetchall() == [("first",), ("second",)]


def test_backup_restore_removes_stale_sqlite_wal_sidecars(tmp_path: Path) -> None:
    from ai_threat_hunting_cli.backup import restore_backup

    install_root = tmp_path / "install"
    data_dir = install_root / "orchestrator" / "backend" / "data"
    data_dir.mkdir(parents=True)
    backup = tmp_path / "selected.sqlite3"

    import sqlite3

    with sqlite3.connect(backup) as connection:
        connection.execute("CREATE TABLE restored (id INTEGER PRIMARY KEY)")

    live = data_dir / "orchestrator.sqlite3"
    live.write_text("old", encoding="utf-8")
    live.with_name(live.name + "-wal").write_text("stale wal", encoding="utf-8")
    live.with_name(live.name + "-shm").write_text("stale shm", encoding="utf-8")

    restored = restore_backup(install_root, backup)

    assert restored == live
    assert not live.with_name(live.name + "-wal").exists()
    assert not live.with_name(live.name + "-shm").exists()
    with sqlite3.connect(restored) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE name = 'restored'").fetchone() == ("restored",)


def test_oob_start_renders_config_and_starts_idempotent_sessions(tmp_path: Path) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.oob import OobOptions, start_oob

    commands: list[list[str]] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "security-research\n", "")
        if argv[:3] == ["docker", "exec", "security-research"] and "tmux has-session -t oob-server" in argv[-1] and "tmux new-session" not in argv[-1]:
            return DockerResult(1, "", "")
        if argv[:3] == ["docker", "exec", "security-research"] and "tmux has-session -t frpc" in argv[-1] and "tmux new-session" not in argv[-1]:
            return DockerResult(1, "", "")
        return DockerResult(0, "", "")

    start_oob(
        OobOptions(
            install_root=tmp_path,
            frp_host="cal.example.test",
            frp_port=7000,
            frp_token="secret",
            oob_domain="oob.example.test",
        ),
        runner=runner,
    )

    rendered = "\n".join(" ".join(command) for command in commands)
    assert "cal.example.test" in rendered
    assert "oob.example.test" in rendered
    assert "tmux new-session -d -s oob-server" in rendered
    assert "tmux new-session -d -s frpc" in rendered


def test_oob_client_start_uses_session_file_for_domain_resume(tmp_path: Path) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.oob import OobOptions, start_oob_client

    commands: list[list[str]] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "security-research\n", "")
        if argv[:3] == ["docker", "exec", "security-research"] and "tmux has-session -t oob-client-demo" in argv[-1] and "tmux new-session" not in argv[-1]:
            return DockerResult(1, "", "")
        return DockerResult(0, "", "")

    start_oob_client(
        OobOptions(
            install_root=tmp_path,
            frp_token="secret",
            oob_domain="oob.example.test",
        ),
        "demo",
        runner=runner,
    )

    rendered = "\n".join(" ".join(command) for command in commands)
    assert "-session-file /data/oob/clients/demo.session" in rendered
    assert "interactsh-client -server oob.example.test" in rendered


def test_up_skips_oob_when_existing_sessions_are_active(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import up as up_module

    calls: list[str] = []

    monkeypatch.setattr(up_module, "_image_outdated", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module, "_runtime_image_drift", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module.docker, "container_running", lambda name, runner=None: True)
    monkeypatch.setattr(up_module, "start_runtime", lambda *args, **kwargs: calls.append("runtime"))
    monkeypatch.setattr(up_module, "start_proxy", lambda *args, **kwargs: calls.append("mitmproxy"))
    monkeypatch.setattr(
        up_module,
        "oob_status",
        lambda runner=None: {"state": "partial", "server": False, "frpc": True, "clients": ["demo"]},
    )
    monkeypatch.setattr(up_module, "start_oob", lambda *args, **kwargs: calls.append("oob"))
    monkeypatch.setattr(up_module, "start_orchestrator", lambda *args, **kwargs: calls.append("orchestrator"))

    up_module.run_up(up_module.UpOptions(install_root=tmp_path), runner=lambda *args, **kwargs: None)

    assert calls == ["runtime", "orchestrator"]


def test_up_starts_oob_when_only_client_sessions_exist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import up as up_module

    calls: list[str] = []

    monkeypatch.setattr(up_module, "_image_outdated", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module, "_runtime_image_drift", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module.docker, "container_running", lambda name, runner=None: True)
    monkeypatch.setattr(up_module, "start_runtime", lambda *args, **kwargs: calls.append("runtime"))
    monkeypatch.setattr(up_module, "start_orchestrator", lambda *args, **kwargs: calls.append("orchestrator"))
    monkeypatch.setattr(
        up_module,
        "oob_status",
        lambda runner=None: {"state": "partial", "server": False, "frpc": False, "clients": ["demo"]},
    )
    monkeypatch.setattr(
        up_module,
        "_oob_options",
        lambda install_root: up_module.OobOptions(install_root=install_root, frp_token="secret"),
    )
    monkeypatch.setattr(up_module, "start_oob", lambda *args, **kwargs: calls.append("oob"))

    up_module.run_up(up_module.UpOptions(install_root=tmp_path), runner=lambda *args, **kwargs: None)

    assert calls == ["runtime", "orchestrator", "oob"]


def test_up_starts_orchestrator_before_prompting_for_missing_frp_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import up as up_module

    calls: list[str] = []

    monkeypatch.setattr(up_module, "_image_outdated", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module, "_runtime_image_drift", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module.docker, "container_running", lambda name, runner=None: name == "security-research")
    monkeypatch.setattr(up_module, "start_runtime", lambda *args, **kwargs: calls.append("runtime"))
    monkeypatch.setattr(up_module, "start_orchestrator", lambda *args, **kwargs: calls.append("orchestrator"))
    monkeypatch.setattr(
        up_module,
        "oob_status",
        lambda runner=None: {"state": "stopped", "server": False, "frpc": False, "clients": []},
    )
    monkeypatch.setattr(
        up_module,
        "_oob_options",
        lambda install_root: up_module.OobOptions(install_root=install_root, frp_token=""),
    )

    def fake_prompt() -> str:
        calls.append("frp-prompt")
        return ""

    monkeypatch.setattr(up_module, "_prompt_frp_token", fake_prompt)

    up_module.run_up(up_module.UpOptions(install_root=tmp_path), runner=lambda *args, **kwargs: None)

    assert calls[:3] == ["runtime", "orchestrator", "frp-prompt"]
