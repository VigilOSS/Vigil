from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
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


def test_mcp_install_registers_codex_and_claude_servers(monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import main as main_module

    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(main_module.subprocess, "run", fake_run)

    main_module.main(["mcp", "install", "both"])

    assert ["claude", "mcp", "remove", "-s", "user", "kali"] in calls
    assert ["claude", "mcp", "add", "-s", "user", "kali", "--", "docker", "exec", "-i", "security-research", "mcp-server"] in calls
    assert ["codex", "mcp", "remove", "kali"] in calls
    assert ["codex", "mcp", "add", "kali", "--", "docker", "exec", "-i", "security-research", "mcp-server"] in calls
