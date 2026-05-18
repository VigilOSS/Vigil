from __future__ import annotations

import json
import os
import signal
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo_root))
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


def _isolate_orchestrator_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ORCHESTRATOR_BASE_URL", "http://127.0.0.1:9")


def test_engagement_create_web_writes_scope_launchers_and_list_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_threat_hunting_cli.engagements import CreateEngagementOptions, create_engagement, list_engagements

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
            hosts=["app.example.com", "admin.example.com"],
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
    assert scope["exploit_policy"] == "pause"
    assert scope["exploit_review_state"] == "pending"
    assert scope["approved_targets"] == []
    assert auth["mode"] == "none"
    assert auth["state"] == "none"
    assert auth["use_for_requests"] is False
    assert manifest["key"] == created.key
    assert (created.path / "cases.db").exists()
    assert (created.path / "start_codex.sh").exists()
    assert (created.path / "start_claude.sh").exists()
    assert "codex --full-auto" in (created.path / "start_codex.sh").read_text(encoding="utf-8")

    rows = list_engagements(install_root)
    assert [row.key for row in rows] == [created.key]
    assert rows[0].target == "https://app.example.com"


def test_engagement_create_does_not_accept_exploit_policy_or_auth_mode_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_threat_hunting_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    for flag, value in (("--exploit-policy", "selected"), ("--auth-mode", "manual")):
        with pytest.raises(SystemExit):
            main_module.main(
                [
                    "--root",
                    str(install_root),
                    "engagement",
                    "create",
                    "--type",
                    "web",
                    "https://app.example.com",
                    "--hosts",
                    "app.example.com",
                    "--no-prompt",
                    flag,
                    value,
                ]
            )


def test_engagement_create_emits_post_create_footer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ai_threat_hunting_cli import docker as docker_mod
    from ai_threat_hunting_cli import oob as oob_mod
    from ai_threat_hunting_cli.engagements import CreateEngagementOptions, create_engagement

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    monkeypatch.setattr(docker_mod, "container_running", lambda *_a, **_k: False)
    monkeypatch.setattr(oob_mod, "oob_status", lambda *_a, **_k: {"state": "stopped"})

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
        )
    )

    captured = capsys.readouterr()
    assert "mitmproxy: stopped" in captured.err
    assert "oob:" in captured.err and "stopped" in captured.err
    assert f"aith mitmproxy start {created.key}" in captured.err
    assert "aith oob start" in captured.err
    assert f"aith engagement start {created.key} --client codex" in captured.err


def test_engagement_create_footer_suppresses_hints_when_services_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ai_threat_hunting_cli import docker as docker_mod
    from ai_threat_hunting_cli import oob as oob_mod
    from ai_threat_hunting_cli.engagements import CreateEngagementOptions, create_engagement

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    monkeypatch.setattr(docker_mod, "container_running", lambda *_a, **_k: True)
    monkeypatch.setattr(oob_mod, "oob_status", lambda *_a, **_k: {"state": "running"})

    create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
        )
    )

    captured = capsys.readouterr()
    assert "mitmproxy: running" in captured.err
    assert "oob:       running" in captured.err
    assert "aith mitmproxy start" not in captured.err
    assert "aith oob start" not in captured.err


def test_engagement_create_android_uses_artifact_only_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_threat_hunting_cli.engagements import CreateEngagementOptions, create_engagement, list_engagements

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    apk_path = tmp_path / "keeper.xapk"

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="android",
            artifacts=[str(apk_path)],
            android_package="com.callpod.android_apps.keeper",
            dynamic_mode="static_only",
            hosts=["api.keepersecurity.com"],
            skip_permissions=True,
        )
    )

    scope = json.loads((created.path / "scope.json").read_text(encoding="utf-8"))
    manifest = json.loads((created.path / "engagement.json").read_text(encoding="utf-8"))

    assert scope["engagement_type"] == "android"
    assert scope["mobile_platform"] == "android"
    assert scope["scope_mode"] == "artifact-only"
    assert scope["hosts"] == []
    assert scope["backend_hosts"] == ["api.keepersecurity.com"]
    assert scope["android_package"] == "com.callpod.android_apps.keeper"
    assert scope["artifacts"] == [str(apk_path)]
    assert scope["current_phase"] == "ingest"
    assert manifest["target"] == "com.callpod.android_apps.keeper"
    assert (created.path / "source").is_dir()
    assert (created.path / "cases.db").exists()
    assert list_engagements(install_root)[0].target == "com.callpod.android_apps.keeper"


def test_engagement_create_android_cli_accepts_package_positional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ai_threat_hunting_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    main_module.main(
        [
            "--root",
            str(install_root),
            "engagement",
            "create",
            "--type",
            "android",
            "com.callpod.android_apps.keeper",
            "--no-prompt",
        ]
    )

    created_path = Path(capsys.readouterr().out.strip())
    scope = json.loads((created_path / "scope.json").read_text(encoding="utf-8"))
    assert scope["engagement_type"] == "android"
    assert scope["scope_mode"] == "artifact-only"
    assert scope["hosts"] == []
    assert scope["android_package"] == "com.callpod.android_apps.keeper"


def test_engagement_create_android_cli_infers_apk_without_interactive_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ai_threat_hunting_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    apk_path = tmp_path / "keeper.apk"

    class _InteractiveStdin:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(main_module.sys, "stdin", _InteractiveStdin())
    monkeypatch.setattr(
        main_module,
        "_prompt_choice",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected prompt")),
    )

    main_module.main(
        [
            "--root",
            str(install_root),
            "engagement",
            "create",
            "--apk",
            str(apk_path),
        ]
    )

    created_path = Path(capsys.readouterr().out.strip())
    scope = json.loads((created_path / "scope.json").read_text(encoding="utf-8"))
    assert scope["engagement_type"] == "android"
    assert scope["artifacts"] == [str(apk_path)]
    assert scope["hosts"] == []


def test_engagement_create_snapshots_backend_data_dir_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli.engagements import CreateEngagementOptions, create_engagement

    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    custom_data = tmp_path / "backend-data"
    default_data = install_root / "orchestrator" / "backend" / "data"
    _write_marker_database(custom_data / "orchestrator.sqlite3", "custom")
    _write_marker_database(default_data / "orchestrator.sqlite3", "default")
    _isolate_orchestrator_url(monkeypatch)
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
    (source_root / "agent" / ".codex" / "agents").mkdir(parents=True)
    (source_root / "agent" / ".codex" / "agents" / "vulnerability-analyst.toml").write_text(
        "name = \"vulnerability-analyst\"\n",
        encoding="utf-8",
    )
    (source_root / "orchestrator" / "backend" / "app.py").write_text("managed backend\n", encoding="utf-8")
    (source_root / "docker" / "callback_listener.py").write_text("managed docker\n", encoding="utf-8")

    marker = install_root / "agent" / "engagements" / "existing" / "scope.json"
    marker.write_text('{"target":"https://old.example"}\n', encoding="utf-8")
    (marker.parent / ".codex").mkdir()
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
    codex_agents = marker.parent / ".codex" / "agents"
    assert codex_agents.is_symlink()
    assert codex_agents.resolve() == (install_root / "agent" / ".codex" / "agents").resolve()
    assert (codex_agents / "vulnerability-analyst.toml").exists()
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


def test_runtime_start_missing_image_points_to_orchestrator_for_backend_state(tmp_path: Path) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(1, "", "missing")
        if argv[:4] == ["docker", "inspect", "--type", "image"]:
            return DockerResult(1, "", "missing")
        if argv[:3] == ["docker", "images", "-q"]:
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit) as exc_info:
        start_runtime(RuntimeOptions(install_root=install_root), runner=runner, validate_tools=False)

    message = str(exc_info.value)
    assert "Missing runtime image" in message
    assert "aith runtime build" in message
    assert "aith orchestrator status" in message


def test_runtime_start_grants_sys_ptrace_capability(tmp_path: Path) -> None:
    """B2: runtime diagnostic tooling needs CAP_SYS_PTRACE; the docker-run argv
    must request it explicitly so ptrace operations do not fail with EPERM."""
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


def test_mitmproxy_docker_start_builds_and_mounts_engagements_root(tmp_path: Path) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.mitmproxy import MitmproxyOptions, start_proxy

    install_root = tmp_path / "install"
    engagements_root = install_root / "agent" / "engagements"
    engagement = engagements_root / "eng-1"
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
        MitmproxyOptions(
            install_root=install_root,
            engagements_root=engagements_root,
            mode="docker",
            port=9090,
        ),
        runner=runner,
        verify_port=False,
    )

    build_command = next(command for command in commands if command[:3] == ["docker", "build", "-t"])
    run_command = next(command for command in commands if command[:3] == ["docker", "run", "-d"])
    assert str(install_root / "agent" / "docker" / "mitmproxy" / "Dockerfile") in build_command
    assert str(install_root / "agent") == build_command[-1]
    assert "--add-host=host.docker.internal:host-gateway" in run_command
    assert "127.0.0.1:9090:8080" in run_command
    # New contract: bind-mount the whole engagements tree at /engagements.
    assert f"{engagements_root}:/engagements" in run_command
    # ENGAGEMENT_KEY is gone — the addon learns the key per flow.
    assert not any(item.startswith("ENGAGEMENT_KEY=") for item in run_command)
    assert "ORCHESTRATOR_BASE_URL=http://host.docker.internal:18000" in run_command
    # The --set switches the addon to multi-engagement mode.
    assert "engagements_root=/engagements" in run_command


def test_mitmproxy_start_polls_port_until_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import mitmproxy as mitmproxy_module
    from ai_threat_hunting_cli.docker import DockerResult

    install_root = tmp_path / "install"
    engagements_root = install_root / "agent" / "engagements"
    engagement = engagements_root / "eng-1"
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
        mitmproxy_module.MitmproxyOptions(
            install_root=install_root, engagements_root=engagements_root, port=9090
        ),
        runner=runner,
    )

    assert attempts == [("127.0.0.1", 9090)] * 3


def test_mitmproxy_start_uses_install_engagements_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`aith mitmproxy start` now mounts the whole engagements tree — no
    per-engagement context required, the addon routes each captured flow to
    the matching engagement.
    """
    from ai_threat_hunting_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_start_proxy(options: object) -> None:
        captured["engagements_root"] = options.engagements_root  # type: ignore[attr-defined]

    monkeypatch.setattr(main_module, "start_proxy", fake_start_proxy)

    main_module.main(["--root", str(install_root), "mitmproxy", "start"])

    assert captured["engagements_root"] == install_root / "agent" / "engagements"


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


def test_orchestrator_start_builds_frontend_then_errors_when_backend_already_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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

    with pytest.raises(SystemExit) as excinfo:
        orchestrator_module.start_orchestrator(orchestrator_module.OrchestratorOptions(install_root=install_root))

    assert calls == [["npm", "ci"], ["npm", "run", "build"]]
    message = str(excinfo.value)
    assert "Orchestrator is already running" in message
    assert "PID: 123" in message
    assert str(pid_file) in message
    assert "http://127.0.0.1:18000" in message
    assert "aith orchestrator restart" in message
    assert "aith logs orchestrator" in message


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
    signals_sent: list[tuple[int, signal.Signals]] = []

    def fake_popen(*_: object, **kwargs: object) -> FakeProcess:
        assert kwargs["start_new_session"] is True
        assert kwargs["stdin"] is not None
        return fake_process

    def fake_killpg(pid: int, sig: signal.Signals) -> None:
        signals_sent.append((pid, sig))

    monkeypatch.setattr(orchestrator_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(orchestrator_module.os, "killpg", fake_killpg)
    monkeypatch.setattr(orchestrator_module, "_wait_for_health", lambda *_, **__: False)

    with pytest.raises(SystemExit, match="did not become healthy"):
        orchestrator_module.start_orchestrator(orchestrator_module.OrchestratorOptions(install_root=install_root))

    assert signals_sent == [(4321, signal.SIGTERM)]
    assert fake_process.terminated is False
    assert fake_process.killed is False
    assert not pid_file.exists()


def test_orchestrator_start_terminates_child_when_readiness_times_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import orchestrator as orchestrator_module

    install_root = tmp_path / "install"
    frontend_dist = install_root / "orchestrator" / "frontend" / "dist"
    frontend_dist.mkdir(parents=True)
    (frontend_dist / "index.html").write_text("ok", encoding="utf-8")
    pid_file = install_root / ".runtime-data" / "pids" / "orchestrator.pid"

    class FakeProcess:
        pid = 4322

        def poll(self) -> int | None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            return 0

    fake_process = FakeProcess()
    signals_sent: list[tuple[int, signal.Signals]] = []

    def fake_popen(*_: object, **kwargs: object) -> FakeProcess:
        assert kwargs["start_new_session"] is True
        return fake_process

    def fake_killpg(pid: int, sig: signal.Signals) -> None:
        signals_sent.append((pid, sig))

    monkeypatch.setattr(orchestrator_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(orchestrator_module.os, "killpg", fake_killpg)
    monkeypatch.setattr(orchestrator_module, "_wait_for_health", lambda *_, **__: True)
    monkeypatch.setattr(orchestrator_module, "_wait_for_readiness", lambda *_, **__: False)

    with pytest.raises(SystemExit, match="did not become ready"):
        orchestrator_module.start_orchestrator(orchestrator_module.OrchestratorOptions(install_root=install_root))

    assert signals_sent == [(4322, signal.SIGTERM)]
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

    _isolate_orchestrator_url(monkeypatch)
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
    # nofile/nproc are dockerd-side (default-ulimits in daemon.json); see README
    # "Container resource limits". `aith runtime start` probes them via
    # _check_runtime_ulimits and warns to stderr when low.


def test_runtime_start_rejects_already_running_container_with_clear_message(tmp_path: Path) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "security-research\n", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(
                0,
                f"{install_root / '.runtime-data'} -> /data\n{install_root / 'agent' / 'engagements'} -> /engagements\n",
                "",
            )
        if argv[:2] == ["docker", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "exec", "security-research"] and argv[-1] == "ulimit -n; ulimit -u":
            return DockerResult(0, "1048576\nunlimited\n", "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit) as excinfo:
        start_runtime(RuntimeOptions(install_root=install_root), runner=runner, validate_tools=False)

    message = str(excinfo.value)
    assert "Runtime container is already running" in message
    assert "container: security-research" in message
    assert "aith runtime status" in message
    assert "aith runtime restart" in message


def test_check_runtime_ulimits_warns_when_below_threshold(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "security-research\n", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, f"{install_root / '.runtime-data'} -> /data\n{install_root / 'agent' / 'engagements'} -> /engagements\n", "")
        if argv[:2] == ["docker", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "exec", "security-research"] and argv[-1] == "ulimit -n; ulimit -u":
            return DockerResult(0, "8192\n4096\n", "")
        return DockerResult(0, "", "")

    start_runtime(
        RuntimeOptions(install_root=install_root, recreate=False),
        runner=runner,
        validate_tools=False,
        allow_existing=True,
    )
    err = capsys.readouterr().err
    assert "WARN: dockerd default ulimits are low" in err
    assert "nofile=8192" in err
    assert "nproc=4096" in err


def test_check_runtime_ulimits_silent_when_limits_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "security-research\n", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, f"{install_root / '.runtime-data'} -> /data\n{install_root / 'agent' / 'engagements'} -> /engagements\n", "")
        if argv[:2] == ["docker", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "exec", "security-research"] and argv[-1] == "ulimit -n; ulimit -u":
            return DockerResult(0, "1048576\nunlimited\n", "")
        return DockerResult(0, "", "")

    start_runtime(
        RuntimeOptions(install_root=install_root, recreate=False),
        runner=runner,
        validate_tools=False,
        allow_existing=True,
    )
    assert "WARN" not in capsys.readouterr().err


def test_check_runtime_ulimits_silent_on_exec_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from ai_threat_hunting_cli.docker import DockerResult
    from ai_threat_hunting_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "security-research\n", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, f"{install_root / '.runtime-data'} -> /data\n{install_root / 'agent' / 'engagements'} -> /engagements\n", "")
        if argv[:2] == ["docker", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "exec", "security-research"] and argv[-1] == "ulimit -n; ulimit -u":
            return DockerResult(1, "", "exec failed")
        return DockerResult(0, "", "")

    start_runtime(
        RuntimeOptions(install_root=install_root, recreate=False),
        runner=runner,
        validate_tools=False,
        allow_existing=True,
    )
    assert "WARN" not in capsys.readouterr().err


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


def test_engagement_create_infers_localhost_url_as_web(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
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


def test_oob_status_json_reports_effective_domain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from ai_threat_hunting_cli import main as main_module
    from ai_threat_hunting_cli.docker import DockerResult

    config_path = tmp_path / "config.json"
    monkeypatch.setenv("AI_THREAT_HUNTING_CONFIG", str(config_path))

    main_module.main(["config", "set", "oob.domain", "oob.example.test"])
    capsys.readouterr()

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    monkeypatch.setattr(main_module, "docker_run_command", runner)

    main_module.main(["oob", "status", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "stopped"
    assert payload["domain"] == "oob.example.test"


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


def test_mitmproxy_start_legacy_engagement_arg_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Legacy `aith mitmproxy start <engagement>` is a no-op selector — the
    proxy serves every active engagement. The CLI should accept it silently
    (printing one notice) rather than error out.
    """
    from ai_threat_hunting_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_start_proxy(options: object) -> None:
        captured["engagements_root"] = options.engagements_root  # type: ignore[attr-defined]

    monkeypatch.setattr(main_module, "start_proxy", fake_start_proxy)

    main_module.main(["--root", str(install_root), "mitmproxy", "start", "eng-1"])
    assert captured["engagements_root"] == install_root / "agent" / "engagements"
    err = capsys.readouterr().err
    assert "ignoring engagement selector" in err


def test_mitmproxy_reload_touches_sentinel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`aith mitmproxy reload` writes the sentinel the addon polls for, so the
    bind-mount surfaces it to the running container immediately.
    """
    from ai_threat_hunting_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    engagements_root = install_root / "agent" / "engagements"
    engagements_root.mkdir(parents=True)
    main_module.main(["--root", str(install_root), "mitmproxy", "reload"])
    sentinel = engagements_root / ".mitmproxy-reload-requested"
    assert sentinel.exists()


def test_mitmproxy_routes_reads_addon_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`aith mitmproxy routes` parses the snapshot the addon wrote and prints
    a readable summary; --json round-trips the raw cache.
    """
    from ai_threat_hunting_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    engagements_root = install_root / "agent" / "engagements"
    engagements_root.mkdir(parents=True)
    snapshot = {
        "generated_at": "2026-05-18T12:00:00Z",
        "engagements": [
            {
                "key": "eng-1",
                "scope_patterns": ["app.example.com", "*.example.com"],
                "scope_priority": 5,
                "updated_at": "2026-05-18T11:59:00Z",
            }
        ],
    }
    (engagements_root / ".mitmproxy-routes.json").write_text(json.dumps(snapshot), encoding="utf-8")
    main_module.main(["--root", str(install_root), "mitmproxy", "routes"])
    out = capsys.readouterr().out
    assert "eng-1" in out
    assert "app.example.com" in out
    main_module.main(["--root", str(install_root), "mitmproxy", "routes", "--json"])
    out_json = capsys.readouterr().out
    assert json.loads(out_json) == snapshot


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
    monkeypatch.setattr(up_module, "start_proxy", lambda *args, **kwargs: calls.append("mitmproxy"))
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

    # Mitmproxy now starts unconditionally (it serves every engagement at
    # once), so the ordered call list includes it between orchestrator and the
    # oob token prompt.
    assert calls[:4] == ["runtime", "orchestrator", "mitmproxy", "frp-prompt"]


def test_up_passes_injected_runner_to_image_builds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ai_threat_hunting_cli import up as up_module

    seen: dict[str, object] = {}

    def fake_runner(*_args, **_kwargs):
        return None

    monkeypatch.setattr(up_module, "resolve_source_root", lambda *_args, **_kwargs: tmp_path)
    monkeypatch.setattr(up_module, "install_from_source", lambda *args, **kwargs: None)
    monkeypatch.setattr(up_module.docker, "container_running", lambda name, runner=None: False)
    monkeypatch.setattr(up_module, "_image_outdated", lambda *args, **kwargs: True)
    monkeypatch.setattr(up_module, "_start_or_restart_runtime", lambda *args, **kwargs: None)
    monkeypatch.setattr(up_module, "start_orchestrator", lambda *args, **kwargs: None)
    monkeypatch.setattr(up_module, "_start_mitmproxy_if_needed", lambda *args, **kwargs: None)
    monkeypatch.setattr(up_module, "_start_oob_if_needed", lambda *args, **kwargs: None)

    def fake_build_runtime(_install_root, *, runner=None, **_kwargs):
        seen["runtime_runner"] = runner

    def fake_build_mitmproxy(_install_root, *, runner=None):
        seen["mitmproxy_runner"] = runner

    monkeypatch.setattr(up_module, "build_runtime", fake_build_runtime)
    monkeypatch.setattr(up_module, "_build_mitmproxy_image", fake_build_mitmproxy)

    up_module.run_up(up_module.UpOptions(install_root=tmp_path), runner=fake_runner)

    assert seen["runtime_runner"] is fake_runner
    assert seen["mitmproxy_runner"] is fake_runner


# ---------------------------------------------------------------------------
# Wave 3 W3-B mutation-helper coverage
# ---------------------------------------------------------------------------


def _load_assess_main():
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    for module_name in list(sys.modules):
        if module_name == "assess" or module_name.startswith("assess."):
            sys.modules.pop(module_name, None)
    from assess.cli import main as assess_main  # type: ignore[import-not-found]

    return assess_main


def _seed_dispatch_db(db_path: Path, rows: list[dict[str, object]]) -> None:
    """Insert synthetic work_items rows for dispatch / list-clusters tests."""
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    for module_name in list(sys.modules):
        if module_name == "assess" or module_name.startswith("assess."):
            sys.modules.pop(module_name, None)
    from assess.lib.db import db_init  # type: ignore[import-not-found]

    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.touch()
    db_init(str(db_path))
    conn = sqlite3.connect(str(db_path))
    try:
        for row in rows:
            conn.execute(
                """INSERT INTO work_items
                (queue_key, method, url, url_path, query_params, body_params,
                 type, source, status, priority_score, cluster_key, terminal_reason)
                VALUES (?, ?, ?, ?, '{}', '{}', ?, 'test', ?, ?, ?, ?)""",
                (
                    row["queue_key"],
                    row.get("method", "GET"),
                    row["url"],
                    row.get("url_path", "/"),
                    row.get("type", "api"),
                    row.get("status", "pending"),
                    row.get("priority_score", 0),
                    row.get("cluster_key"),
                    row.get("terminal_reason"),
                ),
            )
            if "id" in row:
                conn.execute(
                    "UPDATE work_items SET id = ? WHERE queue_key = ?",
                    (row["id"], row["queue_key"]),
                )
        conn.commit()
    finally:
        conn.close()


def test_resolve_surface_requires_rationale(capsys: pytest.CaptureFixture[str]) -> None:
    """P1 #2: --rationale is required so the audit trail is never empty."""
    assess_main = _load_assess_main()
    with pytest.raises(SystemExit):
        assess_main(["resolve-surface", "1", "--status", "covered"])
    err = capsys.readouterr().err
    assert "--rationale" in err


def test_resolve_surface_rejects_empty_rationale(capsys: pytest.CaptureFixture[str]) -> None:
    """P1 #2: --rationale='' surfaces an early error before HTTP."""
    assess_main = _load_assess_main()
    with pytest.raises(SystemExit) as exc:
        assess_main(["resolve-surface", "1", "--status", "covered", "--rationale", "   "])
    assert "--rationale must be non-empty" in (str(exc.value) or "")


def test_resolve_surface_lowercases_status(capsys: pytest.CaptureFixture[str]) -> None:
    """P3 #1: --status is case-insensitive and rejected by argparse choices when invalid."""
    assess_main = _load_assess_main()
    # Mixed-case input parses to lowercase via type=lambda.
    with pytest.raises(SystemExit):
        assess_main(["resolve-surface", "1", "--status", "BOGUS", "--rationale", "x"])
    err = capsys.readouterr().err
    assert "invalid choice" in err.lower() or "invalid choice" in str(err)


def test_resolve_surface_partially_covered_requires_followup_condition(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """N7 — `--status partially-covered` without `--followup-condition` exits with a clear error."""
    assess_main = _load_assess_main()
    with pytest.raises(SystemExit) as exc:
        assess_main(
            [
                "resolve-surface",
                "1",
                "--status",
                "partially-covered",
                "--rationale",
                "unauth path tested",
            ]
        )
    message = str(exc.value) or ""
    assert "--followup-condition" in message
    assert "partially-covered" in message


def test_resolve_surface_accepts_partially_covered_with_followup_condition(
    monkeypatch, tmp_path: Path
) -> None:
    """N7 — argparse round-trip: `partially-covered` with a follow-up condition parses
    cleanly and the payload reaches the backend client with `followup_condition`."""
    module = _load_assess_module(
        "round3_resolve_surface_module",
        "agent/scripts/assess/commands/resolve_surface.py",
    )

    captured: dict[str, dict] = {}

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def patch(self, path: str, payload: dict) -> dict:
            captured["path"] = path
            captured["payload"] = payload
            return {"id": 42, "status": payload["status"], **payload}

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(tmp_path),
            engagement_key="eng-test",
            agent_root=str(tmp_path),
        ),
    )

    module.run(
        SimpleNamespace(
            surface_id=42,
            status="partially-covered",
            rationale="unauth path tested",
            source_name="",
            evidence_ref="",
            followup_condition="needs auth re-test",
            engagement_dir=str(tmp_path),
        )
    )

    assert captured["path"] == "surfaces/42"
    assert captured["payload"]["status"] == "partially-covered"
    assert captured["payload"]["followup_condition"] == "needs auth re-test"


def test_transition_phase_resolves_engagement_dir_from_cwd(
    monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`transition-phase` should share the standard assess config fallback:
    cwd with scope.json is a valid engagement context."""
    module = _load_assess_module(
        "round3_transition_phase_cwd_module",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    engagement = tmp_path / "agent" / "engagements" / "eng-test"
    engagement.mkdir(parents=True)
    scope_path = engagement / "scope.json"
    scope_path.write_text(
        json.dumps({"engagement_type": "web", "current_phase": ""}),
        encoding="utf-8",
    )

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.delenv("ENGAGEMENT_DIR", raising=False)
    monkeypatch.setenv("ORCHESTRATOR_BASE_URL", "http://127.0.0.1:9")
    monkeypatch.chdir(engagement)

    module.run(SimpleNamespace(engagement_dir=None, target_phase="recon", force=False))

    assert json.loads(scope_path.read_text(encoding="utf-8"))["current_phase"] == "recon"
    assert "Phase transitioned" in capsys.readouterr().out


def test_transition_phase_backend_error_blocks_precondition_check(
    monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Backend/query failures during guarded phase transitions are blockers
    because the readiness state is unknown."""
    module = _load_assess_module(
        "round3_transition_phase_blocker_module",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    engagement = tmp_path / "agent" / "engagements" / "eng-test"
    engagement.mkdir(parents=True)
    scope_path = engagement / "scope.json"
    scope_path.write_text(
        json.dumps({"engagement_type": "web", "current_phase": "recon"}),
        encoding="utf-8",
    )

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get(self, _path: str) -> dict:
            raise RuntimeError("backend unavailable")

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(engagement),
            engagement_key=engagement.name,
            agent_root=str(tmp_path / "agent"),
        ),
    )

    with pytest.raises(SystemExit) as exc:
        module.run(
            SimpleNamespace(
                engagement_dir=str(engagement),
                target_phase="collect",
                force=False,
            )
        )

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "precondition_check_failed" in err
    assert "backend unavailable" in err
    assert json.loads(scope_path.read_text(encoding="utf-8"))["current_phase"] == "recon"


def test_transition_phase_both_engagement_advances_code_track_separately(
    monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_assess_module(
        "round3_transition_phase_both_code_module",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    engagement = tmp_path / "agent" / "engagements" / "eng-test"
    engagement.mkdir(parents=True)
    scope_path = engagement / "scope.json"
    scope_path.write_text(
        json.dumps({"engagement_type": "both", "current_phase": "recon", "code_phase": "ingest"}),
        encoding="utf-8",
    )

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get(self, path: str) -> dict:
            if path == "code/coverage":
                return {"total_files": 2, "by_classification": {"critical": {"count": 1}}}
            return {}

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(engagement),
            engagement_key=engagement.name,
            agent_root=str(tmp_path / "agent"),
        ),
    )

    module.run(
        SimpleNamespace(
            engagement_dir=str(engagement),
            target_phase="classify-map",
            force=False,
            track="auto",
        )
    )

    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    assert scope["current_phase"] == "recon"
    assert scope["code_phase"] == "classify-map"
    assert "Phase transitioned (code)" in capsys.readouterr().out


def test_transition_phase_both_engagement_requires_track_for_ambiguous_complete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_assess_module(
        "round3_transition_phase_both_ambiguous_module",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    engagement = tmp_path / "agent" / "engagements" / "eng-test"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(
        json.dumps({"engagement_type": "both", "current_phase": "report", "code_phase": "verify-variant"}),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc:
        module.run(
            SimpleNamespace(
                engagement_dir=str(engagement),
                target_phase="complete",
                force=False,
                track="auto",
            )
        )

    assert exc.value.code == 2
    assert "pass --track web or --track code" in capsys.readouterr().err


def test_transition_phase_exploit_variant_gate_requests_full_dispatch_page(
    monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The variant-pass gate must request a page large enough that engagements
    with hundreds of dispatches do not drop the variant run behind the
    default backend limit=100. Regression for PR 14 Codex P1."""
    module = _load_assess_module(
        "transition_phase_variant_pagination_module",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    engagement = tmp_path / "agent" / "engagements" / "eng-test"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(
        json.dumps({"engagement_type": "web", "current_phase": "verify"}),
        encoding="utf-8",
    )

    confirmed_finding = {
        "slug": "ssrf-host-header",
        "severity": "high",
        "verification_state": "verified",
        "workflow_status": "active",
    }
    older_variant_dispatch = {
        "agent_role": "vulnerability-analyst",
        "task": "Variant hunt for ssrf-host-header siblings",
        "finding_slugs": ["ssrf-host-header"],
    }
    captured_paths: list[str] = []

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get(self, path: str):
            captured_paths.append(path)
            if path == "findings":
                return [confirmed_finding]
            if path.startswith("dispatches"):
                return [older_variant_dispatch]
            return []

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(engagement),
            engagement_key=engagement.name,
            agent_root=str(tmp_path / "agent"),
        ),
    )

    module.run(
        SimpleNamespace(
            engagement_dir=str(engagement),
            target_phase="exploit",
            force=False,
        )
    )

    dispatch_paths = [p for p in captured_paths if p.startswith("dispatches")]
    assert dispatch_paths, "transition-phase did not query dispatches"
    dispatch_query = dispatch_paths[0]
    assert "limit=1000" in dispatch_query, (
        f"variant-pass gate must request the full backend page, got: {dispatch_query!r}"
    )
    assert "role=vulnerability-analyst" in dispatch_query
    err = capsys.readouterr().err
    assert "missing_variant_pass" not in err


def test_check_coverage_reports_partially_covered_surfaces(
    monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`check-coverage` should explain partial-coverage blockers instead of
    exiting non-zero without naming the follow-up condition."""
    module = _load_assess_module(
        "round3_check_coverage_module",
        "agent/scripts/assess/commands/check_coverage.py",
    )

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get(self, path: str) -> dict:
            assert path == "coverage-readiness"
            return {
                "ready": False,
                "blocker_count": 1,
                "unresolved_surfaces": [],
                "partially_covered_surfaces": [
                    {
                        "surface_type": "object_reference",
                        "target_descriptor": "https://example.test/api/users/{id}",
                        "followup_condition": "needs auth re-test",
                    }
                ],
                "high_risk_deferred_surfaces": [],
            }

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(tmp_path),
            engagement_key="eng-test",
            agent_root=str(tmp_path),
        ),
    )

    with pytest.raises(SystemExit) as exc:
        module.run(SimpleNamespace(engagement_dir=str(tmp_path)))

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "Partially covered surfaces need follow-up" in err
    assert "needs auth re-test" in err


def _load_assess_module(name: str, relative: str):
    """Load an assess CLI submodule by relative path so tests can call ``module.run`` directly."""
    import importlib.util

    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = repo_root / relative
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_dispatch_action(db_path: Path, action: str, extra: list[str] | None = None, reason: str = "") -> None:
    module = _load_assess_module(
        "wave3_dispatch_module",
        "agent/scripts/assess/commands/dispatch.py",
    )
    module.run(
        SimpleNamespace(
            db_path=str(db_path),
            action=action,
            extra=list(extra or []),
            reason=reason,
            by="status",
        )
    )


def _run_list_clusters_action(
    db_path: Path,
    status: str = "pending",
    limit: int = 100,
    host: str = "",
) -> None:
    module = _load_assess_module(
        "wave3_list_clusters_module",
        "agent/scripts/assess/commands/list_clusters.py",
    )
    module.run(
        SimpleNamespace(
            db_path=str(db_path),
            status=status,
            limit=limit,
            host=host,
        )
    )


def test_dispatch_defer_items_accepts_multiple_positional_ids(tmp_path: Path) -> None:
    """P1 #10: defer-items must affect every id, not just extra[0]."""
    db = tmp_path / "cases.db"
    _seed_dispatch_db(
        db,
        [
            {"queue_key": "q:1", "url": "https://target.example/a", "id": 1},
            {"queue_key": "q:2", "url": "https://target.example/b", "id": 2},
            {"queue_key": "q:3", "url": "https://target.example/c", "id": 3},
        ],
    )

    _run_dispatch_action(db, "defer-items", ["1", "2", "3"], reason="low signal")

    rows = sqlite3.connect(str(db)).execute(
        "SELECT id, status, terminal_reason FROM work_items ORDER BY id"
    ).fetchall()
    assert [(r[0], r[1]) for r in rows] == [(1, "skipped"), (2, "skipped"), (3, "skipped")]
    assert all(r[2] == "low signal" for r in rows)


def test_dispatch_defer_items_accepts_comma_separated(tmp_path: Path) -> None:
    """P1 #10: comma form still works alongside the multi-positional form."""
    db = tmp_path / "cases.db"
    _seed_dispatch_db(
        db,
        [
            {"queue_key": "q:1", "url": "https://target.example/a", "id": 10},
            {"queue_key": "q:2", "url": "https://target.example/b", "id": 11},
        ],
    )

    _run_dispatch_action(db, "defer-items", ["10,11"], reason="noise")

    rows = sqlite3.connect(str(db)).execute(
        "SELECT status FROM work_items ORDER BY id"
    ).fetchall()
    assert [r[0] for r in rows] == ["skipped", "skipped"]


def test_dispatch_defer_items_with_no_ids_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """P1 #10: empty / pure-comma id input must abort instead of silently no-op."""
    db = tmp_path / "cases.db"
    _seed_dispatch_db(db, [])

    with pytest.raises(SystemExit):
        _run_dispatch_action(db, "defer-items", [], reason="x")
    err = capsys.readouterr().err
    assert "Usage" in err or "id" in err.lower()


def test_dispatch_defer_items_pure_comma_string_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """P3 #15: a pure-comma id_list (e.g. ',') must abort instead of silently no-op."""
    db = tmp_path / "cases.db"
    _seed_dispatch_db(db, [])

    with pytest.raises(SystemExit):
        _run_dispatch_action(db, "defer-items", [","], reason="x")
    err = capsys.readouterr().err
    assert "at least one numeric ID" in err


def test_dispatch_defer_items_zero_rows_exits_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """P2 #11: zero matched rows must surface an error so a typo isn't a silent success."""
    db = tmp_path / "cases.db"
    _seed_dispatch_db(
        db,
        [
            {"queue_key": "q:1", "url": "https://target.example/a", "id": 1, "status": "done"},
        ],
    )

    with pytest.raises(SystemExit):
        _run_dispatch_action(db, "defer-items", ["1"], reason="x")
    err = capsys.readouterr().err
    assert "no pending items matched" in err


def test_dispatch_done_marks_every_id(tmp_path: Path) -> None:
    """P1 #10: done must update all ids, not just the first one in `extra`."""
    db = tmp_path / "cases.db"
    _seed_dispatch_db(
        db,
        [
            {"queue_key": "q:1", "url": "https://target.example/a", "id": 1, "status": "processing"},
            {"queue_key": "q:2", "url": "https://target.example/b", "id": 2, "status": "processing"},
        ],
    )

    _run_dispatch_action(db, "done", ["1", "2"])

    rows = sqlite3.connect(str(db)).execute("SELECT status FROM work_items ORDER BY id").fetchall()
    assert [r[0] for r in rows] == ["done", "done"]


def test_dispatch_peek_invalid_limit_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """P3 #12: a non-integer peek limit prints a clean usage line instead of a stacktrace."""
    db = tmp_path / "cases.db"
    _seed_dispatch_db(db, [])
    with pytest.raises(SystemExit):
        _run_dispatch_action(db, "peek", ["api", "abc"])
    err = capsys.readouterr().err
    assert "must be an integer" in err


def test_dispatch_fetch_by_priority_warns_when_only_non_routable_pending(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """P2 #14: pending rows in non-routable types must surface a stderr WARN."""
    db = tmp_path / "cases.db"
    _seed_dispatch_db(
        db,
        [
            {
                "queue_key": "img:1",
                "url": "https://target.example/logo.png",
                "id": 1,
                "type": "image",
                "status": "pending",
            },
        ],
    )

    _run_dispatch_action(db, "fetch-by-priority", ["10", "auto"])

    captured = capsys.readouterr()
    assert "WARN fetch-by-priority" in captured.err
    assert "image" in captured.err


def test_list_clusters_host_filter_matches_full_population(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """P1 #25: --host considers ALL items per cluster, not just the first 5 samples."""
    db = tmp_path / "cases.db"
    rows = []
    # Cluster A: 6 items on other-host.com, then 1 on target.example (sample window covers
    # only the first 5 by priority — the legacy implementation would miss target.example).
    for i in range(6):
        rows.append(
            {
                "queue_key": f"a:{i}",
                "url": f"https://other-host.com/x{i}",
                "id": i + 1,
                "cluster_key": "alpha",
                "priority_score": 100 - i,
                "type": "api",
            }
        )
    rows.append(
        {
            "queue_key": "a:target",
            "url": "https://target.example/important",
            "id": 100,
            "cluster_key": "alpha",
            "priority_score": 1,
            "type": "api",
        }
    )
    # Cluster B: only on other-host.com.
    rows.append(
        {
            "queue_key": "b:1",
            "url": "https://other-host.com/y",
            "id": 200,
            "cluster_key": "beta",
            "priority_score": 50,
            "type": "api",
        }
    )
    _seed_dispatch_db(db, rows)

    _run_list_clusters_action(db, host="target.example")
    payload = json.loads(capsys.readouterr().out)
    cluster_keys = [c["cluster_key"] for c in payload["clusters"]]
    assert "alpha" in cluster_keys
    assert "beta" not in cluster_keys


def test_list_clusters_host_filter_supports_wildcard(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Bonus #26: '*.example.com' fnmatches subdomains, exact 'example.com' does not."""
    db = tmp_path / "cases.db"
    _seed_dispatch_db(
        db,
        [
            {
                "queue_key": "a:1",
                "url": "https://api.example.com/v1",
                "id": 1,
                "cluster_key": "alpha",
                "priority_score": 10,
            },
            {
                "queue_key": "a:2",
                "url": "https://example.com/",
                "id": 2,
                "cluster_key": "beta",
                "priority_score": 5,
            },
        ],
    )

    _run_list_clusters_action(db, host="*.example.com")
    payload = json.loads(capsys.readouterr().out)
    cluster_keys = [c["cluster_key"] for c in payload["clusters"]]
    assert "alpha" in cluster_keys
    assert "beta" not in cluster_keys

    # Exact apex match excludes subdomain-only clusters.
    _run_list_clusters_action(db, host="example.com")
    payload = json.loads(capsys.readouterr().out)
    cluster_keys = [c["cluster_key"] for c in payload["clusters"]]
    assert "beta" in cluster_keys
    assert "alpha" not in cluster_keys


def test_supersede_intel_requires_natural_key_before_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Supersede inserts a replacement row; metadata-only edits must fail
    client-side and tell the operator to include the natural key."""
    supersede_module = _load_assess_module(
        "wave3_supersede_intel_module",
        "agent/scripts/assess/commands/supersede_intel.py",
    )

    captured: dict[str, object] = {}

    class _StubClient:
        _engagement_prefix = "/engagements/test"

        def __init__(self, *_: object, **__: object) -> None:
            pass

        def _request(self, method: str, path: str, body: bytes | None = None):
            captured["method"] = method
            captured["path"] = path
            captured["body"] = body
            return 200, json.dumps({"id": 5, "validation_status": "exploited"})

        def close(self) -> None:
            return None

    monkeypatch.setattr(supersede_module, "AssessmentClient", _StubClient)
    monkeypatch.setattr(
        supersede_module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(tmp_path),
            engagement_key="eng-test",
            agent_root=str(tmp_path),
        ),
    )

    with pytest.raises(SystemExit) as exc:
        supersede_module.run(
            SimpleNamespace(
                intel_type="cve",
                intel_id=5,
                payload=None,
                inline_payload='{"validation_status":"exploited"}',
                rationale="post-validation",
                engagement_dir=str(tmp_path),
            )
        )

    assert exc.value.code == 1
    assert captured == {}
    err = capsys.readouterr().err
    assert "missing required supersede natural-key field: cve_id" in err
    assert "missing required supersede natural-key field: affected_component" in err


def test_validate_dispatch_contract_accepts_minimal_payload(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """P3 #31: the validator returns OK for a contract with every required field set."""
    assess_main = _load_assess_main()
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
        "skills": "auth-bypass",
    }
    contract_path = tmp_path / "dispatch.json"
    contract_path.write_text(json.dumps(payload), encoding="utf-8")

    assess_main(["validate-dispatch-contract", str(contract_path)])
    assert "OK" in capsys.readouterr().out


def test_validate_dispatch_contract_accepts_dispatch_register_payload(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The contract preflight accepts the same role field used by agent start."""
    assess_main = _load_assess_main()
    payload = {
        "agent_id": "VA-1",
        "agent_role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
        "skills": "auth-bypass",
    }
    contract_path = tmp_path / "dispatch.json"
    contract_path.write_text(json.dumps(payload), encoding="utf-8")

    assess_main(["validate-dispatch-contract", str(contract_path)])
    assert "OK" in capsys.readouterr().out


def test_validate_dispatch_contract_rejects_role_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assess_main = _load_assess_main()
    payload = {
        "role": "recon-specialist",
        "agent_role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
        "skills": "auth-bypass",
    }
    contract_path = tmp_path / "dispatch.json"
    contract_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SystemExit):
        assess_main(["validate-dispatch-contract", str(contract_path)])
    assert "role and agent_role must match" in capsys.readouterr().err


def test_list_skills_uses_directory_names_for_dispatch_audit(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assess_main = _load_assess_main()

    assess_main(["list-skills", "--json"])

    rows = json.loads(capsys.readouterr().out)
    google = next(row for row in rows if row["path"] == "agent/skills/google-workspaces/SKILL.md")
    assert google["name"] == "google-workspaces"


def test_validate_dispatch_contract_accepts_list_skills_canonical_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assess_main = _load_assess_main()
    payload = {
        "agent_role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
        "skills": "google-workspaces",
    }
    contract_path = tmp_path / "dispatch.json"
    contract_path.write_text(json.dumps(payload), encoding="utf-8")

    assess_main(["validate-dispatch-contract", str(contract_path)])
    captured = capsys.readouterr()
    assert "OK" in captured.out
    assert "WARN skill" not in captured.err


def test_validate_dispatch_contract_rejects_unknown_dispatch_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Unknown dispatch_mode values surface as errors so the contract fails closed."""
    assess_main = _load_assess_main()
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "turbo-mode",
        "skills": "auth-bypass",
    }
    contract_path = tmp_path / "dispatch.json"
    contract_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SystemExit):
        assess_main(["validate-dispatch-contract", str(contract_path)])
    err = capsys.readouterr().err
    assert "dispatch_mode" in err and "turbo-mode" in err


def test_validate_dispatch_contract_requires_skills_for_specialist(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Specialist dispatches must declare which skills the agent loaded."""
    assess_main = _load_assess_main()
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
    }
    contract_path = tmp_path / "dispatch.json"
    contract_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SystemExit):
        assess_main(["validate-dispatch-contract", str(contract_path)])
    err = capsys.readouterr().err
    assert "skills is required" in err


def test_validate_dispatch_contract_operator_skills_optional(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Operator role coordinates phases; skills are not required on operator dispatches."""
    assess_main = _load_assess_main()
    payload = {
        "role": "operator",
        "dispatch_mode": "deep-manual",
    }
    contract_path = tmp_path / "dispatch.json"
    contract_path.write_text(json.dumps(payload), encoding="utf-8")

    assess_main(["validate-dispatch-contract", str(contract_path)])
    assert "OK" in capsys.readouterr().out


def test_validate_dispatch_contract_operator_skills_optional_case_insensitive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Operator casing variants are exempt from specialist skill requirements."""
    assess_main = _load_assess_main()
    payload = {
        "role": "Operator",
        "agent_role": "operator",
        "dispatch_mode": "deep-manual",
    }
    contract_path = tmp_path / "dispatch.json"
    contract_path.write_text(json.dumps(payload), encoding="utf-8")

    assess_main(["validate-dispatch-contract", str(contract_path)])
    assert "OK" in capsys.readouterr().out


def test_actor_kind_warn_on_non_log_subcommand(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """P3 #33: passing --actor-kind to a subcommand that doesn't consume it warns on stderr."""
    assess_main = _load_assess_main()
    payload = {
        "role": "vulnerability-analyst",
        "dispatch_mode": "deep-manual",
        "skills": "auth-bypass",
    }
    contract_path = tmp_path / "dispatch.json"
    contract_path.write_text(json.dumps(payload), encoding="utf-8")

    assess_main(
        [
            "--actor-kind",
            "operator",
            "validate-dispatch-contract",
            str(contract_path),
        ]
    )
    err = capsys.readouterr().err
    assert "--actor-kind=operator ignored" in err


# ---------------------------------------------------------------------------
# Round 9 — handoff render tests against the backend
#
# The renderer now reads from the orchestrator's assessment_dispatches and
# assessment_dispatch_handoffs tables.
# These tests stub the AssessmentClient calls so we exercise the rendering
# logic without standing up the real backend.
# ---------------------------------------------------------------------------


def _stub_render_handoff_environment(
    monkeypatch,
    module,
    engagement_dir: Path,
    *,
    handoff: dict | None,
    dispatch_row: dict | None = None,
    findings_by_slug: dict[str, dict] | None = None,
    missing_slugs: tuple[str, ...] = (),
    credentials: list[dict] | None = None,
) -> None:
    """Wire a fake AssessmentClient + load_config into the dispatch module."""

    class _StubClient:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def get(self, endpoint: str):
            if endpoint.startswith("findings/"):
                slug = endpoint.split("/", 1)[1]
                if slug in missing_slugs:
                    raise module.AssessError("HTTP 404: not found")
                if findings_by_slug and slug in findings_by_slug:
                    return findings_by_slug[slug]
                raise module.AssessError("HTTP 404: not found")
            if endpoint == "credentials":
                return list(credentials or [])
            raise module.AssessError(f"unexpected endpoint {endpoint}")

        def get_handoff(self, agent_id: str):
            if handoff is None:
                return None
            return handoff

        def get_dispatch(self, agent_id: str):
            return dispatch_row

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", _StubClient)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(engagement_dir),
            engagement_key=engagement_dir.name,
            agent_root=str(engagement_dir.parent),
        ),
    )


def _load_dispatch_module():
    """Load ``dispatch.py`` (internal lifecycle + work-buffer implementation).

    The operator CLI routes to ``aith assess agent`` / ``aith assess work-buffer``;
    this module remains shared implementations and legacy argparse for tests.
    """
    return _load_assess_module(
        "round9_dispatch_module",
        "agent/scripts/assess/commands/dispatch.py",
    )


def _run_render_handoff(
    module,
    engagement_dir: Path,
    agent_id: str,
    *,
    max_lines: int = 40,
    include_evidence: bool = False,
) -> None:
    module.run(
        SimpleNamespace(
            db_path="render-handoff",
            action=agent_id,
            extra=[],
            reason="",
            by="status",
            max_lines=max_lines,
            include_evidence=include_evidence,
            engagement_dir=str(engagement_dir),
        )
    )


def test_render_handoff_emits_known_fields_for_existing_agent_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Round 9: render the bounded handoff blob from backend dispatch + handoff rows."""
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "tools").mkdir()
    (engagement_dir / "tools" / "exploit-state").mkdir()
    (engagement_dir / "tools" / "exploit-state" / "EX-001-payload.sql").write_text(
        "-- payload", encoding="utf-8"
    )

    handoff = {
        "agent_id": "AGENT-EX-1",
        "agent_role": "vulnerability-analyst",
        "summary": "Validated IDOR on /api/users/{id}; confirmed write primitive.",
        "confidence": "high",
        "finding_slugs": ["VA-001", "VA-002"],
        "next_steps": [
            {"action": "replay captured cookie at /api/users/2 and confirm IDOR write"},
        ],
        "coverage_gaps": [
            {"area": "auth boundary", "reason": "anonymous session not tested"},
        ],
        "working_artifacts": [
            {"path": "tools/exploit-state/EX-001-payload.sql"},
            {"path": "tools/exploit-state/EX-002-poc.py"},
        ],
        "runtime_issues": [],
        "open_questions": [],
        "extras": None,
        "recommended_next_agent": "exploit-developer",
        "created_at": "2026-04-27T10:00:00Z",
    }
    dispatch_row = {
        "agent_id": "AGENT-EX-1",
        "agent_role": "vulnerability-analyst",
        "task": "Validate IDOR on /api/users/{id}",
        "scope_host": "target.example",
        "dispatched_at": "2026-04-27T10:00:00Z",
        "status": "completed",
    }

    module = _load_dispatch_module()
    _stub_render_handoff_environment(
        monkeypatch,
        module,
        engagement_dir,
        handoff=handoff,
        dispatch_row=dispatch_row,
        findings_by_slug={
            "VA-001": {"slug": "VA-001", "title": "IDOR write on user profile", "severity": "high"},
            "VA-002": {"slug": "VA-002", "title": "IDOR read on user email", "severity": "medium"},
        },
        credentials=[
            {"id": 17, "source_name": "vulnerability-analyst"},
            {"id": 18, "source_name": "exploit-developer"},
        ],
    )

    _run_render_handoff(module, engagement_dir, "AGENT-EX-1")

    out = capsys.readouterr().out
    assert "#### Handoff from vulnerability-analyst dispatch AGENT-EX-1" in out
    assert "Validate IDOR on /api/users/{id}" in out
    assert "target.example" in out
    assert "Validated IDOR on /api/users/{id}" in out  # summary
    assert "Confidence:** high" in out
    assert "`VA-001` — IDOR write on user profile [severity=high]" in out
    assert "`VA-002` — IDOR read on user email [severity=medium]" in out
    assert "tools/exploit-state/EX-001-payload.sql` (state: present)" in out
    assert "tools/exploit-state/EX-002-poc.py` (state: missing)" in out
    assert "replay captured cookie at /api/users/2" in out
    assert "Recommended next agent:** exploit-developer" in out
    assert "Credentials captured:** 1 rows (ids: 17)" in out


def test_render_handoff_404s_unknown_agent_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Round 9: an unknown agent-id (no handoff row) exits 2."""
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()

    module = _load_dispatch_module()
    _stub_render_handoff_environment(
        monkeypatch, module, engagement_dir, handoff=None
    )

    with pytest.raises(SystemExit) as exc_info:
        _run_render_handoff(module, engagement_dir, "AGENT-DOES-NOT-EXIST")
    assert exc_info.value.code == 2
    err = capsys.readouterr().err
    assert "AGENT-DOES-NOT-EXIST" in err
    # Helpful hint about where the data should come from.
    assert "agent handoff" in err


def test_render_handoff_truncates_at_max_lines(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Round 9: a large finding_slugs list collapses with '... and N more'."""
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()

    slugs = [f"VA-{idx:03d}" for idx in range(1, 21)]
    handoff = {
        "agent_id": "AGENT-MANY-FINDINGS",
        "agent_role": "vulnerability-analyst",
        "summary": "Deep IDOR sweep across 20 endpoints — many findings recorded.",
        "finding_slugs": slugs,
        "next_steps": [{"action": "promote highest-severity finding to exploit-developer"}],
        "coverage_gaps": [],
        "working_artifacts": [],
        "runtime_issues": [],
        "open_questions": [],
        "recommended_next_agent": "exploit-developer",
        "created_at": "2026-04-27T11:00:00Z",
    }
    dispatch_row = {
        "agent_id": "AGENT-MANY-FINDINGS",
        "agent_role": "vulnerability-analyst",
        "task": "deep IDOR sweep across 20 endpoints",
        "scope_host": "target.example",
        "dispatched_at": "2026-04-27T11:00:00Z",
        "status": "completed",
    }
    findings = {
        slug: {"slug": slug, "title": f"finding {slug}", "severity": "medium"}
        for slug in slugs
    }

    module = _load_dispatch_module()
    _stub_render_handoff_environment(
        monkeypatch,
        module,
        engagement_dir,
        handoff=handoff,
        dispatch_row=dispatch_row,
        findings_by_slug=findings,
    )

    _run_render_handoff(module, engagement_dir, "AGENT-MANY-FINDINGS", max_lines=20)
    out = capsys.readouterr().out
    assert "... and " in out and " more" in out
    assert "#### Handoff from vulnerability-analyst dispatch AGENT-MANY-FINDINGS" in out
    assert "promote highest-severity finding" in out


def test_render_handoff_missing_slug_distinct_from_fetch_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """ISSUE-010: 404 on a slug renders 'slug missing in backend', not 'non-dict response'."""
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()

    handoff = {
        "agent_id": "AGENT-DROP",
        "agent_role": "vulnerability-analyst",
        "summary": "Slug was killed between dispatch and handoff.",
        "finding_slugs": ["VA-DROPPED"],
        "next_steps": [],
        "coverage_gaps": [],
        "working_artifacts": [],
        "runtime_issues": [],
        "open_questions": [],
        "recommended_next_agent": None,
        "created_at": "2026-04-27T12:00:00Z",
    }
    dispatch_row = {
        "agent_id": "AGENT-DROP",
        "agent_role": "vulnerability-analyst",
        "task": "slug-drop test",
        "scope_host": "target.example",
        "dispatched_at": "2026-04-27T12:00:00Z",
        "status": "completed",
    }

    module = _load_dispatch_module()
    _stub_render_handoff_environment(
        monkeypatch,
        module,
        engagement_dir,
        handoff=handoff,
        dispatch_row=dispatch_row,
        missing_slugs=("VA-DROPPED",),
    )
    _run_render_handoff(module, engagement_dir, "AGENT-DROP")
    out = capsys.readouterr().out
    assert "VA-DROPPED" in out
    assert "deleted or never recorded" in out, (
        "ISSUE-010: a 404 on a slug must render the explicit 'slug missing' wording, "
        "not a generic 'non-dict response' / 'fetch error' fallback"
    )


# ---------------------------------------------------------------------------
# Round 9 — backend agent lifecycle / handoff / decision tests
# record-decision / record-handoff` smoke tests. The CLI calls the
# AssessmentClient's helper methods, so we wire a fake client and assert
# the CLI builds the right payloads / prints the right output.
# ---------------------------------------------------------------------------


class _CapturingClient:
    """Minimal AssessmentClient stand-in for CLI smoke tests."""

    def __init__(self, *_: object, **__: object) -> None:
        self.recorded: list[dict] = []
        self.patches: list[tuple[str, dict]] = []
        self.dispatches_by_id: dict[str, dict] = {}
        self.handoff_response: dict | None = None
        self.decisions_recorded: list[dict] = []
        self.handoff_calls: list[dict] = []
        self.handoffs_by_id: dict[str, dict] = {}

    def record_dispatch(self, payload: dict) -> dict:
        self.recorded.append(payload)
        row = {"id": 1, **payload, "status": payload.get("status", "in-progress")}
        self.dispatches_by_id[row["agent_id"]] = row
        return row

    def update_dispatch(self, agent_id: str, patch: dict) -> dict:
        self.patches.append((agent_id, patch))
        existing = dict(self.dispatches_by_id.get(agent_id) or {"agent_id": agent_id})
        existing.update(patch)
        self.dispatches_by_id[agent_id] = existing
        return existing

    def get_dispatch(self, agent_id: str):
        return self.dispatches_by_id.get(agent_id)

    def list_dispatches(self, **filters):
        return list(self.dispatches_by_id.values())

    def record_decision(self, payload: dict) -> dict:
        self.decisions_recorded.append(payload)
        return {"id": 99, **payload}

    def record_handoff(self, payload: dict, *, upsert: bool = False) -> dict:
        # Track every call for idempotency tests; the dispatch CLI should
        # always pass upsert=True so checkpointing the same agent_id is safe.
        self.handoff_response = payload
        self.handoff_calls.append({"payload": payload, "upsert": upsert})
        prior = self.handoffs_by_id.get(payload.get("agent_id"))
        if prior is not None and not upsert:
            from agent.scripts.assess.lib.client import AssessError  # type: ignore
            raise AssessError("HTTP 409:\nduplicate (engagement, agent_id)")
        # Latest write wins (upsert semantics).
        merged = {"id": 42, **(prior or {}), **payload}
        self.handoffs_by_id[payload.get("agent_id")] = merged
        return {"id": merged["id"], "agent_id": merged.get("agent_id")}

    def update_handoff(self, agent_id: str, patch: dict) -> dict:
        existing = dict(self.handoffs_by_id.get(agent_id) or {"agent_id": agent_id})
        existing.update(patch)
        self.handoffs_by_id[agent_id] = existing
        return existing

    def close(self) -> None:
        return None


def _run_dispatch_verb(monkeypatch, action: str, *, extra=None, **flags):
    """Execute dispatch.run with a fake AssessmentClient injected."""
    module = _load_dispatch_module()
    fake = _CapturingClient()
    monkeypatch.setattr(module, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir="/tmp/eng",
            engagement_key="eng",
            agent_root="/tmp",
        ),
    )
    args_dict = {
        "db_path": action,
        "action": "",
        "extra": list(extra or []),
        "reason": "",
        "by": "status",
        "max_lines": 40,
        "include_evidence": False,
        "engagement_dir": None,
        "agent_id": None,
        "agent_role": None,
        "task": None,
        "scope_host": None,
        "dispatch_model": None,
        "reasoning": None,
        "dispatch_mode_arg": None,
        "from_json": None,
        "dispatch_status": None,
        "completed_at": None,
        "finding_slugs": None,
        "filter_role": None,
        "filter_since": None,
        "task_q": None,
        "dispatch_limit": None,
        "decision_kind": None,
        "payload_json": None,
        "surfaced_to_user": False,
        "decision_host": None,
        "decision_vendor": None,
        "decision_choice": None,
        "decision_note": None,
        "decision_phase": None,
        "hf_summary": None,
        "hf_confidence": None,
        "hf_next_steps": None,
        "hf_coverage_gaps": None,
        "hf_runtime_issues": None,
        "hf_working_artifacts": None,
        "hf_open_questions": None,
        "hf_recommended_next_agent": None,
        "hf_extras_json": None,
    }
    args_dict.update(flags)
    module.run(SimpleNamespace(**args_dict))
    return fake


def _dispatch_args(action: str, *, db_path: str | None = None, extra=None, **flags) -> SimpleNamespace:
    args_dict = {
        "db_path": action if db_path is None else db_path,
        "action": "" if db_path is None else action,
        "extra": list(extra or []),
        "reason": "",
        "by": "status",
        "max_lines": 40,
        "include_evidence": False,
        "engagement_dir": None,
        "agent_id": None,
        "agent_role": None,
        "task": None,
        "scope_host": None,
        "dispatch_model": None,
        "reasoning": None,
        "dispatch_mode_arg": None,
        "from_json": None,
        "dispatch_status": None,
        "completed_at": None,
        "finding_slugs": None,
        "filter_role": None,
        "filter_since": None,
        "task_q": None,
        "dispatch_limit": None,
        "decision_kind": None,
        "payload_json": None,
        "surfaced_to_user": False,
        "decision_host": None,
        "decision_vendor": None,
        "decision_choice": None,
        "decision_note": None,
        "decision_phase": None,
        "hf_summary": None,
        "hf_confidence": None,
        "hf_next_steps": None,
        "hf_coverage_gaps": None,
        "hf_runtime_issues": None,
        "hf_working_artifacts": None,
        "hf_open_questions": None,
        "hf_recommended_next_agent": None,
        "hf_extras_json": None,
    }
    args_dict.update(flags)
    return SimpleNamespace(**args_dict)


def test_dispatch_backend_actions_reject_cases_db_prefix(capsys: pytest.CaptureFixture[str]) -> None:
    module = _load_dispatch_module()

    with pytest.raises(SystemExit) as exc_info:
        module.run(_dispatch_args("record-handoff", db_path="cases.db"))

    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "must not take a cases.db path" in err
    assert "aith assess agent handoff" in err


def test_dispatch_record_handoff_from_json_rejects_agent_id_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_dispatch_module()
    payload_path = tmp_path / "handoff.json"
    payload_path.write_text(
        json.dumps(
            {
                "agent_id": "stale-local-name",
                "agent_role": "recon-specialist",
                "summary": "checkpoint from a local artifact",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            _dispatch_args(
                "record-handoff",
                from_json=str(payload_path),
                agent_id="actual-agent-id",
            )
        )

    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "does not match explicit --agent-id 'actual-agent-id'" in err


def test_dispatch_register_writes_payload(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _run_dispatch_verb(
        monkeypatch,
        "register",
        agent_id="AG-CLI-1",
        agent_role="vulnerability-analyst",
        task="IDOR sweep",
        reasoning="high",
        dispatch_mode_arg="item-iterating",
        skills="idor-testing",
    )
    out = capsys.readouterr().out
    body = json.loads(out)
    assert body["agent_id"] == "AG-CLI-1"
    assert body["status"] == "in-progress"
    assert fake.recorded[0]["agent_role"] == "vulnerability-analyst"
    assert fake.recorded[0]["dispatch_mode"] == "item-iterating"


def test_dispatch_register_normalizes_list_skills_from_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload_path = tmp_path / "dispatch.json"
    payload_path.write_text(
        json.dumps(
            {
                "agent_id": "AG-LIST-SKILLS",
                "agent_role": "vulnerability-analyst",
                "task": "IDOR sweep",
                "dispatch_mode": "item-iterating",
                "skills": ["idor-testing", "auth-bypass"],
            }
        ),
        encoding="utf-8",
    )

    fake = _run_dispatch_verb(monkeypatch, "register", from_json=str(payload_path))
    capsys.readouterr()

    assert fake.recorded[0]["skills"] == "idor-testing,auth-bypass"


def test_dispatch_register_rejects_missing_skills_locally(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _run_dispatch_verb(
            monkeypatch,
            "register",
            agent_id="AG-NO-SKILL",
            agent_role="vulnerability-analyst",
            task="IDOR sweep",
            dispatch_mode_arg="item-iterating",
        )
    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "skills is required for role 'vulnerability-analyst'" in err


def test_dispatch_register_warns_on_structured_overlap(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_dispatch_module()
    fake = _CapturingClient()
    fake.dispatches_by_id["AG-OLD"] = {
        "id": 1,
        "agent_id": "AG-OLD",
        "agent_role": "vulnerability-analyst",
        "status": "in-progress",
        "finding_slugs": ["VA-001"],
        "task": "Older exploitation attempt",
    }
    monkeypatch.setattr(module, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir="/tmp/eng",
            engagement_key="eng",
            agent_root="/tmp",
        ),
    )

    module.run(
        _dispatch_args(
            "register",
            agent_id="AG-NEW",
            agent_role="vulnerability-analyst",
            task="Follow-up exploitation attempt",
            finding_slugs="VA-001",
            dispatch_mode_arg="item-iterating",
            skills="idor-testing",
        )
    )

    err = capsys.readouterr().err
    assert "WARN agent start" in err
    assert "same finding_slugs: VA-001" in err
    assert fake.recorded[0]["agent_id"] == "AG-NEW"


def test_dispatch_register_does_not_warn_for_shared_host_mode_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_dispatch_module()
    fake = _CapturingClient()
    fake.dispatches_by_id["AG-OLD"] = {
        "id": 1,
        "agent_id": "AG-OLD",
        "agent_role": "vulnerability-analyst",
        "status": "in-progress",
        "scope_host": "app.example.test",
        "dispatch_mode": "hypothesis-driven",
        "task": "Review password reset flows",
    }
    monkeypatch.setattr(module, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir="/tmp/eng",
            engagement_key="eng",
            agent_root="/tmp",
        ),
    )

    module.run(
        _dispatch_args(
            "register",
            agent_id="AG-NEW",
            agent_role="vulnerability-analyst",
            scope_host="app.example.test",
            dispatch_mode_arg="hypothesis-driven",
            task="Review account deletion flows",
            skills="idor-testing",
        )
    )

    err = capsys.readouterr().err
    assert "WARN agent start" not in err
    assert fake.recorded[0]["agent_id"] == "AG-NEW"


def test_dispatch_abort_duplicate_marks_row_and_records_decision(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_dispatch_module()
    fake = _CapturingClient()
    fake.dispatches_by_id["AG-KEEP"] = {
        "id": 1,
        "agent_id": "AG-KEEP",
        "agent_role": "vulnerability-analyst",
        "status": "in-progress",
    }
    fake.dispatches_by_id["AG-DUP"] = {
        "id": 2,
        "agent_id": "AG-DUP",
        "agent_role": "vulnerability-analyst",
        "status": "in-progress",
    }
    monkeypatch.setattr(module, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir="/tmp/eng",
            engagement_key="eng",
            agent_root="/tmp",
        ),
    )

    module.run(
        _dispatch_args(
            "abort-duplicate",
            extra=["AG-DUP"],
            replacement_agent_id="AG-KEEP",
            reason="same exploit review was registered twice",
        )
    )

    assert fake.patches[0][0] == "AG-DUP"
    assert fake.patches[0][1]["status"] == "aborted"
    decision = fake.decisions_recorded[0]
    assert decision["kind"] == "dispatch_duplicate"
    assert decision["payload"]["replacement_agent_id"] == "AG-KEEP"


def test_dispatch_abort_duplicate_rejects_missing_replacement(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _run_dispatch_verb(
            monkeypatch,
            "abort-duplicate",
            extra=["AG-DUP"],
            replacement_agent_id="AG-MISSING",
            reason="same exploit review was registered twice",
        )
    assert exc_info.value.code == 2
    err = capsys.readouterr().err
    assert "replacement dispatch 'AG-MISSING' was not found" in err


def test_dispatch_abort_duplicate_rejects_same_replacement(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _run_dispatch_verb(
            monkeypatch,
            "abort-duplicate",
            extra=["AG-DUP"],
            replacement_agent_id="AG-DUP",
            reason="same exploit review was registered twice",
        )
    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "must point at the dispatch to keep" in err


def test_dispatch_update_status_marks_completed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _run_dispatch_verb(
        monkeypatch,
        "update-status",
        extra=["AG-CLI-1"],
        dispatch_status="completed",
        finding_slugs="VA-001,VA-002",
    )
    assert fake.patches[0][0] == "AG-CLI-1"
    patch = fake.patches[0][1]
    assert patch["status"] == "completed"
    assert patch["finding_slugs"] == ["VA-001", "VA-002"]
    assert patch.get("completed_at"), "completed_at must be auto-stamped on terminal status"


def test_dispatch_list_emits_jsonl(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_dispatch_module()

    class _ListClient(_CapturingClient):
        def list_dispatches(self, **filters):
            return [
                {"id": 1, "agent_id": "L1", "agent_role": "recon-specialist"},
                {"id": 2, "agent_id": "L2", "agent_role": "vulnerability-analyst"},
            ]

    fake = _ListClient()
    monkeypatch.setattr(module, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir="/tmp/eng",
            engagement_key="eng",
            agent_root="/tmp",
        ),
    )
    module.run(SimpleNamespace(
        db_path="list", action="", extra=[], reason="", by="status",
        max_lines=40, include_evidence=False, engagement_dir=None,
        agent_id=None, agent_role=None, task=None, scope_host=None,
        dispatch_model=None, reasoning=None,
        dispatch_mode_arg=None,
        from_json=None, dispatch_status=None, completed_at=None, finding_slugs=None,
        filter_role=None, filter_since=None, task_q=None, dispatch_limit=None,
        decision_kind=None, payload_json=None, surfaced_to_user=False,
        decision_host=None, decision_vendor=None, decision_choice=None,
        decision_note=None, decision_phase=None,
        hf_summary=None, hf_confidence=None, hf_next_steps=None,
        hf_coverage_gaps=None, hf_runtime_issues=None, hf_working_artifacts=None,
        hf_open_questions=None, hf_recommended_next_agent=None, hf_extras_json=None,
    ))
    out = capsys.readouterr().out
    lines = [line for line in out.strip().split("\n") if line.strip()]
    assert len(lines) == 2
    rows = [json.loads(line) for line in lines]
    assert {r["agent_id"] for r in rows} == {"L1", "L2"}


def test_dispatch_get_exits_2_on_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _run_dispatch_verb(monkeypatch, "get", extra=["NOPE"])
    assert exc_info.value.code == 2


def test_dispatch_record_decision_friendly_flags(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _run_dispatch_verb(
        monkeypatch,
        "record-decision",
        decision_kind="scope_decision",
        decision_host="vendor-saas.example.com",
        decision_vendor="salesforce",
        decision_choice="in_scope",
        surfaced_to_user=True,
    )
    decisions = fake.decisions_recorded
    assert len(decisions) == 1
    body = decisions[0]
    assert body["kind"] == "scope_decision"
    assert body["payload"]["host"] == "vendor-saas.example.com"
    assert body["surfaced_to_user"] is True


def test_dispatch_record_decision_includes_reason_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _run_dispatch_verb(
        monkeypatch,
        "record-decision",
        decision_kind="dispatch_blocked",
        decision_phase="recon",
        reason="missing massdns binary in runtime image",
        surfaced_to_user=True,
    )
    body = fake.decisions_recorded[0]
    assert body["kind"] == "dispatch_blocked"
    assert body["payload"]["phase"] == "recon"
    assert body["payload"]["reason"] == "missing massdns binary in runtime image"


def test_dispatch_record_handoff_flag_based(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _run_dispatch_verb(
        monkeypatch,
        "record-handoff",
        agent_id="HF-CLI-1",
        agent_role="vulnerability-analyst",
        hf_summary="Validated IDOR write primitive.",
        hf_next_steps=["promote to exploit-developer"],
        hf_coverage_gaps=["auth boundary: anonymous untested"],
        hf_recommended_next_agent="exploit-developer",
        finding_slugs="VA-001",
    )
    payload = fake.handoff_response
    assert payload["agent_id"] == "HF-CLI-1"
    assert payload["summary"] == "Validated IDOR write primitive."
    assert payload["next_steps"] == [{"action": "promote to exploit-developer"}]
    assert payload["coverage_gaps"][0]["area"] == "auth boundary"
    assert payload["finding_slugs"] == ["VA-001"]
    assert payload["recommended_next_agent"] == "exploit-developer"
    # The CLI MUST request upsert semantics so checkpointing is idempotent.
    assert fake.handoff_calls[-1]["upsert"] is True


def test_dispatch_record_handoff_is_idempotent_for_repeat_calls(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Round 9c: agents call record-handoff after every major step. The same
    (engagement, agent_id) tuple collides on every call after the first; the
    CLI must transparently fall back to PATCH so the agent never sees a 409."""
    module = _load_dispatch_module()
    # One fake shared across all three calls so handoffs_by_id persists.
    shared_fake = _CapturingClient()
    monkeypatch.setattr(module, "AssessmentClient", lambda *a, **k: shared_fake)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir="/tmp/eng",
            engagement_key="eng",
            agent_root="/tmp",
        ),
    )

    payload_v1 = {
        "agent_id": "HF-CHECKPOINT",
        "agent_role": "recon-specialist",
        "summary": "checkpoint v1 — wafw00f done",
        "confidence": "low",
    }
    payload_v2 = {
        "agent_id": "HF-CHECKPOINT",
        "agent_role": "recon-specialist",
        "summary": "checkpoint v2 — nmap done",
        "confidence": "medium",
    }
    payload_v3 = {
        "agent_id": "HF-CHECKPOINT",
        "agent_role": "recon-specialist",
        "summary": "checkpoint v3 — full sweep done",
        "confidence": "high",
    }

    p1 = tmp_path / "v1.json"
    p2 = tmp_path / "v2.json"
    p3 = tmp_path / "v3.json"
    p1.write_text(json.dumps(payload_v1), encoding="utf-8")
    p2.write_text(json.dumps(payload_v2), encoding="utf-8")
    p3.write_text(json.dumps(payload_v3), encoding="utf-8")

    def _invoke(path: Path) -> None:
        args_dict = {
            "db_path": "record-handoff",
            "action": "",
            "extra": [],
            "reason": "",
            "by": "status",
            "max_lines": 40,
            "include_evidence": False,
            "engagement_dir": None,
            "agent_id": None,
            "agent_role": None,
            "task": None,
            "scope_host": None,
            "dispatch_model": None,
            "reasoning": None,
            "dispatch_mode_arg": None,
            "from_json": str(path),
            "dispatch_status": None,
            "completed_at": None,
            "finding_slugs": None,
            "filter_role": None,
            "filter_since": None,
            "task_q": None,
            "dispatch_limit": None,
            "decision_kind": None,
            "payload_json": None,
            "surfaced_to_user": False,
            "decision_host": None,
            "decision_vendor": None,
            "decision_choice": None,
            "decision_note": None,
            "decision_phase": None,
            "hf_summary": None,
            "hf_confidence": None,
            "hf_next_steps": None,
            "hf_coverage_gaps": None,
            "hf_runtime_issues": None,
            "hf_working_artifacts": None,
            "hf_open_questions": None,
            "hf_recommended_next_agent": None,
            "hf_extras_json": None,
        }
        module.run(SimpleNamespace(**args_dict))

    _invoke(p1)
    _invoke(p2)
    _invoke(p3)

    # All three calls passed upsert=True (the contract).
    assert len(shared_fake.handoff_calls) == 3
    assert all(call["upsert"] is True for call in shared_fake.handoff_calls)

    # Latest payload wins; row reflects the v3 summary.
    final = shared_fake.handoffs_by_id["HF-CHECKPOINT"]
    assert final["summary"] == "checkpoint v3 — full sweep done"
    assert final["confidence"] == "high"


def test_record_handoff_client_upsert_falls_back_to_patch_on_409() -> None:
    """The client helper itself catches 409 and re-issues a PATCH."""
    from agent.scripts.assess.lib.client import AssessError, AssessmentClient

    captured: dict[str, object] = {"posts": [], "patches": []}

    class _StubClient(AssessmentClient):
        def __init__(self) -> None:
            # Skip parent __init__ — we don't need a real socket for this unit test.
            pass

        def post(self, endpoint: str, payload: dict) -> dict:  # type: ignore[override]
            captured["posts"].append((endpoint, payload))
            raise AssessError(
                "HTTP 409:\n"
                + json.dumps(
                    {
                        "detail": (
                            "handoff with agent_id='AG-X' already exists; "
                            "PATCH to update"
                        )
                    }
                )
            )

        def patch(self, endpoint: str, payload: dict, *, accept_409: bool = False) -> dict:  # type: ignore[override]
            captured["patches"].append((endpoint, payload))
            return {"id": 7, "agent_id": "AG-X", **payload}

    stub = _StubClient()
    out = stub.record_handoff(
        {"agent_id": "AG-X", "agent_role": "recon-specialist", "summary": "v2"},
        upsert=True,
    )
    assert out["summary"] == "v2"
    assert len(captured["posts"]) == 1
    assert len(captured["patches"]) == 1
    assert captured["patches"][0][0] == "dispatch-handoffs/AG-X"
    # PATCH body must NOT include agent_id (URL-bound) or agent_role
    # (immutable post-create — HandoffUpdate forbids both).
    patch_body = captured["patches"][0][1]
    assert "agent_id" not in patch_body
    assert "agent_role" not in patch_body
    assert patch_body["summary"] == "v2"


def test_record_handoff_client_upsert_does_not_patch_role_mismatch_409() -> None:
    """Role-mismatch 409s are validation failures, not duplicate-row upserts."""
    from agent.scripts.assess.lib.client import AssessError, AssessmentClient

    captured: dict[str, object] = {"posts": [], "patches": []}

    class _StubClient(AssessmentClient):
        def __init__(self) -> None:
            pass

        def post(self, endpoint: str, payload: dict) -> dict:  # type: ignore[override]
            captured["posts"].append((endpoint, payload))
            raise AssessError(
                "HTTP 409:\n"
                + json.dumps(
                    {
                        "detail": (
                            "agent_role mismatch: handoff agent_role='wrong' "
                            "does not match registered dispatch role='right'"
                        )
                    }
                )
            )

        def patch(self, endpoint: str, payload: dict, *, accept_409: bool = False) -> dict:  # type: ignore[override]
            captured["patches"].append((endpoint, payload))
            return {"id": 7, "agent_id": "AG-X", **payload}

    stub = _StubClient()
    with pytest.raises(AssessError, match="agent_role mismatch"):
        stub.record_handoff(
            {"agent_id": "AG-X", "agent_role": "wrong", "summary": "v2"},
            upsert=True,
        )
    assert len(captured["posts"]) == 1
    assert captured["patches"] == []


# ──────────────────────────────────────────────────────────────────────────
# resolve_orchestrator_base_url precedence chain
#
# Resolution order (highest → lowest):
#   1. ORCHESTRATOR_BASE_URL env var (explicit override)
#   2. Per-engagement ``.orchestrator.env``
#   3. ``aith config get orchestrator_base_url`` (persistent default)
#   4. Install-root env files (legacy fallback)
#   5. Hardcoded fallback ``http://127.0.0.1:18000``
# ──────────────────────────────────────────────────────────────────────────


def test_resolve_orchestrator_base_url_env_var_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_threat_hunting_cli import paths as paths_module
    from ai_threat_hunting_cli.paths import resolve_orchestrator_base_url

    install_root = tmp_path / "install"
    install_root.mkdir()
    engagement_dir = tmp_path / "eng"
    engagement_dir.mkdir()
    (engagement_dir / ".orchestrator.env").write_text(
        "ORCHESTRATOR_BASE_URL=http://from-env-file:9000\n", encoding="utf-8"
    )

    monkeypatch.setenv("ORCHESTRATOR_BASE_URL", "http://from-env-var:1234/")
    monkeypatch.setattr(paths_module, "get_config_value", lambda key: "http://from-config:5678")

    assert (
        resolve_orchestrator_base_url(install_root, engagement_dir)
        == "http://from-env-var:1234"
    )


def test_resolve_orchestrator_base_url_engagement_env_file_wins_over_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_threat_hunting_cli import paths as paths_module
    from ai_threat_hunting_cli.paths import resolve_orchestrator_base_url

    install_root = tmp_path / "install"
    install_root.mkdir()
    engagement_dir = tmp_path / "eng"
    engagement_dir.mkdir()
    (engagement_dir / ".orchestrator.env").write_text(
        "ORCHESTRATOR_BASE_URL=http://from-env-file:9000/\n", encoding="utf-8"
    )

    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.setattr(paths_module, "get_config_value", lambda key: "http://from-config:5678")

    assert (
        resolve_orchestrator_base_url(install_root, engagement_dir)
        == "http://from-env-file:9000"
    )


def test_resolve_orchestrator_base_url_aith_config_falls_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With env var unset and no engagement env file override, aith config
    is consulted before the hardcoded default."""
    from ai_threat_hunting_cli import paths as paths_module
    from ai_threat_hunting_cli.paths import resolve_orchestrator_base_url

    install_root = tmp_path / "install"
    install_root.mkdir()
    engagement_dir = tmp_path / "eng"
    engagement_dir.mkdir()
    # No env file at all — everything falls through to the config layer.

    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.setattr(paths_module, "get_config_value", lambda key: "http://from-config:5678/")

    assert (
        resolve_orchestrator_base_url(install_root, engagement_dir)
        == "http://from-config:5678"
    )


def test_resolve_orchestrator_base_url_engagement_env_wins_over_install_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_threat_hunting_cli import paths as paths_module
    from ai_threat_hunting_cli.paths import resolve_orchestrator_base_url

    install_root = tmp_path / "install"
    install_root.mkdir()
    engagement_dir = tmp_path / "eng"
    engagement_dir.mkdir()
    (install_root / ".env").write_text(
        "ORCHESTRATOR_BASE_URL=http://from-install-env:18000\n", encoding="utf-8"
    )
    (engagement_dir / ".orchestrator.env").write_text(
        "ORCHESTRATOR_BASE_URL=http://from-engagement-env:18000\n", encoding="utf-8"
    )

    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.setattr(paths_module, "get_config_value", lambda key: "http://from-config:5678")

    assert (
        resolve_orchestrator_base_url(install_root, engagement_dir)
        == "http://from-engagement-env:18000"
    )


def test_resolve_orchestrator_base_url_aith_config_wins_over_install_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_threat_hunting_cli import paths as paths_module
    from ai_threat_hunting_cli.paths import resolve_orchestrator_base_url

    install_root = tmp_path / "install"
    install_root.mkdir()
    engagement_dir = tmp_path / "eng"
    engagement_dir.mkdir()
    (install_root / ".env").write_text(
        "ORCHESTRATOR_BASE_URL=http://from-install-env:18000\n", encoding="utf-8"
    )

    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.setattr(paths_module, "get_config_value", lambda key: "http://from-config:5678/")

    assert (
        resolve_orchestrator_base_url(install_root, engagement_dir)
        == "http://from-config:5678"
    )


def test_resolve_orchestrator_base_url_falls_back_to_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_threat_hunting_cli import paths as paths_module
    from ai_threat_hunting_cli.paths import (
        DEFAULT_ORCHESTRATOR_BASE_URL,
        resolve_orchestrator_base_url,
    )

    install_root = tmp_path / "install"
    install_root.mkdir()
    engagement_dir = tmp_path / "eng"
    engagement_dir.mkdir()

    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.setattr(paths_module, "get_config_value", lambda key: None)

    assert (
        resolve_orchestrator_base_url(install_root, engagement_dir)
        == DEFAULT_ORCHESTRATOR_BASE_URL
    )


def test_assess_config_engagement_env_wins_over_install_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib

    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module = importlib.import_module("assess.lib.config")
    install_root = tmp_path / "install"
    engagement_dir = install_root / "agent" / "engagements" / "eng-test"
    engagement_dir.mkdir(parents=True)
    (install_root / ".env").write_text(
        "ORCHESTRATOR_BASE_URL=http://from-install-env:18000\n", encoding="utf-8"
    )
    (engagement_dir / ".orchestrator.env").write_text(
        "ORCHESTRATOR_BASE_URL=http://from-engagement-env:18000\n", encoding="utf-8"
    )

    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.delenv("AI_THREAT_HUNTING_CONFIG", raising=False)

    assert (
        module.resolve_base_url(str(engagement_dir), str(install_root / "agent"))
        == "http://from-engagement-env:18000"
    )


def test_assess_config_aith_config_wins_over_install_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib

    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module = importlib.import_module("assess.lib.config")
    install_root = tmp_path / "install"
    engagement_dir = install_root / "agent" / "engagements" / "eng-test"
    engagement_dir.mkdir(parents=True)
    (install_root / ".env").write_text(
        "ORCHESTRATOR_BASE_URL=http://from-install-env:18000\n", encoding="utf-8"
    )
    config_path = tmp_path / "aith-config.json"
    config_path.write_text(
        json.dumps({"orchestrator_base_url": "http://from-config:5678/"}),
        encoding="utf-8",
    )

    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.setenv("AI_THREAT_HUNTING_CONFIG", str(config_path))

    assert (
        module.resolve_base_url(str(engagement_dir), str(install_root / "agent"))
        == "http://from-config:5678"
    )


# ---------------------------------------------------------------------------
# C7 — scope_host validation in dispatch contract
# ---------------------------------------------------------------------------


def _make_engagement_dir_with_scope(tmp_path: Path, hosts: list[str]) -> Path:
    eng_dir = tmp_path / "eng"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(
        json.dumps({"hosts": hosts, "status": "in_progress"}),
        encoding="utf-8",
    )
    return eng_dir


def test_validate_dispatch_blocks_out_of_scope_vuln_analyst(tmp_path: Path) -> None:
    """C7: vulnerability-analyst dispatching against an out-of-scope host must
    fail the contract validator with a clear error referencing scope.json."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    eng_dir = _make_engagement_dir_with_scope(tmp_path, ["app.example.test"])
    payload = {
        "agent_id": "va-1",
        "agent_role": "vulnerability-analyst",
        "task": "Probe IDOR",
        "scope_host": "evil-attacker.test",
        "dispatch_mode": "item-iterating",
        "skills": "idor-testing",
    }
    errors, _warnings = validate_specialist_dispatch_contract(
        payload, engagement_dir=str(eng_dir)
    )
    assert any("not in scope.json" in e for e in errors), errors


def test_validate_dispatch_allows_in_scope_exploit_developer(tmp_path: Path) -> None:
    """C7: exploit-developer dispatching against a host that IS in scope must
    pass the scope gate (no scope-related errors)."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    eng_dir = _make_engagement_dir_with_scope(tmp_path, ["app.example.test"])
    payload = {
        "agent_id": "exp-1",
        "agent_role": "exploit-developer",
        "task": "Chain IDOR + token reuse",
        "scope_host": "app.example.test",
        "dispatch_mode": "deep-manual",
        "skills": "idor-testing",
    }
    errors, _warnings = validate_specialist_dispatch_contract(
        payload, engagement_dir=str(eng_dir)
    )
    assert not any("not in scope.json" in e for e in errors), errors


def test_validate_dispatch_allows_recon_against_adjacent_host(tmp_path: Path) -> None:
    """C7: recon and osint are NOT scope-gated because they legitimately
    reach adjacent/related hosts during discovery (cert chains, DNS history,
    GitHub mirrors). recon-specialist with an out-of-scope scope_host must
    pass the scope gate (the skills-required check still applies separately)."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    eng_dir = _make_engagement_dir_with_scope(tmp_path, ["app.example.test"])
    payload = {
        "agent_id": "recon-1",
        "agent_role": "recon-specialist",
        "task": "Cert-chain pivot recon",
        "scope_host": "related.example.test",
        "dispatch_mode": "hypothesis-driven",
        "skills": "web-recon",
    }
    errors, _warnings = validate_specialist_dispatch_contract(
        payload, engagement_dir=str(eng_dir)
    )
    assert not any("not in scope.json" in e for e in errors), errors


def test_validate_dispatch_skips_scope_check_when_engagement_dir_omitted(
    tmp_path: Path,
) -> None:
    """C7: callers that do not pass engagement_dir keep the prior behavior —
    no scope check fires. Keeps the validator usable for unit tests + stdin
    linting where the engagement context is not available."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    payload = {
        "agent_id": "va-1",
        "agent_role": "vulnerability-analyst",
        "task": "Probe IDOR",
        "scope_host": "anywhere.test",
        "dispatch_mode": "item-iterating",
        "skills": "idor-testing",
    }
    errors, _warnings = validate_specialist_dispatch_contract(payload)
    assert not any("scope" in e.lower() for e in errors), errors


# ---------------------------------------------------------------------------
# Item 11 — scope_host rejection telemetry (audits the C7 gate)
# ---------------------------------------------------------------------------


def _load_auth_status_module():
    """Bootstrap sys.path for the assess package, then import auth_status."""
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    # Reload assess modules so the injected sys.path takes effect even when
    # earlier tests imported them under a different layout.
    for module_name in list(sys.modules):
        if module_name == "assess" or module_name.startswith("assess."):
            sys.modules.pop(module_name, None)
    from assess.commands import auth_status  # type: ignore[import-not-found]
    return auth_status


def test_auth_status_reports_bearer_token_and_recommends_refresh(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """C42a: aith assess auth-status reads auth.json and emits a structured
    snapshot — auth_context, mode, expires_state, present token shapes, and
    a refresh-path recommendation matching the C42 recovery loop. The
    command does NOT write to auth.json or trigger a refresh."""
    eng_dir = tmp_path / "eng"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "auth.json").write_text(
        json.dumps(
            {
                "auth_context": "authenticated",
                "mode": "proxy_capture",
                "use_for_requests": True,
                "state": "available",
                "expires_at": "2099-01-01T00:00:00Z",
                "headers": {"Authorization": "Bearer aaa.bbb.ccc.ddd.eee.fff"},
                "cookies": {"sessionid": "abc123"},
            }
        ),
        encoding="utf-8",
    )

    module = _load_auth_status_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(eng_dir),
            engagement_key="eng-c42a",
        ),
    )

    # Stub the AssessmentClient so last_auth_probe lookup does not require a
    # live backend; return one fake AUTH-technique row. Stubs `.get` because
    # /command-runs is an assessment-scoped endpoint.
    class _FakeAuthClient:
        def __init__(self, *_: object, **__: object) -> None:
            self.base_url = "http://example.test"
            self.engagement_key = "eng-c42a"

        def get(self, endpoint: str):
            assert endpoint == "command-runs?technique=AUTH&limit=1"
            return {
                "items": [
                    {
                        "id": 7,
                        "status": "completed",
                        "intent": "credential validation",
                        "started_at": "2026-05-16T20:00:00Z",
                        "completed_at": "2026-05-16T20:00:01Z",
                    }
                ]
            }

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", _FakeAuthClient)

    module.run(
        SimpleNamespace(
            engagement_dir=str(eng_dir),
            json_output=True,
            expires_warning_seconds=300,
        )
    )
    out = capsys.readouterr().out
    snapshot = json.loads(out)
    assert snapshot["auth_context"] == "authenticated"
    assert snapshot["mode"] == "proxy_capture"
    assert snapshot["expires_state"] == "valid"
    assert any("Authorization: Bearer" in t for t in snapshot["tokens"])
    assert any("flat_cookies" in t for t in snapshot["tokens"])
    assert snapshot["last_auth_probe"]["run_id"] == 7
    assert "Bearer token present" in snapshot["recommend"]


def test_auth_status_flags_expired_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """C42a: when expires_at is in the past, expires_state reports 'expired'
    and the recommend line still names the appropriate refresh path."""
    eng_dir = tmp_path / "eng-expired"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "auth.json").write_text(
        json.dumps(
            {
                "auth_context": "authenticated",
                "mode": "proxy_capture",
                "use_for_requests": True,
                "state": "available",
                "expires_at": "2000-01-01T00:00:00Z",
                "headers": {"Authorization": "Bearer expired.token"},
            }
        ),
        encoding="utf-8",
    )
    module = _load_auth_status_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(eng_dir),
            engagement_key="eng-expired",
        ),
    )

    class _NoProbeClient:
        def __init__(self, *_: object, **__: object) -> None:
            self.base_url = "http://example.test"
            self.engagement_key = "eng-expired"

        def get(self, endpoint: str):
            return {"items": []}

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", _NoProbeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=str(eng_dir),
            json_output=True,
            expires_warning_seconds=300,
        )
    )
    snapshot = json.loads(capsys.readouterr().out)
    assert snapshot["expires_state"] == "expired"
    assert snapshot["expires_in_seconds"] is not None
    assert snapshot["expires_in_seconds"] < 0
    assert snapshot["last_auth_probe"] is None


def test_auth_status_last_probe_uses_assessment_scoped_route(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`/command-runs` is registered on the assessment router. `_last_auth_probe`
    must route through `client.get(...)` (which carries the /assessment prefix);
    using `client.get_engagement(...)` 404s and silently returns None, so the
    operator never sees the last AUTH probe even when one exists."""
    eng_dir = tmp_path / "eng-route"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "auth.json").write_text(
        json.dumps(
            {
                "auth_context": "authenticated",
                "mode": "proxy_capture",
                "use_for_requests": True,
                "state": "available",
                "expires_at": "2099-01-01T00:00:00Z",
                "headers": {"Authorization": "Bearer route.token"},
            }
        ),
        encoding="utf-8",
    )
    module = _load_auth_status_module()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(eng_dir),
            engagement_key="eng-route",
        ),
    )

    class _RouteAssertingClient:
        """Fails loudly if production hits the non-assessment route."""

        def __init__(self, *_: object, **__: object) -> None:
            self.base_url = "http://example.test"
            self.engagement_key = "eng-route"

        def get(self, endpoint: str):
            assert endpoint == "command-runs?technique=AUTH&limit=1"
            return {
                "items": [
                    {
                        "id": 42,
                        "status": "completed",
                        "intent": "auth probe",
                        "started_at": "2026-05-18T10:00:00Z",
                        "completed_at": "2026-05-18T10:00:01Z",
                    }
                ]
            }

        def get_engagement(self, endpoint: str):
            raise AssertionError(
                "_last_auth_probe routed through .get_engagement(); "
                "/command-runs lives under the assessment router so it must use .get()"
            )

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", _RouteAssertingClient)

    module.run(
        SimpleNamespace(
            engagement_dir=str(eng_dir),
            json_output=True,
            expires_warning_seconds=300,
        )
    )
    snapshot = json.loads(capsys.readouterr().out)
    assert snapshot["last_auth_probe"]["run_id"] == 42


def test_assessment_client_list_all_decisions_paginates_until_exhausted() -> None:
    """`list_all_decisions` must paginate `/dispatch-decisions` until the
    backend returns fewer rows than the page size, so internal gating
    (vendor-SaaS, etc.) sees every recorded decision instead of the first
    page's worth.

    Drives a real AssessmentClient with `.get` monkeypatched to return three
    synthetic pages — full, full, partial — and asserts the helper:
      1. Sends the right offsets (0, 1000, 2000)
      2. Concatenates every row
      3. Stops at the partial page (no spurious offset=3000 call)
    """
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    for module_name in list(sys.modules):
        if module_name == "assess" or module_name.startswith("assess."):
            sys.modules.pop(module_name, None)
    from assess.lib.client import AssessmentClient  # type: ignore[import-not-found]

    client = AssessmentClient.__new__(AssessmentClient)
    # Bypass __init__ — we override the only method `list_all_decisions` needs.
    captured: list[str] = []

    def _fake_get(endpoint: str):
        captured.append(endpoint)
        if "offset=0" in endpoint or ("offset=" not in endpoint and "limit=1000" in endpoint):
            return [{"id": i, "kind": "scope_decision"} for i in range(1000)]
        if "offset=1000" in endpoint:
            return [{"id": i, "kind": "scope_decision"} for i in range(1000, 2000)]
        if "offset=2000" in endpoint:
            return [{"id": i, "kind": "scope_decision"} for i in range(2000, 2350)]
        raise AssertionError(f"unexpected pagination request: {endpoint}")

    client.get = _fake_get  # type: ignore[method-assign]

    rows = client.list_all_decisions(kind="scope_decision")

    assert len(rows) == 2350
    assert {row["id"] for row in rows} == set(range(2350))
    # Three requests, no fourth (the partial page short-circuits).
    assert len(captured) == 3
    # Each request scoped to the kind filter.
    assert all("kind=scope_decision" in url for url in captured)
    # Offsets in order, with the paginating page size.
    assert "offset=0" in captured[0]
    assert "limit=1000" in captured[0]
    assert "offset=1000" in captured[1]
    assert "offset=2000" in captured[2]


def test_assessment_client_list_all_decisions_strips_caller_limit_offset() -> None:
    """Callers must not be able to neuter `list_all_decisions` by passing
    their own `limit`/`offset` — the helper drives pagination itself.
    """
    scripts_root = repo_root / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    for module_name in list(sys.modules):
        if module_name == "assess" or module_name.startswith("assess."):
            sys.modules.pop(module_name, None)
    from assess.lib.client import AssessmentClient  # type: ignore[import-not-found]

    client = AssessmentClient.__new__(AssessmentClient)
    captured: list[str] = []

    def _fake_get(endpoint: str):
        captured.append(endpoint)
        # Single short page so the loop exits.
        return [{"id": 1, "kind": "scope_decision"}]

    client.get = _fake_get  # type: ignore[method-assign]

    # Caller tries to pin a tiny limit and a nonsense offset.
    client.list_all_decisions(kind="scope_decision", limit=5, offset=999)

    # The helper rewrote limit to 1000 and offset to 0.
    assert "limit=1000" in captured[0]
    assert "offset=0" in captured[0]
    assert "limit=5" not in captured[0]
    assert "offset=999" not in captured[0]


def test_scope_rejection_writes_dispatch_decision_row(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Item 11: when the C7 scope_host gate rejects a vulnerability-analyst
    dispatch, a `kind='scope_rejection'` decision row is written so the
    rejection is queryable post-engagement. Telemetry is best-effort —
    failures don't block the original error."""
    eng_dir = tmp_path / "eng"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(
        json.dumps({"hosts": ["app.example.test"], "status": "in_progress"}),
        encoding="utf-8",
    )

    module = _load_dispatch_module()
    recorded_decisions: list[dict] = []

    class _DecisionCapturingClient:
        def __init__(self, *_: object, **__: object) -> None:
            self.base_url = "http://example.test"
            self.engagement_key = "eng"

        def record_decision(self, body: dict) -> dict:
            recorded_decisions.append(body)
            return {"id": 1, **body}

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", _DecisionCapturingClient)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(eng_dir),
            engagement_key="eng",
            agent_root=str(tmp_path),
        ),
    )

    with pytest.raises(SystemExit) as excinfo:
        module._build_register_payload(
            _dispatch_args(
                "register",
                agent_id="va-rej-1",
                agent_role="vulnerability-analyst",
                scope_host="evil-attacker.test",
                dispatch_mode_arg="item-iterating",
                task="probe IDOR",
                skills="idor-testing",
                engagement_dir=str(eng_dir),
            )
        )
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "not in scope.json" in err
    # Exactly one telemetry row, with the rejected host + role + scope entries
    assert len(recorded_decisions) == 1
    row = recorded_decisions[0]
    assert row["kind"] == "scope_rejection"
    assert row["surfaced_to_user"] is True
    payload = row["payload"]
    assert payload["host"] == "evil-attacker.test"
    assert payload["role"] == "vulnerability-analyst"
    assert payload["scope_entries"] == ["app.example.test"]
    assert "not in scope.json" in payload["reason"]
