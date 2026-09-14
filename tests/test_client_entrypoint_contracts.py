"""Executable contracts for every repository-supported client entrypoint.

The real client binaries are replaced with deterministic capture stubs.  This
keeps the test free while still exercising the generated bash launchers rather
than inferring support from launcher-file presence.
"""

from __future__ import annotations

import json
import io
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from vigil_cli import engagements
from vigil_cli import install as install_module
from vigil_cli import client_rosters


_CAPTURE_STUB = """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

cwd = Path.cwd()
names = (
    "AGENTS.md",
    "CLAUDE.md",
    ".codex/config.toml",
    ".codex/agents/operator.toml",
    ".claude/settings.json",
    ".claude/agents/operator.md",
    "opencode.json",
    ".opencode/agent/operator.md",
    ".opencode/plugin/standard-hooks.js",
    ".goosehints",
    ".goose/recipes/recon-specialist.yaml",
    ".agents/plugins/vigil-standard/hooks/hooks.json",
)
payload = {
    "argv": sys.argv,
    "cwd": str(cwd),
    "env": {
        key: os.environ.get(key)
        for key in (
            "ENGAGEMENT_DIR",
            "VIGIL_SESSION_ENGAGEMENT_DIR",
            "ENGAGEMENT_KEY",
            "VIGIL_AGENT_ROOT",
            "VIGIL_INSTALL_DIR",
            "VIGIL_CLIENT_NAME",
            "ORCHESTRATOR_BASE_URL",
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY",
            "DEEPSEEK_API_KEY",
            "OPENROUTER_API_KEY",
            "OPENAI_API_KEY",
            "OPENAI_HOST",
            "GOOSE_PROVIDER",
            "GOOSE_MODEL",
            "GOOSE_RECIPE_PATH",
            "GOOSE_DISABLE_KEYRING",
            "GOOSE_MODE",
            "GOOSE_DISABLE_SESSION_NAMING",
        )
    },
    "files": {
        name: (cwd / name).read_text(encoding="utf-8")
        for name in names
        if (cwd / name).is_file()
    },
}
Path(os.environ["VIGIL_ENTRYPOINT_CAPTURE"]).write_text(
    json.dumps(payload), encoding="utf-8"
)
"""


def _write_agent_sources(agent_root: Path) -> None:
    (agent_root / ".codex" / "agents").mkdir(parents=True)
    (agent_root / ".codex" / "agents" / "operator.toml").write_text("name = 'operator'\n")
    (agent_root / ".codex" / "config.toml").write_text("model = 'test'\n")

    (agent_root / ".claude" / "agents").mkdir(parents=True)
    (agent_root / ".claude" / "agents" / "operator.md").write_text("# Operator\n")
    (agent_root / ".claude" / "settings.json").write_text("{}\n")

    # Rendered operator commands: one Claude slash command per canonical source,
    # one Codex project skill directory per canonical source.
    (agent_root / ".claude" / "commands").mkdir(parents=True)
    for command_name in ("vigil-resume", "vigil-compact"):
        (agent_root / ".claude" / "commands" / f"{command_name}.md").write_text(
            f"---\ndescription: {command_name}\n---\n\nbody\n"
        )
        skill_dir = agent_root / ".codex" / "skills" / command_name
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            f"---\nname: {command_name}\ndescription: {command_name}\n---\n\nbody\n"
        )

    (agent_root / ".opencode" / "agent").mkdir(parents=True)
    (agent_root / ".opencode" / "agent" / "operator.md").write_text("# Operator\n")
    (agent_root / ".opencode" / "plugin").mkdir()
    (agent_root / ".opencode" / "plugin" / "standard-hooks.js").write_text("// hook\n")

    (agent_root / ".goose" / "recipes").mkdir(parents=True)
    (agent_root / ".goose" / "recipes" / "recon-specialist.yaml").write_text("name: recon\n")
    hooks = agent_root / "scripts" / "hooks"
    hooks.mkdir(parents=True)
    for name in ("goose-hook-adapter.sh", "scope-check.sh", "post-tool-log.sh"):
        (hooks / name).write_text("#!/usr/bin/env bash\nexit 0\n")

    (agent_root / "AGENTS.md").write_text("# Canonical operator instructions\n")
    (agent_root / "CLAUDE.md").write_text("# Canonical Claude instructions\n")


def test_claude_settings_materialize_absolute_hooks_for_bare_engagement_sessions(
    tmp_path: Path,
) -> None:
    agent_root = tmp_path / "agent root 'with spaces'"
    claude_dir = tmp_path / "engagement" / ".claude"
    hooks_dir = agent_root / "scripts" / "hooks"
    hooks_dir.mkdir(parents=True)
    marker = tmp_path / "hook-ran"
    for name in ("post-tool-log.sh", "scope-check.sh"):
        hook = hooks_dir / name
        hook.write_text(
            "#!/usr/bin/env bash\n"
            "cat >/dev/null\n"
            f"printf '%s' {name!r} >{str(marker)!r}\n"
        )
        hook.chmod(0o755)

    source = {
        "hooks": {
            "PostToolUse": [
                {
                    "matcher": matcher,
                    "hooks": [
                        {
                            "type": "command",
                            "command": (
                                "bash -c 'try environment and relative fallbacks; "
                                f"then run {script}'"
                            ),
                        }
                    ],
                }
                for matcher, script in (
                    ("Bash", "post-tool-log.sh"),
                    ("Agent", "post-tool-log.sh"),
                    ("Write", "post-tool-log.sh"),
                )
            ],
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "bash relative/scope-check.sh",
                        }
                    ],
                }
            ],
        }
    }
    source_dir = agent_root / ".claude"
    source_dir.mkdir()
    (source_dir / "settings.json").write_text(json.dumps(source))

    client_rosters.ensure_claude_settings(agent_root, claude_dir)

    settings = json.loads((claude_dir / "settings.json").read_text())
    assert [item["matcher"] for item in settings["hooks"]["PostToolUse"]] == [
        "Bash",
        "Write",
    ]
    commands = [
        hook["command"]
        for phase in settings["hooks"].values()
        for item in phase
        for hook in item["hooks"]
    ]
    assert all("VIGIL_AGENT_ROOT" not in command for command in commands)
    assert all("scripts/hooks" in command for command in commands)
    assert {
        shlex.split(command)[1]
        for command in commands
    } == {
        str(hooks_dir / "post-tool-log.sh"),
        str(hooks_dir / "scope-check.sh"),
    }

    env = os.environ.copy()
    env.pop("VIGIL_AGENT_ROOT", None)
    for command in commands:
        marker.unlink(missing_ok=True)
        result = subprocess.run(
            command,
            cwd=claude_dir.parent,
            env=env,
            shell=True,
            input="{}",
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert marker.is_file()


def _build_entrypoint_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    # The literal shell expansion is deliberate: install paths are data, and must
    # survive launcher generation without being interpreted as shell syntax.
    install_root = tmp_path / "install-$VIGIL_PATH_EXPANSION"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "client-contract"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)

    (install_root / ".env").write_text("DEEPSEEK_API_KEY=test-deepseek\n")
    (engagement_dir / ".orchestrator.env").write_text(
        "ORCHESTRATOR_BASE_URL=http://engagement.test:8000/\n"
    )
    (engagement_dir / "scope.json").write_text('{"status":"active"}\n')

    engagements._write_prompt_wrappers(
        agent_root, engagement_dir, "both", engagement_type="web"
    )
    engagements._write_codex_config(agent_root, engagement_dir)
    engagements._write_claude_config(agent_root, engagement_dir)
    engagements._write_opencode_config(agent_root, engagement_dir)
    engagements._write_goose_config(agent_root, engagement_dir)
    engagements._write_launchers(agent_root, engagement_dir, "both", skip_permissions=True)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for client in ("codex", "claude", "opencode", "goose", "kimi"):
        executable = bin_dir / client
        executable.write_text(_CAPTURE_STUB)
        executable.chmod(0o755)
    return install_root, engagement_dir, bin_dir


def _seed_physical_client_rosters(
    agent_root: Path, engagement_dir: Path
) -> tuple[list[tuple[Path, Path]], Path]:
    roster_pairs = [
        (agent_root / ".codex" / "agents", engagement_dir / ".codex" / "agents"),
        (agent_root / ".claude" / "agents", engagement_dir / ".claude" / "agents"),
        (agent_root / ".opencode" / "agent", engagement_dir / ".opencode" / "agent"),
        (agent_root / ".opencode" / "agent", engagement_dir / ".opencode" / "agents"),
        (agent_root / ".goose" / "recipes", engagement_dir / ".goose" / "recipes"),
    ]
    for source, destination in roster_pairs:
        destination.mkdir(parents=True)
        for source_file in source.iterdir():
            if source_file.is_file():
                (destination / source_file.name).write_text("stale generated roster\n")
    extra = engagement_dir / ".codex" / "agents" / "operator-session.tmp"
    extra.touch()
    return roster_pairs, extra


def test_physical_client_rosters_require_explicit_refresh_and_preserve_extras(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "install"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "legacy-physical-rosters"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)
    (engagement_dir / "scope.json").write_text("{}\n")
    roster_pairs, extra = _seed_physical_client_rosters(agent_root, engagement_dir)
    new_sources = (
        agent_root / ".codex" / "agents" / "new-specialist.toml",
        agent_root / ".claude" / "agents" / "new-specialist.md",
        agent_root / ".opencode" / "agent" / "new-specialist.md",
        agent_root / ".goose" / "recipes" / "new-specialist.yaml",
    )
    for source in new_sources:
        source.write_text(f"canonical {source.name}\n")

    default_result = client_rosters.repair_engagement_client_rosters(install_root)

    expected_roster_paths = tuple(
        sorted(str(destination.relative_to(install_root)) for _, destination in roster_pairs)
    )
    assert default_result.physical_roster_paths == expected_roster_paths
    assert default_result.refreshed_physical_roster_paths == ()
    for source, destination in roster_pairs:
        first_source = next(
            path for path in source.iterdir() if not path.name.startswith("new-specialist.")
        )
        assert (destination / first_source.name).read_text() == "stale generated roster\n"
    assert extra.read_bytes() == b""

    refreshed = client_rosters.repair_engagement_client_rosters(
        install_root, refresh_physical_client_rosters=True
    )

    assert refreshed.physical_roster_paths == expected_roster_paths
    assert refreshed.refreshed_physical_roster_paths == expected_roster_paths
    assert refreshed.files_added == 5
    assert refreshed.files_updated == 5
    assert refreshed.files_unchanged == 0
    assert refreshed.extra_files_preserved == 1
    for source, destination in roster_pairs:
        for source_file in source.iterdir():
            if source_file.is_file():
                assert (destination / source_file.name).read_bytes() == source_file.read_bytes()
    assert extra.read_bytes() == b""

    repeated = client_rosters.repair_engagement_client_rosters(
        install_root, refresh_physical_client_rosters=True
    )

    assert repeated.files_added == 0
    assert repeated.files_updated == 0
    assert repeated.files_unchanged == 10
    assert repeated.extra_files_preserved == 1
    assert extra.read_bytes() == b""


@pytest.mark.parametrize("collision_kind", ["symlink", "directory"])
def test_physical_client_roster_refresh_rejects_collision_before_any_write(
    tmp_path: Path,
    collision_kind: str,
) -> None:
    install_root = tmp_path / "install"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "legacy-unsafe-roster"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)
    (engagement_dir / "scope.json").write_text("{}\n")
    roster_pairs, _extra = _seed_physical_client_rosters(agent_root, engagement_dir)
    codex_destination = engagement_dir / ".codex" / "agents" / "operator.toml"
    codex_destination.unlink()
    outside = tmp_path / "outside-operator.toml"
    outside.write_text("outside must remain\n")
    if collision_kind == "symlink":
        codex_destination.symlink_to(outside)
    else:
        codex_destination.mkdir()
    claude_destination = engagement_dir / ".claude" / "agents" / "operator.md"
    assert claude_destination.read_text() == "stale generated roster\n"

    with pytest.raises(RuntimeError, match="unsafe physical client roster"):
        client_rosters.repair_engagement_client_rosters(
            install_root, refresh_physical_client_rosters=True
        )

    assert outside.read_text() == "outside must remain\n"
    assert claude_destination.read_text() == "stale generated roster\n"
    for _source, destination in roster_pairs:
        assert destination.is_dir()


@pytest.mark.parametrize(
    ("client", "expected_argv"),
    [
        (
            "codex",
            [
                "codex",
                "--dangerously-bypass-approvals-and-sandbox",
                # Keeps `scope-check.sh` live without an operator answering
                # Codex's startup hook-trust review. See _REQUIRED_CLIENT_ARGS.
                "--dangerously-bypass-hook-trust",
                "--model",
                "test-model",
                "operator task",
            ],
        ),
        (
            "claude",
            ["claude", "--dangerously-skip-permissions", "--model", "test-model", "operator task"],
        ),
        (
            "opencode",
            [
                "opencode",
                "--agent",
                "operator",
                "--dangerously-skip-permissions",
                "--model",
                "test-model",
                "--prompt",
                "operator task",
            ],
        ),
        (
            "goose",
            [
                "goose",
                "run",
                "--interactive",
                "--with-builtin",
                "developer",
                "--model",
                "test-model",
                "-t",
                "operator task",
            ],
        ),
        ("kimi", ["kimi", "--auto", "--model", "test-model", "operator task"]),
    ],
)
def test_generated_client_entrypoint_executes_canonical_contract(
    tmp_path: Path, client: str, expected_argv: list[str]
) -> None:
    install_root, engagement_dir, bin_dir = _build_entrypoint_fixture(tmp_path)
    capture = tmp_path / f"{client}.json"
    env = os.environ.copy()
    for key in (
        "ORCHESTRATOR_BASE_URL",
        "DEEPSEEK_API_KEY",
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_HOST",
        "GOOSE_PROVIDER",
        "GOOSE_MODEL",
        "GOOSE_RECIPE_PATH",
        "GOOSE_DISABLE_KEYRING",
        "GOOSE_MODE",
        "GOOSE_DISABLE_SESSION_NAMING",
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY",
    ):
        env.pop(key, None)
    env.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{env['PATH']}",
            "VIGIL_ENTRYPOINT_CAPTURE": str(capture),
            "VIGIL_PATH_EXPANSION": "must-not-expand",
            "VIGIL_GOOSE_REASONING_PROXY": "0",
        }
    )
    if client == "goose":
        env["OPENAI_API_KEY"] = "test-openai"
        env["OPENAI_HOST"] = "https://api.openai.com/v1"
        env["GOOSE_PROVIDER"] = "ambient-provider"
        env["GOOSE_MODEL"] = "deepseek-v4-flash"
        env["GOOSE_RECIPE_PATH"] = "/tmp/ambient-recipes"
        env["GOOSE_DISABLE_KEYRING"] = "0"
        env["GOOSE_MODE"] = "approve"
        env["GOOSE_DISABLE_SESSION_NAMING"] = "false"

    # Go through the exact argv `vigil engagement start` builds, so the launcher's
    # forwarding and Vigil's message placement are asserted as one contract.
    result = subprocess.run(
        [
            str(engagement_dir / f"start_{client}.sh"),
            *engagements.client_launch_argv(
                client, ["--model", "test-model", "operator task"]
            ),
        ],
        cwd=engagement_dir,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(capture.read_text())
    assert [Path(payload["argv"][0]).name, *payload["argv"][1:]] == expected_argv
    assert payload["cwd"] == str(engagement_dir)
    expected_common_env = {
        "ENGAGEMENT_DIR": str(engagement_dir),
        "VIGIL_SESSION_ENGAGEMENT_DIR": str(engagement_dir),
        "ENGAGEMENT_KEY": engagement_dir.name,
        "VIGIL_AGENT_ROOT": str(install_root / "agent"),
        "VIGIL_INSTALL_DIR": str(install_root),
        "VIGIL_CLIENT_NAME": client,
        "ORCHESTRATOR_BASE_URL": "http://engagement.test:8000",
    }
    assert {
        key: payload["env"][key]
        for key in expected_common_env
    } == expected_common_env
    assert str(install_root / "agent" / "AGENTS.md") in payload["files"]["AGENTS.md"]

    if client == "claude":
        assert payload["env"]["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] == "1"
        assert "Read `AGENTS.md`" in payload["files"]["CLAUDE.md"]
        assert json.loads(payload["files"][".claude/settings.json"]) == {
            "autoMemoryEnabled": False,
        }
        assert payload["files"][".claude/agents/operator.md"] == "# Operator\n"
    elif client == "opencode":
        assert payload["env"]["DEEPSEEK_API_KEY"] == "test-deepseek"
        assert payload["env"]["OPENROUTER_API_KEY"] is None
        assert json.loads(payload["files"]["opencode.json"])["permission"]["*"] == "allow"
        assert payload["files"][".opencode/agent/operator.md"] == "# Operator\n"
        assert payload["files"][".opencode/plugin/standard-hooks.js"] == "// hook\n"
    elif client == "goose":
        assert payload["env"]["DEEPSEEK_API_KEY"] == "test-deepseek"
        assert payload["env"]["OPENAI_API_KEY"] == "test-deepseek"
        assert payload["env"]["OPENAI_HOST"] == "https://api.deepseek.com"
        assert payload["env"]["GOOSE_PROVIDER"] == "openai"
        assert payload["env"]["GOOSE_MODEL"] == "deepseek-v4-pro"
        assert payload["env"]["GOOSE_RECIPE_PATH"] == str(
            engagement_dir / ".goose" / "recipes"
        )
        assert payload["env"]["GOOSE_DISABLE_KEYRING"] == "1"
        assert payload["env"]["GOOSE_MODE"] == "auto"
        assert payload["env"]["GOOSE_DISABLE_SESSION_NAMING"] == "true"
        assert "dispatch, do not solo" in payload["files"][".goosehints"]
        assert payload["files"][".goose/recipes/recon-specialist.yaml"] == "name: recon\n"
        assert "PostToolUse" in payload["files"][
            ".agents/plugins/vigil-standard/hooks/hooks.json"
        ]
    elif client == "codex":
        assert payload["files"][".codex/config.toml"] == "model = 'test'\n"
        assert payload["files"][".codex/agents/operator.toml"] == "name = 'operator'\n"


@pytest.mark.parametrize("skip_permissions", [False, True])
def test_install_upgrade_reconciles_all_client_entrypoints_for_existing_engagement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    skip_permissions: bool,
) -> None:
    source_root = tmp_path / "source"
    source_agent_root = source_root / "agent"
    _write_agent_sources(source_agent_root)

    install_root = tmp_path / "install-$VIGIL_PATH_EXPANSION"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "legacy-client-contract"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)
    (install_root / ".runtime-data").mkdir()
    (install_root / ".env").write_text("DEEPSEEK_API_KEY=test-deepseek\n")
    (engagement_dir / ".orchestrator.env").write_text(
        "ORCHESTRATOR_BASE_URL=http://engagement.test:8000/\n"
    )
    (engagement_dir / "scope.json").write_text('{"status":"active"}\n')
    manifest_bytes = b'{"key":"legacy-client-contract","owner_note":"retain exactly"}\n'
    (engagement_dir / "engagement.json").write_bytes(manifest_bytes)
    evidence_bytes = b"operator-authored evidence\x00must survive\n"
    (engagement_dir / "evidence.bin").write_bytes(evidence_bytes)

    engagements._write_prompt_wrappers(
        agent_root, engagement_dir, "both", engagement_type="web"
    )
    engagements._write_codex_config(agent_root, engagement_dir)
    engagements._write_claude_config(agent_root, engagement_dir)
    engagements._write_launchers(
        agent_root,
        engagement_dir,
        "both",
        skip_permissions=skip_permissions,
    )
    for client in ("opencode", "goose", "kimi"):
        (engagement_dir / f"start_{client}.sh").unlink()

    # Existing user-authored client state is not an installer-owned generated file.
    (engagement_dir / "opencode.json").write_text(
        '{"theme":"operator-custom"}\n', encoding="utf-8"
    )
    custom_plugin = engagement_dir / ".opencode" / "plugin" / "operator-custom.js"
    custom_plugin.parent.mkdir(parents=True)
    custom_plugin.write_text("// retain me\n", encoding="utf-8")

    ambiguous_dir = agent_root / "engagements" / "legacy-config-only"
    ambiguous_dir.mkdir()
    (ambiguous_dir / "scope.json").write_text("{}\n")
    (ambiguous_dir / ".codex").mkdir()
    (ambiguous_dir / ".claude").mkdir()
    ambiguous_evidence = ambiguous_dir / "evidence.bin"
    ambiguous_evidence.write_bytes(b"ambiguous state must remain")

    monkeypatch.setattr(install_module, "initialize_relay_route", lambda *args, **kwargs: None)
    monkeypatch.setattr(install_module.config_module, "get_config_value", lambda *args: None)
    install_result = install_module.install_from_source(
        install_module.InstallOptions(
            source_root=source_root,
            install_root=install_root,
            verify_docker_image=False,
        )
    )

    repair_result = install_result.client_entrypoint_repair
    assert repair_result is not None
    assert repair_result.scanned_count == 2
    assert repair_result.reconciled == ("legacy-client-contract",)
    assert len(repair_result.skipped) == 1
    assert repair_result.skipped[0].engagement_key == "legacy-config-only"
    assert repair_result.skipped[0].reason == "permission_mode_unavailable"
    install_stderr = capsys.readouterr().err
    assert "scanned=2 reconciled=1 skipped=1" in install_stderr
    assert "engagement=legacy-config-only reason=permission_mode_unavailable" in install_stderr
    assert (engagement_dir / "engagement.json").read_bytes() == manifest_bytes
    assert (engagement_dir / "evidence.bin").read_bytes() == evidence_bytes
    assert ambiguous_evidence.read_bytes() == b"ambiguous state must remain"
    assert not any(ambiguous_dir.glob("start_*.sh"))
    assert json.loads((engagement_dir / "opencode.json").read_text())["theme"] == "operator-custom"
    assert custom_plugin.read_text(encoding="utf-8") == "// retain me\n"

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for client in ("codex", "claude", "opencode", "goose", "kimi"):
        executable = bin_dir / client
        executable.write_text(_CAPTURE_STUB)
        executable.chmod(0o755)

    permission_args = {
        "codex": ["--dangerously-bypass-approvals-and-sandbox"] if skip_permissions else [],
        "claude": ["--dangerously-skip-permissions"] if skip_permissions else [],
        "opencode": ["--dangerously-skip-permissions"] if skip_permissions else [],
        "goose": [],
        "kimi": ["--auto"] if skip_permissions else [],
    }
    # Unconditional per-client arguments: not a permission choice, so they ride
    # both `--skip-permissions` parametrizations. Codex gates project-local hooks
    # behind an interactive startup trust review; without the bypass the scope
    # guard silently does not run.
    required_args = {
        "codex": ["--dangerously-bypass-hook-trust"],
        "claude": [],
        "opencode": [],
        "goose": [],
        "kimi": [],
    }
    command_prefixes = {
        "codex": ["codex"],
        "claude": ["claude"],
        "opencode": ["opencode", "--agent", "operator"],
        "goose": ["goose", "run", "--interactive", "--with-builtin", "developer"],
        "kimi": ["kimi"],
    }
    for client in ("codex", "claude", "opencode", "goose", "kimi"):
        capture = tmp_path / f"{client}-{skip_permissions}.json"
        env = os.environ.copy()
        for key in (
            "ORCHESTRATOR_BASE_URL",
            "DEEPSEEK_API_KEY",
            "OPENROUTER_API_KEY",
            "OPENAI_API_KEY",
            "OPENAI_HOST",
            "GOOSE_PROVIDER",
            "GOOSE_MODEL",
            "GOOSE_RECIPE_PATH",
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY",
        ):
            env.pop(key, None)
        env.update(
            {
                "PATH": f"{bin_dir}{os.pathsep}{env['PATH']}",
                "VIGIL_ENTRYPOINT_CAPTURE": str(capture),
                "VIGIL_PATH_EXPANSION": "must-not-expand",
                "VIGIL_GOOSE_REASONING_PROXY": "0",
            }
        )
        result = subprocess.run(
            [
                str(engagement_dir / f"start_{client}.sh"),
                *engagements.client_launch_argv(client, ["operator task"]),
            ],
            cwd=engagement_dir,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0, f"{client}: {result.stderr}"
        payload = json.loads(capture.read_text())
        expected_argv = [
            *command_prefixes[client],
            *permission_args[client],
            *required_args[client],
            *{"goose": ["-t"], "opencode": ["--prompt"]}.get(client, []),
            "operator task",
        ]
        assert [Path(payload["argv"][0]).name, *payload["argv"][1:]] == expected_argv
        assert payload["env"]["VIGIL_CLIENT_NAME"] == client
        assert payload["env"]["VIGIL_SESSION_ENGAGEMENT_DIR"] == str(engagement_dir)
        assert payload["env"]["ORCHESTRATOR_BASE_URL"] == "http://engagement.test:8000"
        assert str(agent_root / "AGENTS.md") in payload["files"]["AGENTS.md"]
        if client == "codex":
            assert payload["files"][".codex/config.toml"] == "model = 'test'\n"
            assert payload["files"][".codex/agents/operator.toml"] == "name = 'operator'\n"
        elif client == "claude":
            assert payload["env"]["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] == "1"
            assert json.loads(payload["files"][".claude/settings.json"]) == {
                "autoMemoryEnabled": False,
            }
            assert payload["files"][".claude/agents/operator.md"] == "# Operator\n"
        elif client == "opencode":
            assert payload["env"]["DEEPSEEK_API_KEY"] == "test-deepseek"
            assert payload["env"]["OPENROUTER_API_KEY"] is None
            opencode_config = json.loads(payload["files"]["opencode.json"])
            assert opencode_config["theme"] == "operator-custom"
            assert opencode_config["permission"]["*"] == "allow"
            assert payload["files"][".opencode/agent/operator.md"] == "# Operator\n"
            assert payload["files"][".opencode/plugin/standard-hooks.js"] == "// hook\n"
        elif client == "goose":
            assert payload["env"]["OPENAI_API_KEY"] == "test-deepseek"
            assert payload["env"]["GOOSE_RECIPE_PATH"] == str(
                engagement_dir / ".goose" / "recipes"
            )
            assert "dispatch, do not solo" in payload["files"][".goosehints"]
            assert payload["files"][".goose/recipes/recon-specialist.yaml"] == "name: recon\n"
            assert "PostToolUse" in payload["files"][
                ".agents/plugins/vigil-standard/hooks/hooks.json"
            ]


@pytest.mark.parametrize(
    ("client_kind", "present_primary", "absent_primary"),
    [
        ("codex", "codex", "claude"),
        ("claude", "claude", "codex"),
    ],
)
def test_entrypoint_repair_preserves_existing_primary_client_kind(
    tmp_path: Path,
    client_kind: str,
    present_primary: str,
    absent_primary: str,
) -> None:
    install_root = tmp_path / "install"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / f"legacy-{client_kind}"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)
    (engagement_dir / "scope.json").write_text("{}\n")
    engagements._write_prompt_wrappers(
        agent_root, engagement_dir, client_kind, engagement_type="web"
    )
    if client_kind == "codex":
        engagements._write_codex_config(agent_root, engagement_dir)
    else:
        engagements._write_claude_config(agent_root, engagement_dir)
    engagements._write_launchers(
        agent_root, engagement_dir, client_kind, skip_permissions=False
    )
    for client in ("opencode", "goose", "kimi"):
        (engagement_dir / f"start_{client}.sh").unlink()

    engagements.repair_engagement_client_entrypoints(install_root)

    assert (engagement_dir / f"start_{present_primary}.sh").is_file()
    assert not (engagement_dir / f"start_{absent_primary}.sh").exists()
    for client in ("opencode", "goose", "kimi"):
        assert (engagement_dir / f"start_{client}.sh").is_file()


def test_entrypoint_repair_migrates_legacy_generated_codex_skip_flag(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "install"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "legacy-codex-skip"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)
    (engagement_dir / "scope.json").write_text("{}\n")
    engagements._write_prompt_wrappers(
        agent_root, engagement_dir, "both", engagement_type="web"
    )
    engagements._write_codex_config(agent_root, engagement_dir)
    engagements._write_claude_config(agent_root, engagement_dir)
    engagements._write_launchers(
        agent_root, engagement_dir, "both", skip_permissions=True
    )
    codex_launcher = engagement_dir / "start_codex.sh"
    codex_launcher.write_text(
        codex_launcher.read_text().replace(
            "--dangerously-bypass-approvals-and-sandbox", "--full-auto"
        )
    )

    result = engagements.repair_engagement_client_entrypoints(install_root)

    assert result.reconciled == ("legacy-codex-skip",)
    assert result.skipped == ()
    assert result.permission_overrides == ()
    repaired = codex_launcher.read_text()
    assert "--dangerously-bypass-approvals-and-sandbox" in repaired
    assert "--full-auto" not in repaired


def test_entrypoint_repair_skips_conflicting_existing_permission_modes(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "install"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "legacy-conflict"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)
    (engagement_dir / "scope.json").write_text("{}\n")
    engagements._write_prompt_wrappers(
        agent_root, engagement_dir, "both", engagement_type="web"
    )
    engagements._write_launchers(
        agent_root, engagement_dir, "both", skip_permissions=True
    )
    codex_launcher = engagement_dir / "start_codex.sh"
    codex_launcher.write_text(
        codex_launcher.read_text().replace(" --dangerously-bypass-approvals-and-sandbox ", "  ")
    )
    for client in ("opencode", "goose", "kimi"):
        (engagement_dir / f"start_{client}.sh").unlink()

    result = engagements.repair_engagement_client_entrypoints(install_root)

    assert result.scanned_count == 1
    assert result.reconciled == ()
    assert len(result.skipped) == 1
    assert result.skipped[0].engagement_key == "legacy-conflict"
    assert result.skipped[0].reason == "permission_mode_conflict"
    assert result.skipped[0].evidence == ("claude=skip", "codex=prompt")
    for client in ("opencode", "goose", "kimi"):
        assert not (engagement_dir / f"start_{client}.sh").exists()


def test_entrypoint_repair_explicit_skip_override_normalizes_recognized_conflict(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "install"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "legacy-conflict"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)
    (engagement_dir / "scope.json").write_text("{}\n")
    engagements._write_prompt_wrappers(
        agent_root, engagement_dir, "both", engagement_type="web"
    )
    engagements._write_launchers(
        agent_root, engagement_dir, "both", skip_permissions=True
    )
    codex_launcher = engagement_dir / "start_codex.sh"
    codex_launcher.write_text(
        codex_launcher.read_text().replace(" --dangerously-bypass-approvals-and-sandbox ", "  ")
    )
    for client in ("opencode", "goose", "kimi"):
        (engagement_dir / f"start_{client}.sh").unlink()

    result = engagements.repair_engagement_client_entrypoints(
        install_root, ambiguous_permissions_as_skip=True
    )

    assert result.reconciled == ("legacy-conflict",)
    assert result.permission_overrides == ("legacy-conflict",)
    assert result.skipped == ()
    assert "--dangerously-bypass-approvals-and-sandbox" in (
        engagement_dir / "start_codex.sh"
    ).read_text()
    assert "--dangerously-skip-permissions" in (
        engagement_dir / "start_claude.sh"
    ).read_text()
    for client in ("opencode", "goose", "kimi"):
        assert (engagement_dir / f"start_{client}.sh").is_file()


def test_entrypoint_repair_skips_config_only_legacy_engagement_without_permission_evidence(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "install"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "legacy-config-only"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)
    (engagement_dir / "scope.json").write_text("{}\n")
    (engagement_dir / ".codex").mkdir()
    (engagement_dir / ".claude").mkdir()
    evidence = engagement_dir / "evidence.bin"
    evidence.write_bytes(b"retain\x00exactly")

    result = engagements.repair_engagement_client_entrypoints(install_root)

    assert result.scanned_count == 1
    assert result.reconciled == ()
    assert len(result.skipped) == 1
    assert result.skipped[0].engagement_key == "legacy-config-only"
    assert result.skipped[0].reason == "permission_mode_unavailable"
    assert result.skipped[0].evidence == ("client_kind=both",)
    assert evidence.read_bytes() == b"retain\x00exactly"
    assert not any(engagement_dir.glob("start_*.sh"))


def test_entrypoint_repair_explicit_skip_override_upgrades_config_only_legacy_engagement(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "install"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "legacy-config-only"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)
    (engagement_dir / "scope.json").write_text("{}\n")
    (engagement_dir / "AGENTS.md").write_text("# Legacy pointer\n")
    (engagement_dir / ".codex").mkdir()
    (engagement_dir / ".claude").mkdir()
    evidence = engagement_dir / "evidence.bin"
    evidence.write_bytes(b"retain\x00exactly")

    result = engagements.repair_engagement_client_entrypoints(
        install_root, ambiguous_permissions_as_skip=True
    )

    assert result.reconciled == ("legacy-config-only",)
    assert result.permission_overrides == ("legacy-config-only",)
    assert result.skipped == ()
    assert evidence.read_bytes() == b"retain\x00exactly"
    for client in ("codex", "claude", "opencode", "goose", "kimi"):
        assert (engagement_dir / f"start_{client}.sh").is_file()
    assert "--dangerously-bypass-approvals-and-sandbox" in (
        engagement_dir / "start_codex.sh"
    ).read_text()
    assert "--dangerously-skip-permissions" in (
        engagement_dir / "start_claude.sh"
    ).read_text()
    assert "--dangerously-skip-permissions" in (
        engagement_dir / "start_opencode.sh"
    ).read_text()
    assert "--auto" in (engagement_dir / "start_kimi.sh").read_text()


def test_entrypoint_repair_reports_clientless_engagement_without_mutation(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "install"
    engagement_dir = install_root / "agent" / "engagements" / "legacy-clientless"
    engagement_dir.mkdir(parents=True)
    (engagement_dir / "scope.json").write_text("{}\n")

    result = engagements.repair_engagement_client_entrypoints(install_root)

    assert result.scanned_count == 1
    assert result.reconciled == ()
    assert len(result.skipped) == 1
    assert result.skipped[0].reason == "clientless"
    assert result.skipped[0].evidence == ()
    assert sorted(path.name for path in engagement_dir.iterdir()) == ["scope.json"]

    override_result = engagements.repair_engagement_client_entrypoints(
        install_root, ambiguous_permissions_as_skip=True
    )
    assert override_result.reconciled == ()
    assert override_result.permission_overrides == ()
    assert override_result.skipped[0].reason == "clientless"


def test_entrypoint_repair_does_not_overwrite_unrecognized_primary_launcher(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "install"
    engagement_dir = install_root / "agent" / "engagements" / "legacy-custom-launcher"
    engagement_dir.mkdir(parents=True)
    (engagement_dir / "scope.json").write_text("{}\n")
    (engagement_dir / ".codex").mkdir()
    launcher = engagement_dir / "start_codex.sh"
    custom_bytes = b"#!/usr/bin/env bash\nexec custom-codex-wrapper \"$@\"\n"
    launcher.write_bytes(custom_bytes)

    result = engagements.repair_engagement_client_entrypoints(install_root)

    assert result.reconciled == ()
    assert len(result.skipped) == 1
    assert result.skipped[0].reason == "unrecognized_primary_launcher"
    assert result.skipped[0].evidence == ("codex=unrecognized_generated_preamble",)
    assert launcher.read_bytes() == custom_bytes
    assert not (engagement_dir / "start_opencode.sh").exists()

    override_result = engagements.repair_engagement_client_entrypoints(
        install_root, ambiguous_permissions_as_skip=True
    )
    assert override_result.reconciled == ()
    assert override_result.permission_overrides == ()
    assert override_result.skipped[0].reason == "unrecognized_primary_launcher"
    assert launcher.read_bytes() == custom_bytes


def test_entrypoint_repair_accepts_legacy_generated_launcher_without_engagement_key(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "install"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "legacy-pre-key-export"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)
    (engagement_dir / "scope.json").write_text("{}\n")
    (engagement_dir / "AGENTS.md").write_text("# Legacy pointer\n")
    (engagement_dir / ".claude").mkdir()
    (engagement_dir / "start_claude.sh").write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n\n"
        'ENGAGEMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
        "export ENGAGEMENT_DIR\n\n"
        'AGENT_ROOT="$(cd "$ENGAGEMENT_DIR/../.." && pwd)"\n'
        "export AGENT_ROOT\n\n"
        'exec claude --dangerously-skip-permissions "$@"\n'
    )

    result = engagements.repair_engagement_client_entrypoints(install_root)

    assert result.reconciled == ("legacy-pre-key-export",)
    assert result.skipped == ()
    for client in ("claude", "opencode", "goose", "kimi"):
        assert (engagement_dir / f"start_{client}.sh").is_file()
    assert not (engagement_dir / "start_codex.sh").exists()
    assert "--dangerously-skip-permissions" in (
        engagement_dir / "start_claude.sh"
    ).read_text()
    assert "--auto" in (engagement_dir / "start_kimi.sh").read_text()


@pytest.mark.parametrize(
    "relative_path",
    (
        ".codex",
        ".codex/config.toml",
        ".claude",
        ".claude/settings.json",
        ".opencode",
        ".opencode/plugin",
        ".opencode/plugins",
        "opencode.json",
        ".goose",
        ".goosehints",
        ".agents",
        ".agents/plugins/vigil-standard/hooks/hooks.json",
        "start_codex.sh",
        "start_claude.sh",
        "start_opencode.sh",
        "start_goose.sh",
        "start_kimi.sh",
    ),
)
def test_entrypoint_repair_skips_external_symlinked_destination(
    tmp_path: Path, relative_path: str
) -> None:
    install_root, engagement_dir, _bin_dir = _build_entrypoint_fixture(tmp_path)
    destination = engagement_dir / relative_path
    outside = tmp_path / f"outside-{relative_path.replace('/', '-')}"
    if destination.is_dir() and not destination.is_symlink():
        shutil.rmtree(destination)
        outside.mkdir()
        (outside / "sentinel").write_text("do not modify\n")
        destination.symlink_to(outside, target_is_directory=True)
    else:
        destination.unlink()
        outside.write_text("do not modify\n")
        destination.symlink_to(outside)

    result = engagements.repair_engagement_client_entrypoints(install_root)

    assert result.reconciled == ()
    assert len(result.skipped) == 1
    assert result.skipped[0].reason == "unsafe_repair_destination"
    assert result.skipped[0].evidence == (relative_path,)
    if outside.is_dir():
        assert sorted(path.name for path in outside.iterdir()) == ["sentinel"]
        assert (outside / "sentinel").read_text() == "do not modify\n"
    else:
        assert outside.read_text() == "do not modify\n"


@pytest.mark.parametrize(
    "relative_path",
    (
        ".codex",
        ".codex/config.toml",
        "opencode.json",
        ".agents/plugins/vigil-standard/hooks/hooks.json",
        "start_opencode.sh",
    ),
)
def test_entrypoint_repair_refuses_internal_symlinked_destination(
    tmp_path: Path, relative_path: str
) -> None:
    install_root, engagement_dir, _bin_dir = _build_entrypoint_fixture(tmp_path)
    destination = engagement_dir / relative_path
    preserved = engagement_dir / f"preserved-{relative_path.replace('/', '-')}"
    if destination.is_dir() and not destination.is_symlink():
        shutil.rmtree(destination)
        preserved.mkdir()
        (preserved / "sentinel").write_text("do not modify\n")
        destination.symlink_to(preserved, target_is_directory=True)
    else:
        destination.unlink()
        preserved.write_text("do not modify\n")
        destination.symlink_to(preserved)

    result = engagements.repair_engagement_client_entrypoints(install_root)

    assert result.reconciled == ()
    assert len(result.skipped) == 1
    assert result.skipped[0].reason == "unsafe_repair_destination"
    assert result.skipped[0].evidence == (relative_path,)
    if preserved.is_dir():
        assert sorted(path.name for path in preserved.iterdir()) == ["sentinel"]
        assert (preserved / "sentinel").read_text() == "do not modify\n"
    else:
        assert preserved.read_text() == "do not modify\n"


@pytest.mark.parametrize(
    "relative_path",
    (".codex", ".claude", ".opencode", ".goose", ".agents"),
)
def test_roster_repair_does_not_follow_external_symlinked_client_paths(
    tmp_path: Path, relative_path: str
) -> None:
    install_root, engagement_dir, _bin_dir = _build_entrypoint_fixture(tmp_path)
    destination = engagement_dir / relative_path
    assert destination.is_dir()
    shutil.rmtree(destination)
    outside = tmp_path / f"outside-roster-{relative_path.removeprefix('.') }"
    outside.mkdir()
    (outside / "sentinel").write_text("do not modify\n")
    destination.symlink_to(outside, target_is_directory=True)

    client_rosters.repair_engagement_client_rosters(install_root)

    assert sorted(path.name for path in outside.iterdir()) == ["sentinel"]
    assert (outside / "sentinel").read_text() == "do not modify\n"


@pytest.mark.parametrize("relative_path", (".codex", ".agents"))
def test_roster_repair_does_not_follow_internal_symlinked_client_paths(
    tmp_path: Path, relative_path: str
) -> None:
    install_root, engagement_dir, _bin_dir = _build_entrypoint_fixture(tmp_path)
    destination = engagement_dir / relative_path
    assert destination.is_dir()
    shutil.rmtree(destination)
    preserved = engagement_dir / f"preserved-roster-{relative_path.removeprefix('.')}"
    preserved.mkdir()
    (preserved / "sentinel").write_text("do not modify\n")
    destination.symlink_to(preserved, target_is_directory=True)

    client_rosters.repair_engagement_client_rosters(install_root)

    assert sorted(path.name for path in preserved.iterdir()) == ["sentinel"]
    assert (preserved / "sentinel").read_text() == "do not modify\n"


def test_install_cli_plumbs_explicit_ambiguous_permission_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import main as main_module

    source_root = tmp_path / "source"
    source_root.mkdir()
    install_root = tmp_path / "install"
    seen: list[install_module.InstallOptions] = []

    def fake_install(options: install_module.InstallOptions) -> install_module.InstallResult:
        seen.append(options)
        return install_module.InstallResult(
            install_root=options.install_root,
            is_upgrade=False,
            image_built=False,
        )

    monkeypatch.setattr(main_module, "install_from_source", fake_install)
    main_module.main(
        [
            "--source",
            str(source_root),
            "install",
            str(install_root),
            "--dry-run",
            "--repair-ambiguous-client-permissions-as-skip",
            "--refresh-physical-client-rosters",
        ]
    )

    assert len(seen) == 1
    assert seen[0].repair_ambiguous_client_permissions_as_skip is True
    assert seen[0].refresh_physical_client_rosters is True
    assert capsys.readouterr().out.strip() == str(install_root)


def test_install_upgrade_applies_explicit_ambiguous_permission_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_root = tmp_path / "source"
    _write_agent_sources(source_root / "agent")
    install_root = tmp_path / "install"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "legacy-config-only"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)
    (install_root / ".runtime-data").mkdir()
    (engagement_dir / "scope.json").write_text("{}\n")
    (engagement_dir / "AGENTS.md").write_text("# Legacy pointer\n")
    (engagement_dir / ".codex").mkdir()
    (engagement_dir / ".claude").mkdir()
    roster_pairs, extra = _seed_physical_client_rosters(agent_root, engagement_dir)

    monkeypatch.setattr(install_module, "initialize_relay_route", lambda *args, **kwargs: None)
    monkeypatch.setattr(install_module.config_module, "get_config_value", lambda *args: None)
    result = install_module.install_from_source(
        install_module.InstallOptions(
            source_root=source_root,
            install_root=install_root,
            verify_docker_image=False,
            repair_ambiguous_client_permissions_as_skip=True,
            refresh_physical_client_rosters=True,
        )
    )

    roster_result = result.client_roster_repair
    assert roster_result is not None
    assert roster_result.physical_roster_paths == tuple(
        sorted(str(destination.relative_to(install_root)) for _, destination in roster_pairs)
    )
    assert roster_result.refreshed_physical_roster_paths == roster_result.physical_roster_paths
    assert roster_result.files_added == 0
    assert roster_result.files_updated == 5
    assert roster_result.extra_files_preserved == 1
    assert extra.read_bytes() == b""
    repair_result = result.client_entrypoint_repair
    assert repair_result is not None
    assert repair_result.reconciled == ("legacy-config-only",)
    assert repair_result.permission_overrides == ("legacy-config-only",)
    assert repair_result.skipped == ()
    stderr = capsys.readouterr().err
    assert "physical=5 refreshed=5 files_added=0 files_updated=5" in stderr
    assert "reconciled=1 skipped=0 permission_overrides=1" in stderr
    for client in ("codex", "claude", "opencode", "goose", "kimi"):
        assert (engagement_dir / f"start_{client}.sh").is_file()


@pytest.mark.parametrize("client", ["codex", "claude", "opencode", "goose", "kimi"])
def test_start_engagement_dispatches_to_exact_client_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, client: str
) -> None:
    install_root = tmp_path / "install"
    engagement_dir = install_root / "agent" / "engagements" / "client-contract"
    engagement_dir.mkdir(parents=True)
    (engagement_dir / "scope.json").write_text('{"status":"active"}\n')
    launcher = engagement_dir / f"start_{client}.sh"
    launcher.write_text("#!/usr/bin/env bash\n")
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    calls: dict[str, object] = {}
    monkeypatch.setattr(engagements.os, "chdir", lambda path: calls.setdefault("cwd", path))
    monkeypatch.setattr(
        engagements.os,
        "execv",
        lambda path, argv: calls.setdefault("execv", (path, argv)),
    )

    engagements.start_engagement(install_root, engagement_dir, client, ["--model", "test"])

    assert calls == {
        "cwd": engagement_dir,
        "execv": (str(launcher), [str(launcher), "--model", "test"]),
    }
    assert engagements.os.environ["VIGIL_REQUESTED_CLIENT"] == client


def test_noninteractive_selection_fails_before_starting_fzf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = engagements.EngagementRow(
        key="eng-1",
        path=tmp_path,
        target="https://example.test",
        status="in_progress",
        current_phase="recon",
        created_at="2026-09-11T00:00:00Z",
    )
    monkeypatch.setattr(engagements.sys, "stdin", io.StringIO(""))
    monkeypatch.setattr(engagements.shutil, "which", lambda _name: "/usr/bin/fzf")
    monkeypatch.setattr(
        engagements.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("fzf must not start without a TTY"),
    )

    with pytest.raises(SystemExit, match="non-interactive"):
        engagements._select_engagement([row])


# ── Session-shaped goose / opencode launches (no headless one-shot) ───────────


@pytest.mark.parametrize(
    ("client_args", "expected_tail"),
    [
        # A bare `vigil engagement start <key> --client goose` is the documented
        # spelling; it must open a session, not invoke `goose run` with no
        # instruction (which exits 1 before the model is ever asked anything).
        ([], ["goose", "session", "--with-builtin", "developer"]),
        # A flag VALUE is never the operator prompt.
        (
            ["--model", "test-model"],
            ["goose", "session", "--with-builtin", "developer", "--model", "test-model"],
        ),
        (
            ["operator task"],
            [
                "goose",
                "run",
                "--interactive",
                "--with-builtin",
                "developer",
                "-t",
                "operator task",
            ],
        ),
        # An explicitly passed-through goose instruction flag still routes to `run`.
        (
            ["-t", "operator task"],
            [
                "goose",
                "run",
                "--interactive",
                "--with-builtin",
                "developer",
                "-t",
                "operator task",
            ],
        ),
    ],
)
def test_goose_launcher_routes_between_run_and_session(
    tmp_path: Path, client_args: list[str], expected_tail: list[str]
) -> None:
    install_root, engagement_dir, bin_dir = _build_entrypoint_fixture(tmp_path)
    capture = tmp_path / "goose.json"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{env['PATH']}",
            "VIGIL_ENTRYPOINT_CAPTURE": str(capture),
            "VIGIL_PATH_EXPANSION": "must-not-expand",
            "VIGIL_GOOSE_REASONING_PROXY": "0",
        }
    )

    result = subprocess.run(
        [
            str(engagement_dir / "start_goose.sh"),
            *engagements.client_launch_argv("goose", client_args),
        ],
        cwd=engagement_dir,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(capture.read_text())
    assert [Path(payload["argv"][0]).name, *payload["argv"][1:]] == expected_tail


@pytest.mark.parametrize(
    ("client_args", "expected_tail"),
    [
        # The TUI is the session; `opencode run` is the one-shot form and must not
        # be what an engagement start execs.
        ([], ["opencode", "--agent", "operator", "--dangerously-skip-permissions"]),
        (
            ["--model", "test-model"],
            [
                "opencode",
                "--agent",
                "operator",
                "--dangerously-skip-permissions",
                "--model",
                "test-model",
            ],
        ),
        (
            ["operator task"],
            [
                "opencode",
                "--agent",
                "operator",
                "--dangerously-skip-permissions",
                "--prompt",
                "operator task",
            ],
        ),
    ],
)
def test_opencode_launcher_opens_a_session(
    tmp_path: Path, client_args: list[str], expected_tail: list[str]
) -> None:
    install_root, engagement_dir, bin_dir = _build_entrypoint_fixture(tmp_path)
    capture = tmp_path / "opencode.json"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{env['PATH']}",
            "VIGIL_ENTRYPOINT_CAPTURE": str(capture),
            "VIGIL_PATH_EXPANSION": "must-not-expand",
        }
    )

    result = subprocess.run(
        [
            str(engagement_dir / "start_opencode.sh"),
            *engagements.client_launch_argv("opencode", client_args),
        ],
        cwd=engagement_dir,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(capture.read_text())
    assert [Path(payload["argv"][0]).name, *payload["argv"][1:]] == expected_tail


@pytest.mark.parametrize(
    ("client", "client_args", "expected"),
    [
        # `-- --model x` must not hand "x" to the model as the operator prompt.
        ("goose", ["--model", "x"], ["--model", "x"]),
        ("opencode", ["--model", "x"], ["--model", "x"]),
        ("goose", ["--model", "x", "task"], ["--model", "x", "-t", "task"]),
        ("goose", ["--model=x", "task"], ["--model=x", "-t", "task"]),
        (
            "opencode",
            ["--model=x", "task"],
            ["--model=x", "--prompt", "task"],
        ),
        ("opencode", ["task"], ["--prompt", "task"]),
        # Clients that take the prompt positionally are untouched.
        ("claude", ["--model", "x", "task"], ["--model", "x", "task"]),
        ("codex", [], []),
    ],
)
def test_client_launch_argv_places_the_operator_message(
    client: str, client_args: list[str], expected: list[str]
) -> None:
    assert engagements.client_launch_argv(client, client_args) == expected


_RENDERED_COMMANDS = ("vigil-resume", "vigil-compact")


@pytest.mark.parametrize(
    ("body", "expected_error"),
    [
        (
            "<!-- vigil:only cursor -->\nprivate\n<!-- vigil:end -->\n",
            "unknown capability client 'cursor'",
        ),
        (
            "<!-- vigil:only claude -->\n<!-- vigil:only codex -->\n"
            "private\n<!-- vigil:end -->\n<!-- vigil:end -->\n",
            "nested capability block",
        ),
        (
            "<!-- vigil:only claude -->\nprivate\n",
            "missing <!-- vigil:end -->",
        ),
        ("<!-- vigil:end -->\n", "unmatched <!-- vigil:end -->"),
    ],
    ids=("unknown-client", "nested", "missing-end", "unmatched-end"),
)
def test_command_renderer_rejects_malformed_capability_blocks(
    tmp_path: Path, body: str, expected_error: str
) -> None:
    source = Path(__file__).resolve().parents[1] / "agent"
    agent_root = tmp_path / "agent"
    shutil.copytree(source, agent_root, symlinks=True)
    (agent_root / "commands" / "vigil-resume.md").write_text(
        "---\nname: vigil-resume\ndescription: test\n---\n\n" + body,
        encoding="utf-8",
    )

    result = subprocess.run(
        ["bash", str(agent_root / "scripts" / "render-operator-prompts.sh"), "repo"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr


def _assert_command_pointers(engagement_dir: Path, agent_root: Path) -> None:
    """Every rendered command reaches the engagement as a pointer, not a copy."""
    for command_name in _RENDERED_COMMANDS:
        claude_command = engagement_dir / ".claude" / "commands" / f"{command_name}.md"
        assert claude_command.is_symlink(), f"{command_name} must be a pointer, not a copy"
        assert (
            claude_command.resolve()
            == (agent_root / ".claude" / "commands" / f"{command_name}.md").resolve()
        )
        assert claude_command.read_text(encoding="utf-8").startswith("---")

        codex_skill = engagement_dir / ".codex" / "skills" / command_name
        assert codex_skill.is_symlink()
        assert codex_skill.resolve() == (
            agent_root / ".codex" / "skills" / command_name
        ).resolve()
        assert (codex_skill / "SKILL.md").is_file()

    # The owning directories are real, so a hand-authored sibling can coexist and
    # so the repair symlink guards keep working.
    assert not (engagement_dir / ".claude" / "commands").is_symlink()
    assert not (engagement_dir / ".codex" / "skills").is_symlink()


def test_generated_engagement_exposes_operator_commands_to_claude_and_codex_only(
    tmp_path: Path,
) -> None:
    install_root, engagement_dir, _ = _build_entrypoint_fixture(tmp_path)
    agent_root = install_root / "agent"

    _assert_command_pointers(engagement_dir, agent_root)

    # opencode / goose / kimi get no commands: they have no project-command
    # surface, and shipping an unreadable directory would imply one exists.
    assert not (engagement_dir / ".opencode" / "commands").exists()
    assert not (engagement_dir / ".opencode" / "skills").exists()
    assert not (engagement_dir / ".goose" / "commands").exists()
    assert not (engagement_dir / ".goose" / "skills").exists()
    assert not (engagement_dir / "commands").exists()
    assert not (engagement_dir / "skills").exists()


def test_entrypoint_repair_backfills_operator_commands_for_existing_engagement(
    tmp_path: Path,
) -> None:
    install_root, engagement_dir, _ = _build_entrypoint_fixture(tmp_path)
    agent_root = install_root / "agent"

    shutil.rmtree(engagement_dir / ".claude" / "commands")
    shutil.rmtree(engagement_dir / ".codex" / "skills")

    result = engagements.repair_engagement_client_entrypoints(install_root)

    assert result.reconciled == (engagement_dir.name,)
    _assert_command_pointers(engagement_dir, agent_root)


def test_command_pointers_preserve_hand_authored_engagement_local_command(
    tmp_path: Path,
) -> None:
    """An operator-authored command of the same name is never clobbered.

    Engagement directories carry operator-owned content.  The generated pointer
    yields to a real file the operator wrote, exactly as the roster machinery
    preserves unknown entries rather than deleting them.
    """
    install_root, engagement_dir, _ = _build_entrypoint_fixture(tmp_path)

    commands_dir = engagement_dir / ".claude" / "commands"
    hand_authored = commands_dir / "vigil-resume.md"
    hand_authored.unlink()
    hand_authored.write_text("---\ndescription: mine\n---\n\nhand authored\n")
    sibling = commands_dir / "engagement-only.md"
    sibling.write_text("---\ndescription: local\n---\n\nlocal only\n")

    engagements.repair_engagement_client_entrypoints(install_root)

    assert not hand_authored.is_symlink()
    assert "hand authored" in hand_authored.read_text(encoding="utf-8")
    assert sibling.is_file()
    assert (commands_dir / "vigil-compact.md").is_symlink()


def test_entrypoint_repair_skips_engagement_whose_commands_dir_is_a_symlink(
    tmp_path: Path,
) -> None:
    install_root, engagement_dir, _ = _build_entrypoint_fixture(tmp_path)

    commands_dir = engagement_dir / ".claude" / "commands"
    shutil.rmtree(commands_dir)
    outside = tmp_path / "outside-commands"
    outside.mkdir()
    commands_dir.symlink_to(outside, target_is_directory=True)

    result = engagements.repair_engagement_client_entrypoints(install_root)

    assert result.reconciled == ()
    assert [skip.reason for skip in result.skipped] == ["unsafe_repair_destination"]
    assert result.skipped[0].evidence == (".claude/commands",)
    assert not any(outside.iterdir())


def test_claude_settings_materialize_absolute_paths_for_compaction_and_session_hooks(
    tmp_path: Path,
) -> None:
    """PreCompact/SessionEnd hook commands are rewritten like the tool hooks.

    A bare engagement session has no `VIGIL_AGENT_ROOT` and its cwd is the
    engagement, not the agent root, so a relative hook path resolves to nothing
    and the hook silently never runs.
    """
    agent_root = tmp_path / "agent root 'with spaces'"
    claude_dir = tmp_path / "engagement" / ".claude"
    hooks_dir = agent_root / "scripts" / "hooks"
    hooks_dir.mkdir(parents=True)
    for script in ("pre-compact.sh", "session-end.sh"):
        (hooks_dir / script).write_text("#!/usr/bin/env bash\nexit 0\n")
    (agent_root / ".claude").mkdir()
    (agent_root / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreCompact": [
                        {"hooks": [{"type": "command", "command": "bash scripts/hooks/pre-compact.sh"}]}
                    ],
                    "SessionEnd": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "bash scripts/hooks/session-end.sh",
                                    "timeout": 10,
                                }
                            ]
                        }
                    ],
                }
            }
        )
    )

    client_rosters.ensure_claude_settings(agent_root, claude_dir)

    settings = json.loads((claude_dir / "settings.json").read_text(encoding="utf-8"))
    pre_compact = settings["hooks"]["PreCompact"][0]["hooks"][0]
    session_end = settings["hooks"]["SessionEnd"][0]["hooks"][0]
    assert pre_compact["command"] == shlex.join(
        ["bash", str(hooks_dir / "pre-compact.sh")]
    )
    assert session_end["command"] == shlex.join(
        ["bash", str(hooks_dir / "session-end.sh")]
    )
    # An explicit timeout survives the rewrite: SessionEnd hooks share a 1.5s
    # default budget, so dropping it would silently truncate the activity write.
    assert session_end["timeout"] == 10
    # No matcher on either event — PreCompact must cover manual and auto alike.
    assert "matcher" not in settings["hooks"]["PreCompact"][0]
    assert "matcher" not in settings["hooks"]["SessionEnd"][0]


def test_codex_config_materializes_absolute_paths_for_all_hooks(tmp_path: Path) -> None:
    """Codex hooks must also work when the client is opened without a launcher."""
    import tomllib

    repo_root = Path(__file__).resolve().parents[1]
    agent_root = tmp_path / "agent root 'with spaces'"
    source_dir = agent_root / ".codex"
    source_dir.mkdir(parents=True)
    shutil.copy2(repo_root / "agent" / ".codex" / "config.toml", source_dir / "config.toml")
    hooks_dir = agent_root / "scripts" / "hooks"
    hooks_dir.mkdir(parents=True)
    for script in ("scope-check.sh", "post-tool-log.sh", "session-end.sh"):
        (hooks_dir / script).write_text("#!/usr/bin/env bash\nexit 0\n")

    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    engagements._write_codex_config(agent_root, engagement_dir)

    config = tomllib.loads(
        (engagement_dir / ".codex" / "config.toml").read_text(encoding="utf-8")
    )
    commands = [
        hook["command"]
        for event in config["hooks"].values()
        for entry in event
        for hook in entry["hooks"]
    ]
    assert commands == [
        shlex.join(["bash", str(hooks_dir / "scope-check.sh")]),
        shlex.join(["bash", str(hooks_dir / "post-tool-log.sh")]),
        shlex.join(["bash", str(hooks_dir / "session-end.sh")]),
    ]
    assert all("VIGIL_AGENT_ROOT" not in command for command in commands)


def test_committed_claude_settings_register_compaction_and_session_end_hooks() -> None:
    """The committed generated settings are what every engagement copy is made from."""
    repo_root = Path(__file__).resolve().parents[1]
    settings = json.loads(
        (repo_root / "agent" / ".claude" / "settings.json").read_text(encoding="utf-8")
    )
    hooks = settings["hooks"]
    assert "PreCompact" in hooks and "SessionEnd" in hooks
    for event, script in (("PreCompact", "pre-compact.sh"), ("SessionEnd", "session-end.sh")):
        entries = hooks[event]
        assert len(entries) == 1, f"{event} must be one no-matcher entry"
        assert "matcher" not in entries[0]
        commands = entries[0]["hooks"]
        assert len(commands) == 1
        assert script in commands[0]["command"]
    assert hooks["SessionEnd"][0]["hooks"][0]["timeout"] >= 5


def test_committed_codex_config_registers_session_end_but_no_compaction_hook() -> None:
    """Codex gets the session-end receipt hook, deliberately no PreCompact."""
    import tomllib

    repo_root = Path(__file__).resolve().parents[1]
    config = tomllib.loads(
        (repo_root / "agent" / ".codex" / "config.toml").read_text(encoding="utf-8")
    )
    hooks = config["hooks"]
    assert "PreCompact" not in hooks
    session_end = hooks["SessionEnd"]
    assert len(session_end) == 1
    command = session_end[0]["hooks"][0]
    assert "session-end.sh" in command["command"]
    # Codex 0.154.0 hard-caps the SessionEnd hook at 3s and prints
    # "clamping SessionEnd hook timeout to 3s" on every launch for any larger
    # value. Asking for more does not buy time, it only adds a warning, so the
    # config states the budget Codex will actually honour. Claude keeps its own
    # 10s in `.claude/settings.json`; the two clients are not required to match.
    assert command["timeout"] == 3


def test_engagement_settings_pin_claude_auto_memory_off_regardless_of_template(
    tmp_path: Path,
) -> None:
    """Auto-memory is a settings-file guarantee, not a launcher-only env export.

    The engagement's own `.claude/settings.json` carries it, so it holds for a
    bare `claude` started in the engagement directory too — not just for the
    launcher `vigil engagement start` execs. Pinned in code so editing the
    committed template cannot silently re-enable a second context store
    alongside the backend ledger.
    """
    agent_root = tmp_path / "agent"
    (agent_root / ".claude").mkdir(parents=True)
    # Template deliberately tries to turn it back ON.
    (agent_root / ".claude" / "settings.json").write_text(
        json.dumps({"autoMemoryEnabled": True, "hooks": {}}), encoding="utf-8"
    )
    claude_dir = tmp_path / "engagement" / ".claude"

    client_rosters.ensure_claude_settings(agent_root, claude_dir)

    settings = json.loads((claude_dir / "settings.json").read_text(encoding="utf-8"))
    assert settings["autoMemoryEnabled"] is False


def test_committed_client_configs_disable_cross_session_memory_for_both_clients() -> None:
    """Claude and Codex get the same treatment: no second cross-session store.

    Claude uses `autoMemoryEnabled`; Codex uses `[features] memories`. Both ship
    off so the backend ledger stays the engagement's single record of truth, and
    so an operator's global config cannot turn either on inside an engagement.
    """
    import tomllib

    repo_root = Path(__file__).resolve().parents[1]

    claude_settings = json.loads(
        (repo_root / "agent" / ".claude" / "settings.json").read_text(encoding="utf-8")
    )
    assert claude_settings["autoMemoryEnabled"] is False

    codex_config = tomllib.loads(
        (repo_root / "agent" / ".codex" / "config.toml").read_text(encoding="utf-8")
    )
    assert codex_config["features"]["memories"] is False


def test_codex_launcher_bypasses_hook_trust_regardless_of_permission_mode(
    tmp_path: Path,
) -> None:
    """The Codex scope guard must not depend on an operator answering a prompt.

    Codex 0.154.0 treats every project-local `[hooks]` entry as untrusted until
    it is reviewed: the TUI opens on "Hooks need review" and an operator who
    presses esc, or picks "Continue without trusting", gets a session in which
    `scope-check.sh` never runs and nothing in the UI says so. That silent-off
    state is the failure mode the bypass removes; the flag itself is loud, Codex
    prints a standing "hooks may run without review" warning under it.

    It is not a permission choice, so it holds for both `--skip-permissions`
    modes. Only the Codex launcher carries it; no other client is affected.
    """
    agent_root = tmp_path / "install" / "agent"
    _write_agent_sources(agent_root)

    for skip_permissions in (False, True):
        engagement_dir = agent_root / "engagements" / f"trust-{skip_permissions}"
        engagement_dir.mkdir(parents=True)
        engagements._write_launchers(
            agent_root, engagement_dir, "both", skip_permissions=skip_permissions
        )

        codex_exec = [
            line
            for line in (engagement_dir / "start_codex.sh").read_text().splitlines()
            if line.startswith("exec ")
        ]
        expected = "exec codex"
        if skip_permissions:
            expected += " --dangerously-bypass-approvals-and-sandbox"
        expected += ' --dangerously-bypass-hook-trust "$@"'
        assert codex_exec == [expected]

        for client in ("claude", "opencode", "goose", "kimi"):
            body = (engagement_dir / f"start_{client}.sh").read_text()
            assert "--dangerously-bypass-hook-trust" not in body


def test_entrypoint_repair_backfills_codex_hook_trust_bypass(tmp_path: Path) -> None:
    """Engagements created before the bypass get it on repair.

    Their scope guard is inert until they do, so recognizing the older exec line
    matters as much as writing the new one: a launcher that failed to parse would
    be skipped as unrecognized and keep running without the guard.
    """
    install_root = tmp_path / "install"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "legacy-hook-trust"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)
    (engagement_dir / "scope.json").write_text("{}\n")
    engagements._write_prompt_wrappers(
        agent_root, engagement_dir, "both", engagement_type="web"
    )
    engagements._write_codex_config(agent_root, engagement_dir)
    engagements._write_claude_config(agent_root, engagement_dir)
    engagements._write_launchers(
        agent_root, engagement_dir, "both", skip_permissions=True
    )
    codex_launcher = engagement_dir / "start_codex.sh"
    codex_launcher.write_text(
        codex_launcher.read_text().replace(" --dangerously-bypass-hook-trust", "")
    )

    result = engagements.repair_engagement_client_entrypoints(install_root)

    assert result.reconciled == ("legacy-hook-trust",)
    assert result.skipped == ()
    repaired = codex_launcher.read_text()
    assert (
        'exec codex --dangerously-bypass-approvals-and-sandbox'
        ' --dangerously-bypass-hook-trust "$@"' in repaired
    )
    # The permission choice recorded in the legacy launcher must survive the
    # backfill: reading it as "prompt" would silently downgrade the engagement.
    assert "--dangerously-bypass-approvals-and-sandbox" in repaired
