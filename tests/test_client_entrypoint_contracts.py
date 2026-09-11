"""Executable contracts for every repository-supported client entrypoint.

The real client binaries are replaced with deterministic capture stubs.  This
keeps the test free while still exercising the generated bash launchers rather
than inferring support from launcher-file presence.
"""

from __future__ import annotations

import json
import os
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


def _build_entrypoint_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    # The literal shell expansion is deliberate: install paths are data, and must
    # survive launcher generation without being interpreted as shell syntax.
    install_root = tmp_path / "install-$VIGIL_PATH_EXPANSION"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "client-contract"
    engagement_dir.mkdir(parents=True)
    _write_agent_sources(agent_root)

    (install_root / ".env").write_text(
        "DEEPSEEK_API_KEY=test-deepseek\nOPENROUTER_API_KEY=test-openrouter\n"
    )
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
                "run",
                "--agent",
                "operator",
                "--dangerously-skip-permissions",
                "--model",
                "test-model",
                "operator task",
            ],
        ),
        (
            "goose",
            [
                "goose",
                "run",
                "--no-session",
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
            "--model",
            "test-model",
            "operator task",
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
        assert json.loads(payload["files"][".claude/settings.json"]) == {}
        assert payload["files"][".claude/agents/operator.md"] == "# Operator\n"
    elif client == "opencode":
        assert payload["env"]["DEEPSEEK_API_KEY"] == "test-deepseek"
        assert payload["env"]["OPENROUTER_API_KEY"] == "test-openrouter"
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
    (install_root / ".env").write_text(
        "DEEPSEEK_API_KEY=test-deepseek\nOPENROUTER_API_KEY=test-openrouter\n"
    )
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

    monkeypatch.setattr(install_module, "initialize_tenant_route", lambda *args, **kwargs: None)
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
    command_prefixes = {
        "codex": ["codex"],
        "claude": ["claude"],
        "opencode": ["opencode", "run", "--agent", "operator"],
        "goose": ["goose", "run", "--no-session", "--with-builtin", "developer"],
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
            [str(engagement_dir / f"start_{client}.sh"), "operator task"],
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
            *(["-t"] if client == "goose" else []),
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
            assert json.loads(payload["files"][".claude/settings.json"]) == {}
            assert payload["files"][".claude/agents/operator.md"] == "# Operator\n"
        elif client == "opencode":
            assert payload["env"]["DEEPSEEK_API_KEY"] == "test-deepseek"
            assert payload["env"]["OPENROUTER_API_KEY"] == "test-openrouter"
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

    monkeypatch.setattr(install_module, "initialize_tenant_route", lambda *args, **kwargs: None)
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
