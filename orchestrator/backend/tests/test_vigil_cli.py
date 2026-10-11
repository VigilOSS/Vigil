from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "src"))
# `agent/scripts` is the root the agent-side packages are canonically imported
# from: `assess.lib.client`, never `agent.scripts.assess.lib.client`. The repo
# root above makes the second spelling resolve too — to an independent SECOND
# copy of the same file, whose classes fail `except`/`pytest.raises` identity
# checks against the canonical ones. Declaring the real root here keeps the
# canonical spelling working under any test selection; it otherwise arrives only
# as a side effect of app.main importing the backend's taxonomy bridge, which is
# documented to tolerate an absent agent tree.
sys.path.insert(0, str(repo_root / "agent" / "scripts"))

from tests.proof_fixtures import completed_confirm_check, post_artifact_backed_source_observation  # noqa: E402
from vigil_cli import restart_manifest  # noqa: E402


@pytest.fixture(autouse=True)
def application_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore per-test explicit application fixtures to the caller's environment."""
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(repo_root))


def _copy_agent_fixture(agent_root: Path, install_root: Path) -> Path:
    target_agent = install_root / "agent"
    target_agent.mkdir(parents=True)
    for name in ("scripts", ".codex", ".claude"):
        shutil.copytree(agent_root / name, target_agent / name)
    for name in ("AGENTS.md", "AGENTS-blue.md", "operator-core-code.md", "CLAUDE.md", "SKILL.md"):
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


def _write_blue_scope(eng_dir: Path) -> None:
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(
        json.dumps(
            {
                "engagement_type": "blue",
                "customer": "acme",
                "platforms": ["gws"],
                "tenant_reference_paths": ["agent/references/tenants/acme-workspace.md"],
                "status": "in_progress",
                "current_phase": "investigate",
                "hosts": [],
            }
        ),
        encoding="utf-8",
    )


def test_engagement_create_web_writes_scope_launchers_and_list_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.engagements import (
        CreateEngagementOptions,
        create_engagement,
        list_engagements,
    )

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
    manifest = json.loads((created.path / "engagement.json").read_text(encoding="utf-8"))

    assert created.path.parent == install_root / "agent" / "engagements"
    assert scope["engagement_type"] == "offensive"
    assert scope["tracks"] == {"web": {"phase": "recon"}}
    assert scope["hostname"] == "app.example.com"
    assert scope["hosts"] == ["app.example.com", "admin.example.com"]
    assert scope["exploit_policy"] == "pause"
    assert scope["exploit_review_state"] == "pending"
    assert scope["approved_targets"] == []
    # Credentials are centralized in the backend store; no auth.json scaffold.
    assert not (created.path / "auth.json").exists()
    assert manifest["key"] == created.key
    # local cases.db no longer created; work items live in the backend
    # ``assessment_work_items`` table — see tests/test_work_buffer_backend.py.
    assert (created.path / "start_codex.sh").exists()
    assert (created.path / "start_claude.sh").exists()
    codex_launcher = (created.path / "start_codex.sh").read_text(encoding="utf-8")
    claude_launcher = (created.path / "start_claude.sh").read_text(encoding="utf-8")
    assert 'export VIGIL_CLIENT_NAME="codex"' in codex_launcher
    assert 'export VIGIL_CLIENT_NAME="claude"' in claude_launcher
    assert 'export CLAUDE_CODE_DISABLE_AUTO_MEMORY="1"' in claude_launcher
    assert "CLAUDE_CODE_DISABLE_AUTO_MEMORY" not in codex_launcher
    assert "codex --dangerously-bypass-approvals-and-sandbox" in codex_launcher
    assert (created.path / "start_kimi.sh").exists()
    assert "kimi --auto" in (created.path / "start_kimi.sh").read_text(encoding="utf-8")
    engagement_pointer = (created.path / "AGENTS.md").read_text(encoding="utf-8")
    assert "bounded parts" in engagement_pointer
    assert "end of the file" in engagement_pointer

    rows = list_engagements(install_root)
    assert [row.key for row in rows] == [created.key]
    assert rows[0].target == "https://app.example.com"


def test_engagement_create_blue_points_to_canonical_blue_operator_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import client_rosters as client_rosters_module
    from vigil_cli import engagements as engagements_module
    from vigil_cli.engagements import CreateEngagementOptions, create_engagement

    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    (install_root / "agent" / "AGENTS-blue.md").write_text(
        "canonical blue operator prompt\n", encoding="utf-8"
    )
    _isolate_orchestrator_url(monkeypatch)
    monkeypatch.setattr(engagements_module, "_verify_backend_install_root", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(engagements_module, "_emit_post_create_footer", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        client_rosters_module,
        "_render_codex_compact_prompt",
        lambda *_args, **_kwargs: "test compact prompt",
    )

    monkeypatch.setattr(
        engagements_module.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("blue engagement creation must not render a private prompt copy")
        ),
    )

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="blue",
            customer="acme",
            platforms=["gws"],
            tenant_reference_paths=["agent/references/tenants/acme-workspace.md"],
            skip_permissions=True,
        )
    )

    # Blue and red both use a small engagement-local bootstrap; the full blue
    # doctrine has one generated owner under the installed agent tree.
    blue_agents = (created.path / "AGENTS.md").read_text(encoding="utf-8")
    assert "agent/AGENTS-blue.md" in blue_agents
    assert "canonical blue operator prompt" not in blue_agents
    assert "bounded parts" in blue_agents
    assert "end of the file" in blue_agents
    assert "Read `ENGAGEMENT.md` in this directory if present" in blue_agents
    assert (created.path / ".codex" / "agents").is_symlink()


def test_engagement_create_does_not_accept_exploit_policy_or_auth_mode_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import main as main_module

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
    from vigil_cli import docker as docker_mod
    from vigil_cli import oob as oob_mod
    from vigil_cli.engagements import CreateEngagementOptions, create_engagement

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
    assert "vigil mitmproxy start" in captured.err
    assert f"vigil mitmproxy start {created.key}" not in captured.err
    assert "vigil oob start" in captured.err
    assert f"vigil engagement start {created.key} --client codex" in captured.err


def test_engagement_create_footer_suppresses_hints_when_services_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import docker as docker_mod
    from vigil_cli import oob as oob_mod
    from vigil_cli.engagements import CreateEngagementOptions, create_engagement

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
    assert "vigil mitmproxy start" not in captured.err
    assert "vigil oob start" not in captured.err


def test_engagement_create_android_uses_artifact_only_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.engagements import (
        CreateEngagementOptions,
        create_engagement,
        list_engagements,
    )

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
    # local cases.db no longer created; work items live in the backend
    # ``assessment_work_items`` table — see tests/test_work_buffer_backend.py.
    assert list_engagements(install_root)[0].target == "com.callpod.android_apps.keeper"


def test_engagement_create_android_cli_accepts_package_positional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module

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
    from vigil_cli import main as main_module

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


def test_engagement_create_leaves_database_and_backups_untouched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    from vigil_cli.engagements import CreateEngagementOptions, create_engagement

    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    custom_data = tmp_path / "backend-data"
    default_data = install_root / "orchestrator" / "backend" / "data"
    _write_marker_database(custom_data / "orchestrator.sqlite3", "custom")
    _write_marker_database(default_data / "orchestrator.sqlite3", "default")
    old_backup = custom_data / "orchestrator.sqlite3.bak.20260425T010000Z.11111"
    old_backup.write_bytes(b"retained backup")
    original_database = (custom_data / "orchestrator.sqlite3").read_bytes()
    _isolate_orchestrator_url(monkeypatch)
    monkeypatch.delenv("VIGIL_DATA_DIR", raising=False)
    monkeypatch.setenv("REDTEAM_ORCHESTRATOR_DATA_DIR", str(custom_data))

    create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
        )
    )

    custom_snapshots = sorted(custom_data.glob("orchestrator.sqlite3.bak.*"))
    assert custom_snapshots == [old_backup]
    assert old_backup.read_bytes() == b"retained backup"
    assert (custom_data / "orchestrator.sqlite3").read_bytes() == original_database
    assert not list(default_data.glob("orchestrator.sqlite3.bak.*"))
    assert "database snapshot" not in capsys.readouterr().err


class _TTYStdin:
    """Stdin stand-in whose isatty() is True, for wizard-path tests."""

    def isatty(self) -> bool:
        return True


def _created_path_from_stdout(out: str) -> Path:
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 1, f"stdout must carry exactly the engagement path, got: {out!r}"
    return Path(lines[0].strip())


def test_engagement_create_cli_merges_host_flags_and_hosts_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text(
        "# extra scope\nc.example.com\n\na.example.com\n",
        encoding="utf-8",
    )

    main_module.main(
        [
            "--root",
            str(install_root),
            "engagement",
            "create",
            "https://app.example.com",
            "--hosts",
            "a.example.com",
            "--host",
            "b.example.com",
            "--hosts-file",
            str(hosts_file),
            "--no-prompt",
        ]
    )

    created_path = _created_path_from_stdout(capsys.readouterr().out)
    scope = json.loads((created_path / "scope.json").read_text(encoding="utf-8"))
    # csv first, then --host entries, then file lines; duplicates collapse.
    assert scope["hosts"] == ["a.example.com", "b.example.com", "c.example.com"]


def test_engagement_create_cli_missing_hosts_file_fails_with_clear_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    with pytest.raises(SystemExit, match="hosts-file"):
        main_module.main(
            [
                "--root",
                str(install_root),
                "engagement",
                "create",
                "https://app.example.com",
                "--hosts-file",
                str(tmp_path / "missing.txt"),
                "--no-prompt",
            ]
        )
    assert not list((install_root / "agent" / "engagements").iterdir())


def test_engagement_create_cli_echoes_inferred_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    main_module.main(
        [
            "--root",
            str(install_root),
            "engagement",
            "create",
            "https://app.example.com",
            "--no-prompt",
        ]
    )

    captured = capsys.readouterr()
    created_path = _created_path_from_stdout(captured.out)
    scope = json.loads((created_path / "scope.json").read_text(encoding="utf-8"))
    assert scope["engagement_type"] == "offensive"
    assert "inferred type: web" in captured.err
    assert "--type" in captured.err


def test_engagement_create_cli_ambiguous_type_requires_explicit_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    with pytest.raises(SystemExit, match="--type"):
        main_module.main(
            [
                "--root",
                str(install_root),
                "engagement",
                "create",
                "my-project",
                "--no-prompt",
            ]
        )
    assert not list((install_root / "agent" / "engagements").iterdir())


def test_engagement_create_cli_repo_flag_requires_explicit_remediation_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    repository = tmp_path / "acme"
    subprocess.run(["git", "init", str(repository)], check=True, capture_output=True)

    with pytest.raises(SystemExit, match="--type remediation"):
        main_module.main([
            "--root", str(install_root), "engagement", "create", "Acme",
            "--repo", str(repository), "--no-prompt",
        ])
    assert not (repository / "PROJECT.md").exists()
    assert not list((install_root / "agent/engagements").iterdir())

    main_module.main(
        [
            "--root",
            str(install_root),
            "engagement",
            "create",
            "--type",
            "remediation",
            "Acme",
            "--repo",
            str(repository),
            "--no-prompt",
        ]
    )

    captured = capsys.readouterr()
    created_path = _created_path_from_stdout(captured.out)
    scope = json.loads((created_path / "scope.json").read_text(encoding="utf-8"))
    assert scope["engagement_type"] == "remediation"
    assert scope["current_phase"] == "intake"
    assert scope["name"] == "Acme"


def test_engagement_create_cli_repo_plus_web_target_rejects_mixed_workflows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    with pytest.raises(SystemExit, match="remediation"):
        main_module.main(
            [
                "--root", str(install_root), "engagement", "create",
                "https://app.example.com", "--repo", str(tmp_path / "repo"),
                "--name", "my-project", "--no-prompt",
            ]
        )
    assert not list((install_root / "agent" / "engagements").iterdir())


def test_engagement_create_wizard_prompts_on_stderr_keep_stdout_path_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    monkeypatch.setattr(main_module.sys, "stdin", _TTYStdin())
    # target, attribution-header (blank = none), out-of-scope (blank = none), confirm.
    answers = iter(["app.example.com", "", "", "y"])
    monkeypatch.setattr("builtins.input", lambda *_args: next(answers))

    main_module.main(["--root", str(install_root), "engagement", "create", "--type", "web"])

    captured = capsys.readouterr()
    created_path = _created_path_from_stdout(captured.out)
    scope = json.loads((created_path / "scope.json").read_text(encoding="utf-8"))
    assert scope["engagement_type"] == "offensive"
    assert scope["hosts"] == ["app.example.com"]
    assert "Target URL or host" in captured.err
    assert "Create engagement?" in captured.err


def test_engagement_create_bare_invocation_runs_full_wizard_with_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    monkeypatch.setattr(main_module.sys, "stdin", _TTYStdin())
    # type choice (1 = web), target, attribution (blank=none), out-of-scope (blank), confirmation.
    answers = iter(["1", "app.example.com", "", "", "y"])
    monkeypatch.setattr("builtins.input", lambda *_args: next(answers))

    main_module.main(["--root", str(install_root), "engagement", "create"])

    captured = capsys.readouterr()
    created_path = _created_path_from_stdout(captured.out)
    scope = json.loads((created_path / "scope.json").read_text(encoding="utf-8"))
    assert scope["engagement_type"] == "offensive"
    assert scope["hosts"] == ["app.example.com"]
    assert "Engagement type" in captured.err
    assert "Create engagement?" in captured.err


def test_engagement_create_wizard_confirmation_decline_aborts_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    monkeypatch.setattr(main_module.sys, "stdin", _TTYStdin())
    # target, attribution (blank=none), out-of-scope (blank), decline confirm.
    answers = iter(["app.example.com", "", "", "n"])
    monkeypatch.setattr("builtins.input", lambda *_args: next(answers))

    with pytest.raises(SystemExit):
        main_module.main(["--root", str(install_root), "engagement", "create", "--type", "web"])
    assert not list((install_root / "agent" / "engagements").iterdir())


def test_engagement_create_wizard_reprompts_on_empty_required_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    monkeypatch.setattr(main_module.sys, "stdin", _TTYStdin())
    # empty (reprompt), target, attribution (blank=none), out-of-scope (blank), confirm.
    answers = iter(["", "app.example.com", "", "", "y"])
    monkeypatch.setattr("builtins.input", lambda *_args: next(answers))

    main_module.main(["--root", str(install_root), "engagement", "create", "--type", "web"])

    created_path = _created_path_from_stdout(capsys.readouterr().out)
    scope = json.loads((created_path / "scope.json").read_text(encoding="utf-8"))
    assert scope["hosts"] == ["app.example.com"]


def test_engagement_create_interactive_with_complete_flags_skips_wizard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    monkeypatch.setattr(main_module.sys, "stdin", _TTYStdin())
    monkeypatch.setattr(
        "builtins.input",
        lambda *_args: (_ for _ in ()).throw(AssertionError("wizard must not engage when flags are complete")),
    )

    # "Complete" now includes the attribution header + out-of-scope dimensions:
    # supplying them via flags suppresses the wizard prompts entirely (the
    # interactive header/OOS wizard otherwise fires for web engagements).
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
            "--program",
            "bugcrowd",
            "--researcher",
            "tester",
            "--out-of-scope",
            "blocked.example.com",
        ]
    )

    created_path = _created_path_from_stdout(capsys.readouterr().out)
    assert (created_path / "scope.json").is_file()
    scope = json.loads((created_path / "scope.json").read_text(encoding="utf-8"))
    assert scope["required_headers"] == {"X-Bug-Bounty": "tester"}
    assert scope["out_of_scope"] == ["blocked.example.com"]


def test_engagement_create_persists_header_and_rate_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # --header (repeatable) + --rate-limit both land in scope.json for a web
    # engagement. The cap is a per-invocation / GLOBAL req/s ceiling (bounds
    # per-host as a side effect); the recon pipeline's bulk web stages read it
    # back via assess.lib.scope.rate_limit / rate_caps_for_dir.
    from vigil_cli import main as main_module

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
            "web",
            "https://app.example.com",
            "--hosts",
            "app.example.com",
            "--no-prompt",
            "--header",
            "X-Bug-Bounty: acme-researcher",
            "--header",
            "X-Trace: deadbeef",
            "--rate-limit",
            "5",
        ]
    )

    created_path = _created_path_from_stdout(capsys.readouterr().out)
    scope = json.loads((created_path / "scope.json").read_text(encoding="utf-8"))
    assert scope["required_headers"] == {"X-Bug-Bounty": "acme-researcher", "X-Trace": "deadbeef"}
    assert scope["rate_limit"] == 5.0


def test_engagement_create_omits_rate_limit_when_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Unset --rate-limit must leave scope.json with NO rate_limit key, so the
    # accessor returns None and recon stages keep their per-tool defaults.
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    main_module.main(
        [
            "--root",
            str(install_root),
            "engagement",
            "create",
            "https://app.example.com",
            "--no-prompt",
        ]
    )

    created_path = _created_path_from_stdout(capsys.readouterr().out)
    scope = json.loads((created_path / "scope.json").read_text(encoding="utf-8"))
    assert "rate_limit" not in scope


def test_resolve_rate_limit_accessor() -> None:
    # The shared resolver: None/empty -> None (unchanged default); a number >= 1
    # passes through; non-numeric AND sub-1 values (0, negative, fractional <1)
    # raise SystemExit so a malformed/unexpressible cap is never persisted. httpx
    # -rate-limit / katana -rl take an integer req/s, so a sub-1 cap (e.g. 0.5)
    # would floor UP to 1 (2x the intended ceiling) — reject it at the boundary.
    from vigil_cli.engagements import resolve_rate_limit

    assert resolve_rate_limit(None) is None
    assert resolve_rate_limit("") is None
    assert resolve_rate_limit(5) == 5.0
    assert resolve_rate_limit("3.5") == 3.5
    assert resolve_rate_limit(1) == 1.0          # boundary: exactly 1 req/s is allowed
    with pytest.raises(SystemExit):
        resolve_rate_limit(0)
    with pytest.raises(SystemExit):
        resolve_rate_limit(-1)
    with pytest.raises(SystemExit):
        resolve_rate_limit(0.5)                  # sub-1 fractional cap now rejected
    with pytest.raises(SystemExit):
        resolve_rate_limit("0.5")                # ...including the string form
    with pytest.raises(SystemExit):
        resolve_rate_limit("bogus")


def test_engagement_create_rejects_sub1_rate_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A sub-1 --rate-limit must be rejected at create: httpx -rate-limit /
    # katana -rl take an integer req/s, so a 0.5 cap would floor UP to 1 (2x the
    # intended ceiling). Reject it rather than silently doubling the cap.
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    with pytest.raises(SystemExit) as exc:
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
                "--rate-limit",
                "0.5",
            ]
        )
    assert "at least 1 req/s" in str(exc.value)


def test_engagement_create_rate_limit_rejected_for_code_engagement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # --rate-limit is HTTP-target only; a code engagement must reject it with a
    # clear error rather than silently writing it into a non-HTTP scope.
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    with pytest.raises(SystemExit) as exc:
        main_module.main(
            [
                "--root",
                str(install_root),
                "engagement",
                "create",
                "--type",
                "code",
                "myproj",
                "--no-prompt",
                "--rate-limit",
                "5",
            ]
        )
    assert "--rate-limit" in str(exc.value)


def test_engagement_create_cli_json_output_replaces_bare_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    main_module.main(
        [
            "--root",
            str(install_root),
            "engagement",
            "create",
            "https://app.example.com",
            "--no-prompt",
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["engagement_type"] == "offensive"
    assert payload["scope"]["hosts"] == ["app.example.com"]
    created_path = Path(payload["path"])
    assert created_path.name == payload["key"]
    assert (created_path / "scope.json").is_file()


def test_engagement_create_interactive_dry_run_skips_creation_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    monkeypatch.setattr(main_module.sys, "stdin", _TTYStdin())
    # target + attribution (blank=none) + out-of-scope (blank). A
    # "Create engagement?" confirmation would exhaust the iterator and fail the
    # test — dry-run must not ask it.
    answers = iter(["app.example.com", "", ""])
    monkeypatch.setattr("builtins.input", lambda *_args: next(answers))

    main_module.main(["--root", str(install_root), "engagement", "create", "--type", "web", "--dry-run"])

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "dry-run" in captured.err
    assert "Create engagement?" not in captured.err
    assert not list((install_root / "agent" / "engagements").iterdir())


@pytest.mark.skipif(os.geteuid() == 0, reason="permission checks are bypassed when running as root")
def test_engagement_create_cli_unreadable_hosts_file_fails_with_clear_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("a.example.com\n", encoding="utf-8")
    hosts_file.chmod(0o000)

    try:
        with pytest.raises(SystemExit, match="hosts-file"):
            main_module.main(
                [
                    "--root",
                    str(install_root),
                    "engagement",
                    "create",
                    "https://app.example.com",
                    "--hosts-file",
                    str(hosts_file),
                    "--no-prompt",
                ]
            )
    finally:
        hosts_file.chmod(0o644)
    assert not list((install_root / "agent" / "engagements").iterdir())


def test_engagement_create_cli_dry_run_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    data_dir = install_root / "orchestrator" / "backend" / "data"
    _write_marker_database(data_dir / "orchestrator.sqlite3", "untouched")
    monkeypatch.delenv("VIGIL_DATA_DIR", raising=False)
    monkeypatch.delenv("REDTEAM_ORCHESTRATOR_DATA_DIR", raising=False)

    main_module.main(
        [
            "--root",
            str(install_root),
            "engagement",
            "create",
            "https://app.example.com",
            "--no-prompt",
            "--dry-run",
            "--json",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["dry_run"] is True
    assert payload["engagement_type"] == "web"
    assert payload["scope"]["hosts"] == ["app.example.com"]
    assert not list((install_root / "agent" / "engagements").iterdir())
    assert not list(data_dir.glob("orchestrator.sqlite3.bak.*"))


def test_engagement_create_cli_dry_run_text_keeps_stdout_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    main_module.main(
        [
            "--root",
            str(install_root),
            "engagement",
            "create",
            "https://app.example.com",
            "--no-prompt",
            "--dry-run",
        ]
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "dry-run" in captured.err
    assert "web" in captured.err
    assert not list((install_root / "agent" / "engagements").iterdir())


def test_engagement_create_dry_run_still_validates_required_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    with pytest.raises(SystemExit, match="require"):
        main_module.main(
            [
                "--root",
                str(install_root),
                "engagement",
                "create",
                "--type",
                "web",
                "--no-prompt",
                "--dry-run",
            ]
        )


def test_engagement_create_help_documents_examples_and_blue_pointer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(["engagement", "create", "--help"])
    assert excinfo.value.code == 0

    help_text = capsys.readouterr().out
    assert "Examples" in help_text
    assert "vigil blue engage" in help_text


def test_prompt_choice_reprompts_on_invalid_then_accepts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli.main import _prompt_choice

    answers = iter(["9", "code"])
    monkeypatch.setattr("builtins.input", lambda *_args: next(answers))

    assert _prompt_choice("Engagement type", "web", ["web", "code", "both", "android"]) == "code"
    assert "Invalid" in capsys.readouterr().err


def test_plan_engagement_scope_matches_created_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.engagements import (
        CreateEngagementOptions,
        create_engagement,
        plan_engagement,
    )

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    options = CreateEngagementOptions(
        install_root=install_root,
        engagement_type="web",
        target="https://app.example.com",
        hosts=["app.example.com", "admin.example.com"],
    )

    plan = plan_engagement(options)
    created = create_engagement(options)

    scope_on_disk = json.loads((created.path / "scope.json").read_text(encoding="utf-8"))
    assert plan.scope == scope_on_disk
    assert plan.engagement_type == "web"
    assert plan.label


def test_resolve_runtime_data_dir_honours_runtime_then_legacy_then_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.runtime import _resolve_runtime_data_dir

    install_root = tmp_path / "install"

    # VIGIL_RUNTIME_DATA_DIR wins over everything.
    monkeypatch.setenv("VIGIL_RUNTIME_DATA_DIR", "/mnt/runtime-data")
    monkeypatch.setenv("KALI_MCP_DATA_DIR", "/mnt/legacy-data")
    assert _resolve_runtime_data_dir(install_root) == Path("/mnt/runtime-data")

    # Legacy KALI_MCP_DATA_DIR is honoured when VIGIL_RUNTIME_DATA_DIR is unset, so
    # a pre-rename install that relocated runtime state keeps working post-upgrade.
    monkeypatch.delenv("VIGIL_RUNTIME_DATA_DIR", raising=False)
    assert _resolve_runtime_data_dir(install_root) == Path("/mnt/legacy-data")

    # Neither env var set -> default under the install root.
    monkeypatch.delenv("KALI_MCP_DATA_DIR", raising=False)
    assert _resolve_runtime_data_dir(install_root) == install_root / "state" / "runtime"

    # The orchestrator's VIGIL_DATA_DIR must NOT relocate the runtime dir — the two
    # are deliberately decoupled (regression guard for the env-collision fix).
    monkeypatch.setenv("VIGIL_DATA_DIR", "/mnt/orchestrator-data")
    assert _resolve_runtime_data_dir(install_root) == install_root / "state" / "runtime"

    # A value in the install-root .env is honoured host-side, not silently only inside
    # the container (Codex P2: docker --env-file never reaches this resolver).
    monkeypatch.delenv("VIGIL_RUNTIME_DATA_DIR", raising=False)
    install_root.mkdir(parents=True, exist_ok=True)
    (install_root / ".env").write_text("VIGIL_RUNTIME_DATA_DIR=/mnt/from-dotenv\n")
    assert _resolve_runtime_data_dir(install_root) == Path("/mnt/from-dotenv")

    # An exported env var still overrides the .env file.
    monkeypatch.setenv("VIGIL_RUNTIME_DATA_DIR", "/mnt/from-export")
    assert _resolve_runtime_data_dir(install_root) == Path("/mnt/from-export")
    monkeypatch.delenv("VIGIL_RUNTIME_DATA_DIR", raising=False)

    # A relative .env value resolves against the install root, not CWD.
    (install_root / ".env").write_text("VIGIL_RUNTIME_DATA_DIR=custom-data\n")
    assert _resolve_runtime_data_dir(install_root) == install_root / "custom-data"


def test_resolve_source_root_uses_matched_application_instead_of_legacy_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import paths as paths_module

    install_root = tmp_path / "install"
    cached_source = tmp_path / "cached-source"
    for root in (install_root, cached_source):
        (root / "agent").mkdir(parents=True)
        (root / "orchestrator").mkdir()
    monkeypatch.delenv("VIGIL_SOURCE_DIR", raising=False)
    monkeypatch.setattr(paths_module, "get_config_value", lambda *args: None)
    monkeypatch.setattr(paths_module, "find_repo_root", lambda start=None: None)
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(cached_source))
    assert paths_module.resolve_source_root(install_root=install_root) == cached_source.resolve()


def test_install_adopts_local_state_without_replacing_legacy_application(tmp_path: Path) -> None:
    from vigil_cli.install import InstallOptions, install_from_source

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

    assert (install_root / "README.md").read_text(encoding="utf-8") == "old readme\n"
    assert not (install_root / "AGENTS.md").exists()
    assert not (install_root / "agent" / "AGENTS.md").exists()
    assert marker.exists()
    codex_agents = marker.parent / ".codex" / "agents"
    assert not codex_agents.exists()
    assert database.read_text(encoding="utf-8") == "db"
    assert (install_root / "agent" / "old-managed.txt").read_text() == "remove me\n"
    assert legacy_installer.read_text() == "old installer\n"
    metadata = json.loads((install_root / "workspace.json").read_text())
    assert metadata["paths"]["engagements"] == str(marker.parent.parent)
    assert metadata["paths"]["data"] == str(database.parent)
    assert metadata["application"]["root"] == str(source_root)


# --------------------------------------------------------------------------- #
# W0 — install-staleness guard. `vigil install` stamps the source git sha into
# .vigil-install-meta.json so `vigil status` can warn (non-fatally) when the
# working root (~/vigil/agent tree) has fallen behind the source it was
# installed from (the I-5 root cause: a lagging install silently disables the
# whole feature set). Two-layer model: `vigil install` upgrades the
# WORKING ROOT; `uv tool upgrade vigil` upgrades only the CLI BINARY.
# --------------------------------------------------------------------------- #


def _git_env() -> dict[str, str]:
    return {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
    }


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        capture_output=True,
        check=True,
        env=_git_env(),
    )
    return result.stdout.strip()


def _init_git_repo(root: Path, files: dict[str, str] | None = None) -> str:
    """Init a minimal git repo at `root` with one commit; return HEAD sha."""
    files = files or {"README.md": "seed\n"}
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return _git(root, "rev-parse", "HEAD")


def _git_commit(root: Path, rel: str, content: str) -> str:
    (root / rel).write_text(content, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "more")
    return _git(root, "rev-parse", "HEAD")


def _installable_source(root: Path) -> Path:
    source_file = root / "src" / "vigil_cli" / "feature.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text("version = 'one'\n", encoding="utf-8")
    (root / "agent" / "engagements").mkdir(parents=True)
    (root / "orchestrator" / "backend" / "data").mkdir(parents=True)
    (root / "README.md").write_text("source\n", encoding="utf-8")
    return source_file


def _minimal_status(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "install_root": "/x",
        "install_exists": True,
        "engagement_count": 0,
        "orchestrator": {"state": "stopped", "healthy": False, "readiness": {}},
        "runtime": {"state": "stopped", "mounts_ok": None, "resources": None},
        "mitmproxy": {"state": "stopped", "ca_volume": False},
        "oob": {"state": "stopped", "clients": [], "domain": "-"},
        "backup": {"latest": None, "modified_at": None},
        "legacy_both_missing_code_phase": [],
        "install_staleness": {"state": "current"},
    }
    base.update(overrides)
    return base


def test_install_meta_records_and_reads_back_source_sha(tmp_path: Path) -> None:
    from vigil_cli.status import read_install_meta, write_install_meta

    source = tmp_path / "source"
    sha = _init_git_repo(source)
    install = tmp_path / "install"
    install.mkdir()

    meta = write_install_meta(install, source)
    assert meta["source_sha"] == sha
    assert (install / ".vigil-install-meta.json").is_file()

    read = read_install_meta(install)
    assert read is not None
    assert read["source_sha"] == sha
    assert "installed_at" in read


def test_install_staleness_current_when_sha_matches(tmp_path: Path) -> None:
    from vigil_cli.status import install_staleness, write_install_meta

    source = tmp_path / "source"
    _init_git_repo(source)
    install = tmp_path / "install"
    install.mkdir()
    shutil.copy2(source / "README.md", install / "README.md")
    write_install_meta(install, source)

    result = install_staleness(install, source_root=source)
    assert result["state"] == "current"


def test_install_staleness_stale_when_source_advances(tmp_path: Path) -> None:
    from vigil_cli.status import install_staleness, write_install_meta

    source = tmp_path / "source"
    _init_git_repo(source)
    install = tmp_path / "install"
    install.mkdir()
    write_install_meta(install, source)  # stamps the old sha

    new_sha = _git_commit(source, "README.md", "v2\n")
    result = install_staleness(install, source_root=source)
    assert result["state"] == "stale"
    assert result["current_source_sha"] == new_sha
    assert result["behind_count"] == 1


def test_install_stamp_records_current_application_bytes_without_copying_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import install as install_module
    from vigil_cli import status as status_module

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    source_file = _installable_source(source)
    install = tmp_path / "install"
    real_write_install_meta = status_module.write_install_meta

    def mutate_then_stamp(
        install_root: Path, source_root: Path, **kwargs: int
    ) -> dict[str, object]:
        source_file.write_text("version = 'two'\n", encoding="utf-8")
        return real_write_install_meta(install_root, source_root, **kwargs)

    monkeypatch.setattr(install_module, "write_install_meta", mutate_then_stamp)

    install_module.install_from_source(
        install_module.InstallOptions(
            source_root=source,
            install_root=install,
            verify_docker_image=False,
        )
    )

    assert not (install / "src").exists()
    assert source_file.read_text() == "version = 'two'\n"
    assert status_module.install_staleness(install, source_root=source)["state"] == (
        "current"
    )


def test_install_manifest_tracks_executable_mode_and_reinstall_repairs_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import install as install_module
    from vigil_cli.status import install_staleness

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    source_file = _installable_source(source)
    source_file.chmod(0o644)
    install = tmp_path / "install"
    options = install_module.InstallOptions(
        source_root=source,
        install_root=install,
        verify_docker_image=False,
    )
    install_module.install_from_source(options)
    assert install_staleness(install, source_root=source)["state"] == "current"

    source_file.chmod(0o755)

    assert install_staleness(install, source_root=source)["state"] == "stale"
    install_module.install_from_source(options)
    assert not (install / "src").exists()
    assert source_file.stat().st_mode & 0o777 == 0o755
    assert install_staleness(install, source_root=source)["state"] == "current"


def test_client_entrypoint_copy_excludes_cache_and_build_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import install as install_module
    from vigil_cli.status import read_install_meta

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    codex_role = source / "agent" / ".codex" / "agents" / "role.toml"
    claude_role = source / "agent" / ".claude" / "agents" / "role.md"
    codex_role.parent.mkdir(parents=True)
    claude_role.parent.mkdir(parents=True)
    codex_role.write_text("name = 'role'\n", encoding="utf-8")
    claude_role.write_text("# Role\n", encoding="utf-8")
    codex_cache = source / "agent" / ".codex" / "__pycache__" / "cache.pyc"
    claude_cache = source / "agent" / ".claude" / "node_modules" / "cache.bin"
    codex_cache.parent.mkdir()
    claude_cache.parent.mkdir()
    codex_cache.write_bytes(b"first-cache")
    claude_cache.write_bytes(b"first-node-module")
    install = tmp_path / "install"
    options = install_module.InstallOptions(
        source_root=source,
        install_root=install,
        verify_docker_image=False,
    )

    install_module.install_from_source(options)

    assert not (install / ".codex").exists()
    assert not (install / ".claude").exists()
    assert codex_role.is_file() and claude_role.is_file()
    assert not (install / ".codex" / "__pycache__").exists()
    assert not (install / ".claude" / "node_modules").exists()
    first_digest = (read_install_meta(install) or {})["source_content_sha256"]
    codex_cache.write_bytes(b"changed-cache")
    claude_cache.write_bytes(b"changed-node-module")

    install_module.install_from_source(options)

    assert not (install / ".codex" / "__pycache__").exists()
    assert not (install / ".claude" / "node_modules").exists()
    assert (read_install_meta(install) or {})["source_content_sha256"] == first_digest


@pytest.mark.parametrize("link_kind", ["outside", "loop"])
def test_install_rejects_source_symlink_before_destination_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, link_kind: str
) -> None:
    from vigil_cli import install as install_module

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "external.txt").write_text("must not copy\n", encoding="utf-8")
    link = source / "src" / "link"
    target = outside if link_kind == "outside" else link
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    install = tmp_path / "install"
    installed_file = install / "src" / "vigil_cli" / "feature.py"
    installed_file.parent.mkdir(parents=True)
    installed_file.write_text("preserve me\n", encoding="utf-8")

    with pytest.raises(OSError, match="unsafe symbolic link"):
        install_module.install_from_source(
            install_module.InstallOptions(
                source_root=source,
                install_root=install,
                verify_docker_image=False,
            )
        )

    assert installed_file.read_text(encoding="utf-8") == "preserve me\n"
    assert not (install / ".vigil-install-meta.json").exists()


def test_install_preserves_symlinked_legacy_source_without_external_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import install as install_module

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("outside\n", encoding="utf-8")
    install = tmp_path / "install"
    install.mkdir()
    try:
        (install / "src").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    install_module.install_from_source(
        install_module.InstallOptions(
            source_root=source,
            install_root=install,
            verify_docker_image=False,
        )
    )
    assert sentinel.read_text(encoding="utf-8") == "outside\n"
    assert not (outside / "vigil_cli").exists()
    assert (install / ".vigil-install-meta.json").exists()
    assert (install / "src").is_symlink()


def test_install_rejects_symlinked_runtime_state_before_external_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import install as install_module

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    outside = tmp_path / "outside-runtime"
    outside.mkdir()
    install = tmp_path / "install"
    install.mkdir()
    try:
        (install / ".runtime-data").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(OSError, match="unsafe symbolic link"):
        install_module.install_from_source(
            install_module.InstallOptions(
                source_root=source,
                install_root=install,
                verify_docker_image=False,
            )
        )

    assert list(outside.iterdir()) == []
    assert not (install / ".vigil-install-meta.json").exists()


@pytest.mark.parametrize("linked_ancestor", ["source", "install"])
def test_install_rejects_symlinked_ancestor_without_external_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, linked_ancestor: str
) -> None:
    from vigil_cli import install as install_module

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    real_source_parent = tmp_path / "real-source-parent"
    source = real_source_parent / "source"
    _installable_source(source)
    install = tmp_path / "install"
    install.mkdir()
    installed_sentinel = install / "sentinel.txt"
    installed_sentinel.write_text("installed untouched\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_sentinel = outside / "sentinel.txt"
    outside_sentinel.write_text("outside untouched\n", encoding="utf-8")

    try:
        if linked_ancestor == "source":
            alias = tmp_path / "source-alias"
            alias.symlink_to(real_source_parent, target_is_directory=True)
            source = alias / "source"
        else:
            alias = tmp_path / "install-alias"
            alias.symlink_to(outside, target_is_directory=True)
            install = alias / "working-root"
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(OSError, match="unsafe symbolic link"):
        install_module.install_from_source(
            install_module.InstallOptions(
                source_root=source,
                install_root=install,
                verify_docker_image=False,
            )
        )

    assert installed_sentinel.read_text(encoding="utf-8") == "installed untouched\n"
    assert outside_sentinel.read_text(encoding="utf-8") == "outside untouched\n"
    assert not (outside / "working-root").exists()


def test_install_rejects_destination_root_swap_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import install as install_module

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    install = tmp_path / "install"
    install.mkdir()
    detached = tmp_path / "detached-install"
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("outside untouched\n", encoding="utf-8")
    real_validate = install_module.validate_install_destination
    swapped = False

    def validate_then_swap(path: Path) -> None:
        nonlocal swapped
        real_validate(path)
        path.rename(detached)
        path.symlink_to(outside, target_is_directory=True)
        swapped = True

    monkeypatch.setattr(
        install_module, "validate_install_destination", validate_then_swap
    )

    with pytest.raises(OSError, match="unsafe symbolic link"):
        install_module.install_from_source(
            install_module.InstallOptions(
                source_root=source,
                install_root=install,
                verify_docker_image=False,
            )
        )

    assert swapped is True
    assert sentinel.read_text(encoding="utf-8") == "outside untouched\n"
    assert sorted(path.name for path in outside.iterdir()) == ["sentinel.txt"]


def test_install_rejects_destination_child_swap_between_check_and_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import install as install_module, workspace as workspace_module

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    install = tmp_path / "install"
    destination_child = install / "state"
    destination_child.mkdir(parents=True)
    (destination_child / "old.txt").write_text("old\n", encoding="utf-8")
    detached = tmp_path / "detached-src"
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("outside untouched\n", encoding="utf-8")
    real_open = workspace_module.open_pinned_directory
    swapped = False

    def check_then_swap(path: Path, **kwargs):
        nonlocal swapped
        boundary = real_open(path, **kwargs)
        if path == destination_child and not swapped:
            path.rename(detached)
            path.symlink_to(outside, target_is_directory=True)
            swapped = True
        return boundary

    monkeypatch.setattr(workspace_module, "open_pinned_directory", check_then_swap)

    with pytest.raises(OSError, match="unsafe symbolic link"):
        install_module.install_from_source(
            install_module.InstallOptions(
                source_root=source,
                install_root=install,
                verify_docker_image=False,
            )
        )

    assert swapped is True
    assert sentinel.read_text(encoding="utf-8") == "outside untouched\n"
    assert sorted(path.name for path in outside.iterdir()) == ["sentinel.txt"]


@pytest.mark.parametrize(
    ("destination_name", "expected"),
    [
        ("README.md", "source\n"),
        ("AGENTS.md", "# Vigil Operator Entry Point\n"),
        ("CLAUDE.md", "# Claude source\n"),
    ],
)
def test_install_preserves_hardlinked_legacy_application_and_custom_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    destination_name: str,
    expected: str,
) -> None:
    from vigil_cli import install as install_module

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    (source / "agent" / "AGENTS.md").write_text("# Agent source\n", encoding="utf-8")
    (source / "agent" / "CLAUDE.md").write_text("# Claude source\n", encoding="utf-8")
    install = tmp_path / "install"
    install.mkdir()
    outside = tmp_path / f"outside-{destination_name}"
    outside.write_text("outside untouched\n", encoding="utf-8")
    os.link(outside, install / destination_name)

    install_module.install_from_source(
        install_module.InstallOptions(
            source_root=source,
            install_root=install,
            verify_docker_image=False,
        )
    )

    assert outside.read_text(encoding="utf-8") == "outside untouched\n"
    assert (install / destination_name).read_text(encoding="utf-8") == "outside untouched\n"
    assert (install / destination_name).stat().st_ino == outside.stat().st_ino


def test_install_removes_derived_entrypoints_when_their_sources_are_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import install as install_module
    from vigil_cli.status import install_staleness

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    (source / "agent" / "AGENTS.md").write_text("# Agent source\n", encoding="utf-8")
    (source / "agent" / "CLAUDE.md").write_text("# Claude source\n", encoding="utf-8")
    (source / "agent" / ".codex" / "agents").mkdir(parents=True)
    (source / "agent" / ".codex" / "agents" / "role.toml").write_text(
        "name = 'role'\n", encoding="utf-8"
    )
    (source / "agent" / ".claude" / "agents").mkdir(parents=True)
    (source / "agent" / ".claude" / "agents" / "role.md").write_text(
        "# Role\n", encoding="utf-8"
    )
    install = tmp_path / "install"
    options = install_module.InstallOptions(
        source_root=source,
        install_root=install,
        verify_docker_image=False,
    )
    install_module.install_from_source(options)

    (source / "agent" / "AGENTS.md").unlink()
    (source / "agent" / "CLAUDE.md").unlink()
    shutil.rmtree(source / "agent" / ".codex")
    shutil.rmtree(source / "agent" / ".claude")
    install_module.install_from_source(options)

    for name in ("AGENTS.md", "CLAUDE.md", ".codex", ".claude"):
        assert not (install / name).exists()
    assert install_staleness(install, source_root=source)["state"] == "current"


@pytest.mark.parametrize(
    ("source_kind", "destination_kind"),
    [("file", "directory"), ("directory", "file")],
)
def test_install_reconciles_file_directory_collisions_and_is_immediately_current(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_kind: str,
    destination_kind: str,
) -> None:
    from vigil_cli import install as install_module
    from vigil_cli.status import install_staleness

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    managed_source = source / "docker"
    if source_kind == "file":
        managed_source.write_text("source file\n", encoding="utf-8")
    else:
        managed_source.mkdir()
        (managed_source / "nested.txt").write_text("source dir\n", encoding="utf-8")
    install = tmp_path / "install"
    install.mkdir()
    managed_destination = install / "docker"
    if destination_kind == "file":
        managed_destination.write_text("old file\n", encoding="utf-8")
    else:
        managed_destination.mkdir()
        (managed_destination / "old.txt").write_text("old dir\n", encoding="utf-8")

    install_module.install_from_source(
        install_module.InstallOptions(
            source_root=source,
            install_root=install,
            verify_docker_image=False,
        )
    )

    assert managed_destination.is_file() is (destination_kind == "file")
    assert managed_destination.is_dir() is (destination_kind == "directory")
    if destination_kind == "file":
        assert managed_destination.read_text() == "old file\n"
    else:
        assert (managed_destination / "old.txt").read_text() == "old dir\n"
    assert install_staleness(install, source_root=source)["state"] == "current"


def test_install_manifest_normalizes_installer_created_preserved_ancestors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import install as install_module
    from vigil_cli.status import install_staleness

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    (source / "agent" / "engagements").mkdir(parents=True)
    (source / "orchestrator").mkdir(parents=True)
    (source / "README.md").write_text("source\n", encoding="utf-8")
    install = tmp_path / "install"

    install_module.install_from_source(
        install_module.InstallOptions(
            source_root=source,
            install_root=install,
            verify_docker_image=False,
        )
    )

    assert (install / "state").is_dir()
    assert not (install / "orchestrator").exists()
    assert install_staleness(install, source_root=source)["state"] == "current"


def test_in_place_install_preserves_repository_root_entrypoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import install as install_module

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    maintainer_entrypoint = "# Maintainer repository instructions\n"
    (source / "AGENTS.md").write_text(maintainer_entrypoint, encoding="utf-8")
    (source / "agent" / "AGENTS.md").write_text(
        "# Engagement operator instructions\n", encoding="utf-8"
    )

    install_module.install_from_source(
        install_module.InstallOptions(
            source_root=source,
            install_root=source,
            verify_docker_image=False,
        )
    )

    assert (source / "AGENTS.md").read_text(encoding="utf-8") == maintainer_entrypoint


@pytest.mark.parametrize("alias_kind", ["symlink", "hardlink"])
def test_install_metadata_alias_never_mutates_external_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, alias_kind: str
) -> None:
    from vigil_cli import install as install_module
    from vigil_cli.status import INSTALL_META_FILENAME, install_staleness

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    install = tmp_path / "install"
    install.mkdir()
    external = tmp_path / "external-meta.json"
    external.write_text("external untouched\n", encoding="utf-8")
    destination = install / INSTALL_META_FILENAME
    try:
        if alias_kind == "symlink":
            destination.symlink_to(external)
        else:
            os.link(external, destination)
    except OSError as exc:
        pytest.skip(f"filesystem alias unavailable: {exc}")

    if alias_kind == "symlink":
        with pytest.raises(OSError, match="unsafe symbolic link|non-regular workspace file"):
            install_module.install_from_source(
                install_module.InstallOptions(
                    source_root=source,
                    install_root=install,
                    verify_docker_image=False,
                )
            )
    else:
        install_module.install_from_source(
            install_module.InstallOptions(
                source_root=source,
                install_root=install,
                verify_docker_image=False,
            )
        )
        assert install_staleness(install, source_root=source)["state"] == "current"
        assert destination.stat().st_ino != external.stat().st_ino

    assert external.read_text(encoding="utf-8") == "external untouched\n"


@pytest.mark.parametrize("command", ["install"])
@pytest.mark.parametrize("carrier", ["explicit", "environment", "config"])
def test_public_sync_commands_preserve_source_and_install_aliases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    carrier: str,
) -> None:
    from vigil_cli import main as main_module
    from vigil_cli import paths as paths_module
    from vigil_cli.install import InstallResult

    real_parent = tmp_path / "real-parent"
    source = real_parent / "source"
    _installable_source(source)
    alias_parent = tmp_path / "alias-parent"
    try:
        alias_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    source_alias = alias_parent / "source"
    install_alias = alias_parent / "install"
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    if carrier == "environment":
        monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(source_alias))
        monkeypatch.setenv("VIGIL_INSTALL_DIR", str(install_alias))
        arguments = [command]
    elif carrier == "config":
        monkeypatch.setattr(
            paths_module,
            "get_config_value",
            lambda key, *_a: {
                "source.dir": str(source_alias),
                "install.root": str(install_alias),
            }.get(key),
        )
        arguments = [command]
    else:
        arguments = [
            "--root",
            str(install_alias),
            "--source",
            str(source_alias),
            command,
        ]

    captured: dict[str, Path | None] = {}

    def capture_install(options, **_kwargs):
        captured["install"] = options.install_root
        captured["source"] = options.source_root
        return InstallResult(
            install_root=options.install_root,
            is_upgrade=False,
            image_built=False,
        )

    def capture_up(options, **_kwargs):
        captured["install"] = options.install_root
        captured["source"] = getattr(options, "source_root", None)

    monkeypatch.setattr(main_module, "install_from_source", capture_install)
    monkeypatch.setattr(main_module, "run_up", capture_up)
    monkeypatch.setattr(main_module.config_module, "set_config_value", lambda *_a: None)

    main_module.main(arguments)

    assert captured == {"install": install_alias, "source": repo_root if carrier == "config" else source_alias}


@pytest.mark.parametrize("carrier", ["explicit", "environment", "config"])
def test_public_up_preserves_workspace_alias_until_initialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, carrier: str
) -> None:
    from vigil_cli import paths as paths_module
    from vigil_cli import up as up_module

    real_parent = tmp_path / "real-parent"
    source = real_parent / "source"
    _installable_source(source)
    alias_parent = tmp_path / "alias-parent"
    try:
        alias_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    source_alias = alias_parent / "source"
    install_alias = alias_parent / "install"
    if carrier == "environment":
        monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(source_alias))
        source_value = None
    elif carrier == "config":
        monkeypatch.setattr(
            paths_module,
            "get_config_value",
            lambda key, *_a: str(source_alias) if key == "source.dir" else None,
        )
        source_value = None
    else:
        source_value = source_alias

    captured: dict[str, Path] = {}

    def capture_install(root, *, application_root):
        captured["install"] = root
        captured["source"] = application_root
        raise RuntimeError("captured initialization boundary")

    monkeypatch.setattr(up_module, "initialize_workspace", capture_install)

    with pytest.raises(RuntimeError, match="captured initialization boundary"):
        up_module.run_up(
            up_module.UpOptions(
                install_root=install_alias,
                source_root=source_value,
            )
        )

    assert captured == {"install": install_alias, "source": repo_root if carrier == "config" else source_alias}


def test_main_passes_explicit_source_alias_to_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import main as main_module

    real_parent = tmp_path / "real-parent"
    source = real_parent / "source"
    _installable_source(source)
    alias_parent = tmp_path / "alias-parent"
    try:
        alias_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    source_alias = alias_parent / "source"
    install_alias = alias_parent / "install"
    captured = None

    def capture_up(options, **_kwargs):
        nonlocal captured
        captured = options

    monkeypatch.setattr(main_module, "run_up", capture_up)
    main_module.main(
        [
            "--root",
            str(install_alias),
            "--source",
            str(source_alias),
            "up",
        ]
    )

    assert captured is not None
    assert captured.install_root == install_alias
    assert captured.source_root == source_alias


def test_install_keeps_destination_boundary_attached_through_post_sync_phases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import install as install_module

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    install = tmp_path / "install"
    detached = tmp_path / "detached"
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("outside untouched\n", encoding="utf-8")
    real_initialize = install_module.initialize_workspace
    post_sync_called = False

    def initialize_then_swap(install_root: Path, **kwargs):
        metadata = real_initialize(install_root, **kwargs)
        install_root.rename(detached)
        install_root.symlink_to(outside, target_is_directory=True)
        return metadata

    def unexpected_repair(*_args, **_kwargs):
        nonlocal post_sync_called
        post_sync_called = True
        raise AssertionError("post-sync path work touched a replaced root")

    monkeypatch.setattr(install_module, "initialize_workspace", initialize_then_swap)
    monkeypatch.setattr(
        install_module, "repair_engagement_client_rosters", unexpected_repair
    )

    with pytest.raises(OSError, match="unsafe symbolic link"):
        install_module.install_from_source(
            install_module.InstallOptions(
                source_root=source,
                install_root=install,
                verify_docker_image=False,
                refresh_physical_client_rosters=True,
            )
        )

    assert post_sync_called is False
    assert sentinel.read_text(encoding="utf-8") == "outside untouched\n"
    assert sorted(path.name for path in outside.iterdir()) == ["sentinel.txt"]


@pytest.mark.parametrize(
    ("phase", "existing_oob_route"),
    [
        ("roster", False),
        ("entrypoint", False),
        ("oob", False),
        ("oob", True),
        ("stamp", False),
        ("image", False),
    ],
    ids=["roster", "entrypoint", "oob-new", "oob-existing", "stamp", "image"],
)
def test_post_sync_phases_use_the_pinned_destination_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    existing_oob_route: bool,
) -> None:
    from vigil_cli import engagements as engagements_module
    from vigil_cli import install as install_module
    from vigil_cli import runtime as runtime_module
    from vigil_cli.client_rosters import ClientRosterRepairResult
    from vigil_cli.docker import DockerResult
    from vigil_cli.engagements import ClientEntrypointRepairResult

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    if phase == "image":
        for image_input in runtime_module.runtime_image_inputs(source):
            image_input.parent.mkdir(parents=True, exist_ok=True)
            image_input.write_text("build input\n", encoding="utf-8")
    install = tmp_path / "install"
    requested_install_root = Path(os.path.abspath(install))
    registry_path = tmp_path / "oob-allocations.json"
    if existing_oob_route:
        from vigil_cli.oob_relay import allocate_relay_route

        allocate_relay_route(
            install,
            slot_name="install",
            base_domain="oob.example.test",
            registry_path=registry_path,
            identity_factory=lambda: "existing-install-identity",
        )
    detached = tmp_path / "detached"
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("outside untouched\n", encoding="utf-8")
    original_cwd = Path.cwd()
    swapped = False
    received_roots: list[Path] = []

    def swap_public_root(root: Path, *, write_effect: bool = True) -> None:
        nonlocal swapped
        received_roots.append(root)
        if not swapped:
            install.rename(detached)
            install.symlink_to(outside, target_is_directory=True)
            swapped = True
        if write_effect:
            (root / f"{phase}-effect").write_text("phase effect\n", encoding="utf-8")

    def roster(root: Path, **_kwargs) -> ClientRosterRepairResult:
        if phase == "roster":
            swap_public_root(root)
        return ClientRosterRepairResult()

    def entrypoint(root: Path, **_kwargs) -> ClientEntrypointRepairResult:
        if phase == "entrypoint":
            swap_public_root(root)
        return ClientEntrypointRepairResult(
            scanned_count=0,
            reconciled=(),
            skipped=(),
        )

    real_initialize_relay_route = install_module.initialize_relay_route

    def oob(root: Path, **kwargs) -> None:
        if phase == "oob":
            swap_public_root(root)
            real_initialize_relay_route(root, **kwargs)

    real_write_install_meta = install_module.write_install_meta

    def stamp(root: Path, source_root: Path, **kwargs: int) -> dict[str, object]:
        if phase == "stamp":
            swap_public_root(root, write_effect=False)
            from vigil_cli.install_fs import atomic_write_bytes
            atomic_write_bytes(kwargs["install_fd"], "stamp-effect", b"phase effect\n", mode=0o644, display=root / "stamp-effect")
        return real_write_install_meta(root, source_root, **kwargs)

    real_build_runtime = runtime_module.build_runtime

    def image(root: Path, **kwargs) -> None:
        if phase == "image":
            swap_public_root(root, write_effect=False)
        real_build_runtime(root, **kwargs)

    def runner(argv: list[str], **_kwargs) -> DockerResult:
        if argv[:2] == ["docker", "build"]:
            (Path(argv[-1]) / "docker-runner-effect").write_text(
                "docker effect\n", encoding="utf-8"
            )
        return DockerResult(0, "", "")

    monkeypatch.setattr(install_module, "repair_engagement_client_rosters", roster)
    monkeypatch.setattr(
        engagements_module, "repair_engagement_client_entrypoints", entrypoint
    )
    monkeypatch.setattr(install_module, "initialize_relay_route", oob)
    monkeypatch.setattr(install_module, "write_install_meta", stamp)
    monkeypatch.setattr(install_module, "build_runtime", image)
    if phase == "oob":
        monkeypatch.setenv("VIGIL_OOB_DOMAIN", "oob.example.test")

    with pytest.raises(OSError, match="replaced directory"):
        install_module.install_from_source(
            install_module.InstallOptions(
                source_root=source,
                install_root=install,
                force_image=phase == "image",
                verify_docker_image=phase == "image",
                refresh_physical_client_rosters=phase in {"roster", "entrypoint"},
            ),
            runner=runner,
            build_runner=runner,
        )

    assert received_roots == [install if phase in {"stamp", "image"} else Path(".")]
    assert Path.cwd() == original_cwd
    assert sentinel.read_text(encoding="utf-8") == "outside untouched\n"
    assert sorted(path.name for path in outside.iterdir()) == ["sentinel.txt"]
    if phase == "oob":
        registry = json.loads(registry_path.read_text())
        [allocation] = registry["allocations"].values()
        assert allocation["install_root"] == str(requested_install_root)


@pytest.mark.parametrize("operation", ["manifest", "copy"])
def test_special_file_swap_is_opened_nonblocking_and_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    from vigil_cli import install_fs, install_manifest

    source = tmp_path / "source"
    source.mkdir()
    source_file = source / "payload"
    source_file.write_bytes(b"regular\n")
    destination = tmp_path / "destination"
    destination.mkdir()
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    destination_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    real_open = os.open
    opened_nonblocking = False

    def guarded_open(path, flags, *args, **kwargs):
        nonlocal opened_nonblocking
        if path == "payload":
            opened_nonblocking = bool(flags & os.O_NONBLOCK)
            if not opened_nonblocking:
                raise AssertionError("special-file candidate opened without O_NONBLOCK")
        return real_open(path, flags, *args, **kwargs)

    source_file.unlink()
    try:
        os.mkfifo(source_file)
    except OSError as exc:
        os.close(source_fd)
        os.close(destination_fd)
        pytest.skip(f"FIFO unavailable: {exc}")
    monkeypatch.setattr(install_fs.os, "open", guarded_open)

    try:
        with pytest.raises(OSError, match="non-regular file"):
            if operation == "copy":
                install_fs.copy_regular_file(
                    source_fd,
                    "payload",
                    destination_fd,
                    "payload",
                    source_display=source_file,
                    destination_display=destination / "payload",
                )
            else:
                metadata = os.stat(
                    "payload", dir_fd=source_fd, follow_symlinks=False
                )
                install_manifest._read_regular_file(
                    source_fd, "payload", source_file, metadata
                )
    finally:
        os.close(source_fd)
        os.close(destination_fd)

    assert opened_nonblocking is True


@pytest.mark.parametrize("failure", ["close", "replace"])
def test_atomic_publication_failure_cleans_temp_and_preserves_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    from vigil_cli import install_fs

    destination = tmp_path / "destination"
    destination.mkdir()
    published = destination / "payload"
    published.write_bytes(b"original")
    directory_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    if failure == "replace":
        monkeypatch.setattr(
            install_fs.os,
            "replace",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("replace failed")),
        )
    else:
        real_close = install_fs.os.close
        failed = False

        def close_then_fail(fd: int) -> None:
            nonlocal failed
            real_close(fd)
            if not failed:
                failed = True
                raise OSError("close failed")

        monkeypatch.setattr(install_fs.os, "close", close_then_fail)

    try:
        with pytest.raises(OSError, match=f"{failure} failed"):
            install_fs.atomic_write_bytes(
                directory_fd,
                "payload",
                b"replacement",
                mode=0o644,
                display=published,
            )
    finally:
        if failure != "close":
            os.close(directory_fd)

    assert published.read_bytes() == b"original"
    assert sorted(path.name for path in destination.iterdir()) == ["payload"]


def test_install_rejects_incomplete_application_and_preserves_existing_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import install as install_module

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    _installable_source(source)
    stale = source / "orchestrator" / "stale.txt"
    stale.write_text("remove me\n", encoding="utf-8")
    install = tmp_path / "install"
    options = install_module.InstallOptions(
        source_root=source,
        install_root=install,
        verify_docker_image=False,
    )
    preserved = install / "orchestrator" / "backend" / "data" / "keep.db"
    preserved.parent.mkdir(parents=True)
    preserved.write_bytes(b"keep")
    legacy_source = install / "orchestrator" / "stale.txt"
    legacy_source.write_text("old application retained\n")
    install_module.install_from_source(options)
    stamp = (install / ".vigil-install-meta.json").read_bytes()
    shutil.rmtree(source / "orchestrator")

    with pytest.raises(SystemExit, match="Invalid Vigil application directory"):
        install_module.install_from_source(options)

    assert preserved.read_bytes() == b"keep"
    assert legacy_source.read_text() == "old application retained\n"
    assert (install / ".vigil-install-meta.json").read_bytes() == stamp


def test_install_staleness_unknown_without_resolvable_source(tmp_path: Path) -> None:
    from vigil_cli.status import install_staleness, write_install_meta

    source = tmp_path / "source"
    _init_git_repo(source)
    install = tmp_path / "install"
    install.mkdir()
    write_install_meta(install, source)

    # A path that is not a git checkout yields no current sha -> unknown, not stale.
    result = install_staleness(install, source_root=tmp_path / "not-a-repo")
    assert result["state"] == "unknown"


def test_install_staleness_no_stamp_when_meta_missing(tmp_path: Path) -> None:
    from vigil_cli.status import install_staleness

    source = tmp_path / "source"
    _init_git_repo(source)
    install = tmp_path / "install"
    install.mkdir()

    result = install_staleness(install, source_root=source)
    assert result["state"] == "no-stamp"


def test_print_status_warns_when_working_root_behind_source(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli.status import print_status

    status = _minimal_status(
        install_staleness={
            "state": "stale",
            "installed_sha": "a" * 40,
            "current_source_sha": "b" * 40,
            "behind_count": 3,
        }
    )
    print_status(status)
    out = capsys.readouterr().out
    assert "warn" in out
    assert "vigil install" in out
    assert "matched application" in out
    assert "without copying source" in out
    assert "3" in out


def test_print_status_warns_on_missing_install_stamp(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli.status import print_status

    status = _minimal_status(install_staleness={"state": "no-stamp"})
    print_status(status)
    out = capsys.readouterr().out
    assert "warn" in out
    assert "vigil install" in out


def test_print_status_silent_when_install_current(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli.status import print_status

    print_status(_minimal_status(install_staleness={"state": "current"}))
    out = capsys.readouterr().out
    assert "behind source" not in out
    assert "install stamp" not in out


def test_print_status_warns_when_backend_build_inputs_changed_after_process_start(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli.status import print_status

    status = _minimal_status(
        orchestrator={
            "state": "running",
            "healthy": True,
            "readiness": {
                "reachable": True,
                "http_status": 200,
                "status": "ready",
                "backend_runtime": {
                    "restart_required": True,
                    "process_started_at": "2026-07-24T15:23:00Z",
                    "source_root": "/Users/example/vigil/orchestrator/backend/app",
                    "changed_inputs": ["app/services/state_manager/coverage.py"],
                },
            },
        },
    )

    print_status(status)

    out = capsys.readouterr().out
    assert "backend restart required" in out
    assert "coverage.py" in out


def test_collect_status_includes_install_staleness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.status import collect_status

    install = tmp_path / "install"
    (install / "agent" / "engagements").mkdir(parents=True)
    monkeypatch.setenv("VIGIL_SOURCE_DIR", str(tmp_path / "none"))

    def runner(argv: list[str], **_: object) -> DockerResult:
        return DockerResult(0, "", "")

    payload = collect_status(install, runner=runner)
    assert "install_staleness" in payload
    assert isinstance(payload["install_staleness"], dict)
    assert "state" in payload["install_staleness"]  # type: ignore[operator]


def test_install_cli_stamps_install_meta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module
    from vigil_cli.status import read_install_meta

    source = tmp_path / "source"
    (source / "agent" / "engagements").mkdir(parents=True)
    (source / "orchestrator" / "backend" / "data").mkdir(parents=True)
    sha = _init_git_repo(source, {"README.md": "seed\n"})
    install = tmp_path / "install"
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))

    main_module.main(
        ["--root", str(install), "--source", str(source), "install", "--skip-image-check"]
    )
    capsys.readouterr()

    meta = read_install_meta(install)
    assert meta is not None
    assert meta["source_sha"] == sha


def test_install_from_source_stamps_every_sync_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The stamp is written by the sync itself, not by the CLI dispatch table.

    `vigil up` calls install_from_source directly, so a stamp owned by the
    `install` dispatch branch left `up` syncing without re-stamping —
    the recorded sha stayed pinned at the last explicit install and `vigil status`
    reported a permanent false "stale".
    """
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.status import read_install_meta

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    (source / "agent" / "engagements").mkdir(parents=True)
    (source / "orchestrator" / "backend" / "data").mkdir(parents=True)
    sha = _init_git_repo(source, {"README.md": "seed\n"})
    install = tmp_path / "install"

    install_from_source(
        InstallOptions(source_root=source, install_root=install, verify_docker_image=False)
    )

    meta = read_install_meta(install)
    assert meta is not None and meta["source_sha"] == sha

    advanced = _git_commit(source, "README.md", "advanced\n")
    install_from_source(
        InstallOptions(source_root=source, install_root=install, verify_docker_image=False)
    )
    assert (read_install_meta(install) or {})["source_sha"] == advanced


def _capture_relay_route(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Stub the OOB layer out of install and record the roots it was handed.

    The upgrade verdict is no longer routed through it: relay routing decides
    legacy-vs-allocate from the install's own OOB state
    (``oob_relay.has_pre_routing_oob_state``), so ``InstallResult.is_upgrade``
    is where that contract is asserted. Recording the calls still proves the OOB
    phase ran rather than being silently skipped.
    """
    from vigil_cli import install as install_module

    seen: list[Path] = []

    def fake_initialize_relay_route(install_root, **_kwargs):
        seen.append(Path(install_root))
        return None

    monkeypatch.setattr(install_module, "initialize_relay_route", fake_initialize_relay_route)
    return seen


def _seed_source_tree(root: Path) -> None:
    """A pristine source checkout: the managed directories exist, Vigil state does
    not. `agent/engagements/.gitkeep` is TRACKED in the repo, so the placeholder
    must not read as a real engagement."""
    (root / "agent" / "engagements").mkdir(parents=True)
    (root / "agent" / "engagements" / ".gitkeep").write_text("", encoding="utf-8")
    (root / "orchestrator" / "backend" / "data").mkdir(parents=True)
    (root / ".claude").mkdir()
    (root / ".codex").mkdir()


def test_install_in_place_first_run_is_not_an_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A FIRST in-place install (install root == source checkout) is not an upgrade.

    Upgrade detection used to test for `agent`/`orchestrator`/`.claude`/`.codex`
    directories, which exist in the checkout itself before Vigil has ever run
    there. The false "upgrade" made `initialize_relay_route` pin the legacy
    SHARED OOB domain and ports 53/8443 instead of allocating an install-specific
    route, so two fresh in-place developer installs collided at the FRP/OOB edge.
    """
    from vigil_cli.install import InstallOptions, install_from_source

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "oob.example.test")
    root = tmp_path / "checkout"
    _seed_source_tree(root)
    seen = _capture_relay_route(monkeypatch)

    result = install_from_source(
        InstallOptions(source_root=root, install_root=root, verify_docker_image=False)
    )

    assert result.is_upgrade is False
    assert len(seen) == 1


def test_install_in_place_second_run_is_an_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The state the first in-place install leaves behind makes the second one
    an upgrade — the signal is Vigil's own state, not the checkout's layout."""
    from vigil_cli.install import InstallOptions, install_from_source

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "oob.example.test")
    root = tmp_path / "checkout"
    _seed_source_tree(root)
    seen = _capture_relay_route(monkeypatch)
    options = InstallOptions(source_root=root, install_root=root, verify_docker_image=False)

    install_from_source(options)
    result = install_from_source(options)

    assert result.is_upgrade is True
    assert len(seen) == 2


def test_install_out_of_tree_over_existing_install_is_an_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The normal `~/vigil` upgrade path must still report an upgrade.

    Both markers predate relay routing, so any install root that could hold a
    legacy shared route carries at least one of them.
    """
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.status import INSTALL_META_FILENAME

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "oob.example.test")
    source = tmp_path / "source"
    _seed_source_tree(source)

    markers = (
        ("meta", INSTALL_META_FILENAME),
        ("runtime-data", ".runtime-data/oob"),
        # An install old enough to predate BOTH stamps still has the operator's
        # engagements — that is the install the legacy shared route exists for.
        ("engagements", "agent/engagements/existing"),
    )
    for marker, subpath in markers:
        install_root = tmp_path / f"vigil-{marker}"
        (install_root / "agent").mkdir(parents=True)
        target = install_root / subpath
        if marker == "meta":
            target.write_text("{}", encoding="utf-8")
        else:
            target.mkdir(parents=True)
        seen = _capture_relay_route(monkeypatch)

        result = install_from_source(
            InstallOptions(
                source_root=source, install_root=install_root, verify_docker_image=False
            )
        )

        assert result.is_upgrade is True, marker
        assert len(seen) == 1, marker


def test_install_out_of_tree_into_empty_root_is_not_an_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "oob.example.test")
    source = tmp_path / "source"
    _seed_source_tree(source)
    seen = _capture_relay_route(monkeypatch)

    result = install_from_source(
        InstallOptions(
            source_root=source, install_root=tmp_path / "vigil", verify_docker_image=False
        )
    )

    assert result.is_upgrade is False
    assert len(seen) == 1


@pytest.mark.parametrize(
    ("prior_marker", "expected_upgrade"),
    [(None, False), (".vigil-install-meta.json", True)],
)
def test_install_from_source_dry_run_preflights_and_reports_state_without_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    prior_marker: str | None,
    expected_upgrade: bool,
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source

    source = tmp_path / "source"
    (source / "agent" / "engagements").mkdir(parents=True)
    (source / "orchestrator").mkdir()
    (source / "README.md").write_text("managed source\n", encoding="utf-8")
    install = tmp_path / "install"
    install.mkdir()
    if prior_marker is not None:
        (install / prior_marker).write_text("{}\n", encoding="utf-8")
    sentinel = install / "operator-state.txt"
    sentinel.write_text("preserve me\n", encoding="utf-8")
    before = {
        path.relative_to(tmp_path): (path.lstat().st_mode, path.read_bytes())
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("dry-run crossed a mutating install phase")

    monkeypatch.setattr("vigil_cli.install.initialize_workspace", forbidden)
    monkeypatch.setattr("vigil_cli.install.config_module.load_config", forbidden)
    monkeypatch.setattr("vigil_cli.install.initialize_relay_route", forbidden)
    monkeypatch.setattr("vigil_cli.install.repair_engagement_client_rosters", forbidden)
    monkeypatch.setattr("vigil_cli.install.write_install_meta", forbidden)
    monkeypatch.setattr("vigil_cli.install.build_runtime", forbidden)
    monkeypatch.setattr("vigil_cli.install.docker.image_exists", forbidden)

    result = install_from_source(
        InstallOptions(
            source_root=source,
            install_root=install,
            dry_run=True,
            force_image=True,
            verify_docker_image=True,
        )
    )

    assert result.install_root == install
    assert result.is_upgrade is expected_upgrade
    assert result.image_built is False
    assert before == {
        path.relative_to(tmp_path): (path.lstat().st_mode, path.read_bytes())
        for path in tmp_path.rglob("*")
        if path.is_file()
    }


def test_install_from_source_dry_run_rejects_unsafe_destination(
    tmp_path: Path,
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source

    source = tmp_path / "source"
    _installable_source(source)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("untouched\n", encoding="utf-8")
    install = tmp_path / "install"
    install.symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError, match="unsafe symbolic link"):
        install_from_source(
            InstallOptions(source_root=source, install_root=install, dry_run=True)
        )

    assert sentinel.read_text(encoding="utf-8") == "untouched\n"


def test_install_from_source_dry_run_rejects_unsafe_managed_source(
    tmp_path: Path,
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source

    source = tmp_path / "source"
    source.mkdir()
    (source / "orchestrator").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (source / "agent").symlink_to(outside, target_is_directory=True)
    install = tmp_path / "install"

    with pytest.raises(OSError, match="unsafe symbolic link"):
        install_from_source(
            InstallOptions(source_root=source, install_root=install, dry_run=True)
        )

    assert not install.exists()


def test_up_updates_workspace_application_provenance_without_copying_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Bring-up initializes private state and records matched release content."""
    from vigil_cli import up as up_module
    from vigil_cli.workspace import read_workspace

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    source = tmp_path / "source"
    (source / "agent" / "engagements").mkdir(parents=True)
    (source / "orchestrator" / "backend" / "data").mkdir(parents=True)
    (source / "README.md").write_text("seed\n")
    canonical = source / "cli" / "vigil_cli" / "scope_entries.py"
    canonical.parent.mkdir(parents=True)
    shutil.copy2(repo_root / "src" / "vigil_cli" / "scope_entries.py", canonical)
    install = tmp_path / "install"

    monkeypatch.setattr(up_module, "resolve_application_root", lambda *_a, **_k: source)
    monkeypatch.setattr(up_module, "image_outdated", lambda *_a, **_k: False)
    monkeypatch.setattr(up_module, "_runtime_image_drift", lambda *_a, **_k: False)
    monkeypatch.setattr(up_module, "proxy_image_drift", lambda **_k: False)
    monkeypatch.setattr(up_module.docker, "container_running", lambda name, runner=None: False)
    monkeypatch.setattr(up_module, "start_runtime", lambda *_a, **_k: None)
    monkeypatch.setattr(up_module, "start_proxy", lambda *_a, **_k: None)
    monkeypatch.setattr(up_module, "start_orchestrator", lambda *_a, **_k: None)
    monkeypatch.setattr(
        up_module, "oob_status", lambda *_a, **_k: {"state": "running", "clients": [{"x": 1}]}
    )
    monkeypatch.setattr(up_module, "start_oob", lambda *_a, **_k: None)

    up_module.run_up(up_module.UpOptions(install_root=install), runner=lambda *_a, **_k: None)
    capsys.readouterr()
    first = read_workspace(install)

    (source / "README.md").write_text("advanced\n")
    up_module.run_up(up_module.UpOptions(install_root=install), runner=lambda *_a, **_k: None)
    capsys.readouterr()

    latest = read_workspace(install)
    assert latest is not None and first is not None
    assert latest["application"] != first["application"]
    assert not (install / "agent").exists()
    assert not (install / "orchestrator").exists()


def test_doctor_reports_install_staleness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lagging working root is why a documented verb "does not exist" — doctor
    is where that question gets asked, so the drift has to show up there."""
    from vigil_cli import status as status_module
    from vigil_cli.docker import DockerResult

    source = tmp_path / "source"
    (source / "agent").mkdir(parents=True)
    (source / "orchestrator").mkdir(parents=True)
    installed_sha = _init_git_repo(source, {"README.md": "seed\n"})
    install = tmp_path / "install"
    install.mkdir()
    status_module.write_install_meta(install, source)
    current_sha = _git_commit(source, "README.md", "advanced\n")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(source))
    monkeypatch.setattr(status_module.shutil, "which", lambda _command: None)
    monkeypatch.setattr(status_module, "runtime_status", lambda **_k: "stopped")

    checks = status_module.collect_doctor_checks(
        install, runner=lambda *_a, **_k: DockerResult(0, "", "")
    )

    check = next(c for c in checks if c.name == "install-staleness")
    assert check.status == "STALE"
    assert installed_sha[:12] in check.detail
    assert current_sha[:12] in check.detail
    assert "vigil install" in check.detail


def test_assess_passthrough_stays_silent_even_when_the_install_is_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """One warning per engagement, not one per `vigil assess` call.

    The passthrough executes the selected application's assess.py. Startup owns
    restart diagnostics, so repeated helper calls preserve clean output."""
    from vigil_cli import main as main_module
    from vigil_cli.status import write_install_meta

    source = tmp_path / "source"
    (source / "agent" / "scripts").mkdir(parents=True)
    (source / "orchestrator").mkdir(parents=True)
    _init_git_repo(source, {"README.md": "seed\n"})
    install = tmp_path / "install"
    (install / "agent" / "scripts").mkdir(parents=True)
    assess = source / "agent" / "scripts" / "assess.py"
    assess.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    write_install_meta(install, source)
    _git_commit(source, "README.md", "advanced\n")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(source))

    execs: list[list[str]] = []
    monkeypatch.setattr(main_module.os, "execvpe", lambda path, argv, env: execs.append(argv))

    main_module._exec_assess_passthrough(["--root", str(install), "assess", "list-skills"], 2)

    captured = capsys.readouterr()
    assert captured.out == ""  # stdout stays clean for JSON consumers
    assert captured.err == ""
    assert execs == [[str(assess), "list-skills"]]  # never blocks the exec


def test_assess_passthrough_is_silent_when_install_is_current(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module
    from vigil_cli.status import write_install_meta

    source = tmp_path / "source"
    (source / "agent" / "scripts").mkdir(parents=True)
    (source / "orchestrator").mkdir(parents=True)
    _init_git_repo(source, {"README.md": "seed\n"})
    (source / "agent" / "scripts" / "assess.py").write_text("#!\n", encoding="utf-8")
    install = tmp_path / "install"
    shutil.copytree(source / "agent", install / "agent")
    shutil.copytree(source / "orchestrator", install / "orchestrator")
    shutil.copy2(source / "README.md", install / "README.md")
    write_install_meta(install, source)
    monkeypatch.setenv("VIGIL_SOURCE_DIR", str(source))
    monkeypatch.setattr(main_module.os, "execvpe", lambda *_a: None)

    main_module._exec_assess_passthrough(["--root", str(install), "assess", "list-skills"], 2)

    assert capsys.readouterr().err == ""


def test_runtime_start_uses_expected_docker_mounts(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)
    (install_root / ".runtime-data").mkdir()
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
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import RuntimeOptions, start_runtime

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
    assert "vigil runtime build" in message
    assert "vigil orchestrator status" in message


def test_runtime_start_grants_sys_ptrace_capability(tmp_path: Path) -> None:
    """B2: runtime diagnostic tooling needs CAP_SYS_PTRACE; the docker-run argv
    must request it explicitly so ptrace operations do not fail with EPERM."""
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)
    (install_root / ".runtime-data").mkdir()
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
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)
    (install_root / ".runtime-data").mkdir()
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
    from vigil_cli.docker import DockerResult
    from vigil_cli.mitmproxy import MitmproxyOptions, start_proxy

    install_root = tmp_path / "install"
    engagements_root = install_root / "agent" / "engagements"
    engagement = engagements_root / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    (engagement / ".orchestrator.env").write_text(
        "ORCHESTRATOR_BASE_URL=http://127.0.0.1:18000\n",
        encoding="utf-8",
    )
    _make_mitmproxy_inputs(install_root)
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
        verify_running=False,
    )

    build_command = next(command for command in commands if command[:3] == ["docker", "build", "-t"])
    run_command = next(command for command in commands if command[:3] == ["docker", "run", "-d"])
    build_context = Path(build_command[-1])
    build_dockerfile = Path(build_command[build_command.index("-f") + 1])
    assert build_context != install_root
    assert build_context != install_root / "agent"
    assert build_context.name.startswith("vigil-proxy-build-")
    assert build_dockerfile == build_context / "Dockerfile"
    assert "--add-host=host.docker.internal:host-gateway" in run_command
    assert "127.0.0.1:9090:8080" in run_command
    # New contract: bind-mount the whole engagements tree at /engagements.
    assert f"{engagements_root}:/engagements" in run_command
    assert "ORCHESTRATOR_BASE_URL=http://host.docker.internal:18000" in run_command
    # The --set switches the addon to multi-engagement mode.
    assert "engagements_root=/engagements" in run_command


def test_mitmproxy_build_stages_canonical_scope_parser_without_install_state(
    tmp_path: Path,
) -> None:
    """The proxy image imports the shared scope parser without sending the
    install root (and its engagement secrets) to Docker as build context.

    Regression: ``scope.py`` fell back to ``parents[4]`` inside the image when
    ``vigil_cli`` was absent.  Its image path is only three parents deep, so the
    addon crashed before mitmproxy could open its port.
    """
    from vigil_cli import mitmproxy as mitmproxy_module
    from vigil_cli import scope_entries as canonical_scope_entries
    from vigil_cli.docker import DockerResult

    install_root = tmp_path / "install"
    _make_mitmproxy_inputs(install_root)
    assess = install_root / "agent" / "scripts" / "assess"
    (assess / "lib").mkdir(parents=True)
    shutil.copy2(
        repo_root / "agent" / "scripts" / "assess" / "lib" / "scope.py",
        assess / "lib" / "scope.py",
    )
    shutil.copy2(
        repo_root / "agent" / "scripts" / "assess" / "lib" / "tracks.py",
        assess / "lib" / "tracks.py",
    )
    (assess / "__init__.py").write_text("", encoding="utf-8")
    (assess / "lib" / "__init__.py").write_text("", encoding="utf-8")

    # These are runtime state, not image sources. Merely exposing them as build
    # context sends their bytes to the Docker daemon even when COPY omits them.
    (install_root / ".env").write_text("TOP_LEVEL_SECRET=present\n", encoding="utf-8")
    engagement = install_root / "agent" / "engagements" / "customer"
    engagement.mkdir(parents=True)
    (engagement / ".env").write_text("ENGAGEMENT_SECRET=present\n", encoding="utf-8")
    (engagement / "scope.json").write_text("{}\n", encoding="utf-8")

    observed_context: Path | None = None

    def runner(argv: list[str], **_: object) -> DockerResult:
        nonlocal observed_context
        assert argv[:3] == ["docker", "build", "--no-cache"]
        context = Path(argv[-1])
        observed_context = context
        assert context != install_root
        assert context != install_root / "agent"
        assert (context / "Dockerfile").is_file()
        assert (context / "scripts" / "proxy_addon.py").is_file()
        assert (context / "scripts" / "assess" / "lib" / "scope.py").is_file()
        assert (context / "scripts" / "assess" / "lib" / "tracks.py").is_file()

        staged_scope_entries = context / "vigil_cli" / "scope_entries.py"
        assert staged_scope_entries.read_bytes() == Path(
            canonical_scope_entries.__file__
        ).read_bytes()
        assert not (context / ".env").exists()
        assert not (context / "engagements").exists()
        assert not (context / "agent" / "engagements").exists()

        # Recreate the Dockerfile's /opt layout and import from an unrelated cwd
        # so repository/install-root sys.path entries cannot mask image drift.
        image_opt = tmp_path / "image-opt"
        shutil.copytree(context / "scripts" / "assess", image_opt / "assess")
        shutil.copytree(context / "vigil_cli", image_opt / "vigil_cli")
        isolated_cwd = tmp_path / "isolated"
        isolated_cwd.mkdir()
        env = os.environ.copy()
        env["PYTHONPATH"] = str(image_opt)
        imported = subprocess.run(
            [
                sys.executable,
                "-S",
                "-c",
                "from assess.lib.scope import classify_scope_entry; "
                "assert classify_scope_entry('Example.COM')['host'] == 'example.com'",
            ],
            cwd=isolated_cwd,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert imported.returncode == 0, imported.stderr
        return DockerResult(0, "", "")

    mitmproxy_module.build_image(
        install_root,
        force=True,
        runner=runner,
        daemon_runner=lambda _argv, **_kwargs: DockerResult(0, "", ""),
    )

    assert observed_context is not None
    assert not observed_context.exists()


def test_mitmproxy_start_rebuilds_existing_stale_image(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.mitmproxy import MitmproxyOptions, start_proxy

    install_root = tmp_path / "install"
    engagements_root = install_root / "agent" / "engagements"
    engagements_root.mkdir(parents=True)
    _make_mitmproxy_inputs(install_root)
    commands: list[list[str]] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:4] == ["docker", "image", "inspect", "-f"]:
            return DockerResult(0, "2001-01-01T00:00:00Z\n", "")
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:existing\n", "")
        return DockerResult(0, "", "")

    start_proxy(
        MitmproxyOptions(
            install_root=install_root,
            engagements_root=engagements_root,
        ),
        runner=runner,
        verify_port=False,
        verify_running=False,
    )

    assert any(command[:3] == ["docker", "build", "-t"] for command in commands)


def test_mitmproxy_start_uses_install_orchestrator_url_not_engagement_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import paths as paths_module
    from vigil_cli.docker import DockerResult
    from vigil_cli.mitmproxy import MitmproxyOptions, start_proxy

    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.setattr(paths_module, "get_config_value", lambda key: None)
    install_root = tmp_path / "install"
    engagements_root = install_root / "agent" / "engagements"
    # Freshness is content-based: an unstamped image reads as outdated, so the
    # proxy build inputs must exist for start_proxy to reach the run stage.
    _make_mitmproxy_inputs(install_root)
    (install_root / ".orchestrator.env").parent.mkdir(parents=True, exist_ok=True)
    (install_root / ".orchestrator.env").write_text(
        "ORCHESTRATOR_BASE_URL=http://127.0.0.1:19001\n",
        encoding="utf-8",
    )
    for key, port in (("eng-a", 19002), ("eng-b", 19003)):
        engagement = engagements_root / key
        engagement.mkdir(parents=True)
        (engagement / "scope.json").write_text("{}", encoding="utf-8")
        (engagement / ".orchestrator.env").write_text(
            f"ORCHESTRATOR_BASE_URL=http://127.0.0.1:{port}\n",
            encoding="utf-8",
        )
    commands: list[list[str]] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:4] == ["docker", "image", "inspect", "-f"]:
            return DockerResult(0, "2030-01-01T00:00:00Z\n", "")
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "-q"]:
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    start_proxy(
        MitmproxyOptions(install_root=install_root, engagements_root=engagements_root),
        runner=runner,
        verify_port=False,
        verify_running=False,
    )

    run_command = next(command for command in commands if command[:3] == ["docker", "run", "-d"])
    assert "ORCHESTRATOR_BASE_URL=http://host.docker.internal:19001" in run_command
    assert not any("19002" in item or "19003" in item for item in run_command)


def test_mitmproxy_start_polls_port_until_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import mitmproxy as mitmproxy_module
    from vigil_cli.docker import DockerResult

    install_root = tmp_path / "install"
    engagements_root = install_root / "agent" / "engagements"
    # Freshness is content-based: an unstamped image reads as outdated, so the
    # proxy build inputs must exist for start_proxy to reach the run stage.
    _make_mitmproxy_inputs(install_root)
    engagement = engagements_root / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    (engagement / ".orchestrator.env").write_text(
        "ORCHESTRATOR_BASE_URL=http://127.0.0.1:18000\n",
        encoding="utf-8",
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:4] == ["docker", "image", "inspect", "-f"]:
            return DockerResult(0, "2030-01-01T00:00:00Z\n", "")
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
        verify_running=False,
    )

    assert attempts == [("127.0.0.1", 9090)] * 3


def test_mitmproxy_status_uses_published_host_port(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import mitmproxy as mitmproxy_module
    from vigil_cli.docker import DockerResult

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    engagements_root = install_root / "agent" / "engagements"
    engagements_root.mkdir(parents=True)
    inspect_doc = {
        "Id": "abcdef1234567890",
        "State": {
            "Running": True,
            "ExitCode": 0,
            "StartedAt": "2026-05-21T14:00:00Z",
            "FinishedAt": "0001-01-01T00:00:00Z",
        },
        "NetworkSettings": {
            "Ports": {
                "8080/tcp": [
                    {
                        "HostIp": "127.0.0.1",
                        "HostPort": "9090",
                    }
                ]
            }
        },
    }

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "inspect", "--format"]:
            return DockerResult(0, json.dumps(inspect_doc), "")
        return DockerResult(0, "", "")

    attempts: list[tuple[str, int]] = []

    def fake_port_open(host: str, port: int) -> bool:
        attempts.append((host, port))
        return True

    monkeypatch.setattr(mitmproxy_module, "_port_open", fake_port_open)
    monkeypatch.setattr(mitmproxy_module.docker, "image_exists", lambda *_, **__: True)
    monkeypatch.setattr(mitmproxy_module.docker, "volume_exists", lambda *_, **__: True)

    payload = mitmproxy_module.proxy_status_payload(
        install_root,
        engagements_root,
        port=8080,
        runner=runner,
    )

    assert payload["port"] == 9090
    assert payload["port_reachable"] is True
    assert attempts == [("127.0.0.1", 9090)]


def test_mitmproxy_start_uses_install_engagements_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`vigil mitmproxy start` now mounts the whole engagements tree — no
    per-engagement context required, the addon routes each captured flow to
    the matching engagement.
    """
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_start_proxy(options: object, **_: object) -> None:
        captured["engagements_root"] = options.engagements_root  # type: ignore[attr-defined]

    monkeypatch.setattr(main_module, "start_proxy", fake_start_proxy)

    main_module.main(["--root", str(install_root), "mitmproxy", "start"])

    assert captured["engagements_root"] == install_root / "agent" / "engagements"


def test_orchestrator_foreground_execs_from_install_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import orchestrator as orchestrator_module

    install_root = tmp_path / "install"
    frontend_dist = install_root / "orchestrator" / "frontend" / "dist"
    frontend_dist.mkdir(parents=True)
    (frontend_dist / "index.html").write_text("ok", encoding="utf-8")
    (install_root / "agent").mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(install_root))
    # Freshness is a content stamp, not an mtime: an unstamped `dist/` cannot be
    # proven current and would trigger a real `npm ci` inside the test.
    restart_manifest.record_frontend_build(install_root)
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
    monkeypatch.setattr(orchestrator_module, "_check_port_available", lambda *_, **__: None)
    monkeypatch.setattr(orchestrator_module, "_sync_backend_environment", lambda *_, **__: None)

    with pytest.raises(RuntimeError, match="exec blocked"):
        orchestrator_module.start_orchestrator(
            orchestrator_module.OrchestratorOptions(install_root=install_root, foreground=True)
        )

    assert captured["file"] == "uv"
    assert captured["cwd"] == install_root.resolve()
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[:6] == ["uv", "run", "--frozen", "--no-sync", "--directory", "orchestrator/backend"]
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["VIGIL_INSTALL_DIR"] == str(install_root.resolve())


def test_orchestrator_start_builds_frontend_then_errors_when_backend_already_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import orchestrator as orchestrator_module

    install_root = tmp_path / "install"
    frontend_dir = install_root / "orchestrator" / "frontend"
    (frontend_dir / "src").mkdir(parents=True)
    (frontend_dir / "package.json").write_text("{}", encoding="utf-8")
    (frontend_dir / "src" / "main.tsx").write_text("console.log('ok')\n", encoding="utf-8")
    (install_root / "agent").mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(install_root))
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
    assert "vigil orchestrator restart" in message
    assert "vigil logs orchestrator" in message


def test_orchestrator_health_wait_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import orchestrator as orchestrator_module

    attempts: list[str] = []

    def fail_urlopen(url: str, timeout: int):
        attempts.append(url)
        raise OSError("down")

    monkeypatch.setattr(orchestrator_module.urllib.request, "urlopen", fail_urlopen)
    ticks = iter([0.0, *map(float, range(1, 31))])
    monkeypatch.setattr(orchestrator_module.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(orchestrator_module.time, "sleep", lambda _: None)

    assert orchestrator_module._wait_for_health("127.0.0.1", 18000) is False
    assert attempts == ["http://127.0.0.1:18000/healthz"] * 30


def test_orchestrator_health_wait_allows_cold_uv_environment_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vigil_cli import orchestrator as orchestrator_module

    attempts = 0
    now = 0.0

    class HealthyResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            return None

    def delayed_urlopen(_url: str, timeout: int):
        nonlocal attempts
        attempts += 1
        if attempts <= 31:
            raise OSError("backend environment is still building")
        return HealthyResponse()

    def monotonic() -> float:
        nonlocal now
        now += 0.1
        return now

    monkeypatch.setattr(orchestrator_module.urllib.request, "urlopen", delayed_urlopen)
    monkeypatch.setattr(orchestrator_module.time, "monotonic", monotonic)
    monkeypatch.setattr(orchestrator_module.time, "sleep", lambda _: None)

    assert orchestrator_module._wait_for_health("127.0.0.1", 18000) is True
    assert attempts == 32


def test_orchestrator_start_terminates_child_when_health_times_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import orchestrator as orchestrator_module

    install_root = tmp_path / "install"
    frontend_dist = install_root / "orchestrator" / "frontend" / "dist"
    frontend_dist.mkdir(parents=True)
    (frontend_dist / "index.html").write_text("ok", encoding="utf-8")
    (install_root / "agent").mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(install_root))
    # Freshness is a content stamp, not an mtime: an unstamped `dist/` cannot be
    # proven current and would trigger a real `npm ci` inside the test.
    restart_manifest.record_frontend_build(install_root)
    pid_file = install_root / "state" / "runtime" / "pids" / "orchestrator.pid"

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
    monkeypatch.setattr(orchestrator_module, "_check_port_available", lambda *_, **__: None)
    monkeypatch.setattr(orchestrator_module, "_wait_for_health", lambda *_, **__: False)
    monkeypatch.setattr(orchestrator_module, "_sync_backend_environment", lambda *_, **__: None)

    with pytest.raises(SystemExit, match="did not become healthy"):
        orchestrator_module.start_orchestrator(orchestrator_module.OrchestratorOptions(install_root=install_root))

    assert signals_sent == [(4321, signal.SIGTERM)]
    assert fake_process.terminated is False
    assert fake_process.killed is False
    assert not pid_file.exists()


def test_orchestrator_start_terminates_child_when_readiness_times_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import orchestrator as orchestrator_module

    install_root = tmp_path / "install"
    frontend_dist = install_root / "orchestrator" / "frontend" / "dist"
    frontend_dist.mkdir(parents=True)
    (frontend_dist / "index.html").write_text("ok", encoding="utf-8")
    (install_root / "agent").mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(install_root))
    # Freshness is a content stamp, not an mtime: an unstamped `dist/` cannot be
    # proven current and would trigger a real `npm ci` inside the test.
    restart_manifest.record_frontend_build(install_root)
    pid_file = install_root / "state" / "runtime" / "pids" / "orchestrator.pid"

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
    monkeypatch.setattr(orchestrator_module, "_check_port_available", lambda *_, **__: None)
    monkeypatch.setattr(orchestrator_module, "_wait_for_health", lambda *_, **__: True)
    monkeypatch.setattr(orchestrator_module, "_wait_for_readiness", lambda *_, **__: False)
    monkeypatch.setattr(orchestrator_module, "_sync_backend_environment", lambda *_, **__: None)

    with pytest.raises(SystemExit, match="did not become ready"):
        orchestrator_module.start_orchestrator(orchestrator_module.OrchestratorOptions(install_root=install_root))

    assert signals_sent == [(4322, signal.SIGTERM)]
    assert not pid_file.exists()


def test_orchestrator_start_refuses_when_port_already_in_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import orchestrator as orchestrator_module

    install_root = tmp_path / "install"
    frontend_dist = install_root / "orchestrator" / "frontend" / "dist"
    frontend_dist.mkdir(parents=True)
    (frontend_dist / "index.html").write_text("ok", encoding="utf-8")
    (install_root / "agent").mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(install_root))
    # Freshness is a content stamp, not an mtime: an unstamped `dist/` cannot be
    # proven current and would trigger a real `npm ci` inside the test.
    restart_manifest.record_frontend_build(install_root)

    popen_called = False

    def fake_popen(*_: object, **__: object) -> object:
        nonlocal popen_called
        popen_called = True
        raise AssertionError("Popen must not be called when port is already in use")

    monkeypatch.setattr(orchestrator_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(orchestrator_module, "_port_in_use", lambda *_, **__: True)
    monkeypatch.setattr(orchestrator_module, "_port_listener_pid", lambda *_, **__: 99999)

    with pytest.raises(SystemExit) as excinfo:
        orchestrator_module.start_orchestrator(orchestrator_module.OrchestratorOptions(install_root=install_root))

    message = str(excinfo.value)
    assert "127.0.0.1:18000 is already in use" in message
    assert "PID 99999" in message
    assert "vigil orchestrator stop" in message
    assert popen_called is False


def test_stop_orchestrator_escalates_to_sigkill_when_sigterm_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import orchestrator as orchestrator_module

    install_root = tmp_path / "install"
    pid_file = install_root / ".runtime-data" / "pids" / "orchestrator.pid"
    pid_file.parent.mkdir(parents=True)
    pid_file.write_text("4242\n", encoding="utf-8")

    # Simulate a process that ignores SIGTERM but dies on SIGKILL.
    alive_flag = {"alive": True}
    signals_sent: list[tuple[int, signal.Signals]] = []

    def fake_kill(pid: int, sig: signal.Signals) -> None:
        if sig == 0:
            # liveness probe
            if not alive_flag["alive"]:
                raise OSError("no such process")
            return
        signals_sent.append((pid, sig))
        if sig == signal.SIGKILL:
            alive_flag["alive"] = False

    def fake_killpg(pid: int, sig: signal.Signals) -> None:
        fake_kill(pid, sig)

    monkeypatch.setattr(orchestrator_module.os, "kill", fake_kill)
    monkeypatch.setattr(orchestrator_module.os, "killpg", fake_killpg)
    monkeypatch.setattr(orchestrator_module.time, "sleep", lambda _: None)
    monkeypatch.setattr(orchestrator_module, "_wait_for_port_release", lambda *_, **__: True)

    orchestrator_module.stop_orchestrator(install_root)

    assert (4242, signal.SIGTERM) in signals_sent
    assert (4242, signal.SIGKILL) in signals_sent
    assert not pid_file.exists()


def test_stop_orchestrator_warns_when_port_stays_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import orchestrator as orchestrator_module

    install_root = tmp_path / "install"
    pid_file = install_root / ".runtime-data" / "pids" / "orchestrator.pid"
    pid_file.parent.mkdir(parents=True)
    pid_file.write_text("5050\n", encoding="utf-8")

    # Process dies immediately on SIGTERM, but the port stays held by an
    # unrelated process. Stop must not block forever; it should warn and
    # leave the diagnosis to start.
    alive_flag = {"alive": True}

    def fake_kill(pid: int, sig: signal.Signals) -> None:
        if sig == 0:
            if not alive_flag["alive"]:
                raise OSError("no such process")
            return
        alive_flag["alive"] = False

    monkeypatch.setattr(orchestrator_module.os, "kill", fake_kill)
    monkeypatch.setattr(orchestrator_module.os, "killpg", fake_kill)
    monkeypatch.setattr(orchestrator_module.time, "sleep", lambda _: None)
    monkeypatch.setattr(orchestrator_module, "_wait_for_port_release", lambda *_, **__: False)
    monkeypatch.setattr(orchestrator_module, "_port_listener_pid", lambda *_, **__: 7777)

    orchestrator_module.stop_orchestrator(install_root)

    out = capsys.readouterr().out
    assert "127.0.0.1:18000 still held (PID 7777)" in out
    assert not pid_file.exists()


def test_orchestrator_status_payload_reports_stopped_when_pid_dead(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import orchestrator as orchestrator_module

    install_root = tmp_path / "install"
    pid_file = install_root / ".runtime-data" / "pids" / "orchestrator.pid"
    pid_file.parent.mkdir(parents=True)
    pid_file.write_text("99999999\n", encoding="utf-8")

    monkeypatch.setattr(orchestrator_module, "_pid_alive", lambda _: False)
    monkeypatch.setattr(orchestrator_module, "_port_in_use", lambda *_, **__: False)

    payload = orchestrator_module.orchestrator_status_payload(install_root)
    assert payload["state"] == "stopped"
    assert payload["pid"] is None
    assert payload["url"] == "http://127.0.0.1:18000"
    assert payload["port_in_use"] is False


def test_orchestrator_status_payload_reports_running_with_live_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import orchestrator as orchestrator_module

    install_root = tmp_path / "install"
    pid_file = install_root / ".runtime-data" / "pids" / "orchestrator.pid"
    pid_file.parent.mkdir(parents=True)
    pid_file.write_text("8235\n", encoding="utf-8")

    monkeypatch.setattr(orchestrator_module, "_pid_alive", lambda _: True)
    monkeypatch.setattr(orchestrator_module, "_port_in_use", lambda *_, **__: True)

    payload = orchestrator_module.orchestrator_status_payload(install_root)
    assert payload["state"] == "running"
    assert payload["pid"] == 8235
    assert payload["port_in_use"] is True


def test_assess_kali_help_lists_every_typed_verb(capsys: pytest.CaptureFixture[str]) -> None:
    """`vigil assess kali --help` must enumerate the 13 typed verbs plus exec and job."""
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
    from vigil_cli import main as main_module

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
    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(repo_root))
    captured: dict[str, object] = {}

    def fake_execvpe(path: str, argv: list[str], env: dict[str, str]) -> None:
        captured["path"] = path
        captured["argv"] = argv
        captured["env"] = env
        raise SystemExit(0)

    monkeypatch.setattr(
        main_module,
        "_oob_options",
        lambda root: SimpleNamespace(oob_domain="configured.oob.test"),
    )
    monkeypatch.setattr(main_module.os, "execvpe", fake_execvpe)

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(["--root", str(install_root), "assess", "--help"])

    assert excinfo.value.code == 0
    assert captured["path"] == str(repo_root / "agent" / "scripts" / "assess.py")
    assert captured["argv"] == [str(repo_root / "agent" / "scripts" / "assess.py"), "--help"]
    assert captured["env"]["VIGIL_INSTALL_DIR"] == str(install_root)
    assert captured["env"]["VIGIL_APPLICATION_DIR"] == str(repo_root)
    assert captured["env"]["VIGIL_OOB_DOMAIN"] == "configured.oob.test"


def test_runtime_start_applies_resource_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)
    (install_root / ".runtime-data").mkdir()
    monkeypatch.setenv("VIGIL_RUNTIME_MEMORY_GB", "16")
    monkeypatch.setenv("VIGIL_RUNTIME_CPUS", "8")
    monkeypatch.setenv("VIGIL_RUNTIME_PIDS_LIMIT", "1024")
    monkeypatch.setenv("VIGIL_RUNTIME_SHM_SIZE", "2g")
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
    # nofile/nproc are dockerd-side (default-ulimits in daemon.json); see
    # docs/operations.md "File-descriptor and process limits". `vigil runtime start` probes them via
    # _check_runtime_ulimits and warns to stderr when low.


def test_runtime_start_rejects_already_running_container_with_clear_message(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)
    (install_root / ".runtime-data").mkdir()

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(
                0,
                f"{install_root / '.runtime-data'} -> /data\n{install_root / 'agent' / 'engagements'} -> /engagements\n",
                "",
            )
        if argv[:2] == ["docker", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "exec", "vigil"] and argv[-1] == "ulimit -n; ulimit -u":
            return DockerResult(0, "1048576\nunlimited\n", "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit) as excinfo:
        start_runtime(RuntimeOptions(install_root=install_root), runner=runner, validate_tools=False)

    message = str(excinfo.value)
    assert "Runtime container is already running" in message
    assert "container: vigil" in message
    assert "vigil runtime status" in message
    assert "vigil runtime restart" in message


def test_check_runtime_ulimits_warns_when_below_threshold(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)
    (install_root / ".runtime-data").mkdir()

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, f"{install_root / '.runtime-data'} -> /data\n{install_root / 'agent' / 'engagements'} -> /engagements\n", "")
        if argv[:2] == ["docker", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "exec", "vigil"] and argv[-1] == "ulimit -n; ulimit -u":
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
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)
    (install_root / ".runtime-data").mkdir()

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, f"{install_root / '.runtime-data'} -> /data\n{install_root / 'agent' / 'engagements'} -> /engagements\n", "")
        if argv[:2] == ["docker", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "exec", "vigil"] and argv[-1] == "ulimit -n; ulimit -u":
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
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)
    (install_root / ".runtime-data").mkdir()

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, f"{install_root / '.runtime-data'} -> /data\n{install_root / 'agent' / 'engagements'} -> /engagements\n", "")
        if argv[:2] == ["docker", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "exec", "vigil"] and argv[-1] == "ulimit -n; ulimit -u":
            return DockerResult(1, "", "exec failed")
        return DockerResult(0, "", "")

    start_runtime(
        RuntimeOptions(install_root=install_root, recreate=False),
        runner=runner,
        validate_tools=False,
        allow_existing=True,
    )
    assert "WARN" not in capsys.readouterr().err


def test_vigil_runtime_resources_renders_configured_and_live_state(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import vigil_runtime_resources

    monkeypatch.setenv("VIGIL_RUNTIME_MEMORY_GB", "8")
    monkeypatch.setenv("VIGIL_RUNTIME_CPUS", "4")
    monkeypatch.setenv("VIGIL_RUNTIME_PIDS_LIMIT", "512")
    monkeypatch.setenv("VIGIL_RUNTIME_SHM_SIZE", "1g")

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if argv[:3] == ["docker", "exec", "vigil"]:
            return DockerResult(
                0,
                "/sys/fs/cgroup/memory.max=8589934592\n"
                "/sys/fs/cgroup/cpu.max=400000 100000\n"
                "/sys/fs/cgroup/pids.max=512\n",
                "",
            )
        return DockerResult(0, "", "")

    vigil_runtime_resources(runner=runner)
    output = capsys.readouterr().out
    assert "configured\tmemory=8g" in output
    assert "cpus=4" in output
    assert "memory.max=8589934592" in output
    assert "cpu.max=400000 100000" in output
    assert "pids.max=512" in output


def test_vigil_runtime_resources_prints_the_proxy_url_with_its_credentials(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The egress row shows the configured proxy URL exactly as configured.

    The operator set that URL on their own machine; a `***@host` rewrite only
    hid which credential the runtime was about to egress through (ADR 0019)."""
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import vigil_runtime_resources

    monkeypatch.setenv("VIGIL_RUNTIME_EGRESS_PROXY", "http://operator:hunter2@proxy.test:8080")

    def runner(argv: list[str], **_: object) -> DockerResult:
        return DockerResult(0, "", "")

    vigil_runtime_resources(runner=runner, json_output=True)
    egress = json.loads(capsys.readouterr().out)["egress"]
    assert egress["proxy"] == "http://operator:hunter2@proxy.test:8080"


def test_vigil_runtime_resources_handles_stopped_container(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import vigil_runtime_resources

    monkeypatch.delenv("VIGIL_RUNTIME_MEMORY_GB", raising=False)
    monkeypatch.delenv("VIGIL_RUNTIME_CPUS", raising=False)
    monkeypatch.delenv("VIGIL_RUNTIME_PIDS_LIMIT", raising=False)
    monkeypatch.delenv("VIGIL_RUNTIME_SHM_SIZE", raising=False)

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    vigil_runtime_resources(runner=runner)
    output = capsys.readouterr().out
    assert "running=False" in output
    assert "live\tcontainer not running" in output


def test_runtime_shell_exec_passes_symbol_heavy_command_as_single_shell_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import main as main_module

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

    assert calls == [["docker", "exec", "vigil", "sh", "-lc", command]]


def test_runtime_shell_exec_propagates_container_command_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import main as main_module

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 37, "", "boom")

    monkeypatch.setattr(main_module.subprocess, "run", fake_run)

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(["runtime", "shell-exec", "false"])

    assert excinfo.value.code == 37


def test_runtime_shell_exec_strips_separator_and_quotes_multiple_parts(monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import main as main_module

    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(main_module.subprocess, "run", fake_run)

    main_module.main(["runtime", "shell-exec", "--", "printf", "%s", "a b"])

    assert calls == [["docker", "exec", "vigil", "sh", "-lc", "printf %s 'a b'"]]


def test_engagement_create_infers_localhost_url_as_web(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import main as main_module

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)

    main_module.main(["--root", str(install_root), "engagement", "create", "http://localhost:8080", "--no-prompt"])

    created = next((install_root / "agent" / "engagements").iterdir())
    scope = json.loads((created / "scope.json").read_text(encoding="utf-8"))
    manifest = json.loads((created / "engagement.json").read_text(encoding="utf-8"))
    assert scope["engagement_type"] == "offensive"
    assert scope["hostname"] == "localhost"
    assert manifest["target"] == "http://localhost:8080"


def test_engagement_select_uses_fzf_when_requested(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import engagements

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
    monkeypatch.setattr(engagements.sys, "stdin", _TTYStdin())

    assert engagements.resolve_engagement_path(tmp_path / "install", select=True) == newer.resolve()


def test_runtime_start_rejects_running_container_with_wrong_mount(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if argv[:4] == ["docker", "inspect", "-f", "{{.Image}}"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:4] == ["docker", "image", "inspect", "-f"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, "/wrong/data -> /data\n/wrong/engagements -> /engagements\n", "")
        if argv[:3] == ["docker", "exec", "vigil"]:
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit, match="mount drift"):
        start_runtime(RuntimeOptions(install_root=install_root), runner=runner)


def test_doctor_reports_missing_binary_without_crashing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from vigil_cli import main as main_module
    from vigil_cli import status as status_module
    from vigil_cli.docker import DockerResult

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

    # `tmp_path` has no `agent/` tree, so doctor gates on that required row and
    # exits non-zero. What this test pins is the row still being PRINTED rather
    # than the command dying on an absent binary.
    with pytest.raises(SystemExit):
        main_module.main(["--root", str(tmp_path), "doctor"])

    assert "MISSING\tuv" in capsys.readouterr().out


def test_doctor_reports_missing_ripgrep_and_says_what_degrades(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`rg` is the code track's primary search tool and nothing checked for it.

    `agent/shared-constraints-code.md` ranks ripgrep second only to the ctags
    index and uses the ripgrep-only `--type` flag, but Claude and OpenCode ship
    their own Grep tool while the Codex and Goose hunters have shell only. On a
    host with no ripgrep those hunters get exit 127 per search, and the failure
    presents as "no results" rather than "tool missing" — the shape that makes a
    coverage tool report clean coverage of code it never read. A bare MISSING
    row would not say that, so the row carries the degradation.
    """
    from vigil_cli import main as main_module
    from vigil_cli import status as status_module
    from vigil_cli.docker import DockerResult

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    def fake_which(command: str) -> str | None:
        return None if command == "rg" else f"/usr/bin/{command}"

    def fake_docker(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "", "")
        return DockerResult(0, "ok", "")

    monkeypatch.setattr(status_module.shutil, "which", fake_which)
    monkeypatch.setattr(status_module.subprocess, "run", fake_run)
    monkeypatch.setattr(main_module, "docker_run_command", fake_docker)

    # `tmp_path` has no `agent/` tree, so doctor exits non-zero on that required
    # row; what this pins is the ripgrep row and its detail being printed.
    with pytest.raises(SystemExit):
        main_module.main(["--root", str(tmp_path), "doctor"])

    output = capsys.readouterr().out
    assert "MISSING\trg\t" in output
    ripgrep_row = next(line for line in output.splitlines() if line.startswith("MISSING\trg\t"))
    assert "code" in ripgrep_row
    assert "codex" in ripgrep_row.lower() and "goose" in ripgrep_row.lower()


def test_doctor_does_not_require_ripgrep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Advisory, like `fzf`: a web engagement never reaches a code search."""
    from vigil_cli import status as status_module
    from vigil_cli.docker import DockerResult

    monkeypatch.setattr(
        status_module.shutil,
        "which",
        lambda command: None if command == "rg" else f"/usr/bin/{command}",
    )
    monkeypatch.setattr(
        status_module.subprocess,
        "run",
        lambda argv, **_: subprocess.CompletedProcess(argv, 0, "ok", ""),
    )

    checks = status_module.collect_doctor_checks(
        tmp_path, runner=lambda argv, **_: DockerResult(0, "ok", "")
    )

    ripgrep = next(check for check in checks if check.name == "rg")
    assert ripgrep.status == "MISSING"
    assert ripgrep.required is False


def test_doctor_skips_docker_checks_when_docker_cli_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module
    from vigil_cli import status as status_module
    from vigil_cli.docker import DockerResult

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    def fake_which(command: str) -> str | None:
        return None if command == "docker" else f"/usr/bin/{command}"

    def fail_docker(argv: list[str], **_: object) -> DockerResult:
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(status_module.shutil, "which", fake_which)
    monkeypatch.setattr(status_module.subprocess, "run", fake_run)
    monkeypatch.setattr(main_module, "docker_run_command", fail_docker)

    # A host with no Docker CLI cannot run Vigil, so this now gates the exit —
    # the daemon probe is skipped in that branch, so a MISSING `docker` row is
    # the only signal there is.
    with pytest.raises(SystemExit) as excinfo:
        main_module.main(["--root", str(tmp_path), "doctor"])

    assert excinfo.value.code != 0
    output = capsys.readouterr().out
    assert "MISSING\tdocker" in output
    assert "SKIPPED\tdocker-daemon" in output


def test_status_json_reports_runtime_mount_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from vigil_cli import main as main_module
    from vigil_cli.docker import DockerResult

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
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
    from vigil_cli import main as main_module

    config_path = tmp_path / "config.json"
    monkeypatch.setenv("VIGIL_CONFIG", str(config_path))

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
    from vigil_cli import main as main_module
    from vigil_cli.docker import DockerResult

    config_path = tmp_path / "config.json"
    monkeypatch.setenv("VIGIL_CONFIG", str(config_path))

    main_module.main(["config", "set", "oob.domain", "oob.example.test"])
    capsys.readouterr()

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    monkeypatch.setattr(main_module, "docker_run_command", runner)

    # With no runtime container up the status is `down`, which now exits non-zero
    # (so scripts/agents gate on OOB readiness). The JSON payload is still printed
    # before the exit, which is what this test verifies.
    with pytest.raises(SystemExit):
        main_module.main(
            ["--root", str(tmp_path / "install"), "oob", "status", "--json"]
        )

    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "stopped"
    assert payload["domain"] == "oob.example.test"


@pytest.mark.parametrize(
    "argv",
    [
        ["oob", "--help"],
        ["oob", "start", "--help"],
        ["oob", "stop", "--help"],
        ["oob", "restart", "--help"],
        ["oob", "status", "--help"],
        ["oob", "test", "--help"],
        ["oob", "mint", "--help"],
        ["oob", "poll", "--help"],
        ["oob", "client", "--help"],
        ["oob", "client", "start", "--help"],
        ["oob", "client", "logs", "--help"],
        ["oob", "client", "stop", "--help"],
        ["oob", "client", "list", "--help"],
    ],
)
def test_oob_subcommands_have_help_text(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    """Every `vigil oob` (sub)command must be self-describing so the role-file
    OOB prose can collapse to one-liners. `--help` should print a non-trivial
    usage/description block and exit 0."""
    from vigil_cli import main as main_module

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(argv)
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    # More than the bare `usage:` + `-h/--help` boilerplate argparse always emits.
    assert len(out.strip()) > 80


def test_oob_top_level_help_teaches_mint_poll_ordering(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`vigil oob --help` alone must teach the mint -> poll -> correlate flow so
    an operator does not need the role-file prose to learn the ordering."""
    from vigil_cli import main as main_module

    with pytest.raises(SystemExit):
        main_module.main(["oob", "--help"])
    out = capsys.readouterr().out
    assert "mint" in out and "poll" in out
    assert out.index("mint") < out.index("poll")


def test_logs_routes_to_centralized_targets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import main as main_module

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

    assert ["docker", "logs", "--tail", "5", "vigil"] in calls
    assert ["tail", "-n", "5", str(log_file)] in calls


def _install_fake_credential_store(
    monkeypatch: pytest.MonkeyPatch, calls: list[tuple[str, str, dict | None]] | None = None
) -> dict[str, dict]:
    """Stub auth_module._api with an in-memory backend keyed by engagement name.

    ``auth._api`` is the ONE network boundary in ``vigil_cli.auth`` — everything
    above it (status_line, import_auth, probe_liveness, persist_liveness) is real
    code under test here. Stub only this; never the function whose contract the
    test asserts.

    Mirrors the routes in ``app/api/credentials.py``: ``GET /resolve`` honours the
    ``identity``/``scope`` query the CLI sends and, like
    ``creds_service.resolve_identity``, returns ``(requested, {})`` for an unknown
    name; resolved material carries ``identity_name`` the way a stored row does.
    Store shape: {eng_key: {"identities": {name: material}, "active_identity": name}}.
    Pass ``calls`` to record every ``(method, path, payload)`` the CLI issues.
    """
    from vigil_cli import auth as auth_module

    store: dict[str, dict] = {}

    def _state(eng_dir: Path) -> dict:
        return store.setdefault(
            eng_dir.expanduser().resolve().name,
            {"identities": {}, "active_identity": auth_module.DEFAULT_IDENTITY},
        )

    def _resolved(st: dict, requested: str) -> dict:
        name = requested or st["active_identity"]
        material = st["identities"].get(name)
        if not material:
            # Unknown name echoes back (the caller warns); an empty active slot
            # resolves to nothing at all — matches creds_service.resolve_identity.
            return {"identity_name": requested or None, "material": {}}
        return {"identity_name": name, "material": {**material, "identity_name": name}}

    def fake_api(engagement_dir, method, path="", payload=None):
        st = _state(Path(engagement_dir))
        if calls is not None:
            calls.append((method, path, payload))
        if method == "GET" and path == "":
            return st
        if method == "GET" and path.split("?")[0] == "/resolve":
            query = parse_qs(urlparse(path).query)
            return _resolved(st, (query.get("identity") or [""])[0])
        if method == "POST" and path.endswith("/liveness"):
            name = path.strip("/").split("/")[0]
            material = st["identities"].get(name)
            if material is None:
                return {}
            material["liveness_verdict"] = str((payload or {}).get("verdict") or "")
            return {**material, "identity_name": name}
        if method == "GET" and path.startswith("/"):
            return st["identities"].get(path[1:], {})
        if method == "PUT" and path.startswith("/"):
            name = path[1:]
            material = {k: v for k, v in (payload or {}).items() if k != "make_active"}
            st["identities"][name] = material
            if (payload or {}).get("make_active"):
                st["active_identity"] = name
            return {"identity_name": name, "material": material}
        if method == "POST" and path.endswith("/activate"):
            st["active_identity"] = path.strip("/").split("/")[0]
            return {"active_identity": st["active_identity"]}
        if method == "DELETE" and path == "":
            st["identities"].clear()
            return {}
        if method == "DELETE" and path.startswith("/"):
            st["identities"].pop(path[1:], None)
            return {}
        return {}

    monkeypatch.setattr(auth_module, "_api", fake_api)
    return store


def test_auth_status_and_clear_operate_on_engagement_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import auth as auth_module
    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")

    store = _install_fake_credential_store(monkeypatch)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    store["eng-1"] = {
        "identities": {
            auth_module.DEFAULT_IDENTITY: {
                "mode": "manual",
                "state": "present",
                "expires_at": expires_at,
                "cookies": {"sid": "x"},
                "headers": {},
            }
        },
        "active_identity": auth_module.DEFAULT_IDENTITY,
    }

    main_module.main(["--root", str(install_root), "auth", "status", "eng-1"])
    assert "present" in capsys.readouterr().out

    main_module.main(["--root", str(install_root), "auth", "clear", "eng-1"])
    # Clear with no --identity removes the ACTIVE identity; here it was the only
    # one, so the store ends empty.
    assert store["eng-1"]["identities"] == {}


class _FakeProbeResponse:
    """Minimal http.client response for the outbound liveness probe."""

    def __init__(self, status: int, body: str, headers: list[tuple[str, str]]) -> None:
        self.status = status
        self.reason = "OK" if status == 200 else "Found"
        self._body = body
        self._headers = headers

    def getheaders(self) -> list[tuple[str, str]]:
        return self._headers

    def read(self) -> bytes:
        return self._body.encode("utf-8")


def _stub_probe_socket(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: int = 200,
    body: str = "",
    headers: list[tuple[str, str]] | None = None,
) -> list[tuple[str, str, dict[str, str]]]:
    """Stub the probe's OUTBOUND socket only — the real probe_liveness still runs.

    Returns the list of ``(method, path, headers)`` the probe actually sent.
    """
    sent: list[tuple[str, str, dict[str, str]]] = []

    class _FakeConnection:
        def __init__(self, host, port, timeout=None):
            self.host = host
            self.port = port

        def request(self, method, path, headers=None):
            sent.append((method, path, dict(headers or {})))

        def getresponse(self):
            return _FakeProbeResponse(status, body, headers or [])

        def close(self):
            return None

    monkeypatch.setattr("http.client.HTTPSConnection", _FakeConnection)
    monkeypatch.setattr("http.client.HTTPConnection", _FakeConnection)
    return sent


def test_auth_status_probe_reports_requested_identity_instead_of_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`auth status --identity X --probe` must report X, not whatever is active.

    Written against the REAL status_line/probe_liveness/persist_liveness: the
    previous version of this test faked all three with signatures the source did
    not have, so it stayed green while `vigil auth status` raised TypeError. Only
    the two genuine boundaries are stubbed — the backend (`auth._api`) and the
    outbound probe socket.
    """
    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")

    calls: list[tuple[str, str, dict | None]] = []
    store = _install_fake_credential_store(monkeypatch, calls)
    store["eng-1"] = {
        "identities": {
            "other-active": {"mode": "manual", "state": "present", "cookies": {"sid": "a"}},
            "cap-target": {
                "mode": "capture",
                "state": "present",
                "cookies": {"sid": "b"},
                "liveness": {"expect_status": 200, "authed_marker": "signed-in-as-cap"},
            },
        },
        "active_identity": "other-active",
    }
    sent = _stub_probe_socket(monkeypatch, status=200, body="<p>signed-in-as-cap</p>")

    main_module.main(
        [
            "--root",
            str(install_root),
            "auth",
            "status",
            "eng-1",
            "--identity",
            "cap-target",
            "--probe",
            "--probe-url",
            "https://chat.example.test/me",
        ]
    )
    status_out, liveness_out = capsys.readouterr().out.strip().splitlines()

    # The probe carried cap-target's cookie, not the active identity's.
    assert sent == [("GET", "/me", {"Cookie": "sid=b"})]
    # Both printed lines name the REQUESTED identity.
    assert "\tidentity=cap-target\t" in status_out
    assert "other-active" not in status_out
    # And the status line carries the cookie itself, not a count of cookies: the
    # value is what tells the operator which session the next request replays as.
    assert "\tcookies=sid=b\t" in status_out
    assert liveness_out.startswith(
        "liveness=live\tidentity=cap-target\tscope=https://chat.example.test\t"
    )
    assert "persisted=True" in liveness_out
    # The scope the CLI resolved from the probe URL is the one it sent to the
    # backend on every leg — resolve, re-resolve for the status line, and persist.
    resolves = [path for method, path, _ in calls if method == "GET" and path.startswith("/resolve")]
    assert resolves == [
        "/resolve?identity=cap-target&scope=https%3A%2F%2Fchat.example.test",
        "/resolve?identity=cap-target&scope=https%3A%2F%2Fchat.example.test",
    ]
    persist = [payload for method, path, payload in calls if path == "/cap-target/liveness"]
    assert persist and persist[0]["verdict"] == "live"
    assert persist[0]["scope_key"] == "https://chat.example.test"
    assert store["eng-1"]["active_identity"] == "other-active"  # probing never re-activates


def test_auth_status_probe_of_unconfigured_identity_reports_unknown_not_live(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An identity with no `material.liveness` signature must probe `unknown`.

    The honesty invariant behind the whole probe path: a 200 alone is not proof of
    a live session, so the verdict must not be persisted as `live`.
    """
    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")

    calls: list[tuple[str, str, dict | None]] = []
    store = _install_fake_credential_store(monkeypatch, calls)
    store["eng-1"] = {
        "identities": {"cap-target": {"mode": "capture", "state": "present", "cookies": {"sid": "b"}}},
        "active_identity": "cap-target",
    }
    _stub_probe_socket(monkeypatch, status=200, body="<p>hello</p>")

    main_module.main(
        [
            "--root",
            str(install_root),
            "auth",
            "status",
            "eng-1",
            "--identity",
            "cap-target",
            "--probe",
            "--probe-url",
            "https://chat.example.test/me",
        ]
    )
    out = capsys.readouterr().out
    assert "liveness=unknown\tidentity=cap-target" in out
    assert "no liveness signature configured" in out
    persist = [payload for _m, path, payload in calls if path == "/cap-target/liveness"]
    assert persist and persist[0]["verdict"] == "unknown"


def test_auth_clear_without_identity_deletes_only_active_not_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # PR #40: `vigil auth clear` (no --identity) must delete ONLY the active
    # identity, never the whole collection — a routine clear of an expired session
    # must not wipe user_a/user_b/admin. `--all` is the explicit wipe-everything.
    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    store = _install_fake_credential_store(monkeypatch)
    store["eng-1"] = {
        "identities": {
            "user_a": {"cookies": {"s": "a"}},
            "user_b": {"cookies": {"s": "b"}},
            "admin": {"cookies": {"s": "x"}},
        },
        "active_identity": "user_b",
    }

    main_module.main(["--root", str(install_root), "auth", "clear", "eng-1"])
    assert set(store["eng-1"]["identities"]) == {"user_a", "admin"}  # only active gone

    main_module.main(["--root", str(install_root), "auth", "clear", "eng-1", "--all"])
    assert store["eng-1"]["identities"] == {}  # --all wipes everything


def test_auth_import_expands_multi_identity_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # PR #40: importing the legacy multi-identity shape must upsert EACH identity
    # into its own slot (not dump the wrapper into `default`), so the documented
    # `vigil auth import` recovery actually restores usable credentials.
    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    store = _install_fake_credential_store(monkeypatch)
    src = tmp_path / "auth.json"
    src.write_text(
        json.dumps(
            {
                "identities": {
                    "user_a": {"cookies": {"s": "a"}},
                    "user_b": {"cookies": {"s": "b"}},
                },
                "active_identity": "user_b",
            }
        ),
        encoding="utf-8",
    )

    main_module.main(
        ["--root", str(install_root), "auth", "import", "eng-1", "--source", str(src)]
    )
    ids = store["eng-1"]["identities"]
    assert set(ids) == {"user_a", "user_b"}
    assert ids["user_a"]["cookies"] == {"s": "a"}
    assert ids["user_b"]["cookies"] == {"s": "b"}
    assert store["eng-1"]["active_identity"] == "user_b"  # active flag honored


def test_auth_import_rejects_wrapped_payload_that_would_store_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wrapped export must fail loudly, not import an inert empty identity.

    ``{"material": {...}}`` used to reach the backend intact (the request model
    allows extra keys), where only top-level cookies/headers/tokens are read: the
    real cookies landed in raw_json, the identity was stored ``state="missing"``,
    and the CLI printed success — a manufactured credential blocker.
    """
    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    calls: list[tuple[str, str, dict | None]] = []
    store = _install_fake_credential_store(monkeypatch, calls)
    src = tmp_path / "auth.json"
    src.write_text(
        json.dumps({"material": {"cookies": {"sid": "abc"}}, "identity_name": "alice"}),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(
            ["--root", str(install_root), "auth", "import", "eng-1", "--source", str(src)]
        )

    message = str(excinfo.value)
    assert "would store nothing" in message
    assert "'material'" in message  # names the wrapper that was found
    assert '"cookies"' in message  # names the shape that works
    assert not [call for call in calls if call[0] == "PUT"]  # nothing was written
    assert store.get("eng-1", {"identities": {}})["identities"] == {}


def test_auth_import_accepts_host_cookies_only_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """host_cookies alone is replayable material — the empty-import guard must not
    refuse it just because the backend leaves ``state`` at missing for it."""
    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    store = _install_fake_credential_store(monkeypatch)
    src = tmp_path / "auth.json"
    src.write_text(
        json.dumps({"host_cookies": [{"host": "app.example.test", "cookies": {"sid": "x"}}]}),
        encoding="utf-8",
    )

    main_module.main(
        ["--root", str(install_root), "auth", "import", "eng-1", "--source", str(src)]
    )

    stored = store["eng-1"]["identities"]["default"]
    assert stored["host_cookies"][0]["cookies"] == {"sid": "x"}


def test_auth_import_accepts_a_legacy_top_level_bearer_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`{"token": ...}` is replayable (auth._bearer_token reads it back out of
    raw_json), so the empty-import guard must not refuse it — a guard that blocks
    a working import is a worse failure than the silent one it replaced."""
    from vigil_cli import auth as auth_module
    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    store = _install_fake_credential_store(monkeypatch)
    src = tmp_path / "auth.json"
    src.write_text(json.dumps({"token": "eyJhbGciOi.legacy"}), encoding="utf-8")

    main_module.main(
        ["--root", str(install_root), "auth", "import", "eng-1", "--source", str(src)]
    )

    stored = store["eng-1"]["identities"]["default"]
    assert auth_module._bearer_token(stored) == "eyJhbGciOi.legacy"


def test_auth_import_rejects_identity_map_with_no_material_anywhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    calls: list[tuple[str, str, dict | None]] = []
    _install_fake_credential_store(monkeypatch, calls)
    src = tmp_path / "auth.json"
    src.write_text(
        json.dumps({"identities": {"user_a": {"mode": "manual"}, "user_b": {}}}),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(
            ["--root", str(install_root), "auth", "import", "eng-1", "--source", str(src)]
        )

    assert "user_a, user_b" in str(excinfo.value)
    assert not [call for call in calls if call[0] == "PUT"]


def test_auth_edit_without_identity_writes_back_to_the_active_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PR#40 regression: `vigil auth edit` (no --identity) must write the edit BACK to the
    active identity, not blindly to `default`. When a non-default identity is active,
    targeting `default` forked the edit into `default` and make_active flipped the
    engagement onto it — corrupting `default` and leaving the active identity unchanged."""
    from vigil_cli import auth as auth_module
    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")

    store = _install_fake_credential_store(monkeypatch)
    store["eng-1"] = {
        "identities": {
            "alice": {
                "mode": "manual",
                "state": "present",
                "cookies": {"sid": "alice-sid"},
                "headers": {},
            }
        },
        "active_identity": "alice",
    }

    # No-op editor: leave the dumped material untouched so the edit is a pure round-trip.
    monkeypatch.setattr(auth_module.subprocess, "call", lambda *a, **k: 0)

    main_module.main(["--root", str(install_root), "auth", "edit", "eng-1"])

    # The edit lands on `alice` (the active identity), not `default`.
    assert store["eng-1"]["active_identity"] == "alice"
    assert "default" not in store["eng-1"]["identities"]
    assert "updated_at" in store["eng-1"]["identities"]["alice"]
    assert store["eng-1"]["identities"]["alice"]["cookies"] == {"sid": "alice-sid"}


def test_auth_select_selector_overrides_current_engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import auth as auth_module
    from vigil_cli import engagements
    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    root = install_root / "agent" / "engagements"
    older = root / "2026-04-24-120000-older"
    newer = root / "2026-04-24-120001-newer"
    store = _install_fake_credential_store(monkeypatch)
    for path, created_at in (
        (older, "2026-04-24T12:00:00Z"),
        (newer, "2026-04-24T12:00:01Z"),
    ):
        path.mkdir(parents=True)
        (path / "scope.json").write_text('{"status":"in_progress","current_phase":"recon"}', encoding="utf-8")
        (path / "engagement.json").write_text(json.dumps({"key": path.name, "target": path.name, "created_at": created_at}), encoding="utf-8")
        store[path.name] = {
            "identities": {
                auth_module.DEFAULT_IDENTITY: {
                    "mode": "manual",
                    "state": "present",
                    "cookies": {"sid": path.name},
                    "headers": {},
                }
            },
            "active_identity": auth_module.DEFAULT_IDENTITY,
        }

    def fake_which(command: str) -> str | None:
        return "/usr/bin/fzf" if command == "fzf" else None

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, f"{newer.name}\tin_progress\trecon\t{newer.name}\t{newer.resolve()}\n", "")

    monkeypatch.setattr(engagements.shutil, "which", fake_which)
    monkeypatch.setattr(engagements.subprocess, "run", fake_run)
    monkeypatch.setattr(engagements.sys, "stdin", _TTYStdin())
    monkeypatch.chdir(older)

    main_module.main(["--root", str(install_root), "auth", "clear", "--select"])

    # --select picks `newer`; only its centralized credential is cleared.
    assert store[older.name]["identities"][auth_module.DEFAULT_IDENTITY]["cookies"] == {"sid": older.name}
    assert store[newer.name]["identities"] == {}


def test_auth_without_engagement_context_requires_key_or_select(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    engagement = install_root / "agent" / "engagements" / "eng-1"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    (engagement / "engagement.json").write_text(json.dumps({"key": "eng-1", "created_at": "2026-04-24T12:00:00Z"}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit, match="Specify an engagement key or --select"):
        main_module.main(["--root", str(install_root), "auth", "status"])


def test_mitmproxy_reload_touches_sentinel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`vigil mitmproxy reload` writes the sentinel the addon polls for, so the
    bind-mount surfaces it to the running container immediately.
    """
    from vigil_cli import main as main_module

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
    """`vigil mitmproxy routes` parses the snapshot the addon wrote and prints
    a readable summary; --json round-trips the raw cache.
    """
    from vigil_cli import main as main_module

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
    from vigil_cli import main as main_module

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
    ["VIGIL_DATA_DIR", "REDTEAM_ORCHESTRATOR_DATA_DIR"],
)
def test_backup_helpers_use_backend_data_dir_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env_name: str) -> None:
    from vigil_cli.backup import (
        create_backup,
        list_backups,
        live_database,
        restore_backup,
    )

    install_root = tmp_path / "install"
    default_data = install_root / "orchestrator" / "backend" / "data"
    custom_data = tmp_path / "backend-data"
    legacy_data = tmp_path / "legacy-data"
    if env_name == "VIGIL_DATA_DIR":
        monkeypatch.setenv("REDTEAM_ORCHESTRATOR_DATA_DIR", str(legacy_data))
    else:
        monkeypatch.delenv("VIGIL_DATA_DIR", raising=False)
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
    from vigil_cli.backup import create_backup, list_backups

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
    from vigil_cli.backup import restore_backup

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


def _seed_live_oob_state(install_root: Path) -> None:
    """Put the root in the population the shared 53/8443 route exists for.

    The OOB tests below drive rendering and the frpc post-flight on that legacy
    route. `start_oob` refuses it on a root with no slot reserved and no prior
    OOB state, because starting is the thing that would pin it there; a root
    whose callbacks are already live on it is warned and started. A rendered
    `frpc.toml` is the discriminator `has_pre_routing_oob_state` reads.
    """
    from vigil_cli.oob_relay import OOB_STATE_RELATIVE_PATH

    state_dir = install_root / OOB_STATE_RELATIVE_PATH
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "frpc.toml").write_text("[common]\n", encoding="utf-8")


def test_oob_start_renders_config_and_starts_idempotent_sessions(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, start_oob

    _seed_live_oob_state(tmp_path)
    commands: list[list[str]] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if argv[:3] == ["docker", "exec", "vigil"] and "tmux has-session -t oob-server" in argv[-1] and "tmux new-session" not in argv[-1]:
            return DockerResult(1, "", "")
        if argv[:3] == ["docker", "exec", "vigil"] and "tmux has-session -t frpc" in argv[-1] and "tmux new-session" not in argv[-1]:
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
        frpc_ready_timeout=0,
    )

    rendered = "\n".join(" ".join(command) for command in commands)
    assert "cal.example.test" in rendered
    assert "oob.example.test" in rendered
    assert "tmux new-session -d -s oob-server" in rendered
    assert "tmux new-session -d -s frpc" in rendered


def _self_test_marker(token: str) -> str:
    """The channel-verification marker the REAL minter produces for ``token``.

    Never hand-write this label. ``mint_nonce`` reduces the prefix to the
    [a-z0-9] a DNS label can carry, so a hand-written ``vigil-test-…`` is a
    string the shipped code cannot mint — and a test built on one cannot see the
    minter and the self-test recogniser disagreeing about the spelling, which is
    exactly how the recogniser silently never fired.
    """
    from vigil_cli import oob as oob_module

    return oob_module.mint_nonce(
        prefix=oob_module.SELF_TEST_NONCE_PREFIX,
        length=len(token),
        token_factory=lambda _length: token,
    )


def _pin_self_test_marker(monkeypatch: pytest.MonkeyPatch, token: str) -> str:
    """Pin the marker deterministically WITHOUT bypassing the real minter."""
    from vigil_cli import oob as oob_module

    real = oob_module.mint_nonce
    monkeypatch.setattr(
        "vigil_cli.oob.mint_nonce",
        lambda **kwargs: real(**{**kwargs, "token_factory": lambda _length: token}),
    )
    return _self_test_marker(token)


def test_verify_oob_channel_returns_a_verdict_instead_of_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The extracted verifier reports; only `oob test` turns a failure into an error.

    `oob poll` calls it on the zero-match path, where a refusal would be a dead
    end mid-engagement — the caller has to stay free to proceed.
    """
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, verify_oob_channel

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if argv[-1].startswith("dig "):
            return DockerResult(9, "", "connection timed out")
        raise AssertionError(f"unexpected command: {argv[-1]}")

    marker = _pin_self_test_marker(monkeypatch, "deadbeef")
    monkeypatch.setattr(
        "vigil_cli.oob.client_payload_host",
        lambda *_args, **_kwargs: "client-id.slot.oob.example.test",
    )

    result = verify_oob_channel(
        OobOptions(install_root=tmp_path, oob_domain="slot.oob.example.test"),
        client="probe",
        runner=runner,
    )

    assert result.verified is False
    assert "public DNS probe failed" in result.reason
    assert result.client == "probe"  # pinned to the requested client, not the first running one
    assert result.as_dict()["marker"] == marker


def test_verify_oob_channel_unverified_when_runtime_is_down(
    tmp_path: Path,
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, verify_oob_channel

    result = verify_oob_channel(
        OobOptions(install_root=tmp_path, oob_domain="slot.oob.example.test"),
        runner=lambda *_a, **_k: DockerResult(0, "", ""),
    )

    assert result.verified is False
    assert "Kali runtime is not running" in result.reason


def _channel_probe_runner(
    probes: list[str], *, dns_fails: bool = False, marker: str = ""
):
    """Runner that records each channel-verification round trip it is asked for."""
    from vigil_cli.docker import DockerResult

    marker = marker or _self_test_marker("cafebabe")

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        command = argv[-1]
        probes.append(command.split(" ", 1)[0])
        if command.startswith("dig "):
            if dns_fails:
                return DockerResult(9, "", "connection timed out")
            return DockerResult(0, "203.0.113.10\n", "")
        if command.startswith("curl "):
            return DockerResult(0, "200", "")
        if command.startswith("grep "):
            return DockerResult(0, f"[{marker}.host] HTTP\n", "")
        raise AssertionError(f"unexpected command: {command}")

    return runner


def _cached_channel_options(tmp_path: Path):
    from vigil_cli.oob import OobOptions

    return OobOptions(install_root=tmp_path, oob_domain="slot.oob.example.test")


@pytest.fixture
def _channel_check_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_self_test_marker(monkeypatch, "cafebabe")
    monkeypatch.setattr(
        "vigil_cli.oob.client_payload_host",
        lambda *_args, **_kwargs: "agent-a.slot.oob.example.test",
    )


def test_verified_channel_verdict_is_reused_within_its_ttl(
    tmp_path: Path, _channel_check_stubs: None
) -> None:
    """An empty `oob poll` loop must not re-pay the round trip to learn the same fact.

    The proof itself is unchanged — a real DNS + HTTP + callback trip — but an
    agent polling for a blind callback calls this repeatedly, and channel health
    does not change between two polls seconds apart.
    """
    from vigil_cli.oob import VERIFIED_CHANNEL_TTL_SECONDS, verify_oob_channel_cached

    probes: list[str] = []
    options = _cached_channel_options(tmp_path)
    runner = _channel_probe_runner(probes)

    first = verify_oob_channel_cached(options, client="agent-a", runner=runner, now=1_000.0)
    assert first.verified is True
    assert first.cached is False
    fresh_probe_count = len(probes)
    assert fresh_probe_count > 0

    later = verify_oob_channel_cached(
        options,
        client="agent-a",
        runner=runner,
        now=1_000.0 + VERIFIED_CHANNEL_TTL_SECONDS - 1,
    )

    assert later.verified is True
    # The reuse is reported, never dressed up as a fresh proof.
    assert later.cached is True
    assert later.age_seconds == pytest.approx(VERIFIED_CHANNEL_TTL_SECONDS - 1)
    assert later.as_dict()["cached"] is True
    assert later.describe_freshness().startswith("cached(")
    assert len(probes) == fresh_probe_count  # no second round trip


def test_expired_channel_verdict_is_proved_again(
    tmp_path: Path, _channel_check_stubs: None
) -> None:
    """The cadence is a cache, not an answer cast in stone."""
    from vigil_cli.oob import VERIFIED_CHANNEL_TTL_SECONDS, verify_oob_channel_cached

    probes: list[str] = []
    options = _cached_channel_options(tmp_path)
    runner = _channel_probe_runner(probes)

    verify_oob_channel_cached(options, client="agent-a", runner=runner, now=1_000.0)
    fresh_probe_count = len(probes)

    again = verify_oob_channel_cached(
        options,
        client="agent-a",
        runner=runner,
        now=1_000.0 + VERIFIED_CHANNEL_TTL_SECONDS + 1,
    )

    assert again.cached is False
    assert again.age_seconds == 0.0
    assert len(probes) == fresh_probe_count * 2


def test_broken_channel_verdict_expires_sooner_than_a_healthy_one(
    tmp_path: Path, _channel_check_stubs: None
) -> None:
    """A repaired channel must be noticed quickly.

    An `unverified` verdict is the one the operator is actively fixing, so
    holding it for the full healthy TTL would keep reporting a channel as dead
    after it came back. It costs the 10s wait again — bounded to once a minute,
    not once a poll.
    """
    from vigil_cli.oob import (
        UNVERIFIED_CHANNEL_TTL_SECONDS,
        VERIFIED_CHANNEL_TTL_SECONDS,
        verify_oob_channel_cached,
    )

    assert UNVERIFIED_CHANNEL_TTL_SECONDS < VERIFIED_CHANNEL_TTL_SECONDS

    probes: list[str] = []
    options = _cached_channel_options(tmp_path)
    runner = _channel_probe_runner(probes, dns_fails=True)

    first = verify_oob_channel_cached(options, client="agent-a", runner=runner, now=1_000.0)
    assert first.verified is False
    fresh_probe_count = len(probes)

    within = verify_oob_channel_cached(
        options,
        client="agent-a",
        runner=runner,
        now=1_000.0 + UNVERIFIED_CHANNEL_TTL_SECONDS - 1,
    )
    assert within.cached is True
    assert within.verified is False
    assert "public DNS probe failed" in within.reason
    assert len(probes) == fresh_probe_count

    beyond = verify_oob_channel_cached(
        options,
        client="agent-a",
        runner=runner,
        now=1_000.0 + UNVERIFIED_CHANNEL_TTL_SECONDS + 1,
    )
    assert beyond.cached is False
    assert len(probes) == fresh_probe_count * 2


def test_channel_verdict_is_not_shared_across_clients(
    tmp_path: Path, _channel_check_stubs: None
) -> None:
    """A different client is a different payload host and a different log."""
    from vigil_cli.oob import verify_oob_channel_cached

    probes: list[str] = []
    options = _cached_channel_options(tmp_path)
    runner = _channel_probe_runner(probes)

    verify_oob_channel_cached(options, client="agent-a", runner=runner, now=1_000.0)
    fresh_probe_count = len(probes)

    other = verify_oob_channel_cached(options, client="agent-b", runner=runner, now=1_000.5)

    assert other.cached is False
    assert len(probes) == fresh_probe_count * 2


def test_corrupt_channel_verdict_cache_falls_back_to_proving_the_channel(
    tmp_path: Path, _channel_check_stubs: None
) -> None:
    """A hand-edited or half-written cache file must degrade to a real proof."""
    from vigil_cli.oob import (
        CHANNEL_VERIFICATION_CACHE_RELATIVE_PATH,
        verify_oob_channel_cached,
    )

    cache = tmp_path / CHANNEL_VERIFICATION_CACHE_RELATIVE_PATH
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text('{"entries": [1, 2', encoding="utf-8")

    probes: list[str] = []
    result = verify_oob_channel_cached(
        _cached_channel_options(tmp_path),
        client="agent-a",
        runner=_channel_probe_runner(probes),
        now=1_000.0,
    )

    assert result.verified is True
    assert result.cached is False
    assert probes  # the round trip actually ran


def test_channel_verdict_cache_write_failure_never_fails_the_check(
    tmp_path: Path, _channel_check_stubs: None
) -> None:
    """The cache is an optimisation; an unwritable install root must not dead-end a poll."""
    from vigil_cli.oob import verify_oob_channel_cached

    # A file where the cache directory must go makes mkdir/write raise.
    (tmp_path / ".runtime-data").write_text("not a directory", encoding="utf-8")

    result = verify_oob_channel_cached(
        _cached_channel_options(tmp_path),
        client="agent-a",
        runner=_channel_probe_runner([]),
        now=1_000.0,
    )

    assert result.verified is True
    assert result.cached is False


# `_oob_options` resolves the default relay slot domain, and `interactions_for_domain`
# filters callbacks against it — the fixture host must live under it.
def _oob_poll_payload_host() -> str:
    return "agent-a.oob.example.test"


def _seed_oob_poll_engagement(install_root: Path, key: str) -> Path:
    eng_dir = install_root / "agent" / "engagements" / key
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text("{}", encoding="utf-8")
    return eng_dir


class _OobPollClient:
    """AssessmentClient stand-in for `_oob_poll` (the backend boundary)."""

    def __init__(self, probes: list[dict[str, object]]) -> None:
        self._probes = probes
        self.posts: list[tuple[str, dict]] = []

    def get(self, endpoint: str) -> list[dict[str, object]]:
        assert endpoint == "oob-probes"
        return self._probes

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        return {"duplicate": False, "probe": {"technique": "ssrf"}}

    def __enter__(self) -> _OobPollClient:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


def _run_oob_poll(
    monkeypatch: pytest.MonkeyPatch,
    install_root: Path,
    *,
    log: str,
    probes: list[dict[str, object]],
    runner,
    as_json: bool = True,
) -> _OobPollClient:
    from vigil_cli import main as main_module

    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "oob.example.test")
    key = "2026-08-25-120000-poll"
    _seed_oob_poll_engagement(install_root, key)
    client = _OobPollClient(probes)
    monkeypatch.setattr(main_module, "docker_run_command", runner)
    monkeypatch.setattr(main_module, "read_client_log", lambda *_a, **_k: log)
    monkeypatch.setattr(
        main_module, "poll_client_payload_host", lambda *_a, **_k: _oob_poll_payload_host()
    )
    monkeypatch.setattr(main_module, "_build_assessment_client", lambda *_a: client)
    _pin_self_test_marker(monkeypatch, "cafebabe")
    monkeypatch.setattr(
        "vigil_cli.oob.client_payload_host",
        lambda *_args, **_kwargs: _oob_poll_payload_host(),
    )
    args = SimpleNamespace(
        engagement=key, select=False, client="agent-a", lines=2000, json=as_json
    )
    main_module._oob_poll(args, install_root, main_module._oob_options(install_root))
    return client


def test_oob_poll_zero_match_reports_channel_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A clean zero has to say whether the channel could have carried a callback.

    Otherwise `matched 0` from a live channel and from a broken one are
    byte-identical — and an OOB negative is used as evidence.
    """
    from vigil_cli.docker import DockerResult

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        command = argv[-1]
        if command.startswith("dig "):
            return DockerResult(0, "203.0.113.10\n", "")
        if command.startswith("curl "):
            return DockerResult(0, "200", "")
        if command.startswith("grep "):
            return DockerResult(
                0, f"[{_self_test_marker('cafebabe')}.{_oob_poll_payload_host()}] HTTP\n", ""
            )
        raise AssertionError(f"unexpected command: {command}")

    _run_oob_poll(monkeypatch, tmp_path, log="", probes=[], runner=runner)

    payload = json.loads(capsys.readouterr().out)
    assert payload["matched"] == []
    assert payload["channel_verified"] is True
    assert payload["channel_check"]["dns_address"] == "203.0.113.10"
    assert payload["channel_check"]["http_status"] == 200


def test_oob_poll_loop_does_not_reprove_the_channel_every_empty_poll(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Waiting for a blind callback means polling in a loop.

    The first empty poll pays for the end-to-end proof; the ones right behind it
    must not, or every "nothing yet" costs an agent the full callback timeout to
    learn what it already knew. The reused verdict is still reported honestly.
    """
    from vigil_cli.docker import DockerResult

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        command = argv[-1]
        if command.startswith("dig "):
            return DockerResult(0, "203.0.113.10\n", "")
        if command.startswith("curl "):
            return DockerResult(0, "200", "")
        if command.startswith("grep "):
            return DockerResult(
                0, f"[{_self_test_marker('cafebabe')}.{_oob_poll_payload_host()}] HTTP\n", ""
            )
        raise AssertionError(f"unexpected command: {command}")

    def refuses(argv: list[str], **_: object) -> DockerResult:
        raise AssertionError(f"second poll must not re-prove the channel: {argv[-1]}")

    _run_oob_poll(monkeypatch, tmp_path, log="", probes=[], runner=runner)
    first = json.loads(capsys.readouterr().out)
    _run_oob_poll(monkeypatch, tmp_path, log="", probes=[], runner=refuses)
    second = json.loads(capsys.readouterr().out)

    assert first["channel_verified"] is True
    assert first["channel_check"]["cached"] is False
    # Same guarantee, no second round trip — and the caller can see it is reused.
    assert second["channel_verified"] is True
    assert second["channel_check"]["cached"] is True
    assert second["channel_check"]["age_seconds"] >= 0
    assert second["channel_check"]["dns_address"] == "203.0.113.10"


def test_oob_poll_text_output_says_how_the_channel_verdict_was_obtained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Text mode carries the same freshness the JSON does — a cached verdict says so."""
    from vigil_cli.docker import DockerResult

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        command = argv[-1]
        if command.startswith("dig "):
            return DockerResult(0, "203.0.113.10\n", "")
        if command.startswith("curl "):
            return DockerResult(0, "200", "")
        if command.startswith("grep "):
            return DockerResult(
                0, f"[{_self_test_marker('cafebabe')}.{_oob_poll_payload_host()}] HTTP\n", ""
            )
        raise AssertionError(f"unexpected command: {command}")

    _run_oob_poll(monkeypatch, tmp_path, log="", probes=[], runner=runner, as_json=False)
    assert "channel\tverified" in capsys.readouterr().out

    _run_oob_poll(
        monkeypatch,
        tmp_path,
        log="",
        probes=[],
        runner=lambda *_a, **_k: pytest.fail("channel must not be re-proved"),
        as_json=False,
    )
    out = capsys.readouterr().out
    assert "channel\tverified" in out
    assert "checked=cached(" in out


def test_oob_poll_zero_match_reports_an_unverified_channel_without_failing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A broken channel must be loud but must NOT block the caller."""
    from vigil_cli.docker import DockerResult

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if argv[-1].startswith("dig "):
            return DockerResult(9, "", "connection timed out")
        raise AssertionError(f"unexpected command: {argv[-1]}")

    _run_oob_poll(monkeypatch, tmp_path, log="", probes=[], runner=runner, as_json=False)

    out = capsys.readouterr().out
    assert "matched\t0\tunmatched\t0" in out
    assert "channel\tUNVERIFIED" in out
    assert "public DNS probe failed" in out
    assert "not evidence that no callback occurred" in out


def test_oob_poll_does_not_report_its_own_verification_markers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The zero-match channel check fires a REAL round trip into this same log.

    Its markers must never come back as unclaimed callbacks: the operator reads
    `unmatched` as "something hit the channel that no probe claims", and every
    empty poll would otherwise add two synthetic entries that persist for the
    life of the client — the check manufacturing the evidence it exists to
    qualify.
    """
    from vigil_cli.docker import DockerResult

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        command = argv[-1]
        if command.startswith("dig "):
            return DockerResult(0, "203.0.113.10\n", "")
        if command.startswith("curl "):
            return DockerResult(0, "200", "")
        if command.startswith("grep "):
            return DockerResult(
                0, f"[{_self_test_marker('cafebabe')}.{_oob_poll_payload_host()}] HTTP\n", ""
            )
        raise AssertionError(f"unexpected command: {command}")

    host = _oob_poll_payload_host()
    log = (
        f"[{_self_test_marker('cafebabe')}.{host}] Received DNS interaction (A) "
        "from 203.0.113.10 at 2026-08-25 12:00:00\n"
        f"[{_self_test_marker('cafebabe')}.{host}] Received HTTP interaction "
        "from 203.0.113.10 at 2026-08-25 12:00:01\n"
        f"[realstranger1.{host}] Received DNS interaction (A) "
        "from 198.51.100.7 at 2026-08-25 12:00:02\n"
    )
    _run_oob_poll(monkeypatch, tmp_path, log=log, probes=[], runner=runner)

    payload = json.loads(capsys.readouterr().out)
    # The genuine unclaimed callback survives; only Vigil's own markers are dropped.
    assert [item["full_host"] for item in payload["unmatched"]] == [f"realstranger1.{host}"]
    assert payload["parsed"] == 1
    assert payload["channel_verified"] is True


def test_oob_poll_skips_the_channel_check_when_a_probe_correlated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A correlation already proves the channel works — don't pay for the round trip."""
    from vigil_cli.docker import DockerResult

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        raise AssertionError(f"channel check must not run: {argv[-1]}")

    log = (
        f"[knownnonce01.{_oob_poll_payload_host()}] Received DNS interaction (A) "
        "from 203.0.113.9 at 2026-08-25 12:00:00\n"
    )
    client = _run_oob_poll(
        monkeypatch,
        tmp_path,
        log=log,
        probes=[
            {
                "nonce": "knownnonce01",
                "client_name": "agent-a",
                "client_payload_host": _oob_poll_payload_host(),
            }
        ],
        runner=runner,
    )

    payload = json.loads(capsys.readouterr().out)
    assert [entry["nonce"] for entry in payload["matched"]] == ["knownnonce01"]
    assert payload["channel_verified"] is None
    assert "channel_check" not in payload
    assert client.posts and client.posts[0][0] == "oob-probes/interactions"


def test_oob_test_fails_when_public_dns_probe_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, test_oob

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        command = argv[-1]
        if command.startswith("dig "):
            return DockerResult(9, "", "connection timed out")
        raise AssertionError(f"unexpected command: {command}")

    _pin_self_test_marker(monkeypatch, "deadbeef")
    monkeypatch.setattr(
        "vigil_cli.oob.list_running_oob_clients", lambda *_args, **_kwargs: ["probe"]
    )
    monkeypatch.setattr(
        "vigil_cli.oob.client_payload_host",
        lambda *_args, **_kwargs: "client-id.slot.oob.example.test",
    )
    with pytest.raises(SystemExit, match="public DNS probe failed"):
        test_oob(
            OobOptions(
                install_root=tmp_path,
                oob_domain="slot.oob.example.test",
            ),
            runner=runner,
        )


def test_oob_test_reports_bounded_dns_and_http_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, test_oob

    commands: list[str] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        command = argv[-1]
        commands.append(command)
        if command.startswith("dig "):
            return DockerResult(0, "203.0.113.10\n", "")
        if command.startswith("curl "):
            return DockerResult(0, "200", "")
        if command.startswith("grep "):
            return DockerResult(
                0,
                f"[{marker}.client-id.slot.oob.example.test] "
                "Received HTTP interaction\n",
                "",
            )
        raise AssertionError(f"unexpected command: {command}")

    marker = _pin_self_test_marker(monkeypatch, "cafebabe")
    monkeypatch.setattr(
        "vigil_cli.oob.list_running_oob_clients", lambda *_args, **_kwargs: ["probe"]
    )
    monkeypatch.setattr(
        "vigil_cli.oob.client_payload_host",
        lambda *_args, **_kwargs: "client-id.slot.oob.example.test",
    )
    test_oob(
        OobOptions(
            install_root=tmp_path,
            oob_domain="slot.oob.example.test",
        ),
        runner=runner,
    )

    assert capsys.readouterr().out == (
        "oob test\tok\tdomain=slot.oob.example.test"
        f"\tmarker={marker}\tdns=203.0.113.10\thttp=200\n"
    )
    assert len(commands) == 3
    assert all(
        f"{marker}.client-id.slot.oob.example.test" in command
        for command in commands[:2]
    )
    assert marker in commands[2]
    assert all("tail " not in command for command in commands)


def test_oob_test_fails_when_public_http_probe_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, test_oob

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        command = argv[-1]
        if command.startswith("dig "):
            return DockerResult(0, "203.0.113.10\n", "")
        if command.startswith("curl "):
            return DockerResult(28, "000", "operation timed out")
        raise AssertionError(f"unexpected command: {command}")

    _pin_self_test_marker(monkeypatch, "bad0cafe")
    monkeypatch.setattr(
        "vigil_cli.oob.list_running_oob_clients", lambda *_args, **_kwargs: ["probe"]
    )
    monkeypatch.setattr(
        "vigil_cli.oob.client_payload_host",
        lambda *_args, **_kwargs: "client-id.slot.oob.example.test",
    )
    with pytest.raises(SystemExit, match="public HTTP probe failed"):
        test_oob(
            OobOptions(
                install_root=tmp_path,
                oob_domain="slot.oob.example.test",
            ),
            runner=runner,
        )


def test_oob_test_fails_when_callback_does_not_reach_client_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, test_oob

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        command = argv[-1]
        if command.startswith("dig "):
            return DockerResult(0, "203.0.113.10\n", "")
        if command.startswith("curl "):
            return DockerResult(0, "200", "")
        if command.startswith("grep "):
            return DockerResult(1, "", "")
        raise AssertionError(f"unexpected command: {command}")

    monotonic = iter((0.0, 0.0, 11.0))
    monkeypatch.setattr("vigil_cli.oob.time.monotonic", lambda: next(monotonic))
    monkeypatch.setattr("vigil_cli.oob.time.sleep", lambda _seconds: None)
    _pin_self_test_marker(monkeypatch, "nointeraction")
    monkeypatch.setattr(
        "vigil_cli.oob.list_running_oob_clients", lambda *_args, **_kwargs: ["probe"]
    )
    monkeypatch.setattr(
        "vigil_cli.oob.client_payload_host",
        lambda *_args, **_kwargs: "client-id.slot.oob.example.test",
    )

    with pytest.raises(SystemExit, match="callback was not observed"):
        test_oob(
            OobOptions(
                install_root=tmp_path,
                oob_domain="slot.oob.example.test",
            ),
            runner=runner,
        )


def test_oob_test_rejects_http_redirects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, test_oob

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        command = argv[-1]
        if command.startswith("dig "):
            return DockerResult(0, "203.0.113.10\n", "")
        if command.startswith("curl "):
            return DockerResult(0, "308", "")
        raise AssertionError(f"unexpected command: {command}")

    _pin_self_test_marker(monkeypatch, "redirect")
    monkeypatch.setattr(
        "vigil_cli.oob.list_running_oob_clients", lambda *_args, **_kwargs: ["probe"]
    )
    monkeypatch.setattr(
        "vigil_cli.oob.client_payload_host",
        lambda *_args, **_kwargs: "client-id.slot.oob.example.test",
    )

    with pytest.raises(SystemExit, match="public HTTP probe failed"):
        test_oob(
            OobOptions(
                install_root=tmp_path,
                oob_domain="slot.oob.example.test",
            ),
            runner=runner,
        )


def test_oob_start_post_flight_detects_frpc_conflict(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, start_oob

    _seed_live_oob_state(tmp_path)
    commands: list[list[str]] = []
    kill_commands: list[str] = []
    conflict_log = (
        "2026-05-19 10:00:00 [I] [proxy_manager.go:144] [abc] proxy added: [host-oob]\n"
        "2026-05-19 10:00:01 [W] [control.go:148] [abc] [host-oob] start error: "
        "port already used: listen udp :53: bind: address already in use\n"
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        cmd = argv[-1] if len(argv) >= 5 else ""
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "tmux has-session -t oob-server" in cmd and "tmux new-session" not in cmd:
            return DockerResult(1, "", "")
        if "tmux has-session -t frpc" in cmd and "tmux new-session" not in cmd:
            return DockerResult(1, "", "")
        if "tail -n 200 /data/oob/frpc.log" in cmd:
            return DockerResult(0, conflict_log, "")
        if "tmux kill-session" in cmd:
            kill_commands.append(cmd)
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit) as excinfo:
        start_oob(
            OobOptions(
                install_root=tmp_path,
                frp_host="cal.example.test",
                frp_port=7000,
                frp_token="secret",
                oob_domain="oob.example.test",
            ),
            runner=runner,
            frpc_ready_timeout=1.0,
        )

    message = str(excinfo.value)
    assert "OOB resources are already held" in message
    assert "port already used" in message
    assert any("tmux kill-session -t frpc" in c for c in kill_commands)
    assert any("tmux kill-session -t oob-server" in c for c in kill_commands)


def test_oob_start_post_flight_returns_on_success(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, start_oob

    _seed_live_oob_state(tmp_path)
    success_log = (
        "2026-05-19 10:00:00 [I] [proxy_manager.go:144] [xyz] proxy added: [host-oob host-oob-dns host-oob-rev]\n"
        "2026-05-19 10:00:01 [I] [control.go:172] [xyz] [host-oob-dns] start proxy success\n"
        "2026-05-19 10:00:01 [I] [control.go:172] [xyz] [host-oob] start proxy success\n"
        "2026-05-19 10:00:01 [I] [control.go:172] [xyz] [host-oob-rev] start proxy success\n"
    )
    tail_calls = 0

    def runner(argv: list[str], **_: object) -> DockerResult:
        nonlocal tail_calls
        cmd = argv[-1] if len(argv) >= 5 else ""
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "tmux has-session" in cmd and "tmux new-session" not in cmd:
            return DockerResult(1, "", "")
        if "tail -n 200 /data/oob/frpc.log" in cmd:
            tail_calls += 1
            return DockerResult(0, success_log, "")
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
        frpc_ready_timeout=5.0,
    )
    # Reaching here without hitting the 5s timeout means the scan saw success
    # for all rendered proxies on the first poll and returned immediately.
    assert tail_calls == 1


def test_oob_start_post_flight_reports_relay_rejection(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, _check_frpc_for_conflicts

    rejection = "[W] [host-oob] start error: proxy 'host-oob' is not registered\n"
    killed: list[str] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1]
        if "tail -n 200 /data/oob/frpc.log" in command:
            return DockerResult(0, rejection, "")
        if "tmux kill-session" in command:
            killed.append(command)
            return DockerResult(0, "", "")
        if command.startswith("pkill -f "):
            return DockerResult(0, "", "")
        raise AssertionError(f"unexpected command: {command}")

    with pytest.raises(SystemExit) as excinfo:
        _check_frpc_for_conflicts(
            OobOptions(install_root=tmp_path, oob_domain="slot.oob.example.com"),
            runner=runner,
            timeout=1.0,
            sleep=lambda _seconds: None,
        )

    message = str(excinfo.value)
    assert "relay rejected" in message.lower()
    assert rejection.strip() in message
    assert any("tmux kill-session -t frpc" in command for command in killed)
    assert any("tmux kill-session -t oob-server" in command for command in killed)


def test_oob_start_post_flight_waits_for_all_frpc_proxy_successes(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, _check_frpc_for_conflicts

    partial_success_log = "2026-05-19 10:00:01 [I] [control.go:172] [xyz] [host-oob] start proxy success\n"
    mixed_failure_log = (
        partial_success_log
        + "2026-05-19 10:00:02 [W] [control.go:148] [xyz] [host-oob-dns] start error: "
        "port already used: listen udp :53: bind: address already in use\n"
    )
    tail_calls = 0
    kill_commands: list[str] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        nonlocal tail_calls
        cmd = argv[-1] if len(argv) >= 5 else ""
        if "tail -n 200 /data/oob/frpc.log" in cmd:
            tail_calls += 1
            return DockerResult(0, partial_success_log if tail_calls == 1 else mixed_failure_log, "")
        if "tmux kill-session" in cmd:
            kill_commands.append(cmd)
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit) as excinfo:
        _check_frpc_for_conflicts(
            OobOptions(
                install_root=tmp_path,
                frp_host="cal.example.test",
                frp_port=7000,
                frp_token="secret",
                oob_domain="oob.example.test",
            ),
            runner=runner,
            timeout=5.0,
            sleep=lambda _seconds: None,
        )

    message = str(excinfo.value)
    assert "OOB resources are already held" in message
    assert "port already used" in message
    assert tail_calls == 2
    assert any("tmux kill-session -t frpc" in c for c in kill_commands)


def test_oob_start_post_flight_resets_frpc_log_before_scan(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, start_oob

    _seed_live_oob_state(tmp_path)
    log_reset = False
    tail_calls = 0
    stale_conflict_log = "2026-05-19 [W] start error: port already used: listen udp :53\n"
    current_success_log = (
        "2026-05-21 [I] [host-oob-dns] start proxy success\n"
        "2026-05-21 [I] [host-oob] start proxy success\n"
        "2026-05-21 [I] [host-oob-rev] start proxy success\n"
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        nonlocal log_reset, tail_calls
        cmd = argv[-1] if len(argv) >= 5 else ""
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "tmux has-session" in cmd and "tmux new-session" not in cmd:
            return DockerResult(1, "", "")
        if ": > /data/oob/frpc.log" in cmd:
            log_reset = True
            return DockerResult(0, "", "")
        if "tail -n 200 /data/oob/frpc.log" in cmd:
            tail_calls += 1
            return DockerResult(0, current_success_log if log_reset else stale_conflict_log, "")
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
        frpc_ready_timeout=5.0,
    )

    assert log_reset is True
    assert tail_calls == 1


def test_oob_client_start_uses_session_file_for_domain_resume(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, start_oob_client

    commands: list[list[str]] = []
    runtime_route = json.dumps(
        {
            "version": 1,
            "slot_prefix": "legacy",
            "oob_domain": "oob.example.test",
            "dns_remote_port": 53,
            "reverse_remote_port": 8443,
        }
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if argv[-1].startswith("cat ") and "active-relay-routing.json" in argv[-1]:
            return DockerResult(0, runtime_route, "")
        if argv[:3] == ["docker", "exec", "vigil"] and "tmux has-session -t oob-client-demo" in argv[-1] and "tmux new-session" not in argv[-1]:
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
    from vigil_cli import up as up_module

    calls: list[str] = []

    monkeypatch.setattr(up_module, "image_outdated", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module, "_runtime_image_drift", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module, "proxy_image_drift", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module.docker, "container_running", lambda name, runner=None: True)
    monkeypatch.setattr(up_module, "start_runtime", lambda *args, **kwargs: calls.append("runtime"))
    monkeypatch.setattr(up_module, "start_proxy", lambda *args, **kwargs: calls.append("mitmproxy"))
    monkeypatch.setattr(
        up_module,
        "oob_status",
        lambda *a, **k: {
            "state": "partial",
            "server": False,
            "frpc": True,
            "clients": ["demo"],
            "route_matches": True,
        },
    )
    monkeypatch.setattr(up_module, "start_oob", lambda *args, **kwargs: calls.append("oob"))
    monkeypatch.setattr(up_module, "start_orchestrator", lambda *args, **kwargs: calls.append("orchestrator"))

    up_module.run_up(up_module.UpOptions(install_root=tmp_path), runner=lambda *args, **kwargs: None)

    assert calls == ["runtime", "orchestrator"]


def test_up_skips_oob_when_only_client_sessions_exist_but_endpoint_is_unconfigured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import up as up_module

    calls: list[str] = []

    monkeypatch.setattr(up_module, "image_outdated", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module, "_runtime_image_drift", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module, "proxy_image_drift", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module.docker, "container_running", lambda name, runner=None: True)
    monkeypatch.setattr(up_module, "start_runtime", lambda *args, **kwargs: calls.append("runtime"))
    monkeypatch.setattr(up_module, "start_orchestrator", lambda *args, **kwargs: calls.append("orchestrator"))
    monkeypatch.setattr(
        up_module,
        "oob_status",
        lambda *a, **k: {"state": "partial", "server": False, "frpc": False, "clients": ["demo"]},
    )
    monkeypatch.setattr(
        up_module,
        "_oob_options",
        lambda install_root: up_module.OobOptions(install_root=install_root, frp_token="secret"),
    )
    monkeypatch.setattr(up_module, "start_oob", lambda *args, **kwargs: calls.append("oob"))

    up_module.run_up(up_module.UpOptions(install_root=tmp_path), runner=lambda *args, **kwargs: None)

    assert calls == ["runtime", "orchestrator"]
    output = capsys.readouterr().out
    assert "oob\tskipped; infrastructure is not configured" in output
    assert "vigil config set oob.frp_host <host>" in output
    assert "vigil config set oob.domain <domain>" in output


def test_up_does_not_prompt_for_token_until_oob_endpoint_is_configured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import up as up_module

    calls: list[str] = []

    monkeypatch.setattr(up_module, "image_outdated", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module, "_runtime_image_drift", lambda *args, **kwargs: False)
    monkeypatch.setattr(up_module.docker, "container_running", lambda name, runner=None: name == "vigil")
    monkeypatch.setattr(up_module, "start_runtime", lambda *args, **kwargs: calls.append("runtime"))
    monkeypatch.setattr(up_module, "start_proxy", lambda *args, **kwargs: calls.append("mitmproxy"))
    monkeypatch.setattr(up_module, "start_orchestrator", lambda *args, **kwargs: calls.append("orchestrator"))
    monkeypatch.setattr(
        up_module,
        "oob_status",
        lambda *a, **k: {"state": "stopped", "server": False, "frpc": False, "clients": []},
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

    assert calls == ["runtime", "orchestrator", "mitmproxy"]
    output = capsys.readouterr().out
    assert "oob\tskipped; infrastructure is not configured" in output
    assert "vigil config set oob.frp_host <host>" in output


def test_up_passes_injected_runner_to_image_builds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import up as up_module

    seen: dict[str, object] = {}

    def fake_runner(*_args, **_kwargs):
        return None

    monkeypatch.setattr(up_module, "resolve_application_root", lambda *_args, **_kwargs: repo_root)
    monkeypatch.setattr(up_module, "initialize_workspace", lambda *args, **kwargs: None)
    monkeypatch.setattr(up_module.docker, "container_running", lambda name, runner=None: False)
    monkeypatch.setattr(up_module, "image_outdated", lambda *args, **kwargs: True)
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

    def fake_build_runner(*_args, **_kwargs):
        return None

    up_module.run_up(
        up_module.UpOptions(install_root=tmp_path),
        runner=fake_runner,
        build_runner=fake_build_runner,
    )

    # Builds take `build_runner`, never the caller's bounded metadata `runner`:
    # the 20s bound that makes a wedged daemon fail fast would kill a cold image
    # build outright.
    assert seen["runtime_runner"] is fake_build_runner
    assert seen["mitmproxy_runner"] is fake_build_runner


# ---------------------------------------------------------------------------
# Image freshness + proxy container/image drift
# ---------------------------------------------------------------------------


def _make_mitmproxy_inputs(install_root: Path) -> tuple[Path, Path]:
    """Create the Dockerfile + addon that gate mitmproxy image freshness."""
    dockerfile = install_root / "agent" / "docker" / "mitmproxy" / "Dockerfile"
    dockerfile.parent.mkdir(parents=True)
    dockerfile.write_text("FROM python:3.12-slim\n", encoding="utf-8")
    addon = install_root / "agent" / "scripts" / "proxy_addon.py"
    addon.parent.mkdir(parents=True)
    addon.write_text("# addon\n", encoding="utf-8")
    assess = install_root / "agent" / "scripts" / "assess"
    assess.mkdir()
    (assess / "__init__.py").write_text("", encoding="utf-8")
    (install_root / "orchestrator").mkdir(exist_ok=True)
    canonical = install_root / "cli" / "vigil_cli" / "scope_entries.py"
    canonical.parent.mkdir(parents=True)
    shutil.copy2(repo_root / "src" / "vigil_cli" / "scope_entries.py", canonical)
    os.environ["VIGIL_APPLICATION_DIR"] = str(install_root)
    return dockerfile, addon


def test_runtime_build_refuses_before_streaming_when_docker_daemon_is_unresponsive(
    tmp_path: Path,
) -> None:
    from vigil_cli import docker as docker_module
    from vigil_cli import runtime as runtime_module

    build_called = False

    def streaming_runner(argv: list[str], **_kwargs: object) -> docker_module.DockerResult:
        nonlocal build_called
        build_called = argv[:2] == ["docker", "build"]
        return docker_module.DockerResult(0, "", "")

    def daemon_runner(
        _argv: list[str], **_kwargs: object
    ) -> docker_module.DockerResult:
        return docker_module.DockerResult(
            docker_module.TIMEOUT_RETURNCODE,
            "",
            "docker command timed out after 20s (daemon unresponsive?)",
        )

    with pytest.raises(SystemExit, match="Docker is not responding"):
        runtime_module.build_runtime(
            tmp_path,
            runner=streaming_runner,
            daemon_runner=daemon_runner,
        )

    assert build_called is False


def test_mitmproxy_build_refuses_before_streaming_when_docker_daemon_is_unresponsive(
    tmp_path: Path,
) -> None:
    from vigil_cli import docker as docker_module
    from vigil_cli import mitmproxy as mitmproxy_module

    install_root = tmp_path / "install"
    _make_mitmproxy_inputs(install_root)
    build_called = False

    def metadata_runner(argv: list[str], **_kwargs: object) -> docker_module.DockerResult:
        assert argv == ["docker", "info"]
        return docker_module.DockerResult(
            docker_module.TIMEOUT_RETURNCODE,
            "",
            "docker command timed out after 20s (daemon unresponsive?)",
        )

    def streaming_runner(argv: list[str], **_kwargs: object) -> docker_module.DockerResult:
        nonlocal build_called
        build_called = argv[:2] == ["docker", "build"]
        return docker_module.DockerResult(0, "", "")

    with pytest.raises(SystemExit, match="Docker is not responding"):
        mitmproxy_module.build_image(
            install_root,
            force=True,
            runner=metadata_runner,
            build_runner=streaming_runner,
        )

    assert build_called is False


def _mitmproxy_digest(install_root: Path) -> str:
    from vigil_cli import image_freshness
    from vigil_cli.mitmproxy import mitmproxy_image_inputs

    resolved = install_root.expanduser().resolve()
    return image_freshness.inputs_digest(mitmproxy_image_inputs(resolved), root=resolved)


def _label_runner(commands: list[list[str]], label: str):
    """Fake docker runner: the tag EXISTS and carries ``label`` as its input digest."""
    from vigil_cli.docker import DockerResult

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:4] == ["docker", "image", "inspect", "-f"]:
            return DockerResult(0, f"{label}\n", "")
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        return DockerResult(0, "", "")

    return runner


def test_mitmproxy_build_reports_current_when_image_digest_matches_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import mitmproxy as mitmproxy_module

    install_root = tmp_path / "install"
    _make_mitmproxy_inputs(install_root)
    commands: list[list[str]] = []

    mitmproxy_module.build_image(
        install_root, runner=_label_runner(commands, _mitmproxy_digest(install_root))
    )

    out = capsys.readouterr().out
    assert "image current (up to date with source)" in out
    assert not any(cmd[:2] == ["docker", "build"] for cmd in commands)


def test_mitmproxy_build_rebuilds_when_inputs_changed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import mitmproxy as mitmproxy_module

    install_root = tmp_path / "install"
    _, addon = _make_mitmproxy_inputs(install_root)
    stamped = _mitmproxy_digest(install_root)
    addon.write_text("# addon changed\n", encoding="utf-8")
    commands: list[list[str]] = []

    mitmproxy_module.build_image(install_root, runner=_label_runner(commands, stamped))

    out = capsys.readouterr().out
    assert "image current" not in out
    build = next(cmd for cmd in commands if cmd[:3] == ["docker", "build", "-t"])
    # The rebuild re-stamps the CURRENT digest, so the next check reads `current`
    # instead of rebuilding again forever.
    assert build[build.index("--label") + 1] == (
        f"com.vigil.runtime-inputs-sha256={_mitmproxy_digest(install_root)}"
    )
    assert "image built" in out


def test_mitmproxy_build_rebuilds_when_assess_package_changes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import mitmproxy as mitmproxy_module

    install_root = tmp_path / "install"
    _make_mitmproxy_inputs(install_root)
    helper = install_root / "agent" / "scripts" / "assess" / "lib" / "scope.py"
    helper.parent.mkdir(parents=True)
    helper.write_text("# current helper\n", encoding="utf-8")
    stamped = _mitmproxy_digest(install_root)
    helper.write_text("# helper changed\n", encoding="utf-8")
    commands: list[list[str]] = []

    mitmproxy_module.build_image(install_root, runner=_label_runner(commands, stamped))

    assert any(command[:3] == ["docker", "build", "-t"] for command in commands)
    assert "image built" in capsys.readouterr().out


def test_mitmproxy_freshness_detects_canonical_scope_parser_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import mitmproxy as mitmproxy_module

    install_root = tmp_path / "install"
    _make_mitmproxy_inputs(install_root)
    canonical = install_root / "cli" / "vigil_cli" / "scope_entries.py"
    canonical.write_text("# canonical v1\n", encoding="utf-8")
    stamped = _mitmproxy_digest(install_root)

    canonical.write_text("# canonical v2\n", encoding="utf-8")

    assert _mitmproxy_digest(install_root) != stamped
    commands: list[list[str]] = []
    mitmproxy_module.build_image(install_root, runner=_label_runner(commands, stamped))
    assert any(command[:3] == ["docker", "build", "-t"] for command in commands)


def test_mitmproxy_freshness_ignores_bytecode_and_cache_churn(tmp_path: Path) -> None:
    """Regression: the proxy image rebuilt on EVERY `vigil up`, forever.

    Freshness used to be an mtime high-water mark over the whole
    `agent/scripts/assess` directory, and every ordinary `vigil assess` run
    rewrites `__pycache__/*.pyc` under the install root — so the newest "input"
    was always newer than the image Vigil had just built. Bytecode and tool
    caches are build ARTIFACTS, never inputs, and must not move the digest.
    """
    from vigil_cli import mitmproxy as mitmproxy_module

    install_root = tmp_path / "install"
    _make_mitmproxy_inputs(install_root)
    assess = install_root / "agent" / "scripts" / "assess" / "lib"
    assess.mkdir(parents=True)
    (assess / "scope.py").write_text("# helper\n", encoding="utf-8")
    stamped = _mitmproxy_digest(install_root)

    # Exactly what an assess run leaves behind, all stamped in the far future.
    cache = assess / "__pycache__"
    cache.mkdir()
    (cache / "scope.cpython-312.pyc").write_bytes(b"\x00bytecode\x00")
    (assess / "scope.pyc").write_bytes(b"\x00loose\x00")
    for junk in (".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules", ".venv"):
        directory = install_root / "agent" / "scripts" / "assess" / junk
        directory.mkdir(parents=True)
        (directory / "artifact").write_text("junk\n", encoding="utf-8")
    future = 4_000_000_000
    for path in (install_root / "agent" / "scripts" / "assess").rglob("*"):
        os.utime(path, (future, future))

    assert _mitmproxy_digest(install_root) == stamped
    commands: list[list[str]] = []
    mitmproxy_module.build_image(install_root, runner=_label_runner(commands, stamped))
    assert not any(cmd[:2] == ["docker", "build"] for cmd in commands)


def test_mitmproxy_freshness_detects_deleted_input(tmp_path: Path) -> None:
    """Regression: deleting a baked input left the image reading as current.

    An mtime high-water mark only stats files that still EXIST, so an upgrade
    that merely REMOVES an enforcement/classification module under
    `agent/scripts/assess` never invalidated the image and the deleted code kept
    running inside the proxy.
    """
    from vigil_cli import mitmproxy as mitmproxy_module

    install_root = tmp_path / "install"
    _make_mitmproxy_inputs(install_root)
    assess = install_root / "agent" / "scripts" / "assess" / "lib"
    assess.mkdir(parents=True)
    (assess / "scope.py").write_text("# helper\n", encoding="utf-8")
    retired = assess / "retired_classifier.py"
    retired.write_text("# removed by the upgrade\n", encoding="utf-8")
    stamped = _mitmproxy_digest(install_root)

    retired.unlink()

    assert _mitmproxy_digest(install_root) != stamped
    commands: list[list[str]] = []
    mitmproxy_module.build_image(install_root, runner=_label_runner(commands, stamped))
    assert any(cmd[:3] == ["docker", "build", "-t"] for cmd in commands)


def test_mitmproxy_build_stamps_digest_so_the_next_check_is_current(tmp_path: Path) -> None:
    """A build must stamp the digest: an UNSTAMPED image can never be proven
    current, so `vigil up` would rebuild it on every run."""
    from vigil_cli import mitmproxy as mitmproxy_module

    install_root = tmp_path / "install"
    _make_mitmproxy_inputs(install_root)
    commands: list[list[str]] = []

    # No label on the image yet (built before digest stamping) -> must rebuild.
    mitmproxy_module.build_image(install_root, runner=_label_runner(commands, "<no value>"))
    build = next(cmd for cmd in commands if cmd[:3] == ["docker", "build", "-t"])
    stamped = build[build.index("--label") + 1].split("=", 1)[1]

    # Feed that stamp back in: the very next check is `current`, no rebuild.
    follow_up: list[list[str]] = []
    mitmproxy_module.build_image(install_root, runner=_label_runner(follow_up, stamped))
    assert not any(cmd[:2] == ["docker", "build"] for cmd in follow_up)


def test_up_mitmproxy_build_stamps_digest_label(tmp_path: Path) -> None:
    """`vigil up` built the proxy image through its own argv, which omitted the
    label — so its own rebuild left the image unprovable and the next `vigil up`
    rebuilt it again. It must go through the one builder."""
    from vigil_cli import up as up_module

    install_root = tmp_path / "install"
    _make_mitmproxy_inputs(install_root)
    commands: list[list[str]] = []

    up_module._build_mitmproxy_image(
        install_root, runner=_label_runner(commands, "<no value>")
    )

    build = next(cmd for cmd in commands if cmd[:3] == ["docker", "build", "-t"])
    assert build[build.index("--label") + 1] == (
        f"com.vigil.runtime-inputs-sha256={_mitmproxy_digest(install_root)}"
    )


def test_mitmproxy_build_force_uses_no_cache_even_when_fresh(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import mitmproxy as mitmproxy_module

    install_root = tmp_path / "install"
    _make_mitmproxy_inputs(install_root)
    commands: list[list[str]] = []

    mitmproxy_module.build_image(
        install_root, force=True, runner=_label_runner(commands, _mitmproxy_digest(install_root))
    )

    build_command = next(cmd for cmd in commands if cmd[:2] == ["docker", "build"])
    assert "--no-cache" in build_command
    assert "image current" not in capsys.readouterr().out


def test_proxy_image_drift_true_when_container_predates_image() -> None:
    from vigil_cli import image_freshness
    from vigil_cli import up as up_module
    from vigil_cli.docker import DockerResult

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "inspect", "-f"] and argv[3] == "{{.Image}}":
            return DockerResult(0, "sha256:old-container-image\n", "")
        if argv[:4] == ["docker", "image", "inspect", "-f"] and argv[4] == "{{.Id}}":
            return DockerResult(0, "sha256:new-tag-image\n", "")
        return DockerResult(0, "", "")

    assert image_freshness.proxy_image_drift(runner=runner) is True
    # up.py imports and calls the shared function directly (no thin wrapper).
    assert up_module.proxy_image_drift(runner=runner) is True


def test_proxy_image_drift_false_when_ids_match() -> None:
    from vigil_cli import image_freshness
    from vigil_cli.docker import DockerResult

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "inspect", "-f"] and argv[3] == "{{.Image}}":
            return DockerResult(0, "sha256:same\n", "")
        if argv[:4] == ["docker", "image", "inspect", "-f"] and argv[4] == "{{.Id}}":
            return DockerResult(0, "sha256:same\n", "")
        return DockerResult(0, "", "")

    assert image_freshness.proxy_image_drift(runner=runner) is False


def test_proxy_image_drift_false_when_container_absent() -> None:
    from vigil_cli import image_freshness
    from vigil_cli.docker import DockerResult

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "inspect", "-f"] and argv[3] == "{{.Image}}":
            return DockerResult(1, "", "No such object")
        if argv[:4] == ["docker", "image", "inspect", "-f"] and argv[4] == "{{.Id}}":
            return DockerResult(0, "sha256:new-tag-image\n", "")
        return DockerResult(0, "", "")

    assert image_freshness.proxy_image_drift(runner=runner) is False


def test_up_warns_when_proxy_container_predates_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import up as up_module

    calls: list[str] = []
    monkeypatch.setattr(up_module, "resolve_application_root", lambda *_a, **_k: repo_root)
    monkeypatch.setattr(up_module, "initialize_workspace", lambda *a, **k: None)
    monkeypatch.setattr(up_module, "image_outdated", lambda *a, **k: False)
    monkeypatch.setattr(up_module, "_runtime_image_drift", lambda *a, **k: False)
    monkeypatch.setattr(up_module, "proxy_image_drift", lambda **k: True)
    monkeypatch.setattr(up_module.docker, "container_running", lambda name, runner=None: True)
    monkeypatch.setattr(up_module, "start_runtime", lambda *a, **k: calls.append("runtime"))
    monkeypatch.setattr(up_module, "start_proxy", lambda *a, **k: calls.append("mitmproxy"))
    monkeypatch.setattr(up_module, "start_orchestrator", lambda *a, **k: calls.append("orchestrator"))
    monkeypatch.setattr(
        up_module,
        "oob_status",
        lambda *a, **k: {"state": "partial", "server": True, "frpc": True, "clients": []},
    )
    monkeypatch.setattr(up_module, "start_oob", lambda *a, **k: calls.append("oob"))

    up_module.run_up(up_module.UpOptions(install_root=tmp_path), runner=lambda *a, **k: None)

    out = capsys.readouterr().out
    assert "running old image; restart to pick up rebuilt image" in out
    assert "Run `vigil mitmproxy start` to recreate the container on the current image." in out
    # The proxy is already running, so `up` warns instead of recreating it.
    assert "mitmproxy" not in calls


def test_status_payload_reports_mitmproxy_image_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import status as status_module
    from vigil_cli.docker import DockerResult

    _isolate_orchestrator_url(monkeypatch)
    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil-proxy\n", "")
        if argv[:3] == ["docker", "inspect", "-f"] and argv[3] == "{{.Image}}":
            return DockerResult(0, "sha256:old\n", "")
        if argv[:4] == ["docker", "image", "inspect", "-f"] and argv[4] == "{{.Id}}":
            return DockerResult(0, "sha256:new\n", "")
        return DockerResult(0, "", "")

    status = status_module.collect_status(install_root, runner=runner)
    assert status["mitmproxy"]["image_drift"] is True

    status_module.print_status(status)


def test_status_print_shows_restart_needed_on_drift(capsys: pytest.CaptureFixture[str]) -> None:
    from vigil_cli.status import print_status

    print_status(_minimal_status(mitmproxy={"state": "running", "ca_volume": True, "image_drift": True}))
    out = capsys.readouterr().out
    mitm_line = next(line for line in out.splitlines() if line.startswith("mitmproxy\t"))
    assert "restart-needed" in mitm_line


def test_doctor_reports_mitmproxy_container_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import status as status_module
    from vigil_cli.docker import DockerResult

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil-proxy\n", "")
        if argv[:3] == ["docker", "inspect", "-f"] and argv[3] == "{{.Image}}":
            return DockerResult(0, "sha256:old\n", "")
        if argv[:4] == ["docker", "image", "inspect", "-f"] and argv[4] == "{{.Id}}":
            return DockerResult(0, "sha256:new\n", "")
        return DockerResult(0, "ok", "")

    monkeypatch.setattr(status_module.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(
        status_module.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0] if a else [], 0, "ok", ""),
    )
    monkeypatch.setattr(status_module, "runtime_status", lambda **k: "stopped")

    checks = status_module.collect_doctor_checks(tmp_path, runner=runner)
    drift = next(c for c in checks if c.name == "mitmproxy-container-drift")
    assert drift.status == "STALE"
    assert "vigil mitmproxy start" in drift.detail


# ---------------------------------------------------------------------------
# Mutation-helper coverage
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


class _FakeWorkBufferClient:
    """In-memory AssessmentClient stand-in for the backend work buffer.

    The per-engagement local ``cases.db`` ``work_items`` table was folded into
    the orchestrator backend as ``assessment_work_items`` and is now reached over
    HTTP (ADR 0013). These CLI tests therefore drive ``dispatch.run`` /
    ``list_clusters.run`` against this fake instead of a real SQLite file. Reads
    (``get`` / ``get_all_pages``) serve the seeded row dicts honoring the
    ``?status=`` / ``?type=`` filters the commands use; writes (``post``) capture
    the exact ``(endpoint, payload)`` on ``self.posts`` and return a plausible
    ``{"affected": N}`` / ``{"claimed": [...]}`` ack. The former cases.db row-state
    assertions are re-expressed against these captured POSTs — the durable row
    mutation itself is covered server-side by tests/test_work_buffer_backend.py.
    """

    def __init__(self, rows=None, *, fetch_response=None):
        # Normalize seeded rows: default status "pending" (matching the old
        # SQLite column default) so defer/list-cluster status filters behave.
        self.rows: list[dict] = []
        for row in rows or []:
            normalized = dict(row)
            normalized.setdefault("status", "pending")
            self.rows.append(normalized)
        self.posts: list[tuple[str, dict]] = []
        self.fetch_response = fetch_response

    def _match_status(self, endpoint: str, row: dict) -> bool:
        import re as _re

        m = _re.search(r"status=([^&]+)", endpoint)
        if not m:
            return True
        return str(row.get("status") or "pending") == m.group(1)

    def get_all_pages(self, endpoint: str, *, page_size: int = 5000):
        return [dict(r) for r in self.rows if self._match_status(endpoint, r)]

    def get(self, endpoint: str):
        return [dict(r) for r in self.rows if self._match_status(endpoint, r)]

    def post(self, endpoint: str, payload: dict):
        self.posts.append((endpoint, payload))
        if endpoint == "work-items/fetch-by-priority" and self.fetch_response is not None:
            return dict(self.fetch_response)
        if endpoint == "work-items/defer":
            # The backend defers only PENDING rows; mirror that so the
            # zero-matched-rows path still exits non-zero.
            ids = set(payload.get("ids") or [])
            affected = sum(
                1
                for r in self.rows
                if r.get("id") in ids and str(r.get("status") or "pending") == "pending"
            )
            return {"affected": affected}
        if endpoint in ("work-items/fetch", "work-items/fetch-by-priority"):
            return {"claimed": [], "non_routable": [], "allowed_types": []}
        # done / error / mark-manual / defer-cluster / reset-stale / retry-errors
        # all just need a numeric ack the CLI echoes back.
        return {"affected": len(payload.get("ids") or [])}

    def close(self) -> None:
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def test_resolve_surface_requires_rationale(capsys: pytest.CaptureFixture[str]) -> None:
    """P1 #2: --rationale is required so the audit trail is never empty (merged `resolve`)."""
    assess_main = _load_assess_main()
    with pytest.raises(SystemExit):
        assess_main(["resolve", "surface", "1", "--status", "covered"])
    err = capsys.readouterr().err
    assert "--rationale" in err


def test_resolve_surface_rejects_empty_rationale(capsys: pytest.CaptureFixture[str]) -> None:
    """P1 #2: --rationale='' surfaces an early error before HTTP."""
    assess_main = _load_assess_main()
    with pytest.raises(SystemExit):
        assess_main(["resolve", "surface", "1", "--status", "covered", "--rationale", "   "])
    assert "--rationale must be non-empty" in capsys.readouterr().err


def test_resolve_surface_rejects_invalid_status(capsys: pytest.CaptureFixture[str]) -> None:
    """P3 #1: an out-of-vocab --status is rejected in run() with a scoped error + pointer."""
    assess_main = _load_assess_main()
    with pytest.raises(SystemExit):
        assess_main(["resolve", "surface", "1", "--status", "BOGUS", "--rationale", "x"])
    err = capsys.readouterr().err
    assert "invalid status" in err
    assert "See: vigil assess contract resolve" in err


def test_resolve_surface_partially_covered_requires_followup_condition(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """N7 — `--status partially-covered` without `--followup-condition` exits with a clear error."""
    assess_main = _load_assess_main()
    with pytest.raises(SystemExit):
        assess_main(
            [
                "resolve",
                "surface",
                "1",
                "--status",
                "partially-covered",
                "--rationale",
                "unauth path tested",
            ]
        )
    message = capsys.readouterr().err
    assert "--followup-condition" in message
    assert "partially-covered" in message


def test_resolve_surface_accepts_partially_covered_with_followup_condition(
    monkeypatch, tmp_path: Path
) -> None:
    """N7 — round-trip: `resolve surface ... partially-covered` with a follow-up
    condition reaches the backend client with `followup_condition`."""
    module = _load_assess_module(
        "round3_resolve_module",
        "agent/scripts/assess/commands/resolve.py",
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
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

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
            target_kind="surface",
            ids=["42"],
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
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

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
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

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
            assert path == "code/readiness?target_phase=classify-map"
            return {
                "target_phase": "classify-map",
                "transition_ready": True,
                "blockers": [],
                "quality_gate": {"passed": True, "warnings": []},
            }

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

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


def test_transition_phase_both_missing_code_phase_requires_supported_repair(
    monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_assess_module(
        "transition_phase_missing_code_phase_module",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    engagement = tmp_path / "agent" / "engagements" / "eng-test"
    engagement.mkdir(parents=True)
    scope_path = engagement / "scope.json"
    scope_path.write_text(
        json.dumps({"engagement_type": "both", "current_phase": "collect"}),
        encoding="utf-8",
    )
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
                target_phase="classify-map",
                force=False,
                track="code",
                reason="",
            )
        )

    assert exc.value.code == 2
    assert "repair-tracks" in capsys.readouterr().err
    assert "code_phase" not in json.loads(scope_path.read_text(encoding="utf-8"))


def test_transition_phase_both_completes_only_after_each_track(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_assess_module(
        "transition_phase_aggregate_completion_module",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    engagement = tmp_path / "agent" / "engagements" / "eng-test"
    engagement.mkdir(parents=True)
    scope_path = engagement / "scope.json"
    scope_path.write_text(
        json.dumps(
            {
                "engagement_type": "both",
                "current_phase": "report",
                "code_phase": "fuzz",
                "status": "in_progress",
            }
        ),
        encoding="utf-8",
    )
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
    monkeypatch.setattr(module, "_check_preconditions", lambda *_args, **_kwargs: [])

    module.run(
        SimpleNamespace(
            engagement_dir=str(engagement),
            target_phase="complete",
            force=False,
            track="web",
            reason="",
        )
    )
    first = json.loads(scope_path.read_text(encoding="utf-8"))
    assert first["current_phase"] == "complete"
    assert first["code_phase"] == "fuzz"
    assert first["status"] == "in_progress"

    module.run(
        SimpleNamespace(
            engagement_dir=str(engagement),
            target_phase="complete",
            force=False,
            track="code",
            reason="",
        )
    )
    second = json.loads(scope_path.read_text(encoding="utf-8"))
    assert second["status"] == "completed"


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
        "verification_status": "confirmed",
        "workflow_status": "active",
    }
    older_variant_dispatch = {
        "agent_role": "vulnerability-analyst",
        "status": "completed",
        "dispatch_mode": "variant-rotation",
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
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

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


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


def _setup_transition_env(
    monkeypatch, module, tmp_path, *, scope, services=None, findings=None,
    dispatches=None, report_readiness=None, terminal_block=None,
    decisions_by_kind=None, work_items=None,
):
    engagement = tmp_path / "agent" / "engagements" / "eng-test"
    engagement.mkdir(parents=True, exist_ok=True)
    (engagement / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    decisions: list[dict] = []
    decisions_by_kind = decisions_by_kind or {}

    class _Client:
        def __init__(self, *_a, **_k) -> None:
            pass

        def get_all_pages(self, endpoint: str, *, page_size: int = 5000):
            # The work buffer now lives in the backend (assessment_work_items);
            # the consumption advisory / work-buffer gates read it via
            # get_all_pages("work-items..."). Serve the seeded rows (default [])
            # — see tests/test_work_buffer_backend.py for the backend contract.
            return list(work_items or [])

        def get(self, path: str):
            if path == "services":
                return services or []
            if path == "findings":
                return findings or []
            if path.startswith("dispatch-decisions"):
                for kind, rows in decisions_by_kind.items():
                    if f"kind={kind}" in path:
                        return rows
                return []
            if path.startswith("dispatches"):
                return dispatches or []
            if path == "report-readiness":
                return report_readiness or {"ready": True, "blockers": []}
            if path == "application-units/terminal-block":
                return terminal_block or {
                    "skipped": False, "blocking": [], "warned_under_observed": [],
                    "deferred": [], "deferral_count": 0,
                }
            return []

        def record_decision(self, payload):
            decisions.append(payload)
            return {"id": len(decisions)}

        def close(self) -> None:
            return None

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(engagement),
            engagement_key=engagement.name,
            agent_root=str(tmp_path / "agent"),
        ),
    )
    return engagement, decisions


def _transition_args(engagement, target_phase, **overrides):
    base = dict(
        engagement_dir=str(engagement),
        target_phase=target_phase,
        force=False,
        reason="",
        track="auto",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


_CONFIRMED_HIGH = {
    "slug": "ssrf-1",
    "severity": "high",
    "verification_status": "confirmed",
    "workflow_status": "active",
}


def test_transition_variant_gate_rejects_incomplete_dispatch(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_variant_incomplete", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "verify"},
        findings=[_CONFIRMED_HIGH],
        dispatches=[{
            "agent_role": "vulnerability-analyst",
            "status": "in-progress",
            "dispatch_mode": "variant-rotation",
            "finding_slugs": ["ssrf-1"],
        }],
    )
    with pytest.raises(SystemExit):
        module.run(_transition_args(eng, "exploit"))
    assert "missing_variant_pass" in capsys.readouterr().err


def test_transition_variant_gate_rejects_wrong_dispatch_mode(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_variant_wrongmode", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "verify"},
        findings=[_CONFIRMED_HIGH],
        dispatches=[{
            "agent_role": "vulnerability-analyst",
            "status": "completed",
            "dispatch_mode": "hypothesis-driven",
            "finding_slugs": ["ssrf-1"],
        }],
    )
    with pytest.raises(SystemExit):
        module.run(_transition_args(eng, "exploit"))
    assert "missing_variant_pass" in capsys.readouterr().err


def test_transition_variant_gate_satisfied_by_completed_variant_rotation(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_variant_ok", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "verify"},
        findings=[_CONFIRMED_HIGH],
        dispatches=[{
            "agent_role": "vulnerability-analyst",
            "status": "completed",
            "dispatch_mode": "variant-rotation",
            "finding_slugs": ["ssrf-1"],
        }],
    )
    module.run(_transition_args(eng, "exploit"))
    assert "missing_variant_pass" not in capsys.readouterr().err


def test_transition_backward_with_reason_succeeds_and_records_decision(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_backward_reason", "agent/scripts/assess/commands/transition_phase.py")
    eng, decisions = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
    )
    module.run(_transition_args(eng, "recon", reason="re-recon after new subdomain surfaced"))
    scope = json.loads((eng / "scope.json").read_text())
    assert scope["current_phase"] == "recon"
    assert len(decisions) == 1
    assert decisions[0]["kind"] == "phase_regression"
    assert "re-recon" in decisions[0]["payload"]["reason"]


def test_transition_backward_without_reason_or_force_refuses(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_backward_refuse", "agent/scripts/assess/commands/transition_phase.py")
    eng, decisions = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
    )
    with pytest.raises(SystemExit):
        module.run(_transition_args(eng, "recon"))
    assert "refusing backward transition" in capsys.readouterr().err
    assert decisions == []


def test_transition_force_override_records_decision(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_force_audit", "agent/scripts/assess/commands/transition_phase.py")
    eng, decisions = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "recon"},
        services=[],
    )
    module.run(_transition_args(eng, "collect", force=True, reason="services known-empty, internal host"))
    assert len(decisions) == 1
    assert decisions[0]["kind"] == "forced_transition_override"
    assert any(b["kind"] == "no_services" for b in decisions[0]["payload"]["overridden_blockers"])


def test_transition_generalized_walk_checks_intermediate_gates(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_walk", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "recon"},
        services=[], findings=[],
    )
    with pytest.raises(SystemExit):
        module.run(_transition_args(eng, "exploit"))
    err = capsys.readouterr().err
    assert "no_services" in err


def test_transition_verify_consumption_is_advisory_not_block(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_consume_advisory", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "consume-test"},
        findings=[{"slug": "f-1", "workflow_status": "active", "severity": "low"}],
        # One genuinely un-consumed pending item (no terminal_reason) drives the
        # consumption advisory. The work buffer is backend-owned now, so seed the
        # fake client's work-items instead of a local cases.db table.
        work_items=[{"id": 1, "status": "pending", "terminal_reason": None}],
    )
    module.run(_transition_args(eng, "verify"))
    err = capsys.readouterr().err
    assert "consumption_incomplete" in err
    assert "not blocking" in err.lower()
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "verify"


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
def _terminal_block_payload(*, blocking=None, warned=None, deferral_count=0):
    return {
        "skipped": False,
        "blocking": blocking or [],
        "warned_under_observed": warned or [],
        "deferred": [],
        "deferral_count": deferral_count,
    }


_BLOCKING_UNIT = {
    "unit": {"id": 1, "host": "auth.example.com", "path_prefix": "/login",
             "port_class": "web", "depth_tier": "app-unit", "confidence": "low"},
    "block_set_via": "decisive risk surface",
    "decisive_surface": True,
    "missing_block_families": ["auth", "access-control"],
}


def test_transition_report_depth_backstop_blocks(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_depth_report", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        terminal_block=_terminal_block_payload(blocking=[_BLOCKING_UNIT], deferral_count=2),
    )
    with pytest.raises(SystemExit):
        module.run(_transition_args(eng, "report"))
    err = capsys.readouterr().err
    assert "depth_unsatisfied_units" in err
    assert "auth.example.com/login" in err
    assert "depth_deferral" in err
    assert "--force --reason" in err
    assert "2 depth_deferral(s) already recorded" in err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "exploit"


def test_transition_complete_depth_backstop_blocks(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_depth_complete", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "report"},
        terminal_block=_terminal_block_payload(blocking=[_BLOCKING_UNIT]),
    )
    with pytest.raises(SystemExit):
        module.run(_transition_args(eng, "complete"))
    assert "depth_unsatisfied_units" in capsys.readouterr().err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"


def test_transition_report_depth_deferral_does_not_block(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_depth_deferred", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        terminal_block=_terminal_block_payload(blocking=[], deferral_count=1),
    )
    module.run(_transition_args(eng, "report"))
    assert "depth_unsatisfied_units" not in capsys.readouterr().err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"


def test_transition_report_depth_force_reason_proceeds_and_records(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_depth_force", "agent/scripts/assess/commands/transition_phase.py")
    eng, decisions = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        terminal_block=_terminal_block_payload(blocking=[_BLOCKING_UNIT]),
    )
    module.run(_transition_args(eng, "report", force=True,
                                reason="auth unit accepted-risk per client"))
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"
    assert len(decisions) == 1
    assert decisions[0]["kind"] == "forced_transition_override"
    assert any(b["kind"] == "depth_unsatisfied_units"
               for b in decisions[0]["payload"]["overridden_blockers"])


def test_transition_report_force_without_reason_proceeds_and_records(monkeypatch, tmp_path):
    module = _load_assess_module(
        "tp_depth_force_reason_optional",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    eng, decisions = _setup_transition_env(
        monkeypatch,
        module,
        tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        terminal_block=_terminal_block_payload(blocking=[_BLOCKING_UNIT]),
    )

    module.run(_transition_args(eng, "report", force=True))

    assert decisions[0]["kind"] == "forced_transition_override"
    assert decisions[0]["payload"]["reason"] == "(no reason given; --force)"
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"


# ---------------------------------------------------------------------------
# Coverage-grain unbundle (ADR 0012): the CLASS-grain terminal block. A
# decisive/high-confidence unit with `block_grain="class"` + uncovered_classes
# surfaces a `depth_uncovered_classes` blocker (naming the classes + the
# deferral escape), same ONE gate, same --force/--reason and depth_deferral
# valves as the family-grain `depth_unsatisfied_units` block.
# ---------------------------------------------------------------------------
_CLASS_BLOCKING_UNIT = {
    "unit": {"id": 2, "host": "api.example.com", "path_prefix": "/v2/orders",
             "port_class": "web", "depth_tier": "app-unit", "confidence": "high"},
    "block_set_via": "high-confidence deep_required",
    "decisive_surface": False,
    "block_grain": "class",
    "uncovered_classes": ["sqli", "idor"],
    "missing_block_families": [],
}


def test_transition_report_class_grain_block_names_classes(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_depth_classblock", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        terminal_block=_terminal_block_payload(blocking=[_CLASS_BLOCKING_UNIT],
                                               deferral_count=1),
    )
    with pytest.raises(SystemExit):
        module.run(_transition_args(eng, "report"))
    err = capsys.readouterr().err
    assert "depth_uncovered_classes" in err
    assert "api.example.com/v2/orders" in err
    assert "sqli" in err and "idor" in err
    assert "depth_deferral" in err
    assert "--force --reason" in err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "exploit"


def test_transition_report_class_grain_block_force_records(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_depth_classforce", "agent/scripts/assess/commands/transition_phase.py")
    eng, decisions = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        terminal_block=_terminal_block_payload(blocking=[_CLASS_BLOCKING_UNIT]),
    )
    module.run(_transition_args(eng, "report", force=True,
                                reason="sqli/idor class-tested out-of-band, evidence attached"))
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"
    assert len(decisions) == 1
    assert decisions[0]["kind"] == "forced_transition_override"
    assert any(b["kind"] == "depth_uncovered_classes"
               for b in decisions[0]["payload"]["overridden_blockers"])


def test_transition_report_both_grains_block_together(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_depth_bothgrain", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        terminal_block=_terminal_block_payload(
            blocking=[_BLOCKING_UNIT, _CLASS_BLOCKING_UNIT]),
    )
    with pytest.raises(SystemExit):
        module.run(_transition_args(eng, "report"))
    err = capsys.readouterr().err
    assert "depth_unsatisfied_units" in err       # family grain
    assert "depth_uncovered_classes" in err       # class grain
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "exploit"


def test_transition_report_under_observed_warns_not_blocks(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_depth_warn", "agent/scripts/assess/commands/transition_phase.py")
    warned_unit = {
        "unit": {"host": "blog.example.com", "path_prefix": "/about",
                 "port_class": "web", "confidence": "low"},
        "reason": "under-observed (low confidence, no decisive surface)",
        "missing_block_families": [], "missing_warn_families": ["disclosure"],
    }
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        terminal_block=_terminal_block_payload(blocking=[], warned=[warned_unit]),
    )
    module.run(_transition_args(eng, "report"))
    err = capsys.readouterr().err
    assert "depth_under_observed_units" in err
    assert "blog.example.com/about" in err
    assert "depth_unsatisfied_units" not in err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"


def test_transition_recon_to_report_jump_walks_depth_backstop(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_depth_walk", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "recon"},
        services=[{"endpoint": "h:443"}],
        findings=[{"slug": "f-1", "workflow_status": "active",
                   "severity": "low", "verification_status": "confirmed"}],
        report_readiness={"ready": True, "blockers": []},
        terminal_block=_terminal_block_payload(blocking=[_BLOCKING_UNIT]),
    )
    with pytest.raises(SystemExit):
        module.run(_transition_args(eng, "report"))
    err = capsys.readouterr().err
    assert "depth_unsatisfied_units" in err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "recon"


def test_transition_code_complete_unaffected_by_depth_backstop(monkeypatch, tmp_path, capsys):
    module = _load_assess_module("tp_depth_code", "agent/scripts/assess/commands/transition_phase.py")
    queried: list[str] = []
    eng = tmp_path / "agent" / "engagements" / "eng-code"
    eng.mkdir(parents=True, exist_ok=True)
    (eng / "scope.json").write_text(
        json.dumps({"engagement_type": "code", "current_phase": "fuzz"}), encoding="utf-8")

    class _Client:
        def __init__(self, *_a, **_k) -> None:
            pass
        def get(self, path: str):
            queried.append(path)
            if path == "code/readiness?target_phase=complete":
                return {
                    "target_phase": "complete",
                    "transition_ready": True,
                    "blockers": [],
                    "quality_gate": {"passed": True, "warnings": []},
                }
            if path == "findings":
                return []
            return []
        def close(self): return None
        def __enter__(self): return self
        def __exit__(self, *_e): return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(module, "load_config", lambda *_a, **_k: SimpleNamespace(
        base_url="http://example.test", engagement_dir=str(eng),
        engagement_key=eng.name, agent_root=str(tmp_path / "agent")))

    module.run(_transition_args(eng, "complete"))
    assert "code/readiness?target_phase=complete" in queried
    assert "application-units/terminal-block" not in queried
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "complete"


# ---------------------------------------------------------------------------
# Chain-construction pass gate (Exploit -> Report / -> complete).
# Mirrors the variant-pass gate: enumerates confirmed high/critical findings
# (>=2, since the chain runs ACROSS the confirmed set) and demands a COMPLETED
# exploit-developer dispatch on record. Hard `missing_chain_construction`
# blocker at the same enforcement level as `missing_variant_pass`.
# ---------------------------------------------------------------------------

_CONFIRMED_HIGH_2 = {
    "slug": "redirect-2",
    "severity": "high",
    "verification_status": "confirmed",
    "workflow_status": "active",
}


def _accept_verdicts(*slugs: str) -> dict[str, list[dict]]:
    """Blind-triage Accept verdict rows so the (separately-enforced)
    ``missing_blind_triage`` gate is satisfied and the chain gate is isolated.
    The report/complete edge runs both gates; these tests target only the chain
    gate, so they must clear blind-triage independently."""
    return {
        "blind_triage_verdict": [
            {"id": i, "kind": "blind_triage_verdict",
             "payload": {"finding_slug": slug, "verdict": "Accept@P3", "packet_id": "a" * 64}}
            for i, slug in enumerate(slugs, start=1)
        ]
    }


def test_transition_chain_gate_blocks_when_no_exploit_developer_dispatch(
    monkeypatch, tmp_path, capsys
):
    module = _load_assess_module("tp_chain_block", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        findings=[_CONFIRMED_HIGH, _CONFIRMED_HIGH_2],
        dispatches=[],
    )
    with pytest.raises(SystemExit):
        module.run(_transition_args(eng, "report"))
    err = capsys.readouterr().err
    assert "missing_chain_construction" in err
    assert "ssrf-1" in err
    # Phase must NOT have advanced.
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "exploit"


def test_transition_chain_gate_satisfied_by_completed_exploit_developer_dispatch(
    monkeypatch, tmp_path, capsys
):
    module = _load_assess_module("tp_chain_ok", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        findings=[_CONFIRMED_HIGH, _CONFIRMED_HIGH_2],
        dispatches=[{
            "agent_role": "exploit-developer",
            "status": "completed",
            "dispatch_mode": "deep-manual",
            "task": "chain A->B candidates across confirmed set",
        }],
        decisions_by_kind=_accept_verdicts("ssrf-1", "redirect-2"),
    )
    module.run(_transition_args(eng, "report"))
    assert "missing_chain_construction" not in capsys.readouterr().err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"


def test_transition_chain_gate_does_not_block_single_confirmed_finding(
    monkeypatch, tmp_path, capsys
):
    """Nothing to chain ACROSS with only one confirmed high/critical finding —
    the gate is conservative and never fires below two."""
    module = _load_assess_module("tp_chain_single", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        findings=[_CONFIRMED_HIGH],
        dispatches=[],
        decisions_by_kind=_accept_verdicts("ssrf-1"),
    )
    module.run(_transition_args(eng, "report"))
    assert "missing_chain_construction" not in capsys.readouterr().err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"


def test_transition_chain_gate_ignores_incomplete_exploit_developer_dispatch(
    monkeypatch, tmp_path, capsys
):
    """A still-running exploit-developer dispatch is not chain-pass evidence;
    the server-side ``status=completed`` filter excludes it (and the client-side
    re-check guards against a backend that ignores the filter)."""
    module = _load_assess_module("tp_chain_incomplete", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        findings=[_CONFIRMED_HIGH, _CONFIRMED_HIGH_2],
        dispatches=[{
            "agent_role": "exploit-developer",
            "status": "in-progress",
            "dispatch_mode": "deep-manual",
        }],
    )
    with pytest.raises(SystemExit):
        module.run(_transition_args(eng, "report"))
    assert "missing_chain_construction" in capsys.readouterr().err


def test_transition_chain_gate_requests_full_completed_exploit_dev_page(
    monkeypatch, tmp_path, capsys
):
    """The chain gate must request the full backend page filtered by role and
    status so long engagements don't drop the chain pass behind limit=100
    (same pagination contract as the variant-pass gate)."""
    module = _load_assess_module("tp_chain_pagination", "agent/scripts/assess/commands/transition_phase.py")
    captured: list[str] = []
    eng = tmp_path / "agent" / "engagements" / "eng-chain-page"
    eng.mkdir(parents=True, exist_ok=True)
    (eng / "scope.json").write_text(
        json.dumps({"engagement_type": "web", "current_phase": "exploit"}),
        encoding="utf-8",
    )

    class _Client:
        def __init__(self, *_a, **_k) -> None:
            pass

        def get(self, path: str):
            captured.append(path)
            if path == "findings":
                return [_CONFIRMED_HIGH, _CONFIRMED_HIGH_2]
            if path == "report-readiness":
                return {"ready": True, "blockers": []}
            if path == "application-units/terminal-block":
                return {"skipped": False, "blocking": [], "warned_under_observed": [],
                        "deferred": [], "deferral_count": 0}
            if path.startswith("dispatch-decisions"):
                return _accept_verdicts("ssrf-1", "redirect-2")["blind_triage_verdict"]
            if path.startswith("dispatches"):
                return [{"agent_role": "exploit-developer", "status": "completed"}]
            return []

        def close(self): return None
        def __enter__(self): return self
        def __exit__(self, *_e): return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(module, "load_config", lambda *_a, **_k: SimpleNamespace(
        base_url="http://example.test", engagement_dir=str(eng),
        engagement_key=eng.name, agent_root=str(tmp_path / "agent")))

    module.run(_transition_args(eng, "report"))
    chain_queries = [
        p for p in captured
        if p.startswith("dispatches") and "role=exploit-developer" in p
    ]
    assert chain_queries, "chain gate did not query exploit-developer dispatches"
    q = chain_queries[0]
    assert "status=completed" in q
    assert "limit=1000" in q


def test_transition_chain_gate_force_overrides_and_records_decision(
    monkeypatch, tmp_path, capsys
):
    module = _load_assess_module("tp_chain_force", "agent/scripts/assess/commands/transition_phase.py")
    eng, decisions = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "exploit"},
        findings=[_CONFIRMED_HIGH, _CONFIRMED_HIGH_2],
        dispatches=[],
    )
    module.run(_transition_args(eng, "report", force=True,
                                reason="findings are independent, no chain plausible"))
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"
    override = [d for d in decisions if d["kind"] == "forced_transition_override"]
    assert len(override) == 1
    assert any(
        b["kind"] == "missing_chain_construction"
        for b in override[0]["payload"]["overridden_blockers"]
    )


def test_transition_chain_gate_also_fires_on_complete(monkeypatch, tmp_path, capsys):
    """A direct report -> complete edge (where only `complete` preconditions are
    walked) must still enforce the chain pass, mirroring blind-triage/depth."""
    module = _load_assess_module("tp_chain_complete", "agent/scripts/assess/commands/transition_phase.py")
    eng, _ = _setup_transition_env(
        monkeypatch, module, tmp_path,
        scope={"engagement_type": "web", "current_phase": "report"},
        findings=[_CONFIRMED_HIGH, _CONFIRMED_HIGH_2],
        dispatches=[],
    )
    with pytest.raises(SystemExit):
        module.run(_transition_args(eng, "complete"))
    assert "missing_chain_construction" in capsys.readouterr().err
    assert json.loads((eng / "scope.json").read_text())["current_phase"] == "report"


def test_check_phase_readiness_reports_partially_covered_surfaces(
    monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The folded surface-coverage gate (old `check-coverage`, now
    `check-phase-readiness --phase consume`) should EXPLAIN partial-coverage
    blockers and exit non-zero, instead of failing silently."""
    module = _load_assess_module(
        "round3_check_phase_readiness_module",
        "agent/scripts/assess/commands/check_phase_readiness.py",
    )

    coverage_payload = {
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

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get(self, path: str) -> dict:
            if path.startswith("phase-readiness"):
                return {
                    "phase": "consume",
                    "coverage": coverage_payload,
                    "depth_ledger": {"skipped": True, "units": [], "summary": {}},
                }
            if path == "services":
                return []
            if path == "surfaces":
                return []
            if path == "application-units/depth-ledger":
                return {"skipped": True, "units": [], "summary": {}}
            raise AssertionError(f"unexpected endpoint {path}")

        def get_all_pages(self, endpoint: str, *, page_size: int = 5000):
            # coverage_checks._load_work_items_by_host reads the backend work
            # buffer via get_all_pages("work-items"); empty scope means no rows.
            return []

        def get_engagement(self, path: str, query: str = "") -> dict:
            return {"applicable": False, "engagement_type": "red",
                    "open_high_cves": [], "open_leads": [],
                    "exploited_unlinked_cves": [], "dangling_links": []}

        def list_all_decisions(self, **_filters):
            return []

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

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
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": []}), encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                phase="consume",
                as_json=False,
                verbose=False,
                strict_vendor_saas=False,
                by_host=False,
                include_discovered=False,
                auto_redispatch=False,
                max_recommendations=10,
                depth=False,
                by_app_unit=False,
                include_intel=False,
                strict=False,
                strict_deep=False,
            )
        )

    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "Partially covered surfaces need follow-up" in out
    assert "needs auth re-test" in out


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


def test_assess_log_accepts_structured_metadata_inline(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_assess_module(
        "log_entry_command_module_metadata",
        "agent/scripts/assess/commands/log_entry.py",
    )
    posts: list[tuple[str, dict]] = []
    events: list[dict] = []

    class _Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post_engagement(self, endpoint: str, payload: dict) -> dict:
            posts.append((endpoint, payload))
            return {"id": 1, **payload}

        def post_event(self, payload: dict) -> dict:
            events.append(payload)
            return {"id": 2}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    module.run(
        SimpleNamespace(
            eng_dir=None,
            agent="operator",
            title="contain FIND-001",
            action="contain",
            result="recorded approved action",
            actor_kind="operator",
            metadata_inline='{"finding_slug":"FIND-001","proposal_id":"7"}',
        )
    )

    assert posts == [
        (
            "activity-entries",
            {
                "actor_kind": "operator",
                "actor_name": "operator",
                "title": "contain FIND-001",
                "action": "contain",
                "result": "recorded approved action",
                "metadata": {"finding_slug": "FIND-001", "proposal_id": "7"},
            },
        )
    ]
    assert events[0]["event_type"] == "activity.recorded"


def test_assess_log_accepts_structured_metadata_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "log_entry_command_module_metadata_file",
        "agent/scripts/assess/commands/log_entry.py",
    )
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text('{"finding_slug":"FIND-001","proposal_id":"7"}', encoding="utf-8")
    posts: list[tuple[str, dict]] = []

    class _Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post_engagement(self, endpoint: str, payload: dict) -> dict:
            posts.append((endpoint, payload))
            return {"id": 1, **payload}

        def post_event(self, _payload: dict) -> dict:
            return {"id": 2}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    module.run(
        SimpleNamespace(
            eng_dir=None,
            agent="operator",
            title="contain FIND-001",
            action="contain",
            result="recorded approved action",
            actor_kind="operator",
            metadata_inline=None,
            metadata_file=str(metadata_path),
        )
    )

    assert posts[0][1]["metadata"] == {"finding_slug": "FIND-001", "proposal_id": "7"}


def test_blue_verify_requires_verifier_dispatch_unless_forced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    proof_path = tmp_path / "proof.json"
    proof_path.write_text('{"revoked":true}\n', encoding="utf-8")
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(blue_module, "_has_verifier_dispatch_for", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )

    with pytest.raises(SystemExit, match="incident-verifier"):
        blue_module._cmd_verify(
            SimpleNamespace(
                finding_slug="FIND-001",
                disposition="verified",
                reason="verified from tenant evidence",
                kill_check=None,
                kill_reason=None,
                evidence_refs=None,
                new_severity=None,
                force=False,
                engagement_key=None,
                select=False,
            ),
            tmp_path,
        )

    assert calls == []


def test_blue_verify_rejects_non_blue_engagement_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text(
        json.dumps({"engagement_type": "web", "current_phase": "verify"}),
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(blue_module, "_has_verifier_dispatch_for", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )

    with pytest.raises(SystemExit, match="only works on blue engagements"):
        blue_module._cmd_verify(
            SimpleNamespace(
                finding_slug="FIND-001",
                disposition="verified",
                reason="verified from tenant evidence",
                kill_check=None,
                kill_reason=None,
                evidence_refs=None,
                new_severity=None,
                force=False,
                engagement_key=None,
                select=False,
            ),
            tmp_path,
        )

    assert calls == []


def test_blue_verify_force_bypasses_missing_verifier_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    proof_path = tmp_path / "proof.json"
    proof_path.write_text('{"revoked":true}\n', encoding="utf-8")
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(blue_module, "_has_verifier_dispatch_for", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )

    blue_module._cmd_verify(
        SimpleNamespace(
            finding_slug="FIND-001",
            disposition="verified",
            reason="operator-approved bypass",
            kill_check=None,
            kill_reason=None,
            evidence_refs="artifact-1",
            proof_receipt_ids=[71],
            counter_check_file=None,
            new_severity=None,
            force=True,
            engagement_key=None,
            select=False,
        ),
        tmp_path,
    )

    assert calls[0][:5] == ["finding", "verify", "FIND-001", "--status", "confirmed"]
    assert calls[0][calls[0].index("--proof-receipt-id") + 1] == "71"

    from assess.commands import verify_finding

    canonical = argparse.ArgumentParser()
    verify_finding.register(canonical.add_subparsers(dest="command", required=True))
    parsed = canonical.parse_args(calls[0][1:])
    assert parsed.proof_receipt_ids == [71]


def test_blue_verify_downgraded_forwards_receipts_to_canonical_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from assess.commands import verify_finding
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    calls: list[list[str]] = []
    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_a, **_k: eng_dir)
    monkeypatch.setattr(blue_module, "_has_verifier_dispatch_for", lambda *_a, **_k: True)
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _root, _eng, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )

    blue_module._cmd_verify(
        SimpleNamespace(
            finding_slug="FIND-002",
            disposition="downgraded",
            reason="impact is limited by tenant policy",
            evidence_refs=None,
            proof_receipt_ids=[72, 73],
            counter_check_file=None,
            new_severity="low",
            force=False,
            engagement_key=None,
            select=False,
        ),
        tmp_path,
    )

    canonical = argparse.ArgumentParser()
    verify_finding.register(canonical.add_subparsers(dest="command", required=True))
    parsed = canonical.parse_args(calls[0][1:])
    assert parsed.verification_status == "downgraded"
    assert parsed.new_severity == "low"
    assert parsed.proof_receipt_ids == [72, 73]


def test_blue_verify_false_positive_uses_canonical_finding_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    counter_check = tmp_path / "counter-check.json"
    counter_check.write_text(
        json.dumps({
            "method": "query tenant audit records",
            "expected_result": "the suspicious action is present",
            "observed_result": "the action is absent and the known benign job is present",
            "falsified_claim": "the user performed the suspicious action",
            "completed": True,
            "proof_receipt_ids": [72],
        }),
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(blue_module, "_has_verifier_dispatch_for", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )

    blue_module._cmd_verify(
        SimpleNamespace(
            finding_slug="FIND-001",
            disposition="false_positive",
            reason="tenant evidence proves the alert benign",
            evidence_refs="artifact-1,artifact-2",
            proof_receipt_ids=None,
            counter_check_file=str(counter_check),
            new_severity=None,
            force=False,
            engagement_key=None,
            select=False,
        ),
        tmp_path,
    )

    assert calls[0][:7] == [
        "finding",
        "verify",
        "FIND-001",
        "--status",
        "false_positive",
        "--reason",
        "tenant evidence proves the alert benign",
    ]
    assert calls[0][calls[0].index("--counter-check-file") + 1] == str(counter_check)

    from assess.commands import verify_finding

    canonical = argparse.ArgumentParser()
    verify_finding.register(canonical.add_subparsers(dest="command", required=True))
    parsed = canonical.parse_args(calls[0][1:])
    assert parsed.counter_check_file == str(counter_check)


def test_blue_verify_parser_accepts_canonical_evidence_flags() -> None:
    from vigil_cli import blue as blue_module

    parser = argparse.ArgumentParser()
    blue_module.register_blue_parser(parser.add_subparsers(dest="command", required=True))

    confirmed = parser.parse_args([
        "blue", "verify", "FIND-001", "--disposition", "verified",
        "--reason", "reproduced", "--proof-receipt-id", "71",
    ])
    false_positive = parser.parse_args([
        "blue", "verify", "FIND-002", "--disposition", "false_positive",
        "--reason", "falsified", "--counter-check-file", "counter-check.json",
    ])

    assert confirmed.proof_receipt_ids == [71]
    assert false_positive.counter_check_file == "counter-check.json"


def test_blue_contain_logs_structured_activity_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    proof_path = tmp_path / "proof.json"
    proof_path.write_text('{"revoked":true}\n', encoding="utf-8")
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(
        blue_module,
        "_fetch_containment_decision",
        lambda *_args, **_kwargs: {
            "id": 7,
            "resolved": True,
            "payload": {
                "action": "revoke_session",
                "target": "alex@example.com",
                "platform": "gws",
            },
        },
    )
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )

    blue_module._cmd_contain(
        SimpleNamespace(
            finding_slug="FIND-001",
            proposal="7",
            proof_artifact=str(proof_path),
            command_run_id=None,
            action=None,
            target=None,
            engagement_key=None,
            select=False,
        ),
        tmp_path,
    )

    log_call = next(call for call in calls if call[0] == "log")
    assert "--metadata-inline" in log_call
    metadata = json.loads(log_call[log_call.index("--metadata-inline") + 1])
    assert metadata == {
        "containment_action": "revoke_session",
        "target": "alex@example.com",
        "platform": "gws",
        "proposal_id": "7",
        "finding_slug": "FIND-001",
        "command_run_id": None,
    }


def test_blue_contain_requires_proof_artifact_or_command_run_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(
        blue_module,
        "_fetch_containment_decision",
        lambda *_args, **_kwargs: {
            "id": 7,
            "resolved": True,
            "payload": {
                "finding_slug": "FIND-001",
                "action": "revoke_session",
                "target": "alex@example.com",
                "platform": "gws",
            },
        },
    )
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )

    with pytest.raises(SystemExit, match="requires --proof-artifact or --command-run-id"):
        blue_module._cmd_contain(
            SimpleNamespace(
                finding_slug="FIND-001",
                proposal="7",
                proof_artifact=None,
                command_run_id=None,
                action=None,
                target=None,
                engagement_key=None,
                select=False,
            ),
            tmp_path,
        )

    assert calls == []


def test_blue_contain_aborts_when_only_proof_artifact_registration_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    proof_path = tmp_path / "proof.json"
    proof_path.write_text('{"revoked":true}\n', encoding="utf-8")
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(
        blue_module,
        "_fetch_containment_decision",
        lambda *_args, **_kwargs: {
            "id": 7,
            "resolved": True,
            "payload": {
                "finding_slug": "FIND-001",
                "action": "revoke_session",
                "target": "alex@example.com",
                "platform": "gws",
            },
        },
    )

    def fake_run(_install_root: Path, _eng_dir: Path, assess_args: list[str], **_kwargs: object) -> int:
        calls.append(assess_args)
        return 1 if assess_args[:2] == ["artifact", "register"] else 0

    monkeypatch.setattr(blue_module, "_run_assess", fake_run)

    with pytest.raises(SystemExit):
        blue_module._cmd_contain(
            SimpleNamespace(
                finding_slug="FIND-001",
                proposal="7",
                proof_artifact=str(proof_path),
                command_run_id=None,
                action=None,
                target=None,
                engagement_key=None,
                select=False,
            ),
            tmp_path,
        )

    assert calls == [
        [
            "artifact",
            "register",
            str(proof_path),
            "--kind",
            "containment_proof",
            "--finding",
            "FIND-001",
        ]
    ]


def test_blue_contain_accepts_command_run_id_as_execution_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(
        blue_module,
        "_fetch_containment_decision",
        lambda *_args, **_kwargs: {
            "id": 7,
            "resolved": True,
            "payload": {
                "finding_slug": "FIND-001",
                "action": "revoke_session",
                "target": "alex@example.com",
                "platform": "gws",
            },
        },
    )
    monkeypatch.setattr(
        blue_module,
        "_fetch_command_run",
        lambda *_args, **_kwargs: {
            "id": 42,
            "route": "host_exec",
            "phase": "respond",
            "technique": "CONTAINMENT",
            "success": True,
            "finding_id": 11,
            "intent": "containment proposal=7 action=revoke_session",
            "argv": ["gam", "user", "alex@example.com", "signout"],
        },
    )
    monkeypatch.setattr(blue_module, "_fetch_containment_finding", lambda *_args: {"id": 11, "slug": "FIND-001"})
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )

    blue_module._cmd_contain(
        SimpleNamespace(
            finding_slug="FIND-001",
            proposal="7",
            proof_artifact=None,
            command_run_id=42,
            action=None,
            target=None,
            engagement_key=None,
            select=False,
        ),
        tmp_path,
    )

    assert not any(call[:2] == ["artifact", "register"] for call in calls)
    log_call = next(call for call in calls if call[0] == "log")
    metadata = json.loads(log_call[log_call.index("--metadata-inline") + 1])
    assert metadata["command_run_id"] == 42


def test_blue_contain_rejects_unknown_command_run_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(
        blue_module,
        "_fetch_containment_decision",
        lambda *_args, **_kwargs: {
            "id": 7,
            "resolved": True,
            "payload": {
                "finding_slug": "FIND-001",
                "action": "revoke_session",
                "target": "alex@example.com",
                "platform": "gws",
            },
        },
    )
    monkeypatch.setattr(blue_module, "_fetch_command_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )

    with pytest.raises(SystemExit, match="command run id 999999 not found"):
        blue_module._cmd_contain(
            SimpleNamespace(
                finding_slug="FIND-001",
                proposal="7",
                proof_artifact=None,
                command_run_id=999999,
                action=None,
                target=None,
                engagement_key=None,
                select=False,
            ),
            tmp_path,
        )

    assert calls == []


@pytest.mark.parametrize(
    ("command_row", "message"),
    [
        (
            {
                "id": 42,
                "route": "kali",
                "phase": "respond",
                "technique": "CONTAINMENT",
                "success": True,
            },
            "route='kali'",
        ),
        (
            {
                "id": 42,
                "route": "host_exec",
                "phase": "investigate",
                "technique": "CONTAINMENT",
                "success": True,
            },
            "phase='investigate'",
        ),
        (
            {
                "id": 42,
                "route": "host_exec",
                "phase": "respond",
                "technique": "AUDIT-PULL",
                "success": True,
            },
            "technique='AUDIT-PULL'",
        ),
        (
            {
                "id": 42,
                "route": "host_exec",
                "phase": "respond",
                "technique": "CONTAINMENT",
                "success": False,
            },
            "success=False",
        ),
    ],
)
def test_blue_contain_rejects_non_containment_command_run_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command_row: dict,
    message: str,
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(
        blue_module,
        "_fetch_containment_decision",
        lambda *_args, **_kwargs: {
            "id": 7,
            "resolved": True,
            "payload": {
                "finding_slug": "FIND-001",
                "action": "revoke_session",
                "target": "alex@example.com",
                "platform": "gws",
            },
        },
    )
    monkeypatch.setattr(blue_module, "_fetch_command_run", lambda *_args, **_kwargs: {
        "finding_id": 11,
        "intent": "containment proposal=7 action=revoke_session",
        "argv": ["gam", "user", "alex@example.com", "signout"],
        **command_row,
    })
    monkeypatch.setattr(blue_module, "_fetch_containment_finding", lambda *_args: {"id": 11, "slug": "FIND-001"})
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )

    with pytest.raises(SystemExit, match=message):
        blue_module._cmd_contain(
            SimpleNamespace(
                finding_slug="FIND-001",
                proposal="7",
                proof_artifact=None,
                command_run_id=42,
                action=None,
                target=None,
                engagement_key=None,
                select=False,
            ),
            tmp_path,
        )

    assert calls == []


def test_blue_fetch_containment_decision_pages_until_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vigil_cli import blue as blue_module

    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(argv)
        endpoint = argv[-1]
        if "offset=0" in endpoint:
            stdout = json.dumps([{"id": index, "kind": "containment_proposal"} for index in range(1, 1001)])
        elif "offset=1000" in endpoint:
            stdout = json.dumps([
                {
                    "id": 1001,
                    "kind": "containment_proposal",
                    "payload": {"finding_slug": "FIND-001"},
                }
            ])
        else:
            stdout = "[]"
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(blue_module.subprocess, "run", fake_run)

    row = blue_module._fetch_containment_decision(tmp_path, tmp_path / "eng", 1001)

    assert row is not None
    assert row["id"] == 1001
    endpoints = [call[-1] for call in calls]
    assert endpoints == [
        "dispatch-decisions?kind=containment_proposal&limit=1000&offset=0",
        "dispatch-decisions?kind=containment_proposal&limit=1000&offset=1000",
    ]


def test_blue_propose_contain_writes_only_dispatch_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    assess_calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: assess_calls.append(assess_args) or 0,
    )
    monkeypatch.setattr(
        blue_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout='{"id":7,"kind":"containment_proposal","resolved":false}\n',
            stderr="",
        ),
    )

    blue_module._cmd_propose_contain(
        SimpleNamespace(
            finding_slug="FIND-001",
            action="revoke_session",
            target="alex@example.com",
            platform="gws",
            rollback="User signs in again",
            blast_radius="single-user",
            note="verified compromise",
            engagement_key=None,
            select=False,
        ),
        tmp_path,
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "decision_id": 7,
        "approval_hint": "vigil assess approve-proposal 7 --approved-by <operator>",
    }
    assert assess_calls == []
    assert not list((eng_dir / "sessions").glob("containment-proposal-*.json"))


def test_blue_contain_rejects_proposal_for_different_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(
        blue_module,
        "_fetch_containment_decision",
        lambda *_args, **_kwargs: {
            "id": 7,
            "resolved": True,
            "payload": {
                "finding_slug": "FIND-A",
                "action": "revoke_session",
                "target": "alex@example.com",
                "platform": "gws",
            },
        },
    )
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )

    with pytest.raises(SystemExit, match="belongs to finding 'FIND-A'"):
        blue_module._cmd_contain(
            SimpleNamespace(
                finding_slug="FIND-B",
                proposal="7",
                proof_artifact=None,
                command_run_id=42,
                action=None,
                target=None,
                engagement_key=None,
                select=False,
            ),
            tmp_path,
        )

    assert calls == []


def test_blue_help_documents_generic_dispatch_emitter(capsys) -> None:
    from vigil_cli import blue as blue_module

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    blue_module.register_blue_parser(subparsers)

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["blue", "--help"])

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "vigil assess agent start" in help_text
    assert "--prompt-context-json" in help_text
    assert "--emit-prompt" in help_text


def test_blue_initial_report_scaffold_uses_customer_and_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import client_rosters as client_rosters_module
    from vigil_cli import engagements as engagements_module
    from vigil_cli.engagements import CreateEngagementOptions, create_engagement

    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    _isolate_orchestrator_url(monkeypatch)
    monkeypatch.setattr(engagements_module, "_verify_backend_install_root", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(engagements_module, "_emit_post_create_footer", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        client_rosters_module,
        "_render_codex_compact_prompt",
        lambda *_args, **_kwargs: "test compact prompt",
    )
    monkeypatch.setattr(
        engagements_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
    )

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="blue",
            customer="acme",
            platforms=["gws"],
            tenant_reference_paths=["agent/references/tenants/acme-workspace.md"],
        )
    )

    report = (created.path / "report.md").read_text(encoding="utf-8")
    assert "- **Customer**: acme" in report
    assert "- **Scope**: acme:gws" in report


def test_blue_tenant_init_generic_platform_has_template(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import blue as blue_module

    install_root = tmp_path / "install"
    tenant_root = install_root / "agent" / "references" / "tenants"
    shutil.copytree(repo_root / "agent" / "references" / "tenants", tenant_root)

    blue_module._cmd_tenant_init(
        SimpleNamespace(customer="acme", platform="generic", force=False),
        install_root,
    )

    created = tenant_root / "acme-generic.md"
    assert created.is_file()
    assert "acme-generic.md" in capsys.readouterr().out


def test_blue_customers_lists_known_tenant_refs_grouped(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import blue as blue_module

    tenant_root = tmp_path / "agent" / "references" / "tenants"
    tenant_root.mkdir(parents=True)
    (tenant_root / "_template-gws.md").write_text("template\n", encoding="utf-8")
    (tenant_root / "acme-workspace.md").write_text("gws\n", encoding="utf-8")
    (tenant_root / "acme-m365.md").write_text("m365\n", encoding="utf-8")
    (tenant_root / "other-example-aws.md").write_text("aws\n", encoding="utf-8")

    blue_module._cmd_customers(SimpleNamespace(platform=None, json=False), tmp_path)

    output = capsys.readouterr().out
    assert "customer\tplatforms\ttenant_reference_paths" in output
    assert "other-example\taws\t" in output
    assert "acme\tgws,m365\t" in output
    assert "_template" not in output


def test_blue_customers_json_filters_by_platform(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import blue as blue_module

    tenant_root = tmp_path / "agent" / "references" / "tenants"
    tenant_root.mkdir(parents=True)
    (tenant_root / "acme-workspace.md").write_text("gws\n", encoding="utf-8")
    (tenant_root / "acme-m365.md").write_text("m365\n", encoding="utf-8")

    blue_module._cmd_customers(SimpleNamespace(platform="gws", json=True), tmp_path)

    rows = json.loads(capsys.readouterr().out)
    assert rows == [
        {
            "customer": "acme",
            "platforms": ["gws"],
            "tenant_reference_paths": [str(tenant_root / "acme-workspace.md")],
        }
    ]


def test_blue_engage_guides_operator_to_start_session_and_paste_alert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import blue as blue_module

    tenant_root = tmp_path / "agent" / "references" / "tenants"
    tenant_root.mkdir(parents=True)
    (tenant_root / "acme-workspace.md").write_text("tenant\n", encoding="utf-8")
    created_path = tmp_path / "agent" / "engagements" / "eng-1"

    monkeypatch.setattr(
        blue_module,
        "create_engagement",
        lambda _options: SimpleNamespace(path=created_path, key="eng-1"),
    )

    blue_module._cmd_engage(
        SimpleNamespace(
            customer="acme",
            platform="gws",
            severity="high",
            source=None,
            skip_permissions=True,
            start=None,
        ),
        tmp_path,
    )

    captured = capsys.readouterr()
    # stdout stays the bare engagement path (the eng=$(vigil blue engage …) contract).
    assert captured.out.strip() == str(created_path)
    # Single blue footer on stderr — no red-infra noise, no duplicate paste hint.
    assert "vigil blue alert paste" not in captured.err
    assert "paste the alert into the operator chat" in captured.err
    assert "vigil blue alert record" in captured.err
    assert (
        "Shortcut next time: vigil blue engage --customer acme "
        "--platform gws --start codex" in captured.err
    )
    # The red footer (mitmproxy/oob plumbing) must never leak into a blue engage.
    assert "mitmproxy" not in captured.err
    assert "oob" not in captured.err


def test_blue_engage_start_chains_into_operator_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import blue as blue_module

    tenant_root = tmp_path / "agent" / "references" / "tenants"
    tenant_root.mkdir(parents=True)
    (tenant_root / "acme-workspace.md").write_text("tenant\n", encoding="utf-8")
    created_path = tmp_path / "agent" / "engagements" / "eng-1"

    monkeypatch.setattr(
        blue_module,
        "create_engagement",
        lambda _options: SimpleNamespace(path=created_path, key="eng-1"),
    )
    preflight_calls: list[tuple[Path, Path, str]] = []

    def fake_preflight(install_root: Path, path: Path, client: str) -> None:
        preflight_calls.append((install_root, path, client))

    monkeypatch.setattr(
        blue_module,
        "_preflight_engagement_start",
        fake_preflight,
    )
    start_calls: list[tuple] = []
    monkeypatch.setattr(
        blue_module,
        "start_engagement",
        lambda *args: start_calls.append(args),
    )

    blue_module._cmd_engage(
        SimpleNamespace(
            customer="acme",
            platform="gws",
            severity="high",
            source=None,
            skip_permissions=True,
            start="codex",
        ),
        tmp_path,
    )

    captured = capsys.readouterr()
    # stdout is still just the path — flushed before the (mocked) execv launcher.
    assert captured.out.strip() == str(created_path)
    # start_engagement is the final statement: (install_root, path, client, []).
    assert preflight_calls == [(tmp_path, created_path, "codex")]
    assert start_calls == [(tmp_path, created_path, "codex", [])]
    assert "[vigil blue] launching operator session (codex)" in captured.err
    assert "Paste the alert into the operator chat" in captured.err
    assert "mitmproxy" not in captured.err
    assert "oob" not in captured.err


def test_blue_engage_non_tty_without_flags_lists_combos(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vigil_cli import blue as blue_module

    tenant_root = tmp_path / "agent" / "references" / "tenants"
    tenant_root.mkdir(parents=True)
    (tenant_root / "acme-workspace.md").write_text("tenant\n", encoding="utf-8")

    # pytest's captured stdin isn't a TTY; make that explicit and deterministic.
    monkeypatch.setattr(blue_module.sys, "stdin", SimpleNamespace(isatty=lambda: False))

    with pytest.raises(SystemExit, match="Available customer/platform combinations"):
        blue_module._cmd_engage(
            SimpleNamespace(
                customer=None,
                platform=None,
                severity=None,
                source=None,
                skip_permissions=False,
                start=None,
            ),
            tmp_path,
        )


def test_blue_engage_interactive_picker_numbered_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vigil_cli import blue as blue_module

    tenant_root = tmp_path / "agent" / "references" / "tenants"
    tenant_root.mkdir(parents=True)
    (tenant_root / "acme-workspace.md").write_text("tenant\n", encoding="utf-8")
    (tenant_root / "acme-m365.md").write_text("tenant\n", encoding="utf-8")
    created_path = tmp_path / "agent" / "engagements" / "eng-1"

    seen: dict[str, object] = {}

    def fake_create(options: object) -> SimpleNamespace:
        seen["customer"] = options.customer
        seen["platforms"] = options.platforms
        seen["severity"] = options.severity_hint
        return SimpleNamespace(path=created_path, key="eng-1")

    monkeypatch.setattr(blue_module, "create_engagement", fake_create)
    # Force the numbered-menu fallback (no fzf) and a TTY so the picker runs.
    monkeypatch.setattr(blue_module.shutil, "which", lambda _name: None)
    monkeypatch.setattr(blue_module.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    responses = iter(["1", "2", "high"])  # customer=acme, platform=m365, severity=high
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(responses))

    blue_module._cmd_engage(
        SimpleNamespace(
            customer=None,
            platform=None,
            severity=None,
            source=None,
            skip_permissions=True,
            start=None,
        ),
        tmp_path,
    )

    assert seen["customer"] == "acme"
    assert seen["platforms"] == ["m365"]
    assert seen["severity"] == "high"


def test_engagement_create_blue_skips_red_footer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import client_rosters as client_rosters_module
    from vigil_cli import docker as docker_mod
    from vigil_cli import engagements as engagements_module
    from vigil_cli import oob as oob_mod
    from vigil_cli.engagements import CreateEngagementOptions, create_engagement

    install_root = tmp_path / "install"
    _copy_agent_fixture(repo_root / "agent", install_root)
    _isolate_orchestrator_url(monkeypatch)
    # Deliberately do NOT patch _emit_post_create_footer — the type-gate itself
    # must suppress the red footer for blue engagements.
    monkeypatch.setattr(engagements_module, "_verify_backend_install_root", lambda *_a, **_k: None)
    monkeypatch.setattr(
        client_rosters_module,
        "_render_codex_compact_prompt",
        lambda *_args, **_kwargs: "test compact prompt",
    )
    monkeypatch.setattr(docker_mod, "container_running", lambda *_a, **_k: False)
    monkeypatch.setattr(oob_mod, "oob_status", lambda *_a, **_k: {"state": "stopped"})
    monkeypatch.setattr(
        engagements_module.subprocess,
        "run",
        lambda *_a, **_k: SimpleNamespace(returncode=0),
    )

    create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="blue",
            customer="acme",
            platforms=["gws"],
            tenant_reference_paths=["agent/references/tenants/acme-workspace.md"],
        )
    )

    captured = capsys.readouterr()
    assert "mitmproxy" not in captured.err
    assert "oob" not in captured.err


def test_blue_alert_record_body_file_stdin_reads_piped_alert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )
    body = '{"alert_id":"AL-9","actor":"sam@example.com"}\n'
    monkeypatch.setattr(
        blue_module.sys,
        "stdin",
        SimpleNamespace(read=lambda: body, isatty=lambda: False),
    )

    blue_module._cmd_alert_record(
        SimpleNamespace(
            body_file="-",
            external_id="AL-9",
            severity=None,
            source=None,
            engagement_key=None,
            select=False,
        ),
        tmp_path,
    )

    scope = json.loads((eng_dir / "scope.json").read_text(encoding="utf-8"))
    alert_md = scope["alert_metadata"]
    assert alert_md["raw_body"] == body
    assert alert_md["parsed"]["format"] == "json"

    raw_path = eng_dir / "ir" / "alerts" / "AL-9.txt"
    assert raw_path.read_text(encoding="utf-8") == body
    assert ["artifact", "register", str(raw_path), "--kind", "alert_intake"] in calls
    assert capsys.readouterr().out.strip() == str(raw_path)


def test_blue_alert_record_stdin_empty_body_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(blue_module, "_run_assess", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(
        blue_module.sys,
        "stdin",
        SimpleNamespace(read=lambda: "   \n", isatty=lambda: False),
    )

    with pytest.raises(SystemExit, match="stdin body was empty"):
        blue_module._cmd_alert_record(
            SimpleNamespace(
                body_file="-",
                external_id=None,
                severity=None,
                source=None,
                engagement_key=None,
                select=False,
            ),
            tmp_path,
        )


def test_blue_alert_record_body_file_updates_scope_and_registers_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    body_path = tmp_path / "alert.json"
    body_path.write_text('{"alert_id":"AL-1","actor":"alex@example.com"}\n', encoding="utf-8")
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )

    blue_module._cmd_alert_record(
        SimpleNamespace(
            body_file=str(body_path),
            external_id="AL-1",
            severity="high",
            source=None,
            engagement_key=None,
            select=False,
        ),
        tmp_path,
    )

    scope = json.loads((eng_dir / "scope.json").read_text(encoding="utf-8"))
    alert_md = scope["alert_metadata"]
    assert alert_md["source"] == "operator_chat"
    assert alert_md["external_id"] == "AL-1"
    assert alert_md["severity_hint"] == "high"
    assert alert_md["raw_body"].startswith('{"alert_id"')
    assert alert_md["parsed"]["format"] == "json"

    raw_path = eng_dir / "ir" / "alerts" / "AL-1.txt"
    assert raw_path.read_text(encoding="utf-8") == body_path.read_text(encoding="utf-8")
    assert ["artifact", "register", str(raw_path), "--kind", "alert_intake"] in calls
    assert any(call[:5] == ["log", "operator", "alert intake", "alert_intake", "alert recorded"] for call in calls)
    next_step = capsys.readouterr().err
    assert "vigil assess agent start --role alert-triage-specialist" in next_step
    assert "--rate-budget '<authored tenant query budget>'" in next_step
    assert "--prompt-context-json dispatch-context.json --emit-prompt" in next_step


def test_blue_alert_record_rejects_second_intake_without_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    first_body = tmp_path / "first.txt"
    second_body = tmp_path / "second.txt"
    first_body.write_text("first alert\n", encoding="utf-8")
    second_body.write_text("second alert\n", encoding="utf-8")

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(blue_module, "_run_assess", lambda *_args, **_kwargs: 0)

    blue_module._cmd_alert_record(
        SimpleNamespace(
            body_file=str(first_body),
            external_id="AL-1",
            severity="high",
            source=None,
            replace=False,
            engagement_key=None,
            select=False,
        ),
        tmp_path,
    )

    with pytest.raises(SystemExit, match="alert intake already recorded"):
        blue_module._cmd_alert_record(
            SimpleNamespace(
                body_file=str(second_body),
                external_id="AL-1",
                severity="high",
                source=None,
                replace=False,
                engagement_key=None,
                select=False,
            ),
            tmp_path,
        )

    assert (eng_dir / "ir" / "alerts" / "AL-1.txt").read_text(encoding="utf-8") == "first alert\n"
    scope = json.loads((eng_dir / "scope.json").read_text(encoding="utf-8"))
    assert scope["alert_metadata"]["raw_body"] == "first alert\n"


def test_blue_alert_record_replace_keeps_prior_raw_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    first_body = tmp_path / "first.txt"
    second_body = tmp_path / "second.txt"
    first_body.write_text("first alert\n", encoding="utf-8")
    second_body.write_text("second alert\n", encoding="utf-8")

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(blue_module, "_run_assess", lambda *_args, **_kwargs: 0)

    base_args = {
        "external_id": "AL-1",
        "severity": "high",
        "source": None,
        "engagement_key": None,
        "select": False,
    }
    blue_module._cmd_alert_record(SimpleNamespace(body_file=str(first_body), replace=False, **base_args), tmp_path)
    blue_module._cmd_alert_record(SimpleNamespace(body_file=str(second_body), replace=True, **base_args), tmp_path)

    alerts_dir = eng_dir / "ir" / "alerts"
    assert (alerts_dir / "AL-1.txt").read_text(encoding="utf-8") == "first alert\n"
    assert (alerts_dir / "AL-1-2.txt").read_text(encoding="utf-8") == "second alert\n"
    scope = json.loads((eng_dir / "scope.json").read_text(encoding="utf-8"))
    assert scope["alert_metadata"]["raw_body"] == "second alert\n"


def test_blue_closeout_dispatches_report_writer_for_closure_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)
    monkeypatch.setattr(
        blue_module,
        "_run_assess",
        lambda _install_root, _eng_dir, assess_args, **_kwargs: calls.append(assess_args) or 0,
    )

    blue_module._cmd_closeout(
        SimpleNamespace(engagement_key=None, select=False, agent_id=None),
        tmp_path,
    )

    assert calls[0] == ["finding", "report", "--mode", "final"]
    dispatch = calls[1]
    assert dispatch[:2] == ["agent", "start"]
    assert dispatch[dispatch.index("--role") + 1] == "report-writer"
    assert "closeout.md" in dispatch[dispatch.index("--task") + 1]
    assert "false positive" in dispatch[dispatch.index("--task") + 1]
    assert "--no-target-traffic" in dispatch
    prompt_context = json.loads(
        dispatch[dispatch.index("--prompt-context-json") + 1]
    )
    assert set(prompt_context) == {
        "authorized_phase",
        "target",
        "hunt_scope",
        "mindset_lens",
        "depth_expectation",
        "oob",
        "auth_context",
        "credential_id",
        "prior_state",
        "coverage",
        "cleanup",
        "human_reach_decision",
        "role_specific_additions",
    }
    assert prompt_context["authorized_phase"] == "report"
    assert "[vigil blue] dispatched with agent-id=closeout-writer-" in capsys.readouterr().err


def test_blue_report_aborts_when_final_readiness_preflight_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)

    def fake_run(_install_root: Path, _eng_dir: Path, assess_args: list[str], **_kwargs: object) -> int:
        calls.append(assess_args)
        return 1 if assess_args[:2] == ["finding", "report"] else 0

    monkeypatch.setattr(blue_module, "_run_assess", fake_run)

    with pytest.raises(SystemExit):
        blue_module._cmd_report(SimpleNamespace(engagement_key=None, select=False, template=None), tmp_path)

    assert calls == [["finding", "report", "--mode", "final"]]


def test_blue_closeout_aborts_when_final_readiness_preflight_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vigil_cli import blue as blue_module

    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    calls: list[list[str]] = []

    monkeypatch.setattr(blue_module, "_resolve_blue_engagement", lambda *_args, **_kwargs: eng_dir)

    def fake_run(_install_root: Path, _eng_dir: Path, assess_args: list[str], **_kwargs: object) -> int:
        calls.append(assess_args)
        return 1 if assess_args[:2] == ["finding", "report"] else 0

    monkeypatch.setattr(blue_module, "_run_assess", fake_run)

    with pytest.raises(SystemExit):
        blue_module._cmd_closeout(SimpleNamespace(engagement_key=None, select=False, agent_id=None), tmp_path)

    assert calls == [["finding", "report", "--mode", "final"]]


def test_link_finding_intel_preserves_details_related_intel_ids(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        "link_finding_command_module_details",
        "agent/scripts/assess/commands/link_finding.py",
    )
    patches: list[tuple[str, dict]] = []

    class _Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get(self, endpoint: str) -> dict:
            assert endpoint == "findings/FIND-001"
            return {"slug": "FIND-001", "details": {"related_intel_ids": [1]}}

        def patch(self, endpoint: str, payload: dict) -> dict:
            patches.append((endpoint, payload))
            return {
                "finding": {
                    "slug": "FIND-001",
                    "details": payload["details"],
                }
            }

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    module.run(
        SimpleNamespace(
            engagement_dir="/tmp/eng",
            finding_slug="FIND-001",
            root_cause_slug=None,
            sibling_order=None,
            root_cause_effect="eliminates_finding",
                reason_text="link intel",
            source_name="operator",
            provenance_inline=None,
            clear_root_cause=False,
            intel_ids=["2"],
        )
    )

    assert patches == [
        (
            "findings/FIND-001",
            {"details": {"related_intel_ids": [1, 2]}, "reason_text": "link intel"},
        )
    ]
    assert json.loads(capsys.readouterr().out) == {
        "finding": {
            "slug": "FIND-001",
            "details": {"related_intel_ids": [1, 2]},
        }
    }


def _host_finalize_response(payload: dict, **fields: object) -> dict:
    response = dict(payload)
    completed_at = str(response.pop("ended_at"))
    response.pop("output_quiesced", None)
    if payload.get("output_quiesced") is False:
        response["partial_results"] = False
    response["completed_at"] = completed_at.replace("Z", "+00:00")
    response.update(fields)
    return response


class _HostAuditReceiptMixin:
    """Return receipts with the identity captured by the pre-exec write."""

    _run_uuid: str | None = None

    def _pre_exec_response(self, payload: dict, **fields: object) -> dict:
        run_uuid = payload.get("run_uuid")
        assert isinstance(run_uuid, str) and run_uuid
        self._run_uuid = run_uuid
        return {"id": 42, **fields}

    def _finalize_response(self, payload: dict, **fields: object) -> dict:
        assert self._run_uuid is not None
        return _host_finalize_response(
            payload,
            id=42,
            run_uuid=self._run_uuid,
            **fields,
        )


def _patch_test_host_ownership(
    module,
    monkeypatch: pytest.MonkeyPatch,
    *,
    quiescent: bool = True,
) -> None:
    monkeypatch.setattr(
        module.host_processes,
        "capture_process_ownership",
        lambda pid: module.host_processes.ProcessOwnership(
            pid=pid,
            pgid=pid,
            process_identity=f"test-process-{pid}",
        ),
    )
    monkeypatch.setattr(
        module.host_processes,
        "terminate_owned_process",
        lambda _ownership: quiescent,
    )


def test_host_exec_uses_agent_name_env_for_audit_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_agent_name",
        "agent/scripts/assess/commands/host_exec.py",
    )
    posts: list[tuple[str, dict]] = []
    events: list[str] = []

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, endpoint: str, payload: dict) -> dict:
            events.append("audit")
            posts.append((endpoint, payload))
            return self._pre_exec_response(payload)

        def patch(self, endpoint: str, payload: dict, **_kwargs: object) -> dict:
            events.append("finalize")
            return self._finalize_response(payload)

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setenv("AGENT_NAME", "investigator")
    monkeypatch.delenv("VIGIL_AGENT_NAME", raising=False)
    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    process_kwargs: dict[str, object] = {}

    def _fake_run_host_process(*_args: object, **kwargs: object):
        process_kwargs.update(kwargs)
        events.append("process")
        return 0, "ok\n", "", False

    monkeypatch.setattr(module, "_run_host_process", _fake_run_host_process)
    prepared: list[tuple[list[str], str | None]] = []

    def _fake_prepare(argv: list[str], **kwargs: object) -> str:
        prepared.append((list(argv), kwargs.get("identity")))
        report = kwargs.get("report")
        if isinstance(report, dict):
            report["required_header_status"] = "referenced_in_script"
        return "member"

    monkeypatch.setattr(module, "prepare_execution_command", _fake_prepare)
    (tmp_path / "scope.json").write_text(
        json.dumps(
            {
                "hosts": [],
                "required_headers": {"X-Attribution": "researcher"},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="test audit attribution",
                technique="T0000",
                phase="investigate",
                target_host="",
                scope_host="acme",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                identity="member",
            )
        )

    assert exc_info.value.code == 0
    assert posts[0][0] == "command-runs/host-exec"
    assert posts[0][1]["agent_name"] == "investigator"
    assert posts[0][1]["auth_context"] == "member"
    assert prepared == [(["echo", "ok"], "member")]
    assert json.loads(posts[0][1]["notes"])["required_header_status"] == (
        "referenced_in_script"
    )
    assert (
        "VIGIL_REQUIRED_HEADERS",
        "X-Attribution: researcher",
    ) in process_kwargs["env_pairs"]
    assert posts[0][1]["status"] == "running"
    assert posts[0][1]["stdout"] == ""
    assert "command_hash" not in posts[0][1]
    assert posts[0][1]["stdout_path"].endswith(".out")
    assert posts[0][1]["stderr_path"].endswith(".err")
    stdout_metadata = Path(posts[0][1]["stdout_path"]).stat()
    stderr_metadata = Path(posts[0][1]["stderr_path"]).stat()
    assert posts[0][1]["stdout_spill_device"] == stdout_metadata.st_dev
    assert posts[0][1]["stdout_spill_inode"] == stdout_metadata.st_ino
    assert posts[0][1]["stderr_spill_device"] == stderr_metadata.st_dev
    assert posts[0][1]["stderr_spill_inode"] == stderr_metadata.st_ino
    assert events == ["audit", "process", "finalize"]


def test_host_exec_replays_pre_exec_post_after_lost_response_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_lost_post_response",
        "agent/scripts/assess/commands/host_exec.py",
    )
    posts: list[tuple[str, dict]] = []
    events: list[str] = []

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, endpoint: str, payload: dict) -> dict:
            events.append("audit")
            posts.append((endpoint, dict(payload)))
            response = self._pre_exec_response(payload, idempotent_replay=True)
            if len(posts) == 1:
                raise module.AssessError("response lost after the backend committed")
            return response

        def patch(self, endpoint: str, payload: dict, **_kwargs: object) -> dict:
            events.append("finalize")
            assert endpoint == "command-runs/42"
            return self._finalize_response(payload)

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(
        module,
        "prepare_execution_command",
        lambda *_args, **_kwargs: "member",
    )
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_args, **_kwargs: (events.append("process") or (0, "ok\n", "", False)),
    )
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": []}), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="test lost response recovery",
                technique="T0000",
                phase="investigate",
                target_host="",
                scope_host="acme",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
                finding="",
                identity=None,
                identity_scope="",
            )
        )

    assert exc_info.value.code == 0
    assert len(posts) == 2
    assert posts[0] == posts[1]
    assert events == ["audit", "audit", "process", "finalize"]


def test_host_exec_explicit_finding_resolution_failure_stops_before_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_finding_resolution_failure",
        "agent/scripts/assess/commands/host_exec.py",
    )
    events: list[str] = []

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get(self, endpoint: str) -> dict:
            events.append(f"resolve:{endpoint}")
            raise module.AssessError("finding VA-MISSING not found")

        def post(self, _endpoint: str, _payload: dict) -> dict:
            events.append("post")
            return self._pre_exec_response(_payload)

        def patch(self, _endpoint: str, payload: dict, **_kwargs: object) -> dict:
            events.append("finalize")
            return self._finalize_response(payload)

        def close(self) -> None:
            pass

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "prepare_execution_command", lambda *_a, **_k: "member")
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_a, **_k: (events.append("process") or (0, "", "", False)),
    )
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": []}), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="require explicit finding linkage",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=False,
                finding="VA-MISSING",
                identity=None,
                identity_scope="",
            )
        )

    assert exc_info.value.code == 4
    assert events == ["resolve:findings/VA-MISSING"]
    assert not (tmp_path / "scans" / "host-exec").exists()


def test_host_exec_backend_rejection_with_finding_never_retries_unlinked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_finding_post_rejection",
        "agent/scripts/assess/commands/host_exec.py",
    )
    posts: list[dict] = []
    events: list[str] = []

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get(self, endpoint: str) -> dict:
            events.append(f"resolve:{endpoint}")
            return {"id": 7}

        def post(self, _endpoint: str, payload: dict) -> dict:
            events.append("post")
            posts.append(dict(payload))
            if payload.get("finding_id") == 7:
                raise module.AssessError("HTTP 404: finding id=7 not found")
            return self._pre_exec_response(payload)

        def patch(self, _endpoint: str, payload: dict, **_kwargs: object) -> dict:
            events.append("finalize")
            return self._finalize_response(payload)

        def close(self) -> None:
            pass

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "prepare_execution_command", lambda *_a, **_k: "member")
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_a, **_k: (events.append("process") or (0, "", "", False)),
    )
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": []}), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="preserve explicit finding linkage",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=False,
                finding="VA-007",
                identity=None,
                identity_scope="",
            )
        )

    assert exc_info.value.code == 4
    assert len(posts) == 1
    assert posts[0]["finding_id"] == 7
    assert events == ["resolve:findings/VA-007", "post"]


def test_host_exec_destructive_gate_allows_format_flags_but_blocks_format_command() -> None:
    module = _load_assess_module(
        "host_exec_command_module_destructive_format",
        "agent/scripts/assess/commands/host_exec.py",
    )

    assert module._contains_destructive_token(
        ["gcloud", "logging", "read", "severity>=ERROR", "--format=json"]
    ) is None
    assert module._contains_destructive_token(
        ["gam", "user", "alex@example.com", "show", "message", "abc123", "format", "raw"]
    ) is None
    assert module._contains_destructive_token(["format", "/q", "E:"]) == "format"
    assert module._contains_destructive_token([r"C:\Windows\System32\format.com", "E:"]) == "format"
    assert module._contains_destructive_token(["formatter", "raw"]) is None
    assert module._contains_destructive_token(["rm", "-rf", "/tmp/example"]) == "rm -r"


def test_host_exec_registers_process_before_communicate_and_unregisters_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_process_registry",
        "agent/scripts/assess/commands/host_exec.py",
    )
    events: list[str] = []

    class _Proc:
        pid = 4321
        returncode = 0

        def communicate(self, timeout: int):
            events.append("communicate")
            return "ok\n", ""

    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: _Proc())
    _patch_test_host_ownership(module, monkeypatch)
    monkeypatch.setattr(
        module.host_processes,
        "register_owned_process",
        lambda *a, **k: events.append("register"),
    )
    monkeypatch.setattr(
        module.host_processes,
        "unregister_process",
        lambda *a, **k: events.append("unregister"),
    )

    result = module._run_host_process(
        ["echo", "ok"],
        cwd=str(tmp_path),
        timeout_seconds=30,
        engagement_dir=str(tmp_path),
        run_uuid="run-1",
    )

    assert result == (0, "ok\n", "", False)
    assert events == ["register", "communicate", "unregister"]


def test_host_exec_preview_reads_the_open_spill_not_a_swapped_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_preview_fd_pin",
        "agent/scripts/assess/commands/host_exec.py",
    )
    run_uuid = "preview-fd-pin"
    output_dir = tmp_path / "scans" / "host-exec"
    stdout_path = output_dir / f"{run_uuid}.out"
    moved_path = output_dir / "moved-original.out"
    secret_path = tmp_path / "secret.txt"
    secret_path.write_text("secret replacement must not be previewed\n", encoding="utf-8")

    class _Proc:
        pid = 4321
        returncode = 0

        def __init__(self, *, stdout, stderr, **_kwargs):
            self.stdout = stdout
            self.stderr = stderr

        def communicate(self, timeout: int):
            self.stdout.write(b"trusted process output\n")
            self.stdout.flush()
            stdout_path.replace(moved_path)
            stdout_path.symlink_to(secret_path)
            return "", ""

        def poll(self):
            return 0

    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: _Proc(**k))
    _patch_test_host_ownership(module, monkeypatch)
    monkeypatch.setattr(module.host_processes, "register_owned_process", lambda *a, **k: None)
    monkeypatch.setattr(module.host_processes, "unregister_process", lambda *a, **k: None)

    result = module._run_host_process(
        ["echo", "ok"],
        cwd=str(tmp_path),
        timeout_seconds=30,
        engagement_dir=str(tmp_path),
        run_uuid=run_uuid,
    )

    assert result == (0, "trusted process output\n", "", False)
    assert moved_path.read_text(encoding="utf-8") == "trusted process output\n"


def test_host_exec_quiesces_background_child_before_returning_output(
    tmp_path: Path,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_residual_group",
        "agent/scripts/assess/commands/host_exec.py",
    )
    child_pid_path = tmp_path / "child.pid"
    run_uuid = "run-residual-group"
    child_pid = 0
    try:
        result = module._run_host_process(
            [
                sys.executable,
                "-c",
                (
                    "import subprocess, sys; "
                    "child = subprocess.Popen([sys.executable, '-c', "
                    "'import time; time.sleep(30)'], stdin=subprocess.DEVNULL, "
                    "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
                    "open(sys.argv[1], 'w', encoding='ascii').write(str(child.pid))"
                ),
                str(child_pid_path),
            ],
            cwd=str(tmp_path),
            timeout_seconds=10,
            engagement_dir=str(tmp_path),
            run_uuid=run_uuid,
        )
        child_pid = int(child_pid_path.read_text(encoding="ascii"))

        assert result[0] == 0
        registry = (
            tmp_path / ".runtime" / "host-processes" / f"{run_uuid}.json"
        )
        assert not registry.exists()
        assert module.host_processes._pid_exists(child_pid) is False
    finally:
        if child_pid:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_host_exec_quiesces_surviving_group_without_registry_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_registry_read_failure",
        "agent/scripts/assess/commands/host_exec.py",
    )
    child_pid_path = tmp_path / "registry-failure-child.pid"
    run_uuid = "run-registry-read-failure"
    original_popen = module.subprocess.Popen
    spawned: list[subprocess.Popen] = []
    child_pid = 0

    def capture_popen(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        spawned.append(process)
        return process

    monkeypatch.setattr(module.subprocess, "Popen", capture_popen)
    try:
        result = module._run_host_process(
            [
                sys.executable,
                "-c",
                (
                    "import subprocess, sys; "
                    "child = subprocess.Popen([sys.executable, '-c', "
                    "'import time; time.sleep(30)'], stdin=subprocess.DEVNULL, "
                    "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
                    "open(sys.argv[1], 'w', encoding='ascii').write(str(child.pid))"
                ),
                str(child_pid_path),
            ],
            cwd=str(tmp_path),
            timeout_seconds=10,
            engagement_dir=str(tmp_path),
            run_uuid=run_uuid,
        )
        child_pid = int(child_pid_path.read_text(encoding="ascii"))

        assert result[0] == 0
        assert module.host_processes._pid_exists(child_pid) is False
        registry = tmp_path / ".runtime" / "host-processes" / f"{run_uuid}.json"
        assert not registry.exists()
    finally:
        for process in spawned:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
        if child_pid:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_host_exec_in_memory_ownership_never_signals_a_reused_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_registry_pid_reuse",
        "agent/scripts/assess/commands/host_exec.py",
    )
    ownership = module.host_processes.ProcessOwnership(
        pid=4321,
        pgid=4321,
        process_identity="original",
    )

    monkeypatch.setattr(
        module.host_processes,
        "_process_identity",
        lambda _pid: "replacement",
    )
    monkeypatch.setattr(module.host_processes, "_pid_exists", lambda _pid: True)
    monkeypatch.setattr(
        module.host_processes.os,
        "killpg",
        lambda *_args: pytest.fail("reused process group must never be signalled"),
    )

    with pytest.raises(module.HostProcessNotQuiescent):
        module._quiesce_registered_host_process(
            engagement_dir=str(tmp_path),
            run_uuid="run-registry-pid-reuse",
            ownership=ownership,
        )


def test_host_exec_tightens_owned_legacy_output_directory_without_changing_scans_mode(
    tmp_path: Path,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_legacy_output_mode",
        "agent/scripts/assess/commands/host_exec.py",
    )
    scans_dir = tmp_path / "scans"
    output_dir = scans_dir / "host-exec"
    output_dir.mkdir(parents=True)
    scans_dir.chmod(0o755)
    output_dir.chmod(0o755)

    descriptor = module._open_host_exec_output_directory(tmp_path)
    try:
        assert module.stat.S_IMODE(module.os.fstat(descriptor).st_mode) == 0o700
    finally:
        module.os.close(descriptor)

    assert module.stat.S_IMODE(scans_dir.stat().st_mode) == 0o755
    assert module.stat.S_IMODE(output_dir.stat().st_mode) == 0o700


def test_host_exec_rejects_unowned_legacy_output_directory_before_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_unowned_output_mode",
        "agent/scripts/assess/commands/host_exec.py",
    )
    output_dir = tmp_path / "scans" / "host-exec"
    output_dir.mkdir(parents=True)
    output_dir.chmod(0o755)
    output_identity = (output_dir.stat().st_dev, output_dir.stat().st_ino)
    real_fstat = module.os.fstat

    def report_output_as_unowned(descriptor: int):
        metadata = real_fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == output_identity:
            return SimpleNamespace(
                st_mode=metadata.st_mode,
                st_uid=module.os.geteuid() + 1,
            )
        return metadata

    monkeypatch.setattr(module.os, "fstat", report_output_as_unowned)
    monkeypatch.setattr(
        module.os,
        "fchmod",
        lambda *_args: pytest.fail("unowned output directory must not be chmodded"),
    )

    with pytest.raises(module.AssessError, match="not owned by the current user"):
        module._open_host_exec_output_directory(tmp_path)


def test_host_exec_mode_repair_stays_on_pinned_descriptor_during_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_output_mode_fd_pin",
        "agent/scripts/assess/commands/host_exec.py",
    )
    scans_dir = tmp_path / "scans"
    output_dir = scans_dir / "host-exec"
    output_dir.mkdir(parents=True)
    output_dir.chmod(0o755)
    moved_output_dir = scans_dir / "moved-host-exec"
    attacker_output_dir = tmp_path / "attacker-host-exec"
    attacker_output_dir.mkdir()
    attacker_output_dir.chmod(0o755)
    real_fchmod = module.os.fchmod
    swapped = False

    def swap_before_chmod(descriptor: int, mode: int) -> None:
        nonlocal swapped
        if not swapped:
            swapped = True
            output_dir.replace(moved_output_dir)
            output_dir.symlink_to(attacker_output_dir, target_is_directory=True)
        real_fchmod(descriptor, mode)

    monkeypatch.setattr(module.os, "fchmod", swap_before_chmod)

    descriptor = module._open_host_exec_output_directory(tmp_path)
    try:
        opened = module.os.fstat(descriptor)
        moved = moved_output_dir.stat()
        assert (opened.st_dev, opened.st_ino) == (moved.st_dev, moved.st_ino)
    finally:
        module.os.close(descriptor)

    assert swapped is True
    assert output_dir.is_symlink()
    assert module.stat.S_IMODE(moved_output_dir.stat().st_mode) == 0o700
    assert module.stat.S_IMODE(attacker_output_dir.stat().st_mode) == 0o755


def test_host_exec_rejects_symlinked_output_directory_without_chmodding_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_output_mode_symlink",
        "agent/scripts/assess/commands/host_exec.py",
    )
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()
    attacker_output_dir = tmp_path / "attacker-host-exec"
    attacker_output_dir.mkdir()
    attacker_output_dir.chmod(0o755)
    (scans_dir / "host-exec").symlink_to(
        attacker_output_dir,
        target_is_directory=True,
    )
    monkeypatch.setattr(
        module.os,
        "fchmod",
        lambda *_args: pytest.fail("symlink target must not be chmodded"),
    )

    with pytest.raises(OSError):
        module._open_host_exec_output_directory(tmp_path)

    assert module.stat.S_IMODE(attacker_output_dir.stat().st_mode) == 0o755


def test_host_exec_precreated_descriptors_survive_parent_directory_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_parent_fd_pin",
        "agent/scripts/assess/commands/host_exec.py",
    )
    posted_paths: dict[str, Path] = {}
    patches: list[dict] = []
    moved_output_dir = tmp_path / f"moved-host-exec-{uuid.uuid4().hex}"
    attacker_output_dir = tmp_path / "attacker-host-exec"
    attacker_output_dir.mkdir()

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, _endpoint: str, payload: dict) -> dict:
            posted_paths["stdout"] = Path(payload["stdout_path"])
            posted_paths["stderr"] = Path(payload["stderr_path"])
            output_dir = posted_paths["stdout"].parent
            output_dir.replace(moved_output_dir)
            output_dir.symlink_to(attacker_output_dir, target_is_directory=True)
            return self._pre_exec_response(payload)

        def patch(self, _endpoint: str, payload: dict, **_kwargs: object) -> dict:
            patches.append(payload)
            return self._finalize_response(
                payload,
                output_cleanup_status="complete",
            )

        def close(self) -> None:
            pass

    class _Proc:
        pid = 4321
        returncode = 0

        def __init__(self, *, stdout, stderr, **_kwargs: object) -> None:
            stdout.write(b"trusted stdout\n")
            stdout.flush()
            stderr.write(b"trusted stderr\n")
            stderr.flush()

        def communicate(self, timeout: int):
            return None, None

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "prepare_execution_command", lambda *_a, **_k: "anonymous")
    monkeypatch.setattr(module.scope_lib, "enforce_execution_policy", lambda *_a, **_k: {})
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: _Proc(**k))
    _patch_test_host_ownership(module, monkeypatch)
    monkeypatch.setattr(module.host_processes, "register_owned_process", lambda *a, **k: None)
    monkeypatch.setattr(module.host_processes, "unregister_process", lambda *a, **k: None)

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="pin host output descriptors",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
            )
        )

    assert exc_info.value.code == 0
    assert patches
    assert (moved_output_dir / posted_paths["stdout"].name).read_bytes() == b"trusted stdout\n"
    assert (moved_output_dir / posted_paths["stderr"].name).read_bytes() == b"trusted stderr\n"
    assert list(attacker_output_dir.iterdir()) == []


def test_host_exec_spill_identity_claims_reject_leaf_swap_before_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_prepost_leaf_swap",
        "agent/scripts/assess/commands/host_exec.py",
    )
    moved_metadata: dict[str, os.stat_result] = {}
    posted: list[dict] = []

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            output_dir = tmp_path / "scans" / "host-exec"
            for path in output_dir.iterdir():
                moved = path.with_name(f"moved-{path.name}")
                path.replace(moved)
                moved_metadata[path.suffix] = moved.stat()
                path.write_bytes(b"attacker replacement")

        def post(self, _endpoint: str, payload: dict) -> dict:
            posted.append(payload)
            raise module.AssessError(
                "HTTP 409:\nbackend rejected spill identity mismatch"
            )

        def close(self) -> None:
            pass

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "prepare_execution_command", lambda *_a, **_k: "anonymous")
    monkeypatch.setattr(module.scope_lib, "enforce_execution_policy", lambda *_a, **_k: {})
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_a, **_k: pytest.fail("identity-rejected command must not execute"),
    )

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="bind spill identity before post",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
            )
        )

    assert exc_info.value.code == 4
    assert len(posted) == 1
    payload = posted[0]
    stdout_replacement = Path(payload["stdout_path"]).stat()
    stderr_replacement = Path(payload["stderr_path"]).stat()
    assert payload["stdout_spill_device"] == moved_metadata[".out"].st_dev
    assert payload["stdout_spill_inode"] == moved_metadata[".out"].st_ino
    assert payload["stderr_spill_device"] == moved_metadata[".err"].st_dev
    assert payload["stderr_spill_inode"] == moved_metadata[".err"].st_ino
    assert payload["stdout_spill_inode"] != stdout_replacement.st_ino
    assert payload["stderr_spill_inode"] != stderr_replacement.st_ino


def test_host_exec_partial_spill_creation_never_unlinks_a_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_partial_create",
        "agent/scripts/assess/commands/host_exec.py",
    )
    stdout_path = tmp_path / "run.out"
    moved_stdout = tmp_path / "moved.out"
    stderr_path = tmp_path / "run.err"
    stderr_path.write_bytes(b"force second create failure")
    original_open = module.os.open
    leaf_create_count = 0

    def swapping_open(path, flags, *args, **kwargs):
        nonlocal leaf_create_count
        if flags & module.os.O_EXCL:
            leaf_create_count += 1
            if leaf_create_count == 2:
                stdout_path.replace(moved_stdout)
                stdout_path.write_bytes(b"replacement must survive")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", swapping_open)

    with pytest.raises(FileExistsError):
        module._create_output_spills(stdout_path, stderr_path)

    assert stdout_path.read_bytes() == b"replacement must survive"
    assert moved_stdout.read_bytes() == b""


def test_host_exec_spill_leaf_creation_is_nonblocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_nonblocking_spills",
        "agent/scripts/assess/commands/host_exec.py",
    )
    original_open = module.os.open
    leaf_flags: list[int] = []

    def recording_open(path, flags, *args, **kwargs):
        if flags & module.os.O_EXCL:
            leaf_flags.append(flags)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", recording_open)
    descriptors = module._create_output_spills(
        tmp_path / "run.out", tmp_path / "run.err"
    )
    if descriptors is not None:
        for descriptor in descriptors:
            module.os.close(descriptor)

    assert len(leaf_flags) == 2
    assert all(flags & module.os.O_NONBLOCK for flags in leaf_flags)


def test_host_exec_spills_stdout_and_stderr_from_process_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_spill",
        "agent/scripts/assess/commands/host_exec.py",
    )
    stdout_path = tmp_path / "run.out"
    stderr_path = tmp_path / "run.err"

    class _Proc:
        pid = 4321
        returncode = 0

        def poll(self):
            return 0

        def communicate(self, timeout: int):
            return None, None

    def fake_popen(*_args, stdout, stderr, **_kwargs):
        stdout.write(b"first stdout line\n")
        stdout.flush()
        stderr.write(b"first stderr line\n")
        stderr.flush()
        return _Proc()

    monkeypatch.setattr(module.subprocess, "Popen", fake_popen)
    _patch_test_host_ownership(module, monkeypatch)
    monkeypatch.setattr(module.host_processes, "register_owned_process", lambda *a, **k: None)
    monkeypatch.setattr(module.host_processes, "unregister_process", lambda *a, **k: None)

    result = module._run_host_process(
        ["example"],
        cwd=str(tmp_path),
        timeout_seconds=30,
        engagement_dir=str(tmp_path),
        run_uuid="run-spill",
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )

    assert result == (0, "first stdout line\n", "first stderr line\n", False)
    assert stdout_path.read_text() == "first stdout line\n"
    assert stderr_path.read_text() == "first stderr line\n"


def test_host_exec_large_output_returns_bounded_head_tail_preview(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_bounded_preview",
        "agent/scripts/assess/commands/host_exec.py",
    )
    stdout_path = tmp_path / "large.out"
    stderr_path = tmp_path / "large.err"

    class _Proc:
        pid = 4321
        returncode = 0

        def communicate(self, timeout: int):
            return None, None

    def fake_popen(*_args, stdout, stderr, **_kwargs):
        stdout.write(b"HEAD\n" + b"x" * (2 * 1024 * 1024) + b"\nTAIL\n")
        stderr.write(b"ERRHEAD\n" + b"y" * (2 * 1024 * 1024) + b"\nERRTAIL\n")
        return _Proc()

    monkeypatch.setattr(module.subprocess, "Popen", fake_popen)
    _patch_test_host_ownership(module, monkeypatch)
    monkeypatch.setattr(module.host_processes, "register_owned_process", lambda *a, **k: None)
    monkeypatch.setattr(module.host_processes, "unregister_process", lambda *a, **k: None)

    _, stdout_preview, stderr_preview, _ = module._run_host_process(
        ["example"],
        cwd=str(tmp_path),
        timeout_seconds=30,
        engagement_dir=str(tmp_path),
        run_uuid="run-large",
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )

    assert len(stdout_preview.encode()) <= module._OUTPUT_PREVIEW_BYTES
    assert len(stderr_preview.encode()) <= module._OUTPUT_PREVIEW_BYTES
    assert stdout_preview.startswith("HEAD\n")
    assert stdout_preview.endswith("\nTAIL\n")
    assert "omitted; full output:" in stdout_preview
    assert stderr_preview.startswith("ERRHEAD\n")
    assert stderr_preview.endswith("\nERRTAIL\n")
    assert stdout_path.stat().st_size > 2 * 1024 * 1024
    assert stderr_path.stat().st_size > 2 * 1024 * 1024


def test_host_exec_fast_exit_before_registry_is_treated_as_already_reaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_fast_exit_registry",
        "agent/scripts/assess/commands/host_exec.py",
    )
    events: list[str] = []

    class _Proc:
        pid = 4321
        returncode = 0

        def poll(self):
            return 0

        def communicate(self, timeout: int):
            events.append(f"communicate:{timeout}")
            return "done\n", ""

    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: _Proc())
    monkeypatch.setattr(
        module.host_processes,
        "capture_process_ownership",
        lambda _pid: (_ for _ in ()).throw(module.AssessError("process already exited")),
    )
    monkeypatch.setattr(module, "_host_process_group_alive", lambda _pgid: False)

    assert module._run_host_process(
        ["true"],
        cwd=str(tmp_path),
        timeout_seconds=30,
        engagement_dir=str(tmp_path),
        run_uuid="run-fast",
    ) == (0, "done\n", "", False)
    assert events == ["communicate:1"]


def test_host_exec_registry_write_failure_quiesces_fast_leader_descendants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_fast_leader_descendant",
        "agent/scripts/assess/commands/host_exec.py",
    )
    child_pid_path = tmp_path / "fast-leader-child.pid"
    run_uuid = "run-fast-leader-child"
    original_popen = module.subprocess.Popen
    spawned: list[subprocess.Popen] = []
    child_pid = 0
    ownership = module.host_processes.ProcessOwnership(
        pid=0,
        pgid=0,
        process_identity="captured-before-registry-write",
    )

    def capture_popen(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        spawned.append(process)
        return process

    def capture_ownership(pid: int):
        return module.host_processes.ProcessOwnership(
            pid=pid,
            pgid=pid,
            process_identity=ownership.process_identity,
        )

    def wait_for_recorded_child_pid() -> str:
        """Wait until the grandchild's pid file *holds* its pid.

        The grandchild does `open(path, "w").write(str(os.getpid()))`, which
        creates the file before the digits land in it. Waiting on `.exists()`
        can therefore return while the file is still empty — near-impossible
        when this test runs alone, routine when the suite runs across one
        worker per CPU and the grandchild loses the race for a timeslice. Both
        the registry-write failure below (which must not fire until the
        grandchild is genuinely running) and the `int()` conversion afterwards
        need the content, not the inode.
        """
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                recorded = child_pid_path.read_text(encoding="ascii").strip()
            except OSError:
                recorded = ""
            if recorded:
                return recorded
            time.sleep(0.01)
        raise AssertionError(
            f"grandchild never recorded its pid in {child_pid_path}"
        )

    def fail_registry_after_leader_exit(*_args, **_kwargs):
        wait_for_recorded_child_pid()
        spawned[0].wait(timeout=5)
        raise RuntimeError("registry write failed after leader exit")

    monkeypatch.setattr(module.subprocess, "Popen", capture_popen)
    monkeypatch.setattr(
        module.host_processes,
        "capture_process_ownership",
        capture_ownership,
        raising=False,
    )
    monkeypatch.setattr(
        module.host_processes,
        "register_owned_process",
        fail_registry_after_leader_exit,
    )

    try:
        with pytest.raises(RuntimeError, match="registry write failed"):
            module._run_host_process(
                [
                    sys.executable,
                    "-c",
                    (
                        "import subprocess, sys; "
                        "subprocess.Popen([sys.executable, '-c', "
                        "\"import os,sys,time; "
                        "open(sys.argv[1], 'w', encoding='ascii').write(str(os.getpid())); "
                        "time.sleep(2); print('LATE-DESCENDANT', flush=True)\", "
                        "sys.argv[1]], stdin=subprocess.DEVNULL)"
                    ),
                    str(child_pid_path),
                ],
                cwd=str(tmp_path),
                timeout_seconds=10,
                engagement_dir=str(tmp_path),
                run_uuid=run_uuid,
            )
        child_pid = int(wait_for_recorded_child_pid())
        assert module.host_processes._pid_exists(child_pid) is False
        stdout_path = tmp_path / "scans" / "host-exec" / f"{run_uuid}.out"
        assert b"LATE-DESCENDANT" not in stdout_path.read_bytes()
    finally:
        for process in spawned:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
        if child_pid:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_host_exec_registry_failure_terminates_process_group_with_bounded_kill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_registry_failure",
        "agent/scripts/assess/commands/host_exec.py",
    )
    signals: list[int] = []

    class _Proc:
        pid = 4321
        returncode = None

        def poll(self):
            return None

        def communicate(self, timeout: int):
            raise module.subprocess.TimeoutExpired("cmd", timeout)

    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: _Proc())
    monkeypatch.setattr(
        module.host_processes,
        "register_owned_process",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("registry unavailable")),
    )
    alive = True

    def fake_killpg(_pgid, sig):
        nonlocal alive
        if sig == 0:
            if alive:
                return
            raise ProcessLookupError
        signals.append(sig)
        if sig == module.signal.SIGKILL:
            alive = False

    monkeypatch.setattr(
        module.host_processes,
        "capture_process_ownership",
        lambda pid: module.host_processes.ProcessOwnership(pid, pid, "owned"),
    )
    monkeypatch.setattr(module.host_processes, "_process_identity", lambda _pid: "owned")
    monkeypatch.setattr(module.host_processes, "_process_group_id", lambda pid: pid)
    monkeypatch.setattr(module.host_processes.os, "killpg", fake_killpg)
    monkeypatch.setattr(
        module.host_processes,
        "_wait_for_owned_exit",
        lambda *_args: not alive,
    )

    with pytest.raises(RuntimeError, match="registry unavailable"):
        module._run_host_process(
            ["sleep", "60"],
            cwd=str(tmp_path),
            timeout_seconds=30,
            engagement_dir=str(tmp_path),
            run_uuid="run-registry-fail",
        )

    assert signals == [module.signal.SIGTERM, module.signal.SIGKILL]


def test_host_exec_registry_failure_refuses_output_when_group_exit_is_unproven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_registry_failure_unquiesced",
        "agent/scripts/assess/commands/host_exec.py",
    )

    class _Proc:
        pid = 4321
        returncode = None

        def poll(self):
            return None

        def communicate(self, timeout: int):
            raise module.subprocess.TimeoutExpired("cmd", timeout)

    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: _Proc())
    monkeypatch.setattr(
        module.host_processes,
        "register_owned_process",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("registry unavailable")),
    )
    monkeypatch.setattr(
        module.host_processes,
        "capture_process_ownership",
        lambda pid: module.host_processes.ProcessOwnership(pid, pid, "owned"),
    )
    monkeypatch.setattr(module.host_processes, "_process_identity", lambda _pid: "owned")
    monkeypatch.setattr(module.host_processes, "_process_group_id", lambda pid: pid)
    monkeypatch.setattr(module.host_processes.os, "killpg", lambda *_args: None)
    monkeypatch.setattr(
        module.host_processes,
        "_wait_for_owned_exit",
        lambda *_args: False,
    )

    with pytest.raises(module.HostProcessNotQuiescent):
        module._run_host_process(
            ["sleep", "60"],
            cwd=str(tmp_path),
            timeout_seconds=30,
            engagement_dir=str(tmp_path),
            run_uuid="run-registry-unquiesced",
        )


def test_host_exec_refuses_preview_when_registered_group_cannot_be_quiesced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_unquiesced_group",
        "agent/scripts/assess/commands/host_exec.py",
    )

    class _Proc:
        pid = 4321
        returncode = 0

        def communicate(self, timeout: int):
            return None, None

    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: _Proc())
    _patch_test_host_ownership(module, monkeypatch, quiescent=False)
    monkeypatch.setattr(module.host_processes, "register_owned_process", lambda *a, **k: None)
    with pytest.raises(module.AssessError, match="cannot establish quiescence"):
        module._run_host_process(
            ["example"],
            cwd=str(tmp_path),
            timeout_seconds=30,
            engagement_dir=str(tmp_path),
            run_uuid="run-unquiesced",
        )


def test_host_exec_false_registry_absence_cannot_bypass_in_memory_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_false_registry_absence",
        "agent/scripts/assess/commands/host_exec.py",
    )
    ownership = module.host_processes.ProcessOwnership(
        pid=4321,
        pgid=4321,
        process_identity="trusted-live-token",
    )
    events: list[str] = []
    monkeypatch.setattr(
        module.host_processes,
        "terminate_owned_process",
        lambda candidate: (
            events.append(f"memory-proof:{candidate.process_identity}") or True
        ),
    )
    monkeypatch.setattr(
        module.host_processes,
        "unregister_process",
        lambda *a, **k: events.append("unregister"),
    )

    module._quiesce_registered_host_process(
        engagement_dir=str(tmp_path),
        run_uuid="run-false-absence",
        ownership=ownership,
    )

    assert events == ["memory-proof:trusted-live-token", "unregister"]


def test_host_exec_communicate_error_still_quiesces_registered_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_communicate_error_group",
        "agent/scripts/assess/commands/host_exec.py",
    )
    original_popen = module.subprocess.Popen
    spawned: list[subprocess.Popen] = []

    def flaky_popen(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        spawned.append(process)
        original_communicate = process.communicate
        first_call = True

        def flaky_communicate(*, timeout):
            nonlocal first_call
            if first_call:
                first_call = False
                raise OSError("capture pipe failed")
            return original_communicate(timeout=timeout)

        process.communicate = flaky_communicate
        return process

    monkeypatch.setattr(
        module,
        "subprocess",
        SimpleNamespace(Popen=flaky_popen, TimeoutExpired=subprocess.TimeoutExpired),
    )
    run_uuid = "run-communicate-error"
    try:
        with pytest.raises(OSError, match="capture pipe failed"):
            module._run_host_process(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                cwd=str(tmp_path),
                timeout_seconds=30,
                engagement_dir=str(tmp_path),
                run_uuid=run_uuid,
            )

        assert len(spawned) == 1
        assert module.host_processes._pid_exists(spawned[0].pid) is False
        registry = tmp_path / ".runtime" / "host-processes" / f"{run_uuid}.json"
        assert not registry.exists()
    finally:
        for process in spawned:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass


def test_host_exec_records_lost_when_group_cannot_be_quiesced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_unquiesced_audit",
        "agent/scripts/assess/commands/host_exec.py",
    )
    patches: list[dict] = []

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, _endpoint: str, _payload: dict) -> dict:
            return self._pre_exec_response(_payload)

        def patch(self, _endpoint: str, payload: dict, **_kwargs: object) -> dict:
            patches.append(payload)
            return self._finalize_response(payload)

        def close(self) -> None:
            pass

    class _Proc:
        pid = 4321
        returncode = 0

        def communicate(self, timeout: int):
            return None, None

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "prepare_execution_command", lambda *_a, **_k: "anonymous")
    monkeypatch.setattr(module.scope_lib, "enforce_execution_policy", lambda *_a, **_k: {})
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: _Proc())
    _patch_test_host_ownership(module, monkeypatch, quiescent=False)
    monkeypatch.setattr(module.host_processes, "register_owned_process", lambda *a, **k: None)
    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["example"],
                tool="example",
                intent="verify output quiescence",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
            )
        )

    assert exc_info.value.code == 4
    assert len(patches) == 1
    assert patches[0]["status"] == "lost"
    assert patches[0]["output_quiesced"] is False
    assert patches[0]["stdout_preview"] == ""
    assert "cannot establish quiescence" in patches[0]["stderr_preview"]


def test_host_exec_process_failure_finalizes_pre_exec_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_process_failure_audit",
        "agent/scripts/assess/commands/host_exec.py",
    )
    patches: list[tuple[str, dict]] = []
    spill_paths: dict[str, Path] = {}

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, _endpoint: str, payload: dict) -> dict:
            spill_paths["stdout"] = Path(payload["stdout_path"])
            spill_paths["stderr"] = Path(payload["stderr_path"])
            assert spill_paths["stdout"].is_file()
            assert spill_paths["stderr"].is_file()
            assert spill_paths["stdout"].stat().st_mode & 0o777 == 0o600
            assert spill_paths["stderr"].stat().st_mode & 0o777 == 0o600
            return self._pre_exec_response(payload)

        def patch(self, endpoint: str, payload: dict, **_kwargs: object) -> dict:
            patches.append((endpoint, payload))
            return self._finalize_response(payload)

        def close(self) -> None:
            pass

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("registry unavailable")),
    )
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": []}), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="audit process setup failure",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
            )
        )

    assert exc_info.value.code == 1
    assert patches[0][0] == "command-runs/42"
    assert patches[0][1]["status"] == "failed"
    assert "registry unavailable" in patches[0][1]["stderr_preview"]
    assert spill_paths["stdout"].read_bytes() == b""
    assert "registry unavailable" in spill_paths["stderr"].read_text(encoding="utf-8")


def test_host_exec_process_setup_append_failure_still_finalizes_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_append_failure_finalize",
        "agent/scripts/assess/commands/host_exec.py",
    )
    patches: list[tuple[str, dict]] = []

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, _endpoint: str, _payload: dict) -> dict:
            return self._pre_exec_response(_payload)

        def patch(self, endpoint: str, payload: dict, **_kwargs: object) -> dict:
            patches.append((endpoint, payload))
            return self._finalize_response(payload)

        def close(self) -> None:
            pass

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("process setup exploded")
        ),
    )
    monkeypatch.setattr(
        module,
        "_append_spill_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("spill append failed")),
    )
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": []}), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="audit setup and spill failure",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
            )
        )

    assert exc_info.value.code == 1
    assert patches[0][0] == "command-runs/42"
    assert patches[0][1]["status"] == "failed"
    assert "process setup exploded" in patches[0][1]["stderr_preview"]
    assert "spill append failed" in patches[0][1]["stderr_preview"]


def test_host_exec_accepts_exact_terminal_row_after_committed_response_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_finalize_response_loss",
        "agent/scripts/assess/commands/host_exec.py",
    )
    patches: list[tuple[dict, bool]] = []

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, _endpoint: str, _payload: dict) -> dict:
            return self._pre_exec_response(_payload)

        def patch(
            self,
            _endpoint: str,
            payload: dict,
            *,
            accept_409: bool = False,
        ) -> dict:
            patches.append((dict(payload), accept_409))
            if not accept_409:
                raise module.AssessError(
                    "Failed after retry: first finalize committed but its response was lost"
                )
            return {
                "id": 42,
                "run_uuid": self._run_uuid,
                "finalize_409": True,
                "status": payload["status"],
                "return_code": payload["return_code"],
                "timed_out": payload["timed_out"],
                "duration_ms": payload["duration_ms"],
                "partial_results": payload["partial_results"],
                "completed_at": payload["ended_at"].replace("Z", "+00:00"),
                "output_cleanup_status": "not_required",
                "output_integrity_status": "verified",
            }

        def close(self) -> None:
            pass

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "prepare_execution_command", lambda *_a, **_k: "member")
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_args, **_kwargs: (0, "trusted output\n", "", False),
    )
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": []}), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="recover exact finalize response",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
            )
        )

    assert exc_info.value.code == 0
    assert len(patches) == 1
    assert patches[0][1] is True


def test_host_exec_rejects_conflicting_terminal_row_after_finalize_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_finalize_conflict",
        "agent/scripts/assess/commands/host_exec.py",
    )
    patches: list[tuple[dict, bool]] = []

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, _endpoint: str, _payload: dict) -> dict:
            return self._pre_exec_response(_payload)

        def patch(
            self,
            _endpoint: str,
            payload: dict,
            *,
            accept_409: bool = False,
        ) -> dict:
            patches.append((dict(payload), accept_409))
            return {
                "id": 42,
                "run_uuid": self._run_uuid,
                "finalize_409": True,
                "status": payload["status"],
                "return_code": payload["return_code"],
                "timed_out": payload["timed_out"],
                "duration_ms": payload["duration_ms"],
                "partial_results": not payload["partial_results"],
                "completed_at": payload["ended_at"].replace("Z", "+00:00"),
                "output_cleanup_status": "not_required",
                "output_integrity_status": "verified",
            }

        def close(self) -> None:
            pass

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "prepare_execution_command", lambda *_a, **_k: "member")
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_args, **_kwargs: (0, "trusted output\n", "", False),
    )
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": []}), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="reject conflicting finalize response",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
            )
        )

    assert exc_info.value.code == 4
    assert len(patches) == 1


def test_host_exec_policy_refusal_uses_terminal_inline_audit_without_spills(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_policy_refusal",
        "agent/scripts/assess/commands/host_exec.py",
    )
    posts: list[tuple[str, dict]] = []

    class _Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, endpoint: str, payload: dict) -> dict:
            posts.append((endpoint, payload))
            return {"id": 42}

        def close(self) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "prepare_execution_command", lambda *_a, **_k: "anonymous")
    monkeypatch.setattr(
        module.scope_lib,
        "enforce_execution_policy",
        lambda *_a, **_k: (_ for _ in ()).throw(
            module.scope_lib.ScopePolicyError("tool is outside declared scope")
        ),
    )
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_a, **_k: pytest.fail("policy-refused command must not execute"),
    )
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": []}), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "blocked"],
                tool="echo",
                intent="verify policy refusal audit",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
                identity=None,
                identity_scope="",
            )
        )

    assert exc_info.value.code == 3
    assert len(posts) == 1
    endpoint, payload = posts[0]
    assert endpoint == "command-runs/host-exec"
    assert payload["host_record_kind"] == "policy_refusal"
    assert payload["status"] == "failed"
    assert "outside declared scope" in payload["stderr"]
    assert payload["stdout_path"] is None
    assert payload["stderr_path"] is None


@pytest.mark.parametrize(
    ("container_key", "message_fragment"),
    [
        ("other-engagement", "other-engagement"),
        ("eng", "cannot be executed by host-exec"),
    ],
)
def test_host_exec_refuses_container_namespace_script_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    container_key: str,
    message_fragment: str,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_cross_engagement_path",
        "agent/scripts/assess/commands/host_exec.py",
    )
    engagement_dir = tmp_path / "eng"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hosts": ["allowed.example"]}), encoding="utf-8"
    )
    (engagement_dir / "probe.py").write_text(
        'import requests\nrequests.get("https://allowed.example")\n',
        encoding="utf-8",
    )
    posts: list[tuple[str, dict]] = []

    class _Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, endpoint: str, payload: dict) -> dict:
            posts.append((endpoint, payload))
            return {"id": 42}

        def close(self) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(module, "prepare_execution_command", lambda *_a, **_k: "anonymous")
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_args, **_kwargs: pytest.fail("policy-refused command must not execute"),
    )

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(engagement_dir),
                from_json=None,
                command=["python3", f"/engagements/{container_key}/probe.py"],
                tool="python3",
                intent="cross-engagement script path",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
                identity=None,
                identity_scope="",
            )
        )

    assert exc_info.value.code == 3
    assert len(posts) == 1
    assert message_fragment in posts[0][1]["stderr"]


def test_host_exec_emits_nonblocking_recency_advisory_after_pre_exec_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_recency_advisory",
        "agent/scripts/assess/commands/host_exec.py",
    )
    events: list[str] = []

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, _endpoint: str, _payload: dict) -> dict:
            events.append("audit")
            return self._pre_exec_response(_payload)

        def patch(self, _endpoint: str, payload: dict, **_kwargs: object) -> dict:
            events.append("finalize")
            return self._finalize_response(payload)

        def close(self) -> None:
            pass

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(
        module,
        "emit_foreign_lane_recency",
        lambda *_args, **_kwargs: events.append("advisory"),
    )
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_args, **_kwargs: (events.append("process") or (0, "", "", False)),
    )
    (tmp_path / "scope.json").write_text(
        json.dumps({"hosts": ["target.example"], "aggregate_rate_limit_rps": 10}),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["curl", "https://target.example/health"],
                tool="curl",
                intent="host liveness",
                technique="RECON",
                phase="recon",
                target_host="target.example",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
            )
        )

    assert exc_info.value.code == 0
    assert events == [
        "audit",
        "advisory",
        "process",
        "finalize",
    ]


@pytest.mark.parametrize("require_audit", [False, True])
def test_host_exec_fails_closed_when_pre_exec_audit_record_fails(
    require_audit: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_require_audit",
        "agent/scripts/assess/commands/host_exec.py",
    )

    class _Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, _endpoint: str, _payload: dict) -> dict:
            raise RuntimeError("backend down")

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_args, **_kwargs: pytest.fail("WRITE must not execute without its required pre-audit"),
    )
    (tmp_path / "scope.json").write_text(json.dumps({"hosts": []}), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="test required audit",
                technique="T0000",
                phase="respond",
                target_host="",
                agent_name=None,
                scope_host="acme",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=require_audit,
            )
        )

    assert exc_info.value.code == 4


@pytest.mark.parametrize(
    ("status_field", "untrustworthy_status"),
    [
        ("output_cleanup_status", "warning"),
        ("output_cleanup_status", "pending"),
        ("output_integrity_status", "warning"),
        ("output_integrity_status", "pending"),
    ],
)
def test_host_exec_require_audit_rejects_untrustworthy_output_status(
    status_field: str,
    untrustworthy_status: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        f"host_exec_command_module_{status_field}_{untrustworthy_status}",
        "agent/scripts/assess/commands/host_exec.py",
    )

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, _endpoint: str, _payload: dict) -> dict:
            return self._pre_exec_response(_payload)

        def patch(self, _endpoint: str, payload: dict, **_kwargs: object) -> dict:
            response = self._finalize_response(
                payload,
                output_cleanup_status="complete",
                output_integrity_status="verified",
                output_cleanup_warning="retained spill could not be removed",
                output_integrity_warning="retained snapshot could not be verified",
            )
            response[status_field] = untrustworthy_status
            return response

        def close(self) -> None:
            pass

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "prepare_execution_command", lambda *_a, **_k: "anonymous")
    monkeypatch.setattr(module.scope_lib, "enforce_execution_policy", lambda *_a, **_k: {})
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_args, **_kwargs: (0, "ok\n", "", False),
    )

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="require trustworthy audit cleanup",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
            )
        )

    assert exc_info.value.code == 4
    label = status_field.removeprefix("output_").removesuffix("_status")
    assert f"output {label} is {untrustworthy_status}" in capsys.readouterr().err


def test_host_exec_require_audit_rejects_deferred_physical_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_deferred_cleanup",
        "agent/scripts/assess/commands/host_exec.py",
    )

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, _endpoint: str, _payload: dict) -> dict:
            return self._pre_exec_response(_payload)

        def patch(self, _endpoint: str, payload: dict, **_kwargs: object) -> dict:
            return self._finalize_response(
                payload,
                output_cleanup_status="deferred",
                output_cleanup_warning="physical erasure deferred by policy",
                output_integrity_status="not_applicable",
            )

        def close(self) -> None:
            pass

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "prepare_execution_command", lambda *_a, **_k: "anonymous")
    monkeypatch.setattr(module.scope_lib, "enforce_execution_policy", lambda *_a, **_k: {})
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_args, **_kwargs: (0, "", "", False),
    )

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="report deferred cleanup",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
            )
        )

    assert exc_info.value.code == 4
    assert "output cleanup is deferred" in capsys.readouterr().err


def test_host_exec_console_write_failure_cannot_strand_a_quiesced_audit_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_broken_console",
        "agent/scripts/assess/commands/host_exec.py",
    )
    patches: list[dict] = []
    warnings: list[str] = []

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, _endpoint: str, _payload: dict) -> dict:
            return self._pre_exec_response(_payload)

        def patch(self, _endpoint: str, payload: dict, **_kwargs: object) -> dict:
            patches.append(payload)
            return self._finalize_response(
                payload,
                output_cleanup_status="not_required",
                output_integrity_status="verified",
            )

        def close(self) -> None:
            pass

    class _BrokenStdout:
        def write(self, _value: str) -> None:
            raise BrokenPipeError("consumer closed")

        def flush(self) -> None:
            pass

    class _WarningSink:
        def write(self, value: str) -> None:
            warnings.append(value)

        def flush(self) -> None:
            pass

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "prepare_execution_command", lambda *_a, **_k: "anonymous")
    monkeypatch.setattr(module.scope_lib, "enforce_execution_policy", lambda *_a, **_k: {})
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_a, **_k: (0, "trusted output\n", "", False),
    )
    monkeypatch.setattr(
        module,
        "sys",
        SimpleNamespace(stdout=_BrokenStdout(), stderr=_WarningSink(), exit=sys.exit),
    )

    with pytest.raises(SystemExit) as exc_info:
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="finalize despite console closure",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
            )
        )

    assert exc_info.value.code == 1
    assert len(patches) == 1
    assert patches[0]["status"] == "completed"
    assert patches[0]["output_quiesced"] is True
    assert "console output failed" in "".join(warnings)


def test_host_exec_client_close_failure_still_closes_both_retained_spill_fds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "host_exec_command_module_close_chain",
        "agent/scripts/assess/commands/host_exec.py",
    )
    retained_descriptors: list[int] = []
    real_create_output_spills = module._create_output_spills

    def capture_output_spills(*args, **kwargs):
        descriptors = real_create_output_spills(*args, **kwargs)
        retained_descriptors.extend(descriptors)
        return descriptors

    class _Client(_HostAuditReceiptMixin):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def post(self, _endpoint: str, _payload: dict) -> dict:
            return self._pre_exec_response(_payload)

        def patch(self, _endpoint: str, payload: dict, **_kwargs: object) -> dict:
            return self._finalize_response(
                payload,
                output_cleanup_status="not_required",
                output_integrity_status="verified",
            )

        def close(self) -> None:
            raise RuntimeError("client close failed")

    monkeypatch.setattr(module, "_create_output_spills", capture_output_spills)
    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "prepare_execution_command", lambda *_a, **_k: "anonymous")
    monkeypatch.setattr(module.scope_lib, "enforce_execution_policy", lambda *_a, **_k: {})
    monkeypatch.setattr(
        module,
        "_run_host_process",
        lambda *_a, **_k: (0, "", "", False),
    )

    with pytest.raises(RuntimeError, match="client close failed"):
        module.run(
            SimpleNamespace(
                engagement_dir=str(tmp_path),
                from_json=None,
                command=["echo", "ok"],
                tool="echo",
                intent="close retained descriptors",
                technique="T0000",
                phase="investigate",
                target_host="",
                agent_name=None,
                scope_host="",
                cwd=None,
                timeout=30,
                audit_source="argv",
                allow_destructive=False,
                require_audit=True,
            )
        )

    assert len(retained_descriptors) == 2
    for descriptor in retained_descriptors:
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(descriptor)


def test_approve_proposal_rejects_non_containment_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "approve_proposal_command_module_kind",
        "agent/scripts/assess/commands/approve_proposal.py",
    )
    updates: list[tuple[int, dict]] = []

    class _Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def list_decisions(self, **_filters: object) -> list[dict]:
            return [{"id": 7, "kind": "scope_decision", "resolved": False}]

        def list_all_decisions(self, **_filters: object) -> list[dict]:
            return [{"id": 7, "kind": "scope_decision", "resolved": False}]

        def update_decision(self, decision_id: int, patch: dict) -> dict:
            updates.append((decision_id, patch))
            return {"id": decision_id, **patch}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    with pytest.raises(SystemExit):
        module.run(
            SimpleNamespace(
                engagement_dir="/tmp/eng",
                decision_id=7,
                approved_by="operator",
                note=None,
            )
        )

    assert updates == []


def test_approve_proposal_searches_all_decision_pages(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        "approve_proposal_command_module_all_pages",
        "agent/scripts/assess/commands/approve_proposal.py",
    )
    updates: list[tuple[int, dict]] = []

    class _Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def list_decisions(self, **_filters: object) -> list[dict]:
            raise AssertionError("single-page lookup must not be used for approval")

        def list_all_decisions(self, **_filters: object) -> list[dict]:
            return [{"id": 1001, "kind": "containment_proposal", "resolved": False}]

        def update_decision(self, decision_id: int, patch: dict) -> dict:
            updates.append((decision_id, patch))
            return {"id": decision_id, "kind": "containment_proposal", **patch}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    module.run(
        SimpleNamespace(
            engagement_dir="/tmp/eng",
            decision_id=1001,
            approved_by="operator",
            note="approved in chat",
        )
    )

    assert updates
    assert updates[0][0] == 1001
    assert json.loads(capsys.readouterr().out)["resolved"] is True


def test_blue_phase_gate_requires_expected_role_for_completed_tier() -> None:
    module = _load_assess_module(
        "transition_phase_command_module_blue_roles",
        "agent/scripts/assess/commands/transition_phase.py",
    )

    class _Client:
        def get(self, endpoint: str):
            if endpoint == "findings":
                return [{"slug": "FIND-001", "workflow_status": "draft"}]
            if endpoint == "dispatches?status=completed&limit=1000&offset=0":
                return [{"agent_role": "investigator", "tier": "L1", "status": "completed"}]
            return []
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    blockers = module._blue_check_triage_to_investigate(_Client())

    assert any(blocker["kind"] == "no_completed_l1_dispatch" for blocker in blockers)


def test_blue_phase_gate_pages_completed_dispatches() -> None:
    module = _load_assess_module(
        "transition_phase_command_module_blue_dispatch_paging",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    calls: list[str] = []

    class _Client:
        def get(self, endpoint: str):
            calls.append(endpoint)
            if endpoint == "dispatches?status=completed&limit=1000&offset=0":
                return [
                    {"agent_role": "investigator", "tier": "L1", "status": "completed"}
                    for _index in range(1000)
                ]
            if endpoint == "dispatches?status=completed&limit=1000&offset=1000":
                return [
                    {
                        "agent_role": "alert-triage-specialist",
                        "tier": "L1",
                        "status": "completed",
                    }
                ]
            return []
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    count = module._blue_count_completed_dispatches(_Client(), "L1", "alert-triage-specialist")

    assert count == 1
    assert calls == [
        "dispatches?status=completed&limit=1000&offset=0",
        "dispatches?status=completed&limit=1000&offset=1000",
    ]


def test_blue_investigate_gate_rejects_legacy_free_text_auto_close() -> None:
    module = _load_assess_module(
        "transition_phase_command_module_blue_autoclosed_investigate_gate",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    calls: list[str] = []

    class _Client:
        def get(self, endpoint: str):
            calls.append(endpoint)
            if endpoint == "findings":
                return [
                    {
                        "slug": "FIND-001",
                        "workflow_status": "false_positive",
                        "verification_status": "false_positive",
                        "details": {"kill_reason": "Benign admin activity"},
                    }
                ]
            return []
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    blockers = module._blue_check_investigate_to_verify(_Client())

    assert [row["kind"] for row in blockers] == ["no_completed_l2_dispatch"]
    assert calls == ["findings", "dispatches?status=completed&limit=1000&offset=0"]


def test_blue_investigate_gate_accepts_independent_structured_false_positive() -> None:
    module = _load_assess_module(
        "transition_phase_command_module_blue_structured_false_positive_gate",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    calls: list[str] = []

    class _Client:
        def get(self, endpoint: str):
            calls.append(endpoint)
            if endpoint == "findings":
                return [
                    {
                        "slug": "FIND-001",
                        "workflow_status": "false_positive",
                        "verification_status": "false_positive",
                        "counter_check": {
                            "method": "trace access path",
                            "expected_result": "unauthorized access succeeds",
                            "observed_result": "every access is denied",
                            "falsified_claim": "unauthorized access succeeds",
                            "completed": True,
                            "proof_receipt_ids": [17],
                        },
                    }
                ]
            return []

        def close(self) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()
            return False

    blockers = module._blue_check_investigate_to_verify(_Client())

    assert blockers == []
    assert calls == ["findings"]


def test_blue_respond_gate_does_not_treat_approval_as_containment() -> None:
    module = _load_assess_module(
        "transition_phase_command_module_containment_gate",
        "agent/scripts/assess/commands/transition_phase.py",
    )

    class _Client:
        def get(self, endpoint: str):
            if endpoint == "findings":
                return [
                    {
                        "slug": "FIND-001",
                        "workflow_status": "active",
                        "verification_status": "confirmed",
                        "severity": "high",
                    }
                ]
            if endpoint == "dispatch-decisions?kind=containment_proposal&resolved=true&limit=1000":
                return [
                    {
                        "id": 7,
                        "kind": "containment_proposal",
                        "resolved": True,
                        "payload": {"finding_slug": "FIND-001"},
                    }
                ]
            if endpoint == "artifacts/search?finding=FIND-001&limit=1000&offset=0":
                return []
            return []

        def get_engagement(self, endpoint: str, query: str = ""):
            assert endpoint == "activity-entries"
            return {"items": []}
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    blockers = module._blue_check_respond_to_report(_Client())

    assert any(blocker["kind"] == "missing_containment_closure" for blocker in blockers)


def test_blue_intake_gate_missing_tenant_file_is_advisory_not_block(
    tmp_path: Path,
) -> None:
    module = _load_assess_module(
        "transition_phase_command_module_intake_missing_file",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    eng_dir = tmp_path / "engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(
        json.dumps(
            {
                "engagement_type": "blue",
                "tenant_reference_paths": ["references/tenants/does-not-exist.md"],
            }
        ),
        encoding="utf-8",
    )

    class _Client:
        def get(self, endpoint: str):
            assert endpoint == "artifacts/search?kind=alert_intake&limit=1&offset=0"
            return [{"id": 9, "kind": "alert_intake"}]

        def get_engagement(self, endpoint: str, query: str = ""):
            assert endpoint == "activity-entries"
            return {"items": [{"action": "alert_intake"}]}
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    blockers = module._blue_check_intake_to_triage(_Client(), str(eng_dir))

    missing = [b for b in blockers if b["kind"] == "missing_tenant_reference_file"]
    assert len(missing) == 1
    assert missing[0]["severity"] == "advisory"
    hard = [b for b in blockers if b.get("severity", "block") != "advisory"]
    assert hard == []


def test_blue_intake_gate_recorded_alert_passes_without_redundant_metadata(
    tmp_path: Path,
) -> None:
    module = _load_assess_module(
        "transition_phase_command_module_intake_recorded_alert",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    eng_dir = tmp_path / "engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    ref_rel = "references/tenants/acme.md"
    ref_path = eng_dir / ref_rel
    ref_path.parent.mkdir(parents=True, exist_ok=True)
    ref_path.write_text("# tenant\n", encoding="utf-8")
    (eng_dir / "scope.json").write_text(
        json.dumps(
            {
                "engagement_type": "blue",
                "tenant_reference_paths": [ref_rel],
                "alert_metadata": {"raw_body": None, "parsed": None},
            }
        ),
        encoding="utf-8",
    )

    class _Client:
        def get(self, endpoint: str):
            assert endpoint == "artifacts/search?kind=alert_intake&limit=1&offset=0"
            return [{"id": 9, "kind": "alert_intake", "relative_path": "ir/alerts/AL-1.txt"}]

        def get_engagement(self, endpoint: str, query: str = ""):
            assert endpoint == "activity-entries"
            return {"items": [{"action": "alert_intake"}]}
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    blockers = module._blue_check_intake_to_triage(_Client(), str(eng_dir))

    assert blockers == []
    assert not any(b["kind"] == "no_alert_intake" for b in blockers)


def test_blue_intake_gate_blocks_when_alert_artifact_registration_failed(
    tmp_path: Path,
) -> None:
    module = _load_assess_module(
        "transition_phase_command_module_intake_missing_artifact",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    eng_dir = tmp_path / "engagement"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text(
        json.dumps({"engagement_type": "blue", "tenant_reference_paths": []}),
        encoding="utf-8",
    )

    class _Client:
        def get(self, endpoint: str):
            assert endpoint == "artifacts/search?kind=alert_intake&limit=1&offset=0"
            return []

        def get_engagement(self, endpoint: str, query: str = ""):
            assert endpoint == "activity-entries"
            return {"items": [{"action": "alert_intake"}]}

    blockers = module._blue_check_intake_to_triage(_Client(), str(eng_dir))

    missing = [blocker for blocker in blockers if blocker["kind"] == "no_alert_intake_artifact"]
    assert len(missing) == 1
    assert "artifact register" in missing[0]["detail"]


def test_blue_investigate_gate_missing_mitre_is_advisory_not_block() -> None:
    module = _load_assess_module(
        "transition_phase_command_module_investigate_mitre_advisory",
        "agent/scripts/assess/commands/transition_phase.py",
    )

    class _Client:
        def get(self, endpoint: str):
            if endpoint == "findings":
                return [
                    {
                        "slug": "FIND-001",
                        "workflow_status": "active",
                        "verification_status": "confirmed",
                        "details": {},
                    }
                ]
            if endpoint == "dispatches?status=completed&limit=1000&offset=0":
                return [
                    {"agent_role": "investigator", "tier": "L2", "status": "completed"}
                ]
            if endpoint == "artifacts/search?finding=FIND-001&limit=1000&offset=0":
                return [
                    {
                        "kind": "ir_evidence",
                        "relative_path": "e.json",
                        "related_finding_slug": "FIND-001",
                    }
                ]
            return []
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    blockers = module._blue_check_investigate_to_verify(_Client())

    mitre = [b for b in blockers if b["kind"] == "missing_mitre_techniques"]
    assert len(mitre) == 1
    assert mitre[0]["severity"] == "advisory"
    hard = [b for b in blockers if b.get("severity", "block") != "advisory"]
    assert hard == []


def test_blue_respond_gate_single_finding_no_containment_closes() -> None:
    module = _load_assess_module(
        "transition_phase_command_module_single_no_containment",
        "agent/scripts/assess/commands/transition_phase.py",
    )

    class _Client:
        def get(self, endpoint: str):
            if endpoint == "findings":
                return [
                    {
                        "slug": "FIND-001",
                        "workflow_status": "active",
                        "verification_status": "confirmed",
                        "severity": "critical",
                    }
                ]
            if endpoint == "artifacts/search?finding=FIND-001&limit=1000&offset=0":
                return []
            return []

        def get_engagement(self, endpoint: str, query: str = ""):
            assert endpoint == "activity-entries"
            return {
                "items": [
                    {
                        "action": "no_containment_required",
                        "title": "mitigated by existing EDR policy",
                    }
                ]
            }
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    blockers = module._blue_check_respond_to_report(_Client())

    assert blockers == []


def test_blue_phase_gate_pages_activity_entries() -> None:
    module = _load_assess_module(
        "transition_phase_command_module_blue_activity_paging",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    calls: list[str] = []

    class _Client:
        def get_engagement(self, endpoint: str, query: str = ""):
            assert endpoint == "activity-entries"
            calls.append(query)
            if query == "limit=1000&offset=0":
                return {"items": [{"action": "old"} for _index in range(1000)]}
            if query == "limit=1000&offset=1000":
                return {"items": [{"action": "alert_intake"}]}
            return {"items": []}
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    rows = module._blue_list_activity_entries(_Client())

    assert rows[-1]["action"] == "alert_intake"
    assert calls == ["limit=1000&offset=0", "limit=1000&offset=1000"]


def test_blue_complete_gate_accepts_closeout_artifact() -> None:
    module = _load_assess_module(
        "transition_phase_command_module_closeout_gate",
        "agent/scripts/assess/commands/transition_phase.py",
    )

    class _Client:
        def get(self, endpoint: str):
            if endpoint == "artifacts/search?limit=1000&offset=0":
                return [{"kind": "ir_closeout", "relative_path": "closeout.md"}]
            if endpoint == "findings":
                return [{"slug": "FIND-001", "workflow_status": "false_positive"}]
            return []
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    blockers = module._blue_check_report_to_complete(_Client())

    assert blockers == []


def test_blue_complete_gate_pages_until_closeout_artifact() -> None:
    module = _load_assess_module(
        "transition_phase_command_module_closeout_artifact_paging",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    calls: list[str] = []

    class _Client:
        def get(self, endpoint: str):
            calls.append(endpoint)
            if endpoint == "artifacts/search?limit=1000&offset=0":
                return [
                    {"kind": "ir_evidence", "relative_path": f"evidence-{index}.json"}
                    for index in range(1000)
                ]
            if endpoint == "artifacts/search?limit=1000&offset=1000":
                return [{"kind": "ir_closeout", "relative_path": "closeout.md"}]
            if endpoint == "findings":
                return [{"slug": "FIND-001", "workflow_status": "false_positive"}]
            return []
        def close(self) -> None:
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    blockers = module._blue_check_report_to_complete(_Client())

    assert blockers == []
    assert calls[:2] == [
        "artifacts/search?limit=1000&offset=0",
        "artifacts/search?limit=1000&offset=1000",
    ]


def test_blue_direct_phase_jump_runs_intermediate_gates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "transition_phase_command_module_blue_intermediate_gates",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    scope_path = eng_dir / "scope.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    scope["current_phase"] = "intake"
    scope["alert_metadata"] = {"raw_body": None, "parsed": None}
    scope_path.write_text(json.dumps(scope), encoding="utf-8")

    class _Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get(self, _endpoint: str):
            return []

        def get_engagement(self, endpoint: str, query: str = ""):
            assert endpoint == "activity-entries"
            return {"items": []}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(eng_dir),
        ),
    )

    with pytest.raises(SystemExit):
        module.run(SimpleNamespace(engagement_dir=str(eng_dir), target_phase="report", force=False, track="auto"))

    assert json.loads(scope_path.read_text(encoding="utf-8"))["current_phase"] == "intake"


def test_transition_phase_complete_marks_blue_scope_completed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_assess_module(
        "transition_phase_command_module_blue_complete_status",
        "agent/scripts/assess/commands/transition_phase.py",
    )
    eng_dir = tmp_path / "engagement"
    _write_blue_scope(eng_dir)
    scope_path = eng_dir / "scope.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    scope["current_phase"] = "report"
    scope["status"] = "in_progress"
    scope_path.write_text(json.dumps(scope), encoding="utf-8")

    class _Client:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get(self, endpoint: str):
            if endpoint == "artifacts/search?limit=1000&offset=0":
                return [{"kind": "ir_closeout", "relative_path": "closeout.md"}]
            if endpoint == "findings":
                return [{"slug": "FIND-001", "workflow_status": "false_positive"}]
            return []

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(eng_dir),
        ),
    )

    module.run(SimpleNamespace(engagement_dir=str(eng_dir), target_phase="complete", force=False, track="auto"))

    updated = json.loads(scope_path.read_text(encoding="utf-8"))
    assert updated["current_phase"] == "complete"
    assert updated["status"] == "completed"


def _run_dispatch_action(
    monkeypatch,
    rows: list[dict] | None,
    action: str,
    extra: list[str] | None = None,
    reason: str = "",
    *,
    fetch_response: dict | None = None,
    dry_run: bool = False,
    rationale: str = "",
    status: str = "pending",
) -> "_FakeWorkBufferClient":
    """Drive ``dispatch.run`` (work-buffer verbs) against the backend fake."""
    module = _load_assess_module(
        "work_buffer_dispatch_module",
        "agent/scripts/assess/commands/dispatch/__init__.py",
    )
    fake = _FakeWorkBufferClient(rows, fetch_response=fetch_response)
    monkeypatch.setattr(module, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir="/tmp/eng",
        ),
    )
    module.run(
        SimpleNamespace(
            action=action,
            extra=list(extra or []),
            reason=reason,
            reason_tag="",
            by="status",
            dry_run=dry_run,
            triage_rationale=rationale,
            cluster_status=status,
            engagement_dir=None,
        )
    )
    return fake


def _run_list_clusters_action(
    monkeypatch,
    rows: list[dict] | None,
    status: str = "pending",
    limit: int = 100,
    host: str = "",
) -> "_FakeWorkBufferClient":
    module = _load_assess_module(
        "work_buffer_list_clusters_module",
        "agent/scripts/assess/commands/list_clusters.py",
    )
    fake = _FakeWorkBufferClient(rows)
    monkeypatch.setattr(module, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir="/tmp/eng",
        ),
    )
    module.run(
        SimpleNamespace(
            engagement_dir=None,
            status=status,
            limit=limit,
            host=host,
        )
    )
    return fake


def test_dispatch_defer_items_accepts_multiple_positional_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P1 #10: defer-items must send every id to the backend, not just extra[0].

    The row-state mutation (pending -> skipped with terminal_reason) is now
    backend-owned; see tests/test_work_buffer_backend.py. Here we protect the
    CLI wiring: the exact ids + reason POSTed to work-items/defer.
    """
    rows = [
        {"queue_key": "q:1", "url": "https://target.example/a", "id": 1},
        {"queue_key": "q:2", "url": "https://target.example/b", "id": 2},
        {"queue_key": "q:3", "url": "https://target.example/c", "id": 3},
    ]

    fake = _run_dispatch_action(monkeypatch, rows, "defer-items", ["1", "2", "3"], reason="low signal")

    assert fake.posts == [("work-items/defer", {"ids": [1, 2, 3], "reason": "low signal"})]


def test_dispatch_defer_items_accepts_comma_separated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P1 #10: comma form still works alongside the multi-positional form."""
    rows = [
        {"queue_key": "q:1", "url": "https://target.example/a", "id": 10},
        {"queue_key": "q:2", "url": "https://target.example/b", "id": 11},
    ]

    fake = _run_dispatch_action(monkeypatch, rows, "defer-items", ["10,11"], reason="noise")

    assert fake.posts == [("work-items/defer", {"ids": [10, 11], "reason": "noise"})]


def test_dispatch_defer_items_dry_run_reaches_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _run_dispatch_action(
        monkeypatch,
        [{"id": 10}, {"id": 11}],
        "defer-items",
        ["10", "11"],
        reason="reviewed",
        dry_run=True,
    )
    assert fake.posts == [
        (
            "work-items/defer",
            {"ids": [10, 11], "reason": "reviewed", "dry_run": True},
        )
    ]


def test_dispatch_set_rationale_posts_work_item_updates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _run_dispatch_action(
        monkeypatch,
        [{"id": 3}, {"id": 4}],
        "set-rationale",
        ["3", "4"],
        rationale="same-org path already covered by stronger cross-org probe",
    )
    assert fake.posts == [
        (
            "work-items/update",
            {
                "updates": [
                    {
                        "id": 3,
                        "triage_rationale": "same-org path already covered by stronger cross-org probe",
                    },
                    {
                        "id": 4,
                        "triage_rationale": "same-org path already covered by stronger cross-org probe",
                    },
                ]
            },
        )
    ]


def test_dispatch_defer_items_with_no_ids_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """P1 #10: empty / pure-comma id input must abort instead of silently no-op."""
    with pytest.raises(SystemExit):
        _run_dispatch_action(monkeypatch, [], "defer-items", [], reason="x")
    err = capsys.readouterr().err
    assert "Usage" in err or "id" in err.lower()


def test_dispatch_defer_items_pure_comma_string_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """P3 #15: a pure-comma id_list (e.g. ',') must abort instead of silently no-op."""
    with pytest.raises(SystemExit):
        _run_dispatch_action(monkeypatch, [], "defer-items", [","], reason="x")
    err = capsys.readouterr().err
    assert "at least one numeric ID" in err


def test_dispatch_defer_items_zero_rows_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """P2 #11: zero matched rows must surface an error so a typo isn't a silent success.

    The backend returns affected=0 when no PENDING row matches (here the only
    row is already ``done``); the CLI must exit non-zero and explain.
    """
    rows = [{"queue_key": "q:1", "url": "https://target.example/a", "id": 1, "status": "done"}]

    with pytest.raises(SystemExit):
        _run_dispatch_action(monkeypatch, rows, "defer-items", ["1"], reason="x")
    err = capsys.readouterr().err
    assert "no pending items matched" in err


def test_dispatch_done_marks_every_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """P1 #10: done must send all ids to the backend, not just the first in `extra`."""
    rows = [
        {"queue_key": "q:1", "url": "https://target.example/a", "id": 1, "status": "processing"},
        {"queue_key": "q:2", "url": "https://target.example/b", "id": 2, "status": "processing"},
    ]

    fake = _run_dispatch_action(monkeypatch, rows, "done", ["1", "2"])

    assert fake.posts == [("work-items/done", {"ids": [1, 2]})]


def test_dispatch_peek_invalid_limit_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """P3 #12: a non-integer peek limit prints a clean usage line instead of a stacktrace."""
    with pytest.raises(SystemExit):
        _run_dispatch_action(monkeypatch, [], "peek", ["api", "abc"])
    err = capsys.readouterr().err
    assert "must be an integer" in err


def test_dispatch_fetch_by_priority_warns_when_only_non_routable_pending(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """P2 #14: pending rows in non-routable types must surface a stderr WARN.

    The routing + claim run server-side; the CLI just renders the backend's
    ``non_routable`` summary. Drive the fetch-by-priority response directly.
    """
    fetch_response = {
        "claimed": [],
        "non_routable": [{"type": "image", "count": 1}],
        "allowed_types": ["api", "form", "json"],
    }

    _run_dispatch_action(
        monkeypatch, [], "fetch-by-priority", ["10", "auto"], fetch_response=fetch_response
    )

    captured = capsys.readouterr()
    assert "WARN fetch-by-priority" in captured.err
    assert "image" in captured.err


def test_list_clusters_host_filter_matches_full_population(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """P1 #25: --host considers ALL items per cluster, not just the first 5 samples."""
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

    _run_list_clusters_action(monkeypatch, rows, host="target.example")
    payload = json.loads(capsys.readouterr().out)
    cluster_keys = [c["cluster_key"] for c in payload["clusters"]]
    assert "alpha" in cluster_keys
    assert "beta" not in cluster_keys


def test_list_clusters_host_filter_supports_wildcard(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Bonus #26: '*.example.com' fnmatches subdomains, exact 'example.com' does not."""
    rows = [
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
    ]

    _run_list_clusters_action(monkeypatch, rows, host="*.example.com")
    payload = json.loads(capsys.readouterr().out)
    cluster_keys = [c["cluster_key"] for c in payload["clusters"]]
    assert "alpha" in cluster_keys
    assert "beta" not in cluster_keys

    # Exact apex match excludes subdomain-only clusters.
    _run_list_clusters_action(monkeypatch, rows, host="example.com")
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
        "supersede_intel_module",
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
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

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


def test_supersede_intel_to_existing_sends_fk_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """I-15: --to-existing skips payload validation and POSTs a to_existing_id
    body (no payload) to the existing supersede endpoint."""
    supersede_module = _load_assess_module(
        "supersede_intel_module_to_existing",
        "agent/scripts/assess/commands/supersede_intel.py",
    )

    captured: dict[str, object] = {}

    class _StubClient:
        _engagement_prefix = "/engagements/test"

        def __init__(self, *_: object, **__: object) -> None:
            pass

        def post_engagement(self, endpoint: str, payload: dict):
            captured["method"] = "POST"
            captured["path"] = f"{self._engagement_prefix}/{endpoint}"
            captured["body"] = json.dumps(payload).encode()
            return {
                "superseded": {"id": 5, "superseded_by_id": 7},
                "current": {"id": 7},
            }

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

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

    supersede_module.run(
        SimpleNamespace(
            intel_type="tech-component",
            intel_id=5,
            payload=None,
            inline_payload=None,
            to_existing_id=7,
            rationale="dup of canonical",
            engagement_dir=str(tmp_path),
        )
    )

    assert captured["method"] == "POST"
    assert str(captured["path"]).endswith("/intel/tech-components/5/supersede")
    sent = json.loads(captured["body"])
    assert sent == {"to_existing_id": 7, "rationale": "dup of canonical"}
    assert '"current"' in capsys.readouterr().out


def test_supersede_intel_to_existing_rejects_payload_client_side(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """--to-existing is mutually exclusive with a payload argument; the CLI
    rejects it before any network round trip."""
    supersede_module = _load_assess_module(
        "supersede_intel_module_mutex",
        "agent/scripts/assess/commands/supersede_intel.py",
    )
    sent: dict[str, object] = {}

    class _StubClient:
        _engagement_prefix = "/engagements/test"

        def __init__(self, *_: object, **__: object) -> None:
            pass

        def _request(self, *_a: object, **_k: object):
            sent["called"] = True
            return 201, "{}"

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False

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
                intel_type="tech-component",
                intel_id=5,
                payload="new.json",
                inline_payload=None,
                to_existing_id=7,
                rationale="",
                engagement_dir=str(tmp_path),
            )
        )

    assert exc.value.code == 1
    assert sent == {}
    assert "mutually exclusive" in capsys.readouterr().err


def _validate_dispatch_contract(payload: dict):
    """Call the dispatch-contract validator lib directly.

    The former `vigil assess validate-dispatch-contract` CLI verb (a thin
    wrapper over this lib) was retired in the 2026-07 CLI consolidation — its
    validator still runs inside `agent start`. These tests exercise the lib
    that both paths share.
    """
    _load_assess_main()  # ensures agent/scripts is on sys.path
    from assess.lib.contracts import validate_specialist_dispatch_contract

    return validate_specialist_dispatch_contract(payload)


def test_validate_dispatch_contract_accepts_minimal_payload() -> None:
    """P3 #31: the validator returns no errors for a contract with every required field set."""
    errors, _warnings = _validate_dispatch_contract(
        {
            "role": "vulnerability-analyst",
            "dispatch_mode": "item-iterating",
            "skills": "auth-bypass",
        }
    )
    assert errors == []


def test_validate_dispatch_contract_accepts_dispatch_register_payload() -> None:
    """The contract preflight accepts the same role field used by agent start."""
    errors, _warnings = _validate_dispatch_contract(
        {
            "agent_id": "VA-1",
            "agent_role": "vulnerability-analyst",
            "dispatch_mode": "item-iterating",
            "skills": "auth-bypass",
        }
    )
    assert errors == []


def test_validate_dispatch_contract_rejects_role_mismatch() -> None:
    errors, _warnings = _validate_dispatch_contract(
        {
            "role": "recon-specialist",
            "agent_role": "vulnerability-analyst",
            "dispatch_mode": "item-iterating",
            "skills": "auth-bypass",
        }
    )
    assert any("role and agent_role must match" in e for e in errors)


def test_list_skills_uses_directory_names_for_dispatch_audit(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assess_main = _load_assess_main()

    assess_main(["list-skills", "--json"])

    rows = json.loads(capsys.readouterr().out)
    google = next(row for row in rows if row["path"] == "agent/skills/google-workspaces/SKILL.md")
    assert google["name"] == "google-workspaces"


def test_list_references_uses_path_slugs_and_repo_paths(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assess_main = _load_assess_main()

    assess_main(["list-references", "--json"])

    rows = json.loads(capsys.readouterr().out)
    sqli = next(
        row for row in rows if row["path"] == "agent/references/payloads/sqli-payloads.md"
    )
    # `name` is the path relative to references/ minus .md — the references analogue
    # of list-skills using the directory name.
    assert sqli["name"] == "payloads/sqli-payloads"
    assert sqli["description"]
    assert sqli["skill"] == "sqli-testing"


def test_list_references_skill_filter_returns_paired_refs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assess_main = _load_assess_main()

    assess_main(["list-references", "--skill", "idor-testing", "--json"])

    rows = json.loads(capsys.readouterr().out)
    names = {row["name"] for row in rows}
    assert "access-control/idor-modern-architectures" in names
    # Every returned row must actually be paired to the requested skill.
    for row in rows:
        pairs = {s.strip() for s in row["skill"].split(",")}
        assert "idor-testing" in pairs


def test_list_references_every_file_has_a_description(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Completeness guard: a reference added without frontmatter (or with an empty
    description) must fail CI rather than silently render '(no description)'."""
    assess_main = _load_assess_main()

    assess_main(["list-references", "--json"])

    rows = json.loads(capsys.readouterr().out)
    missing = [
        row["name"]
        for row in rows
        if not row["description"] or row["description"] == "(no description)"
    ]
    assert not missing, f"references missing a frontmatter description: {missing}"


def test_list_references_skill_pairings_name_real_skills(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Every `skill:` pairing must resolve to a real agent/skills/<name>/ directory,
    so a typo can never silently break `--skill` filtering or a dispatch audit."""
    assess_main = _load_assess_main()

    assess_main(["list-references", "--json"])

    rows = json.loads(capsys.readouterr().out)
    valid_skills = {
        path.name for path in (repo_root / "agent" / "skills").iterdir() if path.is_dir()
    }
    bad = [
        (row["name"], name)
        for row in rows
        for name in (s.strip() for s in row["skill"].split(",") if s.strip())
        if name not in valid_skills
    ]
    assert not bad, f"references paired to non-existent skills: {bad}"


def test_list_references_cited_skills_have_paired_references(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Forward direction of the skill<->reference pairing audit.

    `test_list_references_skill_pairings_name_real_skills` covers the inverse
    (every `skill: X` in a reference resolves to `agent/skills/X/`). This guards
    the forward gap: when operator docs dispatch a skill with `--skills` and that
    skill's SKILL.md cites `agent/references/`, at least one reference file must
    carry `skill: <name>` in frontmatter — otherwise
    `vigil assess list-references --skill <name>` silently returns []."""
    import re

    assess_main = _load_assess_main()

    assess_main(["list-references", "--json"])
    rows = json.loads(capsys.readouterr().out)

    # 1. Skills that have at least one reference paired to them.
    paired_skill_names = {
        name
        for row in rows
        for name in (s.strip().lower() for s in row["skill"].split(",") if s.strip())
    }

    # 2. Skills cited via `--skills` in operator docs and dispatch invocations.
    agent_dir = repo_root / "agent"
    doc_files: list[Path] = []
    doc_files.extend(sorted(agent_dir.glob("operator-core*.md")))
    doc_files.append(agent_dir / "AGENTS.md")
    doc_files.extend(sorted(agent_dir.glob("shared-constraints*.md")))
    doc_files.extend(sorted(agent_dir.glob("skills/*/SKILL.md")))

    skills_pattern = re.compile(r"--skills\s+[\"']?([a-z0-9,\- ]+)")
    cited: set[str] = set()
    for path in doc_files:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for match in skills_pattern.finditer(text):
            for token in match.group(1).split(","):
                name = token.strip().lower()
                if not name:
                    continue
                # Drop doc placeholders like <name>, $VAR, *.
                if any(ch in name for ch in "<>$*"):
                    continue
                cited.add(name)

    # 3. Only flag skills whose SKILL.md actually promises reference pairings.
    #    A skill "promises" a `--skill`-discoverable pairing only if it cites a
    #    references path other than `agent/references/tenants/`: the tenants files
    #    are per-tenant IR context injected by the operator from scope.json, not
    #    discovered via `list-references --skill`, so they legitimately carry no
    #    `skill:` frontmatter. This is the "skills that legitimately have no
    #    reference pairings" carve-out — without it, every tenant-aware blue skill
    #    would be a false positive.
    skills_dir = agent_dir / "skills"
    refs_cite = re.compile(r"agent/references/(?!tenants/)")
    cited_promising: set[str] = set()
    for name in cited:
        skill_md = skills_dir / name / "SKILL.md"
        if not skill_md.exists():
            # Inverse/validation covers non-existent skill names elsewhere.
            continue
        if refs_cite.search(skill_md.read_text(encoding="utf-8")):
            cited_promising.add(name)

    # 4. Any cited, reference-promising skill with no paired reference is a gap.
    gaps = sorted(cited_promising - paired_skill_names)
    assert not gaps, (
        "These skills are cited in operator docs with --skills and their SKILL.md "
        "references agent/references/, but no reference file carries "
        "`skill: <name>` in its frontmatter — `vigil assess list-references "
        "--skill <name>` would return []. Add the skill: pairing to the "
        "relevant reference files:\n  " + "\n  ".join(gaps)
    )


def test_validate_dispatch_contract_accepts_list_skills_canonical_name() -> None:
    errors, warnings = _validate_dispatch_contract(
        {
            "agent_role": "vulnerability-analyst",
            "dispatch_mode": "item-iterating",
            "skills": "google-workspaces",
        }
    )
    assert errors == []
    assert not any("skill" in w for w in warnings)


def test_validate_dispatch_contract_warns_on_unknown_dispatch_mode() -> None:
    """L2-4: an unknown dispatch_mode is ADVISORY (warn + proceed), not a hard
    error, so a newly-coined mode is not blocked."""
    errors, warnings = _validate_dispatch_contract(
        {
            "role": "vulnerability-analyst",
            "dispatch_mode": "turbo-mode",
            "skills": "auth-bypass",
        }
    )
    assert errors == []
    blob = " ".join(warnings)
    assert "turbo-mode" in blob
    assert "newly-coined mode" in blob


def test_validate_dispatch_contract_operator_skills_optional() -> None:
    """Operator role coordinates phases; skills are not required on operator dispatches."""
    errors, _warnings = _validate_dispatch_contract(
        {
            "role": "operator",
            "dispatch_mode": "deep-manual",
        }
    )
    assert errors == []


def test_validate_dispatch_contract_operator_skills_optional_case_insensitive() -> None:
    """Operator casing variants are exempt from specialist skill requirements."""
    errors, _warnings = _validate_dispatch_contract(
        {
            "role": "Operator",
            "agent_role": "operator",
            "dispatch_mode": "deep-manual",
        }
    )
    assert errors == []


def test_actor_kind_warn_on_non_log_subcommand(
    capsys: pytest.CaptureFixture[str]
) -> None:
    """P3 #33: passing --actor-kind to a subcommand that doesn't consume it warns on stderr."""
    assess_main = _load_assess_main()

    # `contract` is a non-log, no-network subcommand that ignores --actor-kind.
    assess_main(
        [
            "--actor-kind",
            "operator",
            "contract",
            "finding",
            "record",
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
            raise module.AssessError(f"unexpected endpoint {endpoint}")

        def get_engagement(self, endpoint: str):
            if endpoint == "credentials":
                return list(credentials or [])
            raise module.AssessError(f"unexpected engagement endpoint {endpoint}")

        def get_handoff(self, agent_id: str):
            if handoff is None:
                return None
            return handoff

        def get_dispatch(self, agent_id: str):
            return dispatch_row

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module.handoff_renderer, "AssessmentClient", _StubClient)
    monkeypatch.setattr(
        module.handoff_renderer,
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

    The operator CLI routes to ``vigil assess agent`` / ``vigil assess work-buffer``;
    this module remains shared implementations and legacy argparse for tests.
    """
    return _load_assess_module(
        "round9_dispatch_module",
        "agent/scripts/assess/commands/dispatch/__init__.py",
    )


def _run_render_handoff(
    module,
    engagement_dir: Path,
    agent_id: str,
    *,
    max_lines: int = 40,
    include_evidence: bool = False,
) -> None:
    """Run render-handoff through the operator surface.

    ``dispatch.run`` no longer routes render-handoff; it is now
    ``vigil assess agent render-handoff <agent-id>``, which delegates to
    ``dispatch._render_handoff`` (the shared ``handoff_renderer`` blob emitter).
    The ``module`` arg (the dispatch package) is only used by the stub, which
    patches the shared ``handoff_renderer`` — the same module object this run
    reaches via ``assess.commands.agent`` -> ``dispatch._render_handoff``.
    """
    agent_module = _load_assess_module(
        "round9_agent_render_handoff_module",
        "agent/scripts/assess/commands/agent.py",
    )
    agent_module.run(
        SimpleNamespace(
            action="render-handoff",
            extra=[agent_id],
            agent_id=None,
            reason="",
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
        "application_unit_id": 41,
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
    assert "**Application unit:** 41" in out
    assert "Validated IDOR on /api/users/{id}" in out  # summary
    assert "Confidence:** high" in out
    assert "`VA-001` — IDOR write on user profile [severity=high]" in out
    assert "`VA-002` — IDOR read on user email [severity=medium]" in out
    assert "tools/exploit-state/EX-001-payload.sql` (state: present)" in out
    assert "tools/exploit-state/EX-002-poc.py` (state: missing)" in out
    assert "replay captured cookie at /api/users/2" in out
    assert "Recommended next agent:** exploit-developer" in out
    assert "Credentials captured:** 2 rows (ids: 17, 18)" in out


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
        "application_unit_id": 51,
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
        "application_unit_id": 52,
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
        self.decisions: list[dict] = []
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

    def get_handoff(self, agent_id: str):
        return self.handoffs_by_id.get(agent_id)

    def list_handoffs(self, **filters):
        return list(self.handoffs_by_id.values())

    def record_decision(self, payload: dict) -> dict:
        self.decisions_recorded.append(payload)
        return {"id": 99, **payload}

    def list_decisions(self, **filters):
        return [
            row for row in self.decisions
            if not filters.get("kind") or row.get("kind") == filters["kind"]
        ]

    def record_handoff(self, payload: dict, *, upsert: bool = False) -> dict:
        # Track every call for idempotency tests; the dispatch CLI should
        # always pass upsert=True so checkpointing the same agent_id is safe.
        self.handoff_response = payload
        self.handoff_calls.append({"payload": payload, "upsert": upsert})
        prior = self.handoffs_by_id.get(payload.get("agent_id"))
        if prior is not None and not upsert:
            from assess.lib.client import AssessError  # type: ignore[import-not-found]
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
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        self.close()
        return False


def test_resume_brief_cli_requests_targeted_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        "resume_brief_command_module",
        "agent/scripts/assess/commands/resume_brief.py",
    )
    calls: list[str] = []

    class _Client:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def get(self, endpoint: str):
            calls.append(endpoint)
            return {"engagement": {"key": "eng"}, "recommended_next_actions": []}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    module.run(SimpleNamespace(engagement_dir="/tmp/eng", q="OIDC state", finding="VA047", agent_id="AG-1", as_json=True))

    assert calls == ["resume-brief?q=OIDC%20state&finding=VA047&agent_id=AG-1"]
    assert json.loads(capsys.readouterr().out)["engagement"]["key"] == "eng"


def test_resume_brief_orphan_attention_surfaces_degraded_recovery() -> None:
    module = _load_assess_module(
        "resume_brief_command_module_degraded_attention",
        "agent/scripts/assess/commands/resume_brief.py",
    )

    attention = module._orphan_attention(
        json.dumps(
            {
                "summary": {
                    "recovered_degraded": 2,
                    "recovered_degraded_ids": [95, 96],
                    "recovered_degraded_ids_omitted": 0,
                    "output_attention_action": (
                        "vigil assess command-run list --output-attention "
                        "--json --limit 1000"
                    ),
                }
            }
        )
    )

    assert attention == (
        "command_runs:recovered_degraded=2 ids=95,96 "
        "action=`vigil assess command-run list --output-attention --json --limit 1000`"
    )


def test_resume_brief_orphan_attention_locates_failed_recovery_rows() -> None:
    module = _load_assess_module(
        "resume_brief_command_module_failed_recovery_attention",
        "agent/scripts/assess/commands/resume_brief.py",
    )

    attention = module._orphan_attention(
        json.dumps(
            {
                "summary": {
                    "skipped_unverifiable": 3,
                    "pending_recovery_failed": 3,
                    "pending_recovery_failed_ids": [93, 96],
                    "pending_recovery_failed_ids_omitted": 1,
                    "output_attention_action": (
                        "vigil assess command-run list --output-attention "
                        "--json --limit 1000"
                    ),
                }
            }
        )
    )

    assert attention == (
        "command_runs:skipped_unverifiable=3,pending_recovery_failed=3 "
        "failed_ids=93,96 failed_ids_omitted=1 "
        "action=`vigil assess command-run list --output-attention --json --limit 1000`"
    )


def test_resume_brief_command_rows_render_degraded_output_truth() -> None:
    module = _load_assess_module(
        "resume_brief_command_module_output_truth",
        "agent/scripts/assess/commands/resume_brief.py",
    )
    brief = {
        "engagement": {"key": "eng"},
        "command_runs": [
            {
                "id": 7,
                "created_at": "2026-08-06T12:00:00Z",
                "tool_bin": "curl",
                "agent_name": "operator",
                "intent": "suppressed output recovery",
                "output_retention_status": "suppression_deferred",
                "output_cleanup_status": "deferred",
                "output_integrity_status": "not_applicable",
            },
            {
                "id": 8,
                "created_at": "2026-08-06T12:01:00Z",
                "tool_bin": "clang",
                "agent_name": "operator",
                "intent": "snapshot verification",
                "output_retention_status": "integrity_failure",
                "output_cleanup_status": "warning",
                "output_integrity_status": "warning",
            },
        ],
    }

    rendered = module._render_markdown(brief)

    assert "output=suppression_deferred cleanup=deferred integrity=not_applicable" in rendered
    assert "output=integrity_failure cleanup=warning integrity=warning" in rendered


def test_artifact_cli_registers_payload(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        "artifact_command_module",
        "agent/scripts/assess/commands/artifact.py",
    )
    posts: list[tuple[str, dict]] = []

    class _Client:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def post(self, endpoint: str, payload: dict):
            posts.append((endpoint, payload))
            return {"id": 7, "present": True, "relative_path": payload["path"], "kind": payload["kind"]}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        # `engagement_dir` is part of the real `Config`; register canonicalizes the
        # submitted path against it before POSTing so the response comparison is
        # canonical-vs-canonical.
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test", engagement_key="eng", engagement_dir="/tmp/eng"
        ),
    )

    module._run_register(
        SimpleNamespace(
            engagement_dir="/tmp/eng",
            paths=["notes/VA-047.md"],
            paths_file="",
            kind="note",
            media_type="text/markdown",
            finding="VA-047",
            agent_id="AG-1",
            agent_role="vulnerability-analyst",
            command_run_id=12,
            as_json=True,
        )
    )

    assert posts == [
        (
            "artifacts",
            {
                "path": "notes/VA-047.md",
                "kind": "note",
                "media_type": "text/markdown",
                "producer_agent_id": "AG-1",
                "producer_agent_role": "vulnerability-analyst",
                "producer_command_run_id": 12,
                "related_finding_slug": "VA-047",
            },
        )
    ]
    assert json.loads(capsys.readouterr().out)["id"] == 7


def test_artifact_cli_refresh_posts_endpoint(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        "artifact_command_module_refresh",
        "agent/scripts/assess/commands/artifact.py",
    )
    posts: list[tuple[str, dict]] = []

    class _Client:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def post(self, endpoint: str, payload: dict):
            posts.append((endpoint, payload))
            return {"refreshed": 3, "present": 2, "missing": 1}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    module._run_refresh(SimpleNamespace(engagement_dir="/tmp/eng", as_json=False))

    assert posts == [("artifacts/refresh", {})]
    assert capsys.readouterr().out.strip() == "refreshed=3 present=2 missing=1"


def test_artifact_cli_targeted_refresh_and_unlink_use_exact_id(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        "artifact_command_module_targeted",
        "agent/scripts/assess/commands/artifact.py",
    )
    calls: list[tuple[str, str, dict | None]] = []

    class _Client:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def post(self, endpoint: str, payload: dict):
            calls.append(("post", endpoint, payload))
            return {"refreshed": 1, "present": 1, "missing": 0}

        def delete(self, endpoint: str):
            calls.append(("delete", endpoint, None))
            return {"id": 7, "relative_path": "notes/a.md", "related_finding_slug": None}

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    module._run_refresh(SimpleNamespace(engagement_dir="/tmp/eng", artifact_id=7, as_json=False))
    module._run_unlink_finding(SimpleNamespace(engagement_dir="/tmp/eng", artifact_id=7, as_json=True))

    assert calls == [
        ("post", "artifacts/7/refresh", {}),
        ("delete", "artifacts/7/finding-link", None),
    ]
    assert '"related_finding_slug": null' in capsys.readouterr().out


def test_list_command_runs_cli_sends_fuzzy_search_flags(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        "list_command_runs_command_module",
        "agent/scripts/assess/commands/list_command_runs.py",
    )
    calls: list[str] = []

    class _Client:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def get(self, endpoint: str):
            calls.append(endpoint)
            return []

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", _Client)
    monkeypatch.setattr(
        module,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )

    module.run(
        SimpleNamespace(
            engagement_dir="/tmp/eng",
            q="VA047",
            sort="distant",
            show_matches=True,
            exact=False,
            agent_name="",
            phase="",
            tool_name="",
            tool_bin="curl",
            target_host="example.com",
            audit_source="",
            technique="",
            probe_kind="",
            intent_q="",
            success=False,
            failed=False,
            destructive=False,
            not_destructive=False,
            timed_out=False,
            output_attention=True,
            include_output=False,
            limit=10,
            offset=0,
            as_json=False,
        )
    )

    assert calls == [
        "command-runs?q=VA047&tool_bin=curl&target_host=example.com&sort=distant&show_matches=true&output_attention=true&limit=11&offset=0"
    ]
    assert "(no command runs matched)" in capsys.readouterr().out


def test_agent_close_uses_ready_handoff_to_complete_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        "agent_command_module_close",
        "agent/scripts/assess/commands/agent.py",
    )
    fake = _CapturingClient()
    fake.dispatches_by_id["AG-READY"] = {"agent_id": "AG-READY", "status": "in-progress"}
    fake.handoffs_by_id["AG-READY"] = {
        "agent_id": "AG-READY",
        "handoff_status": "ready",
        "handoff_version": 3,
        "finding_slugs": ["VA-001"],
    }
    monkeypatch.setattr(module.dispatch, "_client_for", lambda _args: (fake, SimpleNamespace()))

    module.run(
        SimpleNamespace(
            action="close",
            extra=["AG-READY"],
            agent_id=None,
            completed_at="2026-05-19T12:00:00Z",
            reason="stale closure",
        )
    )

    assert fake.patches == [
        ("AG-READY", {"status": "completed", "completed_at": "2026-05-19T12:00:00Z", "finding_slugs": ["VA-001"]})
    ]
    assert fake.decisions_recorded[0]["kind"] == "dispatch_closed_from_handoff"
    assert json.loads(capsys.readouterr().out)["dispatch"]["status"] == "completed"


def test_agent_close_preserves_variant_parent_scope_in_dispatch_row(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        "agent_command_module_close_variant_scope",
        "agent/scripts/assess/commands/agent.py",
    )
    fake = _CapturingClient()
    fake.dispatches_by_id["VARIANT-READY"] = {
        "agent_id": "VARIANT-READY",
        "agent_role": "code-variant-hunter",
        "status": "in-progress",
        "finding_slugs": ["VF-001"],
    }
    fake.handoffs_by_id["VARIANT-READY"] = {
        "agent_id": "VARIANT-READY",
        "handoff_status": "ready",
        "handoff_version": 1,
        "finding_slugs": ["VF-004"],
    }
    monkeypatch.setattr(module.dispatch, "_client_for", lambda _args: (fake, SimpleNamespace()))

    module.run(
        SimpleNamespace(
            action="close",
            extra=["VARIANT-READY"],
            agent_id=None,
            completed_at="2026-08-06T12:00:00Z",
            reason="variant closure",
        )
    )

    assert fake.patches == [
        (
            "VARIANT-READY",
            {"status": "completed", "completed_at": "2026-08-06T12:00:00Z"},
        )
    ]
    assert json.loads(capsys.readouterr().out)["dispatch"]["status"] == "completed"


def test_agent_reconcile_stale_dry_run_groups_handoffs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        "agent_command_module_reconcile",
        "agent/scripts/assess/commands/agent.py",
    )
    fake = _CapturingClient()
    fake.dispatches_by_id["AG-READY"] = {
        "agent_id": "AG-READY",
        "agent_role": "vulnerability-analyst",
        "status": "in-progress",
        "dispatched_at": "2026-05-17T12:00:00Z",
    }
    fake.dispatches_by_id["AG-GAP"] = {
        "agent_id": "AG-GAP",
        "agent_role": "recon-specialist",
        "status": "in-progress",
        "dispatched_at": "2026-05-17T12:00:00Z",
    }
    fake.handoffs_by_id["AG-READY"] = {"agent_id": "AG-READY", "handoff_status": "ready"}
    monkeypatch.setattr(module.dispatch, "_client_for", lambda _args: (fake, SimpleNamespace()))

    module.run(
        SimpleNamespace(
            action="reconcile-stale",
            extra=[],
            agent_id=None,
            dry_run=True,
            max_age_hours=1,
        )
    )

    rows = {row["agent_id"]: row for row in json.loads(capsys.readouterr().out)}
    assert rows["AG-READY"]["category"] == "ready_handoff"
    assert rows["AG-GAP"]["category"] == "no_handoff"


def test_agent_reconcile_stale_includes_completed_and_honors_reconciliation_decision(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        "agent_command_module_reconcile_terminal",
        "agent/scripts/assess/commands/agent.py",
    )
    fake = _CapturingClient()
    fake.dispatches_by_id["AG-COMPLETE"] = {
        "agent_id": "AG-COMPLETE",
        "agent_role": "recon-specialist",
        "status": "completed",
    }
    fake.dispatches_by_id["AG-FAILED-ADJUDICATED"] = {
        "agent_id": "AG-FAILED-ADJUDICATED",
        "agent_role": "recon-specialist",
        "status": "failed",
    }
    fake.decisions.append(
        {
            "kind": "dispatch_reconciliation",
            "payload": {"agent_id": "AG-FAILED-ADJUDICATED", "reason": "worker died before output"},
        }
    )
    monkeypatch.setattr(module.dispatch, "_client_for", lambda _args: (fake, SimpleNamespace()))

    module.run(
        SimpleNamespace(
            action="reconcile-stale",
            extra=[],
            agent_id=None,
            dry_run=True,
            max_age_hours=1,
        )
    )

    rows = {row["agent_id"]: row for row in json.loads(capsys.readouterr().out)}
    assert rows["AG-COMPLETE"]["category"] == "terminal_no_handoff"
    assert rows["AG-COMPLETE"]["dispatch_status"] == "completed"
    assert "AG-FAILED-ADJUDICATED" not in rows


def test_agent_reconcile_stale_pages_handoffs_before_classifying_candidates(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_assess_module(
        "agent_command_module_reconcile_paged_handoffs",
        "agent/scripts/assess/commands/agent.py",
    )

    class _PagedClient(_CapturingClient):
        def __init__(self) -> None:
            super().__init__()
            self.handoff_page_offsets: list[int] = []

        def list_dispatches(self, **filters):
            status = filters.get("status")
            offset = int(filters.get("offset", 0))
            if status == "in-progress" and offset == 0:
                return [
                    {
                        "agent_id": "AG-PAGED",
                        "agent_role": "recon-specialist",
                        "status": "in-progress",
                        "dispatched_at": "2026-05-17T12:00:00Z",
                    },
                    *[
                        {
                            "agent_id": f"RECENT-{index}",
                            "agent_role": "recon-specialist",
                            "status": "in-progress",
                            "dispatched_at": "2999-01-01T00:00:00Z",
                        }
                        for index in range(999)
                    ],
                ]
            return []

        def list_handoffs(self, **filters):
            offset = int(filters.get("offset", 0))
            self.handoff_page_offsets.append(offset)
            if offset == 0:
                return [
                    {"agent_id": f"OTHER-{index}", "handoff_status": "ready"}
                    for index in range(1000)
                ]
            if offset == 1000:
                return [{"agent_id": "AG-PAGED", "handoff_status": "ready"}]
            return []

        def list_decisions(self, **filters):
            return []

    fake = _PagedClient()
    monkeypatch.setattr(module.dispatch, "_client_for", lambda _args: (fake, SimpleNamespace()))

    module.run(
        SimpleNamespace(
            action="reconcile-stale",
            extra=[],
            agent_id=None,
            dry_run=True,
            max_age_hours=1,
        )
    )

    rows = {row["agent_id"]: row for row in json.loads(capsys.readouterr().out)}
    assert rows["AG-PAGED"]["category"] == "ready_handoff"
    assert fake.handoff_page_offsets == [0, 1000]


def _invoke_backend_lifecycle(module, action: str, args) -> None:
    """Route an OLD dispatch backend-action name to the internal
    ``assess.commands.dispatch.agent`` helper it now lives in.

    Pre-refactor these verbs were routed by a ``db_path`` positional through
    ``dispatch.run``. Routing now lives in ``assess.commands.agent.run`` (the
    ``vigil assess agent <verb>`` operator surface), which delegates to exactly
    these helpers. We call the helpers directly (rather than ``agent.run``) so
    the CLI-wiring assertions here stay exact: ``agent start`` adds a Runtime
    Identity banner + a native-wrapper WARN to the register path, and ``agent
    done`` adds a handoff-closable precheck — operator affordances that would
    perturb these stdout/stderr assertions without exercising anything new.
    The internal helper names are unchanged (dispatch/agent.py ``_DBLESS_ACTIONS``).
    """
    agentmod = module.agent
    extra = list(getattr(args, "extra", None) or [])
    if action == "register":
        agentmod._register_dispatch(args)
    elif action == "update-status":
        agentmod._update_dispatch_status(args, extra)
    elif action == "abort-duplicate":
        agentmod._abort_duplicate_dispatch(args, extra)
    elif action == "list":
        agentmod._list_dispatches(args)
    elif action == "get":
        agentmod._get_dispatch(args, extra)
    elif action == "record-decision":
        agentmod._record_decision(args)
    elif action == "record-handoff":
        agentmod._record_handoff(args)
    else:
        raise AssertionError(f"unmapped backend lifecycle action: {action!r}")


def _run_dispatch_verb(monkeypatch, action: str, *, extra=None, **flags):
    """Execute a backend agent-lifecycle verb with a fake AssessmentClient injected."""
    module = _load_dispatch_module()
    fake = _CapturingClient()
    monkeypatch.setattr(module.agent, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        module.agent,
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
        "application_unit_id": None,
        "dispatch_model": None,
        "reasoning": None,
        "dispatch_mode_arg": None,
        "from_json": None,
        "check_overlap": False,
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
    _invoke_backend_lifecycle(module, action, SimpleNamespace(**args_dict))
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
        "application_unit_id": None,
        "dispatch_model": None,
        "reasoning": None,
        "dispatch_mode_arg": None,
        "from_json": None,
        "check_overlap": False,
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


def test_dispatch_record_handoff_from_json_requires_agent_id_before_client(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_dispatch_module()
    payload_path = tmp_path / "handoff.json"
    payload_path.write_text(
        json.dumps(
                {"agent_role": "recon-specialist", "summary": "checkpoint"}
        ),
        encoding="utf-8",
    )

    # JSON is now the only handoff input surface, so its durable lookup key is
    # validated before resolving an engagement or constructing a client.
    with pytest.raises(SystemExit) as exc_info:
        module.agent._record_handoff(
                _dispatch_args(
                    "record-handoff",
                    from_json=str(payload_path),
                )
        )

    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "agent_id is required" in err


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


def test_dispatch_register_defaults_missing_dispatch_mode_from_role(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """L2-1: a dispatch missing --dispatch-mode no longer hard-errors. The mode
    is defaulted from the role table, the stored row carries it, and a WARN is
    emitted."""
    fake = _run_dispatch_verb(
        monkeypatch,
        "register",
        agent_id="AG-NO-MODE",
        agent_role="vulnerability-analyst",
        task="IDOR sweep",
        skills="idor-testing",
    )
    err = capsys.readouterr().err
    # Canonical per-role default (role file "Default when omitted" + operator-core
    # Iteration-mode Declaration): vulnerability-analyst -> item-iterating.
    assert fake.recorded[0]["dispatch_mode"] == "item-iterating"
    assert "dispatch_mode not set; defaulting to 'item-iterating'" in err


def test_dispatch_register_defaults_mode_for_recon_role(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """L2-1: recon-specialist defaults to hypothesis-driven (canonical per-role
    default from operator-core Iteration-mode Declaration)."""
    fake = _run_dispatch_verb(
        monkeypatch,
        "register",
        agent_id="AG-RECON-NO-MODE",
        agent_role="recon-specialist",
        task="subdomain enum",
        skills="subdomain-enumeration",
    )
    capsys.readouterr()
    assert fake.recorded[0]["dispatch_mode"] == "hypothesis-driven"


def test_dispatch_register_without_skills_proceeds_with_warning(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A dispatch with no --skills WARNs and proceeds rather than exiting
    non-zero — the specialist picks its skills from the surface."""
    fake = _run_dispatch_verb(
        monkeypatch,
        "register",
        agent_id="AG-ADHOC",
        agent_role="vulnerability-analyst",
        task="ad-hoc probe",
        dispatch_mode_arg="item-iterating",
    )
    err = capsys.readouterr().err
    assert "skills not set for role 'vulnerability-analyst'" in err
    assert fake.recorded[0]["agent_id"] == "AG-ADHOC"


def test_dispatch_register_normalizes_role_to_agent_role(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """L2-7: a --from-json payload carrying only `role` is normalized to
    `agent_role` before POST so the backend never silently 422s, and the
    `role` alias is dropped (extra='forbid' on the backend model)."""
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(
            {
                "agent_id": "AG-ROLE-ALIAS",
                "role": "vulnerability-analyst",
                "task": "IDOR sweep",
                "dispatch_mode": "item-iterating",
                "skills": "idor-testing",
            },
            handle,
        )
        payload_path = handle.name

    fake = _run_dispatch_verb(monkeypatch, "register", from_json=payload_path)
    capsys.readouterr()
    recorded = fake.recorded[0]
    assert recorded["agent_role"] == "vulnerability-analyst"
    assert "role" not in recorded


def test_dispatch_register_overlap_check_is_default_on(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Every start checks structured overlap unless explicitly suppressed."""
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
    list_calls: list[dict] = []
    orig_list = fake.list_dispatches

    def _tracking_list(**filters):
        list_calls.append(filters)
        return orig_list(**filters)

    fake.list_dispatches = _tracking_list  # type: ignore[assignment]
    monkeypatch.setattr(module.agent, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        module.agent,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir="/tmp/eng",
            engagement_key="eng",
            agent_root="/tmp",
        ),
    )

    _invoke_backend_lifecycle(
        module,
        "register",
        _dispatch_args(
            "register",
            agent_id="AG-NEW",
            agent_role="vulnerability-analyst",
            task="Follow-up exploitation attempt",
            finding_slugs="VA-001",
            dispatch_mode_arg="item-iterating",
            skills="idor-testing",
        ),
    )

    err = capsys.readouterr().err
    assert "dispatch rows appear to overlap" in err
    assert {call["status"] for call in list_calls} == {"in-progress", "completed"}
    assert fake.recorded[0]["agent_id"] == "AG-NEW"


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
    monkeypatch.setattr(module.agent, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        module.agent,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir="/tmp/eng",
            engagement_key="eng",
            agent_root="/tmp",
        ),
    )

    _invoke_backend_lifecycle(
        module,
        "register",
        _dispatch_args(
            "register",
            agent_id="AG-NEW",
            agent_role="vulnerability-analyst",
            task="Follow-up exploitation attempt",
            finding_slugs="VA-001",
            dispatch_mode_arg="item-iterating",
            skills="idor-testing",
        ),
    )

    err = capsys.readouterr().err
    assert "WARN agent start" in err
    assert "same finding_slugs: VA-001" in err
    assert fake.recorded[0]["agent_id"] == "AG-NEW"


def test_dispatch_overlap_pages_ranks_counts_and_includes_completed(capsys) -> None:
    module = _load_dispatch_module()

    class _PagedOverlapClient:
        def __init__(self) -> None:
            self.calls: list[dict] = []

        def list_dispatches(self, **filters):
            self.calls.append(filters)
            status = filters["status"]
            offset = int(filters.get("offset", 0))
            if status == "in-progress" and offset == 0:
                return [
                    {
                        "agent_id": f"filler-{index}",
                        "agent_role": "vulnerability-analyst",
                        "status": status,
                        "task": f"unrelated {index}",
                    }
                    for index in range(1000)
                ]
            if status == "in-progress" and offset == 1000:
                return [
                    {
                        "agent_id": "active-one",
                        "agent_role": "vulnerability-analyst",
                        "status": status,
                        "finding_slugs": ["VA-001"],
                        "completed_at": None,
                    }
                ]
            if status == "completed" and offset == 0:
                return [
                    {
                        "agent_id": "completed-two",
                        "agent_role": "vulnerability-analyst",
                        "status": status,
                        "finding_slugs": ["VA-001", "VA-002"],
                        "completed_at": "2026-09-09T12:00:00Z",
                    },
                    {
                        "agent_id": "completed-exact-with-findings",
                        "agent_role": "vulnerability-analyst",
                        "status": status,
                        "finding_slugs": ["VA-100", "VA-101", "VA-102"],
                        "task": "new task",
                        "completed_at": "2026-09-09T10:00:00Z",
                    },
                    {
                        "agent_id": "completed-exact-no-findings",
                        "agent_role": "vulnerability-analyst",
                        "status": status,
                        "finding_slugs": [],
                        "task": "new task",
                        "completed_at": "2026-09-09T11:00:00Z",
                    },
                ]
            return []

    client = _PagedOverlapClient()
    module.agent._warn_on_overlapping_dispatch(
        client,
        {
            "agent_id": "new",
            "agent_role": "vulnerability-analyst",
            "finding_slugs": ["VA-001", "VA-002"],
            "task": "new task",
        },
    )

    err = capsys.readouterr().err
    assert err.index("completed-two") < err.index("active-one")
    assert err.index("completed-exact-with-findings") < err.index(
        "completed-exact-no-findings"
    )
    assert "completed-two (vulnerability-analyst, completed)" in err
    assert "4 of 4 overlapping dispatches shown" in err
    assert {call["status"] for call in client.calls} == {"in-progress", "completed"}
    assert any(call.get("offset") == 1000 for call in client.calls)


def test_dispatch_overlap_reports_incomplete_scan_with_zero_matches(capsys) -> None:
    module = _load_dispatch_module()
    module.agent._OVERLAP_PAGE_SIZE = 2
    module.agent._OVERLAP_MAX_PAGES = 2

    class _RepeatingPageClient:
        def list_dispatches(self, **filters):
            status = filters["status"]
            return [
                {
                    "id": index,
                    "agent_id": f"{status}-{index}",
                    "agent_role": "vulnerability-analyst",
                    "status": status,
                    "task": f"unrelated {index}",
                }
                for index in range(2)
            ]

    module.agent._warn_on_overlapping_dispatch(
        _RepeatingPageClient(),
        {
            "agent_id": "new",
            "agent_role": "vulnerability-analyst",
            "task": "new task",
        },
    )

    err = capsys.readouterr().err
    assert "duplicate-overlap history scan incomplete" in err
    assert "4 dispatch rows inspected" in err
    assert "no overlap found in the inspected rows" in err
    assert "backend history was not exhausted" in err


def test_dispatch_register_does_not_warn_for_shared_unit_mode_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_dispatch_module()
    fake = _CapturingClient()
    fake.dispatches_by_id["AG-OLD"] = {
        "id": 1,
        "agent_id": "AG-OLD",
        "agent_role": "vulnerability-analyst",
        "status": "in-progress",
        "application_unit_id": 7,
        "dispatch_mode": "hypothesis-driven",
        "task": "Review password reset flows",
    }
    monkeypatch.setattr(module.agent, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        module.agent,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir="/tmp/eng",
            engagement_key="eng",
            agent_root="/tmp",
        ),
    )

    _invoke_backend_lifecycle(
        module,
        "register",
        _dispatch_args(
            "register",
            agent_id="AG-NEW",
            agent_role="vulnerability-analyst",
            application_unit_id=7,
            dispatch_mode_arg="hypothesis-driven",
            task="Review account deletion flows",
            skills="idor-testing",
        ),
    )

    err = capsys.readouterr().err
    assert "active dispatch rows appear to overlap" not in err
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
    monkeypatch.setattr(module.agent, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        module.agent,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir="/tmp/eng",
            engagement_key="eng",
            agent_root="/tmp",
        ),
    )

    _invoke_backend_lifecycle(
        module,
        "abort-duplicate",
        _dispatch_args(
            "abort-duplicate",
            extra=["AG-DUP"],
            replacement_agent_id="AG-KEEP",
            reason="same exploit review was registered twice",
        ),
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
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    fake = _ListClient()
    monkeypatch.setattr(module.agent, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        module.agent,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir="/tmp/eng",
            engagement_key="eng",
            agent_root="/tmp",
        ),
    )
    module.agent._list_dispatches(SimpleNamespace(
        db_path="list", action="", extra=[], reason="", by="status",
        max_lines=40, include_evidence=False, engagement_dir=None,
        agent_id=None, agent_role=None, task=None, application_unit_id=None,
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


def test_dispatch_record_handoff_from_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload_path = tmp_path / "handoff.json"
    payload_path.write_text(
        json.dumps(
            {
                "agent_id": "HF-CLI-1",
                "agent_role": "vulnerability-analyst",
                "summary": "Validated IDOR write primitive.",
                "next_steps": [{"action": "promote to exploit-developer"}],
                "coverage_gaps": [
                    {"area": "auth boundary", "reason": "anonymous untested"}
                ],
                "recommended_next_agent": "exploit-developer",
                "finding_slugs": ["VA-001"],
            }
        ),
        encoding="utf-8",
    )
    fake = _run_dispatch_verb(
        monkeypatch,
        "record-handoff",
        from_json=str(payload_path),
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


def test_dispatch_handoff_can_patch_status_without_replacing_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_dispatch_module()
    fake = _CapturingClient()
    fake.handoffs_by_id["HF-PROMOTE"] = {
        "id": 42,
        "agent_id": "HF-PROMOTE",
        "agent_role": "vulnerability-analyst",
        "summary": "Specialist-authored detailed summary.",
        "handoff_status": "checkpointed",
    }
    monkeypatch.setattr(module.agent, "_client_for", lambda _args: (fake, SimpleNamespace()))

    payload_path = tmp_path / "handoff-update.json"
    payload_path.write_text(
        '{"agent_id":"HF-PROMOTE","handoff_status":"ready"}\n',
        encoding="utf-8",
    )
    module.agent._record_handoff(SimpleNamespace(from_json=str(payload_path)))

    row = fake.handoffs_by_id["HF-PROMOTE"]
    assert row["handoff_status"] == "ready"
    assert row["summary"] == "Specialist-authored detailed summary."
    assert fake.handoff_calls == []
    assert json.loads(capsys.readouterr().out)["agent_id"] == "HF-PROMOTE"


def test_dispatch_record_handoff_is_idempotent_for_repeat_calls(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Round 9c: agents call record-handoff after every major step. The same
    (engagement, agent_id) tuple collides on every call after the first; the
    CLI must transparently fall back to PATCH so the agent never sees a 409."""
    module = _load_dispatch_module()
    # One fake shared across all three calls so handoffs_by_id persists.
    shared_fake = _CapturingClient()
    monkeypatch.setattr(module.agent, "AssessmentClient", lambda *a, **k: shared_fake)
    monkeypatch.setattr(
        module.agent,
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
            "application_unit_id": None,
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
        module.agent._record_handoff(SimpleNamespace(**args_dict))

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
    from assess.lib.client import AssessError, AssessmentClient  # type: ignore[import-not-found]

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
    from assess.lib.client import AssessError, AssessmentClient  # type: ignore[import-not-found]

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
#   3. ``vigil config get orchestrator_base_url`` (persistent default)
#   4. Install-root env files (legacy fallback)
#   5. Hardcoded fallback ``http://127.0.0.1:18000``
# ──────────────────────────────────────────────────────────────────────────


def test_resolve_orchestrator_base_url_env_var_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import paths as paths_module
    from vigil_cli.paths import resolve_orchestrator_base_url

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
    from vigil_cli import paths as paths_module
    from vigil_cli.paths import resolve_orchestrator_base_url

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
    """With env var unset and no engagement env file override, vigil config
    is consulted before the hardcoded default."""
    from vigil_cli import paths as paths_module
    from vigil_cli.paths import resolve_orchestrator_base_url

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
    from vigil_cli import paths as paths_module
    from vigil_cli.paths import resolve_orchestrator_base_url

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
    from vigil_cli import paths as paths_module
    from vigil_cli.paths import resolve_orchestrator_base_url

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
    from vigil_cli import paths as paths_module
    from vigil_cli.paths import (
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
    monkeypatch.delenv("VIGIL_CONFIG", raising=False)

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
    config_path = tmp_path / "vigil-config.json"
    config_path.write_text(
        json.dumps({"orchestrator_base_url": "http://from-config:5678/"}),
        encoding="utf-8",
    )

    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.setenv("VIGIL_CONFIG", str(config_path))

    assert (
        module.resolve_base_url(str(engagement_dir), str(install_root / "agent"))
        == "http://from-config:5678"
    )


# ---------------------------------------------------------------------------
# Dispatch contract has no target-scope admission
# ---------------------------------------------------------------------------


def test_validate_dispatch_allows_vuln_analyst_without_scope() -> None:
    """A vulnerability analyst receives an objective, not a scope declaration."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    payload = {
        "agent_id": "va-1",
        "agent_role": "vulnerability-analyst",
        "task": "Probe IDOR",
        "dispatch_mode": "item-iterating",
        "skills": "idor-testing",
    }
    errors, _warnings = validate_specialist_dispatch_contract(payload)
    assert errors == []


def test_agent_start_payload_uses_application_unit_without_loading_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A red dispatch is attributed to a concrete unit, never authorized by scope."""
    module = _load_dispatch_module()

    def _scope_load_is_a_bug(*_args, **_kwargs):
        raise AssertionError("agent start must not load engagement scope")

    monkeypatch.setattr(module.agent, "load_config", _scope_load_is_a_bug)
    payload = module._build_register_payload(
        _dispatch_args(
            "register",
            agent_id="va-unit-1",
            agent_role="vulnerability-analyst",
            dispatch_mode_arg="item-iterating",
            task="Deep pass over application unit 41",
            skills="idor-testing",
            application_unit_id=41,
        )
    )
    assert payload["application_unit_id"] == 41
    assert "scope_host" not in payload
    assert "scope_path_prefix" not in payload


def test_validate_dispatch_allows_exploit_developer_without_scope() -> None:
    """Exploit-developer dispatch admission is independent of target scope."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    payload = {
        "agent_id": "exp-1",
        "agent_role": "exploit-developer",
        "task": "Chain IDOR + token reuse",
        "dispatch_mode": "deep-manual",
        "skills": "idor-testing",
    }
    errors, _warnings = validate_specialist_dispatch_contract(payload)
    assert errors == []


def test_validate_dispatch_allows_recon_without_scope() -> None:
    """Recon dispatches use their task objective without a target-scope field."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    payload = {
        "agent_id": "recon-1",
        "agent_role": "recon-specialist",
        "task": "Cert-chain pivot recon",
        "dispatch_mode": "hypothesis-driven",
        "skills": "web-recon",
    }
    errors, _warnings = validate_specialist_dispatch_contract(payload)
    assert errors == []


def test_validate_dispatch_accepts_application_unit_metadata() -> None:
    """Concrete depth attribution is valid optional dispatch metadata."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    payload = {
        "agent_id": "va-1",
        "agent_role": "vulnerability-analyst",
        "task": "Probe IDOR",
        "application_unit_id": 17,
        "dispatch_mode": "item-iterating",
        "skills": "idor-testing",
    }
    errors, _warnings = validate_specialist_dispatch_contract(payload)
    assert errors == []


def test_validate_dispatch_flags_technique_cage_warn_only() -> None:
    """C4a: a numbered step list that pre-names vuln classes reads as a technique
    cage — the validator WARNs (pointing at `coverage --for-dispatch`) and NEVER
    adds to errors. WARN-only is the whole contract of the lint."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    payload = {
        "agent_role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
        "skills": "idor-testing",
        "task": (
            "Test the login endpoint for the following:\n"
            "1. Test for SQLi in the username parameter\n"
            "2. Check for XSS in the redirect field\n"
            "3. Verify the JWT signature is validated\n"
            "4. Confirm CSRF tokens are enforced\n"
        ),
    }
    errors, warnings = validate_specialist_dispatch_contract(payload)
    assert errors == [], errors  # a cage is a depth smell, never an error
    assert any("technique cage" in w for w in warnings), warnings
    assert any("--for-dispatch" in w for w in warnings), warnings
    assert not any("cage" in e.lower() for e in errors), errors


def test_validate_dispatch_open_objective_task_has_no_cage_warning() -> None:
    """C4a conservatism: an open-ended, hypothesis-framed prose task (no step
    list, no imperative verb run) must NOT trip the technique-cage lint, so the
    warning does not fire on legitimately-shaped dispatches."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    payload = {
        "agent_role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
        "skills": "idor-testing",
        "task": (
            "Hunt the tenant-isolation boundary on the orders workflow. We have "
            "two member identities in different orgs; the interesting question is "
            "whether one org's member can observe or mutate the other org's "
            "records. Reason about where the boundary is enforced and where it "
            "leaks, then follow the strongest signal you find."
        ),
    }
    errors, warnings = validate_specialist_dispatch_contract(payload)
    assert not any("technique cage" in w for w in warnings), warnings
    assert errors == [], errors


def test_detect_technique_cage_requires_two_signals() -> None:
    """The pure lint helper is conservative: a single signal (a step list alone,
    or a lone vuln-class mention in prose) is not enough — >=2 co-occurring
    signals are required before it warns."""
    from assess.lib.contracts import _detect_technique_cage

    # A numbered list with NO vuln class and NO imperative-verb run — one signal.
    step_only = (
        "Cover the checkout flow in this order:\n"
        "1. the cart page\n"
        "2. the shipping page\n"
        "3. the payment page\n"
    )
    assert _detect_technique_cage(step_only) == []

    # A single vuln-class mention in open prose — one signal only.
    class_only = "Consider whether an idor is reachable across the two org tenants."
    assert _detect_technique_cage(class_only) == []

    # Two co-occurring signals (step list + pre-named classes) — warns.
    caged = (
        "Run these probes:\n"
        "1. Test the id param for sqli\n"
        "2. Test the url param for ssrf\n"
        "3. Test the next param for open-redirect\n"
    )
    caged_warnings = _detect_technique_cage(caged)
    assert caged_warnings and "technique cage" in caged_warnings[0]
    assert "--for-dispatch" in caged_warnings[0]


def test_detect_technique_cage_ignores_benign_scope_list_but_catches_bug_menu() -> None:
    """Regression (QC): a structured SCOPE list with one incidental class noun and
    NO imperative verbs is not a cage and must not warn (avoids warning-fatigue);
    a verb-less per-step BUG MENU (>=2 steps each pre-naming a class) IS a cage."""
    from assess.lib.contracts import _detect_technique_cage

    # Benign: numbered scope areas, one incidental class token, zero imperative
    # verbs — a single class-naming step line is below the bug-menu threshold.
    benign = (
        "Review these areas in order:\n"
        "1. the sqli-prone search endpoint\n"
        "2. the account settings page\n"
        "3. the admin dashboard\n"
    )
    assert _detect_technique_cage(benign) == []

    # A cage without imperative verbs: each step pre-names a specific bug class.
    bug_menu = (
        "Cover these:\n"
        "1. idor on /api/users/{id}\n"
        "2. sqli on the login form\n"
        "3. ssrf on the webhook url\n"
    )
    menu_warnings = _detect_technique_cage(bug_menu)
    assert menu_warnings and "technique cage" in menu_warnings[0]


def test_detect_technique_cage_needs_named_bug_not_bare_recipe() -> None:
    """Regression (blind triage): a STRUCTURED imperative list that names no bug
    to hunt is NOT a cage — an orientation checklist and a confirmed-finding PoC
    both have >=3 steps + imperative verbs but pre-name no vuln class, so they
    must stay quiet. A cage needs >=2 named bug classes on its recipe lines."""
    from assess.lib.contracts import _detect_technique_cage

    orientation = (
        "Get your bearings first:\n"
        "1. Enumerate the site routes\n"
        "2. Confirm the login flow works\n"
        "3. Verify the account page loads\n"
    )
    assert _detect_technique_cage(orientation) == []

    poc = (
        "Weaponize the confirmed finding:\n"
        "1. Send a request to /latest/meta-data/\n"
        "2. Confirm the metadata document is returned\n"
        "3. Validate the returned creds against STS\n"
    )
    assert _detect_technique_cage(poc) == []

    # Exactly two recipe lines pre-name a bug -> the >=2 threshold; warns.
    two_named = (
        "Run these:\n"
        "1. Test sqli on the id param\n"
        "2. Test xss on the name param\n"
        "3. review the pricing page\n"
    )
    warned = _detect_technique_cage(two_named)
    assert warned and "technique cage" in warned[0]


def test_list_attempts_build_query_emits_route_param_names() -> None:
    """Regression (blind triage): the `coverage --attempts` CLI (folded-in
    list-attempts) must emit the EXACT query-param names the GET /attempts route
    accepts (notably --surface -> surface_id, --host -> target_host); a drift here
    silently returns unfiltered results and no round-trip test would catch it."""
    from types import SimpleNamespace

    from assess.commands.coverage import _attempts_query as _build_query

    args = SimpleNamespace(
        finding="VA-1", surface="12", host="app.example.com",
        attack_family="idor", result_status="no-signal", lens="tenant-boundary",
        limit=25, offset=5,
    )
    query = _build_query(args)
    assert query.startswith("attempts?")
    params = parse_qs(urlparse("http://x/" + query).query)
    assert params["surface_id"] == ["12"]
    assert params["target_host"] == ["app.example.com"]
    assert params["finding"] == ["VA-1"]
    assert params["attack_family"] == ["idor"]
    assert params["result_status"] == ["no-signal"]
    assert params["lens"] == ["tenant-boundary"]
    assert params["limit"] == ["25"]
    assert params["offset"] == ["5"]
    # The CLI-side dest names must NOT leak onto the wire.
    assert "surface" not in params and "host" not in params


def test_validate_dispatch_missing_mode_defaults_and_warns_not_errors() -> None:
    """L2-1: a missing dispatch_mode no longer hard-errors; it warns and names
    the role default rather than emitting `missing required field`."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    payload = {
        "agent_role": "exploit-developer",
        "task": "Chain primitives",
        "skills": "idor-testing",
    }
    errors, warnings = validate_specialist_dispatch_contract(payload)
    assert not any("dispatch_mode" in e for e in errors), errors
    assert not any("missing required field" in e for e in errors), errors
    assert any("deep-manual" in w for w in warnings), warnings


def test_validate_dispatch_unknown_mode_warns_not_errors() -> None:
    """L2-4: an unknown dispatch_mode is advisory at the validator (warn, not
    error) so a newly-coined mode is not blocked."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    payload = {
        "agent_role": "vulnerability-analyst",
        "dispatch_mode": "freshly-coined-mode",
        "skills": "idor-testing",
    }
    errors, warnings = validate_specialist_dispatch_contract(payload)
    assert not any("dispatch_mode" in e for e in errors), errors
    assert any("freshly-coined-mode" in w for w in warnings), warnings


def test_validate_dispatch_missing_skills_is_a_warning_not_an_error() -> None:
    """A missing skills list never blocks a dispatch — it warns."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    payload = {
        "agent_role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
    }
    errors, warnings = validate_specialist_dispatch_contract(payload)
    assert not any("skills is required" in e for e in errors), errors
    assert any("skills not set" in w for w in warnings), warnings


def test_validate_dispatch_missing_recipe_metadata_is_visible_debt() -> None:
    """A live dispatch without requested model/reasoning must not look fully measured."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    errors, warnings = validate_specialist_dispatch_contract(
        {
            "agent_role": "code-vuln-hunter",
            "dispatch_mode": "item-iterating",
            "skills": "code-vulnerability-analysis",
        }
    )

    assert errors == []
    assert any("requested_model" in warning for warning in warnings)
    assert any("requested_reasoning" in warning for warning in warnings)


def test_validate_dispatch_has_no_engagement_file_dependency() -> None:
    """Dispatch validation is a pure payload contract."""
    from assess.lib.contracts import validate_specialist_dispatch_contract

    payload = {
        "agent_id": "va-1",
        "agent_role": "vulnerability-analyst",
        "dispatch_mode": "item-iterating",
        "skills": "idor-testing",
    }
    errors, warnings = validate_specialist_dispatch_contract(payload)
    assert errors == []
    assert not any("scope" in warning.lower() for warning in warnings)


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
    """C42a: vigil assess auth-status reads auth.json and emits a structured
    snapshot — auth_context, mode, expires_state, the auth material it carries
    (raw values, the form an operator replays by hand), and a refresh-path
    recommendation matching the C42 recovery loop. The command does NOT write
    to auth.json or trigger a refresh."""
    eng_dir = tmp_path / "eng"
    eng_dir.mkdir(parents=True, exist_ok=True)
    module = _load_auth_status_module()

    # Active credential lives in the centralized store; stub active_material.
    monkeypatch.setattr(
        module,
        "active_material",
        # record_use=False: the status VIEW is inspection, not a use.
        lambda _eng, *, record_use=True: {
            "auth_context": "authenticated",
            "mode": "proxy_capture",
            "use_for_requests": True,
            "state": "available",
            "expires_at": "2099-01-01T00:00:00Z",
            "headers": {"Authorization": "Bearer aaa.bbb.ccc.ddd.eee.fff"},
            "cookies": {"sessionid": "abc123"},
        },
    )

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
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

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
    assert "Authorization: Bearer aaa.bbb.ccc.ddd.eee.fff" in snapshot["tokens"]
    assert "flat_cookies: sessionid=abc123" in snapshot["tokens"]
    assert snapshot["last_auth_probe"]["run_id"] == 7
    assert "Bearer token present" in snapshot["recommend"]


def test_auth_status_flags_expired_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """C42a: when expires_at is in the past, expires_state reports 'expired'
    and the recommend line still names the appropriate refresh path."""
    eng_dir = tmp_path / "eng-expired"
    eng_dir.mkdir(parents=True, exist_ok=True)
    module = _load_auth_status_module()

    monkeypatch.setattr(
        module,
        "active_material",
        # record_use=False: the status VIEW is inspection, not a use.
        lambda _eng, *, record_use=True: {
            "auth_context": "authenticated",
            "mode": "proxy_capture",
            "use_for_requests": True,
            "state": "available",
            "expires_at": "2000-01-01T00:00:00Z",
            "headers": {"Authorization": "Bearer expired.token"},
        },
    )

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
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

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
    module = _load_auth_status_module()

    monkeypatch.setattr(
        module,
        "active_material",
        # record_use=False: the status VIEW is inspection, not a use.
        lambda _eng, *, record_use=True: {
            "auth_context": "authenticated",
            "mode": "proxy_capture",
            "use_for_requests": True,
            "state": "available",
            "expires_at": "2099-01-01T00:00:00Z",
            "headers": {"Authorization": "Bearer route.token"},
        },
    )

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
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

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


def test_agent_start_does_not_write_scope_rejection_decision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Scope metadata cannot reject a dispatch or emit rejection telemetry."""
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
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module.agent, "AssessmentClient", _DecisionCapturingClient)
    monkeypatch.setattr(
        module.agent,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(eng_dir),
            engagement_key="eng",
            agent_root=str(tmp_path),
        ),
    )

    payload = module._build_register_payload(
        _dispatch_args(
            "register",
            agent_id="va-rej-1",
            agent_role="vulnerability-analyst",
            application_unit_id=19,
            dispatch_mode_arg="item-iterating",
            task="probe IDOR",
            skills="idor-testing",
            engagement_dir=str(eng_dir),
        )
    )
    err = capsys.readouterr().err
    assert "scope" not in err.lower()
    assert payload["application_unit_id"] == 19
    assert recorded_decisions == []


# Shared-VM preflight: refuse/warn when the runtime tier oversubscribes the VM.

def _gib(n: float) -> int:
    return int(n * (1024 ** 3))


def _preflight_runner(commands, *, info_stdout: str, install_root: Path, cotenants=()):
    from vigil_cli.docker import DockerResult

    mounts = (
        f"{install_root / '.runtime-data'} -> /data\n"
        f"{install_root / 'agent' / 'engagements'} -> /engagements\n"
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "info", "--format"]:
            return DockerResult(0, info_stdout, "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "\n".join(cotenants), "")
        if argv[:3] == ["docker", "inspect", "-f"] and "{{range .Mounts}}" in argv[3]:
            return DockerResult(0, mounts, "")
        if argv[:2] == ["docker", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        return DockerResult(0, "", "")

    return runner


def _preflight_install_root(tmp_path: Path) -> Path:
    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)
    (install_root / ".runtime-data").mkdir()
    return install_root


def test_runtime_start_refuses_when_tier_exceeds_vm(tmp_path, monkeypatch):
    import json as _json

    from vigil_cli.runtime import RuntimeOptions, start_runtime

    monkeypatch.setenv("VIGIL_RUNTIME_MEMORY_GB", "8")
    install_root = _preflight_install_root(tmp_path)
    commands: list[list[str]] = []
    # 8 GB VM, 8 GB tier => 100% => refuse.
    runner = _preflight_runner(commands, info_stdout=_json.dumps({"MemTotal": _gib(8), "NCPU": 4}), install_root=install_root)

    with pytest.raises(SystemExit) as exc:
        start_runtime(RuntimeOptions(install_root=install_root), runner=runner, validate_tools=False)
    assert "oversubscribe" in str(exc.value).lower() or "Refusing" in str(exc.value)
    # No container was started.
    assert not any(c[:3] == ["docker", "run", "-d"] for c in commands)


def test_runtime_start_preflights_before_removing_existing_container(tmp_path, monkeypatch):
    import json as _json

    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import RuntimeOptions, start_runtime

    monkeypatch.setenv("VIGIL_RUNTIME_MEMORY_GB", "8")
    install_root = _preflight_install_root(tmp_path)
    commands: list[list[str]] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            return DockerResult(0, "sha256:image\n", "")
        if argv[:3] == ["docker", "info", "--format"]:
            return DockerResult(0, _json.dumps({"MemTotal": _gib(8), "NCPU": 4}), "")
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "", "")
        if argv[:3] == ["docker", "ps", "-a"]:
            return DockerResult(0, "vigil\n", "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit):
        start_runtime(
            RuntimeOptions(install_root=install_root, recreate=True),
            runner=runner,
            validate_tools=False,
        )

    assert not any(c[:3] == ["docker", "rm", "-f"] for c in commands)
    assert not any(c[:3] == ["docker", "run", "-d"] for c in commands)


def test_runtime_start_allow_oversubscribe_bypasses_refusal(tmp_path, monkeypatch):
    import json as _json

    from vigil_cli.runtime import RuntimeOptions, start_runtime

    monkeypatch.setenv("VIGIL_RUNTIME_MEMORY_GB", "8")
    install_root = _preflight_install_root(tmp_path)
    commands: list[list[str]] = []
    runner = _preflight_runner(commands, info_stdout=_json.dumps({"MemTotal": _gib(8), "NCPU": 4}), install_root=install_root)

    start_runtime(
        RuntimeOptions(install_root=install_root, allow_oversubscribe=True),
        runner=runner,
        validate_tools=False,
    )
    assert any(c[:3] == ["docker", "run", "-d"] for c in commands)


def test_runtime_start_warns_with_cotenants_but_proceeds(tmp_path, monkeypatch, capsys):
    import json as _json

    from vigil_cli.runtime import RuntimeOptions, start_runtime

    monkeypatch.setenv("VIGIL_RUNTIME_MEMORY_GB", "8")
    install_root = _preflight_install_root(tmp_path)
    commands: list[list[str]] = []
    # Ample 64 GB VM (frac 0.125) but co-tenant containers present => warn, proceed.
    runner = _preflight_runner(
        commands,
        info_stdout=_json.dumps({"MemTotal": _gib(64), "NCPU": 12}),
        install_root=install_root,
        cotenants=["bigcapital-local-mysql", "database-mssql-1"],
    )
    start_runtime(RuntimeOptions(install_root=install_root), runner=runner, validate_tools=False)
    assert any(c[:3] == ["docker", "run", "-d"] for c in commands)
    assert "co-tenant" in capsys.readouterr().out


def test_runtime_start_proceeds_when_docker_info_unparseable(tmp_path, monkeypatch):
    from vigil_cli.runtime import RuntimeOptions, start_runtime

    monkeypatch.setenv("VIGIL_RUNTIME_MEMORY_GB", "8")
    install_root = _preflight_install_root(tmp_path)
    commands: list[list[str]] = []
    runner = _preflight_runner(commands, info_stdout="not-json-garbage", install_root=install_root)
    start_runtime(RuntimeOptions(install_root=install_root), runner=runner, validate_tools=False)
    # Unreadable capacity => fail open => container still started.
    assert any(c[:3] == ["docker", "run", "-d"] for c in commands)


# ── Phase 6c: `vigil engagement export --format markdown-tree` ──────────────
#
# Deterministic, no live LLM: seed an engagement + findings + a
# verification-narrative artifact through the FastAPI TestClient (the same
# read API the production CLI hits over a socket), wrap that TestClient in a
# tiny `.get(endpoint)` adapter, and drive `export_engagement_tree` straight
# through. Asserts the per-finding directory tree and the draft/debate/report
# file contents so an engagement review is git-diff-able without the backend
# running.

_EXPORT_ENGAGEMENT_KEY = "2026-05-30-100000-export"
_EXPORT_BASE = f"/engagements/{_EXPORT_ENGAGEMENT_KEY}/assessment"


class _TestClientGetAdapter:
    """Adapt a FastAPI TestClient to the `AssessmentClient.get` read surface.

    `export_engagement_tree` only consumes `client.get(endpoint)` where
    `endpoint` is relative to the assessment prefix; this mirrors how the real
    `AssessmentClient.get` builds `/engagements/{key}/assessment/{endpoint}`,
    so the exporter runs against the real backend read path with zero sockets.
    """

    def __init__(self, test_client, engagement_key: str) -> None:
        self._client = test_client
        self._prefix = f"/engagements/{engagement_key}/assessment"

    def get(self, endpoint: str):
        response = self._client.get(f"{self._prefix}/{endpoint}")
        assert response.status_code == 200, (endpoint, response.text)
        return response.json()


def _confirm_export_finding(client, slug: str) -> None:
    verifier_id = f"export-verifier-{slug.lower()}"
    dispatch = client.post(
        f"{_EXPORT_BASE}/dispatches",
        json={
            "agent_id": verifier_id,
            "agent_role": "report-verifier",
            "task": f"Independently verify {slug} for export.",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    run = client.post(
        f"{_EXPORT_BASE}/assessment-runs",
        json={
            "run_uuid": f"export-proof-{slug.lower()}",
            "run_kind": "shared",
            "producer_dispatch_agent_id": verifier_id,
        },
    )
    assert run.status_code == 201, run.text
    linked = client.post(
        f"{_EXPORT_BASE}/findings/{slug}/links",
        json={"link_kind": "proof_run", "target_kind": "assessment_run", "target_id": run.json()["id"]},
    )
    assert linked.status_code == 200, linked.text
    receipt = post_artifact_backed_source_observation(
        client,
        f"{_EXPORT_BASE}/proof-receipts",
        json={
            "run_id": run.json()["id"],
            "evidence_kind": "source_observation",
            "expected_result": "The finding is not reproducible as recorded.",
            "observed_result": "Independent review reproduced the finding as recorded.",
        },
    )
    assert receipt.status_code == 201, receipt.text
    finished = client.patch(
        f"{_EXPORT_BASE}/assessment-runs/{run.json()['id']}",
        json={"status": "completed"},
    )
    assert finished.status_code == 200, finished.text
    verified = client.post(
        f"{_EXPORT_BASE}/findings/{slug}/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "Independent review reproduced the finding.",
            "source_name": "report-verifier",
            "proof_receipt_ids": [receipt.json()["id"]],
            "confirm_check": completed_confirm_check(receipt.json()["id"]),
        },
    )
    assert verified.status_code == 200, verified.text


def _seed_export_engagement(client, isolate_settings) -> Path:
    engagements_dir = isolate_settings["engagements_dir"]
    eng = engagements_dir / _EXPORT_ENGAGEMENT_KEY
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "notes").mkdir(parents=True, exist_ok=True)
    (eng / "engagement.json").write_text(
        json.dumps(
            {
                "key": _EXPORT_ENGAGEMENT_KEY,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-05-30T10:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (eng / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "hosts": ["example.com"],
                "status": "in_progress",
                "current_phase": "recon",
            }
        ),
        encoding="utf-8",
    )
    (eng / "findings.md").write_text("# Findings\n", encoding="utf-8")

    # Force the backend to pick up the on-disk engagement.
    assert client.get(f"/engagements/{_EXPORT_ENGAGEMENT_KEY}").status_code == 200

    author = client.post(
        f"{_EXPORT_BASE}/dispatches",
        json={
            "agent_id": "export-fixture-author",
            "agent_role": "vulnerability-analyst",
            "task": "Record export fixture findings.",
        },
    )
    assert author.status_code == 201, author.text

    # Finding A: high severity, with structured details + a linked debate doc.
    created = client.post(
        f"{_EXPORT_BASE}/findings",
        json={
            "slug": "VA-001",
            "title": "SQL injection in login",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "sqli",
            "canonical_location": "https://example.com/login",
            "summary": "Auth bypass via UNION-based SQLi",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "provenance": {"agent_id": "export-fixture-author"},
            "details": {
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021",
                "remediation": "Use parameterized queries.",
                "steps_to_reproduce": ["POST /login", "Inject ' OR 1=1 --"],
                "impact": "Full authentication bypass.",
            },
        },
    )
    assert created.status_code == 201, created.text
    _confirm_export_finding(client, "VA-001")

    # Finding B: low severity, NO linked narrative → debate.md placeholder.
    created_b = client.post(
        f"{_EXPORT_BASE}/findings",
        json={
            "slug": "VA-002",
            "title": "Verbose error messages",
            "severity": "low",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "info-leak",
            "canonical_location": "https://example.com/debug",
            "summary": "Stack traces leak in 500 responses.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "provenance": {"agent_id": "export-fixture-author"},
        },
    )
    assert created_b.status_code == 201, created_b.text

    # Register the Phase-3 verification-narrative artifact for VA-001.
    (eng / "notes" / "VA-001-debate.md").write_text(
        "# VA-001 Ideator-vs-Tracer debate\n\nClaim -> causal challenge -> evidence -> verdict.\n",
        encoding="utf-8",
    )
    registered = client.post(
        f"{_EXPORT_BASE}/artifacts",
        json={
            "path": "notes/VA-001-debate.md",
            "kind": "verification-narrative",
            "related_finding_slug": "VA-001",
            "producer_agent_role": "vulnerability-analyst",
        },
    )
    assert registered.status_code == 201, registered.text
    return eng


def test_engagement_export_markdown_tree_writes_per_finding_dirs(
    client, isolate_settings, tmp_path: Path
) -> None:
    from vigil_cli.engagements import export_engagement_tree

    _seed_export_engagement(client, isolate_settings)
    adapter = _TestClientGetAdapter(client, _EXPORT_ENGAGEMENT_KEY)
    out_root = tmp_path / "export-tree"

    result = export_engagement_tree(adapter, out_root, fmt="markdown-tree")

    # One directory per finding, named by canonical slug, each with the three
    # review files.
    assert result.finding_count == 2
    assert {d.name for d in result.finding_dirs} == {"VA-001", "VA-002"}
    for finding_dir in result.finding_dirs:
        assert {p.name for p in finding_dir.iterdir()} == {"draft.md", "debate.md", "report.md"}

    va001 = out_root / "VA-001"

    # draft.md = raw finding rendering (flattened details from the backend).
    draft = (va001 / "draft.md").read_text(encoding="utf-8")
    assert "## [VA-001] SQL injection in login" in draft
    assert "- **Severity**: HIGH" in draft
    assert "- **CWE**: CWE-89" in draft
    assert "- **Remediation**: Use parameterized queries." in draft
    # Steps render exactly as authored — no counter and no list marker added.
    assert "**Steps to Reproduce:**\nPOST /login" in draft

    # debate.md = the linked verification-narrative artifact content.
    debate = (va001 / "debate.md").read_text(encoding="utf-8")
    assert "VA-001 Ideator-vs-Tracer debate" in debate
    assert "causal challenge -> evidence -> verdict" in debate
    assert "notes/VA-001-debate.md" in debate  # source provenance comment

    # report.md = report-ready rendering with the sequential report_id.
    report = (va001 / "report.md").read_text(encoding="utf-8")
    assert report.startswith("# 001 — SQL injection in login")
    assert "(`VA-001`)" in report
    assert "## Remediation" in report
    assert "Use parameterized queries." in report
    # report.md and draft.md share one step renderer, so the same finding's steps
    # read identically in both files: verbatim, no imposed counter or marker.
    assert "POST /login" in report
    assert "1. POST /login" not in report
    assert "- POST /login" not in report

    # VA-002 has no narrative → placeholder debate.md (still git-diff-able).
    va002_debate = (out_root / "VA-002" / "debate.md").read_text(encoding="utf-8")
    assert "No verification-narrative artifact" in va002_debate
    assert "vigil assess finding verify VA-002" in va002_debate


def test_engagement_export_markdown_tree_is_idempotent(
    client, isolate_settings, tmp_path: Path
) -> None:
    """Re-exporting into the same root reproduces identical files.

    Stable paths + stable content are the whole point — a second pass with no
    backend changes must leave the tree byte-for-byte identical so git shows
    an empty diff.
    """
    from vigil_cli.engagements import export_engagement_tree

    _seed_export_engagement(client, isolate_settings)
    adapter = _TestClientGetAdapter(client, _EXPORT_ENGAGEMENT_KEY)
    out_root = tmp_path / "export-tree"

    first = export_engagement_tree(adapter, out_root, fmt="markdown-tree")
    snapshot = {
        path.relative_to(out_root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(out_root.rglob("*.md"))
    }

    second = export_engagement_tree(adapter, out_root, fmt="markdown-tree")
    after = {
        path.relative_to(out_root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(out_root.rglob("*.md"))
    }

    assert first.finding_count == second.finding_count == 2
    assert snapshot == after


def test_engagement_export_markdown_tree_prunes_stale_finding_dirs(
    client, isolate_settings, tmp_path: Path
) -> None:
    """A re-export removes dirs for findings no longer present, but never
    touches unrelated content sharing the output root.

    Re-exporting into a stable root after a finding is merged/renamed/removed
    must not leave orphan dirs. The marker-file guard (draft.md + report.md)
    ensures only this exporter's own dirs are pruned.
    """
    from vigil_cli.engagements import export_engagement_tree

    _seed_export_engagement(client, isolate_settings)
    adapter = _TestClientGetAdapter(client, _EXPORT_ENGAGEMENT_KEY)
    out_root = tmp_path / "export-tree"
    out_root.mkdir(parents=True, exist_ok=True)

    # A prior export's orphan: a finding dir (with this exporter's marker
    # files) for a finding that no longer exists in the backend.
    stale = out_root / "VA-OLD"
    stale.mkdir()
    (stale / "draft.md").write_text("stale", encoding="utf-8")
    (stale / "report.md").write_text("stale", encoding="utf-8")
    (stale / "debate.md").write_text("stale", encoding="utf-8")

    # Unrelated content sharing the root must be preserved (no marker files).
    keep_dir = out_root / "keepme"
    keep_dir.mkdir()
    (keep_dir / "notes.txt").write_text("keep", encoding="utf-8")
    (out_root / "README.md").write_text("keep", encoding="utf-8")

    result = export_engagement_tree(adapter, out_root, fmt="markdown-tree")

    names = {p.name for p in out_root.iterdir()}
    assert "VA-OLD" not in names  # stale finding dir pruned
    assert {"VA-001", "VA-002"}.issubset(names)  # current findings written
    assert "keepme" in names and (keep_dir / "notes.txt").exists()  # preserved
    assert "README.md" in names  # non-dir preserved
    assert result.finding_count == 2


def test_engagement_export_markdown_tree_rejects_unknown_format(
    client, isolate_settings, tmp_path: Path
) -> None:
    from vigil_cli.engagements import export_engagement_tree

    _seed_export_engagement(client, isolate_settings)
    adapter = _TestClientGetAdapter(client, _EXPORT_ENGAGEMENT_KEY)

    with pytest.raises(SystemExit):
        export_engagement_tree(adapter, tmp_path / "x", fmt="pdf")


def test_runtime_image_build_state_is_content_based(tmp_path):
    """`runtime_image_build_state` reports missing/unknown/current/stale from a
    content digest stamped on the image, NOT file mtimes — so `vigil install`
    rewriting the baked inputs with identical content does not falsely flag a
    rebuild. This is what lets `vigil install` tell users definitively when a
    `vigil runtime build` is actually required."""
    from vigil_cli import runtime
    from vigil_cli.docker import DockerResult

    (tmp_path / "agent" / "docker" / "runtime-full").mkdir(parents=True)
    (tmp_path / "agent" / "docker" / "patches").mkdir(parents=True)
    (tmp_path / "docker").mkdir()
    (tmp_path / "agent" / "docker" / "runtime-full" / "Dockerfile").write_text("FROM kali\n")
    (tmp_path / "agent" / "docker" / "runtime-full" / "install-external-tools.sh").write_text("#!/bin/sh\n")
    (tmp_path / "agent" / "docker" / "patches" / "arjun-batch-resilience.py").write_text("# patch\n")
    (tmp_path / "docker" / "callback_listener.py").write_text("print(1)\n")
    (tmp_path / "docker" / "start-callback.sh").write_text("#!/bin/sh\n")
    digest = runtime.runtime_inputs_digest(tmp_path)

    def make_runner(*, exists=True, label=""):
        def runner(argv, **kwargs):
            if argv[:3] == ["docker", "image", "inspect"] and "-f" in argv:
                return DockerResult(0, label, "")
            if argv[:3] == ["docker", "image", "inspect"]:
                return DockerResult(0 if exists else 1, "", "")
            if argv[:2] == ["docker", "inspect"]:
                return DockerResult(0 if exists else 1, "", "")
            if argv[:3] == ["docker", "images", "-q"]:
                return DockerResult(0, "x" if exists else "", "")
            return DockerResult(1, "", "")
        return runner

    assert runtime.runtime_image_build_state(tmp_path, runner=make_runner(exists=False)) == "missing"
    assert runtime.runtime_image_build_state(tmp_path, runner=make_runner(label="")) == "unknown"
    assert runtime.runtime_image_build_state(tmp_path, runner=make_runner(label=digest)) == "current"
    assert runtime.runtime_image_build_state(tmp_path, runner=make_runner(label="deadbeef")) == "stale"
    # Rewriting a baked input with identical content (an `install` would) must NOT flip to stale.
    (tmp_path / "docker" / "callback_listener.py").write_text("print(1)\n")
    assert runtime.runtime_image_build_state(tmp_path, runner=make_runner(label=digest)) == "current"
    # A real content change DOES flip to stale.
    (tmp_path / "docker" / "callback_listener.py").write_text("print(2)\n")
    assert runtime.runtime_image_build_state(tmp_path, runner=make_runner(label=digest)) == "stale"
    (tmp_path / "docker" / "callback_listener.py").write_text("print(1)\n")
    (tmp_path / "agent" / "docker" / "runtime-full" / "install-external-tools.sh").write_text("#!/bin/sh\n# changed\n")
    assert runtime.runtime_image_build_state(tmp_path, runner=make_runner(label=digest)) == "stale"
    (tmp_path / "agent" / "docker" / "runtime-full" / "install-external-tools.sh").write_text("#!/bin/sh\n")
    (tmp_path / "agent" / "docker" / "patches" / "arjun-batch-resilience.py").write_text("# patch changed\n")
    assert runtime.runtime_image_build_state(tmp_path, runner=make_runner(label=digest)) == "stale"


def test_install_built_image_carries_runtime_inputs_label(tmp_path):
    """A `vigil install` (or `--force-image`) that builds vigil:latest must stamp
    the same com.vigil.runtime-inputs-sha256 label `vigil runtime build` writes.
    Without it an install-built image reports `unknown` on the next upgrade's
    build-state check, so Vigil can never give the stale/current verdict for an
    image it built itself until the operator manually rebuilds."""
    from vigil_cli import runtime
    from vigil_cli.docker import DockerResult
    from vigil_cli.install import InstallOptions, install_from_source

    source_root = tmp_path / "source"
    install_root = tmp_path / "install"
    (source_root / "agent" / "docker" / "runtime-full").mkdir(parents=True)
    (source_root / "orchestrator").mkdir()
    (source_root / "agent" / "docker" / "patches").mkdir(parents=True)
    (source_root / "docker").mkdir(parents=True)
    (source_root / "agent" / "docker" / "runtime-full" / "Dockerfile").write_text("FROM kali\n")
    (source_root / "agent" / "docker" / "runtime-full" / "install-external-tools.sh").write_text("#!/bin/sh\n")
    (source_root / "agent" / "docker" / "patches" / "arjun-batch-resilience.py").write_text("# patch\n")
    (source_root / "docker" / "callback_listener.py").write_text("print(1)\n")
    (source_root / "docker" / "start-callback.sh").write_text("#!/bin/sh\n")

    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return DockerResult(0, "", "")

    result = install_from_source(
        InstallOptions(
            source_root=source_root,
            install_root=install_root,
            force_image=True,
            verify_docker_image=True,
        ),
        runner=runner,
        build_runner=runner,
    )
    assert result.image_built is True
    build = next(c for c in calls if c[:3] == ["docker", "build", "-t"])
    assert "--label" in build, f"install build must stamp the digest label; got {build}"
    label_value = build[build.index("--label") + 1]
    expected = f"com.vigil.runtime-inputs-sha256={runtime.runtime_inputs_digest(source_root)}"
    assert label_value == expected


def test_install_routes_image_build_to_the_unbounded_streaming_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A build must never inherit the caller's bounded metadata runner.

    `docker.run_command` carries a 20s timeout so a wedged daemon degrades to an
    error instead of a hang — correct for image/container inspects, fatal for a
    cold Kali build that legitimately runs for minutes. `docker.py` states the
    invariant ("image BUILDS deliberately route through run_command_streaming")
    and `build_runtime` defaults to it, but `install_from_source` took a single
    `runner` and handed it to the build site, overriding that default and
    killing every first-run bring-up at 20s.
    """
    from vigil_cli import docker as docker_module
    from vigil_cli.docker import DockerResult
    from vigil_cli.install import InstallOptions, install_from_source

    source = tmp_path / "source"
    (source / "agent" / "engagements").mkdir(parents=True)
    (source / "orchestrator" / "backend" / "data").mkdir(parents=True)
    (source / "README.md").write_text("managed source\n", encoding="utf-8")
    install = tmp_path / "install"

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))

    def metadata_runner(argv: list[str], **_kwargs: object) -> DockerResult:
        assert argv[:2] != ["docker", "build"], (
            "the bounded metadata runner reached a build"
        )
        return DockerResult(1, "", "")

    seen: dict[str, object] = {}

    def capture_build(root: Path, **kwargs: object) -> None:
        seen["runner"] = kwargs.get("runner")

    monkeypatch.setattr("vigil_cli.install.build_runtime", capture_build)

    install_from_source(
        InstallOptions(
            source_root=source,
            install_root=install,
            force_image=True,
            verify_docker_image=True,
        ),
        runner=metadata_runner,
    )

    assert seen["runner"] is docker_module.run_command_streaming
    assert seen["runner"] is not metadata_runner


def test_up_routes_both_image_builds_to_the_unbounded_streaming_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`vigil up` is the README-blessed bring-up; both its builds must stream.

    Same invariant as the install path, asserted on the command a first-run
    operator actually types, and covering the mitmproxy build alongside the
    runtime one — `_build_mitmproxy_image` defaults to the streaming runner but
    was being handed the bounded one at the call site.
    """
    from vigil_cli import docker as docker_module
    from vigil_cli import up as up_module
    from vigil_cli.docker import DockerResult

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    install = tmp_path / "install"
    install.mkdir()

    def metadata_runner(argv: list[str], **_kwargs: object) -> DockerResult:
        assert argv[:2] != ["docker", "build"], (
            "the bounded metadata runner reached a build"
        )
        return DockerResult(0, "", "")

    seen: dict[str, object] = {}

    monkeypatch.setattr(up_module, "initialize_workspace", lambda *_a, **_k: None)
    monkeypatch.setattr(up_module, "resolve_application_root", lambda *_a, **_k: repo_root)
    monkeypatch.setattr(up_module, "image_outdated", lambda *_a, **_k: True)
    monkeypatch.setattr(up_module, "_runtime_image_inputs", lambda *_a, **_k: ())
    monkeypatch.setattr(up_module, "mitmproxy_image_inputs", lambda *_a, **_k: ())
    monkeypatch.setattr(up_module, "_start_or_restart_runtime", lambda *_a, **_k: None)
    monkeypatch.setattr(up_module, "_start_mitmproxy_if_needed", lambda *_a, **_k: None)
    monkeypatch.setattr(up_module, "_start_oob_if_needed", lambda *_a, **_k: None)
    monkeypatch.setattr(up_module, "start_orchestrator", lambda *_a, **_k: None)
    monkeypatch.setattr(up_module.docker, "container_running", lambda *_a, **_k: False)
    monkeypatch.setattr(
        up_module, "build_runtime", lambda _root, **kw: seen.__setitem__("runtime", kw.get("runner"))
    )
    monkeypatch.setattr(
        up_module,
        "_build_mitmproxy_image",
        lambda _root, **kw: seen.__setitem__("mitmproxy", kw.get("runner")),
    )

    up_module.run_up(up_module.UpOptions(install_root=install), runner=metadata_runner)

    assert seen["runtime"] is docker_module.run_command_streaming
    assert seen["mitmproxy"] is docker_module.run_command_streaming


def test_up_no_build_still_keeps_the_bounded_runner_out_of_the_proxy_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--no-build` must not reopen the 20s build bound through a side door.

    `run_up` skips its own proxy build under `--no-build`, but still calls
    `_start_mitmproxy_if_needed`. `start_proxy` runs an independent freshness
    check and builds the image itself, so on a host with a missing or stale
    `vigil-proxy` image this is the only path to that build: it must carry the
    unbounded build runner, or a cold build goes back under the 20s ceiling.

    Both runners travel, in their own roles. Collapsing them — handing
    `start_proxy` the streaming runner as its only runner — swapped one defect
    for another: that runner returns empty stdout by design, so the image label
    read back blank and rebuilt a current image every time, and the post-start
    `docker ps` check saw nothing and declared the proxy it had just started
    already dead.
    """
    from vigil_cli import up as up_module

    seen: dict[str, object] = {}

    def metadata_runner(*_args, **_kwargs):
        return None

    def build_runner(*_args, **_kwargs):
        return None

    monkeypatch.setattr(up_module, "resolve_application_root", lambda *_a, **_k: repo_root)
    monkeypatch.setattr(up_module, "initialize_workspace", lambda *_a, **_k: None)
    monkeypatch.setattr(up_module.docker, "container_running", lambda *_a, **_k: False)
    monkeypatch.setattr(up_module, "proxy_image_drift", lambda **_k: False)
    monkeypatch.setattr(up_module, "_start_or_restart_runtime", lambda *_a, **_k: None)
    monkeypatch.setattr(up_module, "start_orchestrator", lambda *_a, **_k: None)
    monkeypatch.setattr(up_module, "_start_oob_if_needed", lambda *_a, **_k: None)
    monkeypatch.setattr(
        up_module,
        "start_proxy",
        lambda _options, **kwargs: seen.update(
            {
                "proxy_runner": kwargs.get("runner"),
                "proxy_build_runner": kwargs.get("build_runner"),
            }
        ),
    )

    up_module.run_up(
        up_module.UpOptions(install_root=tmp_path, no_build=True),
        runner=metadata_runner,
        build_runner=build_runner,
    )

    assert seen["proxy_build_runner"] is build_runner
    # The metadata role is not the build role: every non-build docker call in
    # `start_proxy` reads the command's stdout.
    assert seen["proxy_runner"] is metadata_runner


def test_start_proxy_reads_docker_output_through_the_capturing_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The image label, `docker ps` and the log tail are all stdout reads.

    `run_command_streaming` returns an empty stdout by design. Used as
    `start_proxy`'s only runner it reports a current image as unstamped — the
    rebuild-every-time loop the freshness stamp exists to remove — and makes the
    liveness check after `docker run` see no container at all, so `vigil up`
    dies claiming the proxy it just started exited within seconds.
    """
    from vigil_cli import docker as docker_module
    from vigil_cli import mitmproxy as mitmproxy_module

    engagements_root = tmp_path / "agent" / "engagements"
    engagements_root.mkdir(parents=True)
    seen: dict[str, object] = {}

    def metadata_runner(argv, **_kwargs):
        seen.setdefault("metadata_argv", []).append(argv)  # type: ignore[union-attr]
        return docker_module.DockerResult(0, "", "")

    def build_runner(argv, **_kwargs):
        seen.setdefault("build_argv", []).append(argv)  # type: ignore[union-attr]
        return docker_module.DockerResult(0, "", "")

    monkeypatch.setattr(
        mitmproxy_module.image_freshness, "image_outdated",
        lambda *_a, **kwargs: seen.__setitem__("freshness_runner", kwargs.get("runner")) or False,
    )
    monkeypatch.setattr(
        mitmproxy_module.docker, "container_running",
        lambda *_a, **kwargs: seen.__setitem__("liveness_runner", kwargs.get("runner")) or True,
    )
    monkeypatch.setattr(
        mitmproxy_module.docker, "container_exists", lambda *_a, **_k: False
    )
    monkeypatch.setattr(mitmproxy_module, "_wait_for_port", lambda *_a, **_k: True)

    mitmproxy_module.start_proxy(
        mitmproxy_module.MitmproxyOptions(
            install_root=tmp_path, engagements_root=engagements_root
        ),
        runner=metadata_runner,
        build_runner=build_runner,
    )

    assert seen["freshness_runner"] is metadata_runner
    assert seen["liveness_runner"] is metadata_runner
