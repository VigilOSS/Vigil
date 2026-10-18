"""Contracts for creating an engagement and starting a client in it.

Three failure modes are pinned here, all of which produced a session (or a
directory) that could never work:

* ``engagement create`` run against an install root with no canonical operator
  prompt used to write scope/manifest/report and only then refuse, leaving a
  scoped engagement with no launchers that ``vigil install`` could not repair.
* ``engagement start`` rejected client flags (``--model opus``) outright unless
  the operator knew to insert a bare ``--``, which nothing documented.
* ``engagement start`` execed the launcher with no checks at all, so an absent
  client binary surfaced as bash exit 127 and an absent provider key as an
  authentication error minutes into the run.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vigil_cli import engagements  # noqa: E402
from vigil_cli import main as main_module  # noqa: E402
from vigil_cli import preflight as preflight_module  # noqa: E402
from vigil_cli.engagements import CreateEngagementOptions  # noqa: E402
from vigil_cli.main import main  # noqa: E402


@pytest.fixture(autouse=True)
def _synthetic_application(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    application = tmp_path / "install"
    (application / "orchestrator").mkdir(parents=True)
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))


def _install_root(tmp_path: Path, *, with_prompt: bool = True) -> Path:
    install_root = tmp_path / "install"
    agent_root = install_root / "agent"
    agent_root.mkdir(parents=True)
    if with_prompt:
        (agent_root / "AGENTS.md").write_text("# Canonical operator instructions\n")
    return install_root


# ── engagement create: no half-made engagements ──────────────────────────────


@pytest.mark.parametrize("contact_backend", [True, False])
def test_create_reports_progress_before_slow_steps_on_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, contact_backend: bool
) -> None:
    install_root = _install_root(tmp_path)
    (install_root / "agent" / "operator-core-code.md").write_text("# Code overlay\n")
    monkeypatch.setattr(engagements, "_install_client_kind", lambda *_: "none")
    messages = []

    def expect_progress(stage):
        def check(*_args, **_kwargs):
            output = capsys.readouterr()
            assert output.out == ""
            assert stage in output.err
            messages.append(output.err)
            if stage == "orchestrator":
                return engagements.BackendInstallRootStatus.VERIFIED
        return check

    monkeypatch.setattr(engagements, "_write_issues_doc", expect_progress("files"))
    monkeypatch.setattr(engagements, "_write_launchers", expect_progress("client"))
    monkeypatch.setattr(engagements, "_verify_backend_install_root", expect_progress("orchestrator"))
    monkeypatch.setattr(engagements, "_emit_post_create_footer", expect_progress("services"))

    created = engagements.create_engagement(
        CreateEngagementOptions(install_root=install_root, engagement_type="code", name="Acme"),
        contact_backend=contact_backend,
    )

    output = capsys.readouterr()
    assert output.out == ""
    assert "created" in output.err
    assert (created.path / "scope.json").is_file()
    if not contact_backend:
        assert not any(word in "".join(messages) for word in ("snapshot", "orchestrator", "services"))


@pytest.mark.parametrize("engagement_type", ["web", "code", "blue", "remediation"])
def test_create_prints_the_key_and_start_command_uniformly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, engagement_type: str
) -> None:
    import subprocess

    install_root = _install_root(tmp_path)
    (install_root / "agent" / "operator-core-code.md").write_text("# Code overlay\n")
    monkeypatch.setattr(engagements, "_install_client_kind", lambda *_: "none")
    options = {
        "web": CreateEngagementOptions(install_root=install_root, engagement_type="web", target="https://target.example"),
        "code": CreateEngagementOptions(install_root=install_root, engagement_type="code", name="Acme"),
        "blue": CreateEngagementOptions(
            install_root=install_root, engagement_type="blue", customer="Acme", platforms=["m365"]
        ),
    }
    (install_root / "agent" / "AGENTS-blue.md").write_text("# Blue operator\n")
    if engagement_type == "remediation":
        repo = tmp_path / "acme"
        repo.mkdir()
        subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
        # Remediation creation resolves its VCS adapter from the installed assess scripts.
        (install_root / "agent" / "scripts").symlink_to(Path(__file__).resolve().parents[1] / "agent" / "scripts")
        (install_root / "agent" / "operator-core-remediation.md").write_text("# Remediation core\n")
        options["remediation"] = CreateEngagementOptions(
            install_root=install_root, engagement_type="remediation", name="Acme", repos=[str(repo)]
        )

    created = engagements.create_engagement(options[engagement_type], contact_backend=False)

    err = capsys.readouterr().err
    start = (
        f"vigil remediation -k {created.key} start"
        if engagement_type == "remediation"
        else f"vigil engagement start {created.key} --client codex"
    )
    assert err.count(f"[vigil] engagement: {created.key}\n") == 1
    assert err.count(f"[vigil] start: {start}") == 1


def test_create_refuses_before_any_side_effect_without_an_installed_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_root = _install_root(tmp_path, with_prompt=False)

    with pytest.raises(SystemExit) as excinfo:
        engagements.create_engagement(
            CreateEngagementOptions(
                install_root=install_root,
                engagement_type="web",
                target="https://target.example",
            )
        )

    message = str(excinfo.value)
    assert "canonical operator prompt not found" in message
    assert f"run `vigil install {install_root}` first" in message
    # A string SystemExit code is a non-zero exit, and nothing was written.
    assert isinstance(excinfo.value.code, str)
    assert not (install_root / "agent" / "engagements").exists()


def test_create_refuses_for_blue_without_the_installed_blue_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_root = _install_root(tmp_path)  # red AGENTS.md only

    with pytest.raises(SystemExit) as excinfo:
        engagements.create_engagement(
            CreateEngagementOptions(
                install_root=install_root,
                engagement_type="blue",
                customer="AcmeCorp",
                platforms=["m365"],
            )
        )

    assert "AGENTS-blue.md" in str(excinfo.value)
    assert not (install_root / "agent" / "engagements").exists()


def test_create_rolls_the_directory_back_when_a_later_writer_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    install_root = _install_root(tmp_path)
    monkeypatch.setattr(engagements, "_install_client_kind", lambda *a, **k: "none")

    def explode(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(engagements, "_write_launchers", explode)

    with pytest.raises(OSError, match="disk full"):
        engagements.create_engagement(
            CreateEngagementOptions(
                install_root=install_root,
                engagement_type="web",
                target="https://target.example",
            )
        )

    assert list(engagements.engagements_root(install_root).iterdir()) == []
    assert "Engagement created." not in capsys.readouterr().err


def test_create_keeps_a_fully_written_engagement_when_backend_sync_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rollback covers the writers only.

    ``_verify_backend_install_root`` runs against a durable engagement and its own
    message tells the operator how to recover; deleting their engagement instead
    would be the worse bug.
    """
    install_root = _install_root(tmp_path)
    monkeypatch.setattr(engagements, "_install_client_kind", lambda *a, **k: "none")
    monkeypatch.setattr(engagements, "_emit_bootstrap_scope_summary", lambda *a, **k: None)

    def refuse(*_args: object, **_kwargs: object) -> engagements.BackendInstallRootStatus:
        raise SystemExit("the running orchestrator does not know about it")

    monkeypatch.setattr(engagements, "_verify_backend_install_root", refuse)

    with pytest.raises(SystemExit):
        engagements.create_engagement(
            CreateEngagementOptions(
                install_root=install_root,
                engagement_type="web",
                target="https://target.example",
            )
        )

    created = list(engagements.engagements_root(install_root).iterdir())
    assert len(created) == 1
    assert (created[0] / "scope.json").is_file()


# ── engagement start: client-flag passthrough ────────────────────────────────


@pytest.fixture
def started(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Run `vigil engagement start` up to (not into) the launcher exec."""
    install_root = _install_root(tmp_path)
    engagement_dir = install_root / "agent" / "engagements" / "2026-01-01-0000-target"
    engagement_dir.mkdir(parents=True)
    (engagement_dir / "scope.json").write_text('{"status":"active"}\n')
    (engagement_dir / "start_claude.sh").write_text("#!/usr/bin/env bash\n")
    (engagement_dir / "start_goose.sh").write_text("#!/usr/bin/env bash\n")
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setattr(main_module, "_preflight_engagement_start", lambda *a, **k: None)

    calls: dict[str, object] = {"install_root": install_root, "dir": engagement_dir}
    monkeypatch.setattr(
        main_module,
        "start_engagement",
        lambda root, path, client, client_args, *, no_autoprompt=False: calls.update(
            client=client, client_args=list(client_args)
        ),
    )
    return calls


def test_start_forwards_unknown_client_flags_without_a_bare_separator(
    started: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    main(
        [
            "--root",
            str(started["install_root"]),
            "engagement",
            "start",
            "2026-01-01-0000-target",
            "--client",
            "claude",
            "--model",
            "opus",
        ]
    )

    assert started["client_args"] == ["--model", "opus"]
    assert "forwarding to the client: --model opus" in capsys.readouterr().err


def test_start_accepts_abbreviated_root_before_client_passthrough(
    started: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    main(
        [
            "--ro",
            str(started["install_root"]),
            "engagement",
            "start",
            "2026-01-01-0000-target",
            "--client",
            "claude",
            "--model",
            "opus",
        ]
    )

    assert started["client_args"] == ["--model", "opus"]
    assert "forwarding to the client: --model opus" in capsys.readouterr().err


@pytest.mark.parametrize("root_flag", ["--root", "--ro"])
def test_start_owns_top_level_root_even_when_written_after_the_subcommand(
    started: dict[str, object], capsys: pytest.CaptureFixture[str], root_flag: str
) -> None:
    main(
        [
            "engagement",
            "start",
            "2026-01-01-0000-target",
            "--client",
            "claude",
            root_flag,
            str(started["install_root"]),
            "--model",
            "opus",
        ]
    )

    assert started["client_args"] == ["--model", "opus"]
    assert "--root" not in capsys.readouterr().err


def test_start_key_detection_matches_unambiguous_argparse_option_abbreviations(
    started: dict[str, object]
) -> None:
    main(
        [
            "--root",
            str(started["install_root"]),
            "engagement",
            "start",
            "--cli",
            "claude",
            "2026-01-01-0000-target",
            "--skip-preflight",
        ]
    )

    assert started["dir"].name == "2026-01-01-0000-target"
    assert started["client_args"] == []


def test_start_forwards_flags_and_message_in_argv_order(
    started: dict[str, object],
) -> None:
    main(
        [
            "--root",
            str(started["install_root"]),
            "engagement",
            "start",
            "2026-01-01-0000-target",
            "--client",
            "goose",
            "--model",
            "opus",
            "operator task",
        ]
    )

    assert started["client_args"] == ["--model", "opus", "operator task"]


def test_start_still_accepts_the_explicit_double_dash_separator(
    started: dict[str, object],
) -> None:
    main(
        [
            "--root",
            str(started["install_root"]),
            "engagement",
            "start",
            "2026-01-01-0000-target",
            "--client",
            "claude",
            "--",
            "--model",
            "opus",
        ]
    )

    assert started["client_args"] == ["--model", "opus"]


def test_start_without_key_does_not_consume_a_client_flag_value_as_the_key(
    started: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(started["dir"])

    main(
        [
            "--root",
            str(started["install_root"]),
            "engagement",
            "start",
            "--client",
            "claude",
            "--model",
            "opus",
            "operator task",
        ]
    )

    assert started["client_args"] == ["--model", "opus", "operator task"]


def test_start_without_key_forwards_everything_after_double_dash(
    started: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(started["dir"])

    main(
        [
            "--root",
            str(started["install_root"]),
            "engagement",
            "start",
            "--client",
            "claude",
            "--",
            "do the thing",
        ]
    )

    assert started["client_args"] == ["do the thing"]


def test_start_refuses_a_near_miss_of_its_own_flag_instead_of_forwarding_it(
    started: dict[str, object],
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "--root",
                str(started["install_root"]),
                "engagement",
                "start",
                "2026-01-01-0000-target",
                "--client",
                "claude",
                "--thinkng",
                "high",
            ]
        )

    message = str(excinfo.value)
    assert "--thinkng" in message
    assert "did you mean --thinking?" in message
    assert "client_args" not in started


@pytest.mark.parametrize("client", ["opencode", "claude"])
def test_start_warns_that_thinking_is_deprecated_and_still_applies_it(
    started: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    client: str,
) -> None:
    calls: dict[str, object] = {}
    monkeypatch.setattr(
        main_module,
        "start_engagement",
        lambda root, path, client, client_args, mode=None, *, thinking=None, no_autoprompt=False: calls.update(
            client=client, thinking=thinking
        ),
    )
    main(
        [
            "--root",
            str(started["install_root"]),
            "engagement",
            "start",
            "2026-01-01-0000-target",
            "--client",
            client,
            "--thinking",
            "high",
        ]
    )

    assert "--thinking is deprecated" in capsys.readouterr().err
    assert calls["client"] == client
    if client == "opencode":
        assert calls["thinking"] == "high"


def test_start_forwards_a_client_flag_that_merely_resembles_a_vigil_flag(
    started: dict[str, object],
) -> None:
    """`--thinking-budget` is a real client flag, not a typo of `--thinking`."""
    main(
        [
            "--root",
            str(started["install_root"]),
            "engagement",
            "start",
            "2026-01-01-0000-target",
            "--client",
            "claude",
            "--thinking-budget",
            "8000",
        ]
    )

    assert started["client_args"] == ["--thinking-budget", "8000"]


# ── engagement start: preflight ──────────────────────────────────────────────


@pytest.fixture
def preflight_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An engagement whose every preflight check passes; tests break one each."""
    install_root = _install_root(tmp_path)
    engagement_dir = install_root / "agent" / "engagements" / "2026-01-01-0000-target"
    engagement_dir.mkdir(parents=True)
    (engagement_dir / ".orchestrator.env").write_text("DEEPSEEK_API_KEY=test-key\n")
    monkeypatch.setattr(preflight_module.shutil, "which", lambda _name: "/usr/local/bin/client")
    monkeypatch.setattr(preflight_module, "orchestrator_status", lambda _root: "running")
    monkeypatch.setattr(engagements, "_verify_backend_install_root", lambda *_: engagements.BackendInstallRootStatus.VERIFIED)
    from vigil_cli import orchestrator
    monkeypatch.setattr(orchestrator, "start_orchestrator", lambda *_: None)
    monkeypatch.setattr(preflight_module, "runtime_status", lambda: "running")
    monkeypatch.setattr(preflight_module, "_warn_if_install_stale", lambda _root: None)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    return engagement_dir


def test_preflight_passes_quietly_when_everything_is_ready(
    preflight_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main_module._preflight_engagement_start(
        preflight_env.parents[2], preflight_env, "goose"
    )

    assert capsys.readouterr().err == ""


def test_preflight_hard_fails_when_the_client_binary_is_absent(
    preflight_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(preflight_module.shutil, "which", lambda _name: None)

    with pytest.raises(SystemExit) as excinfo:
        main_module._preflight_engagement_start(
            preflight_env.parents[2], preflight_env, "claude"
        )

    message = str(excinfo.value)
    assert "claude CLI not found on PATH" in message
    assert "--skip-preflight" in message


def test_preflight_hard_fails_when_the_provider_key_is_absent(
    preflight_env: Path,
) -> None:
    (preflight_env / ".orchestrator.env").write_text("")

    with pytest.raises(SystemExit) as excinfo:
        main_module._preflight_engagement_start(
            preflight_env.parents[2], preflight_env, "goose"
        )

    assert "goose needs DEEPSEEK_API_KEY" in str(excinfo.value)


def test_preflight_uses_only_the_last_assignment_for_a_key_in_each_file(
    preflight_env: Path,
) -> None:
    (preflight_env / ".orchestrator.env").write_text(
        "DEEPSEEK_API_KEY=stale-key\nDEEPSEEK_API_KEY=\n"
    )

    with pytest.raises(SystemExit, match="goose needs DEEPSEEK_API_KEY"):
        main_module._preflight_engagement_start(
            preflight_env.parents[2], preflight_env, "goose"
        )


def test_preflight_accepts_deepseek_key_for_opencode_from_the_install_env_file(
    preflight_env: Path,
) -> None:
    install_root = preflight_env.parents[2]
    (preflight_env / ".orchestrator.env").write_text("")
    (install_root / ".env").write_text("DEEPSEEK_API_KEY=test-deepseek\n")

    main_module._preflight_engagement_start(install_root, preflight_env, "opencode")


def test_preflight_rejects_openrouter_only_configuration_for_opencode(
    preflight_env: Path,
) -> None:
    install_root = preflight_env.parents[2]
    (preflight_env / ".orchestrator.env").write_text("")
    (install_root / ".env").write_text("OPENROUTER_API_KEY=test-openrouter\n")

    with pytest.raises(SystemExit, match="opencode needs DEEPSEEK_API_KEY"):
        main_module._preflight_engagement_start(install_root, preflight_env, "opencode")


def test_preflight_rejects_ambient_openai_key_for_goose_from_the_install_env_file(
    preflight_env: Path,
) -> None:
    install_root = preflight_env.parents[2]
    (preflight_env / ".orchestrator.env").write_text("")
    (install_root / ".env").write_text("OPENAI_API_KEY=test-openai\n")

    with pytest.raises(SystemExit, match="goose needs DEEPSEEK_API_KEY"):
        main_module._preflight_engagement_start(install_root, preflight_env, "goose")


def test_preflight_rejects_ambient_openai_key_for_goose_from_the_process_environment(
    preflight_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (preflight_env / ".orchestrator.env").write_text("")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai")

    with pytest.raises(SystemExit, match="goose needs DEEPSEEK_API_KEY"):
        main_module._preflight_engagement_start(
            preflight_env.parents[2], preflight_env, "goose"
        )


def test_preflight_does_not_require_a_provider_key_for_vendor_authed_clients(
    preflight_env: Path,
) -> None:
    (preflight_env / ".orchestrator.env").write_text("")

    for client in ("claude", "codex", "kimi"):
        main_module._preflight_engagement_start(
            preflight_env.parents[2], preflight_env, client
        )


def test_preflight_recovers_backend_and_warns_when_execution_is_down(
    preflight_env: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(preflight_module, "orchestrator_status", lambda _root: "stopped")
    monkeypatch.setattr(preflight_module, "runtime_status", lambda: "stopped")

    main_module._preflight_engagement_start(
        preflight_env.parents[2], preflight_env, "goose"
    )

    stderr = capsys.readouterr().err
    assert "Starting the engagement backend" in stderr
    assert "WARN: Kali runtime container is stopped" in stderr


def test_start_skips_the_preflight_on_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_root = _install_root(tmp_path)
    engagement_dir = install_root / "agent" / "engagements" / "2026-01-01-0000-target"
    engagement_dir.mkdir(parents=True)
    (engagement_dir / "scope.json").write_text('{"status":"active"}\n')
    (engagement_dir / "start_goose.sh").write_text("#!/usr/bin/env bash\n")
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setattr(
        main_module,
        "_preflight_engagement_start",
        lambda *a, **k: pytest.fail("--skip-preflight must skip the preflight"),
    )
    started: dict[str, object] = {}
    monkeypatch.setattr(
        main_module,
        "start_engagement",
        lambda root, path, client, client_args, *, no_autoprompt=False: started.update(client=client),
    )

    main(
        [
            "--root",
            str(install_root),
            "engagement",
            "start",
            "2026-01-01-0000-target",
            "--client",
            "goose",
            "--skip-preflight",
        ]
    )

    assert started == {"client": "goose"}


def test_start_runs_the_preflight_before_touching_the_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_root = _install_root(tmp_path)
    engagement_dir = install_root / "agent" / "engagements" / "2026-01-01-0000-target"
    engagement_dir.mkdir(parents=True)
    (engagement_dir / "scope.json").write_text('{"status":"active"}\n')
    (engagement_dir / "start_goose.sh").write_text("#!/usr/bin/env bash\n")
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setattr(preflight_module.shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        main_module,
        "start_engagement",
        lambda *a, **k: pytest.fail("a doomed session must never be started"),
    )

    with pytest.raises(SystemExit, match="goose CLI not found on PATH"):
        main(
            [
                "--root",
                str(install_root),
                "engagement",
                "start",
                "2026-01-01-0000-target",
                "--client",
                "goose",
            ]
        )


def test_start_pi_forwards_provider_model_and_thinking(started: dict[str, object]) -> None:
    main([
        "--root", str(started["install_root"]), "engagement", "start",
        "2026-01-01-0000-target", "--client", "pi", "--",
        "--provider", "anthropic", "--model", "test-model", "--thinking", "medium",
        "operator task",
    ])
    assert started["client"] == "pi"
    assert started["client_args"] == [
        "--provider", "anthropic", "--model", "test-model", "--thinking", "medium",
        "operator task",
    ]
