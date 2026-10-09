"""The start preflight is shared by both launch paths, red and blue.

``vigil engagement start`` gained a preflight (client binary, provider key,
orchestrator, runtime container, install freshness) but ``vigil blue engage
--start`` execed the same launcher with none of it — so the operator most
likely to be under time pressure, an incident responder chaining
``vigil blue engage --customer … --start codex``, was the one who discovered a
missing client binary as bash exit 127 minutes into a live incident.

Pinned here: the preflight lives in one module both entrypoints import
(``vigil_cli.preflight``); the blue path runs it, honours ``--skip-preflight``
just like the red path, and refuses BEFORE printing the ``eng=$(vigil blue
engage …)`` stdout path so a refusal never leaves a half-printed contract
behind.

``vigil engagement start``'s own preflight contracts live in
``test_engagement_start_contracts.py``; this file does not restate them.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vigil_cli import blue as blue_module  # noqa: E402
from vigil_cli import main as main_module  # noqa: E402
from vigil_cli import preflight as preflight_module  # noqa: E402
from vigil_cli.engagements import CreatedEngagement  # noqa: E402
from vigil_cli.main import main  # noqa: E402


@pytest.fixture
def blue_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """A blue engagement whose every preflight check passes.

    ``create_engagement`` is stubbed: this file is about the preflight and the
    stdout contract around it, not about engagement scaffolding. Individual
    tests break one check each.
    """
    install_root = tmp_path / "install"
    tenant_dir = install_root / "agent" / "references" / "tenants"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "acme-workspace.md").write_text("# acme\n")
    engagement_dir = install_root / "agent" / "engagements" / "2026-01-01-0000-acme"
    engagement_dir.mkdir(parents=True)
    (engagement_dir / ".orchestrator.env").write_text("DEEPSEEK_API_KEY=test-key\n")

    created = CreatedEngagement(key=engagement_dir.name, path=engagement_dir)
    calls: dict[str, object] = {
        "install_root": install_root,
        "dir": engagement_dir,
        "started": None,
    }
    monkeypatch.setattr(blue_module, "create_engagement", lambda _options: created)
    monkeypatch.setattr(
        blue_module,
        "start_engagement",
        lambda root, path, client, client_args: calls.update(started=client),
    )
    monkeypatch.setattr(
        blue_module, "write_opencode_reasoning_config", lambda *a, **k: None
    )
    monkeypatch.setattr(preflight_module.shutil, "which", lambda _name: "/usr/bin/client")
    monkeypatch.setattr(preflight_module, "orchestrator_status", lambda _root: "running")
    monkeypatch.setattr(preflight_module, "runtime_status", lambda: "running")
    monkeypatch.setattr(preflight_module, "_warn_if_install_stale", lambda _root: None)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    return calls


def _blue_engage(install_root: Path, *extra: str) -> None:
    main(
        [
            "--root",
            str(install_root),
            "blue",
            "engage",
            "--customer",
            "acme",
            "--platform",
            "gws",
            *extra,
        ]
    )


def test_blue_engage_can_start_kimi(blue_env: dict[str, object]) -> None:
    _blue_engage(blue_env["install_root"], "--start", "kimi")  # type: ignore[arg-type]

    assert blue_env["started"] == "kimi"


@pytest.fixture
def red_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """``vigil engagement start`` against the same preflight module."""
    install_root = tmp_path / "install"
    engagement_dir = install_root / "agent" / "engagements" / "2026-01-01-0000-target"
    engagement_dir.mkdir(parents=True)
    (engagement_dir / "scope.json").write_text('{"status":"active"}\n')
    (engagement_dir / ".orchestrator.env").write_text("DEEPSEEK_API_KEY=test-key\n")
    calls: dict[str, object] = {"install_root": install_root, "started": None}
    monkeypatch.setattr(
        main_module,
        "start_engagement",
        lambda root, path, client, client_args: calls.update(started=client),
    )
    monkeypatch.setattr(preflight_module.shutil, "which", lambda _name: "/usr/bin/client")
    monkeypatch.setattr(preflight_module, "orchestrator_status", lambda _root: "running")
    monkeypatch.setattr(preflight_module, "runtime_status", lambda: "running")
    monkeypatch.setattr(preflight_module, "_warn_if_install_stale", lambda _root: None)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    return calls


def _red_start(install_root: Path, client: str, *extra: str) -> None:
    main(
        [
            "--root",
            str(install_root),
            "engagement",
            "start",
            "2026-01-01-0000-target",
            "--client",
            client,
            *extra,
        ]
    )


# ── the shared module is the single home ─────────────────────────────────────


def test_main_and_blue_share_one_preflight_implementation() -> None:
    assert main_module._preflight_engagement_start is (
        preflight_module._preflight_engagement_start
    )
    assert blue_module._preflight_engagement_start is (
        preflight_module._preflight_engagement_start
    )


# ── hard refusals reach both paths ───────────────────────────────────────────


def test_blue_start_refuses_when_the_client_binary_is_absent(
    blue_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(preflight_module.shutil, "which", lambda _name: None)

    with pytest.raises(SystemExit) as excinfo:
        _blue_engage(blue_env["install_root"], "--start", "codex")  # type: ignore[arg-type]

    assert "codex CLI not found on PATH" in str(excinfo.value)
    assert blue_env["started"] is None


def test_red_start_refuses_when_the_client_binary_is_absent(
    red_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(preflight_module.shutil, "which", lambda _name: None)

    with pytest.raises(SystemExit) as excinfo:
        _red_start(red_env["install_root"], "codex")  # type: ignore[arg-type]

    assert "codex CLI not found on PATH" in str(excinfo.value)
    assert red_env["started"] is None


def test_blue_start_refuses_when_the_provider_key_is_absent(
    blue_env: dict[str, object]
) -> None:
    install_root = blue_env["install_root"]
    (blue_env["dir"] / ".orchestrator.env").write_text("")  # type: ignore[operator]

    with pytest.raises(SystemExit) as excinfo:
        _blue_engage(install_root, "--start", "goose")  # type: ignore[arg-type]

    assert "goose needs DEEPSEEK_API_KEY" in str(excinfo.value)
    assert blue_env["started"] is None


def test_red_start_refuses_when_the_provider_key_is_absent(
    red_env: dict[str, object]
) -> None:
    install_root = red_env["install_root"]
    engagement_dir = install_root / "agent" / "engagements" / "2026-01-01-0000-target"  # type: ignore[operator]
    (engagement_dir / ".orchestrator.env").write_text("")

    with pytest.raises(SystemExit) as excinfo:
        _red_start(install_root, "goose")  # type: ignore[arg-type]

    assert "goose needs DEEPSEEK_API_KEY" in str(excinfo.value)
    assert red_env["started"] is None


def test_blue_goose_start_rejects_ambient_openai_key_from_the_process_environment(
    blue_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    install_root = blue_env["install_root"]
    (blue_env["dir"] / ".orchestrator.env").write_text("")  # type: ignore[operator]
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai")

    with pytest.raises(SystemExit, match="goose needs DEEPSEEK_API_KEY"):
        _blue_engage(install_root, "--start", "goose")  # type: ignore[arg-type]

    assert blue_env["started"] is None


def test_red_goose_start_rejects_ambient_openai_key_from_the_process_environment(
    red_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    install_root = red_env["install_root"]
    engagement_dir = install_root / "agent" / "engagements" / "2026-01-01-0000-target"  # type: ignore[operator]
    (engagement_dir / ".orchestrator.env").write_text("")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai")

    with pytest.raises(SystemExit, match="goose needs DEEPSEEK_API_KEY"):
        _red_start(install_root, "goose")  # type: ignore[arg-type]

    assert red_env["started"] is None


def test_blue_opencode_start_refuses_without_the_deepseek_key(
    blue_env: dict[str, object]
) -> None:
    install_root = blue_env["install_root"]
    (blue_env["dir"] / ".orchestrator.env").write_text("")  # type: ignore[operator]

    with pytest.raises(SystemExit, match="opencode needs DEEPSEEK_API_KEY"):
        _blue_engage(install_root, "--start", "opencode")  # type: ignore[arg-type]

    assert blue_env["started"] is None


def test_red_opencode_start_refuses_without_the_deepseek_key(
    red_env: dict[str, object]
) -> None:
    install_root = red_env["install_root"]
    engagement_dir = install_root / "agent" / "engagements" / "2026-01-01-0000-target"  # type: ignore[operator]
    (engagement_dir / ".orchestrator.env").write_text("")

    with pytest.raises(SystemExit, match="opencode needs DEEPSEEK_API_KEY"):
        _red_start(install_root, "opencode")  # type: ignore[arg-type]

    assert red_env["started"] is None


def test_preflight_refuses_cleanly_when_a_provider_env_file_is_not_utf8(
    red_env: dict[str, object]
) -> None:
    install_root = red_env["install_root"]
    engagement_dir = (
        install_root / "agent" / "engagements" / "2026-01-01-0000-target"
    )
    env_file = engagement_dir / ".orchestrator.env"
    env_file.write_bytes(b"DEEPSEEK_API_KEY=\xff\n")

    with pytest.raises(SystemExit) as excinfo:
        _red_start(install_root, "goose")

    message = str(excinfo.value)
    assert "provider-key preflight cannot read" in message
    assert str(env_file) in message
    assert "UTF-8" in message
    assert red_env["started"] is None


def test_the_refusal_names_an_escape_hatch_both_commands_accept(
    blue_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal text is command-agnostic, so both launchers must honour it."""
    monkeypatch.setattr(preflight_module.shutil, "which", lambda _name: None)

    with pytest.raises(SystemExit) as excinfo:
        _blue_engage(blue_env["install_root"], "--start", "codex")  # type: ignore[arg-type]

    assert "Pass --skip-preflight to launch anyway." in str(excinfo.value)

    _blue_engage(blue_env["install_root"], "--start", "codex", "--skip-preflight")  # type: ignore[arg-type]
    assert blue_env["started"] == "codex"


# ── soft warnings warn on both paths and block neither ───────────────────────


def test_blue_start_warns_but_proceeds_when_the_local_stack_is_down(
    blue_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(preflight_module, "orchestrator_status", lambda _root: "stopped")
    monkeypatch.setattr(preflight_module, "runtime_status", lambda: "stopped")
    monkeypatch.setattr(
        preflight_module,
        "_warn_if_install_stale",
        lambda _root: print("[vigil] WARN: install root is stale", file=sys.stderr),
    )

    _blue_engage(blue_env["install_root"], "--start", "goose")  # type: ignore[arg-type]

    captured = capsys.readouterr()
    assert "WARN: orchestrator is not running" in captured.err
    assert "WARN: Kali runtime container is stopped" in captured.err
    assert "WARN: install root is stale" in captured.err
    assert blue_env["started"] == "goose"
    # Every warning is stderr; stdout stays the bare engagement path.
    assert captured.out == f"{blue_env['dir']}\n"


def test_red_start_warns_but_proceeds_when_the_local_stack_is_down(
    red_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(preflight_module, "orchestrator_status", lambda _root: "stopped")
    monkeypatch.setattr(preflight_module, "runtime_status", lambda: "stopped")
    monkeypatch.setattr(
        preflight_module,
        "_warn_if_install_stale",
        lambda _root: print("[vigil] WARN: install root is stale", file=sys.stderr),
    )

    _red_start(red_env["install_root"], "goose")  # type: ignore[arg-type]

    stderr = capsys.readouterr().err
    assert "WARN: orchestrator is not running" in stderr
    assert "WARN: Kali runtime container is stopped" in stderr
    assert "WARN: install root is stale" in stderr
    assert red_env["started"] == "goose"


def test_red_start_warns_when_ripgrep_is_absent(
    red_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Ripgrep is load-bearing for the code track and was never checked anywhere.

    `agent/shared-constraints-code.md` ranks `rg` second only to the ctags index
    and uses the ripgrep-only `--type` flag. Claude and OpenCode bundle their own
    Grep tool, but the Codex and Goose hunters have shell only: with no ripgrep
    on the host every search is exit 127, and the specialist reads that as "no
    results" rather than "tool missing". That is the dangerous failure shape for
    a coverage tool — it reports clean coverage of code it never searched.

    Advisory, not a refusal: a web engagement never reaches a code search, and a
    Claude/OpenCode hunter has its own tool.
    """
    monkeypatch.setattr(
        preflight_module.shutil,
        "which",
        lambda name: None if name == "rg" else "/usr/bin/client",
    )

    _red_start(red_env["install_root"], "goose")  # type: ignore[arg-type]

    stderr = capsys.readouterr().err
    assert "WARN: ripgrep (`rg`) not found on PATH" in stderr
    assert "codex" in stderr.lower() and "goose" in stderr.lower()
    assert "no results" in stderr
    assert red_env["started"] == "goose"


def test_blue_start_warns_when_ripgrep_is_absent(
    blue_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Same module, so the blue launcher must carry it too."""
    monkeypatch.setattr(
        preflight_module.shutil,
        "which",
        lambda name: None if name == "rg" else "/usr/bin/client",
    )

    _blue_engage(blue_env["install_root"], "--start", "codex")  # type: ignore[arg-type]

    captured = capsys.readouterr()
    assert "WARN: ripgrep (`rg`) not found on PATH" in captured.err
    assert blue_env["started"] == "codex"
    # Warnings are stderr only; stdout stays the bare engagement path.
    assert captured.out == f"{blue_env['dir']}\n"


def test_a_present_ripgrep_produces_no_warning(
    red_env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    """The check must stay silent on the hosts that have it."""
    _red_start(red_env["install_root"], "goose")  # type: ignore[arg-type]

    assert "ripgrep" not in capsys.readouterr().err


# ── --skip-preflight bypasses it on both paths ───────────────────────────────


def test_blue_skip_preflight_bypasses_every_check(
    blue_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        preflight_module,
        "_preflight_engagement_start",
        lambda *a, **k: pytest.fail("--skip-preflight must skip the preflight"),
    )
    monkeypatch.setattr(
        blue_module,
        "_preflight_engagement_start",
        lambda *a, **k: pytest.fail("--skip-preflight must skip the preflight"),
    )

    _blue_engage(blue_env["install_root"], "--start", "codex", "--skip-preflight")  # type: ignore[arg-type]

    assert blue_env["started"] == "codex"


def test_red_skip_preflight_bypasses_every_check(
    red_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        main_module,
        "_preflight_engagement_start",
        lambda *a, **k: pytest.fail("--skip-preflight must skip the preflight"),
    )

    _red_start(red_env["install_root"], "codex", "--skip-preflight")  # type: ignore[arg-type]

    assert red_env["started"] == "codex"


# ── the blue stdout contract survives both outcomes ──────────────────────────


def test_blue_start_prints_only_the_engagement_path_on_stdout(
    blue_env: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    _blue_engage(blue_env["install_root"], "--start", "codex")  # type: ignore[arg-type]

    captured = capsys.readouterr()
    assert captured.out == f"{blue_env['dir']}\n"
    assert "launching operator session (codex)" in captured.err
    assert blue_env["started"] == "codex"


def test_blue_preflight_refusal_prints_nothing_on_stdout(
    blue_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A refusal must not leave a bare path behind for `eng=$(…)` to capture.

    The engagement is already created at this point, so the operator still
    needs its key — that goes to stderr, where the launch hints already live.
    """
    monkeypatch.setattr(preflight_module.shutil, "which", lambda _name: None)

    with pytest.raises(SystemExit):
        _blue_engage(blue_env["install_root"], "--start", "codex")  # type: ignore[arg-type]

    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(blue_env["dir"]) not in captured.out
    assert "2026-01-01-0000-acme" in captured.err
    assert "launching operator session" not in captured.err


def test_provider_key_rejects_quoted_empty_and_unwraps_quoted_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dotenv quoting must be normalized before deciding a key exists.

    `DEEPSEEK_API_KEY=""` is a conventional placeholder. Treating the two quote
    characters as a credential lets the launch preflight pass, and the launcher
    then exports the quotes rather than a key — so the operator learns at the
    first provider request instead of before the session starts.
    """
    from vigil_cli.preflight import _resolve_provider_key

    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    install_root = tmp_path / "install"
    engagement = tmp_path / "eng"
    install_root.mkdir()
    engagement.mkdir()

    (install_root / ".env").write_text('DEEPSEEK_API_KEY=""\n', encoding="utf-8")
    assert _resolve_provider_key(install_root, engagement, "DEEPSEEK_API_KEY") is None

    (install_root / ".env").write_text("DEEPSEEK_API_KEY='   '\n", encoding="utf-8")
    assert _resolve_provider_key(install_root, engagement, "DEEPSEEK_API_KEY") is None

    (install_root / ".env").write_text('DEEPSEEK_API_KEY="sk-real"\n', encoding="utf-8")
    assert _resolve_provider_key(install_root, engagement, "DEEPSEEK_API_KEY") == "sk-real"

    (install_root / ".env").write_text("DEEPSEEK_API_KEY=sk-bare\n", encoding="utf-8")
    assert _resolve_provider_key(install_root, engagement, "DEEPSEEK_API_KEY") == "sk-bare"

    # An inherited value gets the same treatment, and an empty-equivalent one must
    # fall through to the files rather than shadowing a usable key.
    monkeypatch.setenv("DEEPSEEK_API_KEY", '"   "')
    assert _resolve_provider_key(install_root, engagement, "DEEPSEEK_API_KEY") == "sk-bare"

    monkeypatch.setenv("DEEPSEEK_API_KEY", '"sk-inherited"')
    assert _resolve_provider_key(install_root, engagement, "DEEPSEEK_API_KEY") == "sk-inherited"


def test_the_assess_passthrough_does_not_warn_about_a_stale_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """One warning per engagement, not one per `vigil assess` call.

    The warning used to fire on the assess exec passthrough, which an operator
    and its specialists run for every finding, fetch, and queue closeout — so a
    single lagging install root produced hundreds of identical stderr lines in
    one engagement. Repetition on the channel real failures use is how a warning
    stops being read. `vigil engagement start` is the one place it is both
    actionable and read, and it keeps it.
    """
    import os

    from vigil_cli import main as main_module

    install_root = tmp_path / "install"
    (install_root / "agent" / "scripts").mkdir(parents=True)
    assess = install_root / "agent" / "scripts" / "assess.py"
    assess.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    monkeypatch.setattr(main_module, "resolve_install_root", lambda _value: install_root)
    monkeypatch.setattr(
        preflight_module,
        "install_staleness",
        lambda _root: {
            "state": "stale",
            "reason": "source_content_changed",
            "installed_sha": "a" * 40,
            "current_source_sha": "b" * 40,
        },
    )
    execed: dict[str, object] = {}
    monkeypatch.setattr(
        os, "execvpe", lambda path, argv, env: execed.update(path=path, argv=argv)
    )

    main_module._exec_assess_passthrough(["vigil", "assess", "finding", "list"], 1)

    captured = capsys.readouterr()
    assert execed["path"] == str(assess), "the passthrough must still exec"
    assert captured.err == ""
    assert captured.out == ""
