"""`vigil engagement start --client claude` runs each offensive track on its default model."""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_cli import config as config_module
from vigil_cli import engagements
from vigil_cli.main import main

CODE_MODEL = "claude-opus-5-5[1m]"
WEB_MODEL = "claude-opus-5[1m]"


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(Path(__file__).resolve().parents[1]))
    for track in ("CODE", "WEB"):
        monkeypatch.delenv(f"VIGIL_CLAUDE_MODEL_{track}", raising=False)
    monkeypatch.setattr(engagements, "_install_client_kind", lambda *_: "both")
    monkeypatch.chdir(root)
    return root


@pytest.fixture
def launched(monkeypatch):
    argv: list[list[str]] = []
    monkeypatch.setattr(engagements.os, "execv", lambda executable, args: argv.append(args))
    return argv


def _engagement(workspace: Path, kind: str) -> Path:
    return engagements.create_engagement(
        engagements.CreateEngagementOptions(
            install_root=workspace, engagement_type=kind, name=f"Acme {kind}",
            target="https://app.acme.example" if kind == "web" else None,
        ),
        contact_backend=False,
    ).path


def _model_flags(argv: list[str]) -> list[str]:
    return [arg for arg in argv[1:] if arg == "--model" or arg.startswith("--model=")]


@pytest.mark.parametrize(("track", "model"), [("code", CODE_MODEL), ("web", WEB_MODEL)])
def test_claude_start_passes_the_track_default_model(workspace, launched, capsys, track, model):
    path = _engagement(workspace, track)
    engagements.start_engagement(workspace, path, "claude", [], track, no_autoprompt=True)
    assert launched[0][1:] == [f"--model={model}"]
    assert f"model: {model} (Vigil {track} default)" in capsys.readouterr().err


@pytest.mark.parametrize("track", ["code", "web"])
def test_operator_message_stays_the_trailing_positional_after_the_model(workspace, launched, track):
    path = _engagement(workspace, track)
    engagements.start_engagement(
        workspace, path, "claude", ["--verbose", "Focus on Acme checkout."], track, no_autoprompt=True,
    )
    model = CODE_MODEL if track == "code" else WEB_MODEL
    assert launched[0][1:] == [f"--model={model}", "--verbose", "Focus on Acme checkout."]


@pytest.mark.parametrize("forwarded", [
    ["--model", "acme-model"],
    ["--model=acme-model"],
    ["--model", "acme-model", "Focus on Acme checkout."],
])
def test_forwarded_model_wins_over_the_track_default(workspace, launched, capsys, forwarded):
    path = _engagement(workspace, "code")
    main([
        "--root", str(workspace), "engagement", "start", path.name, "--client", "claude",
        "--mode", "code", "--no-autoprompt", "--skip-preflight", *forwarded,
    ])
    assert launched[0][1:] == forwarded
    assert "model: acme-model (forwarded --model)" in capsys.readouterr().err


def test_code_autoprompt_keeps_the_default_model_ahead_of_the_setup_message(workspace, launched):
    path = _engagement(workspace, "code")
    engagements.start_engagement(workspace, path, "claude", [], "code")
    assert launched[0][1] == f"--model={CODE_MODEL}"
    assert len(launched[0]) == 3
    assert "source" in launched[0][-1].lower()


def test_resume_start_keeps_the_track_model(workspace, launched):
    path = _engagement(workspace, "code")
    engagements.start_engagement(workspace, path, "claude", ["--resume", "acme-session"], "code")
    assert launched[0][1:] == [f"--model={CODE_MODEL}", "--resume", "acme-session"]


def test_config_override_replaces_the_track_default(workspace, launched, capsys):
    config_module.set_config_value("claude.model.web", "claude-sonnet-5-5")
    path = _engagement(workspace, "web")
    engagements.start_engagement(workspace, path, "claude", [], "web", no_autoprompt=True)
    assert launched[0][1:] == ["--model=claude-sonnet-5-5"]
    assert "model: claude-sonnet-5-5 (config claude.model.web)" in capsys.readouterr().err


def test_environment_override_wins_over_config(workspace, launched, capsys, monkeypatch):
    config_module.set_config_value("claude.model.code", "claude-sonnet-5-5")
    monkeypatch.setenv("VIGIL_CLAUDE_MODEL_CODE", "claude-fable-5-2")
    path = _engagement(workspace, "code")
    engagements.start_engagement(workspace, path, "claude", [], "code", no_autoprompt=True)
    assert launched[0][1:] == ["--model=claude-fable-5-2"]
    assert "model: claude-fable-5-2 (VIGIL_CLAUDE_MODEL_CODE)" in capsys.readouterr().err


def test_default_override_leaves_model_selection_to_claude_code(workspace, launched, capsys):
    config_module.set_config_value("claude.model.code", "default")
    path = _engagement(workspace, "code")
    engagements.start_engagement(workspace, path, "claude", [], "code", no_autoprompt=True)
    assert _model_flags(launched[0]) == []
    assert "model: Claude Code default (config claude.model.code)" in capsys.readouterr().err


def test_other_clients_receive_no_model(workspace, launched, capsys):
    path = _engagement(workspace, "code")
    engagements.start_engagement(workspace, path, "codex", [], "code", no_autoprompt=True)
    assert _model_flags(launched[0]) == []
    assert "model:" not in capsys.readouterr().err


def test_tracks_without_a_vigil_default_pass_no_model():
    for mode in ("blue", "remediation", "android"):
        assert config_module.claude_session_model(mode) == (None, None)
