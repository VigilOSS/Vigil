"""An OpenCode start through the engagement launcher applies a ``#variant``.

Blue (and every other mode that runs ``start_opencode.sh``) forwards the
operator's flags to the OpenCode TUI, which rejects a model id carrying
``#variant``. The launch splits the variant off exactly as the web/code
assessment start does and saves it as OpenCode's choice for that model.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_cli import engagements


@pytest.fixture
def blue_engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "agent" / "engagements" / "acme-blue"
    path.mkdir(parents=True)
    (path / "scope.json").write_text(
        json.dumps({"engagement_type": "blue", "current_phase": "triage"}), encoding="utf-8"
    )
    (path / "start_opencode.sh").write_text("#!/bin/sh\n")
    application = tmp_path / "application"
    (application / "orchestrator").mkdir(parents=True)
    (application / "agent").mkdir()
    (application / "agent" / "AGENTS-blue.md").write_text("synthetic blue operator\n")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    monkeypatch.setattr(engagements, "set_active_engagement", lambda *args: None)
    monkeypatch.setattr(engagements.os, "chdir", lambda *args: None)
    return path


def _saved_choices(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "state"
    saved = state / "opencode" / "model.json"
    saved.parent.mkdir(parents=True)
    saved.write_text(json.dumps({"variant": {"acme/model-1": "high", "acme/model-2": "low"}}))
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    return saved


@pytest.mark.parametrize(
    "arguments",
    [["--model=acme/model-1#max"], ["--model", "acme/model-1#max"], ["-m", "acme/model-1#max"]],
)
def test_blue_opencode_start_saves_the_variant_and_forwards_the_bare_model(
    tmp_path, monkeypatch, capsys, blue_engagement, arguments
) -> None:
    saved = _saved_choices(tmp_path, monkeypatch)
    launched: list[list[str]] = []
    monkeypatch.setattr(engagements.os, "execv", lambda path, argv: launched.append(argv))

    engagements.start_engagement(tmp_path, blue_engagement, "opencode", arguments)

    argv = launched[0]
    assert not any("#" in argument for argument in argv)
    assert "acme/model-1" in argv or "--model=acme/model-1" in argv
    assert json.loads(saved.read_text())["variant"] == {"acme/model-1": "max", "acme/model-2": "low"}
    assert "variant: max for acme/model-1" in capsys.readouterr().err


def test_blue_opencode_start_refuses_an_unreadable_choice_file_before_launch(
    tmp_path, monkeypatch, blue_engagement
) -> None:
    saved = _saved_choices(tmp_path, monkeypatch)
    saved.write_text("[]")
    launched: list[list[str]] = []
    monkeypatch.setattr(engagements.os, "execv", lambda path, argv: launched.append(argv))

    with pytest.raises(SystemExit, match="model.json"):
        engagements.start_engagement(tmp_path, blue_engagement, "opencode", ["--model=acme/model-1#max"])

    assert launched == []
    assert saved.read_text() == "[]"
