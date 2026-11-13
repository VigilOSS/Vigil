"""The engagement-local operator pointer always names the current install and application roots."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_cli import engagements


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    application = tmp_path / "application"
    (application / "orchestrator").mkdir(parents=True)
    (application / "agent").mkdir()
    (application / "agent" / "AGENTS.md").write_text("application web prompt\n")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    workspace = tmp_path / "workspace"
    engagement = workspace / "engagements" / "acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({
        "engagement_type": "offensive", "tracks": {"web": {"phase": "recon"}}, "status": "in_progress",
    }))
    return application, workspace, engagement


def test_a_pointer_naming_another_install_root_is_rewritten(layout, tmp_path: Path) -> None:
    application, workspace, engagement = layout
    # A copied engagement: the prompt path is current, the install root is someone else's.
    engagements._write_prompt_wrappers(
        application / "agent", engagement, "codex", engagement_type="offensive",
        workspace_root=tmp_path / "acme-original-install",
    )
    stale = (engagement / "AGENTS.md").read_text()
    assert str(application / "agent" / "AGENTS.md") in stale

    assert engagements.repair_engagement_operator_pointers(workspace, engagement_dir=engagement) == ("acme",)

    pointer = (engagement / "AGENTS.md").read_text()
    assert f"- Install root: {workspace}\n" in pointer
    assert "acme-original-install" not in pointer


def test_a_current_pointer_is_left_alone(layout) -> None:
    application, workspace, engagement = layout
    engagements._write_prompt_wrappers(
        application / "agent", engagement, "codex", engagement_type="offensive", workspace_root=workspace,
    )
    before = (engagement / "AGENTS.md").read_bytes()
    assert engagements.repair_engagement_operator_pointers(workspace, engagement_dir=engagement) == ()
    assert (engagement / "AGENTS.md").read_bytes() == before


def test_start_refreshes_a_pointer_naming_another_install_root(layout, tmp_path, monkeypatch) -> None:
    application, workspace, engagement = layout
    engagements._write_launchers(application / "agent", engagement, "codex", skip_permissions=False,
                                 workspace_root=workspace)
    # A copied engagement: the prompt path is current, the install root is someone else's.
    engagements._write_prompt_wrappers(application / "agent", engagement, "codex", engagement_type="offensive",
                                       workspace_root=tmp_path / "acme-original-install")
    monkeypatch.setattr(engagements.os, "chdir", lambda *_: None)
    monkeypatch.setattr(engagements.os, "execv", lambda *args: None)

    engagements.start_engagement(workspace, engagement, "codex", [])

    pointer = (engagement / "AGENTS.md").read_text()
    assert f"- Install root: {workspace}\n" in pointer
    assert "acme-original-install" not in pointer


def test_start_names_the_pointer_it_refreshed(layout, tmp_path, monkeypatch, capsys) -> None:
    application, workspace, engagement = layout
    engagements._write_launchers(application / "agent", engagement, "codex", skip_permissions=False,
                                 workspace_root=workspace)
    engagements._write_prompt_wrappers(application / "agent", engagement, "codex", engagement_type="offensive",
                                       workspace_root=tmp_path / "acme-original-install")
    monkeypatch.setattr(engagements.os, "chdir", lambda *_: None)
    monkeypatch.setattr(engagements.os, "execv", lambda *args: None)

    engagements.start_engagement(workspace, engagement, "codex", [])
    refreshed = [line for line in capsys.readouterr().err.splitlines() if "operator pointer" in line]
    assert len(refreshed) == 1
    assert str(engagement / "AGENTS.md") in refreshed[0]
    assert str(workspace) in refreshed[0]

    engagements.start_engagement(workspace, engagement, "codex", [])
    assert "operator pointer" not in capsys.readouterr().err
