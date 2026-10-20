"""Session prompt selection is distinct from durable track authorization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_cli import engagements


def _engagement(tmp_path: Path, scope: dict) -> Path:
    path = tmp_path / "agent" / "engagements" / "example"
    path.mkdir(parents=True)
    (path / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    return path


def test_new_engagement_has_one_track_and_enabling_second_preserves_its_phase(tmp_path: Path) -> None:
    plan = engagements.plan_engagement(
        engagements.CreateEngagementOptions(
            install_root=tmp_path,
            engagement_type="code",
            name="example",
        )
    )
    assert plan.scope["engagement_type"] == "offensive"
    assert plan.scope["tracks"] == {"code": {"phase": "ingest"}}

    engagement_dir = _engagement(tmp_path, {**plan.scope, "status": "in_progress"})
    engagements.add_engagement_track(tmp_path, engagement_dir.name, "web")
    updated = json.loads((engagement_dir / "scope.json").read_text())
    assert updated["engagement_type"] == "offensive"
    assert updated["tracks"] == {"code": {"phase": "ingest"}, "web": {"phase": "recon"}}


def test_explicit_code_creation_retains_declared_hosts_without_enabling_web(tmp_path: Path) -> None:
    plan = engagements.plan_engagement(engagements.CreateEngagementOptions(
        install_root=tmp_path, engagement_type="code", name="example",
        target="https://example.test",
    ))
    assert plan.scope["hosts"] == ["example.test"]
    assert plan.scope["tracks"] == {"code": {"phase": "ingest"}}


def test_new_creation_rejects_combined_operator_type(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="code|web"):
        engagements.plan_engagement(
            engagements.CreateEngagementOptions(
                install_root=tmp_path, engagement_type="both", name="example",
                target="https://example.test", repos=[str(tmp_path / "source")],
            )
        )


def test_creation_refuses_combined_inputs_instead_of_dropping_host_scope(tmp_path: Path) -> None:
    from vigil_cli.main import main

    with pytest.raises(SystemExit, match="remediation"):
        main([
            "--root", str(tmp_path), "engagement", "create", "--no-prompt",
            "--name", "example", "--repo", str(tmp_path), "--hosts", "example.test",
        ])


def test_mode_command_reports_session_selected_prompt_and_tracks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from vigil_cli.main import main

    path = _engagement(tmp_path, {
        "engagement_type": "offensive",
        "tracks": {"web": {"phase": "recon"}, "code": {"phase": "hunt"}},
    })
    monkeypatch.setenv("VIGIL_OPERATOR_MODE", "code")
    monkeypatch.setenv("ENGAGEMENT_DIR", str(path))
    monkeypatch.delenv("VIGIL_SESSION_ENGAGEMENT_DIR", raising=False)

    main(["--root", str(tmp_path), "engagement", "mode", "example"])

    output = capsys.readouterr().out
    assert output.startswith(
        f"mode: code\nprompt: {engagements.engagement_mode_prompt(tmp_path, 'code')}\n"
    )
    assert "web: phase=recon" in output
    assert "code: phase=hunt" in output


def test_start_passes_explicit_session_mode_to_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import main as main_module

    _engagement(tmp_path, {
        "engagement_type": "offensive",
        "tracks": {"web": {"phase": "recon"}, "code": {"phase": "hunt"}},
    })
    calls = []
    monkeypatch.setattr(main_module, "start_engagement", lambda *args, **kwargs: calls.append(args))

    main_module.main([
        "--root", str(tmp_path), "engagement", "start", "example",
        "--client", "codex", "--mode", "code", "--skip-preflight",
    ])

    assert calls == [(
        tmp_path, tmp_path / "agent" / "engagements" / "example", "codex", [], "code"
    )]


def test_dual_track_start_requires_one_explicit_session_mode(tmp_path: Path) -> None:
    engagement_dir = _engagement(tmp_path, {
        "engagement_type": "offensive",
        "tracks": {"web": {"phase": "recon"}, "code": {"phase": "hunt"}},
    })

    with pytest.raises(SystemExit, match="--mode web or --mode code"):
        engagements.resolve_engagement_mode(engagement_dir, None)
    assert engagements.resolve_engagement_mode(engagement_dir, "code") == "code"
    assert engagements.resolve_engagement_mode(engagement_dir, "web") == "web"
    with pytest.raises(SystemExit, match="invalid|unavailable"):
        engagements.resolve_engagement_mode(engagement_dir, "both")


def test_session_mode_does_not_enable_unavailable_track(tmp_path: Path) -> None:
    engagement_dir = _engagement(tmp_path, {
        "engagement_type": "offensive",
        "tracks": {"code": {"phase": "hunt"}},
        "hosts": ["example.test"],
    })

    assert engagements.resolve_engagement_mode(engagement_dir, None) == "code"
    with pytest.raises(SystemExit, match="not enabled|unavailable"):
        engagements.resolve_engagement_mode(engagement_dir, "web")


def test_legacy_both_scope_can_select_each_session_mode(tmp_path: Path) -> None:
    engagement_dir = _engagement(tmp_path, {
        "engagement_type": "both", "current_phase": "recon", "code_phase": "hunt",
    })

    assert engagements.resolve_engagement_mode(engagement_dir, "code") == "code"
    assert engagements.resolve_engagement_mode(engagement_dir, "web") == "web"


def test_blue_and_remediation_cannot_be_selected_on_offensive_engagement(tmp_path: Path) -> None:
    engagement_dir = _engagement(tmp_path, {
        "engagement_type": "offensive", "tracks": {"web": {"phase": "recon"}},
    })

    for mode in ("blue", "remediation", "android"):
        with pytest.raises(SystemExit, match="not enabled|unavailable"):
            engagements.resolve_engagement_mode(engagement_dir, mode)


def test_local_operator_pointer_routes_dual_track_without_loading_two_cores(tmp_path: Path) -> None:
    agent_root = tmp_path / "agent"
    agent_root.mkdir()
    (agent_root / "AGENTS.md").write_text("web prompt\n")
    (agent_root / "operator-core-code.md").write_text("code prompt\n")
    engagement_dir = _engagement(tmp_path, {
        "engagement_type": "offensive",
        "tracks": {"web": {"phase": "recon"}, "code": {"phase": "hunt"}},
    })

    engagements._write_prompt_wrappers(agent_root, engagement_dir, "codex", engagement_type="offensive")

    pointer = (engagement_dir / "AGENTS.md").read_text()
    assert "vigil engagement mode" in pointer
    assert "Read only the absolute prompt path" in pointer
    assert str(agent_root / "AGENTS.md") not in pointer
    assert str(agent_root / "operator-core-code.md") not in pointer


def test_local_operator_pointer_for_code_only_loads_code_core(tmp_path: Path) -> None:
    agent_root = tmp_path / "agent"
    agent_root.mkdir()
    (agent_root / "operator-core-code.md").write_text("code prompt\n")
    engagement_dir = _engagement(tmp_path, {
        "engagement_type": "offensive", "tracks": {"code": {"phase": "ingest"}},
    })

    engagements._write_prompt_wrappers(agent_root, engagement_dir, "codex", engagement_type="offensive")

    pointer = (engagement_dir / "AGENTS.md").read_text()
    assert str(agent_root / "operator-core-code.md") in pointer
    assert str(agent_root / "AGENTS.md") not in pointer


def test_install_repairs_generated_legacy_both_pointer_without_touching_custom_pointer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    agent_root = tmp_path / "agent"
    agent_root.mkdir()
    (agent_root / "AGENTS.md").write_text("web prompt\n")
    (agent_root / "operator-core-code.md").write_text("code prompt\n")
    old = _engagement(tmp_path, {
        "engagement_type": "both", "current_phase": "collect", "code_phase": "hunt",
    })
    engagements._write_prompt_wrappers(agent_root, old, "codex", engagement_type="web")
    custom = old.parent / "custom"
    custom.mkdir()
    (custom / "scope.json").write_text((old / "scope.json").read_text())
    (custom / "AGENTS.md").write_text("My custom instructions\n")

    monkeypatch.chdir(tmp_path)
    assert engagements.repair_engagement_operator_pointers(
        Path("."), rendered_install_root=tmp_path
    ) == ("example",)
    assert "vigil engagement mode" in (old / "AGENTS.md").read_text()
    assert (custom / "AGENTS.md").read_text() == "My custom instructions\n"


def test_explicit_legacy_track_repair_updates_generated_pointer_immediately(tmp_path: Path) -> None:
    agent_root = tmp_path / "agent"
    agent_root.mkdir()
    (agent_root / "AGENTS.md").write_text("web prompt\n")
    (agent_root / "operator-core-code.md").write_text("code prompt\n")
    old = _engagement(tmp_path, {"engagement_type": "both", "current_phase": "verify"})
    engagements._write_prompt_wrappers(agent_root, old, "codex", engagement_type="web")

    engagements.repair_engagement_tracks(tmp_path, "example")

    assert "vigil engagement mode" in (old / "AGENTS.md").read_text()
    assert engagements.resolve_engagement_mode(old, "code") == "code"


def test_install_repairs_legacy_code_pointer_to_absolute_code_core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    agent_root = tmp_path / "agent"
    agent_root.mkdir()
    (agent_root / "AGENTS.md").write_text("web prompt\n")
    (agent_root / "operator-core-code.md").write_text("code prompt\n")
    (tmp_path / "orchestrator").mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(tmp_path))
    old = _engagement(tmp_path, {"engagement_type": "code", "current_phase": "hunt"})
    engagements._write_prompt_wrappers(agent_root, old, "codex", engagement_type="web")

    monkeypatch.chdir(tmp_path)
    assert engagements.repair_engagement_operator_pointers(
        Path("."), rendered_install_root=tmp_path
    ) == ("example",)
    assert str(agent_root / "operator-core-code.md") in (old / "AGENTS.md").read_text()


def test_mode_inspects_dual_tracks_without_selecting_a_session(tmp_path, monkeypatch, capsys):
    from vigil_cli.main import main

    _engagement(tmp_path, {"engagement_type": "offensive", "tracks": {
        "web": {"phase": "recon"}, "code": {"phase": "hunt"},
    }})
    monkeypatch.delenv("VIGIL_OPERATOR_MODE", raising=False)
    main(["--root", str(tmp_path), "engagement", "mode", "example", "--client", "claude", "--json"])
    state = json.loads(capsys.readouterr().out)
    assert state["mode"] is None
    assert state["prompt"] is None
    assert {name: row["phase"] for name, row in state["tracks"].items()} == {
        "web": "recon", "code": "hunt",
    }
    for name, row in state["tracks"].items():
        assert row["prompt"] == str(engagements.engagement_mode_prompt(tmp_path, name))
        assert f"engagement start example --client claude --mode {name}" in row["start_command"]


@pytest.mark.parametrize("binding", ["same", "other", "none"])
def test_mode_uses_only_the_inspected_engagement_session(tmp_path, monkeypatch, capsys, binding):
    from vigil_cli.main import main

    path = _engagement(tmp_path, {"engagement_type": "offensive", "tracks": {
        "web": {"phase": "collect"}, "code": {"phase": "hunt"},
    }})
    monkeypatch.setenv("VIGIL_OPERATOR_MODE", "code")
    monkeypatch.delenv("VIGIL_SESSION_ENGAGEMENT_DIR", raising=False)
    monkeypatch.delenv("ENGAGEMENT_KEY", raising=False)
    monkeypatch.delenv("ENGAGEMENT_DIR", raising=False)
    if binding != "none":
        monkeypatch.setenv("ENGAGEMENT_DIR", str(path if binding == "same" else path.parent / "other"))
    main(["--root", str(tmp_path), "engagement", "mode", "example", "--json"])
    state = json.loads(capsys.readouterr().out)
    assert state["mode"] == ("code" if binding == "same" else None)


def test_ambiguous_start_reports_complete_client_relaunch_commands(tmp_path):
    path = _engagement(tmp_path, {"engagement_type": "offensive", "tracks": {
        "web": {"phase": "recon"}, "code": {"phase": "hunt"},
    }})
    with pytest.raises(SystemExit) as error:
        engagements.start_engagement(tmp_path, path, "codex", [])
    message = str(error.value)
    for mode in ("web", "code"):
        assert f"vigil engagement start example --client codex --mode {mode}" in message


def test_start_reports_workspace_client_mode_and_phase_before_exec(tmp_path, monkeypatch, capsys):
    path = _engagement(tmp_path, {"engagement_type": "offensive", "tracks": {
        "code": {"phase": "hunt"},
    }})
    prompt = tmp_path / "application" / "agent" / "operator-core-code.md"
    (tmp_path / "application" / "orchestrator").mkdir(parents=True)
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(tmp_path / "application"))
    prompt.parent.mkdir(parents=True, exist_ok=True)
    prompt.write_text("synthetic prompt\n")
    launcher = path / "start_codex.sh"
    launcher.write_text("#!/bin/sh\n")
    monkeypatch.setattr(engagements, "set_active_engagement", lambda *args: None)
    monkeypatch.setattr(engagements.os, "chdir", lambda *args: None)
    monkeypatch.setattr(engagements.os, "execv", lambda *args: None)
    monkeypatch.setenv("VIGIL_REQUESTED_CLIENT", "old")
    monkeypatch.setenv("VIGIL_OPERATOR_MODE", "web")
    engagements.start_engagement(tmp_path, path, "codex", [])
    output = capsys.readouterr()
    assert output.out == ""
    assert f"workspace: {tmp_path}" in output.err
    assert "engagement: example" in output.err
    assert "client: codex" in output.err
    assert "mode: code" in output.err
    assert "phase: hunt" in output.err


@pytest.mark.parametrize("session_binding", ["same", "other"])
def test_mode_prefers_session_binding_over_artifact_directory(tmp_path, monkeypatch, capsys, session_binding):
    from vigil_cli.main import main

    path = _engagement(tmp_path, {"engagement_type": "offensive", "tracks": {
        "web": {"phase": "recon"}, "code": {"phase": "hunt"},
    }})
    monkeypatch.setenv("VIGIL_OPERATOR_MODE", "code")
    monkeypatch.setenv("ENGAGEMENT_DIR", str(path))
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(
        path if session_binding == "same" else path.parent / "other"
    ))
    main(["--root", str(tmp_path), "engagement", "mode", "example", "--json"])

    state = json.loads(capsys.readouterr().out)
    assert state["mode"] == ("code" if session_binding == "same" else None)
