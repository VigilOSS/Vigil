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
            repos=[str(tmp_path / "source")],
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
        target="https://example.test", repos=[str(tmp_path / "source")],
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

    with pytest.raises(SystemExit, match="explicit first track"):
        main([
            "--root", str(tmp_path), "engagement", "create", "--no-prompt",
            "--name", "example", "--repo", str(tmp_path), "--hosts", "example.test",
        ])


def test_mode_command_reports_only_session_selected_prompt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from vigil_cli.main import main

    _engagement(tmp_path, {
        "engagement_type": "offensive",
        "tracks": {"web": {"phase": "recon"}, "code": {"phase": "hunt"}},
    })
    monkeypatch.setenv("VIGIL_OPERATOR_MODE", "code")

    main(["--root", str(tmp_path), "engagement", "mode", "example"])

    assert capsys.readouterr().out == (
        f"mode: code\nprompt: {tmp_path / 'agent' / 'operator-core-code.md'}\n"
    )


def test_start_passes_explicit_session_mode_to_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import main as main_module

    _engagement(tmp_path, {
        "engagement_type": "offensive",
        "tracks": {"web": {"phase": "recon"}, "code": {"phase": "hunt"}},
    })
    calls = []
    monkeypatch.setattr(main_module, "start_engagement", lambda *args: calls.append(args))

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
    old = _engagement(tmp_path, {"engagement_type": "code", "current_phase": "hunt"})
    engagements._write_prompt_wrappers(agent_root, old, "codex", engagement_type="web")

    monkeypatch.chdir(tmp_path)
    assert engagements.repair_engagement_operator_pointers(
        Path("."), rendered_install_root=tmp_path
    ) == ("example",)
    assert str(agent_root / "operator-core-code.md") in (old / "AGENTS.md").read_text()
