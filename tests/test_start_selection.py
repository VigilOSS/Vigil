from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from vigil_cli import engagements
from vigil_cli import main as cli


class TerminalInput(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def setup(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(Path(__file__).resolve().parents[1]))
    monkeypatch.setattr(cli.term, "is_terminal", lambda stream: False)
    calls = []
    monkeypatch.setattr(cli, "start_engagement", lambda *args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.setattr(cli, "_preflight_engagement_start", lambda *args, **kwargs: calls.append(("preflight", kwargs)))
    return root, calls


def engagement(root, key="acme", tracks=None, kind="offensive"):
    path = root / "engagements" / key
    path.mkdir(parents=True)
    scope = {"engagement_type": kind, "status": "in_progress"}
    if kind == "offensive":
        scope["tracks"] = tracks or {"web": {"phase": "recon"}}
    (path / "scope.json").write_text(json.dumps(scope))
    (path / "engagement.json").write_text(json.dumps({"target": "https://example.com"}))
    return path


def test_start_asks_engagement_then_client_then_mode(setup, monkeypatch, capsys):
    root, calls = setup
    path = engagement(root)
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("1\n2\n2\n"))
    cli.main(["--root", str(root), "engagement", "start", "--skip-preflight"])
    assert calls[-1][0][1:3] == (path, "claude")
    assert calls[-1][0][4] == "code"
    output = capsys.readouterr().err
    assert output.index("Select engagement") < output.index("Select client") < output.index("Select operator mode")


@pytest.mark.parametrize("initial,selected,phase", [("web", "code", "ingest"), ("code", "web", "recon")])
@pytest.mark.parametrize("legacy", [False, True])
def test_start_selected_mode_initializes_track_and_preserves_existing_state(setup, monkeypatch, initial, selected, phase, legacy):
    root, calls = setup
    path = engagement(root, tracks={initial: {"phase": "verify"}})
    scope = {"engagement_type": initial, "current_phase": "verify"} if legacy else json.loads((path / "scope.json").read_text())
    scope.update(hosts=["app.example.com"], exploit_policy="pause", required_headers={"X-Acme": "test"})
    (path / "scope.json").write_text(json.dumps(scope))
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO())
    cli.main(["--root", str(root), "engagement", "start", "acme", "--client", "zcode", "--mode", selected])
    updated = json.loads((path / "scope.json").read_text())
    assert updated["tracks"] == {initial: {"phase": "verify"}, selected: {"phase": phase}}
    assert updated["track_transitions"][-1]["operation"] == f"add-{selected}"
    for name in ("hosts", "exploit_policy", "required_headers"):
        assert updated[name] == scope[name]
    assert calls[0] == ("preflight", {"mode": selected})
    assert calls[-1][0][4] == selected
    cli.main(["--root", str(root), "engagement", "start", "acme", "--client", "zcode", "--mode", selected])
    assert json.loads((path / "scope.json").read_text()) == updated


def test_single_track_interactive_start_still_asks_for_mode(setup, monkeypatch, capsys):
    root, calls = setup
    engagement(root)
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("2\n"))
    cli.main(["--root", str(root), "engagement", "start", "acme", "--client", "codex"])
    assert calls[-1][0][4] == "code"
    assert "Select operator mode" in capsys.readouterr().err


@pytest.mark.parametrize("missing", ["--client", "--mode"])
def test_noninteractive_start_requires_missing_session_choice(setup, monkeypatch, missing):
    root, calls = setup
    engagement(root, tracks={"web": {"phase": "recon"}, "code": {"phase": "ingest"}})
    flags = ["--mode", "web"] if missing == "--client" else ["--client", "codex"]
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO())
    with pytest.raises(SystemExit, match=missing):
        cli.main(["--root", str(root), "engagement", "start", "acme", *flags])
    assert calls == []


def test_engagement_start_uses_fzf_with_recency_preview_and_create_action(setup, monkeypatch):
    from vigil_cli import prompts

    root, calls = setup
    engagement(root, "acme-a")
    selected = engagement(root, "acme-b")
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("1\n"))
    monkeypatch.setattr(cli.term, "is_terminal", lambda _stream: True)
    monkeypatch.setattr(prompts, "terminal_question", lambda *args, **kwargs: kwargs["choices"][0])
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/fzf")
    previews = []

    def pick(lines, details, **kwargs):
        assert "Create new engagement" in lines[-1]
        previews.extend(details.values())
        return 1

    monkeypatch.setattr(cli.term, "fuzzy_pick", pick)
    cli.main(["--root", str(root), "engagement", "start", "--client", "codex", "--mode", "web", "--skip-preflight"])
    assert calls[-1][0][1] == selected
    assert any("recent" in preview and "acme-b" in preview for preview in previews)


@pytest.mark.parametrize("client", ["claude", "codex", "opencode", "zcode", "kimi", "goose"])
def test_start_without_key_always_asks_even_for_single_ambient_engagement(setup, monkeypatch, capsys, client):
    root, calls = setup
    path = engagement(root)
    monkeypatch.chdir(path)
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(path))
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("1\n\n"))
    cli.main(["--root", str(root), "engagement", "start", "--client", client, "--skip-preflight"])
    assert str(path) in str(calls[-1])
    assert "Select engagement" in capsys.readouterr().err


def test_noninteractive_start_requires_explicit_key_despite_ambient_scope(setup, monkeypatch):
    root, calls = setup
    path = engagement(root)
    monkeypatch.chdir(path)
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(path))
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO())
    with pytest.raises(SystemExit, match="explicit.*key|key.*explicit"):
        cli.main(["--root", str(root), "engagement", "start", "--client", "codex", "--skip-preflight"])
    assert calls == []


def test_explicit_key_still_selects_dual_mode_before_preflight(setup, monkeypatch, capsys):
    root, calls = setup
    engagement(root, tracks={"web": {"phase": "recon"}, "code": {"phase": "ingest"}})
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("2\n"))
    cli.main(["--root", str(root), "engagement", "start", "acme", "--client", "codex"])
    assert calls[0] == ("preflight", {"mode": "code"})
    assert calls[-1][0][4] == "code"
    output = capsys.readouterr().err
    assert "Select operator mode" in output
    assert "Select engagement" not in output


def test_noninteractive_ambiguous_mode_fails_before_preflight(setup, monkeypatch):
    root, calls = setup
    engagement(root, tracks={"web": {"phase": "recon"}, "code": {"phase": "ingest"}})
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO())
    with pytest.raises(SystemExit, match="--mode"):
        cli.main(["--root", str(root), "engagement", "start", "acme", "--client", "codex"])
    assert calls == []


def test_picker_cancel_does_not_create_or_launch(setup, monkeypatch):
    root, calls = setup
    engagement(root)
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput())
    with pytest.raises(SystemExit, match="closed|cancelled"):
        cli.main(["--root", str(root), "engagement", "start", "--client", "codex"])
    assert calls == []


def test_create_action_reuses_creation_questions_and_returns_created_path(setup, monkeypatch, capsys):
    root, calls = setup
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("1\n2\nAcme\ny\n\n"))
    monkeypatch.setattr(engagements, "_verify_backend_install_root", lambda *_: engagements.BackendInstallRootStatus.VERIFIED)
    monkeypatch.setattr(engagements, "_emit_post_create_footer", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(engagements, "_install_client_kind", lambda *_: "none")
    cli.main(["--root", str(root), "engagement", "start", "--client", "zcode", "--skip-preflight"])
    path = calls[-1][0][1]
    assert json.loads((path / "scope.json").read_text())["tracks"] == {"code": {"phase": "ingest"}}
    assert "Engagement name" in capsys.readouterr().err


def test_incompatible_selection_explains_native_limits_before_preflight(setup, monkeypatch, capsys):
    root, calls = setup
    engagement(root, kind="blue")
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("1\n\n"))
    with pytest.raises(SystemExit, match="zcode.*web.*code"):
        cli.main(["--root", str(root), "engagement", "start", "--client", "zcode"])
    assert calls == []
    assert "unsupported" in capsys.readouterr().err


def test_picker_orders_normalized_activity_and_does_not_promote_invalid_creation_dates(setup, monkeypatch, capsys):
    root, calls = setup
    for key, created in [("acme-old", "2026-10-19T10:00:00+02:00"),
                         ("acme-recent", "2026-10-19T09:00:00Z"),
                         ("acme-unknown", "unknown")]:
        path = engagement(root, key)
        (path / "engagement.json").write_text(json.dumps({"created_at": created, "target": "https://example.com"}))
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("1\n\n"))
    cli.main(["--root", str(root), "engagement", "start", "--client", "codex", "--skip-preflight"])
    assert calls[-1][0][1].name == "acme-recent"
    output = capsys.readouterr().err
    assert output.index("acme-recent") < output.index("acme-old") < output.index("acme-unknown")


def test_explicit_selection_never_prompts_and_reaches_preflight_with_validated_mode(setup, monkeypatch):
    root, calls = setup
    engagement(root, tracks={"web": {"phase": "recon"}, "code": {"phase": "ingest"}})
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput())
    monkeypatch.setattr(cli, "_prompt_choice", lambda *args, **kwargs: pytest.fail("explicit selection must not prompt"))
    cli.main(["--root", str(root), "engagement", "start", "acme", "--client", "codex", "--mode", "code"])
    assert calls[0] == ("preflight", {"mode": "code"})


def test_cancel_during_create_confirmation_keeps_workspace_empty(setup, monkeypatch):
    root, calls = setup
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("1\n2\nAcme\nn\n"))
    with pytest.raises(SystemExit, match="not created"):
        cli.main(["--root", str(root), "engagement", "start", "--client", "zcode"])
    assert list(root.iterdir()) == []
    assert calls == []


def test_created_engagement_is_preserved_when_subsequent_start_fails(setup, monkeypatch):
    root, calls = setup
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("1\n2\nAcme\ny\n\n"))
    monkeypatch.setattr(engagements, "_verify_backend_install_root", lambda *_: engagements.BackendInstallRootStatus.VERIFIED)
    monkeypatch.setattr(engagements, "_emit_post_create_footer", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(engagements, "_install_client_kind", lambda *_: "none")

    def fail_launch(*args, **kwargs):
        raise SystemExit("native app unavailable")

    monkeypatch.setattr(cli, "start_engagement", fail_launch)
    with pytest.raises(SystemExit, match="native app unavailable"):
        cli.main(["--root", str(root), "engagement", "start", "--client", "zcode", "--skip-preflight"])
    paths = list((root / "engagements").iterdir())
    assert len(paths) == 1
    assert json.loads((paths[0] / "scope.json").read_text())["tracks"] == {"code": {"phase": "ingest"}}


@pytest.mark.parametrize("scope_text", ["[]", "invalid json"])
def test_invalid_scope_is_reported_without_launching_or_hiding_engagement(setup, monkeypatch, capsys, scope_text):
    root, calls = setup
    path = engagement(root)
    (path / "scope.json").write_text(scope_text)
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("1\n"))
    with pytest.raises(SystemExit, match="scope.json"):
        cli.main(["--root", str(root), "engagement", "start", "--client", "codex"])
    assert calls == []
    assert "acme" in capsys.readouterr().err


def test_picker_identifies_scalar_engagement_type_alongside_its_phase(setup, monkeypatch):
    root, calls = setup
    engagement(root, "acme-defense", kind="blue")
    engagement(root, "acme-repair", kind="remediation")
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput())
    rendered = []

    def select(label, default, choices, **kwargs):
        if label == "Select engagement":
            rendered.extend(choices)
        return choices[0]

    monkeypatch.setattr(cli, "_prompt_choice", select)
    cli.main(["--root", str(root), "engagement", "start", "--client", "codex", "--skip-preflight"])
    assert "blue" in next(choice for choice in rendered if "acme-defense" in choice)
    assert "remediation" in next(choice for choice in rendered if "acme-repair" in choice)
    assert calls[-1][0][1].name == "acme-defense"
