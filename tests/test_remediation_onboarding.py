from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess

import pytest

from vigil_cli import engagements, main as cli, remediation


class TerminalInput(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def onboarding(tmp_path, monkeypatch):
    root = tmp_path / "private"
    root.mkdir()
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(Path(__file__).resolve().parents[1]))
    monkeypatch.setattr(cli.term, "is_terminal", lambda _stream: False)
    calls = []
    monkeypatch.setattr(remediation, "run_session_command", lambda args, _root, path, project, **_kwargs:
                        calls.append((args, path, project)) or 0)
    return root, calls


def project(root, key="acme", *, kind="remediation", created="2026-10-19T09:00:00Z"):
    directory = root / "engagements" / key
    directory.mkdir(parents=True)
    repository = root / "repositories" / key
    repository.mkdir(parents=True)
    (repository / "PROJECT.md").write_text('+++\nrepository = "."\n+++\n# Acme\n')
    (directory / "PROJECT.md").symlink_to(repository / "PROJECT.md")
    (directory / "scope.json").write_text(json.dumps({"engagement_type": kind, "status": "in_progress"}))
    (directory / "engagement.json").write_text(json.dumps({"target": key, "created_at": created}))
    return directory, repository


def test_remediation_start_uses_shared_fzf_picker_with_create_action(onboarding, monkeypatch):
    from vigil_cli import prompts

    root, calls = onboarding
    project(root, "acme-a")
    selected, _ = project(root, "acme-b")
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("1\n"))
    monkeypatch.setattr(cli.term, "is_terminal", lambda _stream: True)
    monkeypatch.setattr(prompts, "terminal_question", lambda *args, **kwargs: kwargs["choices"][0])
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/fzf")
    previews = []

    def pick(lines, details, **kwargs):
        assert "Create new remediation engagement" in lines[-1]
        previews.extend(details.values())
        return 1

    monkeypatch.setattr(cli.term, "fuzzy_pick", pick)
    cli.main(["--root", str(root), "remediation", "start", "--client", "claude"])
    assert calls[0][1] == selected
    assert any("recent" in preview and "acme-b" in preview for preview in previews)


@pytest.mark.parametrize("arguments", [[], ["--help"], ["start", "--help"]])
def test_remediation_entry_help_explains_start_without_resolving_project(onboarding, monkeypatch, capsys, arguments):
    root, calls = onboarding
    monkeypatch.setattr(remediation, "_project", lambda *_: pytest.fail("help must not resolve a project"))
    monkeypatch.setattr(remediation, "_api", lambda *_: pytest.fail("help must not contact backend"))
    try:
        cli.main(["--root", str(root), "remediation", *arguments])
    except SystemExit as exc:
        assert exc.code == 0
    output = capsys.readouterr().out
    assert "vigil remediation start" in output
    assert "PROJECT.md" in output
    assert "/vigil-remediate" in output
    assert not calls
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("arguments,line_budget", [(["--help"], 64), (["start", "--help"], 30)])
def test_remediation_help_fits_a_short_overview(onboarding, capsys, monkeypatch, arguments, line_budget):
    monkeypatch.setenv("COLUMNS", "80")
    root, _ = onboarding
    with pytest.raises(SystemExit) as result:
        cli.main(["--root", str(root), "remediation", *arguments])
    assert result.value.code == 0
    output = capsys.readouterr().out
    assert len(output.splitlines()) <= line_budget
    assert "vigil remediation start" in output
    assert "--help" in output


@pytest.mark.parametrize("ambient", [False, True])
def test_start_always_picks_single_remediation_project(onboarding, monkeypatch, capsys, ambient):
    root, calls = onboarding
    directory, _ = project(root)
    if ambient:
        monkeypatch.setenv("ENGAGEMENT_KEY", "not-selected")
        monkeypatch.chdir(directory)
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("1\n"))
    cli.main(["--root", str(root), "remediation", "start", "--client", "claude"])
    assert calls[0][1] == directory
    assert "Select remediation engagement" in capsys.readouterr().err


def test_picker_filters_to_remediation_and_sorts_meaningful_recency(onboarding, monkeypatch, capsys):
    root, calls = onboarding
    project(root, "acme-old", created="2026-10-19T10:00:00+02:00")
    recent, _ = project(root, "acme-recent", created="2026-10-19T09:00:00Z")
    project(root, "acme-web", kind="web")
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("1\n"))
    cli.main(["--root", str(root), "remediation", "start", "--client", "claude"])
    assert calls[0][1] == recent
    output = capsys.readouterr().err
    assert output.index("acme-recent") < output.index("acme-old")
    assert "acme-web" not in output


def test_noninteractive_start_requires_key_even_with_singleton_and_environment(onboarding, monkeypatch):
    root, calls = onboarding
    project(root)
    monkeypatch.setenv("ENGAGEMENT_KEY", "acme")
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO())
    with pytest.raises(SystemExit, match="explicit.*--engagement-key"):
        cli.main(["--root", str(root), "remediation", "start"])
    assert calls == []


@pytest.mark.parametrize("client", ["claude", "opencode", "zcode"])
def test_explicit_key_and_client_skip_all_questions(onboarding, monkeypatch, client):
    root, calls = onboarding
    directory, _ = project(root)
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput())
    cli.main(["--root", str(root), "remediation", "-k", "acme", "start", "--client", client])
    assert (calls[0][1], calls[0][0].client) == (directory, client)


def test_interactive_start_offers_supported_clients_when_omitted(onboarding, monkeypatch, capsys):
    root, calls = onboarding
    project(root)
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("2\n"))
    cli.main(["--root", str(root), "remediation", "-k", "acme", "start"])
    assert calls[0][0].client == "opencode"
    assert "Select remediation client" in capsys.readouterr().err


def test_noninteractive_explicit_key_preserves_claude_default(onboarding, monkeypatch):
    root, calls = onboarding
    project(root)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO())
    cli.main(["--root", str(root), "remediation", "-k", "acme", "start"])
    assert calls[0][0].client == "claude"


def test_start_create_action_uses_canonical_remediation_wizard(onboarding, monkeypatch):
    root, calls = onboarding
    repository = root / "repositories" / "acme"
    subprocess.run(["git", "init", str(repository)], check=True, capture_output=True)
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput(f"1\nAcme\n{repository}\ny\n"))
    monkeypatch.setattr(engagements, "_verify_backend_install_root", lambda *_: engagements.BackendInstallRootStatus.VERIFIED)
    monkeypatch.setattr(engagements, "_emit_post_create_footer", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(engagements, "_install_client_kind", lambda *_: "none")
    cli.main(["--root", str(root), "remediation", "start", "--client", "claude"])
    _, directory, config = calls[0]
    assert json.loads((directory / "scope.json").read_text())["engagement_type"] == "remediation"
    assert config["repository"] == str(repository)
    assert (directory / "PROJECT.md").resolve() == repository / "PROJECT.md"


def test_cancelled_picker_never_resolves_or_launches(onboarding, monkeypatch):
    root, calls = onboarding
    project(root)
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput())
    monkeypatch.setattr(remediation, "_project", lambda *_: pytest.fail("cancel must not prepare a project"))
    with pytest.raises(SystemExit, match="cancelled|closed"):
        cli.main(["--root", str(root), "remediation", "start"])
    assert calls == []


def test_session_recovery_skips_client_question_and_preserves_identity(onboarding, monkeypatch):
    root, calls = onboarding
    project(root)
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput("1\n"))
    identity = "0c060c49-99de-4dd7-b3d8-a6c195cc6420"
    cli.main(["--root", str(root), "remediation", "start", "--session-id", identity])
    assert (calls[0][0].client, calls[0][0].session_id) == ("claude", identity)


def test_recovery_without_projects_fails_before_creation_or_launch(onboarding, monkeypatch):
    root, calls = onboarding
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput())
    monkeypatch.setattr(cli, "_engagement_create", lambda *_: pytest.fail("recovery must retain the original engagement"))
    monkeypatch.setattr(remediation, "_project", lambda *_: pytest.fail("no project was selected"))
    with pytest.raises(SystemExit, match="No remediation engagements.*recovery"):
        cli.main(["--root", str(root), "remediation", "start", "--session-id",
                  "0c060c49-99de-4dd7-b3d8-a6c195cc6420"])
    assert calls == []
    assert list(root.iterdir()) == []


def test_recovery_picker_exposes_only_existing_remediation_projects(onboarding, monkeypatch):
    root, calls = onboarding
    directory, _ = project(root)
    project(root, "acme-web", kind="web")
    monkeypatch.setattr(cli.sys, "stdin", TerminalInput())
    seen = []

    def select(_label, _default, choices, **kwargs):
        seen.extend(choices)
        return choices[0]

    monkeypatch.setattr(remediation, "prompt_choice", select)
    monkeypatch.setattr(cli, "_engagement_create", lambda *_: pytest.fail("recovery must use its recorded engagement"))
    cli.main(["--root", str(root), "remediation", "start", "--session-id",
              "0c060c49-99de-4dd7-b3d8-a6c195cc6420"])
    assert len(seen) == 1
    assert seen[0].startswith("acme · in_progress · acme · recent ")
    assert (calls[0][1], calls[0][0].client) == (directory, "claude")


def test_other_remediation_commands_keep_ambient_resolution(onboarding, monkeypatch, capsys):
    root, _ = onboarding
    project(root)
    monkeypatch.setenv("ENGAGEMENT_KEY", "acme")
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO())
    monkeypatch.setattr(remediation, "_api", lambda *_: [])
    cli.main(["--root", str(root), "remediation", "list", "--json"])
    assert json.loads(capsys.readouterr().out) == []
