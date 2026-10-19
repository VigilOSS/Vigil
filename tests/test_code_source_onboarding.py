from __future__ import annotations

import json
import io
from pathlib import Path

import pytest

from vigil_cli import engagements
from vigil_cli.main import main


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(Path(__file__).resolve().parents[1]))
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setattr(engagements, "_install_client_kind", lambda *_: "both")
    return root


def _code_engagement(workspace):
    return engagements.create_engagement(
        engagements.CreateEngagementOptions(install_root=workspace, engagement_type="code", name="Acme"),
        contact_backend=False,
    ).path


def test_empty_code_creation_shows_source_location_without_optional_web_services(workspace, capsys):
    path = _code_engagement(workspace)
    output = capsys.readouterr().err
    assert str(path / "source") in output
    assert "mitmproxy" not in output
    assert "oob" not in output
    assert not list((path / "source").iterdir())


def test_interactive_code_creation_needs_only_type_name_and_confirmation(workspace, monkeypatch, capsys):
    from vigil_cli import main as main_module

    class TerminalInput(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(main_module.sys, "stdin", TerminalInput("code\nAcme\ny\n"))
    monkeypatch.setattr(main_module, "_uses_prompt_ui", lambda: False)
    monkeypatch.setattr(engagements, "_verify_backend_install_root", lambda *_: engagements.BackendInstallRootStatus.VERIFIED)
    main(["--root", str(workspace), "engagement", "create"])
    output = capsys.readouterr()
    path = Path(output.out.strip())
    assert path.parent == workspace / "engagements"
    assert not list((path / "source").iterdir())
    assert str(path / "source") in output.err
    assert "repos" not in json.loads((path / "engagement.json").read_text())


@pytest.mark.parametrize("layout", ["empty", "metadata", "loose", "nested"])
def test_mode_reports_source_files_without_requiring_git(workspace, capsys, layout):
    path = _code_engagement(workspace)
    source = path / "source"
    if layout == "metadata":
        (source / ".git").mkdir()
        (source / ".git/config").write_text("fixture metadata\n")
    elif layout == "loose":
        (source / "acme.py").write_text("print('Acme')\n")
    elif layout == "nested":
        (source / "acme").mkdir()
        (source / "acme/main.txt").write_text("Acme source\n")
    main(["--root", str(workspace), "engagement", "mode", path.name, "--json"])
    state = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert state.get("source") == {
        "path": str(source),
        "state": "present" if layout in {"loose", "nested"} else "waiting",
        "file_count": 1 if layout in {"loose", "nested"} else 0,
        "entries": [] if layout in {"empty", "metadata"} else ["acme.py" if layout == "loose" else "acme"],
    }


def test_source_state_updates_when_files_are_added_after_creation(workspace):
    path = _code_engagement(workspace)
    before = engagements.engagement_mode_state(workspace, path)
    assert before.get("source", {}).get("state") == "waiting"
    (path / "source/acme.py").write_text("print('Acme')\n")
    after = engagements.engagement_mode_state(workspace, path)
    assert after.get("source", {}).get("state") == "present"


@pytest.mark.parametrize("reference", ["./acme", "https://example.com/acme.git"])
def test_code_creation_rejects_source_references(workspace, reference):
    with pytest.raises(SystemExit, match="source/"):
        engagements.plan_engagement(engagements.CreateEngagementOptions(
            install_root=workspace, engagement_type="code", name="Acme", repos=[reference],
        ))


def test_source_unavailable_is_distinct_from_an_empty_folder(workspace):
    path = _code_engagement(workspace)
    (path / "source").rmdir()
    (path / "source").write_text("Acme\n")
    source = engagements.engagement_mode_state(workspace, path)["source"]
    assert source["state"] == "unavailable"
    assert source["detail"]


def test_unreadable_source_is_unavailable_instead_of_waiting(workspace, monkeypatch):
    path = _code_engagement(workspace)
    original_stat = Path.stat

    def denied(source, *args, **kwargs):
        if source == path / "source":
            raise PermissionError("Acme source cannot be inspected")
        return original_stat(source, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", denied)
    source = engagements.engagement_mode_state(workspace, path)["source"]
    assert source["state"] == "unavailable"
    assert "cannot be inspected" in source["detail"]


@pytest.mark.parametrize("client", ["claude", "codex"])
@pytest.mark.parametrize("message", [None, "Focus on Acme's parser."])
def test_code_client_starts_with_source_confirmation_before_user_context(workspace, monkeypatch, client, message):
    path = _code_engagement(workspace)
    monkeypatch.chdir(workspace)
    launched = []
    monkeypatch.setattr(engagements.os, "execv", lambda executable, argv: launched.append(argv))
    args = ["--model", "acme-model"] + ([message] if message else [])
    engagements.start_engagement(workspace, path, client, args)
    assert len(launched) == 1
    assert launched[0][1:3] == ["--model", "acme-model"]
    assert len(launched[0]) == 4
    assert "confirm" in launched[0][-1].lower()
    assert "source" in launched[0][-1].lower()
    if message:
        assert launched[0][-1].endswith(message)


@pytest.mark.parametrize("client", ["claude", "codex"])
@pytest.mark.parametrize("message", [None, "Focus on Acme's parser."])
def test_start_no_autoprompt_preserves_only_explicit_client_arguments(workspace, monkeypatch, client, message):
    path = _code_engagement(workspace)
    monkeypatch.chdir(workspace)
    launched = []
    monkeypatch.setattr(engagements.os, "execv", lambda executable, argv: launched.append(argv))
    forwarded = ["--model", "acme-model"] + ([message] if message else [])
    main([
        "--root", str(workspace), "engagement", "start", path.name,
        "--client", client, "--no-autoprompt", "--skip-preflight", *forwarded,
    ])
    assert len(launched) == 1
    assert launched[0][1:] == forwarded


@pytest.mark.parametrize(("client", "forwarded"), [
    ("codex", ["resume"]),
    ("codex", ["resume", "acme-session"]),
    ("codex", ["resume", "--last"]),
    ("codex", ["--model", "acme-model", "resume", "acme-session"]),
    ("codex", ["resume", "acme-session", "Focus on Acme's parser."]),
    ("claude", ["-r"]),
    ("claude", ["-r", "acme-session"]),
    ("claude", ["--resume"]),
    ("claude", ["--resume", "acme-session"]),
    ("claude", ["--resume=acme-session"]),
    ("claude", ["--resume", "acme-session", "Focus on Acme's parser."]),
])
def test_resume_starts_preserve_client_arguments_without_automatic_message(workspace, monkeypatch, client, forwarded):
    path = _code_engagement(workspace)
    monkeypatch.chdir(workspace)
    launched = []
    monkeypatch.setattr(engagements.os, "execv", lambda executable, argv: launched.append(argv))
    main([
        "--root", str(workspace), "engagement", "start", path.name,
        "--client", client, "--skip-preflight", *forwarded,
    ])
    assert len(launched) == 1
    assert launched[0][1:] == forwarded


_SOURCE_TRUST_CONFIRMATION = (
    "Confirm these are the intended source files and that you trust this repository's "
    "build and test code to run inside the Vigil runtime."
)


def test_source_confirmation_asks_for_repository_trust_at_creation_and_start(workspace, monkeypatch, capsys):
    path = _code_engagement(workspace)
    assert _SOURCE_TRUST_CONFIRMATION in capsys.readouterr().err
    monkeypatch.chdir(workspace)
    launched = []
    monkeypatch.setattr(engagements.os, "execv", lambda executable, argv: launched.append(argv))
    engagements.start_engagement(workspace, path, "claude", [])
    assert _SOURCE_TRUST_CONFIRMATION in launched[0][-1]
