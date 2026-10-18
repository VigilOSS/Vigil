from __future__ import annotations

import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from vigil_cli import main


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "project"
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    return repo


@pytest.mark.parametrize("explicit", [False, True])
def test_interactive_remediation_collects_and_binds_local_repository(
    tmp_path, repository, monkeypatch, capsys, explicit,
):
    monkeypatch.setattr(main.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    answers = iter((["4"] if not explicit else []) + ["Project", str(repository)])
    monkeypatch.setattr("builtins.input", lambda: next(answers))
    flags = ["--type", "remediation"] if explicit else []
    main.main(["--root", str(tmp_path / "install"), "engagement", "create", *flags, "--dry-run", "--json"])
    plan = json.loads(capsys.readouterr().out)
    assert plan["scope"]["engagement_type"] == "remediation"
    assert plan["manifest"]["repos"] == [{"path": str(repository), "name": "project"}]
    assert not (tmp_path / "install").exists()


def test_missing_type_error_advertises_remediation(monkeypatch, capsys):
    monkeypatch.setattr(main.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(SystemExit, match="web\\|code\\|android\\|remediation"):
        main.main(["engagement", "create", "--no-prompt"])


@pytest.mark.parametrize("content", ["no frontmatter", None])
def test_bad_project_config_has_cli_error(tmp_path, repository, content):
    path = tmp_path / "PROJECT.md"
    if content is not None:
        path.write_text(content)
    with pytest.raises(SystemExit, match="--project-config"):
        main.main(["--root", str(tmp_path / "install"), "engagement", "create", "--type", "remediation",
                   "--name", "Project", "--repo", str(repository), "--project-config", str(path), "--no-prompt", "--dry-run"])


def test_terminal_choice_uses_keyboard_ui_on_stderr(monkeypatch, capsys):
    monkeypatch.setattr(main.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(main.term, "is_terminal", lambda _stream: True)

    def select(label, **kwargs):
        assert label == "Engagement type"
        assert kwargs["choices"] == ["web", "remediation"]
        assert kwargs["default"] == "web"
        print("keyboard selection")
        return SimpleNamespace(unsafe_ask=lambda: "remediation")

    monkeypatch.setitem(sys.modules, "questionary", SimpleNamespace(select=select))
    monkeypatch.setattr("builtins.input", lambda: pytest.fail("terminal UI must handle selection"))
    assert main._prompt_choice("Engagement type", "web", ["web", "remediation"]) == "remediation"
    output = capsys.readouterr()
    assert output.out == ""
    assert "keyboard selection" in output.err


def test_terminal_prompt_cancellation_is_clean(monkeypatch):
    monkeypatch.setattr(main.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(main.term, "is_terminal", lambda _stream: True)

    def cancel():
        raise KeyboardInterrupt

    monkeypatch.setitem(sys.modules, "questionary", SimpleNamespace(
        select=lambda *_args, **_kwargs: SimpleNamespace(unsafe_ask=cancel),
    ))
    monkeypatch.setattr("builtins.input", lambda: pytest.fail("terminal UI must handle cancellation"))
    with pytest.raises(SystemExit, match="cancelled"):
        main._prompt_choice("Engagement type", "web", ["web", "remediation"])


def test_repository_prompt_retries_invalid_directory(repository, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(main.term, "is_terminal", lambda _stream: False)
    answers = iter([str(tmp_path), str(repository)])
    monkeypatch.setattr("builtins.input", lambda: next(answers))
    assert main._ask_repository() == str(repository)
    assert "repository root" in capsys.readouterr().err


def test_repository_prompt_uses_directory_completion_and_shared_validation(repository, tmp_path, monkeypatch):
    monkeypatch.setattr(main.term, "is_terminal", lambda _stream: True)

    def path(label, **kwargs):
        assert label == "Repository root"
        assert kwargs["only_directories"] is True
        assert kwargs["validate_while_typing"] is False
        assert kwargs["validate"](str(repository)) is True
        assert isinstance(kwargs["validate"](str(tmp_path)), str)
        return SimpleNamespace(unsafe_ask=lambda: str(repository))

    monkeypatch.setitem(sys.modules, "questionary", SimpleNamespace(path=path))
    assert main._ask_repository() == str(repository)
