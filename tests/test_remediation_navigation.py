from __future__ import annotations

import argparse
import json
import shlex
from dataclasses import replace
from types import SimpleNamespace

import pytest

from vigil_cli import remediation, restart_manifest


CASES = [
    {"id": 12, "engagement_id": 5, "source_type": "jira", "source_key": "ACME-7", "title": "Earlier open case",
     "status": "fixing", "updated_at": "2026-01-01 00:00:00"},
    {"id": 41, "engagement_id": 5, "source_type": "manual", "source_key": "report-41", "title": "Closed case",
     "status": "closed", "updated_at": "2026-03-01 00:00:00"},
    {"id": 27, "engagement_id": 5, "source_type": "jira", "source_key": "ACME-42", "title": "Latest open case",
     "status": "review", "updated_at": "2026-02-01 00:00:00"},
]


def arguments(*argv):
    parser = argparse.ArgumentParser()
    remediation.register_remediation_parser(parser.add_subparsers(dest="command"))
    return parser.parse_args(["remediation", *argv])


@pytest.fixture
def navigation(tmp_path, monkeypatch):
    projects = {}
    for key, kind, created in (("acme-old", "remediation", "2026-01-01"),
                               ("acme-new", "remediation", "2026-02-01"),
                               ("acme-web", "web", "2026-03-01")):
        path = tmp_path / "engagements" / key
        path.mkdir(parents=True)
        (path / "scope.json").write_text(json.dumps({"engagement_type": kind, "status": "in_progress"}))
        (path / "engagement.json").write_text(json.dumps({"created_at": created, "target": "Acme"}))
        projects[key] = path
    calls = []
    selections = []
    monkeypatch.delenv("ENGAGEMENT_KEY", raising=False)
    monkeypatch.setattr(remediation, "_project", lambda root, key: (projects[key], {"repository": str(tmp_path)}))
    monkeypatch.setattr(remediation, "_api", lambda root, path, key, method, suffix, *rest: [dict(row) for row in CASES])
    monkeypatch.setattr(remediation, "_case", lambda *a: {"id": a[-1]})
    monkeypatch.setattr(restart_manifest, "backend_state", lambda *a, **kw: restart_manifest.ConsumerState(
        "backend", "backend", "current", "", ""))
    monkeypatch.setattr(remediation, "run_session_command", lambda args, *a, **kw: calls.append(
        (args.remediation_command, args.engagement_key, getattr(args, "case_id", None))) or 0)
    monkeypatch.setattr(remediation.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(remediation.shutil, "which", lambda _: None)
    monkeypatch.setattr("builtins.input", lambda *_: "1")
    return SimpleNamespace(root=tmp_path, projects=projects, calls=calls, selections=selections)


def test_start_and_join_are_the_primary_parser_actions():
    parser = argparse.ArgumentParser()
    remediation.register_remediation_parser(parser.add_subparsers(dest="command"))
    group = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    commands = next(action for action in group.choices["remediation"]._actions
                    if isinstance(action, argparse._SubParsersAction))
    assert list(commands.choices)[:2] == ["start", "join"]


def test_join_accepts_an_optional_numeric_case_id():
    assert arguments("join").case_id is None
    assert arguments("-k", "acme-old", "join", "27").case_id == "27"


def test_list_names_case_ids_and_exact_commands(navigation, capsys):
    remediation.run_remediation(arguments("-k", "acme-old", "list"), navigation.root)
    output = capsys.readouterr().out
    assert "case_id=27" in output and "ACME-42" in output
    assert output.index("case_id=27") < output.index("case_id=12") < output.index("case_id=41")
    assert shlex.join(["vigil", "--root", str(navigation.root), "remediation", "-k", "acme-old", "join", "27"]) in output
    assert "start" in output and "join" in output


def test_list_json_preserves_records_and_adds_unambiguous_join_identity(navigation, capsys):
    remediation.run_remediation(arguments("-k", "acme-old", "list", "--json"), navigation.root)
    rows = json.loads(capsys.readouterr().out)
    assert [row["case_id"] for row in rows] == [27, 12, 41]
    for row in rows:
        assert row["case_id"] == row["id"]
        original = next(item for item in CASES if item["id"] == row["id"])
        assert all(row[key] == value for key, value in original.items())
        assert row["engagement_key"] == "acme-old"
        assert shlex.split(row["join_command"]) == [
            "vigil", "--root", str(navigation.root), "remediation", "-k", "acme-old", "join", str(row["id"]),
        ]


def test_join_without_id_selects_only_remediation_projects_then_recent_open_cases(navigation, monkeypatch, capsys):
    # A launched session's environment must not silently bypass the project picker.
    monkeypatch.setenv("ENGAGEMENT_KEY", "acme-web")
    monkeypatch.setattr("builtins.input", lambda *_: "2" if not navigation.selections else "1")
    # Capture the shared engagement picker's rows without launching a native client.
    from vigil_cli import engagements
    def select(rows):
        navigation.selections.append([row.key for row in rows])
        return rows[1]
    monkeypatch.setattr(engagements, "_select_engagement", select)
    remediation.run_remediation(arguments("join"), navigation.root)
    assert navigation.selections == [["acme-old", "acme-new"]]
    assert navigation.calls == [("join", "acme-new", "27")]
    assert "#27" in capsys.readouterr().err


def test_join_with_project_skips_project_selection(navigation, monkeypatch):
    from vigil_cli import engagements
    monkeypatch.setattr(engagements, "_select_engagement", lambda *_: pytest.fail("project was explicit"))
    remediation.run_remediation(arguments("-k", "acme-old", "join"), navigation.root)
    assert navigation.calls == [("join", "acme-old", "27")]


def test_explicit_join_is_noninteractive(navigation, monkeypatch):
    monkeypatch.setattr(remediation.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("explicit join must not prompt"))
    remediation.run_remediation(arguments("-k", "acme-old", "join", "12"), navigation.root)
    assert navigation.calls == [("join", "acme-old", "12")]


def test_missing_id_in_a_noninteractive_process_explains_explicit_join(navigation, monkeypatch):
    monkeypatch.setattr(remediation.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(remediation, "_api", lambda *a: pytest.fail("no backend lookup before a usable selection"))
    with pytest.raises(SystemExit, match="case_id"):
        remediation.run_remediation(arguments("join"), navigation.root)
    assert navigation.calls == []


@pytest.mark.parametrize("choice", ["0", "999", "invalid", ""])
def test_invalid_case_selection_does_not_attach(navigation, monkeypatch, choice):
    monkeypatch.setattr("builtins.input", lambda *_: choice)
    with pytest.raises(SystemExit, match="selection"):
        remediation.run_remediation(arguments("-k", "acme-old", "join"), navigation.root)
    assert navigation.calls == []


def test_empty_case_list_explains_start(navigation, monkeypatch):
    monkeypatch.setattr(remediation, "_api", lambda *a: [])
    with pytest.raises(SystemExit, match="start"):
        remediation.run_remediation(arguments("-k", "acme-old", "join"), navigation.root)
    assert navigation.calls == []


def test_case_picker_cancellation_does_not_attach(navigation, monkeypatch):
    monkeypatch.setattr(remediation.shutil, "which", lambda _: "/usr/bin/fzf")
    monkeypatch.setattr(remediation.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=130, stdout=""))
    with pytest.raises(SystemExit, match="cancelled"):
        remediation.run_remediation(arguments("-k", "acme-old", "join"), navigation.root)
    assert navigation.calls == []


@pytest.mark.parametrize("invalid", [[{"id": "27"}], [{"id": True}], [{"id": 27}, {"id": 27}]])
def test_invalid_backend_identities_do_not_attach(navigation, monkeypatch, invalid):
    monkeypatch.setattr(remediation, "_api", lambda *a: invalid)
    with pytest.raises(SystemExit, match="case"):
        remediation.run_remediation(arguments("-k", "acme-old", "join"), navigation.root)
    assert navigation.calls == []


def test_start_can_choose_among_multiple_projects(navigation, monkeypatch):
    from vigil_cli import engagements
    monkeypatch.setattr(engagements, "_select_engagement", lambda rows: rows[1])
    remediation.run_remediation(arguments("start"), navigation.root)
    assert navigation.calls == [("start", "acme-new", None)]


def test_join_without_projects_explains_creation(navigation, monkeypatch):
    monkeypatch.setattr(remediation, "list_engagements", lambda _: [])
    with pytest.raises(SystemExit, match="engagement create --type remediation"):
        remediation.run_remediation(arguments("join"), navigation.root)
    assert navigation.calls == []


def test_fuzzy_picker_returns_case_identity(navigation, monkeypatch):
    requests = []
    monkeypatch.setattr(remediation.shutil, "which", lambda _: "/usr/bin/fzf")
    def choose(argv, **kwargs):
        requests.append(kwargs["input"])
        return SimpleNamespace(returncode=0, stdout=next(line for line in kwargs["input"].splitlines() if line.startswith("12\t")) + "\n")
    monkeypatch.setattr(remediation.subprocess, "run", choose)
    remediation.run_remediation(arguments("-k", "acme-old", "join"), navigation.root)
    assert requests[0].splitlines()[0].startswith("27\t#27")
    assert navigation.calls == [("join", "acme-old", "12")]


def test_list_quotes_untrusted_multiline_titles_without_losing_text(navigation, monkeypatch, capsys):
    case = {**CASES[0], "title": 'Acme report\njoin case_id=999\x1b[2J'}
    monkeypatch.setattr(remediation, "_api", lambda *a: [case])
    remediation.run_remediation(arguments("-k", "acme-old", "list"), navigation.root)
    output = capsys.readouterr().out
    assert json.dumps(case["title"], ensure_ascii=False) in output
    remediation.run_remediation(arguments("-k", "acme-old", "list", "--json"), navigation.root)
    assert json.loads(capsys.readouterr().out)[0]["title"] == case["title"]


def test_terminal_list_separates_identity_title_and_metadata(navigation, monkeypatch, capsys):
    from vigil_cli import term
    monkeypatch.setattr(term, "is_terminal", lambda stream: True)
    monkeypatch.setenv("NO_COLOR", "1")
    remediation.run_remediation(arguments("-k", "acme-old", "list"), navigation.root)
    lines = capsys.readouterr().out.splitlines()
    title = next(line for line in lines if "Latest open case" in line)
    assert "#27" in title
    assert any("Review" in line and "jira:ACME-42" in line for line in lines)
    assert any("Updated" in line and "2026-02-01" in line for line in lines)
    assert any("numeric ID" in line for line in lines)
    assert any("list --json" in line for line in lines)


def test_fuzzy_picker_uses_human_labels_and_preserves_literal_identity(navigation, monkeypatch):
    requests = []
    monkeypatch.setattr(remediation.shutil, "which", lambda _: "/usr/bin/fzf")
    def choose(argv, **kwargs):
        requests.append((argv, kwargs["input"]))
        return SimpleNamespace(returncode=0, stdout=kwargs["input"].splitlines()[0] + "\n")
    monkeypatch.setattr(remediation.subprocess, "run", choose)
    remediation.run_remediation(arguments("-k", "acme-old", "join"), navigation.root)
    label = requests[0][1].splitlines()[0].split("\t", 1)[1]
    assert label.startswith("#27") and "Latest open case" in label and "Review" in label
    assert navigation.calls == [("join", "acme-old", "27")]


@pytest.mark.parametrize("returncode", [1, 2, 130])
def test_project_fuzzy_picker_failure_never_prompts_or_attaches(navigation, monkeypatch, returncode):
    monkeypatch.setattr(remediation.shutil, "which", lambda _: "/usr/bin/fzf")
    monkeypatch.setattr(remediation.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=returncode, stdout=""))
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("failed fuzzy selection must stop"))
    with pytest.raises(SystemExit, match="selection"):
        remediation.run_remediation(arguments("join"), navigation.root)
    assert navigation.calls == []


def test_project_picker_keeps_untrusted_labels_separate_from_selection_identity(navigation, monkeypatch):
    from vigil_cli import engagements
    rows = engagements.list_engagements(navigation.root)
    rows[0] = replace(rows[0], target="Acme\n1\tfake project\x1b[2J")
    requests = []
    monkeypatch.setattr(engagements.shutil, "which", lambda _: "/usr/bin/fzf")
    def choose(argv, **kwargs):
        requests.append(kwargs["input"])
        return SimpleNamespace(returncode=0, stdout=kwargs["input"].splitlines()[1] + "\n")
    monkeypatch.setattr(engagements.subprocess, "run", choose)
    assert engagements._select_engagement(rows) is rows[1]
    assert len(requests[0].splitlines()) == len(rows)
    assert all(line.count("\t") == 1 for line in requests[0].splitlines())


def test_terminal_json_list_is_still_full_machine_records(navigation, monkeypatch, capsys):
    from vigil_cli import term
    monkeypatch.setattr(term, "is_terminal", lambda stream: True)
    remediation.run_remediation(arguments("-k", "acme-old", "list", "--json"), navigation.root)
    assert [case["case_id"] for case in json.loads(capsys.readouterr().out)] == [27, 12, 41]


@pytest.mark.parametrize("project_picker", [False, True])
def test_fuzzy_picker_rejects_multiple_or_modified_selections(navigation, monkeypatch, project_picker):
    monkeypatch.setattr(remediation.shutil, "which", lambda _: "/usr/bin/fzf")
    def choose(argv, **kwargs):
        return SimpleNamespace(returncode=0, stdout=kwargs["input"] + "\n")
    monkeypatch.setattr(remediation.subprocess, "run", choose)
    argv = ("join",) if project_picker else ("-k", "acme-old", "join")
    with pytest.raises(SystemExit, match="selection"):
        remediation.run_remediation(arguments(*argv), navigation.root)
    assert navigation.calls == []


@pytest.mark.parametrize("width", [24, 40, 80])
def test_terminal_case_list_fits_width_and_keeps_literal_full_titles(navigation, monkeypatch, capsys, width):
    from vigil_cli import term
    monkeypatch.setattr(term, "is_terminal", lambda stream: True)
    monkeypatch.setenv("COLUMNS", str(width))
    monkeypatch.setenv("NO_COLOR", "1")
    title = "[red]" + "Acme" * 35 + "\x1b[2J"
    cases = [{**CASES[0], "title": title}]
    remediation._print_case_list(navigation.root, "acme-" * 15, cases, as_json=False)
    output = capsys.readouterr().out
    assert all(len(line) <= width for line in output.splitlines())
    assert "[red]" in output and "\\u001b" in "".join(output.split())
    assert "ID" in output and "#12" in output


def test_case_picker_preview_uses_literal_details_and_cleans_up(navigation, monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(remediation.shutil, "which", lambda _: "/usr/bin/fzf")
    monkeypatch.setenv("COLUMNS", "60")
    paths = []
    def choose(argv, **kwargs):
        import shlex
        assert "down" in argv[argv.index("--preview-window") + 1]
        command = shlex.split(argv[argv.index("--preview") + 1])
        preview_dir = Path(command[-2])
        paths.append(preview_dir)
        assert "$(touch /tmp/acme)" in (preview_dir / "12").read_text()
        assert "\\u001b" in (preview_dir / "12").read_text()
        return SimpleNamespace(returncode=0, stdout=kwargs["input"].splitlines()[0] + "\n")
    monkeypatch.setattr(remediation.subprocess, "run", choose)
    case = {**CASES[0], "title": "[red]$(touch /tmp/acme)\x1b[2J"}
    assert remediation._select_case([case]) is case
    assert not paths[0].exists()


@pytest.mark.parametrize("width", [24, 40, 80])
def test_numbered_project_picker_wraps_full_untrusted_values(navigation, monkeypatch, capsys, width):
    from vigil_cli import engagements
    from rich.cells import cell_len
    monkeypatch.setenv("COLUMNS", str(width))
    monkeypatch.setenv("NO_COLOR", "1")
    value = "[blue]" + "界Acme" * 20 + "\x1b[2J"
    row = replace(engagements.list_engagements(navigation.root)[0], key=value, target=value)
    assert engagements._select_engagement([row]) is row
    output = capsys.readouterr().err
    assert all(cell_len(line) <= width for line in output.splitlines())
    assert term_literal(value) in "".join(output.split())


def term_literal(value):
    from vigil_cli import term
    return "".join(term.single_line(value).split())


def test_fuzzy_preview_reader_renders_data_without_shell_evaluation(navigation, monkeypatch):
    import subprocess
    from vigil_cli import term
    run = subprocess.run
    payload = "[red]$(printf forged) `printf forged`\nAcme\x1b[2J"
    def choose(argv, **kwargs):
        preview = argv[argv.index("--preview") + 1].replace("{1}", "12")
        result = run(preview, shell=True, text=True, capture_output=True, check=True)
        assert result.stdout == term.single_line(payload)
        return SimpleNamespace(returncode=0, stdout=kwargs["input"] + "\n")
    monkeypatch.setattr(subprocess, "run", choose)
    assert term.fuzzy_pick(["12\tAcme"], {"12": term.single_line(payload)}, prompt="Case > ", action="join",
                           cancelled="cancelled", invalid="invalid") == 0


def test_case_picker_keeps_source_ticket_searchable(navigation, monkeypatch):
    monkeypatch.setattr(remediation.shutil, "which", lambda _: "/usr/bin/fzf")
    def choose(argv, **kwargs):
        line = next(line for line in kwargs["input"].splitlines() if line.startswith("27\t"))
        label = line.split("\t", 1)[1]
        assert "jira:ACME-42" in label
        return SimpleNamespace(returncode=0, stdout=line + "\n")
    monkeypatch.setattr(remediation.subprocess, "run", choose)
    assert remediation._select_case(CASES)["id"] == 27


def test_project_picker_keeps_target_and_phase_searchable(navigation, monkeypatch):
    from vigil_cli import engagements
    row = replace(engagements.list_engagements(navigation.root)[0], target="api.example.com", current_phase="verification")
    monkeypatch.setattr(engagements.shutil, "which", lambda _: "/usr/bin/fzf")
    def choose(argv, **kwargs):
        label = kwargs["input"].split("\t", 1)[1]
        assert "api.example.com" in label and "verification" in label
        return SimpleNamespace(returncode=0, stdout=kwargs["input"] + "\n")
    monkeypatch.setattr(engagements.subprocess, "run", choose)
    assert engagements._select_engagement([row]) is row


@pytest.mark.parametrize(("key", "label"), [("2026-10-20-123045-Acme", "Acme"), ("2026-10-Acme", "2026-10-Acme"), ("Acme", "Acme")])
def test_project_picker_leads_with_friendly_name_and_retains_full_identity(navigation, monkeypatch, key, label):
    from vigil_cli import engagements
    row = replace(engagements.list_engagements(navigation.root)[0], key=key)
    monkeypatch.setattr(engagements.shutil, "which", lambda _: "/usr/bin/fzf")
    def pick(lines, details, **kwargs):
        display = lines[0].split("\t", 1)[1]
        assert display.startswith(label + "  ")
        assert key in display
        assert str(row.path) in details["0"]
        return 0
    monkeypatch.setattr(engagements.term, "fuzzy_pick", pick)
    assert engagements._select_engagement([row]) is row


def test_remediation_project_selection_fits_narrow_terminal(navigation, monkeypatch, capsys):
    from rich.cells import cell_len
    monkeypatch.setenv("COLUMNS", "24")
    monkeypatch.setenv("NO_COLOR", "1")
    assert remediation._select_project(remediation._remediation_projects(navigation.root)) == "acme-old"
    assert all(cell_len(line) <= 24 for line in capsys.readouterr().err.splitlines())


@pytest.mark.parametrize("choose_project", [False, True])
def test_dumb_terminal_uses_numbered_selection(navigation, monkeypatch, capsys, choose_project):
    monkeypatch.setenv("TERM", "dumb")
    monkeypatch.setattr(remediation.shutil, "which", lambda _: "/usr/bin/fzf")
    monkeypatch.setattr(remediation.subprocess, "run", lambda *a, **kw: pytest.fail("cursor UI is unavailable on this terminal"))
    argv = ("join",) if choose_project else ("-k", "acme-old", "join")
    remediation.run_remediation(arguments(*argv), navigation.root)
    assert navigation.calls == [("join", "acme-old", "27")]
    assert "#27" in capsys.readouterr().err
