from __future__ import annotations

import argparse
import json
import shlex
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
    assert "case_id=27" in capsys.readouterr().err


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
        return SimpleNamespace(returncode=0, stdout='12\tcase_id=12 status="fixing"\n')
    monkeypatch.setattr(remediation.subprocess, "run", choose)
    remediation.run_remediation(arguments("-k", "acme-old", "join"), navigation.root)
    assert requests[0].splitlines()[0].startswith("27\tcase_id=27")
    assert navigation.calls == [("join", "acme-old", "12")]


def test_list_quotes_untrusted_multiline_titles_without_losing_text(navigation, monkeypatch, capsys):
    case = {**CASES[0], "title": 'Acme report\njoin case_id=999\x1b[2J'}
    monkeypatch.setattr(remediation, "_api", lambda *a: [case])
    remediation.run_remediation(arguments("-k", "acme-old", "list"), navigation.root)
    output = capsys.readouterr().out
    assert json.dumps(case["title"], ensure_ascii=False) in output
    remediation.run_remediation(arguments("-k", "acme-old", "list", "--json"), navigation.root)
    assert json.loads(capsys.readouterr().out)[0]["title"] == case["title"]
