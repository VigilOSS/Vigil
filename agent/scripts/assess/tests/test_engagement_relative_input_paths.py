"""Relative input paths resolve against the engagement when the cwd lacks them.

A client whose shell starts outside the engagement root (OpenCode runs its
specialists in ``<engagement>/clients/opencode/<mode>``) passes the same
engagement-relative paths that prompts and handoffs name. Every input-path
argument resolves through one helper: the path as given when it exists from the
working directory, otherwise the engagement-relative file, named on stderr.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assess import cli
from assess.commands import code_dispatch, ingest_spec, post, record_finding, verify_finding


def _engagement(tmp_path: Path) -> tuple[Path, Path]:
    engagement = tmp_path / "2026-11-15-000000-acme"
    (engagement / "scans").mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"hosts": ["acme.example"]}), encoding="utf-8")
    client_dir = engagement / "clients" / "opencode" / "web"
    client_dir.mkdir(parents=True)
    return engagement, client_dir


def _recorder(monkeypatch, module, seen: dict) -> None:
    monkeypatch.setattr(module, "run", lambda args: seen.update(vars(args)))


@pytest.mark.parametrize(
    ("module", "argv", "dest"),
    [
        (ingest_spec, ["ingest", "spec", "scans/input.json"], "spec_file"),
        (record_finding, ["finding", "record", "source-analyzer", "scans/input.json"], "json_file"),
        (post, ["post", "credentials", "scans/input.json"], "payload"),
        (
            verify_finding,
            ["finding", "verify", "SA-001", "--counter-check-file", "scans/input.json"],
            "counter_check_file",
        ),
    ],
)
def test_relative_input_absent_from_cwd_resolves_against_engagement(
    tmp_path, monkeypatch, capsys, module, argv, dest
) -> None:
    engagement, client_dir = _engagement(tmp_path)
    (engagement / "scans" / "input.json").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(client_dir)
    seen: dict = {}
    _recorder(monkeypatch, module, seen)

    cli.main(argv)

    resolved = str((engagement / "scans" / "input.json").resolve())
    assert seen[dest] == resolved
    err = capsys.readouterr().err
    assert "scans/input.json" in err and resolved in err


def test_relative_input_present_in_cwd_is_left_as_given(tmp_path, monkeypatch, capsys) -> None:
    engagement, client_dir = _engagement(tmp_path)
    (engagement / "scans" / "input.json").write_text("{}", encoding="utf-8")
    (client_dir / "scans").mkdir()
    (client_dir / "scans" / "input.json").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(client_dir)
    seen: dict = {}
    _recorder(monkeypatch, ingest_spec, seen)

    cli.main(["ingest", "spec", "scans/input.json"])

    assert seen["spec_file"] == "scans/input.json"
    assert "resolved" not in capsys.readouterr().err


def test_missing_input_and_inline_json_are_left_for_the_verb(tmp_path, monkeypatch, capsys) -> None:
    _engagement_dir, client_dir = _engagement(tmp_path)
    monkeypatch.chdir(client_dir)
    seen: dict = {}
    _recorder(monkeypatch, ingest_spec, seen)
    cli.main(["ingest", "spec", "scans/absent.json"])
    assert seen["spec_file"] == "scans/absent.json"

    seen.clear()
    _recorder(monkeypatch, post, seen)
    cli.main(["post", "credentials", '{"credential_key": "k"}'])
    assert seen["payload"] == '{"credential_key": "k"}'


def test_code_dispatch_ids_file_resolves_against_engagement(tmp_path, monkeypatch) -> None:
    engagement, client_dir = _engagement(tmp_path)
    (engagement / "scans" / "ids.txt").write_text("7\n9\n", encoding="utf-8")
    monkeypatch.chdir(client_dir)

    assert code_dispatch._ids_from_file("scans/ids.txt") == [7, 9]
