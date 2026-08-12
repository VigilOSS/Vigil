"""CLI contract tests for the dynamic fixture manifest command."""
from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import sys
from io import StringIO
from pathlib import Path

import pytest


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_cmd():
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    spec = importlib.util.spec_from_file_location(
        "fixture_identity_cmd_ut",
        _scripts_root() / "assess" / "commands" / "fixture_identity.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _parser(cmd) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    cmd.register(subparsers)
    return parser


def test_fixture_cli_observe_then_resolve(tmp_path, capsys) -> None:
    cmd = _load_cmd()
    payload = tmp_path / "response.json"
    payload.write_text(
        json.dumps(
            {
                "data": {"type": "Person", "id": "person-new"},
                "meta": {"parent": {"type": "Organization", "id": "org-new"}},
            }
        ),
        encoding="utf-8",
    )
    manifest = tmp_path / "fixtures.json"
    parser = _parser(cmd)

    observe = parser.parse_args(
        [
            "fixture",
            "observe",
            "org3.admin",
            str(payload),
            "--manifest",
            str(manifest),
            "--json",
        ]
    )
    cmd.run(observe)
    assert json.loads(capsys.readouterr().out)["observed"] == {
        "organization_id": "org-new",
        "person_id": "person-new",
    }

    resolve = parser.parse_args(
        [
            "fixture",
            "resolve",
            "org3.admin.organization_id",
            "--manifest",
            str(manifest),
            "--json",
        ]
    )
    cmd.run(resolve)
    assert json.loads(capsys.readouterr().out)["id"] == "org-new"


def test_fixture_cli_observe_reads_stdin(monkeypatch, tmp_path, capsys) -> None:
    cmd = _load_cmd()
    manifest = tmp_path / "fixtures.json"
    parser = _parser(cmd)
    observe = parser.parse_args(
        ["fixture", "observe", "stdin-fixture", "--manifest", str(manifest), "--json"]
    )
    monkeypatch.setattr(
        sys,
        "stdin",
        StringIO('{"data":{"type":"Subscription","id":"sub-1"}}'),
    )

    cmd.run(observe)

    assert json.loads(capsys.readouterr().out)["observed"] == {
        "subscription_id": "sub-1"
    }


def test_fixture_cli_fails_closed_without_ids(tmp_path, capsys) -> None:
    cmd = _load_cmd()
    payload = tmp_path / "no-ids.json"
    payload.write_text(json.dumps({"data": {"type": "Widget", "id": "opaque"}}), encoding="utf-8")
    manifest = tmp_path / "fixtures.json"
    parser = _parser(cmd)
    observe = parser.parse_args(
        ["fixture", "observe", "empty", str(payload), "--manifest", str(manifest)]
    )

    with pytest.raises(SystemExit) as excinfo:
        cmd.run(observe)

    assert excinfo.value.code == 1
    assert "no recognized concrete fixture ids" in capsys.readouterr().err
    assert not manifest.exists()


def test_fixture_cli_replace_is_explicit(tmp_path, capsys) -> None:
    cmd = _load_cmd()
    payload = tmp_path / "response.json"
    manifest = tmp_path / "fixtures.json"
    parser = _parser(cmd)

    def observe(value: str, *extra: str) -> None:
        payload.write_text(
            json.dumps({"data": {"type": "Organization", "id": value}}),
            encoding="utf-8",
        )
        args = parser.parse_args(
            [
                "fixture",
                "observe",
                "rotating",
                str(payload),
                "--manifest",
                str(manifest),
                *extra,
            ]
        )
        cmd.run(args)
        capsys.readouterr()

    observe("org-old")
    with pytest.raises(SystemExit) as excinfo:
        observe("org-new")
    assert excinfo.value.code == 1
    assert "already binds" in capsys.readouterr().err
    observe("org-new", "--replace")

    resolve = parser.parse_args(
        ["fixture", "resolve", "rotating.organization_id", "--manifest", str(manifest)]
    )
    cmd.run(resolve)
    assert capsys.readouterr().out.strip() == "org-new"


def test_fixture_cli_requires_manifest() -> None:
    cmd = _load_cmd()
    parser = _parser(cmd)
    try:
        parser.parse_args(["fixture", "resolve", "org3.organization_id"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("fixture resolve must require --manifest")


def test_fixture_contract_is_registered() -> None:
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    from assess.lib import contracts

    contract = contracts.get_contract("fixture")
    assert contract is not None
    assert "fixture observe" in " ".join(contract.preferred_invocations)
    assert "fixture resolve" in " ".join(contract.preferred_invocations)


def test_assess_cli_wires_fixture_command() -> None:
    cli_path = _scripts_root() / "assess" / "cli.py"
    source = cli_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "assess.commands":
            imported.update(alias.name for alias in node.names)
    assert "fixture_identity" in imported
    assert "fixture_identity," in source
