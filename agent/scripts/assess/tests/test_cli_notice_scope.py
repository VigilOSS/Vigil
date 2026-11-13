"""Every top-level `vigil assess` invocation is one run for once-per-run notices."""
from __future__ import annotations

import os

from assess import cli
from assess.commands import list_commands
from assess.lib import run_notices


def test_a_top_level_invocation_prints_a_repeated_advisory_once(monkeypatch, capsys) -> None:
    monkeypatch.delenv(run_notices.ENV_VAR, raising=False)

    def verb(_args) -> None:
        run_notices.emit_once("acme-advisory", "acme advisory (not repeated this run)")
        run_notices.emit_once("acme-advisory", "acme advisory (not repeated this run)")

    monkeypatch.setattr(list_commands, "run", verb)
    cli.main(["list-commands"])

    assert capsys.readouterr().err.count("acme advisory") == 1
    assert run_notices.ENV_VAR not in os.environ
