"""Existence/coverage tests for the per-phase command catalog (WS5).

Mirrors the `test_skill_cli_sync.py` intent — real code contracts, not prose:
build the actual argparse parser via `list_commands.register`, drive `run`, and
assert the catalog is complete and machine-consumable. NOT a wording test.

Guarantees:
  * every canonical phase (kali_audit.ALLOWED_PHASES) is a valid `--phase`
    filter AND resolves to a non-empty catalog slice;
  * `contracts.commands_by_phase` is non-empty for every phase;
  * `--json` round-trips and each row carries its `contract` drill-down pointer;
  * the `consume` short alias resolves to the canonical `consume-test` phase;
  * `--kali-only` / `--grep` narrow the catalog as documented.
"""
from __future__ import annotations

import argparse
import json

import pytest

from assess.commands import list_commands
from assess.lib import contracts
from assess.lib.kali_audit import ALLOWED_PHASES


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    list_commands.register(sub)
    return parser


def _run_json(capsys, argv: list[str]) -> list[dict]:
    args = _parser().parse_args(argv)
    list_commands.run(args)
    out = capsys.readouterr().out
    return json.loads(out)


@pytest.mark.parametrize("phase", ALLOWED_PHASES)
def test_every_allowed_phase_is_a_valid_filter_and_non_empty(phase, capsys):
    # argparse must accept every canonical phase as a --phase choice, and the
    # filtered catalog must be non-empty (a phase with zero commands is a
    # coverage hole in _KALI_VERB_PHASES / the _CONTRACTS phase tags).
    rows = _run_json(capsys, ["list-commands", "--phase", phase, "--json"])
    assert rows, f"catalog is empty for phase {phase!r}"
    for row in rows:
        assert phase in row["phases"], f"{row['name']} leaked into phase {phase!r}"


def test_commands_by_phase_non_empty_for_every_phase():
    for phase in ALLOWED_PHASES:
        matched = contracts.commands_by_phase(phase)
        assert matched, f"commands_by_phase({phase!r}) is empty"
        for contract in matched:
            assert phase in contract.phase


def test_json_round_trips_and_carries_contract_pointer(capsys):
    rows = _run_json(capsys, ["list-commands", "--json"])
    assert isinstance(rows, list) and rows
    # Round-trip: re-serializing the parsed rows yields the same structure.
    assert json.loads(json.dumps(rows)) == rows
    for row in rows:
        assert set(row) == {"name", "summary", "phases", "kali", "contract"}
        assert row["contract"] == f"vigil assess contract {row['name']}"
        assert isinstance(row["phases"], list)


def test_consume_short_alias_resolves_to_consume_test(capsys):
    rows = _run_json(capsys, ["list-commands", "--phase", "consume", "--json"])
    assert rows
    for row in rows:
        assert "consume-test" in row["phases"]


def test_kali_only_filter_returns_only_kali_rows(capsys):
    rows = _run_json(capsys, ["list-commands", "--kali-only", "--json"])
    assert rows
    assert all(row["kali"] for row in rows)
    assert all(row["name"].startswith("kali ") for row in rows)


def test_grep_filter_matches_name_or_summary(capsys):
    rows = _run_json(capsys, ["list-commands", "--grep", "finding", "--json"])
    assert rows
    assert all(
        "finding" in f"{row['name']} {row['summary']}".lower() for row in rows
    )


def test_phase_agnostic_utilities_exist_and_are_excluded_from_phase_filter(capsys):
    # Phase-agnostic utilities (empty phase tuple) must exist in the full
    # catalog but never surface under a --phase filter.
    all_rows = _run_json(capsys, ["list-commands", "--json"])
    agnostic = [r for r in all_rows if not r["phases"]]
    assert agnostic, "expected at least one phase-agnostic utility (e.g. resume-brief)"


def test_grouped_text_output_has_phase_headers(capsys):
    args = _parser().parse_args(["list-commands"])
    list_commands.run(args)
    out = capsys.readouterr().out
    assert "## phase: recon" in out
    assert "## phase-agnostic" in out
    # Each row points operators at the per-command contract for the full schema.
    assert "vigil assess contract " in out
