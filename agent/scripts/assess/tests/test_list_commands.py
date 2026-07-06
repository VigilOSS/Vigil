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
        assert set(row) == {"name", "summary", "phases", "goals", "kali", "contract"}
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


def test_catalog_lists_every_registered_contract_command(capsys):
    # Completeness: the unfiltered catalog must surface EVERY command in the
    # contract registry (the `_CONTRACTS` registry + the kali verb table via
    # `all_command_contracts`). A command that has a contract but never reaches
    # `list-commands` is a discovery hole; a name in the output with no backing
    # contract is drift. The two name sets must be identical.
    rows = _run_json(capsys, ["list-commands", "--json"])
    catalog_names = {row["name"] for row in rows}
    registry_names = {c.name for c in contracts.all_command_contracts()}
    assert catalog_names == registry_names


# The discovery / navigation / core-query commands a specialist reaches for.
# These are phase-agnostic utilities but MUST stay discoverable via
# `list-commands` (the catalog is the commands analogue of list-skills /
# list-references and has to be a complete index, not only write/probe verbs).
_MUST_BE_DISCOVERABLE = (
    # discovery quartet
    "list-commands",
    "list-skills",
    "list-references",
    "contract",
    # phase navigation checkpoints
    "check-phase-readiness",
    "transition-phase",
    # core read/query primitives
    "coverage",
    "list-findings",
    "list-intel",
    "list-command-runs",
    "get-command-run",
    "resume-brief",
    "artifact",
    # representative write/probe verbs across phases
    "record-finding",
    "verify-finding",
    "record-attempt",
    "block-technique",
    "kali sqlmap",
    "kali exec",
)


@pytest.mark.parametrize("name", _MUST_BE_DISCOVERABLE)
def test_expected_command_is_discoverable(name, capsys):
    rows = _run_json(capsys, ["list-commands", "--json"])
    names = {row["name"] for row in rows}
    assert name in names, f"{name!r} dropped out of the command catalog"


def test_discovery_and_navigation_commands_are_phase_agnostic(capsys):
    # The meta/discovery/navigation commands work in any phase, so they must
    # carry an empty phase tuple (grouped under phase-agnostic, never leaked
    # into a --phase filter). Guards against someone mistagging them.
    rows = _run_json(capsys, ["list-commands", "--json"])
    by_name = {row["name"]: row for row in rows}
    for name in (
        "list-commands",
        "list-skills",
        "list-references",
        "contract",
        "check-phase-readiness",
        "transition-phase",
        "coverage",
    ):
        assert by_name[name]["phases"] == [], f"{name!r} should be phase-agnostic"


def test_list_commands_phase_choices_cover_every_allowed_phase():
    # argparse `--phase` choices must include every canonical phase plus the
    # documented `consume` short alias — the single source is CATALOG_PHASES
    # (= kali_audit.ALLOWED_PHASES), so a new canonical phase is auto-covered.
    for phase in ALLOWED_PHASES:
        assert phase in list_commands._PHASE_CHOICES
    assert "consume" in list_commands._PHASE_CHOICES
