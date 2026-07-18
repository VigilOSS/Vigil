"""Coverage tests for the cross-cutting `--goal` lens on the command catalog.

Sibling of `test_list_commands.py` (which owns the per-phase axis). Goals are
ORTHOGONAL to phases: `CommandContract.goals` tags a command by what a caller is
trying to accomplish, and `vigil assess list-commands --goal <g>` filters on it
(AND-composing with `--phase`).

Guarantees:
  * `--goal <g>` returns exactly the rows tagged with that goal;
  * every JSON row carries a `goals` list;
  * `render_contract` surfaces a `Goals:` line for tagged commands (and omits it
    for untagged ones);
  * every seeded goal is in the canonical `COMMAND_GOALS` vocabulary and maps to
    at least one catalog command (no typo'd / orphan goal tag);
  * `--goal` AND-composes with `--phase`.
"""
from __future__ import annotations

import argparse
import json

import pytest

from assess.commands import list_commands
from assess.lib import contracts


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


def _seeded_goals() -> set[str]:
    seeded: set[str] = set()
    for contract in contracts.all_command_contracts():
        seeded.update(contract.goals)
    return seeded


def test_every_json_row_carries_a_goals_list(capsys):
    rows = _run_json(capsys, ["list-commands", "--json"])
    assert rows
    for row in rows:
        assert "goals" in row, f"{row['name']} missing goals key"
        assert isinstance(row["goals"], list)
        # goals round-trip as JSON strings.
        assert all(isinstance(g, str) for g in row["goals"])


@pytest.mark.parametrize("goal", sorted(_seeded_goals()))
def test_goal_filter_returns_exactly_the_tagged_rows(goal, capsys):
    # A --goal filter must return a non-empty slice, and every returned row must
    # actually carry the goal (nothing leaks in).
    filtered = _run_json(capsys, ["list-commands", "--goal", goal, "--json"])
    assert filtered, f"catalog is empty for goal {goal!r}"
    for row in filtered:
        assert goal in row["goals"], f"{row['name']} leaked into goal {goal!r}"

    # And every row in the FULL catalog tagged with the goal is present in the
    # filtered slice (nothing is dropped).
    all_rows = _run_json(capsys, ["list-commands", "--json"])
    expected = {r["name"] for r in all_rows if goal in r["goals"]}
    assert {r["name"] for r in filtered} == expected


def test_seeded_goals_are_canonical_and_covered():
    # Every goal tagged on a contract must be a member of the canonical
    # COMMAND_GOALS vocabulary (guards a typo'd tag) and must map to >=1 command.
    seeded = _seeded_goals()
    assert seeded, "expected at least one command to carry a goal tag"
    for goal in seeded:
        assert goal in contracts.COMMAND_GOALS, f"{goal!r} not in COMMAND_GOALS"
        matched = [c for c in contracts.all_command_contracts() if goal in c.goals]
        assert matched, f"seeded goal {goal!r} maps to no command"


def test_known_goal_tags_are_present():
    # Anchor the taxonomy to a stable set of obvious homes so a future edit that
    # silently drops all tags for a goal is caught.
    seeded = _seeded_goals()
    for goal in ("finding-lifecycle", "artifact", "discovery", "code-analysis",
                 "dispatch", "recon"):
        assert goal in seeded, f"expected goal {goal!r} to be seeded on a command"


def test_representative_command_goal_assignments(capsys):
    rows = {r["name"]: r for r in _run_json(capsys, ["list-commands", "--json"])}
    assert "finding-lifecycle" in rows["finding"]["goals"]
    assert "artifact" in rows["artifact"]["goals"]
    assert "discovery" in rows["list-commands"]["goals"]
    # code-dispatch carries BOTH the dispatch and code-analysis lenses.
    assert set(rows["code-dispatch"]["goals"]) == {"dispatch", "code-analysis"}
    # A command with no obvious goal stays untagged.
    assert rows["resume-brief"]["goals"] == []


def test_render_contract_surfaces_goals_for_tagged_command():
    rendered = contracts.render_contract("finding record")
    assert "Goals: finding-lifecycle" in rendered


def test_render_contract_omits_goals_line_for_untagged_command():
    # resume-brief carries no goals, so no Goals: line should be emitted.
    rendered = contracts.render_contract("resume-brief")
    assert "Goals:" not in rendered


def test_goal_and_composes_with_phase(capsys):
    # The collapsed `finding` group is tagged goal=finding-lifecycle and its
    # phase union includes consume-test (from record-finding), so the AND-composed
    # filter must include it and every returned row must satisfy BOTH predicates.
    rows = _run_json(
        capsys,
        ["list-commands", "--goal", "finding-lifecycle", "--phase", "consume-test", "--json"],
    )
    assert rows
    assert "finding" in {r["name"] for r in rows}
    for row in rows:
        assert "finding-lifecycle" in row["goals"]
        assert "consume-test" in row["phases"]


def test_goal_and_phase_intersection_can_be_empty(capsys):
    # code-analysis goals only tag code-track commands, none of which live in the
    # `recon` phase, so the AND-composition is empty (not an error).
    rows = _run_json(
        capsys,
        ["list-commands", "--goal", "code-analysis", "--phase", "recon", "--json"],
    )
    assert rows == []


def test_goal_choices_cover_the_canonical_vocabulary():
    # argparse `--goal` choices are sourced from COMMAND_GOALS, so a new goal is
    # auto-covered as a valid filter value.
    for goal in contracts.COMMAND_GOALS:
        assert goal in list_commands._GOAL_CHOICES


def test_invalid_goal_is_rejected():
    with pytest.raises(SystemExit):
        _parser().parse_args(["list-commands", "--goal", "not-a-real-goal"])
