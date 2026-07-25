"""Behaviour tests for `vigil assess list-mindsets` (the Dispatch-Mindset lens index).

Mirrors `test_list_commands.py`: build the real argparse parser via
`list_mindsets.register`, drive `run`, and assert the discovery contract — NOT
the wording of any packet. Every assertion about the live library is structural
(a row exists per file, JSON keys are stable, filters narrow) or is made against
a synthetic fixture directory via `--mindsets-dir`, so editing the prose in a
real packet can never fail this module.

Guarantees:
  * one row per `agent/rules/mindsets/*.md` — the index is discovered, not
    enumerated, so a new packet needs no menu edit anywhere;
  * every row carries a non-placeholder description derived from the packet's
    own preamble (the packets have no frontmatter by design);
  * `--json` round-trips with a stable key set;
  * `--grep` narrows on name/title/description/headings;
  * `--sections` surfaces the `##` headings;
  * the derivation handles the awkward real shapes: a hard-wrapped paragraph, a
    terse one-clause opener, an abbreviation-terminated clause, and a file with
    no preamble at all.
  * `list-mindsets` is a first-class catalog row (contract registry + the
    `list-commands` catalog), like the rest of the discovery family.
"""
from __future__ import annotations

import argparse
import json

import pytest

from assess.commands import list_mindsets
from assess.lib import contracts

_JSON_KEYS = {"name", "title", "description", "sections", "path"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    list_mindsets.register(sub)
    return parser


def _run(capsys, argv: list[str]) -> str:
    args = _parser().parse_args(argv)
    list_mindsets.run(args)
    return capsys.readouterr().out


def _run_json(capsys, argv: list[str]) -> list[dict]:
    return json.loads(_run(capsys, [*argv, "--json"]))


# --------------------------------------------------------------------------
# The live library.
# --------------------------------------------------------------------------
def test_every_packet_on_disk_becomes_exactly_one_row(capsys):
    # Discovery, not enumeration: the row set must equal the file set. A packet
    # that never reaches this command is undiscoverable to an operator who has
    # no hard-coded menu.
    rows = _run_json(capsys, ["list-mindsets"])
    on_disk = {p.stem for p in list_mindsets._MINDSETS_DIR.glob("*.md")}
    assert on_disk, "no mindset packets found — is _MINDSETS_DIR resolving correctly?"
    assert {row["name"] for row in rows} == on_disk


def test_json_round_trips_with_a_stable_key_set(capsys):
    rows = _run_json(capsys, ["list-mindsets"])
    assert rows
    assert json.loads(json.dumps(rows)) == rows
    for row in rows:
        assert set(row) == _JSON_KEYS
        assert isinstance(row["sections"], list)
        assert row["path"].startswith("agent/rules/mindsets/")
        assert row["path"].endswith(f"{row['name']}.md")


def test_every_row_has_a_real_derived_description_and_title(capsys):
    # The packets carry NO frontmatter by design, so the derivation is the only
    # source of a description. Assert it produced something usable for EVERY
    # packet (not what it says) — a "(no preamble)" row would mean an operator
    # picking a lens from this index is flying blind.
    rows = _run_json(capsys, ["list-mindsets"])
    for row in rows:
        assert row["description"] != "(no preamble)", (
            f"{row['name']} produced no description — its preamble shape defeated "
            "the derivation in list_mindsets._derive_description"
        )
        assert len(row["description"]) >= 25, row
        assert row["title"] and row["title"] != row["name"]


def test_sections_are_surfaced(capsys):
    rows = _run_json(capsys, ["list-mindsets"])
    # Section headings are the detail that lets an operator choose a lens without
    # opening the file; at least one packet must expose them (structural check —
    # no heading TEXT is asserted).
    assert any(row["sections"] for row in rows)


def test_grep_narrows_and_matches_the_documented_fields(capsys):
    all_rows = _run_json(capsys, ["list-mindsets"])
    target = next(r for r in all_rows if r["name"] == "idor-bac")
    rows = _run_json(capsys, ["list-mindsets", "--grep", "IDOR-BAC"])
    assert [r["name"] for r in rows] == [target["name"]], "grep must be case-insensitive"
    assert len(rows) < len(all_rows)


def test_grep_with_no_match_is_empty_not_an_error(capsys):
    out = _run(capsys, ["list-mindsets", "--grep", "zzz-no-such-lens"])
    assert "(no mindset packets found)" in out


def test_default_table_and_sections_view_render(capsys):
    table = _run(capsys, ["list-mindsets"])
    assert "MINDSET" in table and "DESCRIPTION" in table and "PATH" in table
    # The intro tells the operator what to DO with a row (one lens per dispatch).
    assert "mindset lens:" in table
    expanded = _run(capsys, ["list-mindsets", "--sections"])
    assert "agent/rules/mindsets/" in expanded
    # The expanded view is strictly richer than the table.
    assert len(expanded) > len(table)


def test_missing_mindsets_dir_exits_2(capsys, tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        _run(capsys, ["list-mindsets", "--mindsets-dir", str(tmp_path / "nope")])
    assert excinfo.value.code == 2


# --------------------------------------------------------------------------
# Derivation, against synthetic packets (no live prose is asserted).
# --------------------------------------------------------------------------
_FIXTURES = {
    # Hard-wrapped paragraph: rejoined on single spaces, stops at the first `##`.
    "wrapped": (
        "# Wrapped Lens\n\n"
        "A lens for surfaces that encode a *process*, not just\n"
        "data — checkout, KYC, approval. The second sentence must not be pulled in.\n\n"
        "## 1. First section\nbody\n## 2. Second section\nbody\n"
    ),
    # Terse opener: one clause is true but useless as an index entry, so the
    # derivation grows until it clears the minimum length.
    "terse": (
        "# Terse Lens\n\n"
        "A stance, not a mechanic. It does not add gates or checklists — it sets the\n"
        "burden of proof you carry into the ones that already exist.\n\n"
        "## 1. Burden of proof\nbody\n"
    ),
    # An abbreviation must not be mistaken for a sentence end.
    "abbrev": (
        "# Abbrev Lens\n\n"
        "Covers the injection family (SQLi, SSTI, e.g. the template engines) and\n"
        "their kin, which is a long enough opening sentence to stand alone here.\n\n"
        "## 1. Candidates\nbody\n"
    ),
    # No preamble at all — must degrade to the placeholder, not crash.
    "bare": "# Bare Lens\n\n## 1. Straight into a section\nbody\n",
}


@pytest.fixture()
def fixture_dir(tmp_path):
    for name, text in _FIXTURES.items():
        (tmp_path / f"{name}.md").write_text(text, encoding="utf-8")
    return tmp_path


def _fixture_rows(capsys, fixture_dir) -> dict[str, dict]:
    rows = _run_json(capsys, ["list-mindsets", "--mindsets-dir", str(fixture_dir)])
    return {row["name"]: row for row in rows}


def test_wrapped_paragraph_is_rejoined_and_cut_at_the_first_sentence(capsys, fixture_dir):
    row = _fixture_rows(capsys, fixture_dir)["wrapped"]
    assert row["title"] == "Wrapped Lens"
    assert row["description"] == (
        "A lens for surfaces that encode a *process*, not just data — "
        "checkout, KYC, approval."
    )
    assert row["sections"] == ["1. First section", "2. Second section"]


def test_terse_opener_grows_until_it_is_informative(capsys, fixture_dir):
    row = _fixture_rows(capsys, fixture_dir)["terse"]
    assert row["description"].startswith("A stance, not a mechanic.")
    assert "burden of proof" in row["description"], (
        "a one-clause opener must be grown with the following sentence — on its "
        "own it does not distinguish this lens from any other"
    )


def test_abbreviation_does_not_end_the_sentence(capsys, fixture_dir):
    row = _fixture_rows(capsys, fixture_dir)["abbrev"]
    assert row["description"].endswith("stand alone here.")


def test_packet_without_a_preamble_degrades_cleanly(capsys, fixture_dir):
    row = _fixture_rows(capsys, fixture_dir)["bare"]
    assert row["description"] == "(no preamble)"
    assert row["title"] == "Bare Lens"


def test_mindsets_dir_override_still_prints_a_usable_path(capsys, fixture_dir):
    # A directory outside the repo cannot be made repo-relative; the row must
    # still carry a resolvable path rather than crashing on relative_to().
    rows = _run_json(capsys, ["list-mindsets", "--mindsets-dir", str(fixture_dir)])
    for row in rows:
        assert row["path"].endswith(f"{row['name']}.md")


# --------------------------------------------------------------------------
# Catalog wiring — the discovery family must stay complete.
# --------------------------------------------------------------------------
def test_list_mindsets_is_a_registered_contract():
    contract = contracts.get_contract("list-mindsets")
    assert contract is not None, "`contract list-mindsets` returns Unknown contract"
    assert contract.name == "list-mindsets"
    assert "discovery" in contract.goals
    # Phase-agnostic like the rest of the discovery family (never leaks into a
    # `list-commands --phase <p>` filter).
    assert contract.phase == ()


def test_list_mindsets_appears_in_the_command_catalog():
    names = {c.name for c in contracts.all_command_contracts()}
    assert "list-mindsets" in names
    # The discovery family is a set, not a collection of one-offs: if the others
    # are catalogued, this one must be too.
    assert {"list-skills", "list-references", "list-commands"} <= names
