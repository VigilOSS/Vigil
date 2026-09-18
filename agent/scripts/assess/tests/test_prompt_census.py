"""Behavior tests for `vigil assess prompt-census`.

The census is an advisory measurement surface (never a gate), so these tests
assert what it *measures* — which trees, which files, and how a mutually
exclusive Load-First bundle is accounted for — not the wording of any prompt.
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from assess import cli
from assess.lib.prompt_census import collect_prompt_census

prompt_census_cmd = importlib.import_module("assess.commands.prompt_census")

_REPO_PROMPT_ROOT = Path(__file__).resolve().parents[3]


def _run_cli(argv: list[str]) -> None:
    try:
        cli.main(argv)
    except SystemExit as exc:
        pytest.fail(f"command unexpectedly exited with {exc.code}")


def _write_prompt_tree(prompt_root: Path) -> None:
    """A miniature agent tree with one plain role and one two-track role."""
    roles = prompt_root / "agents"
    roles.mkdir(parents=True)
    (prompt_root / "shared-specialist-core.md").write_text("A" * 100, encoding="utf-8")
    (prompt_root / "shared-constraints-code.md").write_text("B" * 200, encoding="utf-8")
    (prompt_root / "shared-constraints.md").write_text("C" * 400, encoding="utf-8")
    (prompt_root / "rules").mkdir()
    (prompt_root / "rules" / "hunting.md").write_text("D" * 50, encoding="utf-8")
    (prompt_root / "operator-core.md").write_text("core\nweb\n", encoding="utf-8")
    (prompt_root / "operator-core-code.md").write_text("core\ncode\nthree\n", encoding="utf-8")

    (roles / "plain-role.md").write_text(
        "# Plain role\n\n"
        "## Load First\n\n"
        "**MANDATORY (before any work):**\n\n"
        "- `agent/shared-specialist-core.md` — isolation\n"
        "- `agent/rules/hunting.md`\n\n"
        "**LOAD-ON-FIRST-USE (lazy):**\n\n"
        "- `agent/rules/reporting.md` when writing a report\n\n"
        "## Work\nBody\n",
        encoding="utf-8",
    )
    (roles / "two-track-role.md").write_text(
        "# Two track role\n\n"
        "## Load First\n\n"
        "**MANDATORY (before any work):**\n\n"
        "- `agent/shared-specialist-core.md` — isolation\n"
        "- Exactly one mode constraint bundle, selected from the dispatch:\n"
        "  - **Code track** — when the dispatch names code-track work, load "
        "`agent/shared-constraints-code.md` instead of the web bundle.\n"
        "  - **Web track** — otherwise load `agent/shared-constraints.md`. "
        "Do not preload both bundles.\n"
        "- `agent/rules/hunting.md`\n\n"
        "**LOAD-ON-FIRST-USE (lazy):**\n\n"
        "- `agent/rules/reporting.md` when writing a report\n\n"
        "## Work\nBody\n",
        encoding="utf-8",
    )


def test_census_measures_operator_cores_as_their_own_category(tmp_path: Path) -> None:
    prompt_root = tmp_path / "agent"
    _write_prompt_tree(prompt_root)

    result = collect_prompt_census(prompt_root)

    cores = {row["path"]: row for row in result["operator_cores"]}
    assert set(cores) == {"agent/operator-core.md", "agent/operator-core-code.md"}
    assert cores["agent/operator-core.md"]["bytes"] == 9
    assert cores["agent/operator-core.md"]["lines"] == 2
    assert cores["agent/operator-core-code.md"]["lines"] == 3
    # Operator cores carry no per-dispatch multiplier and no Load-First budget,
    # so they are reported as measured size only and never merged into `roles`.
    assert {row["role"] for row in result["roles"]} == {"plain-role", "two-track-role"}
    assert all("budget" not in row for row in result["operator_cores"])


def test_census_reports_a_mutually_exclusive_bundle_per_track(tmp_path: Path) -> None:
    prompt_root = tmp_path / "agent"
    _write_prompt_tree(prompt_root)

    result = collect_prompt_census(prompt_root)
    by_role = {row["role"]: row for row in result["roles"]}

    plain = by_role["plain-role"]
    plain_bytes = (prompt_root / "agents" / "plain-role.md").stat().st_size
    assert plain["mandatory_alternative_groups"] == []
    assert plain["standing_byte_variants"] == []
    assert plain["approximate_standing_bytes"] == plain_bytes + 100 + 50

    two_track = by_role["two-track-role"]
    role_bytes = (prompt_root / "agents" / "two-track-role.md").stat().st_size
    # No single figure can describe a role whose bundle choice is exclusive.
    assert two_track["approximate_standing_bytes"] is None
    assert two_track["approximate_mandatory_reference_bytes"] == 150
    assert [
        (variant["label"], variant["approximate_standing_bytes"])
        for variant in two_track["standing_byte_variants"]
    ] == [
        ("Code track", role_bytes + 150 + 200),
        ("Web track", role_bytes + 150 + 400),
    ]
    groups = two_track["mandatory_alternative_groups"]
    assert len(groups) == 1
    assert [option["label"] for option in groups[0]["options"]] == [
        "Code track",
        "Web track",
    ]
    assert [option["bytes"] for option in groups[0]["options"]] == [200, 400]
    # The exclusive bundle must not also be counted as an unconditional reference.
    assert [row["path"] for row in two_track["mandatory_references"]] == [
        "agent/shared-specialist-core.md",
        "agent/rules/hunting.md",
    ]


def test_census_names_the_measured_tree_in_human_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prompt_root = tmp_path / "agent"
    _write_prompt_tree(prompt_root)

    _run_cli(["prompt-census", "--prompt-root", str(prompt_root)])

    out = capsys.readouterr().out
    assert str(prompt_root.resolve()) in out
    assert "OPERATOR_CORE" in out
    # A two-track role reports its per-track range, never a single fabricated total.
    two_track_line = next(
        line for line in out.splitlines() if line.startswith("two-track-role ")
    )
    assert "-" in two_track_line.split()[2]


def test_census_detects_a_checkout_prompt_tree_that_was_not_measured(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "checkout"
    (checkout / ".jj").mkdir(parents=True)
    (checkout / "agent" / "agents").mkdir(parents=True)
    nested = checkout / "orchestrator" / "backend"
    nested.mkdir(parents=True)

    assert (
        prompt_census_cmd.discover_checkout_prompt_root(nested)
        == checkout / "agent"
    )
    assert prompt_census_cmd.discover_checkout_prompt_root(tmp_path) is None


def test_census_sees_this_checkout_operator_cores_and_every_role() -> None:
    result = collect_prompt_census(_REPO_PROMPT_ROOT)

    core_paths = {row["path"] for row in result["operator_cores"]}
    assert "agent/operator-core.md" in core_paths
    assert result["blocking"] is False
    for row in result["roles"]:
        if row["standing_byte_variants"]:
            assert row["approximate_standing_bytes"] is None
        else:
            assert isinstance(row["approximate_standing_bytes"], int)
        exclusive = [
            reference
            for group in row["mandatory_alternative_groups"]
            for option in group["options"]
            for reference in option["references"]
        ]
        # A Load-First pointer that no longer resolves is the failure this census
        # exists to make visible, and an exclusive bundle is never also billed as
        # an unconditional load.
        assert [
            reference["path"]
            for reference in (*row["mandatory_references"], *exclusive)
            if not reference["present"]
        ] == []
        assert not {reference["path"] for reference in exclusive} & {
            reference["path"] for reference in row["mandatory_references"]
        }


def test_census_json_still_reports_structure_cost_and_partial_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prompt_root = tmp_path / "agent"
    _write_prompt_tree(prompt_root)
    role_path = prompt_root / "agents" / "plain-role.md"
    read_bytes = role_path.read_bytes().index(b"agent/rules/hunting.md") + 3

    _run_cli(
        [
            "prompt-census",
            "--prompt-root",
            str(prompt_root),
            "--read-bytes",
            str(read_bytes),
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["blocking"] is False
    assert payload["prompt_root"] == str(prompt_root.resolve())
    assert payload["prompt_root_source"] == "flag"
    by_role = {row["role"]: row for row in payload["roles"]}
    assert by_role["plain-role"]["read_visibility"] == "partial"


def test_census_warns_when_the_installed_tree_is_not_the_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    installed = tmp_path / "install" / "agent"
    _write_prompt_tree(installed)
    checkout = tmp_path / "checkout"
    (checkout / ".jj").mkdir(parents=True)
    _write_prompt_tree(checkout / "agent")
    monkeypatch.setattr(prompt_census_cmd, "_PROMPT_ROOT", installed)
    monkeypatch.chdir(checkout)

    _run_cli(["prompt-census"])

    captured = capsys.readouterr()
    assert str(installed) in captured.out
    assert "(source: running-script)" in captured.out
    assert str(checkout / "agent") in captured.err
    assert "--prompt-root" in captured.err


def test_census_credits_a_continuation_line_to_its_own_option(tmp_path: Path) -> None:
    prompt_root = tmp_path / "agent"
    roles = prompt_root / "agents"
    roles.mkdir(parents=True)
    for name, size in (("a.md", 10), ("b.md", 20), ("c.md", 40)):
        (prompt_root / name).write_text("x" * size, encoding="utf-8")
    role_path = roles / "role.md"
    role_path.write_text(
        "# Role\n\n"
        "## Load First\n\n"
        "**MANDATORY (before any work):**\n\n"
        "- Exactly one bundle:\n"
        "  - **First** — load `agent/a.md`.\n"
        "  - **Prose sub-item with no file of its own.**\n"
        "    It continues here and names `agent/b.md`.\n"
        "  - **Third** — load `agent/c.md`.\n\n"
        "**LOAD-ON-FIRST-USE (lazy):**\n\n"
        "- none\n",
        encoding="utf-8",
    )

    result = collect_prompt_census(prompt_root)
    role = result["roles"][0]

    options = role["mandatory_alternative_groups"][0]["options"]
    # `agent/b.md` belongs to the prose sub-item it continues, not to `First`.
    assert [(option["label"], option["bytes"]) for option in options] == [
        ("First", 10),
        ("Prose sub-item with no file of its own.", 20),
        ("Third", 40),
    ]
    assert [
        variant["approximate_standing_bytes"]
        for variant in role["standing_byte_variants"]
    ] == [
        role["role_bytes"] + 10,
        role["role_bytes"] + 20,
        role["role_bytes"] + 40,
    ]
