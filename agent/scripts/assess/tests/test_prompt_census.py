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


def _write_operator_core_with_rule_lists(prompt_root: Path) -> Path:
    rules = prompt_root / "rules"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / "resume.md").write_text("R" * 30, encoding="utf-8")
    (rules / "hunting.md").write_text("H" * 70, encoding="utf-8")
    (rules / "hunting-operator.md").write_text("O" * 20, encoding="utf-8")
    (rules / "digest-only.md").write_text("X" * 500, encoding="utf-8")
    (prompt_root / "references").mkdir(exist_ok=True)
    (prompt_root / "references" / "taxonomy.md").write_text("T" * 40, encoding="utf-8")
    core = prompt_root / "operator-core.md"
    core.write_text(
        "## Rules\n\n"
        "Always-active rules:\n"
        "- `agent/rules/resume.md`\n\n"
        "These rule files load on their trigger, not at session start:\n\n"
        "- `agent/rules/hunting.md` — before you judge a negative\n"
        "  or close a surface; see also `agent/rules/digest-only.md`.\n"
        "- `agent/rules/hunting-operator.md` — before you exit a phase\n\n"
        "**Digest.**\n\n"
        "- `agent/rules/digest-only.md` is prose in a list that loads nothing.\n\n"
        "## Loaded on trigger\n\n"
        "Load each file below when its trigger fires:\n\n"
        "| Trigger | Load |\n"
        "|---|---|\n"
        "| Naming a vuln class by hand | `agent/references/taxonomy.md`; helpers refuse a bad token |\n"
        "| Entering a phase | that phase's doc |\n"
        "| When nothing else applies | `agent/rules/missing.md` |\n\n"
        "## Next\n\n"
        "- `agent/rules/digest-only.md` — under a heading that names no trigger\n",
        encoding="utf-8",
    )
    return core


def test_census_reports_operator_session_standing_load_and_trigger_loaded_rules(
    tmp_path: Path,
) -> None:
    prompt_root = tmp_path / "agent"
    _write_prompt_tree(prompt_root)
    core_path = _write_operator_core_with_rule_lists(prompt_root)
    core_bytes = core_path.stat().st_size

    result = collect_prompt_census(prompt_root)
    core = {row["path"]: row for row in result["operator_cores"]}["agent/operator-core.md"]

    assert core["bytes"] == core_bytes
    assert [(row["path"], row["bytes"]) for row in core["standing_references"]] == [
        ("agent/rules/resume.md", 30)
    ]
    # Bullet lists after a trigger lead-in and Trigger/Load tables under a trigger
    # heading both count; prose that merely mentions a path does not.
    assert [
        (row["path"], row["bytes"], row["trigger"])
        for row in core["trigger_loaded_references"]
    ] == [
        (
            "agent/rules/hunting.md",
            70,
            "before you judge a negative or close a surface; see also `agent/rules/digest-only.md`.",
        ),
        ("agent/rules/hunting-operator.md", 20, "before you exit a phase"),
        ("agent/references/taxonomy.md", 40, "Naming a vuln class by hand"),
        ("agent/rules/missing.md", None, "When nothing else applies"),
    ]
    # Session standing load = the core plus what it always loads; trigger-loaded files
    # stay out of it and are summed separately as the every-trigger-fires ceiling.
    assert core["approximate_session_standing_bytes"] == core_bytes + 30
    assert core["approximate_session_ceiling_bytes"] == core_bytes + 30 + 70 + 20 + 40
    assert core["advisories"] == [
        "trigger-loaded reference is not a regular file: agent/rules/missing.md"
    ]
    assert result["advisory_count"] == 1


def test_census_core_without_rule_lists_is_its_own_session_load(tmp_path: Path) -> None:
    prompt_root = tmp_path / "agent"
    _write_prompt_tree(prompt_root)

    result = collect_prompt_census(prompt_root)
    code_core = {row["path"]: row for row in result["operator_cores"]}[
        "agent/operator-core-code.md"
    ]

    assert code_core["standing_references"] == []
    assert code_core["trigger_loaded_references"] == []
    assert code_core["approximate_session_standing_bytes"] == code_core["bytes"]
    assert code_core["approximate_session_ceiling_bytes"] == code_core["bytes"]


def test_census_lists_a_role_s_trigger_loaded_references_apart_from_standing(
    tmp_path: Path,
) -> None:
    prompt_root = tmp_path / "agent"
    _write_prompt_tree(prompt_root)
    (prompt_root / "rules" / "reporting.md").write_text("P" * 60, encoding="utf-8")

    result = collect_prompt_census(prompt_root)
    plain = {row["role"]: row for row in result["roles"]}["plain-role"]
    plain_bytes = (prompt_root / "agents" / "plain-role.md").stat().st_size

    assert [(row["path"], row["bytes"]) for row in plain["trigger_loaded_references"]] == [
        ("agent/rules/reporting.md", 60)
    ]
    assert plain["approximate_trigger_loaded_bytes"] == 60
    assert plain["approximate_standing_bytes"] == plain_bytes + 100 + 50


def test_census_human_output_shows_session_standing_and_trigger_ceiling(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prompt_root = tmp_path / "agent"
    _write_prompt_tree(prompt_root)
    core_bytes = _write_operator_core_with_rule_lists(prompt_root).stat().st_size

    _run_cli(["prompt-census", "--prompt-root", str(prompt_root)])

    out = capsys.readouterr().out
    core_line = next(line for line in out.splitlines() if line.startswith("operator-core "))
    assert str(core_bytes + 30) in core_line.split()
    assert str(core_bytes + 160) in core_line.split()
    assert "  trigger agent/rules/hunting-operator.md  20  before you exit a phase" in out


def test_census_resolves_every_rule_this_checkout_s_operator_cores_list() -> None:
    result = collect_prompt_census(_REPO_PROMPT_ROOT)

    for core in result["operator_cores"]:
        listed = [*core["standing_references"], *core["trigger_loaded_references"]]
        assert [row["path"] for row in listed if not row["present"]] == [], core["path"]
        assert core["approximate_session_standing_bytes"] >= core["bytes"]


def _write_role_with_unmeasurable_lazy_pointers(prompt_root: Path) -> None:
    (prompt_root / "references" / "web").mkdir(parents=True)
    (prompt_root / "agents" / "glob-role.md").write_text(
        "# Glob role\n\n"
        "## Load First\n\n"
        "**MANDATORY (before any work):**\n\n"
        "- `agent/shared-specialist-core.md` — isolation\n\n"
        "**LOAD-ON-FIRST-USE (lazy):**\n\n"
        "- `agent/rules/reporting.md` when writing a report\n"
        "- `agent/skills/*/SKILL.md` — the skill the signal names\n"
        "- `agent/references/web/` — payload references on demand\n\n"
        "## Work\nBody\n",
        encoding="utf-8",
    )


def test_census_lists_lazy_pointers_it_could_not_measure(tmp_path: Path) -> None:
    prompt_root = tmp_path / "agent"
    _write_prompt_tree(prompt_root)
    (prompt_root / "rules" / "reporting.md").write_text("P" * 60, encoding="utf-8")
    _write_role_with_unmeasurable_lazy_pointers(prompt_root)

    result = collect_prompt_census(prompt_root)
    role = {row["role"]: row for row in result["roles"]}["glob-role"]

    assert [row["path"] for row in role["trigger_loaded_references"]] == [
        "agent/rules/reporting.md"
    ]
    assert role["unmeasured_trigger_pointers"] == [
        "agent/skills/*/SKILL.md",
        "agent/references/web/",
    ]


def test_census_human_output_points_at_json_for_what_the_table_omits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prompt_root = tmp_path / "agent"
    _write_prompt_tree(prompt_root)
    (prompt_root / "rules" / "reporting.md").write_text("P" * 60, encoding="utf-8")
    _write_role_with_unmeasurable_lazy_pointers(prompt_root)

    _run_cli(["prompt-census", "--prompt-root", str(prompt_root)])

    out = capsys.readouterr().out
    role_lines = [line for line in out.splitlines() if "glob-role" in line]
    assert any(
        "agent/skills/*/SKILL.md" in line and "agent/references/web/" in line
        for line in role_lines
    )
    assert "--json" in out
    assert "trigger_loaded_references" in out


def _specialist_advisories(result: dict) -> list[str]:
    return [
        advisory
        for row in result["roles"]
        for advisory in row["advisories"]
        if advisory.startswith("specialist_cites_operator_core")
    ]


def test_census_flags_a_specialist_loaded_file_that_cites_an_operator_core(
    tmp_path: Path,
) -> None:
    # Specialists never load an operator core, so a pointer into one from a file
    # a role loads cannot be followed.
    prompt_root = tmp_path / "agent"
    _write_prompt_tree(prompt_root)
    (prompt_root / "rules" / "hunting.md").write_text(
        "Hunt.\nSee `agent/operator-core.md` \"Foo\" for the rule.\n"
        "Never read `agent/AGENTS.md` or `agent/CLAUDE.md`.\n",
        encoding="utf-8",
    )

    advisories = _specialist_advisories(collect_prompt_census(prompt_root))

    # hunting.md is loaded by both roles; each role names it once.
    assert len(advisories) == 2
    assert all("agent/rules/hunting.md:2" in advisory for advisory in advisories)
    assert all("operator-core.md" in advisory for advisory in advisories)


def test_census_flags_a_role_file_citing_a_code_operator_core(tmp_path: Path) -> None:
    prompt_root = tmp_path / "agent"
    _write_prompt_tree(prompt_root)
    role = prompt_root / "agents" / "plain-role.md"
    role.write_text(
        role.read_text(encoding="utf-8") + "Follow operator-core-code.md step 3.\n",
        encoding="utf-8",
    )

    (advisory,) = _specialist_advisories(collect_prompt_census(prompt_root))

    assert "agent/agents/plain-role.md:" in advisory
    assert "operator-core-code.md" in advisory


def test_this_checkout_s_specialist_files_cite_no_operator_core() -> None:
    result = collect_prompt_census(_REPO_PROMPT_ROOT)

    assert _specialist_advisories(result) == []
