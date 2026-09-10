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


def test_finding_update_contract_uses_public_details_shape_and_replacement_semantics():
    contract = contracts.get_contract("finding update")
    assert contract is not None
    text = " ".join(contract.notes)

    assert "returns it back as `details`" in text
    assert "details_json` on read" not in text
    assert "replaces that stored value" in text


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
    # --kali-only EXPANDS the collapsed dispatcher into per-tool `kali <verb>`
    # rows: every name is a two-token `kali <verb>`, and the collapsed root row
    # (bare "kali") is NOT part of the expansion.
    assert all(row["name"].startswith("kali ") for row in rows)
    assert "kali" not in {row["name"] for row in rows}
    # One row per registered kali verb — no tool is dropped from the drill-down.
    assert len(rows) == len(contracts.KALI_VERBS)
    names = {row["name"] for row in rows}
    for verb in ("kali sqlmap", "kali exec", "kali nuclei", "kali browser"):
        assert verb in names, f"{verb!r} missing from --kali-only expansion"


def test_default_catalog_collapses_kali_to_a_single_row(capsys):
    # Tier 0: the default catalog must render `kali` as ONE dispatcher row, not
    # one row per tool. This is the measurement-artifact fix — the per-verb
    # `kali <verb>` rows only surface under --kali-only.
    rows = _run_json(capsys, ["list-commands", "--json"])
    kali_rows = [r for r in rows if r["kali"]]
    assert [r["name"] for r in kali_rows] == ["kali"], (
        "the default catalog must contain exactly one kali row (the collapsed "
        "dispatcher), never the flattened per-tool wrappers"
    )
    assert not any(r["name"].startswith("kali ") for r in rows), (
        "no per-tool `kali <verb>` row should appear in the default catalog"
    )
    # The single row carries a drill-down hint (count + both expansion paths) so
    # the tool wrappers stay discoverable without inflating the default view.
    (kali_row,) = kali_rows
    assert str(len(contracts.KALI_VERBS)) in kali_row["summary"]
    assert "--kali-only" in kali_row["summary"]
    assert "contract kali" in kali_row["summary"]


def test_kali_root_carries_union_of_verb_phases(capsys):
    # The collapsed kali row must be tagged with the union of every kali verb's
    # phase, so `list-commands --phase <p>` still surfaces the dispatcher for the
    # phases ONLY kali covers (recon-pivot / exploit-recon). Otherwise those
    # phase filters would go empty when the per-verb rows are collapsed.
    rows = _run_json(capsys, ["list-commands", "--json"])
    (kali_row,) = [r for r in rows if r["name"] == "kali"]
    for phase in ("recon", "collect", "consume-test", "recon-pivot", "exploit-recon"):
        assert phase in kali_row["phases"], f"kali row missing phase {phase!r}"
    for phase in ("recon-pivot", "exploit-recon"):
        filtered = _run_json(capsys, ["list-commands", "--phase", phase, "--json"])
        assert "kali" in {r["name"] for r in filtered}


@pytest.mark.parametrize("verb", ["kali sqlmap", "kali exec", "kali nuclei", "kali browser"])
def test_collapsed_kali_verbs_still_resolve_as_contracts(verb):
    # Collapsing the catalog must NOT drop any kali contract data — every
    # `kali <verb>` stays fully resolvable via `contract kali <verb>`.
    contract = contracts.get_contract(verb)
    assert contract is not None, f"contract lookup for {verb!r} returned None"
    assert contract.name == verb
    rendered = contracts.render_contract(verb)
    assert rendered.startswith(f"Command: {verb}")


@pytest.mark.parametrize("name", ["auth status", "auth list"])
def test_auth_two_token_resolves_to_auth_contract(name):
    # `auth` is one contract documenting the `list`/`status` subcommands, so the
    # two-token form `contract auth status` / `contract auth list` must resolve to
    # it (mirroring `contract resolve <target>`) instead of returning None ->
    # "Unknown contract".
    contract = contracts.get_contract(name)
    assert contract is not None, f"contract lookup for {name!r} returned None"
    assert contract.name == "auth"
    rendered = contracts.render_contract(name)
    assert rendered.startswith("Command: auth")


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
    # contract registry (the `_CONTRACTS` registry + the SINGLE collapsed `kali`
    # dispatcher row via `all_command_contracts`; the per-tool `kali <verb>`
    # rows live behind --kali-only). A command that has a contract but never
    # reaches `list-commands` is a discovery hole; a name in the output with no
    # backing contract is drift. The two name sets must be identical.
    rows = _run_json(capsys, ["list-commands", "--json"])
    catalog_names = {row["name"] for row in rows}
    registry_names = {c.name for c in contracts.all_command_contracts()}
    assert catalog_names == registry_names


# Registered argparse subcommands that previously had NO CommandContract entry,
# so `list-commands` never surfaced them and `contract <verb>` returned
# "Unknown contract" (regression B-Q1b). Each must now resolve through BOTH the
# list-commands catalog and the contract registry.
_PREVIOUSLY_UNLISTED_CODE_VERBS = (
    "code-coverage",
    "code-ingest",
    "code-index sync",
    "code-size-summary",
)


@pytest.mark.parametrize("name", _PREVIOUSLY_UNLISTED_CODE_VERBS)
def test_previously_unlisted_code_verb_is_discoverable(name, capsys):
    rows = _run_json(capsys, ["list-commands", "--json"])
    names = {row["name"] for row in rows}
    assert name in names, f"{name!r} is missing from the list-commands catalog"


@pytest.mark.parametrize("name", _PREVIOUSLY_UNLISTED_CODE_VERBS)
def test_previously_unlisted_code_verb_resolves_as_contract(name):
    # `vigil assess contract <verb>` must no longer return "Unknown contract".
    contract = contracts.get_contract(name)
    assert contract is not None, f"contract lookup for {name!r} returned None"
    assert contract.name == name


# State-writing verbs that reached NEITHER discovery surface: no contract at the
# verb and none at any parent, so `contract <verb>` returned "Unknown contract"
# AND `list-commands` never listed them. An agent that cannot see a verb's write
# schema either guesses fields or declines to record legitimate state, so each
# must now surface in the catalog. (`assess/tests/test_cli_canonical_shapes.py`
# enforces the general rule against the live argparse tree; these pin the
# specific verbs the audit found.)
_PREVIOUSLY_UNLISTED_WRITE_VERBS = (
    "app-unit",
    "approve-proposal",
    "arjun-select",
    "arjun-sweep",
    "dns-discovery",
    "egress-check",
    "emit-event",
    "exploit",
    "gau",
    "ingest",
    "js-mining",
    "log",
    "post",
    "recon",
    "record-chain",
    "record-reply",
    "scaffold-probe",
    "scope filter",
    "web-discovery",
)


@pytest.mark.parametrize("name", _PREVIOUSLY_UNLISTED_WRITE_VERBS)
def test_previously_unlisted_write_verb_is_discoverable(name, capsys):
    rows = _run_json(capsys, ["list-commands", "--json"])
    names = {row["name"] for row in rows}
    assert name in names, f"{name!r} is missing from the list-commands catalog"


# Namespace children whose PARENT contract explicitly tells the reader to run
# `vigil assess contract <parent> <action>` — and which used to answer that
# pointer with "Unknown contract". A broken pointer is worse than a missing one:
# it spends the agent's attempt and teaches it the surface is unreliable.
_DOCUMENTED_POINTER_ACTIONS = (
    ("finding merge", "finding merge"),
    ("export findings", "export findings"),
    ("export reply", "export reply"),
    ("export surfaces", "export surfaces"),
)


@pytest.mark.parametrize("name,expected", _DOCUMENTED_POINTER_ACTIONS)
def test_namespace_pointer_action_resolves_to_its_own_contract(name, expected):
    contract = contracts.get_contract(name)
    assert contract is not None, f"contract lookup for {name!r} returned None"
    assert contract.name == expected
    assert contracts.render_contract(name).startswith(f"Command: {expected}")


@pytest.mark.parametrize("name,_expected", _DOCUMENTED_POINTER_ACTIONS)
def test_namespace_child_contracts_do_not_double_count_in_the_catalog(
    name, _expected, capsys
):
    # Per-action contracts under a grouped parent render as part of the ONE
    # collapsed parent row; adding them must not re-inflate the catalog.
    rows = _run_json(capsys, ["list-commands", "--json"])
    assert name not in {row["name"] for row in rows}


def test_kali_sweep_is_a_first_class_kali_verb():
    # `sweep` is registered in cli.py's kali loop; it was missing from
    # KALI_VERBS, so `contract kali sweep` returned Unknown and --kali-only
    # dropped it. Its contract must document the surface that actually matters:
    # the required value list and the `--` command template.
    assert "sweep" in contracts.KALI_VERBS
    rendered = contracts.render_contract("kali sweep")
    assert rendered.startswith("Command: kali sweep")
    assert "--values" in rendered
    assert "--placeholder" in rendered


def test_code_coverage_contract_documents_gate_flags():
    # code-coverage runs every code Core-Loop iteration; its contract must
    # document the --cwe-matrix and --require-gate-pass flags it accepts.
    contract = contracts.get_contract("code-coverage")
    assert contract is not None
    blob = " ".join(contract.preferred_invocations)
    blob += " " + " ".join(contract.notes)
    blob += " " + " ".join(default for _, default in contract.helper_defaults)
    assert "--cwe-matrix" in blob
    assert "--require-gate-pass" in blob
    assert "--require-transition-ready" in blob


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
    "resume-brief",
    "artifact",
    # Grouped subcommands render as ONE collapsed catalog row each (like
    # `kali`); their per-action verbs resolve via `contract <parent> <action>`.
    "finding",
    "intel",
    "export",
    "command-run",
    # representative write/probe verbs across phases
    "record-probe",
    "resolve",
    "block-technique",
    # the kali dispatcher is ONE collapsed catalog row; its per-tool wrappers
    # are asserted discoverable under --kali-only elsewhere in this module.
    "kali",
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
