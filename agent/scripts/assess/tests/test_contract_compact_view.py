"""Structural invariants of `vigil assess contract`'s compact view.

The compact view is what an author reads before hand-authoring a payload, so
it has to hold for EVERY contract the CLI can render, not the few a test names:
it renders, it opens with a header that counts what it leaves out and names the
flag that prints it, every field line it prints is reachable through
`--field`, an action of a multi-action command resolves to that action alone,
and nothing grows back into a full-contract dump.
"""
from __future__ import annotations

import json
import re

import pytest

from assess import cli
from assess.lib import contracts
from assess.lib.contract_registry import _CONTRACTS

# The largest compact view (`finding record`, every track) is ~9 KB; a contract
# that crosses this has started printing what `--field`/`--notes` own.
_MAX_COMPACT_BYTES = 10_000

_DISPATCH_VERB_ALIASES = ("register", "update-status", "record-handoff", "record-decision")
_FIELD_LINE = re.compile(r"^  - (?P<path>[\w.]+) \(")
_TERM = re.compile(r"--[a-z][a-z0-9-]*|<[^<>\s]+>|[a-z][a-z0-9]*(?:[_.][a-z0-9]+)+|[A-Za-z][A-Za-z0-9-]{2,}")


def _base_names() -> list[str]:
    names = set(contracts.contract_names()) | set(_CONTRACTS)
    names |= {f"kali {verb}" for verb in contracts.KALI_VERBS}
    names |= {f"agent {verb}" for verb in contracts.AGENT_VERBS + _DISPATCH_VERB_ALIASES}
    names |= {f"work-buffer {verb}" for verb in contracts._WORK_BUFFER_VERBS}
    return sorted(names)


def _variant_names() -> list[str]:
    return [
        f"{name} {variant.name}"
        for name in _base_names()
        for variant in contracts.get_contract(name).variants
    ]


_ALL = _base_names() + _variant_names()


def _field_paths(text: str) -> list[str]:
    paths: list[str] = []
    in_fields = False
    for line in text.splitlines():
        if line.startswith("Fields ("):
            in_fields = True
            continue
        if in_fields and not line.strip():
            break
        match = _FIELD_LINE.match(line) if in_fields else None
        if match:
            paths.append(match.group("path"))
    return paths


@pytest.mark.parametrize("name", _ALL)
def test_every_contract_renders_compact_with_a_counting_header(name: str) -> None:
    text = contracts.render_contract(name)
    contract = contracts.get_contract(name)
    lines = text.splitlines()

    assert lines[0].startswith(f"Command: {contract.name} — ")
    header = lines[1]
    assert header.startswith("Not shown: ")
    assert f"vigil assess contract {contract.name} --field <name>" in header
    # The counts in the header are the contract's own, never a guess.
    if contract.notes:
        assert f"{len(contract.notes)} note" in header
        assert f"vigil assess contract {contract.name} --notes" in header
    if contract.common_mistakes:
        assert f"{len(contract.common_mistakes)} common mistake" in header
    if len(contract.examples) > 1:
        assert f"{len(contract.examples) - 1} more example" in header
    assert len(text.encode()) <= _MAX_COMPACT_BYTES, (name, len(text.encode()))
    # One example at most; the rest are behind --examples.
    assert text.count("\nExample:\n") == (1 if contract.examples else 0)


@pytest.mark.parametrize("name", _ALL)
def test_every_compact_field_line_is_reachable_through_field(name: str) -> None:
    contract = contracts.get_contract(name)
    text = contracts.render_contract(name)
    for path in _field_paths(text):
        section = contracts.render_field_sections(name, [path])
        assert f"  - {path} (" in section, (name, path)
    for entry in contract.author_supplied_fields:
        term = _TERM.search(entry)
        assert term, (name, entry)
        section = contracts.render_field_sections(name, [term.group(0)], strict=False)
        assert entry in section, (name, term.group(0), entry)


@pytest.mark.parametrize("name", _ALL)
def test_notes_and_examples_print_everything_the_compact_view_counts(name: str) -> None:
    contract = contracts.get_contract(name)
    notes = contracts.render_contract_notes(name)
    for note in contract.notes:
        assert note in notes
    for wrong, fix in contract.common_mistakes:
        assert f"{wrong} -> {fix}" in notes
    for key, value in contract.helper_defaults:
        assert f"{key} = {value}" in notes
    examples = contracts.render_contract_examples(name)
    for example in contract.examples:
        assert json.dumps(example, indent=2, ensure_ascii=False) in examples


@pytest.mark.parametrize(
    "parent", [name for name in _base_names() if contracts.get_contract(name).variants]
)
def test_each_action_of_a_multi_action_command_resolves_to_that_action(parent: str) -> None:
    root = contracts.get_contract(parent)
    root_text = contracts.render_contract(parent)
    assert "Actions: " + ", ".join(v.name for v in root.variants) in root_text
    for variant in root.variants:
        view = contracts.get_contract(f"{parent} {variant.name}")
        assert view.name == f"{parent} {variant.name}"
        assert view.variants == ()
        # Every action has a usage line, and the view prints no other action's.
        assert view.preferred_invocations, (parent, variant.name)
        for line in view.preferred_invocations:
            assert re.search(
                rf"vigil assess {re.escape(parent)} {re.escape(variant.name)}(\s|$)", line
            ), (parent, variant.name, line)
        assert set(view.notes) <= set(root.notes)
        for field in variant.fields:
            assert field in view.author_supplied_fields


def test_code_dispatch_done_prints_only_done() -> None:
    text = contracts.render_contract("code-dispatch done")
    usage = [line for line in text.splitlines() if line.startswith("  vigil assess ")]
    assert usage and all(line.startswith("  vigil assess code-dispatch done ") for line in usage)
    assert "<cwe-coverage>" in text
    assert "adopt-lease" not in text


def test_a_track_filter_hides_other_tracks_fields_and_says_how_to_see_them() -> None:
    schema = contracts.load_schema("finding-record.schema.json")
    blue = sorted(
        f"details.{key}"
        for key, prop in schema["properties"]["details"]["properties"].items()
        if str(prop.get("x-vigil-extension", "")).startswith("blue/")
    )
    assert blue

    web = contracts.render_contract("finding record", tracks=("web",), track_source="--track")
    assert not set(blue) & set(_field_paths(web))
    assert f"{len(blue)} blue-track fields (`vigil assess contract finding record --track blue`)" in web
    assert "Track fields shown: web (from --track)" in web

    every = contracts.render_contract("finding record")
    assert set(blue) <= set(_field_paths(every))
    assert "Track fields shown: every track" in every


def test_unknown_field_gets_a_did_you_mean_and_the_pointer() -> None:
    with pytest.raises(ValueError, match="Did you mean: .*details.evidence"):
        contracts.render_field_sections("finding record", ["details.evidense"])

    refusal = contracts.render_field_sections(
        "finding record", ["details.evidense", "details.impact"], strict=False
    )
    assert "Did you mean:" in refusal
    assert "  - details.impact (string, required) — " in refusal
    assert refusal.rstrip().endswith(
        "every field on one line each: `vigil assess contract finding record`."
    )


def test_a_contract_group_prefix_names_its_members() -> None:
    with pytest.raises(ValueError, match="`code-record` is a group of contracts: .*code-record analysis"):
        contracts.render_contract("code-record")


def test_cli_flags_print_the_parts(capsys, tmp_path) -> None:
    cli.main(["contract", "code-dispatch", "done", "--field", "skip-reason"])
    out = capsys.readouterr().out
    assert out.startswith("code-dispatch done --field skip-reason\n")
    assert "--skip-reason <reason>" in out

    cli.main(["contract", "finding", "record", "--notes", "--examples"])
    out = capsys.readouterr().out
    assert "Notes:" in out and "Assessment binding:" in out
    assert out.count('"title"') == len(contracts.get_contract("finding record").examples)

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["contract", "finding", "record", "--field", "no_such_field"])
    assert excinfo.value.code == 1
    assert "says nothing about 'no_such_field'" in capsys.readouterr().err


def test_cli_defaults_the_track_to_the_engagement_scope(capsys, tmp_path) -> None:
    engagement = tmp_path / "acme-code"
    engagement.mkdir()
    (engagement / "scope.json").write_text(
        json.dumps({"tracks": {"code": {"phase": "hunt"}}}), encoding="utf-8"
    )

    cli.main(["--engagement-dir", str(engagement), "contract", "finding", "record"])
    out = capsys.readouterr().out
    assert "Track fields shown: code (from the engagement's scope.json)" in out
    assert "  - details.timeline (" not in out
    assert "  - details.function (" in out

    cli.main(["--engagement-dir", str(engagement), "contract", "finding", "record", "--track", "blue"])
    out = capsys.readouterr().out
    assert "Track fields shown: blue (from --track)" in out
    assert "  - details.timeline (" in out


# --------------------------------------------------------------------------- #
# What the compact view owes its reader without a second read
# --------------------------------------------------------------------------- #


def _section_lines(text: str, heading: str) -> list[str]:
    lines = text.splitlines()
    start = lines.index(heading) + 1
    body: list[str] = []
    for line in lines[start:]:
        if not line.strip():
            break
        body.append(line)
    return body


def test_the_record_time_verification_value_reads_in_the_default_view() -> None:
    # The helper default calls unreviewed the only value a record may carry; the
    # compact line has to say so, or an author learns it from the refusal.
    line = next(
        line for line in contracts.render_contract("finding record").splitlines()
        if line.startswith("  - verification_status (")
    )
    assert "the only record-time value" in line
    assert "finding verify" in line


def test_finding_record_says_what_evidence_ref_must_be_in_the_default_view() -> None:
    supplies = "\n".join(_section_lines(contracts.render_contract("finding record"), "Author supplies:"))
    assert "evidence_ref" in supplies
    assert "one existing" in supplies.lower()
    assert "readiness" in supplies


@pytest.mark.parametrize(
    "name",
    [
        f"kali {verb}" for verb in contracts.KALI_TARGET_VERBS if verb != "job"
    ] + ["kali job start", "kali"],
)
def test_every_target_facing_kali_view_carries_the_audit_flags_rules(name: str) -> None:
    from assess.lib.audit_enums import PROBE_KIND_ENUM

    supplies = _section_lines(contracts.render_contract(name), "Author supplies:")
    # `kali job start` is attributed by --agent-name (it has no --agent-id).
    attribution = "--agent-name" if name == "kali job start" else "--agent-id"
    by_flag = {
        flag: next((entry for entry in supplies if entry.startswith(f"  - {flag} ")), "")
        for flag in ("--probe-kind", "--phase", "--destructive", attribution)
    }
    assert all(by_flag.values()), (name, supplies)
    assert all(kind in by_flag["--probe-kind"] for kind in PROBE_KIND_ENUM)
    assert all(phase in by_flag["--phase"] for phase in contracts.ALLOWED_PHASES)
    assert "current_phase" in by_flag["--phase"]
    if attribution == "--agent-id":
        assert "--agent-id <your dispatch agent_id>" in by_flag["--agent-id"]
        assert "--agent-name" in by_flag["--agent-id"]


def test_kali_attribution_note_agrees_with_the_proof_receipt_rule() -> None:
    # A command receipt backing verifier evidence needs a run attributed to the
    # dispatch id; the kali note that explains --agent-name must say the same.
    note = next(note for note in contracts._KALI_COMMON_NOTES if "$VIGIL_AGENT_NAME" in note)
    assert "--agent-id <your dispatch agent_id>" in note


def test_proof_receipt_create_names_the_independence_rule_in_the_default_view() -> None:
    supplies = "\n".join(_section_lines(contracts.render_contract("proof-receipt create"), "Author supplies:"))
    assert "completed" in supplies and "separate from the" in supplies
    assert "fixed once" in supplies


def test_finding_update_says_how_payload_file_notes_land_in_the_default_view() -> None:
    supplies = "\n".join(_section_lines(contracts.render_contract("finding update"), "Author supplies:"))
    assert "notes_mode" in supplies and "appended" in supplies


@pytest.mark.parametrize("name", _variant_names())
def test_an_action_view_counts_everything_it_filtered_out(name: str) -> None:
    view = contracts.get_contract(name)
    found = contracts._variant_parent(name)
    assert found is not None
    parent = found[0]
    header = contracts.render_contract(name).splitlines()[1]
    hidden = {
        "note": len(parent.notes) - len(view.notes),
        "common mistake": len(parent.common_mistakes) - len(view.common_mistakes),
        "helper default": len(parent.helper_defaults) - len(view.helper_defaults),
    }
    if any(hidden.values()):
        assert f"about other actions (`vigil assess contract {parent.name} --notes`)" in header, header
        for noun, number in hidden.items():
            if number:
                assert re.search(rf"\b{number} {noun}s?\b[^;]*about other actions", header), (noun, header)


def test_code_dispatch_done_keeps_the_do_not_inflate_effort_note() -> None:
    assert any("inflate CWE effort" in note for note in contracts.get_contract("code-dispatch done").notes)


@pytest.mark.parametrize(
    ("name", "member", "outsider"),
    [
        ("kali nmapscan", "kali nmap-scan", "approve-proposal"),
        ("agent stat", "agent start", "approve-proposal"),
        ("intel record techcomponent", "intel record tech-component", "agent start"),
        ("finding recrod", "finding record", "agent start"),
    ],
)
def test_a_miss_inside_a_family_lists_that_family(name: str, member: str, outsider: str) -> None:
    with pytest.raises(ValueError) as excinfo:
        contracts.render_contract(name)
    message = str(excinfo.value)
    assert member in message
    assert outsider not in message


def test_work_buffer_lists_every_action_including_its_own_contracts() -> None:
    text = contracts.render_contract("work-buffer")
    actions = next(line for line in text.splitlines() if line.startswith("Actions: "))
    assert "reclassify" in actions and "link-surface" in actions
    with pytest.raises(ValueError, match="link-surface"):
        contracts.render_contract("work-buffer bogus")


@pytest.mark.parametrize("name", _ALL)
def test_the_helper_default_count_matches_what_the_field_lines_leave_out(name: str) -> None:
    contract = contracts.get_contract(name)
    text = contracts.render_contract(name)
    compact = {
        match.group("path"): line
        for line in text.splitlines()
        if (match := _FIELD_LINE.match(line))
    }
    hidden = [
        key for key, value in contract.helper_defaults
        if f"default {value}" not in compact.get(key, "")
    ]
    header = text.splitlines()[1]
    own = re.search(
        rf"(\d+) helper defaults? \(`vigil assess contract {re.escape(contract.name)} --notes`\)", header
    )
    assert (int(own.group(1)) if own else 0) == len(hidden), (name, hidden, header)


@pytest.mark.parametrize(
    "content", ["[]", "{not json", json.dumps({"tracks": "code"})]
)
def test_a_malformed_scope_falls_back_to_every_track_and_says_why(capsys, tmp_path, content) -> None:
    engagement = tmp_path / "acme-web"
    engagement.mkdir()
    (engagement / "scope.json").write_text(content, encoding="utf-8")

    cli.main(["--engagement-dir", str(engagement), "contract", "finding", "record"])
    out = capsys.readouterr().out
    line = next(line for line in out.splitlines() if line.startswith("Track fields shown: "))
    assert line.startswith("Track fields shown: every track (")
    assert "scope.json" in line
    assert "  - details.timeline (" in out


def test_only_the_blue_extension_is_filtered_by_track() -> None:
    # The backend accepts every extension on every track; the code example
    # still writes poc_request/poc_response, so hiding them on a code
    # engagement hid fields the author was being shown how to use.
    code = _field_paths(contracts.render_contract("finding record", tracks=("code",)))
    assert {"details.poc_request", "details.poc_response", "details.discovered_credential"} <= set(code)
    web = _field_paths(contracts.render_contract("finding record", tracks=("web",)))
    assert {"details.function", "details.source_anchor"} <= set(web)
    assert "details.timeline" not in web


# --------------------------------------------------------------------------- #
# A refused write prints the section that fixes it
# --------------------------------------------------------------------------- #


def test_a_top_level_key_hinted_into_details_prints_that_section() -> None:
    from assess.lib.contract_sections import offending_fields

    error = "payload.evidence is not allowed. Did you mean: payload.details.evidence, evidence_ref, evidence_type?"
    assert offending_fields("finding record", [error])[0] == "details.evidence"


def test_an_unknown_nested_key_without_a_hint_prints_its_parents_legal_keys() -> None:
    from assess.lib.contract_sections import refusal_sections

    schema = contracts.load_schema("finding-record.schema.json")
    keys = sorted(schema["properties"]["details"]["properties"]["unblock_requirements"]["properties"])
    text = refusal_sections("finding record", ["payload.details.unblock_requirements.foo is not allowed"])
    line = next(
        (line for line in text.splitlines() if line.startswith("  - details.unblock_requirements (")), ""
    )
    assert line, text
    assert all(key in line for key in keys), line
