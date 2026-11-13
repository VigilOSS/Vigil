"""`vigil assess contract <verb>` publishes the whole authoring surface.

A bundled schema is strict: an unknown key, or a value outside a declared enum,
is rejected before the backend is contacted. The contract is the only place an
agent can read that vocabulary, so a field list that stops at the top level and
prints no accepted values sends the author back to guessing. The compact view
prints every field's domain on one line (enum, object keys, required marks);
`--field <name>` prints its description and nested content through one
schema-aware renderer for every schema-backed contract — intel record types and
the code analysis receipt alike.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from assess.commands import transition_phase
from assess.lib import contracts
from assess.lib.intel_types import INTEL_TYPES


def test_cve_contract_publishes_the_validation_status_domain() -> None:
    rendered = contracts.render_contract("intel record cve")

    assert (
        "  - validation_status (string; one of: unverified, version_match, "
        "poc_available_unverified, attempted_blocked, exploited, ruled_out)"
    ) in rendered


@pytest.mark.parametrize("intel_type", sorted(INTEL_TYPES))
def test_every_intel_contract_expands_its_provenance_object(intel_type: str) -> None:
    # Generic renderer, not a CVE special case: every intel schema declares the
    # same provenance object and every contract must publish its legal keys —
    # named on the compact line, rendered one per line by `--field`.
    name = f"intel record {intel_type}"
    compact = next(
        line for line in contracts.render_contract(name).splitlines()
        if line.startswith("  - provenance (object")
    )
    section = contracts.render_field_sections(name, ["provenance"])

    assert "  - provenance (object)" in section
    for key in ("agent_name", "artifact_ref", "captured_at", "command_run_id"):
        assert key in compact, key
        assert f"      - {key} (" in section, key


def test_intel_contract_expands_a_second_level_object_with_required_keys() -> None:
    rendered = contracts.render_field_sections("intel record cve", ["provenance"])

    assert "      - code_snapshot (object)" in rendered
    assert "          - repo_id (integer, required)" in rendered
    assert "          - source_manifest_digest (string, required)" in rendered


def test_open_objects_say_that_other_keys_are_accepted() -> None:
    # `details` is additionalProperties:true on the CVE schema; declaring only
    # its one documented key without saying the object is open would read as an
    # exhaustive list and make operators drop legitimate context.
    assert "  - details (object; keys: block_reason; other keys allowed)" in (
        contracts.render_contract("intel record cve")
    )
    section = contracts.render_field_sections("intel record cve", ["details"])
    assert "  - details (object; other keys allowed)" in section
    assert "      - block_reason (string)" in section


def test_reviewed_spans_publishes_its_required_element_properties() -> None:
    line = next(
        line for line in contracts.render_contract("code-record analysis").splitlines()
        if line.startswith("  - reviewed_spans (")
    )
    assert line.startswith("  - reviewed_spans (array of object; default []")
    assert line.endswith("; keys: end_line*, file_id*, label, start_line*)")
    rendered = contracts.render_field_sections("code-record analysis", ["reviewed_spans"])

    assert "  - reviewed_spans (array of object)" in rendered
    assert "      - file_id (integer, required)" in rendered
    assert "      - start_line (integer, required)" in rendered
    assert "      - end_line (integer, required)" in rendered
    assert "      - label (string)" in rendered


def test_reviewed_spans_has_a_populated_unsupported_file_example() -> None:
    # Unsupported-language files have no registered callables, so a span is the
    # only coverage evidence they can carry. An example that only ever shows
    # `[]` never demonstrates the shape the author actually has to write.
    contract = contracts.get_contract("code-record analysis")
    assert contract is not None

    populated = [
        example
        for example in contract.examples
        if example.get("reviewed_spans")
    ]
    assert populated, "no example demonstrates a populated reviewed_spans"
    span = populated[0]["reviewed_spans"][0]
    assert set(span) >= {"file_id", "start_line", "end_line"}
    assert "file_path" not in span


def test_reviewed_span_file_path_is_a_named_mistake() -> None:
    # `cross_file_triggers` entries DO carry file_path; a span does not. The
    # near-miss is the reason the rejection is confusing enough to name.
    rendered = contracts.render_contract("code-record analysis")

    assert "file_path" in rendered
    assert "file_id" in rendered
    assert any(
        "file_path" in wrong
        for wrong, _fix in contracts.get_contract("code-record analysis").common_mistakes
    )


def test_details_keys_render_through_the_same_renderer() -> None:
    # `finding record` owns the `details` vocabulary, so each key gets its own
    # compact line (domain and required mark) instead of one `details` line.
    rendered = contracts.render_contract("finding record")

    assert "  - details (" not in rendered
    assert rendered.count("  - details.attacker_trace (") == 1
    assert "  - details.confidence (string; one of: low, medium, high)" in rendered
    assert "  - details.evidence (string, required)" in rendered


def test_schema_field_rendering_is_deterministic() -> None:
    assert contracts.render_contract("intel record cve") == contracts.render_contract(
        "intel record cve"
    )


def test_a_field_publishes_the_schema_description_after_its_domain() -> None:
    # The parenthesised domain says what a value may legally BE; the schema's
    # own description says what it MEANS, and 79% of declared properties carry
    # one. Rendering only the domain sent the author to read the schema file by
    # hand for the half of the answer the contract already had.
    rendered = contracts.render_field_sections("intel record note", ["title", "provenance"])

    assert (
        "  - title (string, required) — Short, unique title per engagement — serves as the "
        "natural dedup key"
    ) in rendered
    # Nested properties are equally invisible without this, so the description
    # follows the recursion rather than stopping at the top level.
    assert (
        "      - evidence_quote (string) — Verbatim excerpt that supports this note."
    ) in rendered


def test_a_description_is_rendered_on_one_line() -> None:
    # The contract is grepped as much as read: a wrapped description would break
    # `grep '  - <field> ('` on exactly the fields whose meaning was sought.
    rendered = contracts.render_field_sections("finding record", ["steps_to_reproduce"])

    steps = [
        line for line in rendered.splitlines()
        if line.strip().startswith("- details.steps_to_reproduce (")
    ]
    assert len(steps) == 1
    assert steps[0].split(" — ", 1)[1].strip()


def test_a_null_enum_member_renders_in_json_spelling() -> None:
    # `str(None)` prints `None`, which reads as a legal string member — an author
    # copying it writes "None" into a schema that rejects it.
    rendered = contracts.render_contract("intel record note")

    assert (
        "  - lead_status (string or null; one of: open, in_progress, resolved, "
        "ruled_out, null)"
    ) in rendered
    assert ", None)" not in rendered


def test_every_depth_blocker_kind_transition_phase_raises_is_named_in_a_contract() -> None:
    # `transition-phase` refuses the terminal report/complete edge on app-unit
    # depth, but the `app-unit` contract used to call that score "advisory,
    # never a hard block" — the contract contradicted the code, and the three
    # kinds appeared in no contract at all. Derive the kinds from the command
    # that raises them so a new one cannot land undocumented.
    source = (
        Path(transition_phase.__file__).read_text(encoding="utf-8")
    )
    kinds = set(re.findall(r'"kind":\s*"(depth_\w+)"', source))
    assert kinds, "no depth blocker kinds found in transition_phase.py"

    published = "\n".join(
        contracts.render_contract_notes(name)
        for name in ("transition-phase", "check-phase-readiness", "app-unit")
    )
    for kind in sorted(kinds):
        assert kind in published, kind


def test_code_record_examples_demonstrate_both_cross_file_trigger_targets() -> None:
    # A trigger target is checked against the current generation, and only an
    # explicit outside_snapshot flag records a target the snapshot cannot hold.
    # Examples that only ever show `[]` never teach either shape, and every
    # example must still pass the bundled schema the CLI enforces.
    from assess.lib.schema_validation import collect_validation_errors, load_schema

    contract = contracts.get_contract("code-record analysis")
    assert contract is not None
    schema = load_schema(contract.schema_name)

    for example in contract.examples:
        assert collect_validation_errors(example, schema) == []
    triggers = [
        trigger
        for example in contract.examples
        for trigger in example.get("cross_file_triggers") or []
    ]
    assert any(not trigger.get("outside_snapshot") for trigger in triggers)
    assert any(trigger.get("outside_snapshot") is True for trigger in triggers)
