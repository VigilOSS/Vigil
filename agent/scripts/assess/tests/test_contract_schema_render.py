"""`vigil assess contract <verb>` publishes the whole authoring surface.

A bundled schema is strict: an unknown key, or a value outside a declared enum,
is rejected before the backend is contacted. The contract is the only place an
agent can read that vocabulary, so a field list that stops at the top level and
prints no accepted values sends the author back to guessing. One schema-aware
renderer owns enum domains, nested object keys, and per-property required
marking for every schema-backed contract — intel record types and the code
analysis receipt alike.
"""
from __future__ import annotations

import pytest

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
    # same provenance object and every contract must publish its legal keys.
    rendered = contracts.render_contract(f"intel record {intel_type}")

    assert "  - provenance (object)" in rendered
    for key in ("agent_name", "artifact_ref", "captured_at", "command_run_id"):
        assert f"      - {key} (" in rendered, key


def test_intel_contract_expands_a_second_level_object_with_required_keys() -> None:
    rendered = contracts.render_contract("intel record cve")

    assert "      - code_snapshot (object)" in rendered
    assert "          - repo_id (integer, required)" in rendered
    assert "          - source_manifest_digest (string, required)" in rendered


def test_open_objects_say_that_other_keys_are_accepted() -> None:
    # `details` is additionalProperties:true on the CVE schema; declaring only
    # its one documented key without saying the object is open would read as an
    # exhaustive list and make operators drop legitimate context.
    rendered = contracts.render_contract("intel record cve")

    assert "  - details (object; other keys allowed)" in rendered
    assert "      - block_reason (string)" in rendered


def test_reviewed_spans_publishes_its_required_element_properties() -> None:
    rendered = contracts.render_contract("code-record analysis")

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
    # `finding record` documents `details` in its own deeper section. The
    # top-level list must point at that section instead of printing the same
    # ~60 keys twice, and the section itself gains the domains/required marks.
    rendered = contracts.render_contract("finding record")

    assert '  - details (object; see "Allowed details keys" below)' in rendered
    assert rendered.count("  - attacker_trace (") == 1
    assert "  - confidence (string; one of: low, medium, high)" in rendered
    assert "  - evidence (string, required)" in rendered


def test_schema_field_rendering_is_deterministic() -> None:
    assert contracts.render_contract("intel record cve") == contracts.render_contract(
        "intel record cve"
    )
