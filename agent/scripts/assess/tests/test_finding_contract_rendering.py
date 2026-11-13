"""What the finding contracts must PRINT, not merely hold in metadata.

``vigil assess contract`` is the only operator-facing surface for a verb's
payload truth, so these are rendering assertions: a field the registry carries
but the renderer drops is invisible to every agent that asks, and a required
mark the renderer prints from a source that does not describe the author's job
is a falsehood the author has no way to catch.

* ``finding update`` prints its own top-level patch fields (its request shape is
  a backend Pydantic model, not a bundled schema, so nothing derives them), and
  its ``details`` field points at ``finding record`` for the shared vocabulary.
* ``finding record`` marks ``required`` only what an AUTHOR must write. The
  schema's ``required`` array is a post-normalization contract — the CLI
  ``setdefault``s most of its names before validation runs — so a name a helper
  default fills is printed with that default instead.
* Every ``details`` key has its own line, and ``--field`` prints its schema
  description; every note stays reachable through ``--notes``.
"""
from __future__ import annotations

import re

import pytest

from assess.lib import contracts

_FIELD_LINE = re.compile(r"^  - (?P<path>[\w.]+) \((?P<domain>[^)]*)")


def _field_lines(text: str) -> dict[str, str]:
    """Compact field path -> its parenthesised domain."""
    fields: dict[str, str] = {}
    in_fields = False
    for line in text.splitlines():
        if line.startswith("Fields ("):
            in_fields = True
            continue
        if in_fields and not line.strip():
            break
        match = _FIELD_LINE.match(line) if in_fields else None
        if match:
            fields[match.group("path")] = match.group("domain")
    return fields


@pytest.fixture(scope="module")
def record_fields() -> dict[str, str]:
    return _field_lines(contracts.render_contract("finding record"))


@pytest.fixture(scope="module")
def update_fields() -> dict[str, str]:
    return _field_lines(contracts.render_contract("finding update"))


def test_update_prints_its_top_level_patch_fields(update_fields):
    # Every documented patch field reaches the rendered output, including the
    # ones a patcher cannot guess and cannot find anywhere else.
    assert set(update_fields) == {name for name, _, _ in contracts.FINDING_PATCH_FIELDS}
    assert {"notes_mode", "details_mode", "expected_row_version", "reason_text"} <= set(update_fields)


def test_update_details_field_points_at_record_for_the_vocabulary():
    section = contracts.render_field_sections("finding update", ["details"])
    assert "vigil assess contract finding record" in section


def test_record_marks_required_only_what_the_author_supplies(record_fields):
    required = {path for path, domain in record_fields.items() if ", required" in domain}
    assert required == {"title", "details.evidence", "details.impact"}


def test_record_helper_filled_names_carry_their_default(record_fields):
    helper_filled = {key for key, _ in contracts.get_contract("finding record").helper_defaults}
    for path in helper_filled & set(record_fields):
        domain = record_fields[path]
        assert ", required" not in domain, f"{path} is helper-filled; an author never supplies it"
        assert "default " in domain or "helper-filled" in domain, path
    # The record-time verification value is the one a payload must not override.
    assert "default unreviewed" in record_fields["verification_status"]


def test_every_details_key_has_a_line_and_a_described_section(record_fields):
    schema = contracts.load_schema("finding-record.schema.json")
    details = schema["properties"]["details"]["properties"]
    for key, prop in details.items():
        assert f"details.{key}" in record_fields, key
        if prop.get("description"):
            section = contracts.render_field_sections("finding record", [f"details.{key}"])
            head = next(line for line in section.splitlines() if line.startswith(f"  - details.{key} ("))
            assert " — " in head, f"{key} renders without its schema description"


def test_every_record_note_is_reachable():
    contract = contracts.get_contract("finding record")
    notes = contracts.render_contract_notes("finding record")
    for note in contract.notes:
        assert note in notes


def test_a_field_section_carries_the_notes_and_mistakes_that_name_it():
    # `--field` is the refusal-time read, so the rules about a field travel with
    # its schema line rather than staying behind in `--notes`.
    section = contracts.render_field_sections("finding record", ["evidence_ref"])
    contract = contracts.get_contract("finding record")
    naming = [note for note in contract.notes if "evidence_ref" in note]
    assert naming
    for note in naming:
        assert note in section
