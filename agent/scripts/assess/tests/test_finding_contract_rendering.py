"""What the finding contracts must PRINT, not merely hold in metadata.

``vigil assess contract`` is the only operator-facing surface for a verb's
payload truth, so these are rendering assertions: a field the registry carries
but the renderer drops is invisible to every agent that asks, and a section the
renderer prints from a source that does not describe this verb is a falsehood
the author has no way to catch.

Three rendered claims are pinned here:

* ``finding update`` prints its own top-level patch fields (its request shape is
  a backend Pydantic model, not a bundled schema, so nothing derives them) and
  POINTS at ``finding record`` for the shared ``details`` vocabulary instead of
  re-rendering 15 KB of it.
* ``finding record``'s required-fields section names what an AUTHOR must write.
  The schema's ``required`` array is a post-normalization contract — the CLI
  ``setdefault``s ten of its twelve names before validation ever runs — so
  rendering it verbatim told authors to supply values the helper owns, and
  contradicted the helper-defaults section two sections above it.
* The notes carry only what the generated schema block does not already print.
"""
from __future__ import annotations

import pytest

from assess.lib import contracts


def _field_name(line: str) -> str:
    """The field name a rendered bullet opens with."""
    return line.strip().lstrip("- ").split("(")[0].split()[0]


def _section(text: str, heading: str) -> list[str]:
    """The bullet lines under ``heading`` in a rendered contract."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(heading):
            break
    else:
        return []
    body: list[str] = []
    for line in lines[index + 1 :]:
        if not line.strip():
            break
        body.append(line)
    return body


@pytest.fixture(scope="module")
def record_text() -> str:
    return contracts.render_contract("finding record")


@pytest.fixture(scope="module")
def update_text() -> str:
    return contracts.render_contract("finding update")


# --------------------------------------------------------------------------- #
# finding update — its own patch fields, and a pointer for the shared details
# --------------------------------------------------------------------------- #


def test_update_prints_its_top_level_patch_fields(update_text):
    fields = _section(update_text, "Allowed top-level fields:")
    names = {_field_name(line) for line in fields}
    # Every documented patch field reaches the rendered output.
    assert names == {name for name, _, _ in contracts.FINDING_PATCH_FIELDS}
    # The ones a patcher cannot guess and cannot find anywhere else.
    assert {"notes_mode", "details_mode", "expected_row_version", "reason_text"} <= names


def test_update_points_at_record_for_the_details_vocabulary(update_text):
    # The 15 KB details block belongs to `finding record`; `finding update`
    # writes the same object through the same client-side schema check.
    assert "Allowed details keys" not in update_text
    assert "vigil assess contract finding record" in update_text


def test_update_keeps_what_is_specific_to_patching(update_text):
    # Merge-vs-replace and the compare-and-swap requirement are patch-only and
    # appear in no other contract.
    assert "--details-replace" in update_text
    assert "details_mode" in update_text
    assert "expected_row_version" in update_text


# --------------------------------------------------------------------------- #
# finding record — required means author-required
# --------------------------------------------------------------------------- #


def test_record_required_section_names_only_author_required_fields(record_text):
    required = {
        _field_name(line) for line in _section(record_text, "Required top-level fields")
    }
    assert required == {"title", "details"}


def test_record_required_section_excludes_helper_filled_names(record_text):
    required = _section(record_text, "Required top-level fields")
    helper_filled = {key for key, _ in contracts.get_contract("finding record").helper_defaults}
    for line in required:
        name = _field_name(line)
        assert name not in helper_filled, f"{name} is helper-filled; an author never supplies it"


def test_record_required_section_names_the_details_sub_keys(record_text):
    # `details` is helper-CREATED but never helper-SATISFIED: the object still
    # fails validation without these two, which is the whole reason it stays.
    body = "\n".join(_section(record_text, "Required top-level fields"))
    assert "evidence" in body and "impact" in body


def test_record_required_section_does_not_contradict_helper_defaults(record_text):
    # The helper-defaults line calls unreviewed "the ONLY record-time value";
    # listing verification_status as author-required said the opposite.
    assert "the ONLY record-time value" in record_text
    assert "verification_status" not in "\n".join(
        _section(record_text, "Required top-level fields")
    )


# --------------------------------------------------------------------------- #
# finding record — notes carry only what the schema block does not print
# --------------------------------------------------------------------------- #


# The four notes deleted here restated keys the generated details block already
# prints with a fuller schema description. Each phrase is the note's own opening,
# not a word the surviving notes could reuse by coincidence.
_RESTATED_NOTE_OPENINGS = (
    "Code-specific detail fields are valid:",
    "details.poc_code holds exploit scripts",
    "details.steps_to_reproduce is written FROM WHAT YOU ACTUALLY RAN",
    "details.references is an array of strings",
)

_RESTATED_KEYS = (
    "entry_point",
    "sink",
    "taint_path",
    "guards_evaluated",
    "slot_type",
    "variant_of",
    "original_pattern",
    "poc_code",
    "poc_request",
    "poc_response",
    "references",
    "steps_to_reproduce",
    "repro_runs",
)


@pytest.mark.parametrize("opening", _RESTATED_NOTE_OPENINGS)
def test_schema_restating_notes_are_gone(record_text, opening):
    notes = "\n".join(_section(record_text, "Notes:"))
    assert opening not in notes


@pytest.mark.parametrize("key", _RESTATED_KEYS)
def test_restated_keys_survive_in_the_block_that_owns_them(record_text, key):
    # Deleting the notes must not delete the documentation: each key keeps its
    # own line, with its schema description, under "Allowed details keys".
    line = next(
        (entry for entry in _section(record_text, "Allowed details keys") if entry.startswith(f"  - {key} (")),
        "",
    )
    assert line, f"{key} lost its entry in the details block"
    assert " — " in line, f"{key} renders without its schema description"


def test_notes_keep_the_rules_that_exist_nowhere_else(record_text):
    notes = "\n".join(_section(record_text, "Notes:"))
    for rule in (
        "Dedup keys on",
        "Kill re-mint guard (D4)",
        "--agent-id <dispatch agent_id>",
        "evidence_ref should point at ONE existing engagement path",
        "block_reason",
    ):
        assert rule in notes
