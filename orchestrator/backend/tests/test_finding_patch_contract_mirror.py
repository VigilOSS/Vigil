"""`finding update`'s documented patch fields mirror ``FindingPatchRequest``.

The patch request is a backend Pydantic model with no bundled schema, so the
contract renderer cannot derive its top-level fields the way it does for every
``*.schema.json`` verb — ``contracts.FINDING_PATCH_FIELDS`` is a hand-written
mirror, and a hand-written mirror is the shape that rots. Agent code cannot
import the backend package, so the pin lives here, beside the other CLI-mirror
guards in this suite.

A field added to ``FindingPatchRequest`` and not to the roster is invisible to
every agent that reads the contract; a field dropped from the model and left in
the roster teaches a patch the API rejects with a 422.
"""
from __future__ import annotations

import sys
from pathlib import Path

# The assess CLI package lives under agent/scripts (mirrors test_record_finding.py).
_SCRIPTS_ROOT = Path(__file__).resolve().parents[3] / "agent" / "scripts"
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from app.api.assessment import FindingPatchRequest  # noqa: E402
from assess.lib import contracts  # noqa: E402


def test_documented_patch_fields_mirror_the_backend_model():
    documented = {name for name, _, _ in contracts.FINDING_PATCH_FIELDS}
    assert documented == set(FindingPatchRequest.model_fields)


def test_every_documented_patch_field_renders():
    text = contracts.render_contract("finding update")
    assert "Allowed top-level fields:" in text
    fields = text.split("Allowed top-level fields:", 1)[1].split("\n\n", 1)[0]
    for name, annotation, description in contracts.FINDING_PATCH_FIELDS:
        assert f"  - {name} (" in fields
        assert annotation.strip(), f"{name} carries no type annotation"
        assert description.strip(), f"{name} carries no description"
