"""Schema example self-consistency tests.

Every ``examples[]`` entry in each ``agent/schemas/*.json`` schema file must
validate against the schema it lives in via
``assess.lib.schema_validation.collect_validation_errors``.

This guards against schema evolution where the ``required`` list is tightened
but the embedded examples are not updated (previously the finding-record BOF
example omitted ``details.cvss_vector``, ``details.cvss_score``,
``details.remediation``, and ``details.steps_to_reproduce``).

All tests are offline and deterministic — no network, no LLM, no backend.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assess.lib.schema_validation import collect_validation_errors

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_DIR = _REPO_ROOT / "agent" / "schemas"


def _schema_files() -> list[Path]:
    return sorted(_SCHEMA_DIR.glob("*.json"))


def _example_cases() -> list[tuple[str, int, dict, dict]]:
    """Return (schema_filename, example_index, example, schema) tuples."""
    cases: list[tuple[str, int, dict, dict]] = []
    for schema_path in _schema_files():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        examples = schema.get("examples", [])
        for idx, example in enumerate(examples):
            cases.append((schema_path.name, idx, example, schema))
    return cases


_CASES = _example_cases()
_IDS = [f"{name}[{idx}]" for name, idx, _, _ in _CASES]


@pytest.mark.parametrize("schema_name,example_idx,example,schema", _CASES, ids=_IDS)
def test_schema_example_self_validates(
    schema_name: str,
    example_idx: int,
    example: dict,
    schema: dict,
) -> None:
    """Example ``example_idx`` in ``schema_name`` must have zero validation errors."""
    errors = collect_validation_errors(example, schema)
    assert errors == [], (
        f"{schema_name} examples[{example_idx}] has validation errors:\n"
        + "\n".join(f"  - {e}" for e in errors)
    )
