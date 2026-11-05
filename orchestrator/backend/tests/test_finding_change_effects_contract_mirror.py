"""The finding write contracts document the verdict effects the backend applies.

``finding_change_policy`` owns what every finding write does to a verdict. Agent
code cannot import the backend package, so ``contract_registry.FINDING_CHANGE_EFFECTS``
is a hand-written mirror that renders into the contract notes of every verb that
writes a finding. A row added to the policy and not to the mirror is an effect no
agent can anticipate; a row left in the mirror teaches an effect the backend no
longer applies.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS_ROOT = Path(__file__).resolve().parents[3] / "agent" / "scripts"
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from app.services.state_manager import finding_change_policy  # noqa: E402
from assess.lib import contract_registry, contracts  # noqa: E402


def test_documented_change_effects_mirror_the_policy_table():
    assert list(contract_registry.FINDING_CHANGE_EFFECTS) == finding_change_policy.effect_table()


@pytest.mark.parametrize(
    "verb", ["finding update", "finding link", "finding merge", "finding relocate"]
)
def test_every_finding_write_contract_renders_each_effect(verb):
    notes = contracts.render_contract(verb).split("Notes:", 1)[1]
    for effect in finding_change_policy.Effect:
        line = next(
            (row for row in notes.splitlines() if row.startswith(f"  - Verdict effect {effect.value} (")),
            None,
        )
        assert line is not None, (verb, effect)
        for axis, row_effect in contract_registry.FINDING_CHANGE_EFFECTS:
            if row_effect == effect.value:
                assert axis in line, (verb, axis)
