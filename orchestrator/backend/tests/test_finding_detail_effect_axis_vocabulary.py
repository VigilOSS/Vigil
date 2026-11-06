"""Every `details.*` verdict axis must name a detail key that exists.

`finding_change_policy.effect_table()` is rendered verbatim into the contract of
every finding write verb, so each row is an authoritative statement about what a
write does to a verdict. A row naming a `details` key that is not in
`FINDING_DETAIL_PROPERTIES` describes an axis NO finding can ever move: the
details object is validated under `additionalProperties: false`, so the key
cannot be written, cannot be removed, and the rule can never fire.

`test_finding_change_effects_contract_mirror` does not catch this. It pins the
assess mirror to the policy table — mirror -> policy — and both sides agree on a
key that the detail vocabulary has never held. This file closes the third edge:
policy -> vocabulary.
"""
from __future__ import annotations

from app.services.state_manager import finding_change_policy
from app.services.state_manager.finding_details import FINDING_DETAIL_PROPERTIES


_DETAIL_PREFIX = "details."
# `details.*` is the deliberate catch-all row for every detail key without one
# of its own, not a key.
_WILDCARD_AXIS = finding_change_policy.DEFAULT_DETAIL_AXIS


def _detail_key(axis: str) -> str:
    """The detail key an axis names, stripped of the `.removed` qualifier."""
    key = axis[len(_DETAIL_PREFIX):]
    return key.removesuffix(".removed")


def test_every_detail_axis_resolves_to_a_declared_detail_key() -> None:
    axes = [
        axis
        for axis, _effect in finding_change_policy.effect_table()
        if axis.startswith(_DETAIL_PREFIX) and axis != _WILDCARD_AXIS
    ]
    assert axes, "no details.* axes found — effect_table() changed shape"

    unreachable = sorted(
        axis for axis in axes if _detail_key(axis) not in FINDING_DETAIL_PROPERTIES
    )
    assert not unreachable, (
        "the finding-change policy names details keys the detail vocabulary does "
        "not declare, so these axes are unreachable for every finding and the "
        "contract of every finding write verb publishes them as live rules: "
        + ", ".join(unreachable)
        + ". Either register the key in finding_details.FINDING_DETAIL_CORE_PROPERTIES "
        "(or an extension) or drop it from the policy set that generated the axis "
        "(PROOF_DEPENDENCY_DETAIL_KEYS / DETAIL_KEY_EFFECTS), then re-run the "
        "contract mirror test."
    )


def test_the_proof_dependency_keys_are_all_writable() -> None:
    """The removal rules exist to protect evidence a finding actually carries.

    A proof-dependency key that cannot be written is not protecting anything —
    it is a rule whose trigger condition no record can reach.
    """
    unwritable = sorted(
        key
        for key in finding_change_policy.PROOF_DEPENDENCY_DETAIL_KEYS
        if key not in FINDING_DETAIL_PROPERTIES
    )
    assert not unwritable, (
        "PROOF_DEPENDENCY_DETAIL_KEYS protects detail keys no finding can hold: "
        + ", ".join(unwritable)
    )
