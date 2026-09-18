"""The code-dispatch contract declares the lease-specific scratch directory.

`code-dispatch fetch` creates one scratch directory per claimed queue item and
returns it on the item. It is the only temp location that is engagement-contained
and lane-private, so a specialist that instead writes into the client harness's
own scratchpad leaves evidence outside the engagement and collides with the other
lanes sharing that directory. The contract has to name the field, say it wins over
a client-provided location, and state the filename rule for any directory the
harness shares.
"""
from __future__ import annotations

from assess.lib import contracts


def _dispatch_contract() -> contracts.CommandContract:
    contract = contracts.get_contract("code-dispatch")
    assert contract is not None
    return contract


def test_scratch_dir_is_a_declared_helper_supplied_field() -> None:
    defaults = dict(_dispatch_contract().helper_defaults)

    assert "scratch_dir" in defaults
    assert "tools/analysis-state/code-dispatch-scratch" in defaults["scratch_dir"]


def test_contract_prefers_the_lease_scratch_dir_over_client_scratch_locations() -> None:
    notes = " ".join(_dispatch_contract().notes)

    assert "scratch_dir" in notes
    assert "client" in notes
    assert "lane-unique" in notes
