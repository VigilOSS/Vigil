"""An operator-attested chain leg counts as verified when the report proves a chain.

ADR 0043's operator-authority verdict is a terminal `confirmed`/`downgraded`
reached on the operator's own out-of-snapshot evidence. The report delivers it
(with its stamp), so a chain whose steps are all delivered verified findings is
proven whether a leg was dispatch-verified or operator-attested.
"""
from __future__ import annotations

from tests.test_report_export import (
    _add_finding,
    _chain,
    _export,
    _injected_payload,
    _medium_finding,
    _operator_authority_downgrade,
    _record_finding,
    _seed,
    _step,
    fake_template,  # noqa: F401 - fixture
)


def test_an_operator_attested_leg_counts_toward_chain_proven_severity(
    client, isolate_settings, fake_template  # noqa: F811 - fixture
):
    _seed(client, isolate_settings)
    _add_finding(client, _medium_finding("VA-140", "Admin router guard skipped"))
    _record_finding(client, _medium_finding("VA-141", "Admin export reachable"))
    _operator_authority_downgrade(client, "VA-141")
    _chain(client, "chain-operator-leg", "high", [_step("VA-140"), _step("VA-141")])

    response = _export(client, mode="draft")
    assert response.status_code == 200, response.text
    payload = _injected_payload(isolate_settings, response.json()["relative_path"])

    records = {
        record["slug"]: record for record in payload["finding_groups"]["standalone"]
    }
    assert records["VA-141"]["operator_authority"]["kind"] == "out_of_snapshot"
    assert records["VA-141"]["verification_status"] == "downgraded"
    proven = {chain["chain_key"]: chain["chain_proven"] for chain in payload["attack_chains"]}
    assert proven == {"chain-operator-leg": True}
    assert payload["summary"]["chain_proven_severity"] == "high"
