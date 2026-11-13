"""A finding write naming a field the request does not have says where it belongs.

The request models refuse unknown fields (``extra="forbid"``) so a typo never
lands silently; the refusal names each unknown field and its home — a details
key, a provenance key, the request field it misspells — instead of the bare
"Extra inputs are not permitted".
"""
from __future__ import annotations

import pytest

from tests.test_finding_change_policy import _record
from tests.test_verification_status_contract import BASE, _finding_payload, _seed


@pytest.fixture
def seeded(client, isolate_settings):
    _seed(client, isolate_settings)
    _record(client, "VA-700")


def _messages(response) -> str:
    assert response.status_code == 422, response.text
    return " ".join(str(item.get("msg", "")) for item in response.json()["detail"])


@pytest.mark.parametrize(
    ("method", "path", "body", "field", "home"),
    [
        ("post", "/findings", {**_finding_payload("VA-701"), "cvss_score": 7.5},
         "cvss_score", "details.cvss_score"),
        ("patch", "/findings/VA-700", {"agent_id": "HUNT-A"},
         "agent_id", "provenance.agent_id"),
        ("patch", "/findings/VA-700", {"sumary": "revised"}, "sumary", "summary"),
        ("patch", "/findings/VA-700", {"verification_status": "confirmed"},
         "verification_status", "finding verify"),
        ("post", "/findings/VA-700/verify",
         {"verification_status": "blocked", "block_reason": "no Acme account"},
         "block_reason", "details.block_reason"),
        ("post", "/findings/VA-700/verify",
         {"verification_status": "blocked", "reason": "no Acme account"},
         "reason", "reason_text"),
        ("post", "/findings/VA-700/verify",
         {"verification_status": "downgraded", "severity": "low"},
         "severity", "new_severity"),
    ],
)
def test_an_unknown_request_field_names_its_home(
    client, seeded, method, path, body, field, home
):
    response = getattr(client, method)(f"{BASE}{path}", json=body)

    message = _messages(response)
    assert repr(field) in message, message
    assert home in message, message


def test_an_unknown_nested_details_field_names_the_allowed_ones(client, seeded):
    response = client.patch(f"{BASE}/findings/VA-700", json={
        "details": {"ghsa": {"ecosystem": "pip", "package": "acme-orders"}},
    })

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "details.ghsa.package" in detail
    assert "package_name" in detail


def test_each_unknown_field_is_its_own_error_beside_the_other_errors(client, seeded):
    """One error per unknown field, located at the field, and the request's other
    validation errors still reported in the same response."""
    response = client.post(f"{BASE}/findings/VA-700/verify", json={
        "verification_status": "not-a-status", "reason": "x", "zzz": 1,
    })

    assert response.status_code == 422, response.text
    errors = response.json()["detail"]
    by_loc = {tuple(error["loc"]): error for error in errors}
    assert by_loc[("body", "reason")]["type"] == "extra_forbidden"
    assert "reason_text" in by_loc[("body", "reason")]["msg"]
    assert by_loc[("body", "zzz")]["type"] == "extra_forbidden"
    assert "'zzz'" in by_loc[("body", "zzz")]["msg"]
    assert ("body", "verification_status") in by_loc
