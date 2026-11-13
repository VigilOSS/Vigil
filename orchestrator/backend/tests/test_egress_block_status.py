"""The egress banner reads the structured egress-check decision, not command intent text."""
from __future__ import annotations

import pytest

from app.services import state_manager
from tests.test_engagements_api import write_engagement

ENGAGEMENT_KEY = "2026-05-17-100000-egress"


@pytest.fixture
def engagement_id(client, isolate_settings) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def _connectivity_check(**overrides) -> dict:
    payload = {
        "subtype": "connectivity_check",
        "verdict": "cluster_blackholed",
        "blocked_pct": 80,
        "sampled": 5,
        "classified": 5,
        "sample_observations": {f"h{i}.acme.example": "blackholed" for i in range(4)}
        | {"h4.acme.example": "live"},
        "waf_or_edge_observations": {},
        "blackholed_hosts": [f"h{i}.acme.example" for i in range(4)],
    }
    payload.update(overrides)
    return payload


def _record(engagement_id: int, payload: dict, kind: str = "egress_decision") -> None:
    state_manager.record_decision(engagement_id, kind=kind, payload=payload, surfaced_to_user=True)


def test_status_comes_from_the_latest_connectivity_check(engagement_id):
    _record(engagement_id, _connectivity_check(blocked_pct=20, blackholed_hosts=["h0.acme.example"]))
    _record(engagement_id, _connectivity_check())

    status = state_manager.egress_block_status(engagement_id)

    assert status["blocked_pct"] == 80
    assert status["pattern"] == "geoblock-reset"
    assert status["samples_total"] == 5
    assert status["samples_blocked"] == 4
    assert status["checked_at"]


@pytest.mark.parametrize(
    ("blackholed", "waf", "pattern"),
    [
        ([], {"h0.acme.example": "cloudflare challenge"}, "cdn-403"),
        (["h1.acme.example"], {"h0.acme.example": "cloudflare challenge"}, "mixed"),
        ([], {}, "unknown"),
    ],
)
def test_pattern_follows_the_recorded_classifications(engagement_id, blackholed, waf, pattern):
    _record(engagement_id, _connectivity_check(blocked_pct=60, blackholed_hosts=blackholed,
                                               waf_or_edge_observations=waf))

    assert state_manager.egress_block_status(engagement_id)["pattern"] == pattern


def test_only_the_recorded_connectivity_check_counts(engagement_id):
    """Only the decision egress-check records counts; other rows leave it unsampled."""
    _record(engagement_id, {"choice": "browser-based-tool", "egress_block_pct": 67})
    _record(engagement_id, {"subtype": "waf_challenge", "host": "h0.acme.example"})
    _record(engagement_id, {"subtype": "connectivity_check", "blocked_pct": 90}, kind="scope_decision")

    status = state_manager.egress_block_status(engagement_id)

    assert status == {"blocked_pct": 0, "pattern": "unknown", "samples_total": 0,
                      "samples_blocked": 0, "checked_at": None}
