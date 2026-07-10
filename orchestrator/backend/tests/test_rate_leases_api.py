"""Engagement-wide target-rate lease contract."""
from __future__ import annotations

import json
from pathlib import Path


ENGAGEMENT_KEY = "2026-07-14-120000-rate-leases"


def _write_engagement(engagements_dir: Path, *, aggregate_rps: float | None = 10) -> None:
    engagement_dir = engagements_dir / ENGAGEMENT_KEY
    engagement_dir.mkdir(parents=True, exist_ok=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": ENGAGEMENT_KEY,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-07-14T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    scope = {
        "hostname": "example.com",
        "hosts": ["example.com"],
        "status": "in_progress",
        "current_phase": "recon",
    }
    if aggregate_rps is not None:
        scope["rate_limit_aggregate_rps"] = aggregate_rps
    (engagement_dir / "scope.json").write_text(json.dumps(scope), encoding="utf-8")


def _acquire(client, **overrides):
    payload = {
        "owner": "recon-specialist",
        "effective_rate_rps": 6,
        "ttl_seconds": 300,
    }
    payload.update(overrides)
    return client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/rate-leases",
        json=payload,
    )


def test_rate_lease_refuses_aggregate_over_cap(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"], aggregate_rps=10)
    first = _acquire(client)
    assert first.status_code == 201, first.text

    refused = _acquire(client, owner="web-specialist", effective_rate_rps=5)

    assert refused.status_code == 409, refused.text
    detail = refused.json()["detail"]
    assert detail["active_rate_rps"] == 6
    assert detail["requested_rate_rps"] == 5
    assert detail["aggregate_limit_rps"] == 10


def test_rate_lease_override_requires_reason_and_is_auditable(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"], aggregate_rps=10)
    assert _acquire(client).status_code == 201

    no_reason = _acquire(client, effective_rate_rps=5, override_reason="")
    assert no_reason.status_code == 409

    allowed = _acquire(
        client,
        owner="operator-approved-specialist",
        effective_rate_rps=5,
        override_reason="Program approved a short coordinated burst",
    )
    assert allowed.status_code == 201, allowed.text
    assert allowed.json()["override_reason"].startswith("Program approved")
    assert allowed.json()["aggregate_limit_rps"] == 10


def test_rate_lease_release_removes_rate_from_active_total(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"], aggregate_rps=10)
    first = _acquire(client).json()

    released = client.patch(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/rate-leases/{first['lease_token']}",
        json={"release": True},
    )
    assert released.status_code == 200, released.text
    assert released.json()["released_at"] is not None

    replacement = _acquire(client, owner="web-specialist", effective_rate_rps=10)
    assert replacement.status_code == 201, replacement.text


def test_rate_lease_renewal_rejects_released_token(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"], aggregate_rps=10)
    lease = _acquire(client).json()
    endpoint = (
        f"/engagements/{ENGAGEMENT_KEY}/assessment/rate-leases/"
        f"{lease['lease_token']}"
    )
    assert client.patch(endpoint, json={"release": True}).status_code == 200

    renew = client.patch(endpoint, json={"ttl_seconds": 600})

    assert renew.status_code == 409


def test_rate_lease_unconfigured_cap_allows_declaration(client, isolate_settings):
    _write_engagement(isolate_settings["engagements_dir"], aggregate_rps=None)
    response = _acquire(client, effective_rate_rps=500)
    assert response.status_code == 201, response.text
    assert response.json()["aggregate_limit_rps"] is None


def test_expired_rate_lease_does_not_consume_capacity(client, isolate_settings):
    from app.db import get_connection

    _write_engagement(isolate_settings["engagements_dir"], aggregate_rps=10)
    first = _acquire(client, effective_rate_rps=10).json()
    with get_connection() as connection:
        connection.execute(
            "UPDATE assessment_rate_leases SET expires_at = ? WHERE lease_token = ?",
            ("2000-01-01T00:00:00Z", first["lease_token"]),
        )

    replacement = _acquire(client, owner="replacement", effective_rate_rps=10)

    assert replacement.status_code == 201, replacement.text
