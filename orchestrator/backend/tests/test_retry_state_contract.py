"""Blocked-technique retry state is a bounded, service-owned contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.services import state_manager
from app.services.engagements import get_engagement_or_404

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "agent" / "scripts"))
from assess.commands.block_technique import RETRY_STATES as CLI_RETRY_STATES  # noqa: E402
from app.services.state_manager.chains import RETRY_STATES  # noqa: E402


ENGAGEMENT_KEY = "2026-09-08-120000-retry-state"


def test_retry_state_vocabulary_stays_in_sync_with_the_cli() -> None:
    assert CLI_RETRY_STATES == RETRY_STATES


def _seed(client, engagements_dir: Path) -> int:
    engagement = engagements_dir / ENGAGEMENT_KEY
    engagement.mkdir(parents=True)
    (engagement / "engagement.json").write_text(
        json.dumps(
            {
                "key": ENGAGEMENT_KEY,
                "target": "https://example.com",
                "created_at": "2026-09-08T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "hosts": ["example.com"],
                "status": "in_progress",
                "current_phase": "recon",
            }
        ),
        encoding="utf-8",
    )
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return get_engagement_or_404(ENGAGEMENT_KEY).id


@pytest.mark.parametrize(
    "retry_state",
    [
        "pending",
        "no_retry",
        "retryable",
        "blocked",
        "blocked_on_dependency",
        "needs_authorization",
    ],
)
def test_blocked_technique_service_accepts_all_reviewed_retry_states(
    client,
    isolate_settings,
    retry_state: str,
) -> None:
    engagement_id = _seed(client, isolate_settings["engagements_dir"])

    record = state_manager.record_blocked_technique(
        engagement_id,
        technique_key=f"ssrf:host:{retry_state}",
        technique="SSRF",
        target_kind="host",
        target_ref="api.example.com",
        reason="reviewed block",
        retry_state=retry_state,
        evidence_ref="",
        notes="",
        provenance={"agent_name": "operator"},
    )

    assert record["retry_state"] == retry_state


def test_blocked_technique_service_rejects_unreviewed_retry_state(
    client,
    isolate_settings,
) -> None:
    engagement_id = _seed(client, isolate_settings["engagements_dir"])

    with pytest.raises(HTTPException, match="retry_state") as exc:
        state_manager.record_blocked_technique(
            engagement_id,
            technique_key="ssrf:host:forever",
            technique="SSRF",
            target_kind="host",
            target_ref="api.example.com",
            reason="unreviewed prose state",
            retry_state="never-again-probably",
            evidence_ref="",
            notes="",
            provenance={"agent_name": "operator"},
        )

    assert exc.value.status_code == 400


def test_blocked_technique_updates_append_auditable_revalidation_history(
    client,
    isolate_settings,
) -> None:
    engagement_id = _seed(client, isolate_settings["engagements_dir"])
    common = {
        "engagement_id": engagement_id,
        "technique_key": "ssrf:host:api",
        "technique": "SSRF",
        "target_kind": "host",
        "target_ref": "api.example.com",
        "evidence_ref": "evidence/egress.txt",
        "notes": "operator review required",
    }

    created = state_manager.record_blocked_technique(
        **common,
        reason="initial network wall",
        retry_state="pending",
        provenance={"source_name": "specialist-a"},
        revalidation_context={"actor": "specialist-a", "basis": "first observation"},
    )
    updated = state_manager.record_blocked_technique(
        **common,
        reason="second identity reproduced the wall",
        retry_state="blocked_on_dependency",
        provenance={"source_name": "verifier-b"},
        revalidation_context={
            "actor": "verifier-b",
            "basis": "independent identity replay",
        },
    )

    assert created["id"] == updated["id"]
    history = state_manager.list_blocked_technique_history(
        engagement_id, technique_key="ssrf:host:api"
    )
    assert [row["event_kind"] for row in history] == [
        "retry_state_changed",
        "created",
    ]
    assert history[0]["from_retry_state"] == "pending"
    assert history[0]["to_retry_state"] == "blocked_on_dependency"
    assert history[0]["reason"] == "second identity reproduced the wall"
    assert history[0]["provenance"] == {"source_name": "verifier-b"}
    assert history[0]["revalidation_context"] == {
        "actor": "verifier-b",
        "basis": "independent identity replay",
    }
    assert history[1]["reason"] == "initial network wall"
    assert history[1]["provenance"] == {"source_name": "specialist-a"}


def test_same_retry_state_is_recorded_as_revalidation(client, isolate_settings) -> None:
    engagement_id = _seed(client, isolate_settings["engagements_dir"])
    common = {
        "engagement_id": engagement_id,
        "technique_key": "auth:host:portal",
        "technique": "BFLA",
        "target_kind": "host",
        "target_ref": "portal.example.com",
        "reason": "requires an org-admin account",
        "retry_state": "needs_authorization",
        "evidence_ref": "",
        "notes": "",
        "provenance": {"source_name": "operator"},
    }
    state_manager.record_blocked_technique(
        **common, revalidation_context={"actor": "operator", "basis": "scope review"}
    )
    state_manager.record_blocked_technique(
        **common,
        revalidation_context={"actor": "operator", "basis": "resume review"},
    )

    history = state_manager.list_blocked_technique_history(
        engagement_id, technique_key="auth:host:portal"
    )
    assert [row["event_kind"] for row in history] == ["revalidated", "created"]
    assert history[0]["revalidation_context"]["basis"] == "resume review"


def test_blocked_technique_api_validates_state_and_exposes_bounded_history(
    client,
    isolate_settings,
) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    endpoint = f"/engagements/{ENGAGEMENT_KEY}/assessment/blocked-techniques"
    payload = {
        "technique_key": "ssrf:host:api",
        "technique": "SSRF",
        "target_kind": "host",
        "target_ref": "api.example.com",
        "reason": "identity cannot reach the service",
        "retry_state": "blocked_on_dependency",
        "provenance": {"source_name": "specialist-a"},
        "revalidation_context": {
            "actor": "specialist-a",
            "basis": "account-bound replay",
        },
    }

    created = client.post(endpoint, json=payload)
    assert created.status_code == 201, created.text
    rejected = client.post(endpoint, json={**payload, "retry_state": "never again"})
    assert rejected.status_code == 422, rejected.text

    history = client.get(
        f"{endpoint}/history",
        params={"technique_key": "ssrf:host:api", "limit": 10},
    )
    assert history.status_code == 200, history.text
    assert len(history.json()) == 1
    assert history.json()[0]["revalidation_context"] == {
        "actor": "specialist-a",
        "basis": "account-bound replay",
    }
