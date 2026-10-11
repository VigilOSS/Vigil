"""Dispatch records separate requested runtime from trustworthy provenance."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


ENGAGEMENT_KEY = "2026-09-08-120000-dispatch-provenance"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, engagements_dir: Path) -> None:
    engagement = engagements_dir / ENGAGEMENT_KEY
    engagement.mkdir(parents=True)
    (engagement / "engagement.json").write_text(
        json.dumps(
            {
                "key": ENGAGEMENT_KEY,
                "target": "https://example.com",
                "hostname": "example.com",
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


def test_dispatch_instruction_provenance_round_trips(
    client,
    isolate_settings,
) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    payload = {
        "agent_id": "PROVENANCE-1",
        "agent_role": "recon-specialist",
        "requested_model": "gpt-requested",
        "requested_reasoning": "high",
        "client_name": "codex",
        "requested_client": "claude",
        "launcher_effective_client": "codex",
        "provider_observed_client": "unknown",
        "source_revision": "a" * 40,
        "operator_instruction_path": "agent/AGENTS.md",
        "operator_instruction_sha256": "b" * 64,
        "specialist_instruction_path": "agent/.codex/agents/recon-specialist.toml",
        "specialist_instruction_sha256": "c" * 64,
        "instruction_identity_status": "verified",
        "instructions_stale": False,
    }

    created = client.post(f"{BASE}/dispatches", json=payload)

    assert created.status_code == 201, created.text
    for key, value in payload.items():
        assert created.json()[key] == value
    assert created.json()["actual_model"] == "unknown"
    assert created.json()["actual_reasoning"] == "unknown"
    assert created.json()["launcher_effective_model"] is None
    assert created.json()["launcher_effective_reasoning"] is None
    assert created.json()["launcher_effective_source"] is None
    fetched = client.get(f"{BASE}/dispatches/PROVENANCE-1")
    listed = client.get(f"{BASE}/dispatches")
    assert fetched.status_code == 200, fetched.text
    assert listed.status_code == 200, listed.text
    assert fetched.json() == created.json()
    assert listed.json() == [created.json()]


def test_dispatch_rejects_caller_claimed_provider_observation(
    client,
    isolate_settings,
) -> None:
    _seed(client, isolate_settings["engagements_dir"])

    response = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "FORGED-PROVIDER",
            "agent_role": "recon-specialist",
            "provider_observed_client": "codex",
        },
    )

    assert response.status_code == 422, response.text


def test_dispatch_api_rejects_caller_attested_actual_identity(
    client,
    isolate_settings,
) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    created = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "PROVENANCE-2",
            "agent_role": "recon-specialist",
            "requested_model": "gpt-requested",
            "client_name": "codex",
            "source_revision": "unknown",
            "instruction_identity_status": "incomplete",
        },
    )
    assert created.status_code == 201, created.text

    assert created.json()["actual_model"] == "unknown"
    assert created.json()["actual_reasoning"] == "unknown"

    for field in ("actual_model", "actual_reasoning"):
        self_attested_create = client.post(
            f"{BASE}/dispatches",
            json={
                "agent_id": f"FORGED-{field}",
                "agent_role": "recon-specialist",
                field: "caller-claim",
            },
        )
        assert self_attested_create.status_code == 422, self_attested_create.text
        self_attested_update = client.patch(
            f"{BASE}/dispatches/PROVENANCE-2",
            json={field: "caller-claim"},
        )
        assert self_attested_update.status_code == 422, self_attested_update.text


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("launcher_effective_model", "deepseek/deepseek-v4-flash"),
        ("launcher_effective_reasoning", "off"),
        (
            "launcher_effective_source",
            "agent/.opencode/agent/recon-specialist.md",
        ),
    ],
)
def test_dispatch_api_rejects_caller_attested_launcher_effective_identity(
    client,
    isolate_settings,
    field: str,
    value: str,
) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    response = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "FORGED-LAUNCHER-EFFECTIVE",
            "agent_role": "recon-specialist",
            "client_name": "opencode",
            field: value,
        },
    )

    assert response.status_code == 422, response.text


def test_dispatch_api_rejects_complete_caller_attested_launcher_effective_identity(
    client,
    isolate_settings,
) -> None:
    """A forged complete tuple must not bypass the per-field rejection coverage."""
    _seed(client, isolate_settings["engagements_dir"])

    response = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "FORGED-LAUNCHER-EFFECTIVE-TUPLE",
            "agent_role": "recon-specialist",
            "client_name": "opencode",
            "launcher_effective_model": "caller-forged-model",
            "launcher_effective_reasoning": "caller-forged-reasoning",
            "launcher_effective_source": "caller-forged-source",
        },
    )

    assert response.status_code == 422, response.text


def test_dispatch_provenance_rejects_malformed_hashes_and_status(
    client,
    isolate_settings,
) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    base = {
        "agent_id": "PROVENANCE-BAD",
        "agent_role": "recon-specialist",
        "client_name": "codex",
        "source_revision": "unknown",
    }
    for field, value in (
        ("operator_instruction_sha256", "not-a-digest"),
        ("specialist_instruction_sha256", "A" * 64),
        ("instruction_identity_status", "trusted-by-request"),
    ):
        response = client.post(f"{BASE}/dispatches", json={**base, field: value})
        assert response.status_code == 422, (field, response.text)
    incomplete = client.post(
        f"{BASE}/dispatches",
        json={**base, "instruction_identity_status": "verified"},
    )
    assert incomplete.status_code == 422, incomplete.text

