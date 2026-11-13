"""An attack-chain write refuses every unknown field, naming where it belongs.

A chain payload hand-written from the adjudication template carries words the
request has no field for (`steps`, `impact`, a link's `slug`). Dropping them
stored a chain without its steps behind a success receipt; the write now names
each one and its home, and stores nothing.
"""
from __future__ import annotations

import json
from pathlib import Path

ENGAGEMENT_KEY = "2026-11-14-120000-acme-chain-fields"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    engagement_dir = Path(isolate_settings["engagements_dir"]) / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Acme Chains", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200


def test_unknown_chain_and_link_fields_are_each_refused_with_their_home(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)

    refused = client.post(f"{BASE}/attack-chains", json={
        "title": "Acme IDOR to account takeover",
        "steps": ["IDOR-001", "ATO-002"],
        "impact": "Any Acme account can be taken over.",
        "links": [{"entity_kind": "finding", "slug": "IDOR-001"}],
    })

    assert refused.status_code == 422, refused.text
    errors = {tuple(error["loc"]): error["msg"] for error in refused.json()["detail"]}
    steps = errors[("body", "steps")]
    assert "'steps'" in steps and "links" in steps
    assert "narrative" in errors[("body", "impact")]
    assert "entity_ref" in errors[("body", "links", 0, "slug")]
    assert client.get(f"{BASE}/attack-chains").json() == []


def test_a_chain_with_only_its_fields_is_recorded(client, isolate_settings) -> None:
    _seed(client, isolate_settings)

    created = client.post(f"{BASE}/attack-chains", json={
        "title": "Acme IDOR to account takeover",
        "narrative": "VA-047 leaks the reset token VA-048 replays.",
        "links": [{"entity_kind": "credential", "entity_ref": "acme-reset-token", "notes": "replayed"}],
    })

    assert created.status_code in {200, 201}, created.text
    assert created.json()["chain"]["chain_key"] == "acme-idor-to-account-takeover"
