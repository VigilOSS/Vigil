"""Round 9: contract tests for the new ``assessment_dispatch_decisions`` API.

POST + LIST + PATCH coverage. Decisions are flat operator-checkpoint records
(scope_decision, egress_decision, dispatch_blocked, …); ``kind`` is open
text by design so operators can introduce new checkpoint kinds without a
backend redeploy.
"""
from __future__ import annotations

import json
from pathlib import Path


ENGAGEMENT_KEY = "2026-04-28-140000-decisions"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _write_engagement(engagements_dir: Path, key: str = ENGAGEMENT_KEY) -> Path:
    eng = engagements_dir / key
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "engagement.json").write_text(
        json.dumps({"key": key, "target": "https://example.com", "hostname": "example.com",
                    "created_at": "2026-04-28T14:00:00Z"}),
        encoding="utf-8",
    )
    (eng / "scope.json").write_text(
        json.dumps({
            "hostname": "example.com",
            "hosts": ["example.com"],
            "status": "in_progress",
            "current_phase": "recon",
        }),
        encoding="utf-8",
    )
    return eng


def _seed(client, isolate_settings) -> None:
    _write_engagement(isolate_settings["engagements_dir"])
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text


def test_decision_post_list_filter_patch(client, isolate_settings) -> None:
    _seed(client, isolate_settings)

    # Create a vendor-SaaS scope_decision
    create = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": "scope_decision",
        "payload": {
            "host": "vendor-saas.example.com",
            "vendor": "salesforce",
            "choice": "in_scope",
            "note": "Authorized per VDP",
        },
        "surfaced_to_user": True,
    })
    assert create.status_code == 201, create.text
    created = create.json()
    assert created["kind"] == "scope_decision"
    assert created["payload"]["host"] == "vendor-saas.example.com"
    assert created["surfaced_to_user"] is True
    assert created["resolved"] is False
    decision_id = created["id"]

    # And an egress_decision
    create2 = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": "egress_decision",
        "payload": {"blocked_pct": 67, "choice": "use-proxy"},
    })
    assert create2.status_code == 201

    # List all
    listed = client.get(f"{BASE}/dispatch-decisions").json()
    assert len(listed) == 2

    # Filter by kind
    scope_only = client.get(f"{BASE}/dispatch-decisions", params={"kind": "scope_decision"}).json()
    assert len(scope_only) == 1
    assert scope_only[0]["kind"] == "scope_decision"

    # Filter by resolved=false (everything is unresolved at this point)
    unresolved = client.get(f"{BASE}/dispatch-decisions", params={"resolved": "false"}).json()
    assert len(unresolved) == 2

    # PATCH to mark resolved
    patched = client.patch(
        f"{BASE}/dispatch-decisions/{decision_id}",
        json={"resolved": True, "resolution": {"closed_by": "operator", "outcome": "in_scope"}},
    )
    assert patched.status_code == 200, patched.text
    body = patched.json()
    assert body["resolved"] is True
    assert body["resolution"]["closed_by"] == "operator"

    # resolved=true filter now picks up the patched row
    resolved = client.get(f"{BASE}/dispatch-decisions", params={"resolved": "true"}).json()
    assert len(resolved) == 1
    assert resolved[0]["id"] == decision_id


def test_decision_kind_required(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    bad = client.post(f"{BASE}/dispatch-decisions", json={"kind": "", "payload": {}})
    assert bad.status_code == 422

    # Empty payload is allowed (the kind field is the load-bearing axis)
    ok = client.post(f"{BASE}/dispatch-decisions", json={"kind": "test_kind", "payload": {}})
    assert ok.status_code == 201


def test_decision_404_on_missing_patch(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    resp = client.patch(f"{BASE}/dispatch-decisions/9999", json={"resolved": True})
    assert resp.status_code == 404
