"""Imported sources a proof run never read cannot disappear from its outcome."""
from __future__ import annotations

import pytest

from tests.test_run_accounting_api import (
    BASE,
    _recovery_parent_run,
    _recovery_receipt,
    _seed,
    _source,
)


def _import(client, run: dict, count: int) -> list[dict]:
    response = client.post(
        f"{BASE}/assessment-runs/{run['id']}/sources",
        json={
            "sources": [
                _source(
                    target_key="service-a",
                    path=f"src/module_{index}.py",
                    content=f"VALUE = {index}\n".encode(),
                )
                for index in range(count)
            ]
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _source_obligation(client, run: dict, source: dict) -> dict:
    page = client.get(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        params={"limit": 1000, "offset": 0},
    )
    assert page.status_code == 200, page.text
    [obligation] = [
        row
        for row in page.json()["items"]
        if row["identity_key"] == f"source_read:{source['id']}"
    ]
    return obligation


@pytest.mark.parametrize("closing_status", ["resolved", "accepted_gap"])
def test_manual_closure_cannot_retire_an_unread_source(
    client, isolate_settings, closing_status
) -> None:
    _seed(client, isolate_settings)
    run = _recovery_parent_run(client, run_uuid=f"unread-{closing_status}")
    receipt_id = _recovery_receipt(
        client, run, slug=f"unread-{closing_status}", observed="guard absent"
    )
    [source] = _import(client, run, 1)
    obligation = _source_obligation(client, run, source)

    refused = client.patch(
        f"{BASE}/assessment-runs/{run['id']}/obligations/{obligation['id']}",
        json={
            "status": closing_status,
            "resolution": "not needed for this proof",
            "proof_receipt_ids": [receipt_id],
        },
    )

    assert refused.status_code == 409, refused.text
    assert "source-read record" in refused.json()["detail"]
    assert "obligation release" in refused.json()["detail"]
    assert _source_obligation(client, run, source)["status"] == "open"


def test_recording_a_closed_source_read_obligation_is_refused(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    run = _recovery_parent_run(client, run_uuid="recorded-source-closure")
    receipt_id = _recovery_receipt(
        client, run, slug="recorded-source-closure", observed="guard absent"
    )

    refused = client.post(
        f"{BASE}/assessment-runs/{run['id']}/obligations",
        json={
            "identity_key": "source_read:manual",
            "obligation_kind": "source_read",
            "object_type": "source",
            "object_key": "service-a:src/never_read.py",
            "hard": True,
            "status": "resolved",
            "resolution": "assumed read",
            "proof_receipt_ids": [receipt_id],
        },
    )

    assert refused.status_code == 409, refused.text
    assert "source-read record" in refused.json()["detail"]
